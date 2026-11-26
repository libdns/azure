package azure

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/dns/armdns"

	"github.com/libdns/libdns"
)

// Client is an abstraction of RecordSetsClient for Azure DNS
type Client struct {
	azureClient *armdns.RecordSetsClient
	mutex       sync.Mutex
}

// setupClient invokes authentication and store client to the provider instance.
func (p *Provider) setupClient() error {
	if p.client.azureClient == nil {
		credentials, err := p.newCredentials()
		if err != nil {
			return err
		}

		chainedTokenCredential, err := azidentity.NewChainedTokenCredential(credentials, nil)
		if err != nil {
			return err
		}
		clientFactory, err := armdns.NewClientFactory(p.SubscriptionId, chainedTokenCredential, nil)
		if err != nil {
			return err
		}
		p.client.azureClient = clientFactory.NewRecordSetsClient()
	}

	return nil
}

// newCredentials returns the credentials to authenticate with, in the order to try them.
func (p *Provider) newCredentials() ([]azcore.TokenCredential, error) {
	credentials := []azcore.TokenCredential{}

	// If Tenant ID, Client ID, or Client Secret is specified, attempt to authenticate using a client secret.
	// If not, attempt to authenticate using workload identity, if it is configured in the environment,
	// and then using managed identity.
	// Authentication using a client secret is prioritized over the others to keep backward compatibility.
	if p.TenantId != "" || p.ClientId != "" || p.ClientSecret != "" {
		clientCredential, err := azidentity.NewClientSecretCredential(p.TenantId, p.ClientId, p.ClientSecret, nil)
		if err != nil {
			return nil, err
		}
		credentials = append(credentials, clientCredential)
	} else {
		// Not used if it can't be created, which is the case unless the environment variables of
		// workload identity (AZURE_TENANT_ID, AZURE_CLIENT_ID, and AZURE_FEDERATED_TOKEN_FILE) are set
		// to valid values, so that existing deployments keep working as they are.
		if workloadIdentityCredential, err := azidentity.NewWorkloadIdentityCredential(nil); err == nil {
			credentials = append(credentials, workloadIdentityCredential)
		}

		managedIdentityCredential, err := azidentity.NewManagedIdentityCredential(nil)
		if err != nil {
			return nil, err
		}
		credentials = append(credentials, managedIdentityCredential)
	}

	return credentials, nil
}

// getRecords gets all records in specified zone on Azure DNS.
func (p *Provider) getRecords(ctx context.Context, zone string) ([]libdns.Record, error) {
	p.client.mutex.Lock()
	defer p.client.mutex.Unlock()

	if err := p.setupClient(); err != nil {
		return nil, err
	}

	var recordSets []*armdns.RecordSet

	pager := p.client.azureClient.NewListByDNSZonePager(
		p.ResourceGroupName,
		strings.TrimSuffix(zone, "."),
		&armdns.RecordSetsClientListByDNSZoneOptions{
			Top:                 nil,
			Recordsetnamesuffix: nil,
		})

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		recordSets = append(recordSets, page.Value...)
	}

	records, _ := convertAzureRecordSetsToLibdnsRecords(recordSets)
	return records, nil
}

// createRecord adds a record to the specified zone. Azure stores all records
// with the same name and type in one record set, so the record is added to
// the existing set, if any. For example, the ACME challenges of example.com and
// *.example.com are two TXT values in the same record set.
// It reports whether the zone changed, which is not the case if the zone already has the record.
func (p *Provider) createRecord(ctx context.Context, zone string, record libdns.Record) (bool, error) {
	recordSet, err := convertLibdnsRecordToAzureRecordSet(record)
	if err != nil {
		return false, err
	}
	rr := record.RR()
	return p.modifyRecordSet(ctx, zone, rr.Name, rr.Type, func(dst *armdns.RecordSetProperties) (bool, error) {
		return addValues(dst, recordSet.Properties)
	})
}

// deleteRecord deletes a record. Other values in the same record set are kept,
// and the record set is deleted when it becomes empty. The TTL is not compared,
// because Azure has a single TTL per record set. A record without data deletes
// the whole record set.
// It reports whether the zone changed, which is not the case if the zone doesn't have the record.
func (p *Provider) deleteRecord(ctx context.Context, zone string, record libdns.Record) (bool, error) {
	rr := record.RR()
	if rr.Data == "" {
		return p.modifyRecordSet(ctx, zone, rr.Name, rr.Type, removeAll)
	}
	recordSet, err := convertLibdnsRecordToAzureRecordSet(record)
	if err != nil {
		return false, err
	}
	return p.modifyRecordSet(ctx, zone, rr.Name, rr.Type, func(dst *armdns.RecordSetProperties) (bool, error) {
		return removeValues(dst, recordSet.Properties)
	})
}

// setRecordSet replaces the record set with the name and type of records by
// the values of records, which all share one name and one type. The TTL of the
// record set is the lowest TTL of records.
func (p *Provider) setRecordSet(ctx context.Context, zone string, records []libdns.Record) error {
	p.client.mutex.Lock()
	defer p.client.mutex.Unlock()

	if err := p.setupClient(); err != nil {
		return err
	}

	rr := records[0].RR()
	recordType, err := convertStringToRecordType(rr.Type)
	if err != nil {
		return err
	}

	properties := &armdns.RecordSetProperties{}
	for _, record := range records {
		recordSet, err := convertLibdnsRecordToAzureRecordSet(record)
		if err != nil {
			return err
		}
		if _, err := addValues(properties, recordSet.Properties); err != nil {
			return fmt.Errorf("%s record set %q: %w", recordType, generateRecordSetName(rr.Name, zone), err)
		}
		// A TTL of 0 is unspecified, so it only stays if no record has a TTL.
		if ttl := recordSet.Properties.TTL; *ttl != 0 && (*properties.TTL == 0 || *ttl < *properties.TTL) {
			properties.TTL = ttl
		}
	}

	_, err = p.client.azureClient.CreateOrUpdate(
		ctx,
		p.ResourceGroupName,
		strings.TrimSuffix(zone, "."),
		generateRecordSetName(rr.Name, zone),
		recordType,
		armdns.RecordSet{Properties: properties},
		nil,
	)
	return err
}

// maxAttempts bounds how often a record set is read and written again after
// someone else changed it in between.
const maxAttempts = 10

// modifyRecordSet changes the values of a record set without touching the
// others. The write is conditional on the record set's etag, so concurrent
// changes, also from other processes, are not lost. change edits the current
// values, which are empty if the record set doesn't exist, and reports whether
// it changed anything. Nothing is written otherwise. modifyRecordSet reports
// the same.
func (p *Provider) modifyRecordSet(ctx context.Context, zone, name, typeName string, change func(properties *armdns.RecordSetProperties) (bool, error)) (bool, error) {
	p.client.mutex.Lock()
	defer p.client.mutex.Unlock()

	if err := p.setupClient(); err != nil {
		return false, err
	}

	recordType, err := convertStringToRecordType(typeName)
	if err != nil {
		return false, err
	}
	zoneName := strings.TrimSuffix(zone, ".")
	recordSetName := generateRecordSetName(name, zone)

	for attempt := range maxAttempts {
		if attempt > 0 {
			// Jitter, so writers that keep conflicting spread out.
			select {
			case <-ctx.Done():
				return false, ctx.Err()
			case <-time.After(rand.N(time.Duration(attempt) * 50 * time.Millisecond)):
			}
		}

		current, err := p.client.azureClient.Get(
			ctx,
			p.ResourceGroupName,
			zoneName,
			recordSetName,
			recordType,
			nil,
		)
		missing := hasStatus(err, http.StatusNotFound)
		if err != nil && !missing {
			return false, err
		}

		properties := &armdns.RecordSetProperties{}
		var etag *string
		if !missing && current.Properties != nil {
			properties = copyRecordSetProperties(current.Properties)
			etag = current.Etag
		}
		changed, err := change(properties)
		if err != nil {
			return false, fmt.Errorf("%s record set %q: %w", recordType, recordSetName, err)
		}
		if !changed {
			return false, nil
		}

		if isEmpty(properties) {
			_, err = p.client.azureClient.Delete(
				ctx,
				p.ResourceGroupName,
				zoneName,
				recordSetName,
				recordType,
				&armdns.RecordSetsClientDeleteOptions{
					IfMatch: etag,
				},
			)
		} else {
			options := &armdns.RecordSetsClientCreateOrUpdateOptions{
				IfMatch: etag,
			}
			if missing {
				options = &armdns.RecordSetsClientCreateOrUpdateOptions{
					IfNoneMatch: to.Ptr("*"),
				}
			}
			_, err = p.client.azureClient.CreateOrUpdate(
				ctx,
				p.ResourceGroupName,
				zoneName,
				recordSetName,
				recordType,
				armdns.RecordSet{Properties: properties},
				options,
			)
		}
		if !hasStatus(err, http.StatusPreconditionFailed) {
			return err == nil, err
		}
	}

	return false, fmt.Errorf("%s record set %q kept changing, gave up after %d attempts", recordType, recordSetName, maxAttempts)
}

// hasStatus reports whether err is an Azure API error with the given HTTP status.
func hasStatus(err error, status int) bool {
	var respErr *azcore.ResponseError
	return errors.As(err, &respErr) && respErr.StatusCode == status
}

// copyRecordSetProperties returns the writable properties of a record set.
func copyRecordSetProperties(p *armdns.RecordSetProperties) *armdns.RecordSetProperties {
	properties := &armdns.RecordSetProperties{
		TTL:         p.TTL,
		Metadata:    p.Metadata,
		ARecords:    slices.Clone(p.ARecords),
		AaaaRecords: slices.Clone(p.AaaaRecords),
		CaaRecords:  slices.Clone(p.CaaRecords),
		CnameRecord: p.CnameRecord,
		MxRecords:   slices.Clone(p.MxRecords),
		NsRecords:   slices.Clone(p.NsRecords),
		PtrRecords:  slices.Clone(p.PtrRecords),
		SoaRecord:   p.SoaRecord,
		SrvRecords:  slices.Clone(p.SrvRecords),
		TxtRecords:  slices.Clone(p.TxtRecords),
	}
	// Azure returns an empty target resource for record sets that aren't aliases.
	if p.TargetResource != nil && p.TargetResource.ID != nil {
		properties.TargetResource = p.TargetResource
	}
	return properties
}

// isEmpty reports whether a record set has no values left.
func isEmpty(p *armdns.RecordSetProperties) bool {
	return len(p.ARecords) == 0 && len(p.AaaaRecords) == 0 && len(p.CaaRecords) == 0 &&
		p.CnameRecord == nil && len(p.MxRecords) == 0 && len(p.NsRecords) == 0 &&
		len(p.PtrRecords) == 0 && p.SoaRecord == nil && len(p.SrvRecords) == 0 &&
		len(p.TxtRecords) == 0 && p.TargetResource == nil
}

// countValues returns the number of values in a record set.
func countValues(p *armdns.RecordSetProperties) int {
	n := len(p.ARecords) + len(p.AaaaRecords) + len(p.CaaRecords) + len(p.MxRecords) +
		len(p.NsRecords) + len(p.PtrRecords) + len(p.SrvRecords) + len(p.TxtRecords)
	if p.CnameRecord != nil {
		n++
	}
	if p.SoaRecord != nil {
		n++
	}
	return n
}

// addValues adds the values of src to dst, skipping the ones dst already has.
// It reports whether dst changed. The TTL of dst is kept, unless dst was empty.
func addValues(dst, src *armdns.RecordSetProperties) (bool, error) {
	if isEmpty(dst) {
		dst.TTL = src.TTL
	}
	if src.CnameRecord != nil || src.SoaRecord != nil {
		// A record set holds a single CNAME or SOA value.
		if !isEmpty(dst) {
			if sameCNAME(dst.CnameRecord, src.CnameRecord) && sameSOA(dst.SoaRecord, src.SoaRecord) {
				return false, nil
			}
			return false, errors.New("already exists")
		}
		dst.CnameRecord = src.CnameRecord
		dst.SoaRecord = src.SoaRecord
		return true, nil
	}
	before := countValues(dst)
	dst.ARecords = appendMissing(dst.ARecords, src.ARecords, sameA)
	dst.AaaaRecords = appendMissing(dst.AaaaRecords, src.AaaaRecords, sameAAAA)
	dst.CaaRecords = appendMissing(dst.CaaRecords, src.CaaRecords, sameCAA)
	dst.MxRecords = appendMissing(dst.MxRecords, src.MxRecords, sameMX)
	dst.NsRecords = appendMissing(dst.NsRecords, src.NsRecords, sameNS)
	dst.PtrRecords = appendMissing(dst.PtrRecords, src.PtrRecords, samePTR)
	dst.SrvRecords = appendMissing(dst.SrvRecords, src.SrvRecords, sameSRV)
	dst.TxtRecords = appendMissing(dst.TxtRecords, src.TxtRecords, sameTXT)
	return countValues(dst) != before, nil
}

// removeValues removes the values of src from dst. It reports whether dst changed.
func removeValues(dst, src *armdns.RecordSetProperties) (bool, error) {
	before := countValues(dst)
	if sameCNAME(dst.CnameRecord, src.CnameRecord) {
		dst.CnameRecord = nil
	}
	if sameSOA(dst.SoaRecord, src.SoaRecord) {
		dst.SoaRecord = nil
	}
	dst.ARecords = deleteMatching(dst.ARecords, src.ARecords, sameA)
	dst.AaaaRecords = deleteMatching(dst.AaaaRecords, src.AaaaRecords, sameAAAA)
	dst.CaaRecords = deleteMatching(dst.CaaRecords, src.CaaRecords, sameCAA)
	dst.MxRecords = deleteMatching(dst.MxRecords, src.MxRecords, sameMX)
	dst.NsRecords = deleteMatching(dst.NsRecords, src.NsRecords, sameNS)
	dst.PtrRecords = deleteMatching(dst.PtrRecords, src.PtrRecords, samePTR)
	dst.SrvRecords = deleteMatching(dst.SrvRecords, src.SrvRecords, sameSRV)
	dst.TxtRecords = deleteMatching(dst.TxtRecords, src.TxtRecords, sameTXT)
	return countValues(dst) != before, nil
}

// removeAll removes all the values from dst. It reports whether dst changed.
func removeAll(dst *armdns.RecordSetProperties) (bool, error) {
	changed := !isEmpty(dst)
	*dst = armdns.RecordSetProperties{}
	return changed, nil
}

// appendMissing appends the values of src that dst does not have yet.
func appendMissing[T any](dst, src []*T, same func(a, b *T) bool) []*T {
	for _, s := range src {
		if !slices.ContainsFunc(dst, func(d *T) bool { return same(d, s) }) {
			dst = append(dst, s)
		}
	}
	return dst
}

// deleteMatching removes the values of src from dst.
func deleteMatching[T any](dst, src []*T, same func(a, b *T) bool) []*T {
	return slices.DeleteFunc(dst, func(d *T) bool {
		return slices.ContainsFunc(src, func(s *T) bool { return same(d, s) })
	})
}

// val dereferences p, returning the zero value for nil.
func val[T any](p *T) (v T) {
	if p != nil {
		v = *p
	}
	return v
}

// sameA and the other same* functions report whether two values of a record set are equal.
func sameA(a, b *armdns.ARecord) bool { return val(a.IPv4Address) == val(b.IPv4Address) }

func sameAAAA(a, b *armdns.AaaaRecord) bool { return val(a.IPv6Address) == val(b.IPv6Address) }

func sameCAA(a, b *armdns.CaaRecord) bool {
	return val(a.Flags) == val(b.Flags) && val(a.Tag) == val(b.Tag) && val(a.Value) == val(b.Value)
}

func sameMX(a, b *armdns.MxRecord) bool {
	return val(a.Preference) == val(b.Preference) && val(a.Exchange) == val(b.Exchange)
}

// sameCNAME and sameSOA treat two missing values as the same.
func sameCNAME(a, b *armdns.CnameRecord) bool {
	if a == nil || b == nil {
		return a == b
	}
	return val(a.Cname) == val(b.Cname)
}

func sameSOA(a, b *armdns.SoaRecord) bool {
	if a == nil || b == nil {
		return a == b
	}
	return val(a.Host) == val(b.Host) && val(a.Email) == val(b.Email) &&
		val(a.SerialNumber) == val(b.SerialNumber) && val(a.RefreshTime) == val(b.RefreshTime) &&
		val(a.RetryTime) == val(b.RetryTime) && val(a.ExpireTime) == val(b.ExpireTime) &&
		val(a.MinimumTTL) == val(b.MinimumTTL)
}

func sameNS(a, b *armdns.NsRecord) bool { return val(a.Nsdname) == val(b.Nsdname) }

func samePTR(a, b *armdns.PtrRecord) bool { return val(a.Ptrdname) == val(b.Ptrdname) }

func sameSRV(a, b *armdns.SrvRecord) bool {
	return val(a.Priority) == val(b.Priority) && val(a.Weight) == val(b.Weight) &&
		val(a.Port) == val(b.Port) && val(a.Target) == val(b.Target)
}

func sameTXT(a, b *armdns.TxtRecord) bool {
	return slices.EqualFunc(a.Value, b.Value, func(x, y *string) bool { return val(x) == val(y) })
}

// generateRecordSetName generates name for RecordSet object.
func generateRecordSetName(name string, zone string) string {
	recordSetName := libdns.RelativeName(strings.TrimSuffix(name, ".")+".", zone)
	if recordSetName == "" {
		return "@"
	}
	return recordSetName
}

// convertStringToRecordType casts standard type name string to an Azure-styled dedicated type.
func convertStringToRecordType(typeName string) (armdns.RecordType, error) {
	switch typeName {
	case "A":
		return armdns.RecordTypeA, nil
	case "AAAA":
		return armdns.RecordTypeAAAA, nil
	case "CAA":
		return armdns.RecordTypeCAA, nil
	case "CNAME":
		return armdns.RecordTypeCNAME, nil
	case "MX":
		return armdns.RecordTypeMX, nil
	case "NS":
		return armdns.RecordTypeNS, nil
	case "SRV":
		return armdns.RecordTypeSRV, nil
	case "TXT":
		return armdns.RecordTypeTXT, nil
	case "PTR":
		return armdns.RecordTypePTR, nil
	case "SOA":
		return armdns.RecordTypeSOA, nil
	default:
		return armdns.RecordTypeA, fmt.Errorf("the type %v cannot be interpreted", typeName)
	}
}

// convertAzureRecordSetsToLibdnsRecords converts Azure-styled records to libdns records.
func convertAzureRecordSetsToLibdnsRecords(recordSets []*armdns.RecordSet) ([]libdns.Record, error) {
	var records []libdns.Record

	for _, recordSet := range recordSets {
		switch typeName := strings.TrimPrefix(*recordSet.Type, "Microsoft.Network/dnszones/"); typeName {
		case "A":
			for _, v := range recordSet.Properties.ARecords {
				ip, err := netip.ParseAddr(*v.IPv4Address)
				if err != nil {
					return nil, fmt.Errorf("failed to parse IP address: %w", err)
				}
				record := libdns.Address{
					Name: *recordSet.Name,
					TTL:  time.Duration(*recordSet.Properties.TTL) * time.Second,
					IP:   ip,
				}
				records = append(records, record)
			}
		case "AAAA":
			for _, v := range recordSet.Properties.AaaaRecords {
				ip, err := netip.ParseAddr(*v.IPv6Address)
				if err != nil {
					return nil, fmt.Errorf("failed to parse IP address: %w", err)
				}
				record := libdns.Address{
					Name: *recordSet.Name,
					TTL:  time.Duration(*recordSet.Properties.TTL) * time.Second,
					IP:   ip,
				}
				records = append(records, record)
			}
		case "CAA":
			for _, v := range recordSet.Properties.CaaRecords {
				record := libdns.CAA{
					Name:  *recordSet.Name,
					TTL:   time.Duration(*recordSet.Properties.TTL) * time.Second,
					Flags: uint8(*v.Flags),
					Tag:   *v.Tag,
					Value: *v.Value,
				}
				records = append(records, record)
			}
		case "CNAME":
			record := libdns.CNAME{
				Name:   *recordSet.Name,
				TTL:    time.Duration(*recordSet.Properties.TTL) * time.Second,
				Target: *recordSet.Properties.CnameRecord.Cname,
			}
			records = append(records, record)
		case "MX":
			for _, v := range recordSet.Properties.MxRecords {
				record := libdns.MX{
					Name:       *recordSet.Name,
					TTL:        time.Duration(*recordSet.Properties.TTL) * time.Second,
					Preference: uint16(*v.Preference),
					Target:     *v.Exchange,
				}
				records = append(records, record)
			}
		case "NS":
			for _, v := range recordSet.Properties.NsRecords {
				record := libdns.NS{
					Name:   *recordSet.Name,
					TTL:    time.Duration(*recordSet.Properties.TTL) * time.Second,
					Target: *v.Nsdname,
				}
				records = append(records, record)
			}
		case "SRV":
			for _, v := range recordSet.Properties.SrvRecords {
				parts := strings.SplitN(*recordSet.Name, ".", 3)
				if len(parts) < 2 {
					return nil, fmt.Errorf("name %v does not contain enough fields; expected format: '_service._proto.name' or '_service._proto'", *recordSet.Name)
				}
				name := "@"
				if len(parts) == 3 {
					name = parts[2]
				}
				record := libdns.SRV{
					Service:   strings.TrimPrefix(parts[0], "_"),
					Transport: strings.TrimPrefix(parts[1], "_"),
					Name:      name,
					TTL:       time.Duration(*recordSet.Properties.TTL) * time.Second,
					Priority:  uint16(*v.Priority),
					Weight:    uint16(*v.Weight),
					Port:      uint16(*v.Port),
					Target:    *v.Target,
				}
				records = append(records, record)
			}
		case "TXT":
			for _, v := range recordSet.Properties.TxtRecords {
				for _, txt := range v.Value {
					record := libdns.TXT{
						Name: *recordSet.Name,
						TTL:  time.Duration(*recordSet.Properties.TTL) * time.Second,
						Text: *txt,
					}
					records = append(records, record)
				}
			}
		case "PTR":
			for _, v := range recordSet.Properties.PtrRecords {
				record := libdns.RR{
					Name: *recordSet.Name,
					Type: "PTR",
					TTL:  time.Duration(*recordSet.Properties.TTL) * time.Second,
					Data: *v.Ptrdname,
				}
				records = append(records, record)
			}
		case "SOA":
			soaData := strings.Join([]string{
				*recordSet.Properties.SoaRecord.Host,
				*recordSet.Properties.SoaRecord.Email,
				fmt.Sprint(*recordSet.Properties.SoaRecord.SerialNumber),
				fmt.Sprint(*recordSet.Properties.SoaRecord.RefreshTime),
				fmt.Sprint(*recordSet.Properties.SoaRecord.RetryTime),
				fmt.Sprint(*recordSet.Properties.SoaRecord.ExpireTime),
				fmt.Sprint(*recordSet.Properties.SoaRecord.MinimumTTL)},
				" ")
			record := libdns.RR{
				Name: *recordSet.Name,
				Type: "SOA",
				TTL:  time.Duration(*recordSet.Properties.TTL) * time.Second,
				Data: soaData,
			}
			records = append(records, record)
		default:
			return []libdns.Record{}, fmt.Errorf("the type %v cannot be interpreted", typeName)
		}
	}

	return records, nil
}

// convertLibdnsRecordToAzureRecordSet converts a libdns record to an Azure-styled record.
func convertLibdnsRecordToAzureRecordSet(record libdns.Record) (armdns.RecordSet, error) {
	rr, err := record.RR().Parse()
	if err != nil {
		return armdns.RecordSet{}, fmt.Errorf("unable to parse libdns.RR: %w", err)
	}

	switch rec := rr.(type) {
	case libdns.Address:
		recordSet := armdns.RecordSet{
			Properties: &armdns.RecordSetProperties{
				TTL: to.Ptr(int64(rec.TTL / time.Second)),
			},
		}
		if rec.IP.Is6() {
			recordSet.Properties.AaaaRecords = []*armdns.AaaaRecord{{
				IPv6Address: to.Ptr(rec.IP.String()),
			}}
		} else {
			recordSet.Properties.ARecords = []*armdns.ARecord{{
				IPv4Address: to.Ptr(rec.IP.String()),
			}}
		}
		return recordSet, nil
	case libdns.CAA:
		recordSet := armdns.RecordSet{
			Properties: &armdns.RecordSetProperties{
				TTL: to.Ptr(int64(rec.TTL / time.Second)),
				CaaRecords: []*armdns.CaaRecord{{
					Flags: to.Ptr(int32(rec.Flags)),
					Tag:   to.Ptr(rec.Tag),
					Value: to.Ptr(rec.Value),
				}},
			},
		}
		return recordSet, nil
	case libdns.CNAME:
		recordSet := armdns.RecordSet{
			Properties: &armdns.RecordSetProperties{
				TTL: to.Ptr(int64(rec.TTL / time.Second)),
				CnameRecord: &armdns.CnameRecord{
					Cname: to.Ptr(rec.Target),
				},
			},
		}
		return recordSet, nil
	case libdns.MX:
		recordSet := armdns.RecordSet{
			Properties: &armdns.RecordSetProperties{
				TTL: to.Ptr(int64(rec.TTL / time.Second)),
				MxRecords: []*armdns.MxRecord{{
					Preference: to.Ptr(int32(rec.Preference)),
					Exchange:   to.Ptr(rec.Target),
				}},
			},
		}
		return recordSet, nil
	case libdns.NS:
		recordSet := armdns.RecordSet{
			Properties: &armdns.RecordSetProperties{
				TTL: to.Ptr(int64(rec.TTL / time.Second)),
				NsRecords: []*armdns.NsRecord{{
					Nsdname: to.Ptr(rec.Target),
				}},
			},
		}
		return recordSet, nil
	case libdns.SRV:
		recordSet := armdns.RecordSet{
			Properties: &armdns.RecordSetProperties{
				TTL: to.Ptr(int64(rec.TTL / time.Second)),
				SrvRecords: []*armdns.SrvRecord{{
					Priority: to.Ptr(int32(rec.Priority)),
					Weight:   to.Ptr(int32(rec.Weight)),
					Port:     to.Ptr(int32(rec.Port)),
					Target:   to.Ptr(rec.Target),
				}},
			},
		}
		return recordSet, nil
	case libdns.TXT:
		recordSet := armdns.RecordSet{
			Properties: &armdns.RecordSetProperties{
				TTL: to.Ptr(int64(rec.TTL / time.Second)),
				TxtRecords: []*armdns.TxtRecord{{
					Value: []*string{&rec.Text},
				}},
			},
		}
		return recordSet, nil
	case libdns.RR:
		switch strings.ToUpper(rec.Type) {
		case "PTR":
			recordSet := armdns.RecordSet{
				Properties: &armdns.RecordSetProperties{
					TTL: to.Ptr(int64(rec.TTL / time.Second)),
					PtrRecords: []*armdns.PtrRecord{{
						Ptrdname: to.Ptr(rec.Data),
					}},
				},
			}
			return recordSet, nil
		case "SOA":
			values := strings.Split(rec.Data, " ")
			if len(values) < 7 {
				return armdns.RecordSet{}, fmt.Errorf("invalid SOA record data: %s", rec.Data)
			}

			serialNumber, _ := strconv.ParseInt(values[2], 10, 64)
			refreshTime, _ := strconv.ParseInt(values[3], 10, 64)
			retryTime, _ := strconv.ParseInt(values[4], 10, 64)
			expireTime, _ := strconv.ParseInt(values[5], 10, 64)
			minimumTTL, _ := strconv.ParseInt(values[6], 10, 64)

			recordSet := armdns.RecordSet{
				Properties: &armdns.RecordSetProperties{
					TTL: to.Ptr(int64(rec.TTL / time.Second)),
					SoaRecord: &armdns.SoaRecord{
						Host:         to.Ptr(values[0]),
						Email:        to.Ptr(values[1]),
						SerialNumber: to.Ptr(serialNumber),
						RefreshTime:  to.Ptr(refreshTime),
						RetryTime:    to.Ptr(retryTime),
						ExpireTime:   to.Ptr(expireTime),
						MinimumTTL:   to.Ptr(minimumTTL),
					},
				},
			}
			return recordSet, nil
		default:
			return armdns.RecordSet{}, fmt.Errorf("the type %v cannot be interpreted", rec.Type)
		}
	default:
		return armdns.RecordSet{}, fmt.Errorf("the type %v cannot be interpreted", rec.RR().Type)
	}
}
