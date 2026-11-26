package azure

import (
	"context"
	"fmt"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	azfake "github.com/Azure/azure-sdk-for-go/sdk/azcore/fake"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/dns/armdns"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/dns/armdns/fake"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/libdns/libdns"
)

var azureFakeRecords = []armdns.RecordSet{
	{
		Name: to.Ptr("record-a"),
		Type: to.Ptr("Microsoft.Network/dnszones/A"),
		Etag: to.Ptr("ETAG_A"),
		Properties: &armdns.RecordSetProperties{
			TTL:  to.Ptr[int64](30),
			Fqdn: to.Ptr("record-a.example.com."),
			ARecords: []*armdns.ARecord{
				{
					IPv4Address: to.Ptr("127.0.0.1"),
				},
			},
		},
	},
	{
		Name: to.Ptr("record-aaaa"),
		Type: to.Ptr("Microsoft.Network/dnszones/AAAA"),
		Etag: to.Ptr("ETAG_AAAA"),
		Properties: &armdns.RecordSetProperties{
			TTL:  to.Ptr[int64](30),
			Fqdn: to.Ptr("record-aaaa.example.com."),
			AaaaRecords: []*armdns.AaaaRecord{{
				IPv6Address: to.Ptr("::1"),
			}},
		},
	},
	{
		Name: to.Ptr("record-caa"),
		Type: to.Ptr("Microsoft.Network/dnszones/CAA"),
		Etag: to.Ptr("ETAG_CAA"),
		Properties: &armdns.RecordSetProperties{
			TTL:  to.Ptr[int64](30),
			Fqdn: to.Ptr("record-caa.example.com."),
			CaaRecords: []*armdns.CaaRecord{{
				Flags: to.Ptr[int32](0),
				Tag:   to.Ptr("issue"),
				Value: to.Ptr("ca.example.com"),
			}},
		},
	},
	{
		Name: to.Ptr("record-cname"),
		Type: to.Ptr("Microsoft.Network/dnszones/CNAME"),
		Etag: to.Ptr("ETAG_CNAME"),
		Properties: &armdns.RecordSetProperties{
			TTL:  to.Ptr[int64](30),
			Fqdn: to.Ptr("record-cname.example.com."),
			CnameRecord: &armdns.CnameRecord{
				Cname: to.Ptr("www.example.com"),
			},
		},
	},
	{
		Name: to.Ptr("record-mx"),
		Type: to.Ptr("Microsoft.Network/dnszones/MX"),
		Etag: to.Ptr("ETAG_MX"),
		Properties: &armdns.RecordSetProperties{
			TTL:  to.Ptr[int64](30),
			Fqdn: to.Ptr("record-mx.example.com."),
			MxRecords: []*armdns.MxRecord{{
				Preference: to.Ptr[int32](10),
				Exchange:   to.Ptr("mail.example.com"),
			}},
		},
	},
	{
		Name: to.Ptr("@"),
		Type: to.Ptr("Microsoft.Network/dnszones/NS"),
		Etag: to.Ptr("ETAG_NS"),
		Properties: &armdns.RecordSetProperties{
			TTL:  to.Ptr[int64](30),
			Fqdn: to.Ptr("example.com."),
			NsRecords: []*armdns.NsRecord{
				{
					Nsdname: to.Ptr("ns1.example.com"),
				},
			},
		},
	},
	{
		Name: to.Ptr("_service._proto.record-srv"),
		Type: to.Ptr("Microsoft.Network/dnszones/SRV"),
		Etag: to.Ptr("ETAG_SRV"),
		Properties: &armdns.RecordSetProperties{
			TTL:  to.Ptr[int64](30),
			Fqdn: to.Ptr("_service._proto.record-srv.example.com."),
			SrvRecords: []*armdns.SrvRecord{{
				Priority: to.Ptr[int32](1),
				Weight:   to.Ptr[int32](10),
				Port:     to.Ptr[int32](5269),
				Target:   to.Ptr("app.example.com"),
			}},
		},
	},
	{
		Name: to.Ptr("record-txt"),
		Type: to.Ptr("Microsoft.Network/dnszones/TXT"),
		Etag: to.Ptr("ETAG_TXT"),
		Properties: &armdns.RecordSetProperties{
			TTL:  to.Ptr[int64](30),
			Fqdn: to.Ptr("record-txt.example.com."),
			TxtRecords: []*armdns.TxtRecord{{
				Value: []*string{to.Ptr("TEST VALUE")},
			}},
		},
	},
	{
		Name: to.Ptr("record-ptr"),
		Type: to.Ptr("Microsoft.Network/dnszones/PTR"),
		Etag: to.Ptr("ETAG_PTR"),
		Properties: &armdns.RecordSetProperties{
			TTL:  to.Ptr[int64](30),
			Fqdn: to.Ptr("record-ptr.example.com."),
			PtrRecords: []*armdns.PtrRecord{{
				Ptrdname: to.Ptr("hoge.example.com"),
			}},
		},
	}, {
		Name: to.Ptr("@"),
		Type: to.Ptr("Microsoft.Network/dnszones/SOA"),
		Etag: to.Ptr("ETAG_SOA"),
		Properties: &armdns.RecordSetProperties{
			TTL:  to.Ptr[int64](30),
			Fqdn: to.Ptr("example.com."),
			SoaRecord: &armdns.SoaRecord{
				Host:         to.Ptr("ns1.example.com"),
				Email:        to.Ptr("hostmaster.example.com"),
				SerialNumber: to.Ptr[int64](1),
				RefreshTime:  to.Ptr[int64](7200),
				RetryTime:    to.Ptr[int64](900),
				ExpireTime:   to.Ptr[int64](1209600),
				MinimumTTL:   to.Ptr[int64](86400),
			},
		},
	},
}

var libdnsFakeRecords = []libdns.Record{
	libdns.Address{
		Name: "record-a",
		TTL:  time.Duration(30) * time.Second,
		IP:   netip.MustParseAddr("127.0.0.1"),
	},
	libdns.Address{
		Name: "record-aaaa",
		TTL:  time.Duration(30) * time.Second,
		IP:   netip.MustParseAddr("::1"),
	},
	libdns.CAA{
		Name:  "record-caa",
		TTL:   time.Duration(30) * time.Second,
		Flags: 0,
		Tag:   "issue",
		Value: "ca.example.com",
	},
	libdns.CNAME{
		Name:   "record-cname",
		TTL:    time.Duration(30) * time.Second,
		Target: "www.example.com",
	},
	libdns.MX{
		Name:       "record-mx",
		TTL:        time.Duration(30) * time.Second,
		Preference: 10,
		Target:     "mail.example.com",
	},
	libdns.NS{
		Name:   "@",
		TTL:    time.Duration(30) * time.Second,
		Target: "ns1.example.com",
	},
	libdns.SRV{
		Service:   "service",
		Transport: "proto",
		Name:      "record-srv",
		TTL:       time.Duration(30) * time.Second,
		Priority:  1,
		Weight:    10,
		Port:      5269,
		Target:    "app.example.com",
	},
	libdns.TXT{
		Name: "record-txt",
		TTL:  time.Duration(30) * time.Second,
		Text: "TEST VALUE",
	},
	libdns.RR{
		Type: "PTR",
		Name: "record-ptr",
		TTL:  time.Duration(30) * time.Second,
		Data: "hoge.example.com",
	},
	libdns.RR{
		Type: "SOA",
		Name: "@",
		TTL:  time.Duration(30) * time.Second,
		Data: "ns1.example.com hostmaster.example.com 1 7200 900 1209600 86400",
	},
}

func chunkBy[T any](items []T, size int) (chunks [][]T) {
	for size < len(items) {
		items, chunks = items[size:], append(chunks, items[0:size:size])
	}
	return append(chunks, items)
}

func getFakeRecordSetsServer() fake.RecordSetsServer {
	return fake.RecordSetsServer{
		NewListByDNSZonePager: func(resourceGroupName string, zoneName string, options *armdns.RecordSetsClientListByDNSZoneOptions) (resp azfake.PagerResponder[armdns.RecordSetsClientListByDNSZoneResponse]) {
			// Responce fake records in chunks of 3
			for _, fakeRecordsChunk := range chunkBy(azureFakeRecords, 3) {
				values := []*armdns.RecordSet{}
				for _, v := range fakeRecordsChunk {
					record := v
					values = append(values, &record)
				}
				page := armdns.RecordSetsClientListByDNSZoneResponse{
					RecordSetListResult: armdns.RecordSetListResult{
						Value: values,
					},
				}
				resp.AddPage(http.StatusOK, page, nil)
			}
			return
		},
		CreateOrUpdate: func(ctx context.Context, resourceGroupName string, zoneName string, relativeRecordSetName string, recordType armdns.RecordType, parameters armdns.RecordSet, options *armdns.RecordSetsClientCreateOrUpdateOptions) (resp azfake.Responder[armdns.RecordSetsClientCreateOrUpdateResponse], errResp azfake.ErrorResponder) {
			parameters.Name = to.Ptr(relativeRecordSetName)
			parameters.Type = to.Ptr(string(recordType))
			parameters.Etag = to.Ptr("ETAG_" + string(recordType))
			response := armdns.RecordSetsClientCreateOrUpdateResponse{
				RecordSet: parameters,
			}
			resp.SetResponse(http.StatusOK, response, nil)
			return
		},
		Get: func(ctx context.Context, resourceGroupName string, zoneName string, relativeRecordSetName string, recordType armdns.RecordType, options *armdns.RecordSetsClientGetOptions) (resp azfake.Responder[armdns.RecordSetsClientGetResponse], errResp azfake.ErrorResponder) {
			for _, v := range azureFakeRecords {
				if *v.Name == relativeRecordSetName && strings.HasSuffix(*v.Type, "/"+string(recordType)) {
					resp.SetResponse(http.StatusOK, armdns.RecordSetsClientGetResponse{RecordSet: v}, nil)
					return
				}
			}
			errResp.SetResponseError(http.StatusNotFound, "NotFound")
			return
		},
		Delete: func(ctx context.Context, resourceGroupName string, zoneName string, relativeRecordSetName string, recordType armdns.RecordType, options *armdns.RecordSetsClientDeleteOptions) (resp azfake.Responder[armdns.RecordSetsClientDeleteResponse], errResp azfake.ErrorResponder) {
			response := armdns.RecordSetsClientDeleteResponse{}
			resp.SetResponse(http.StatusOK, response, nil)
			return
		},
	}
}

func getFakeProvider() (provider Provider) {
	fakeRecordSetsServer := getFakeRecordSetsServer()
	azureClient, _ := armdns.NewRecordSetsClient("fake-subscription-id", &azfake.TokenCredential{}, &arm.ClientOptions{
		ClientOptions: azcore.ClientOptions{
			Transport: fake.NewRecordSetsServerTransport(&fakeRecordSetsServer),
		},
	})
	provider = Provider{
		SubscriptionId:    "fake-subscription-id",
		ResourceGroupName: "fake-resource-group-name",
		client: Client{
			azureClient: azureClient,
		},
	}
	return
}

func Test_newCredentials(t *testing.T) {
	// A non-https value makes creating the credentials fail.
	t.Setenv("AZURE_AUTHORITY_HOST", "")
	tokenFile := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenFile, []byte("token"), 0o600); err != nil {
		t.Fatalf("%s", err)
	}
	setWorkloadIdentityEnv := func(t *testing.T) {
		t.Setenv("AZURE_TENANT_ID", "tenant")
		t.Setenv("AZURE_CLIENT_ID", "client")
		t.Setenv("AZURE_FEDERATED_TOKEN_FILE", tokenFile)
	}
	clearWorkloadIdentityEnv := func(t *testing.T) {
		for _, name := range []string{"AZURE_TENANT_ID", "AZURE_CLIENT_ID", "AZURE_FEDERATED_TOKEN_FILE"} {
			t.Setenv(name, "")
		}
	}
	typeNames := func(credentials []azcore.TokenCredential) (names []string) {
		for _, c := range credentials {
			names = append(names, fmt.Sprintf("%T", c))
		}
		return names
	}

	tests := []struct {
		name     string
		provider *Provider
		env      func(t *testing.T)
		want     []string
	}{{
		name:     "managed identity only",
		provider: &Provider{},
		env:      clearWorkloadIdentityEnv,
		want:     []string{"*azidentity.ManagedIdentityCredential"},
	}, {
		name:     "workload identity before managed identity",
		provider: &Provider{},
		env:      setWorkloadIdentityEnv,
		want:     []string{"*azidentity.WorkloadIdentityCredential", "*azidentity.ManagedIdentityCredential"},
	}, {
		name:     "client secret takes precedence",
		provider: &Provider{TenantId: "tenant", ClientId: "client", ClientSecret: "secret"},
		env:      setWorkloadIdentityEnv,
		want:     []string{"*azidentity.ClientSecretCredential"},
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.env(t)
			credentials, err := tt.provider.newCredentials()
			if err != nil {
				t.Fatalf("%s", err)
			}
			if diff := cmp.Diff(typeNames(credentials), tt.want); diff != "" {
				t.Errorf("diff: %s", diff)
			}
		})
	}
}

func Test_getRecords(t *testing.T) {
	provider := getFakeProvider()
	records, err := provider.getRecords(context.TODO(), "example.com.")
	if err != nil {
		t.Errorf("%s", err)
	}
	for _, record := range records {
		t.Log(record)
	}
	if len(records) != len(azureFakeRecords) {
		t.Errorf("got: %d, want: %d", len(records), len(azureFakeRecords))
	}
}

func Test_createRecord(t *testing.T) {
	provider := getFakeProvider()
	record, err := provider.createRecord(context.TODO(), "example.com.", libdnsFakeRecords[0])
	t.Log(record)
	if err != nil {
		t.Errorf("%s", err)
	}
}

func Test_SetRecords_ttl(t *testing.T) {
	txt := func(ttl time.Duration, text string) libdns.Record {
		return libdns.TXT{Name: "t", TTL: ttl, Text: text}
	}
	tests := []struct {
		name    string
		records []libdns.Record
		want    int64
	}{
		{name: "lowest", records: []libdns.Record{txt(time.Hour, "a"), txt(time.Minute, "b")}, want: 60},
		{name: "unspecified first", records: []libdns.Record{txt(0, "a"), txt(time.Minute, "b")}, want: 60},
		{name: "unspecified last", records: []libdns.Record{txt(time.Minute, "a"), txt(0, "b")}, want: 60},
		{name: "all unspecified", records: []libdns.Record{txt(0, "a"), txt(0, "b")}, want: 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			z := newFakeZoneServer()
			p := getFakeZoneProvider(t, z)
			if _, err := p.SetRecords(context.TODO(), "example.com.", tt.records); err != nil {
				t.Fatalf("%s", err)
			}
			if got := *z.sets[setKey("t", armdns.RecordTypeTXT)].Properties.TTL; got != tt.want {
				t.Errorf("got TTL %d, want %d", got, tt.want)
			}
		})
	}
}

func Test_SetRecords_values(t *testing.T) {
	z := newFakeZoneServer()
	p := getFakeZoneProvider(t, z)
	ctx := context.TODO()
	a := libdns.TXT{Name: "_acme-challenge", TTL: time.Hour, Text: "a"}
	b := libdns.TXT{Name: "_acme-challenge.example.com.", TTL: time.Minute, Text: "b"}
	other := libdns.TXT{Name: "other", TTL: time.Hour, Text: "c"}

	if _, err := p.AppendRecords(ctx, "example.com.", []libdns.Record{fakeChallengeRecord("old")}); err != nil {
		t.Fatalf("%s", err)
	}
	got, err := p.SetRecords(ctx, "example.com.", []libdns.Record{a, other, b})
	if err != nil {
		t.Fatalf("%s", err)
	}
	if diff := cmp.Diff(got, []libdns.Record{a, b, other}); diff != "" {
		t.Errorf("returned records diff: %s", diff)
	}
	if diff := cmp.Diff(z.txtValues("_acme-challenge"), []string{"a", "b"}); diff != "" {
		t.Errorf("values diff: %s", diff)
	}
	if diff := cmp.Diff(z.txtValues("other"), []string{"c"}); diff != "" {
		t.Errorf("other values diff: %s", diff)
	}
	if ttl := *z.sets[setKey("_acme-challenge", armdns.RecordTypeTXT)].Properties.TTL; ttl != 60 {
		t.Errorf("got TTL %d, want the lowest TTL, 60", ttl)
	}

	// Setting fewer values removes the others.
	if _, err := p.SetRecords(ctx, "example.com.", []libdns.Record{a}); err != nil {
		t.Fatalf("%s", err)
	}
	if diff := cmp.Diff(z.txtValues("_acme-challenge"), []string{"a"}); diff != "" {
		t.Errorf("values diff: %s", diff)
	}

	// A record set holds a single CNAME.
	cname := libdns.CNAME{Name: "www", TTL: time.Minute, Target: "a.example.com."}
	otherCname := libdns.CNAME{Name: "www", TTL: time.Minute, Target: "b.example.com."}
	if _, err := p.SetRecords(ctx, "example.com.", []libdns.Record{cname, otherCname}); err == nil {
		t.Error("setting two CNAME values succeeded")
	}
}

func Test_deleteRecord(t *testing.T) {
	provider := getFakeProvider()
	deleted, err := provider.deleteRecord(context.TODO(), "example.com.", libdnsFakeRecords[0])
	t.Log(deleted)
	if err != nil {
		t.Errorf("%s", err)
	}
}

func Test_generateRecordSetName(t *testing.T) {
	t.Run("name=\"\"", func(t *testing.T) {
		got := generateRecordSetName("", "example.com.")
		want := "@"
		if diff := cmp.Diff(got, want); diff != "" {
			t.Errorf("diff: %s", diff)
		}
	})
	t.Run("name=@", func(t *testing.T) {
		got := generateRecordSetName("@", "example.com.")
		want := "@"
		if diff := cmp.Diff(got, want); diff != "" {
			t.Errorf("diff: %s", diff)
		}
	})
	t.Run("name=test", func(t *testing.T) {
		got := generateRecordSetName("test", "example.com.")
		want := "test"
		if diff := cmp.Diff(got, want); diff != "" {
			t.Errorf("diff: %s", diff)
		}
	})
	t.Run("name=test.example.com", func(t *testing.T) {
		got := generateRecordSetName("test.example.com", "example.com.")
		want := "test"
		if diff := cmp.Diff(got, want); diff != "" {
			t.Errorf("diff: %s", diff)
		}
	})
	t.Run("name=test.example.com.", func(t *testing.T) {
		got := generateRecordSetName("test.example.com.", "example.com.")
		want := "test"
		if diff := cmp.Diff(got, want); diff != "" {
			t.Errorf("diff: %s", diff)
		}
	})
	t.Run("name=example.com.", func(t *testing.T) {
		got := generateRecordSetName("example.com.", "example.com.")
		want := "@"
		if diff := cmp.Diff(got, want); diff != "" {
			t.Errorf("diff: %s", diff)
		}
	})
}

func Test_convertStringToRecordType(t *testing.T) {
	typeNames := []string{"A", "AAAA", "CAA", "CNAME", "MX", "NS", "SRV", "TXT", "PTR", "SOA"}
	for _, typeName := range typeNames {
		t.Run("type="+typeName, func(t *testing.T) {
			recordType, _ := convertStringToRecordType(typeName)
			got := fmt.Sprintf("%T:%v", recordType, recordType)
			want := "armdns.RecordType:" + typeName
			if diff := cmp.Diff(got, want); diff != "" {
				t.Errorf("diff: %s", diff)
			}
		})
	}
	t.Run("type=ERR", func(t *testing.T) {
		_, err := convertStringToRecordType("ERR")
		got := err.Error()
		want := "the type ERR cannot be interpreted"
		if diff := cmp.Diff(got, want); diff != "" {
			t.Errorf("diff: %s", diff)
		}
	})
}

func Test_convertAzureRecordSetsToLibdnsRecords(t *testing.T) {
	t.Run("type=supported", func(t *testing.T) {
		azureRecordSets := []*armdns.RecordSet{}
		for _, v := range azureFakeRecords {
			record := v
			azureRecordSets = append(azureRecordSets, &record)
		}
		got, _ := convertAzureRecordSetsToLibdnsRecords(azureRecordSets)
		want := libdnsFakeRecords
		if diff := cmp.Diff(got, want, cmpopts.EquateComparable(netip.Addr{})); diff != "" {
			t.Errorf("diff: %s", diff)
		}
	})
	t.Run("type=unsupported", func(t *testing.T) {
		azureRecordSets := []*armdns.RecordSet{{
			Type: to.Ptr("Microsoft.Network/dnszones/ERR"),
		}}
		_, err := convertAzureRecordSetsToLibdnsRecords(azureRecordSets)
		got := err.Error()
		want := "the type ERR cannot be interpreted"
		if diff := cmp.Diff(got, want); diff != "" {
			t.Errorf("diff: %s", diff)
		}
	})
}

func Test_convertLibdnsRecordToAzureRecordSet(t *testing.T) {
	t.Run("type=supported", func(t *testing.T) {
		var got []armdns.RecordSet
		for _, libdnsRecord := range libdnsFakeRecords {
			convertedRecord, _ := convertLibdnsRecordToAzureRecordSet(libdnsRecord)
			got = append(got, convertedRecord)
		}
		want := azureFakeRecords
		opts := []cmp.Option{
			cmpopts.IgnoreFields(armdns.RecordSet{}, "Name", "Type", "Etag"),
			cmpopts.IgnoreFields(armdns.RecordSetProperties{}, "Fqdn"),
		}
		if diff := cmp.Diff(got, want, opts...); diff != "" {
			t.Errorf("diff: %s", diff)
		}
	})
	t.Run("type=unsupported", func(t *testing.T) {
		libdnsRecords := []libdns.Record{
			libdns.RR{
				Type: "ERR",
				Name: "test",
				TTL:  time.Duration(30) * time.Second,
				Data: "test",
			},
		}
		_, err := convertLibdnsRecordToAzureRecordSet(libdnsRecords[0])
		got := err.Error()
		want := "the type ERR cannot be interpreted"
		if diff := cmp.Diff(got, want); diff != "" {
			t.Errorf("diff: %s", diff)
		}
	})
}

// fakeZoneServer is an in-memory Azure DNS zone that honors If-Match and
// If-None-Match like Azure does.
type fakeZoneServer struct {
	mu   sync.Mutex
	sets map[string]armdns.RecordSet
	etag int
	// beforeWrite, if set, runs before each write is checked, to simulate a
	// concurrent change.
	beforeWrite func()
}

func newFakeZoneServer() *fakeZoneServer {
	return &fakeZoneServer{sets: map[string]armdns.RecordSet{}}
}

func setKey(name string, typ armdns.RecordType) string { return name + "/" + string(typ) }

// put stores a record set the way another client would.
func (z *fakeZoneServer) put(name string, typ armdns.RecordType, props *armdns.RecordSetProperties) {
	z.etag++
	// Like Azure, return an empty target resource for record sets that
	// aren't aliases.
	stored := *props
	if stored.TargetResource == nil {
		stored.TargetResource = &armdns.SubResource{}
	}
	z.sets[setKey(name, typ)] = armdns.RecordSet{
		Name:       to.Ptr(name),
		Type:       to.Ptr("Microsoft.Network/dnszones/" + string(typ)),
		Etag:       to.Ptr(fmt.Sprint(z.etag)),
		Properties: &stored,
	}
}

// preconditionFailed reports whether a write with these conditions must be
// rejected.
func (z *fakeZoneServer) preconditionFailed(key string, ifMatch, ifNoneMatch *string) bool {
	if z.beforeWrite != nil {
		f := z.beforeWrite
		z.beforeWrite = nil
		f()
	}
	cur, exists := z.sets[key]
	if val(ifNoneMatch) == "*" && exists {
		return true
	}
	return ifMatch != nil && (!exists || *ifMatch != *cur.Etag)
}

func (z *fakeZoneServer) server() *fake.RecordSetsServer {
	return &fake.RecordSetsServer{
		Get: func(ctx context.Context, resourceGroupName, zoneName, name string, typ armdns.RecordType, options *armdns.RecordSetsClientGetOptions) (resp azfake.Responder[armdns.RecordSetsClientGetResponse], errResp azfake.ErrorResponder) {
			z.mu.Lock()
			defer z.mu.Unlock()
			set, ok := z.sets[setKey(name, typ)]
			if !ok {
				errResp.SetResponseError(http.StatusNotFound, "NotFound")
				return
			}
			resp.SetResponse(http.StatusOK, armdns.RecordSetsClientGetResponse{RecordSet: set}, nil)
			return
		},
		CreateOrUpdate: func(ctx context.Context, resourceGroupName, zoneName, name string, typ armdns.RecordType, parameters armdns.RecordSet, options *armdns.RecordSetsClientCreateOrUpdateOptions) (resp azfake.Responder[armdns.RecordSetsClientCreateOrUpdateResponse], errResp azfake.ErrorResponder) {
			z.mu.Lock()
			defer z.mu.Unlock()
			key := setKey(name, typ)
			var ifMatch, ifNoneMatch *string
			if options != nil {
				ifMatch, ifNoneMatch = options.IfMatch, options.IfNoneMatch
			}
			if z.preconditionFailed(key, ifMatch, ifNoneMatch) {
				errResp.SetResponseError(http.StatusPreconditionFailed, "PreconditionFailed")
				return
			}
			z.put(name, typ, parameters.Properties)
			resp.SetResponse(http.StatusOK, armdns.RecordSetsClientCreateOrUpdateResponse{RecordSet: z.sets[key]}, nil)
			return
		},
		Delete: func(ctx context.Context, resourceGroupName, zoneName, name string, typ armdns.RecordType, options *armdns.RecordSetsClientDeleteOptions) (resp azfake.Responder[armdns.RecordSetsClientDeleteResponse], errResp azfake.ErrorResponder) {
			z.mu.Lock()
			defer z.mu.Unlock()
			key := setKey(name, typ)
			if z.preconditionFailed(key, options.IfMatch, nil) {
				errResp.SetResponseError(http.StatusPreconditionFailed, "PreconditionFailed")
				return
			}
			delete(z.sets, key)
			resp.SetResponse(http.StatusOK, armdns.RecordSetsClientDeleteResponse{}, nil)
			return
		},
	}
}

// txtValues returns the TXT values of a record set, nil if it doesn't exist.
func (z *fakeZoneServer) txtValues(name string) []string {
	z.mu.Lock()
	defer z.mu.Unlock()
	set, ok := z.sets[setKey(name, armdns.RecordTypeTXT)]
	if !ok {
		return nil
	}
	values := []string{}
	for _, r := range set.Properties.TxtRecords {
		for _, v := range r.Value {
			values = append(values, *v)
		}
	}
	slices.Sort(values)
	return values
}

// newZoneProvider returns a provider backed by z. Each provider has its own
// mutex, like separate processes.
func getFakeZoneProvider(t *testing.T, z *fakeZoneServer) *Provider {
	t.Helper()
	client, err := armdns.NewRecordSetsClient("sub", &azfake.TokenCredential{}, &arm.ClientOptions{
		ClientOptions: azcore.ClientOptions{Transport: fake.NewRecordSetsServerTransport(z.server())},
	})
	if err != nil {
		t.Fatalf("%s", err)
	}
	return &Provider{SubscriptionId: "sub", ResourceGroupName: "rg", client: Client{azureClient: client}}
}

// fakeChallengeRecord returns an ACME challenge record with the given value.
func fakeChallengeRecord(text string) libdns.Record {
	return libdns.TXT{Name: "_acme-challenge", TTL: time.Minute, Text: text}
}

func Test_modifyRecordSet(t *testing.T) {
	type step struct {
		append bool
		text   string
		want   []string
	}
	tests := []struct {
		name  string
		steps []step
	}{{
		name: "apex and wildcard challenges share a record set",
		steps: []step{
			{append: true, text: "apex", want: []string{"apex"}},
			{append: true, text: "wildcard", want: []string{"apex", "wildcard"}},
			{append: false, text: "apex", want: []string{"wildcard"}},
			{append: false, text: "wildcard", want: nil},
		},
	}, {
		name: "appending an existing value keeps one copy",
		steps: []step{
			{append: true, text: "a", want: []string{"a"}},
			{append: true, text: "a", want: []string{"a"}},
		},
	}, {
		name: "deleting a missing value changes nothing",
		steps: []step{
			{append: false, text: "a", want: nil},
			{append: true, text: "a", want: []string{"a"}},
			{append: false, text: "b", want: []string{"a"}},
		},
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			z := newFakeZoneServer()
			p := getFakeZoneProvider(t, z)
			for i, s := range tt.steps {
				var err error
				if s.append {
					_, err = p.AppendRecords(context.TODO(), "example.com.", []libdns.Record{fakeChallengeRecord(s.text)})
				} else {
					_, err = p.DeleteRecords(context.TODO(), "example.com.", []libdns.Record{fakeChallengeRecord(s.text)})
				}
				if err != nil {
					t.Fatalf("step %d: %s", i, err)
				}
				got := z.txtValues("_acme-challenge")
				if diff := cmp.Diff(got, s.want); diff != "" {
					t.Fatalf("step %d: diff: %s", i, diff)
				}
			}
		})
	}
}

func Test_modifyRecordSet_concurrentChange(t *testing.T) {
	tests := []struct {
		name   string
		append bool
		seed   []string
		want   []string
	}{
		{name: "append", append: true, seed: []string{"other"}, want: []string{"mine", "other", "theirs"}},
		{name: "delete", append: false, seed: []string{"mine", "other"}, want: []string{"other", "theirs"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			z := newFakeZoneServer()
			p := getFakeZoneProvider(t, z)
			seed := []*armdns.TxtRecord{}
			for _, v := range tt.seed {
				seed = append(seed, &armdns.TxtRecord{Value: []*string{to.Ptr(v)}})
			}
			z.put("_acme-challenge", armdns.RecordTypeTXT, &armdns.RecordSetProperties{
				TTL:        to.Ptr[int64](60),
				TxtRecords: seed,
			})
			z.beforeWrite = func() {
				set := z.sets[setKey("_acme-challenge", armdns.RecordTypeTXT)]
				props := copyRecordSetProperties(set.Properties)
				props.TxtRecords = append(props.TxtRecords, &armdns.TxtRecord{Value: []*string{to.Ptr("theirs")}})
				z.put("_acme-challenge", armdns.RecordTypeTXT, props)
			}

			var err error
			if tt.append {
				_, err = p.AppendRecords(context.TODO(), "example.com.", []libdns.Record{fakeChallengeRecord("mine")})
			} else {
				_, err = p.DeleteRecords(context.TODO(), "example.com.", []libdns.Record{fakeChallengeRecord("mine")})
			}
			if err != nil {
				t.Fatalf("%s", err)
			}
			got := z.txtValues("_acme-challenge")
			if diff := cmp.Diff(got, tt.want); diff != "" {
				t.Errorf("diff: %s", diff)
			}
		})
	}
}

func Test_modifyRecordSet_parallelAppends(t *testing.T) {
	z := newFakeZoneServer()
	var want []string
	var wg sync.WaitGroup
	for i := range 10 {
		text := fmt.Sprint("value", i)
		want = append(want, text)
		p := getFakeZoneProvider(t, z)
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := p.AppendRecords(context.TODO(), "example.com.", []libdns.Record{fakeChallengeRecord(text)}); err != nil {
				t.Errorf("%s", err)
			}
		}()
	}
	wg.Wait()
	slices.Sort(want)
	got := z.txtValues("_acme-challenge")
	if diff := cmp.Diff(got, want); diff != "" {
		t.Errorf("diff: %s", diff)
	}
}

func Test_createRecord_existingCNAME(t *testing.T) {
	z := newFakeZoneServer()
	p := getFakeZoneProvider(t, z)
	rec := libdns.CNAME{Name: "www", TTL: time.Minute, Target: "a.example.com."}
	if _, err := p.AppendRecords(context.TODO(), "example.com.", []libdns.Record{rec}); err != nil {
		t.Fatalf("%s", err)
	}
	rec.Target = "b.example.com."
	if _, err := p.AppendRecords(context.TODO(), "example.com.", []libdns.Record{rec}); err == nil {
		t.Error("appending a second CNAME succeeded")
	}
}

func Test_AppendRecords_returnsAdded(t *testing.T) {
	z := newFakeZoneServer()
	p := getFakeZoneProvider(t, z)
	a, b := fakeChallengeRecord("a"), fakeChallengeRecord("b")
	steps := []struct {
		name    string
		records []libdns.Record
		want    []libdns.Record
	}{
		{name: "new value", records: []libdns.Record{a}, want: []libdns.Record{a}},
		{name: "existing value", records: []libdns.Record{a}, want: nil},
		{name: "existing and new value", records: []libdns.Record{a, b}, want: []libdns.Record{b}},
	}
	for _, s := range steps {
		got, err := p.AppendRecords(context.TODO(), "example.com.", s.records)
		if err != nil {
			t.Fatalf("%s: %s", s.name, err)
		}
		if diff := cmp.Diff(got, s.want); diff != "" {
			t.Errorf("%s: diff: %s", s.name, diff)
		}
	}
}

func Test_DeleteRecords_matching(t *testing.T) {
	cname := libdns.CNAME{Name: "www", TTL: time.Minute, Target: "a.example.com."}
	otherCname := libdns.CNAME{Name: "www", TTL: time.Minute, Target: "b.example.com."}
	tests := []struct {
		name    string
		records []libdns.Record
		delete  libdns.Record
		deleted bool
		want    []string
	}{{
		name:    "missing record set",
		delete:  fakeChallengeRecord("a"),
		deleted: false,
		want:    nil,
	}, {
		name:    "missing value",
		records: []libdns.Record{fakeChallengeRecord("a")},
		delete:  fakeChallengeRecord("b"),
		deleted: false,
		want:    []string{"a"},
	}, {
		name:    "other TTL",
		records: []libdns.Record{fakeChallengeRecord("a"), fakeChallengeRecord("b")},
		delete:  libdns.TXT{Name: "_acme-challenge", TTL: time.Hour, Text: "a"},
		deleted: true,
		want:    []string{"b"},
	}, {
		name:    "no data deletes the record set",
		records: []libdns.Record{fakeChallengeRecord("a"), fakeChallengeRecord("b")},
		delete:  libdns.RR{Name: "_acme-challenge", Type: "TXT"},
		deleted: true,
		want:    nil,
	}, {
		name:    "no data and missing record set",
		delete:  libdns.RR{Name: "_acme-challenge", Type: "TXT"},
		deleted: false,
		want:    nil,
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			z := newFakeZoneServer()
			p := getFakeZoneProvider(t, z)
			if len(tt.records) > 0 {
				if _, err := p.AppendRecords(context.TODO(), "example.com.", tt.records); err != nil {
					t.Fatalf("%s", err)
				}
			}
			got, err := p.DeleteRecords(context.TODO(), "example.com.", []libdns.Record{tt.delete})
			if err != nil {
				t.Fatalf("%s", err)
			}
			var want []libdns.Record
			if tt.deleted {
				want = []libdns.Record{tt.delete}
			}
			if diff := cmp.Diff(got, want); diff != "" {
				t.Errorf("deleted records diff: %s", diff)
			}
			if diff := cmp.Diff(z.txtValues("_acme-challenge"), tt.want); diff != "" {
				t.Errorf("remaining values diff: %s", diff)
			}
		})
	}

	t.Run("CNAME", func(t *testing.T) {
		z := newFakeZoneServer()
		p := getFakeZoneProvider(t, z)
		if _, err := p.AppendRecords(context.TODO(), "example.com.", []libdns.Record{cname}); err != nil {
			t.Fatalf("%s", err)
		}
		deleted, err := p.DeleteRecords(context.TODO(), "example.com.", []libdns.Record{otherCname})
		if err != nil || len(deleted) != 0 {
			t.Errorf("deleting a CNAME with another target: got %v, %v; want nothing", deleted, err)
		}
		if _, ok := z.sets[setKey("www", armdns.RecordTypeCNAME)]; !ok {
			t.Fatal("the CNAME was deleted")
		}
		deleted, err = p.DeleteRecords(context.TODO(), "example.com.", []libdns.Record{cname})
		if err != nil || len(deleted) != 1 {
			t.Errorf("deleting the CNAME: got %v, %v; want the CNAME", deleted, err)
		}
		if _, ok := z.sets[setKey("www", armdns.RecordTypeCNAME)]; ok {
			t.Error("the CNAME was not deleted")
		}
	})
}
