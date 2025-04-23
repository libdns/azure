package azure

import (
	"context"
	"fmt"
	"net/http"
	"net/netip"
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

func Test_updateRecord(t *testing.T) {
	provider := getFakeProvider()
	record, err := provider.updateRecord(context.TODO(), "example.com.", libdnsFakeRecords[0])
	t.Log(record)
	if err != nil {
		t.Errorf("%s", err)
	}
}

func Test_deleteRecord(t *testing.T) {
	provider := getFakeProvider()
	record, err := provider.deleteRecord(context.TODO(), "example.com.", libdnsFakeRecords[0])
	t.Log(record)
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
