package azure

import (
	"context"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/libdns/libdns"
)

var testRecord = libdns.Address{
	Name: "libdns-integration-test",
	IP:   netip.MustParseAddr("127.0.0.1"),
	TTL:  time.Duration(30) * time.Second,
}

func Test_Authentication(t *testing.T) {
	isIntegrationTest := os.Getenv("LIBDNS_AZURE_INTEGRATION_TEST")
	if isIntegrationTest == "" {
		t.Skip("set LIBDNS_AZURE_INTEGRATION_TEST to run integration test")
	}

	t.Run("envs", func(t *testing.T) {
		envs := []string{
			"LIBDNS_AZURE_TENANT_ID",
			"LIBDNS_AZURE_CLIENT_ID",
			"LIBDNS_AZURE_CLIENT_SECRET",
			"LIBDNS_AZURE_SUBSCRIPTION_ID",
			"LIBDNS_AZURE_RESOURCE_GROUP_NAME",
			"LIBDNS_AZURE_DNS_ZONE_FQDN",
		}
		for _, env := range envs {
			value := os.Getenv(env)
			if value == "" {
				t.Fatalf("%v is required", env)
			}
		}
	})

	clientSecretProvider := Provider{
		SubscriptionId:    os.Getenv("LIBDNS_AZURE_SUBSCRIPTION_ID"),
		ResourceGroupName: os.Getenv("LIBDNS_AZURE_RESOURCE_GROUP_NAME"),
		TenantId:          os.Getenv("LIBDNS_AZURE_TENANT_ID"),
		ClientId:          os.Getenv("LIBDNS_AZURE_CLIENT_ID"),
		ClientSecret:      os.Getenv("LIBDNS_AZURE_CLIENT_SECRET"),
	}
	managedIdentityProvider := Provider{
		SubscriptionId:    os.Getenv("LIBDNS_AZURE_SUBSCRIPTION_ID"),
		ResourceGroupName: os.Getenv("LIBDNS_AZURE_RESOURCE_GROUP_NAME"),
	}

	t.Run("auth-clientsecret", func(t *testing.T) {
		_, err := clientSecretProvider.SetRecords(context.TODO(), os.Getenv("LIBDNS_AZURE_DNS_ZONE_FQDN"), []libdns.Record{testRecord})
		if err != nil {
			t.Errorf("%s", err)
		}
	})
	t.Run("auth-managedidentity", func(t *testing.T) {
		_, err := managedIdentityProvider.SetRecords(context.TODO(), os.Getenv("LIBDNS_AZURE_DNS_ZONE_FQDN"), []libdns.Record{testRecord})
		if err != nil {
			t.Errorf("%s", err)
		}
	})
	t.Run("auth-cleanup", func(t *testing.T) {
		_, err := clientSecretProvider.SetRecords(context.TODO(), os.Getenv("LIBDNS_AZURE_DNS_ZONE_FQDN"), []libdns.Record{testRecord})
		if err != nil {
			t.Errorf("%s", err)
		}
	})
}

func Test_GetRecords(t *testing.T) {
	isIntegrationTest := os.Getenv("LIBDNS_AZURE_INTEGRATION_TEST")
	if isIntegrationTest == "" {
		t.Skip("set LIBDNS_AZURE_INTEGRATION_TEST to run integration test")
	}

	provider := Provider{
		SubscriptionId:    os.Getenv("LIBDNS_AZURE_SUBSCRIPTION_ID"),
		ResourceGroupName: os.Getenv("LIBDNS_AZURE_RESOURCE_GROUP_NAME"),
		TenantId:          os.Getenv("LIBDNS_AZURE_TENANT_ID"),
		ClientId:          os.Getenv("LIBDNS_AZURE_CLIENT_ID"),
		ClientSecret:      os.Getenv("LIBDNS_AZURE_CLIENT_SECRET"),
	}

	t.Run("get-prepare", func(t *testing.T) {
		_, err := provider.SetRecords(context.TODO(), os.Getenv("LIBDNS_AZURE_DNS_ZONE_FQDN"), []libdns.Record{testRecord})
		if err != nil {
			t.Errorf("%s", err)
		}
	})
	t.Run("get-success", func(t *testing.T) {
		records, err := provider.GetRecords(context.TODO(), os.Getenv("LIBDNS_AZURE_DNS_ZONE_FQDN"))
		if err != nil {
			t.Errorf("%s", err)
		}
		isExist := false
		for _, record := range records {
			if record.RR().Name == testRecord.Name {
				t.Logf("%v", record)
				isExist = true
			}
		}
		if !isExist {
			t.Errorf("record %s not found", testRecord.Name)
		}
	})
	t.Run("get-cleanup", func(t *testing.T) {
		_, err := provider.DeleteRecords(context.TODO(), os.Getenv("LIBDNS_AZURE_DNS_ZONE_FQDN"), []libdns.Record{testRecord})
		if err != nil {
			t.Errorf("%s", err)
		}
	})
}

func Test_AppendRecords(t *testing.T) {
	isIntegrationTest := os.Getenv("LIBDNS_AZURE_INTEGRATION_TEST")
	if isIntegrationTest == "" {
		t.Skip("set LIBDNS_AZURE_INTEGRATION_TEST to run integration test")
	}

	provider := Provider{
		SubscriptionId:    os.Getenv("LIBDNS_AZURE_SUBSCRIPTION_ID"),
		ResourceGroupName: os.Getenv("LIBDNS_AZURE_RESOURCE_GROUP_NAME"),
		TenantId:          os.Getenv("LIBDNS_AZURE_TENANT_ID"),
		ClientId:          os.Getenv("LIBDNS_AZURE_CLIENT_ID"),
		ClientSecret:      os.Getenv("LIBDNS_AZURE_CLIENT_SECRET"),
	}

	t.Run("append-prepare", func(t *testing.T) {
		_, err := provider.DeleteRecords(context.TODO(), os.Getenv("LIBDNS_AZURE_DNS_ZONE_FQDN"), []libdns.Record{testRecord})
		if err != nil {
			t.Errorf("%s", err)
		}
	})
	t.Run("append-success", func(t *testing.T) {
		_, err := provider.AppendRecords(context.TODO(), os.Getenv("LIBDNS_AZURE_DNS_ZONE_FQDN"), []libdns.Record{testRecord})
		if err != nil {
			t.Errorf("%s", err)
		}
	})
	t.Run("append-failure", func(t *testing.T) {
		_, err := provider.AppendRecords(context.TODO(), os.Getenv("LIBDNS_AZURE_DNS_ZONE_FQDN"), []libdns.Record{testRecord})
		if err == nil {
			t.Errorf("%s", err)
		}
	})
	t.Run("append-cleanup", func(t *testing.T) {
		_, err := provider.DeleteRecords(context.TODO(), os.Getenv("LIBDNS_AZURE_DNS_ZONE_FQDN"), []libdns.Record{testRecord})
		if err != nil {
			t.Errorf("%s", err)
		}
	})
}

func Test_SetRecords(t *testing.T) {
	isIntegrationTest := os.Getenv("LIBDNS_AZURE_INTEGRATION_TEST")
	if isIntegrationTest == "" {
		t.Skip("set LIBDNS_AZURE_INTEGRATION_TEST to run integration test")
	}

	provider := Provider{
		SubscriptionId:    os.Getenv("LIBDNS_AZURE_SUBSCRIPTION_ID"),
		ResourceGroupName: os.Getenv("LIBDNS_AZURE_RESOURCE_GROUP_NAME"),
		TenantId:          os.Getenv("LIBDNS_AZURE_TENANT_ID"),
		ClientId:          os.Getenv("LIBDNS_AZURE_CLIENT_ID"),
		ClientSecret:      os.Getenv("LIBDNS_AZURE_CLIENT_SECRET"),
	}

	t.Run("set-success", func(t *testing.T) {
		_, err := provider.SetRecords(context.TODO(), os.Getenv("LIBDNS_AZURE_DNS_ZONE_FQDN"), []libdns.Record{testRecord})
		if err != nil {
			t.Errorf("%s", err)
		}
	})
	t.Run("set-cleanup", func(t *testing.T) {
		_, err := provider.DeleteRecords(context.TODO(), os.Getenv("LIBDNS_AZURE_DNS_ZONE_FQDN"), []libdns.Record{testRecord})
		if err != nil {
			t.Errorf("%s", err)
		}
	})
}

func Test_DeleteRecords(t *testing.T) {
	isIntegrationTest := os.Getenv("LIBDNS_AZURE_INTEGRATION_TEST")
	if isIntegrationTest == "" {
		t.Skip("set LIBDNS_AZURE_INTEGRATION_TEST to run integration test")
	}

	provider := Provider{
		SubscriptionId:    os.Getenv("LIBDNS_AZURE_SUBSCRIPTION_ID"),
		ResourceGroupName: os.Getenv("LIBDNS_AZURE_RESOURCE_GROUP_NAME"),
		TenantId:          os.Getenv("LIBDNS_AZURE_TENANT_ID"),
		ClientId:          os.Getenv("LIBDNS_AZURE_CLIENT_ID"),
		ClientSecret:      os.Getenv("LIBDNS_AZURE_CLIENT_SECRET"),
	}

	t.Run("delete-prepare", func(t *testing.T) {
		_, err := provider.SetRecords(context.TODO(), os.Getenv("LIBDNS_AZURE_DNS_ZONE_FQDN"), []libdns.Record{testRecord})
		if err != nil {
			t.Errorf("%s", err)
		}
	})
	t.Run("delete-success", func(t *testing.T) {
		_, err := provider.DeleteRecords(context.TODO(), os.Getenv("LIBDNS_AZURE_DNS_ZONE_FQDN"), []libdns.Record{testRecord})
		if err != nil {
			t.Errorf("%s", err)
		}
	})
}
