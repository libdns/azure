package main

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"time"

	"github.com/libdns/azure"
	"github.com/libdns/libdns"
)

// main shows how libdns works with Azure DNS.
//
// In this example, the information required for authentication is passed as environment variables.
func main() {

	// Create new provider instance by authenticating using a service principal with a secret.
	// To authenticate using a managed identity, remove TenantId, ClientId, and ClientSecret.
	provider := azure.Provider{
		SubscriptionId:    os.Getenv("AZURE_SUBSCRIPTION_ID"),
		ResourceGroupName: os.Getenv("AZURE_RESOURCE_GROUP_NAME"),
		TenantId:          os.Getenv("AZURE_TENANT_ID"),
		ClientId:          os.Getenv("AZURE_CLIENT_ID"),
		ClientSecret:      os.Getenv("AZURE_CLIENT_SECRET"),
	}
	zone := os.Getenv("AZURE_DNS_ZONE_FQDN")

	// List existing records
	fmt.Printf("(1) List existing records\n")
	currentRecords, err := provider.GetRecords(context.TODO(), zone)
	if err != nil {
		fmt.Printf("%v\n", err)
		return
	}
	for _, record := range currentRecords {
		fmt.Printf("Exists: %v\n", record)
	}

	// Define test records
	testRecords := []libdns.Record{
		libdns.Address{
			Name: "record-a",
			TTL:  time.Duration(30) * time.Second,
			IP:   netip.MustParseAddr("127.0.0.1"),
		},
		libdns.Address{
			Name: "record-aaaa",
			TTL:  time.Duration(31) * time.Second,
			IP:   netip.MustParseAddr("::1"),
		},
		libdns.CAA{
			Name:  "record-caa",
			TTL:   time.Duration(32) * time.Second,
			Flags: 0,
			Tag:   "issue",
			Value: "ca." + zone,
		},
		libdns.CNAME{
			Name:   "record-cname",
			TTL:    time.Duration(33) * time.Second,
			Target: "www." + zone,
		},
		libdns.MX{
			Name:       "record-mx",
			TTL:        time.Duration(34) * time.Second,
			Preference: 10,
			Target:     "mail." + zone,
		},
		// libdns.NS{
		// 	Name:  "@",
		// 	TTL:   time.Duration(35) * time.Second,
		// 	Target: "ns1.example.com.",
		// },
		libdns.SRV{
			Service:   "service",
			Transport: "proto",
			Name:      "record-srv",
			TTL:       time.Duration(38) * time.Second,
			Priority:  1,
			Weight:    10,
			Port:      5269,
			Target:    "app." + zone,
		},
		libdns.TXT{
			Name: "record-txt",
			TTL:  time.Duration(39) * time.Second,
			Text: "TEST VALUE",
		},
		libdns.RR{
			Type: "PTR",
			Name: "record-ptr",
			TTL:  time.Duration(36) * time.Second,
			Data: "hoge." + zone,
		},
		// libdns.RR{
		// 	Type:  "SOA",
		// 	Name:  "@",
		// 	TTL:   time.Duration(37) * time.Second,
		// 	Data: "ns1.example.com. hostmaster." + zone + " 1 7200 900 1209600 86400",
		// },
	}

	// Create new records
	fmt.Printf("(2) Create new records\n")
	createdRecords, err := provider.AppendRecords(context.TODO(), zone, testRecords)
	if err != nil {
		fmt.Printf("%v\n", err)
		return
	}
	for _, record := range createdRecords {
		fmt.Printf("Created: %v\n", record)
	}

	// Update new records
	fmt.Printf("(3) Update newly added records\n")
	updatedRecords, err := provider.SetRecords(context.TODO(), zone, testRecords)
	if err != nil {
		fmt.Printf("%v\n", err)
		return
	}
	for _, record := range updatedRecords {
		fmt.Printf("Updated: %v\n", record)
	}

	// Delete new records
	fmt.Printf("(4) Delete newly added records\n")
	deletedRecords, err := provider.DeleteRecords(context.TODO(), zone, testRecords)
	if err != nil {
		fmt.Printf("%v\n", err)
		return
	}
	for _, record := range deletedRecords {
		fmt.Printf("Deleted: %v\n", record)
	}

}
