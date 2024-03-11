package main

import (
	"context"
	"fmt"
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
		TenantId:          os.Getenv("AZURE_TENANT_ID"),
		ClientId:          os.Getenv("AZURE_CLIENT_ID"),
		ClientSecret:      os.Getenv("AZURE_CLIENT_SECRET"),
		SubscriptionId:    os.Getenv("AZURE_SUBSCRIPTION_ID"),
		ResourceGroupName: os.Getenv("AZURE_RESOURCE_GROUP_NAME"),
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
		{
			Type:  "A",
			Name:  "record-a",
			Value: "127.0.0.1",
			TTL:   time.Duration(30) * time.Second,
		},
		{
			Type:  "AAAA",
			Name:  "record-aaaa",
			Value: "::1",
			TTL:   time.Duration(31) * time.Second,
		},
		{
			Type:  "CAA",
			Name:  "record-caa",
			Value: "0 issue 'ca." + zone + "'",
			TTL:   time.Duration(32) * time.Second,
		},
		{
			Type:  "CNAME",
			Name:  "record-cname",
			Value: "www." + zone,
			TTL:   time.Duration(33) * time.Second,
		},
		{
			Type:  "MX",
			Name:  "record-mx",
			Value: "10 mail." + zone,
			TTL:   time.Duration(34) * time.Second,
		},
		// {
		// 	Type:  "NS",
		// 	Name:  "@",
		// 	Value: "ns1.example.com.",
		// 	TTL:   time.Duration(35) * time.Second,
		// },
		{
			Type:  "PTR",
			Name:  "record-ptr",
			Value: "hoge." + zone,
			TTL:   time.Duration(36) * time.Second,
		},
		// {
		// 	Type:  "SOA",
		// 	Name:  "@",
		// 	Value: "ns1.example.com. hostmaster." + zone + " 1 7200 900 1209600 86400",
		// 	TTL:   time.Duration(37) * time.Second,
		// },
		{
			Type:  "SRV",
			Name:  "record-srv",
			Value: "1 10 5269 app." + zone,
			TTL:   time.Duration(38) * time.Second,
		},
		{
			Type:  "TXT",
			Name:  "record-txt",
			Value: "TEST VALUE",
			TTL:   time.Duration(39) * time.Second,
		},
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
