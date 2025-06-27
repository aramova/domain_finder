package main

import (
	"testing"
	"time"
)

// sampleGoogleWhois provides a sample WHOIS record for google.com
func sampleGoogleWhois() string {
	return `
   Domain Name: GOOGLE.COM
   Registry Domain ID: 2138514_DOMAIN_COM-VRSN
   Registrar WHOIS Server: whois.markmonitor.com
   Registrar URL: http://www.markmonitor.com
   Updated Date: 2023-09-07T19:36:43Z
   Creation Date: 1997-09-15T04:00:00Z
   Registry Expiry Date: 2028-09-14T04:00:00Z
   Registrar: MarkMonitor Inc.
   Registrar IANA ID: 292
   Registrant Name: Google LLC
   Name Server: NS1.GOOGLE.COM
   Name Server: NS2.GOOGLE.COM
   Name Server: NS3.GOOGLE.COM
   Name Server: NS4.GOOGLE.COM
`
}

func TestParseWhois(t *testing.T) {
	rawText := sampleGoogleWhois()
	data, err := ParseWhois(rawText)
	if err != nil {
		t.Fatalf("ParseWhois failed: %v", err)
	}

	if data.DomainName != "google.com" {
		t.Errorf("Expected DomainName 'google.com', got '%s'", data.DomainName)
	}
	if data.Registrar != "MarkMonitor Inc." {
		t.Errorf("Expected Registrar 'MarkMonitor Inc.', got '%s'", data.Registrar)
	}
	if data.RegistrantName != "Google LLC" {
		t.Errorf("Expected RegistrantName 'Google LLC', got '%s'", data.RegistrantName)
	}
	expectedExpiry := time.Date(2028, 9, 14, 4, 0, 0, 0, time.UTC)
	if !data.ExpiryDate.Equal(expectedExpiry) {
		t.Errorf("Expected ExpiryDate %v, got %v", expectedExpiry, data.ExpiryDate)
	}
	if len(data.NameServers) != 4 {
		t.Errorf("Expected 4 name servers, got %d", len(data.NameServers))
	}
}

func TestCompareWhoisRecords(t *testing.T) {
	baseData := &WhoisData{
		ExpiryDate:     time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
		UpdatedDate:    time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
		RegistrantName: "Old Owner",
		NameServers:    []string{"ns1.old.com"},
	}
	baseRecord := &WhoisRecord{Data: baseData}

	testCases := []struct {
		name              string
		newData           *WhoisData
		expectedChanges   []string
		expectDifferences bool
	}{
		{
			name:              "No change",
			newData:           baseData, // Same data
			expectDifferences: false,
		},
		{
			name: "Expiry Date changed",
			newData: &WhoisData{
				ExpiryDate:     baseData.ExpiryDate.AddDate(1, 0, 0),
				UpdatedDate:    baseData.UpdatedDate,
				RegistrantName: baseData.RegistrantName,
				NameServers:    baseData.NameServers,
			},
			expectedChanges:   []string{"Expiry Date"},
			expectDifferences: true,
		},
		{
			name: "Registrant and Name Servers changed",
			newData: &WhoisData{
				ExpiryDate:     baseData.ExpiryDate,
				UpdatedDate:    baseData.UpdatedDate,
				RegistrantName: "New Owner",
				NameServers:    []string{"ns1.new.com"},
			},
			expectedChanges:   []string{"Registrant Name", "Name Servers"},
			expectDifferences: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			newRecord := &WhoisRecord{Data: tc.newData}
			differences, hasDiff := CompareWhoisRecords(baseRecord, newRecord)

			if hasDiff != tc.expectDifferences {
				t.Errorf("Expected differences to be %v, but got %v", tc.expectDifferences, hasDiff)
			}

			if len(differences) != len(tc.expectedChanges) {
				t.Fatalf("Expected %d differences, but got %d: %v", len(tc.expectedChanges), len(differences), differences)
			}

			// Check if the specific changes are correct
			for _, expected := range tc.expectedChanges {
				found := false
				for _, actual := range differences {
					if actual == expected {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("Expected change '%s' not found in differences: %v", expected, differences)
				}
			}
		})
	}
}
