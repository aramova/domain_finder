package main

import (
	"os"
	"testing"
	"time"
)

// mockWhoisProvider provides mock WHOIS data for testing.
func mockWhoisProvider(domain string) (string, error) {
	switch domain {
	case "change.com":
		// This raw text will be parsed by the real ParseWhois function
		return `
Domain Name: change.com
Registrar: New Registrar
Updated Date: 2025-01-02T15:04:05Z
Creation Date: 2024-01-01T00:00:00Z
Registry Expiry Date: 2026-01-01T00:00:00Z
Name Server: ns1.new.com
Name Server: ns2.new.com
Registrant Name: New Owner
`, nil
	case "expiring.com":
		return `
Domain Name: expiring.com
Registry Expiry Date: ` + time.Now().Add(59*time.Minute).Format(time.RFC3339), nil
	default:
		return `
Domain Name: stable.com
Registry Expiry Date: ` + time.Now().Add(100*24*time.Hour).Format(time.RFC3339), nil
	}
}

func TestProcessDomain(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	// --- Setup initial state for 'change.com' ---
	initialRawText := `
Domain Name: change.com
Registrar: Old Registrar
Updated Date: 2025-01-01T15:04:05Z
Creation Date: 2024-01-01T00:00:00Z
Registry Expiry Date: 2025-01-01T00:00:00Z
Name Server: ns1.old.com
Registrant Name: Old Owner
`
	initialParsed, _ := ParseWhois(initialRawText)
	initialRecord := &WhoisRecord{
		DomainName: "change.com",
		CheckedAt:  time.Now().Add(-24 * time.Hour),
		Data:       initialParsed,
		RawText:    initialRawText,
	}
	if err := SaveWhoisRecord(db, initialRecord); err != nil {
		t.Fatalf("Failed to save initial record: %v", err)
	}

	// --- Test Case 1: Change Detected ---
	t.Run("Change Detected", func(t *testing.T) {
		actions, err := ProcessDomain(db, "change.com", mockWhoisProvider)
		if err != nil {
			t.Fatalf("ProcessDomain failed for change.com: %v", err)
		}
		if len(actions) == 0 {
			t.Fatal("Expected at least one action for a changed domain, got 0")
		}
		changeActionFound := false
		for _, action := range actions {
			if action.Type == "change" {
				changeActionFound = true
				if len(action.Changes) < 4 {
					t.Errorf("Expected at least 4 changes, got %d: %v", len(action.Changes), action.Changes)
				}
			}
		}
		if !changeActionFound {
			t.Error("Expected a 'change' action, but none was found")
		}
	})

	// --- Test Case 2: Expiry Warning ---
	t.Run("Expiry Warning", func(t *testing.T) {
		actions, err := ProcessDomain(db, "expiring.com", mockWhoisProvider)
		if err != nil {
			t.Fatalf("ProcessDomain failed for expiring.com: %v", err)
		}
		if len(actions) != 1 {
			t.Fatalf("Expected 1 action for expiring.com, got %d", len(actions))
		}
		action := actions[0]
		if action.Type != "expiry" {
			t.Errorf("Expected action type 'expiry', got '%s'", action.Type)
		}
		if action.MinutesRemaining < 58 || action.MinutesRemaining > 59 {
			t.Errorf("Expected 58 or 59 minutes remaining, got %d", action.MinutesRemaining)
		}
	})

	// --- Test Case 3: Alert Already Active ---
	t.Run("Alert Already Active", func(t *testing.T) {
		// Manually add an active alert for the specific change we expect.
		alert := &Alert{
			DiscordMessageID: "msg123",
			DomainName:       "change.com",
			AlertType:        "change_Expiry Date_Updated Date_Registrant Name_Name Servers",
			IsAcknowledged:   false,
			CreatedAt:        time.Now(),
		}
		if err := SaveActiveAlert(db, alert); err != nil {
			t.Fatalf("Failed to save active alert: %v", err)
		}

		// Re-run processing for change.com
		actions, err := ProcessDomain(db, "change.com", mockWhoisProvider)
		if err != nil {
			t.Fatalf("ProcessDomain failed: %v", err)
		}
		// We expect 0 actions because the specific change alert is already active.
		if len(actions) != 0 {
			t.Fatalf("Expected 0 actions when alert is already active, got %d", len(actions))
		}
	})
}

func TestMain(m *testing.M) {
	// This is to ensure that the test database is cleaned up even if tests panic.
	code := m.Run()
	os.Remove(":memory:") // This might not be strictly necessary for in-memory dbs but is good practice.
	os.Exit(code)
}