package main

import (
	"database/sql"
	"testing"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

// setupTestDB creates a temporary database for testing and returns the connection.
func setupTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("Failed to open in-memory db: %v", err)
	}

	err = InitializeDatabase(db)
	if err != nil {
		t.Fatalf("Failed to initialize database: %v", err)
	}

	return db
}

func TestInitializeDatabase(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	// Check if tables were created
	tables := []string{"domain_history", "active_alerts", "domain_reminders", "monitored_domains"}
	for _, table := range tables {
		var name string
		err := db.QueryRow("SELECT name FROM sqlite_master WHERE type='table' AND name=?", table).Scan(&name)
		if err != nil {
			t.Errorf("Table '%s' was not created: %v", table, err)
		}
	}
}

func TestMonitoredDomains(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	domain1 := "google.com"
	domain2 := "github.com"

	// 1. Add domains
	if err := AddMonitoredDomain(db, domain1); err != nil {
		t.Fatalf("AddMonitoredDomain failed for %s: %v", domain1, err)
	}
	if err := AddMonitoredDomain(db, domain2); err != nil {
		t.Fatalf("AddMonitoredDomain failed for %s: %v", domain2, err)
	}

	// 2. Check if monitored
	isMon, err := IsDomainMonitored(db, domain1)
	if err != nil {
		t.Fatalf("IsDomainMonitored failed: %v", err)
	}
	if !isMon {
		t.Errorf("Expected %s to be monitored, but it wasn't", domain1)
	}

	// 3. Get all monitored domains
	domains, err := GetMonitoredDomains(db)
	if err != nil {
		t.Fatalf("GetMonitoredDomains failed: %v", err)
	}
	if len(domains) != 2 {
		t.Fatalf("Expected 2 monitored domains, got %d", len(domains))
	}

	// 4. Remove a domain
	if err := RemoveMonitoredDomain(db, domain1); err != nil {
		t.Fatalf("RemoveMonitoredDomain failed: %v", err)
	}

	// 5. Check again
	isMon, err = IsDomainMonitored(db, domain1)
	if err != nil {
		t.Fatalf("IsDomainMonitored after remove failed: %v", err)
	}
	if isMon {
		t.Errorf("Expected %s to be unmonitored, but it was", domain1)
	}

	domains, err = GetMonitoredDomains(db)
	if err != nil {
		t.Fatalf("GetMonitoredDomains after remove failed: %v", err)
	}
	if len(domains) != 1 || domains[0] != domain2 {
		t.Errorf("Expected [github.com] after remove, got %v", domains)
	}
}


func TestSaveAndGetLatestWhoisRecord(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	domain := "example.com"
	record := &WhoisRecord{
		DomainName: domain,
		CheckedAt:  time.Now(),
		Data: &WhoisData{
			DomainName:   domain,
			Registrar:    "Test Registrar",
			ExpiryDate:   time.Now().Add(24 * time.Hour),
			NameServers:  []string{"ns1.example.com"},
			RawText:      "raw whois data 1",
		},
	}

	// 1. Test saving a new record
	err := SaveWhoisRecord(db, record)
	if err != nil {
		t.Fatalf("SaveWhoisRecord failed: %v", err)
	}

	// 2. Test retrieving the record
	retrieved, err := GetLatestWhoisRecord(db, domain)
	if err != nil {
		t.Fatalf("GetLatestWhoisRecord failed: %v", err)
	}
	if retrieved == nil {
		t.Fatal("Expected a record, but got nil")
	}

	if retrieved.Data.RawText != record.Data.RawText {
		t.Errorf("Expected raw data '%s', got '%s'", record.Data.RawText, retrieved.Data.RawText)
	}
	if retrieved.Data.Registrar != "Test Registrar" {
		t.Errorf("Expected registrar 'Test Registrar', got '%s'", retrieved.Data.Registrar)
	}

	// 3. Save a newer record and ensure it's the one retrieved
	newerRecord := &WhoisRecord{
		DomainName: domain,
		CheckedAt:  time.Now().Add(1 * time.Hour),
		Data: &WhoisData{
			DomainName:   domain,
			Registrar:    "New Registrar",
			ExpiryDate:   time.Now().Add(48 * time.Hour),
			NameServers:  []string{"ns2.example.com"},
			RawText:      "raw whois data 2",
		},
	}
	err = SaveWhoisRecord(db, newerRecord)
	if err != nil {
		t.Fatalf("SaveWhoisRecord (newer) failed: %v", err)
	}

	retrieved, err = GetLatestWhoisRecord(db, domain)
	if err != nil {
		t.Fatalf("GetLatestWhoisRecord (newer) failed: %v", err)
	}
	if retrieved.Data.RawText != newerRecord.Data.RawText {
		t.Errorf("Expected newer raw data '%s', got '%s'", newerRecord.Data.RawText, retrieved.Data.RawText)
	}
	if retrieved.Data.Registrar != "New Registrar" {
		t.Errorf("Expected registrar 'New Registrar', got '%s'", retrieved.Data.Registrar)
	}
}

func TestGetLatestWhoisRecord_NoRecord(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	retrieved, err := GetLatestWhoisRecord(db, "nonexistent.com")
	if err != nil {
		t.Fatalf("GetLatestWhoisRecord for non-existent domain failed: %v", err)
	}
	if retrieved != nil {
		t.Fatal("Expected nil for a non-existent domain, but got a record")
	}
}

func TestActiveAlerts(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	alert := &Alert{
		DiscordMessageID: "msg123",
		DomainName:       "example.com",
		AlertType:        "expiry_48h",
		IsAcknowledged:   false,
		CreatedAt:        time.Now(),
	}

	// 1. Save a new alert
	err := SaveActiveAlert(db, alert)
	if err != nil {
		t.Fatalf("SaveActiveAlert failed: %v", err)
	}

	// 2. Check if it's active and not acknowledged
	isActive, err := IsAlertActive(db, "example.com", "expiry_48h")
	if err != nil {
		t.Fatalf("IsAlertActive failed: %v", err)
	}
	if !isActive {
		t.Fatal("Expected alert to be active, but it wasn't")
	}

	// 3. Acknowledge the alert
	err = AcknowledgeAlert(db, "msg123")
	if err != nil {
		t.Fatalf("AcknowledgeAlert failed: %v", err)
	}

	// 4. Check that it is no longer considered "active" for alerting purposes
	isActive, err = IsAlertActive(db, "example.com", "expiry_48h")
	if err != nil {
		t.Fatalf("IsAlertActive after ack failed: %v", err)
	}
	if isActive {
		t.Fatal("Expected alert to be inactive after acknowledgment, but it was active")
	}
}

func TestReminders(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	userID := "user123"
	domain1 := "reminder.com"

	// 1. Add a reminder
	err := AddReminder(db, userID, domain1)
	if err != nil {
		t.Fatalf("AddReminder failed: %v", err)
	}

	// 2. Get reminders for user
	reminders, err := GetRemindersForUser(db, userID)
	if err != nil {
		t.Fatalf("GetRemindersForUser failed: %v", err)
	}
	if len(reminders) != 1 || reminders[0] != domain1 {
		t.Fatalf("Expected [reminder.com], got %v", reminders)
	}

	// 3. Get users to remind for a domain
	users, err := GetUsersToRemindForDomain(db, domain1)
	if err != nil {
		t.Fatalf("GetUsersToRemindForDomain failed: %v", err)
	}
	if len(users) != 1 || users[0] != userID {
		t.Fatalf("Expected [user123], got %v", users)
	}

	// 4. Set alerting status
	err = SetReminderAlertingStatus(db, userID, domain1, true)
	if err != nil {
		t.Fatalf("SetReminderAlertingStatus failed: %v", err)
	}

	// 5. Now, GetUsersToRemindForDomain should return no one
	users, err = GetUsersToRemindForDomain(db, domain1)
	if err != nil {
		t.Fatalf("GetUsersToRemindForDomain after alerting failed: %v", err)
	}
	if len(users) != 0 {
		t.Fatalf("Expected no users to remind when alerting is active, got %v", users)
	}

	// 6. Deactivate the alerting reminder
	deactivatedDomain, err := DeactivateAlertingReminderForUser(db, userID)
	if err != nil {
		t.Fatalf("DeactivateAlertingReminderForUser failed: %v", err)
	}
	if deactivatedDomain != domain1 {
		t.Errorf("Expected deactivated domain to be '%s', got '%s'", domain1, deactivatedDomain)
	}

	// 7. Check that the reminder is no longer active
	reminders, err = GetRemindersForUser(db, userID)
	if err != nil {
		t.Fatalf("GetRemindersForUser after deactivation failed: %v", err)
	}
	if len(reminders) != 0 {
		t.Fatalf("Expected no active reminders after deactivation, got %v", reminders)
	}
}

// TestSQLInjection is a security test to ensure that user-provided domain
// names cannot be used to perform SQL injection attacks.
func TestSQLInjection(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	// This string is a common SQL injection payload. If the code is vulnerable,
	// this could delete the 'monitored_domains' table.
	maliciousDomain := "'; DROP TABLE monitored_domains; --"

	// Attempt to add the malicious domain.
	// We expect this to succeed because the input should be treated as a literal string.
	if err := AddMonitoredDomain(db, maliciousDomain); err != nil {
		t.Fatalf("AddMonitoredDomain failed with a potentially malicious string: %v", err)
	}

	// Verify that the malicious domain was added literally.
	isMonitored, err := IsDomainMonitored(db, maliciousDomain)
	if err != nil {
		t.Fatalf("IsDomainMonitored failed: %v", err)
	}
	if !isMonitored {
		t.Error("The malicious domain was not added to the database as a literal string.")
	}

	// The most important check: verify that the 'monitored_domains' table still exists.
	// If the injection was successful, this query will fail.
	var name string
	err = db.QueryRow("SELECT name FROM sqlite_master WHERE type='table' AND name='monitored_domains'").Scan(&name)
	if err != nil {
		t.Fatalf("The 'monitored_domains' table appears to have been dropped, SQL injection likely occurred: %v", err)
	}
	if name != "monitored_domains" {
		t.Fatal("The 'monitored_domains' table was not found after attempting injection.")
	}
}
