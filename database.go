package main

import (
	"database/sql"
	"encoding/json"
	"time"
)

// WhoisData holds all the structured information parsed from a WHOIS lookup.
type WhoisData struct {
	DomainName         string    `json:"domain_name"`
	RegistryDomainID   string    `json:"registry_domain_id"`
	Registrar          string    `json:"registrar"`
	UpdatedDate        time.Time `json:"updated_date"`
	CreationDate       time.Time `json:"creation_date"`
	ExpiryDate         time.Time `json:"expiry_date"`
	NameServers        []string  `json:"name_servers"`
	RegistrantName     string    `json:"registrant_name"`
	RegistrantOrg      string    `json:"registrant_org"`
	RawText            string    `json:"raw_text"`
}

// WhoisRecord represents a single snapshot of a domain's WHOIS data in the database.
type WhoisRecord struct {
	ID         int
	DomainName string
	CheckedAt  time.Time
	Data       *WhoisData // The structured data, stored as JSON
	RawText    string     // The raw WHOIS text
}

// Alert represents an active notification sent to Discord.
type Alert struct {
	DiscordMessageID string
	DomainName       string
	AlertType        string
	IsAcknowledged   bool
	CreatedAt        time.Time
}

// InitializeDatabase creates the necessary tables in the database if they don't already exist.
func InitializeDatabase(db *sql.DB) error {
	historyTable := `
	CREATE TABLE IF NOT EXISTS domain_history (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		domain_name TEXT NOT NULL,
		checked_at DATETIME NOT NULL,
		whois_data_json TEXT NOT NULL
	);`
	// This new table will store the full raw text of every WHOIS lookup.
	rawHistoryTable := `
	CREATE TABLE IF NOT EXISTS whois_raw_history (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		domain_name TEXT NOT NULL,
		checked_at DATETIME NOT NULL,
		raw_text TEXT NOT NULL
	);`
	alertsTable := `
	CREATE TABLE IF NOT EXISTS active_alerts (
		discord_message_id TEXT PRIMARY KEY,
		domain_name TEXT NOT NULL,
		alert_type TEXT NOT NULL,
		is_acknowledged BOOLEAN NOT NULL DEFAULT 0,
		created_at DATETIME NOT NULL
	);`
	remindersTable := `
	CREATE TABLE IF NOT EXISTS domain_reminders (
		user_id TEXT NOT NULL,
		domain_name TEXT NOT NULL,
		is_active BOOLEAN NOT NULL DEFAULT 1,
		is_currently_alerting BOOLEAN NOT NULL DEFAULT 0,
		PRIMARY KEY (user_id, domain_name)
	);`
	monitoredDomainsTable := `
	CREATE TABLE IF NOT EXISTS monitored_domains (
		domain_name TEXT PRIMARY KEY NOT NULL
	);`

	if _, err := db.Exec(historyTable); err != nil {
		return err
	}
	if _, err := db.Exec(rawHistoryTable); err != nil {
		return err
	}
	if _, err := db.Exec(alertsTable); err != nil {
		return err
	}
	if _, err := db.Exec(remindersTable); err != nil {
		return err
	}
	if _, err := db.Exec(monitoredDomainsTable); err != nil {
		return err
	}
	return nil
}

// --- Monitored Domain Functions ---

// AddMonitoredDomain adds a new domain to the monitored list in the database.
func AddMonitoredDomain(db *sql.DB, domainName string) error {
	stmt, err := db.Prepare("INSERT OR IGNORE INTO monitored_domains (domain_name) VALUES (?)")
	if err != nil {
		return err
	}
	defer stmt.Close()
	_, err = stmt.Exec(domainName)
	return err
}

// RemoveMonitoredDomain removes a domain from the monitored list.
func RemoveMonitoredDomain(db *sql.DB, domainName string) error {
	stmt, err := db.Prepare("DELETE FROM monitored_domains WHERE domain_name = ?")
	if err != nil {
		return err
	}
	defer stmt.Close()
	_, err = stmt.Exec(domainName)
	return err
}

// GetMonitoredDomains retrieves the full list of domains to check.
func GetMonitoredDomains(db *sql.DB) ([]string, error) {
	rows, err := db.Query("SELECT domain_name FROM monitored_domains")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var domains []string
	for rows.Next() {
		var domain string
		if err := rows.Scan(&domain); err != nil {
			return nil, err
		}
		domains = append(domains, domain)
	}
	return domains, nil
}

// GetDomainsNearingExpiry retrieves domains that are expiring within the specified duration.
func GetDomainsNearingExpiry(db *sql.DB, within time.Duration) ([]string, error) {
	// We need to get the latest record for each domain and check its expiry.
	// This is a bit more complex as we only want to check the *most recent* entry.
	query := `
	SELECT
		t1.domain_name
	FROM
		domain_history t1
	INNER JOIN (
		SELECT
			domain_name,
			MAX(checked_at) AS max_checked_at
		FROM
			domain_history
		GROUP BY
			domain_name
	) t2 ON t1.domain_name = t2.domain_name AND t1.checked_at = t2.max_checked_at
	WHERE
		json_extract(t1.whois_data_json, '$.expiry_date') IS NOT NULL;
	`

	rows, err := db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var domainsNearingExpiry []string
	for rows.Next() {
		var domainName string
		if err := rows.Scan(&domainName); err != nil {
			return nil, err
		}

		// Now, for each domain, get the latest record to check the expiry date
		latestRecord, err := GetLatestWhoisRecord(db, domainName)
		if err != nil {
			return nil, err
		}

		if latestRecord != nil && !latestRecord.Data.ExpiryDate.IsZero() {
			if time.Until(latestRecord.Data.ExpiryDate) < within {
				domainsNearingExpiry = append(domainsNearingExpiry, domainName)
			}
		}
	}
	return domainsNearingExpiry, nil
}


// IsDomainMonitored checks if a domain is already in the database.
func IsDomainMonitored(db *sql.DB, domainName string) (bool, error) {
	var count int
	err := db.QueryRow("SELECT COUNT(*) FROM monitored_domains WHERE domain_name = ?", domainName).Scan(&count)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}


// --- WHOIS History Functions ---

// SaveWhoisRecord inserts a new parsed WHOIS record and the raw text into their respective tables.
func SaveWhoisRecord(db *sql.DB, record *WhoisRecord) error {
	// Use a transaction to ensure both saves succeed or fail together.
	tx, err := db.Begin()
	if err != nil {
		return err
	}

	// 1. Save the parsed data to domain_history
	jsonData, err := json.Marshal(record.Data)
	if err != nil {
		tx.Rollback()
		return err
	}

	stmt1, err := tx.Prepare("INSERT INTO domain_history (domain_name, checked_at, whois_data_json) VALUES (?, ?, ?)")
	if err != nil {
		tx.Rollback()
		return err
	}
	defer stmt1.Close()

	if _, err := stmt1.Exec(record.DomainName, record.CheckedAt, string(jsonData)); err != nil {
		tx.Rollback()
		return err
	}

	// 2. Save the raw text to whois_raw_history
	stmt2, err := tx.Prepare("INSERT INTO whois_raw_history (domain_name, checked_at, raw_text) VALUES (?, ?, ?)")
	if err != nil {
		tx.Rollback()
		return err
	}
	defer stmt2.Close()

	if _, err := stmt2.Exec(record.DomainName, record.CheckedAt, record.RawText); err != nil {
		tx.Rollback()
		return err
	}

	// Commit the transaction
	return tx.Commit()
}

// GetLatestWhoisRecord retrieves the most recent WHOIS record for a given domain.
func GetLatestWhoisRecord(db *sql.DB, domainName string) (*WhoisRecord, error) {
	return GetHistoricalWhoisRecord(db, domainName, 1)
}

// GetHistoricalWhoisRecord retrieves the Nth most recent WHOIS record for a given domain.
// An offset of 1 gets the latest, 2 gets the second latest, and so on.
func GetHistoricalWhoisRecord(db *sql.DB, domainName string, offset int) (*WhoisRecord, error) {
	if offset < 1 {
		offset = 1 // Default to the latest record if offset is invalid.
	}
	// The offset in SQL is 0-based, so we subtract 1.
	query := "SELECT id, domain_name, checked_at, whois_data_json FROM domain_history WHERE domain_name = ? ORDER BY checked_at DESC LIMIT 1 OFFSET ?"
	row := db.QueryRow(query, domainName, offset-1)

	record := &WhoisRecord{}
	var jsonData string
	err := row.Scan(&record.ID, &record.DomainName, &record.CheckedAt, &jsonData)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil // No record found is not an error
		}
		return nil, err
	}

	// Unmarshal the JSON data back into the struct.
	var whoisData WhoisData
	if err := json.Unmarshal([]byte(jsonData), &whoisData); err != nil {
		return nil, err
	}
	record.Data = &whoisData

	// We also need to fetch the corresponding raw text.
	var rawText string
	err = db.QueryRow("SELECT raw_text FROM whois_raw_history WHERE domain_name = ? ORDER BY checked_at DESC LIMIT 1 OFFSET ?", domainName, offset-1).Scan(&rawText)
	if err != nil {
		// If no raw text is found, we can just leave it blank.
		if err != sql.ErrNoRows {
			return nil, err
		}
	}
	record.RawText = rawText

	return record, nil
}

// --- Alert Functions ---

// SaveActiveAlert stores a record of a sent alert.
func SaveActiveAlert(db *sql.DB, alert *Alert) error {
	stmt, err := db.Prepare("INSERT INTO active_alerts (discord_message_id, domain_name, alert_type, is_acknowledged, created_at) VALUES (?, ?, ?, ?, ?)")
	if err != nil {
		return err
	}
	defer stmt.Close()

	_, err = stmt.Exec(alert.DiscordMessageID, alert.DomainName, alert.AlertType, alert.IsAcknowledged, alert.CreatedAt)
	return err
}

// AcknowledgeAlert marks an alert as acknowledged based on its Discord Message ID.
func AcknowledgeAlert(db *sql.DB, messageID string) error {
	stmt, err := db.Prepare("UPDATE active_alerts SET is_acknowledged = 1 WHERE discord_message_id = ?")
	if err != nil {
		return err
	}
	defer stmt.Close()

	_, err = stmt.Exec(messageID)
	return err
}

// IsAlertActive checks if there is a non-acknowledged alert of a specific type for a domain.
func IsAlertActive(db *sql.DB, domainName, alertType string) (bool, error) {
	var count int
	err := db.QueryRow("SELECT COUNT(*) FROM active_alerts WHERE domain_name = ? AND alert_type = ? AND is_acknowledged = 0", domainName, alertType).Scan(&count)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

// --- Reminder Functions ---

// AddReminder adds or reactivates a reminder for a user and domain.
func AddReminder(db *sql.DB, userID, domainName string) error {
	stmt, err := db.Prepare("INSERT INTO domain_reminders (user_id, domain_name, is_active, is_currently_alerting) VALUES (?, ?, 1, 0) ON CONFLICT(user_id, domain_name) DO UPDATE SET is_active=1, is_currently_alerting=0")
	if err != nil {
		return err
	}
	defer stmt.Close()
	_, err = stmt.Exec(userID, domainName)
	return err
}

// GetRemindersForUser retrieves all active reminders for a specific user.
func GetRemindersForUser(db *sql.DB, userID string) ([]string, error) {
	rows, err := db.Query("SELECT domain_name FROM domain_reminders WHERE user_id = ? AND is_active = 1", userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var domains []string
	for rows.Next() {
		var domain string
		if err := rows.Scan(&domain); err != nil {
			return nil, err
		}
		domains = append(domains, domain)
	}
	return domains, nil
}

// GetUsersToRemindForDomain retrieves all users who have an active, non-alerting reminder for a domain.
func GetUsersToRemindForDomain(db *sql.DB, domainName string) ([]string, error) {
	rows, err := db.Query("SELECT user_id FROM domain_reminders WHERE domain_name = ? AND is_active = 1 AND is_currently_alerting = 0", domainName)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var userIDs []string
	for rows.Next() {
		var userID string
		if err := rows.Scan(&userID); err != nil {
			return nil, err
		}
		userIDs = append(userIDs, userID)
	}
	return userIDs, nil
}

// SetReminderAlertingStatus updates the alerting status for a specific reminder.
func SetReminderAlertingStatus(db *sql.DB, userID, domainName string, isAlerting bool) error {
	stmt, err := db.Prepare("UPDATE domain_reminders SET is_currently_alerting = ? WHERE user_id = ? AND domain_name = ?")
	if err != nil {
		return err
	}
	defer stmt.Close()
	_, err = stmt.Exec(isAlerting, userID, domainName)
	return err
}

// DeactivateAlertingReminderForUser finds which reminder is currently alerting for a user and deactivates it.
func DeactivateAlertingReminderForUser(db *sql.DB, userID string) (string, error) {
	var domainName string
	// Find the domain that is currently alerting for this user
	err := db.QueryRow("SELECT domain_name FROM domain_reminders WHERE user_id = ? AND is_currently_alerting = 1", userID).Scan(&domainName)
	if err != nil {
		if err == sql.ErrNoRows {
			return "", nil // No active alert to deactivate
		}
		return "", err
	}

	// Deactivate it
	stmt, err := db.Prepare("UPDATE domain_reminders SET is_active = 0, is_currently_alerting = 0 WHERE user_id = ? AND domain_name = ?")
	if err != nil {
		return "", err
	}
	defer stmt.Close()
	_, err = stmt.Exec(userID, domainName)
	if err != nil {
		return "", err
	}
	return domainName, nil
}
