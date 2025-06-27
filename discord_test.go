package main

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestFormatHelpMessage(t *testing.T) {
	message := FormatHelpMessage()
	commands := []string{"!help", "!lookup", "!add", "!remove", "!list", "!remindme", "!testremindme"}
	for _, cmd := range commands {
		if !strings.Contains(message, cmd) {
			t.Errorf("Help message missing command: %s", cmd)
		}
	}
}

func TestFormatChangeNotification(t *testing.T) {
	newRecord := &WhoisRecord{
		DomainName: "example.com",
		Data: &WhoisData{
			Registrar:      "New Registrar",
			RegistrantName: "New Owner",
			ExpiryDate:     time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		},
	}

	message := FormatChangeNotification(newRecord)

	// Check that the output is valid JSON
	var data map[string]interface{}
	// Extract the json part from the message
	jsonStr := message[strings.Index(message, "```json\n")+8 : strings.LastIndex(message, "\n```")]
	err := json.Unmarshal([]byte(jsonStr), &data)
	if err != nil {
		t.Fatalf("Formatted message does not contain valid JSON: %v", err)
	}

	if !strings.Contains(message, "Domain Change Alert: **example.com**") {
		t.Error("Message missing title or domain name")
	}

	if !strings.Contains(message, `"registrar": "New Registrar"`) {
		t.Error("Message missing new registrar info")
	}
	if !strings.Contains(message, `"registrant_name": "New Owner"`) {
		t.Error("Message missing new owner info")
	}
}

func TestFormatExpiryNotification(t *testing.T) {
	domain := "expiring.com"
	expiryDate := time.Now().Add(59 * time.Minute)
	minutesRemaining := 59

	message := FormatExpiryNotification(domain, expiryDate, minutesRemaining)

	if !strings.Contains(message, "Domain Expiration Warning") {
		t.Error("Message missing title")
	}
	if !strings.Contains(message, "expiring.com") {
		t.Error("Message missing domain name")
	}
	if !strings.Contains(message, "expires in approximately **59 minutes**") {
		t.Error("Message missing or incorrect minutes remaining")
	}
	if !strings.Contains(message, expiryDate.Format(time.RFC1123)) {
		t.Errorf("Message missing or incorrect expiry date string")
	}
}

func TestFormatListResponse(t *testing.T) {
	now := time.Now()
	records := []*WhoisRecord{
		{
			DomainName: "google.com",
			CheckedAt:  now,
			Data: &WhoisData{
				ExpiryDate: now.AddDate(1, 0, 0),
			},
		},
		{
			DomainName: "github.com",
			CheckedAt:  now.Add(-1 * time.Hour),
			Data: &WhoisData{
				ExpiryDate: now.AddDate(0, 6, 0),
			},
		},
	}

	message := FormatListResponse(records)

	if !strings.Contains(message, "Monitored Domains") {
		t.Error("Message missing title")
	}
	if !strings.Contains(message, "google.com") {
		t.Error("Message missing google.com")
	}
	if !strings.Contains(message, "github.com") {
		t.Error("Message missing github.com")
	}
	if !strings.Contains(message, now.Format(time.RFC1123)) {
		t.Error("Message missing formatted check time")
	}
	if !strings.Contains(message, records[0].Data.ExpiryDate.Format(time.RFC1123)) {
		t.Error("Message missing formatted expiry time for google.com")
	}
}

func TestFormatListResponse_Empty(t *testing.T) {
	records := []*WhoisRecord{}
	message := FormatListResponse(records)
	if !strings.Contains(message, "No domains are currently being monitored") {
		t.Error("Message for empty list is incorrect")
	}
}

// TestMarkdownInjection is a security test to ensure that user-provided
// input is properly escaped to prevent Discord markdown injection.
func TestMarkdownInjection(t *testing.T) {
	// This domain name contains backticks, which are used for code blocks in Discord.
	// If not escaped, this could break the formatting of the bot's message.
	maliciousDomain := "`google.com`"

	// We'll test this with the FormatListResponse function.
	records := []*WhoisRecord{
		{
			DomainName: maliciousDomain,
			CheckedAt:  time.Now(),
			Data: &WhoisData{
				ExpiryDate: time.Now().AddDate(1, 0, 0),
			},
		},
	}

	message := FormatListResponse(records)

	// The expected output should have the backticks escaped with backslashes.
	expectedEscapedString := "`google.com`"

	if !strings.Contains(message, expectedEscapedString) {
		t.Errorf("Markdown injection vulnerability detected. Expected to find '%s' in the message, but it was not present.\nGot:\n%s", expectedEscapedString, message)
	}
}
