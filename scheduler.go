package main

import (
	"database/sql"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/bwmarrin/discordgo"
)

// NotificationAction represents a notification that needs to be sent.
type NotificationAction struct {
	Type           string // "change" or "expiry"
	Domain         string
	Changes        []string
	OldRecord      *WhoisRecord
	NewRecord      *WhoisRecord
	MinutesRemaining int
	ExpiryDate     time.Time
}

// WhoisProvider defines the function signature for a WHOIS lookup implementation.
type WhoisProvider func(domain string) (string, error)

// ProcessDomain checks a single domain and returns a list of actions to take.
func ProcessDomain(db *sql.DB, domain string, whoisFn WhoisProvider) ([]NotificationAction, error) {
	var actions []NotificationAction

	// 1. Get the last record from our DB
	lastRecord, err := GetLatestWhoisRecord(db, domain)
	if err != nil {
		return nil, fmt.Errorf("could not get last record for %s: %w", domain, err)
	}

	// 2. Perform a fresh WHOIS lookup
	rawText, err := whoisFn(domain)
	if err != nil {
		log.Printf("WHOIS lookup failed for %s: %v", domain, err)
		return nil, nil // Don't halt everything, just skip this domain for now.
	}

	whoisData, err := ParseWhois(rawText)
	if err != nil {
		log.Printf("Could not parse WHOIS for %s: %v", domain, err)
		return nil, nil
	}

	newRecord := &WhoisRecord{
		DomainName: domain,
		CheckedAt:  time.Now(),
		Data:       whoisData,
		RawText:    rawText, // Store the raw text
	}

	// 3. Compare and decide on actions
	if lastRecord != nil {
		changes, hasDiff := CompareWhoisRecords(lastRecord, newRecord)
		if hasDiff {
			alertType := "change_" + strings.Join(changes, "_")
			isActive, err := IsAlertActive(db, domain, alertType)
			if err != nil {
				return nil, fmt.Errorf("could not check for active alert: %w", err)
			}
			if !isActive {
				actions = append(actions, NotificationAction{
					Type:      "change",
					Domain:    domain,
					Changes:   changes,
					OldRecord: lastRecord,
					NewRecord: newRecord,
				})
			}
		}
	}

	// 4. Check for expiration
	if !whoisData.ExpiryDate.IsZero() {
		minutesRemaining := int(time.Until(whoisData.ExpiryDate).Minutes())
		alertType := ""
		// New high-frequency alert for domains expiring in <= 60 minutes
		if minutesRemaining > 0 && minutesRemaining <= 60 {
			alertType = "expiry_1h"
		} else if minutesRemaining > 0 && minutesRemaining <= 48*60 { // 48 hours
			alertType = "expiry_48h"
		}

		if alertType != "" {
			isActive, err := IsAlertActive(db, domain, alertType)
			if err != nil {
				return nil, fmt.Errorf("could not check for active alert: %w", err)
			}
			if !isActive {
				actions = append(actions, NotificationAction{
					Type:           "expiry",
					Domain:         domain,
					MinutesRemaining: minutesRemaining,
					ExpiryDate:     whoisData.ExpiryDate,
				})
			}
		}
	}

	// 5. Save the new record for the next run
	if err := SaveWhoisRecord(db, newRecord); err != nil {
		return nil, fmt.Errorf("could not save new whois record for %s: %w", domain, err)
	}

	return actions, nil
}

// StartScheduler manages all periodic checks.
func StartScheduler(db *sql.DB, state *AppState, dg *discordgo.Session) {
	// A wait group to manage all our running goroutines
	var wg sync.WaitGroup

	// --- Normal Check Scheduler ---
	wg.Add(1)
	go func() {
		defer wg.Done()
		// Run once on startup, then on a regular interval
		runChecks(db, state, dg, false) // 'false' for not high-frequency
		ticker := time.NewTicker(time.Duration(state.Config.CheckIntervalMinutes) * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			runChecks(db, state, dg, false)
		}
	}()

	// --- High-Frequency Check Scheduler ---
	wg.Add(1)
	go func() {
		defer wg.Done()
		// This ticker runs every minute to see if any domains need high-frequency checks.
		ticker := time.NewTicker(1 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			runChecks(db, state, dg, true) // 'true' for high-frequency
		}
	}()

	wg.Wait()
}

// runChecks is the core function that performs the checks.
// isHighFrequency determines which set of domains to check.
func runChecks(db *sql.DB, state *AppState, dg *discordgo.Session, isHighFrequency bool) {
	var domains []string
	var err error

	if isHighFrequency {
		// Get domains expiring in the next 60 minutes
		domains, err = GetDomainsNearingExpiry(db, 60*time.Minute)
		if err != nil {
			log.Printf("ERROR: Could not get high-frequency domains: %v", err)
			return
		}
		if len(domains) > 0 {
			log.Printf("High-frequency check for %d domains: %v", len(domains), domains)
		}
	} else {
		// Get all monitored domains for a normal run
		log.Println("Starting normal domain checks...")
		domains, err = GetMonitoredDomains(db)
		if err != nil {
			log.Printf("ERROR: Could not get monitored domains: %v", err)
			return
		}
		log.Printf("Checking %d domains: %v", len(domains), domains)
	}

	if len(domains) == 0 {
		if !isHighFrequency {
			log.Println("No domains to check.")
		}
		return
	}

	for _, domain := range domains {
		// Process each domain
		actions, err := ProcessDomain(db, domain, PerformWhoisLookup)
		if err != nil {
			log.Printf("Error processing domain %s: %v", domain, err)
			continue
		}

		// Handle the actions (notifications, etc.)
		handleActions(db, state, dg, domain, actions)
	}

	if !isHighFrequency {
		log.Println("Normal domain checks finished.")
	}
}

// handleActions sends notifications based on the results of a domain check.
func handleActions(db *sql.DB, state *AppState, dg *discordgo.Session, domain string, actions []NotificationAction) {
	var lastAction NotificationAction
	for _, action := range actions {
		lastAction = action
		var message string
		var alertType string

		if action.Type == "change" {
			message = FormatChangeNotification(action.NewRecord)
			alertType = "change_" + strings.Join(action.Changes, "_")
		} else if action.Type == "expiry" {
			if action.MinutesRemaining <= 60 {
				alertType = "expiry_1h"
			} else {
				alertType = "expiry_48h"
			}
			message = FormatExpiryNotification(action.Domain, action.ExpiryDate, action.MinutesRemaining)
		}

		sentMsg, err := SendDiscordMessage(dg, state.Config.DiscordChannelID, message)
		if err != nil {
			log.Printf("Failed to send Discord message for %s: %v", domain, err)
			continue
		}

		alert := &Alert{
			DiscordMessageID: sentMsg.ID,
			DomainName:       domain,
			AlertType:        alertType,
			IsAcknowledged:   false,
			CreatedAt:        time.Now(),
		}
		if err := SaveActiveAlert(db, alert); err != nil {
			log.Printf("Failed to save active alert for %s: %v", domain, err)
		}
	}

	// Handle personal DM reminders, which are always high-frequency (last 30 mins)
	if !lastAction.ExpiryDate.IsZero() {
		minutesRemaining := time.Until(lastAction.ExpiryDate).Minutes()
		if minutesRemaining > 0 && minutesRemaining <= 30 {
			usersToRemind, err := GetUsersToRemindForDomain(db, domain)
			if err != nil {
				log.Printf("Error getting users to remind for %s: %v", domain, err)
				return
			}
			for _, userID := range usersToRemind {
				go sendDMReminderLoop(db, dg, userID, domain, lastAction.ExpiryDate)
			}
		}
	}
}


// sendDMReminderLoop sends a reminder to a user every minute until the domain expires or they ack.
func sendDMReminderLoop(db *sql.DB, dg *discordgo.Session, userID, domain string, expiryDate time.Time) {
	// Mark the user as being alerted so we don't start a second loop for them.
	if err := SetReminderAlertingStatus(db, userID, domain, true); err != nil {
		log.Printf("ERROR: could not set alerting status for %s/%s: %v", userID, domain, err)
		return
	}
	log.Printf("Starting DM reminder loop for %s about %s", userID, domain)

	dmChannel, err := dg.UserChannelCreate(userID)
	if err != nil {
		log.Printf("ERROR: could not create DM channel for %s: %v", userID, err)
		SetReminderAlertingStatus(db, userID, domain, false)
		return
	}

	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if time.Now().After(expiryDate) {
				log.Printf("Domain %s has expired. Stopping reminder loop for %s.", domain, userID)
				SetReminderAlertingStatus(db, userID, domain, false)
				return
			}

			var isAlerting bool
			err := db.QueryRow("SELECT is_currently_alerting FROM domain_reminders WHERE user_id = ? AND domain_name = ?", userID, domain).Scan(&isAlerting)
			if err != nil || !isAlerting {
				log.Printf("Stopping reminder loop for %s/%s because it was acknowledged or an error occurred.", userID, domain)
				return
			}

			message := FormatDMReminder(domain, expiryDate)
			_, err = dg.ChannelMessageSend(dmChannel.ID, message)
			if err != nil {
				log.Printf("IO: ERROR: failed to send DM to %s: %v", userID, err)
				if restErr, ok := err.(*discordgo.RESTError); ok && restErr.Message.Code == discordgo.ErrCodeCannotSendMessagesToThisUser {
					log.Printf("Disabling reminder for %s/%s due to Discord privacy settings (50007).", userID, domain)
					DeactivateAlertingReminderForUser(db, userID)
					return
				}
			} else {
				log.Printf("IO: SEND: (DM) User: %s | Msg: \"%s\"", userID, strings.ReplaceAll(message, "\n", " "))
			}
		}
	}
}
