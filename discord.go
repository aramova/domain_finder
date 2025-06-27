package main

import (
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/bwmarrin/discordgo"
)

// NewDiscordSession creates and returns a new Discord session.
func NewDiscordSession(token string) (*discordgo.Session, error) {
	dg, err := discordgo.New("Bot " + token)
	if err != nil {
		return nil, err
	}
	return dg, nil
}

// FormatChangeNotification creates a formatted string for a domain change alert, presenting the full new WHOIS record.
func FormatChangeNotification(newRecord *WhoisRecord) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("### Domain Change Alert: **%s**\n", newRecord.DomainName))
	sb.WriteString("A change was detected in the WHOIS record. The new data is:\n")
	sb.WriteString("```json\n")

	// Use json.MarshalIndent for a pretty-printed format.
	prettyJSON, err := json.MarshalIndent(newRecord.Data, "", "  ")
	if err != nil {
		// Fallback to a less pretty format if JSON marshaling fails.
		sb.WriteString(fmt.Sprintf("%+v\n", newRecord.Data))
	} else {
		sb.WriteString(string(prettyJSON))
	}

	sb.WriteString("\n```")
	return sb.String()
}

// FormatExpiryNotification creates a formatted string for a domain expiration warning.
func FormatExpiryNotification(domain string, expiryDate time.Time, minutesRemaining int) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("### Domain Expiration Warning: **%s**\n", domain))

	if minutesRemaining <= 60 {
		sb.WriteString(fmt.Sprintf("This domain expires in approximately **%d minutes**\n", minutesRemaining))
	} else {
		hoursRemaining := minutesRemaining / 60
		sb.WriteString(fmt.Sprintf("This domain expires in approximately **%d hours**\n", hoursRemaining))
	}

	sb.WriteString(fmt.Sprintf("**Expiration Date:** `%s`\n", expiryDate.Format(time.RFC1123)))
	return sb.String()
}

// SendDiscordMessage sends a message to a specific channel and logs the action and any errors.
func SendDiscordMessage(session *discordgo.Session, channelID, message string) (*discordgo.Message, error) {
	log.Printf("IO: SEND: Chan: %s | Msg: \"%s\"", channelID, strings.ReplaceAll(message, "\n", " "))
	msg, err := session.ChannelMessageSend(channelID, message)
	if err != nil {
		log.Printf("IO: ERROR: Failed to send message to channel %s: %v", channelID, err)
	}
	return msg, err
}

// SendDiscordReply sends a reply to a specific message and logs the action.
func SendDiscordReply(session *discordgo.Session, originalMessage *discordgo.Message, replyText string) (*discordgo.Message, error) {
	log.Printf("IO: REPLY: Chan: %s | To: %s | Msg: \"%s\"", originalMessage.ChannelID, originalMessage.ID, strings.ReplaceAll(replyText, "\n", " "))
	msg, err := session.ChannelMessageSendReply(originalMessage.ChannelID, replyText, originalMessage.Reference())
	if err != nil {
		log.Printf("IO: ERROR: Failed to send reply to message %s: %v", originalMessage.ID, err)
	}
	return msg, err
}

// FormatHelpMessage creates the help message text.
func FormatHelpMessage() string {

	var sb strings.Builder
	sb.WriteString("### Domain Finder Bot Commands\n")
	sb.WriteString("`!help` - Shows this help message.\n")
	sb.WriteString("`!lookup <domain>` - Performs an immediate WHOIS lookup for the specified domain.\n")
	sb.WriteString("  *Example: `!lookup google.com`*\n")
	sb.WriteString("`!add <domain>` - Adds a new domain to the monitoring list.\n")
	sb.WriteString("  *Example: `!add github.com`*\n")
	sb.WriteString("`!remove <domain>` - Removes a domain from the monitoring list.\n")
	sb.WriteString("  *Example: `!remove github.com`*\n")
	sb.WriteString("`!list` - Lists all currently monitored domains and their last check status.\n")
	sb.WriteString("`!stats <domain> [n]` - Shows historical WHOIS data. `n` is the optional history offset (1 = latest).\n")
	sb.WriteString("  *Example: `!stats google.com 2`*\n")
	sb.WriteString("`!remindme [domain]` - Manage personal expiration reminders. Use without a domain to list your reminders.\n")
	sb.WriteString("  *Example: `!remindme google.com`*\n")
	sb.WriteString("`!testremindme <domain>` - Test the DM reminder loop for a domain you have a reminder for.\n")
	sb.WriteString("  *Example: `!testremindme google.com`*\n")
	return sb.String()
}

// FormatStatsResponse formats a historical WHOIS record for display.
func FormatStatsResponse(record *WhoisRecord, offset int) string {
	if record == nil {
		return "No historical record found at that position."
	}

	// Create a temporary struct to hold the data we want to show, excluding the raw text.
	displayData := struct {
		DomainName       string    `json:"domain_name"`
		RegistryDomainID string    `json:"registry_domain_id"`
		Registrar        string    `json:"registrar"`
		UpdatedDate      time.Time `json:"updated_date"`
		CreationDate     time.Time `json:"creation_date"`
		ExpiryDate       time.Time `json:"expiry_date"`
		NameServers      []string  `json:"name_servers"`
		RegistrantName   string    `json:"registrant_name"`
		RegistrantOrg    string    `json:"registrant_org"`
	}{
		DomainName:       record.Data.DomainName,
		RegistryDomainID: record.Data.RegistryDomainID,
		Registrar:        record.Data.Registrar,
		UpdatedDate:      record.Data.UpdatedDate,
		CreationDate:     record.Data.CreationDate,
		ExpiryDate:       record.Data.ExpiryDate,
		NameServers:      record.Data.NameServers,
		RegistrantName:   record.Data.RegistrantName,
		RegistrantOrg:    record.Data.RegistrantOrg,
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("### Historical WHOIS Data for **%s**\n", record.DomainName))
	sb.WriteString(fmt.Sprintf("**Record from:** `%s` (Position #%d)\n", record.CheckedAt.Format(time.RFC1123), offset))
	sb.WriteString("```json\n")

	prettyJSON, err := json.MarshalIndent(displayData, "", "  ")
	if err != nil {
		sb.WriteString(fmt.Sprintf("%+v\n", displayData))
	} else {
		sb.WriteString(string(prettyJSON))
	}

	sb.WriteString("\n```")
	return sb.String()
}

// FormatLookupResponse formats the raw WHOIS text for a Discord message.
func FormatLookupResponse(domain string, rawWhois string, expiry time.Time) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("### WHOIS Lookup: **%s**\n", domain))
	if !expiry.IsZero() {
		sb.WriteString(fmt.Sprintf("**Expires On:** `%s` (%d days from now)\n", expiry.Format(time.RFC1123), int(time.Until(expiry).Hours()/24)))
	} else {
		sb.WriteString("**Expiration Date:** `Not found`\n")
	}
	sb.WriteString("\n```\n")
	// Limit the raw whois to avoid hitting Discord's message character limit
	if len(rawWhois) > 1800 {
		sb.WriteString(rawWhois[:1800])
		sb.WriteString("\n... (truncated)")
	} else {
		sb.WriteString(rawWhois)
	}
	sb.WriteString("\n```")
	return sb.String()
}

// FormatListResponse formats the list of monitored domains.
func FormatListResponse(domains []*WhoisRecord) string {
	var sb strings.Builder
	sb.WriteString("### Monitored Domains\n")
	if len(domains) == 0 {
		sb.WriteString("No domains are currently being monitored.")
		return sb.String()
	}

	for _, d := range domains {
		if d != nil {
            sb.WriteString(fmt.Sprintf("- **%s**\n", d.DomainName))
            sb.WriteString(fmt.Sprintf("  - **Last Checked:** `%s`\n", d.CheckedAt.Format(time.RFC1123)))
            sb.WriteString(fmt.Sprintf("  - **Expires On:** `%s`\n", d.Data.ExpiryDate.Format(time.RFC1123)))
        }
    }
    return sb.String()
}

// FormatRemindersList formats the list of a user's personal reminders.
func FormatRemindersList(domains []string) string {
	var sb strings.Builder
	sb.WriteString("### Your Personal Reminders\n")
	if len(domains) == 0 {
		sb.WriteString("You have no active reminders set. Use `!remindme <domain>` to add one.")
		return sb.String()
	}
	for _, domain := range domains {
		sb.WriteString(fmt.Sprintf("- %s\n", domain))
	}
	return sb.String()
}

// FormatDMReminder creates the direct message sent to a user.
func FormatDMReminder(domain string, expiryDate time.Time) string {
	return fmt.Sprintf(
		"**Reminder:** The domain **%s** is expiring in approximately **%.0f minutes**!\n(Expires at: %s)\n\n*Reply `ack` to disable this reminder.*",
		domain,
		time.Until(expiryDate).Minutes(),
		expiryDate.Format(time.RFC1123),
	)
}
