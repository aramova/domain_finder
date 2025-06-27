package main

import (
	"database/sql"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/bwmarrin/discordgo"
	_ "github.com/mattn/go-sqlite3"
)

// isValidDomain checks if a string is a plausible domain name.
// This is not a perfect validation, but it prevents common injection/corruption attacks.
var isValidDomain = regexp.MustCompile(`^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$`).MatchString

func main() {
	// --- Command-line flag parsing ---
	configDir := flag.String("configdir", ".", "Directory where config.json is located.")
	dbDir := flag.String("dbdir", ".", "Directory where the domains.db file will be stored.")
	flag.Parse()

	configPath := filepath.Join(*configDir, "config.json")
	dbPath := filepath.Join(*dbDir, "domains.db")
	// --- End flag parsing ---

	// 1. Check for configuration file and create a default if it doesn't exist.
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		log.Printf("Configuration file not found at %s. Creating a default.", configPath)
		log.Println("Please edit the file with your Discord Bot Token and Channel ID.")
		if err := createDefaultConfiguration(configPath); err != nil {
			log.Fatalf("FATAL: Could not create default configuration file: %v", err)
		}
		// Exit gracefully after creating the file.
		return
	}

	// 2. Load Configuration
	config, err := LoadConfiguration(configPath)
	if err != nil {
		log.Fatalf("FATAL: Could not load configuration from %s: %v", configPath, err)
	}

	// 3. Validate essential configuration
	if config.DiscordBotToken == "" || config.DiscordChannelID == "" {
		log.Fatalf("FATAL: 'discord_bot_token' and 'discord_channel_id' must be set in config.json.")
	}
	if config.CheckIntervalMinutes <= 0 {
		log.Fatalf("FATAL: 'check_interval_minutes' must be a positive number.")
	}

	// 4. Create the shared application state
	appState := &AppState{
		Config: config,
	}

	// 5. Initialize Database
	log.Printf("INFO: Using database file at %s", dbPath)
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		log.Fatalf("FATAL: Could not open database: %v", err)
	}
	defer db.Close()

	if err := InitializeDatabase(db); err != nil {
		log.Fatalf("FATAL: Could not initialize database: %v", err)
	}

	// 6. Create Discord Session
	dg, err := NewDiscordSession(appState.Config.DiscordBotToken)
	if err != nil {
		log.Fatalf("FATAL: Could not create Discord session: %v", err)
	}

	// 7. Add Handlers
	// Add a handler for reaction events (for acks)
	dg.AddHandler(func(s *discordgo.Session, r *discordgo.MessageReactionAdd) {
		reactionCreate(s, r, db)
	})
	// Add a handler for message creation events (for commands)
	dg.AddHandler(func(s *discordgo.Session, m *discordgo.MessageCreate) {
		// Pass the app state and db connection to the handler
		messageCreate(s, m, appState, db)
	})

	// We need message content, reactions, and DMs.
	dg.Identify.Intents = discordgo.IntentsGuildMessages | discordgo.IntentsGuildMessageReactions | discordgo.IntentsDirectMessages

	// 8. Open Discord Connection
	err = dg.Open()
	if err != nil {
		log.Fatalf("FATAL: Could not open Discord connection: %v", err)
	}

	// 9. Verify the bot can access the target channel
	_, err = dg.Channel(appState.Config.DiscordChannelID)
	if err != nil {
		log.Printf("FATAL: Could not access the specified Discord Channel ID ('%s').", appState.Config.DiscordChannelID)
		log.Printf("Please ensure the Channel ID is correct and that the bot has been invited to the server.")
		dg.Close()
		return
	}

	defer dg.Close()

	log.Println("Bot is now running. Press CTRL-C to exit.")

	// 10. Start the Scheduler (in a new goroutine)
	go StartScheduler(db, appState, dg)

	// 11. Wait for shutdown signal
	sc := make(chan os.Signal, 1)
	signal.Notify(sc, syscall.SIGINT, syscall.SIGTERM, os.Interrupt)
	<-sc
	log.Println("Shutdown signal received, exiting.")
}

// reactionCreate is the handler for when a user reacts to a message.
func reactionCreate(s *discordgo.Session, r *discordgo.MessageReactionAdd, db *sql.DB) {
	// Ignore reactions from the bot itself
	if r.UserID == s.State.User.ID {
		return
	}

	// --- Verbose Logging ---
	log.Printf(
		"RECV: User: %s (%s) | Guild: %s | Chan: %s | MsgID: %s | Emoji: %s",
		r.Member.User.Username,
		r.UserID,
		r.GuildID,
		r.ChannelID,
		r.MessageID,
		r.Emoji.Name,
	)
	// --- End Logging ---

	// Check if the reaction is the one we care about
	if r.Emoji.Name == "✅" {
		log.Printf("INFO: Acknowledgment reaction received for message %s", r.MessageID)
		err := AcknowledgeAlert(db, r.MessageID)
		if err != nil {
			log.Printf("ERROR: Failed to acknowledge alert for message %s: %v", r.MessageID, err)
			return
		}
		// Optionally, edit the message to show it's acknowledged
		originalMessage, err := s.ChannelMessage(r.ChannelID, r.MessageID)
		if err == nil {
			newContent := originalMessage.Content + "\n\n**Acknowledged by " + r.Member.User.Username + "**"
			s.ChannelMessageEdit(r.ChannelID, r.MessageID, newContent)
		}
	}
}

// messageCreate is the handler for when a new message is created on any channel.
func messageCreate(s *discordgo.Session, m *discordgo.MessageCreate, state *AppState, db *sql.DB) {
	// Ignore all messages created by the bot itself
	if m.Author.ID == s.State.User.ID {
		return
	}

	// --- Verbose Logging ---
	// Sanitize the user-provided content before logging to prevent log injection.
	sanitizedContent := SanitizeLogInput(m.Content)
	logLine := fmt.Sprintf(
		"RECV: User: %s (%s) | Guild: %s | Chan: %s | Msg: \"%s\"",
		m.Author.Username,
		m.Author.ID,
		m.GuildID, // Will be empty for DMs
		m.ChannelID,
		sanitizedContent,
	)
	if m.GuildID == "" {
		logLine = strings.Replace(logLine, "Guild:  |", "Guild: DM |", 1)
	}
	log.Println(logLine)
	// --- End Logging ---

	// Handle 'ack' in DMs
	if m.GuildID == "" { // DMs don't have a GuildID
		if strings.ToLower(m.Content) == "ack" {
			deactivatedDomain, err := DeactivateAlertingReminderForUser(db, m.Author.ID)
			if err != nil {
				log.Printf("ERROR: failed to deactivate reminder for user %s: %v", m.Author.ID, err)
				s.ChannelMessageSend(m.ChannelID, "An error occurred. Could not deactivate reminder.")
				return
			}
			if deactivatedDomain != "" {
				SendDiscordMessage(s, m.ChannelID, fmt.Sprintf("✅ Reminder for **%s** has been deactivated.", deactivatedDomain))
			} else {
				SendDiscordMessage(s, m.ChannelID, "You have no active alerts to acknowledge.")
			}
		}
		return
	}

	// Handle public channel commands
	if strings.HasPrefix(m.Content, "!") {
		parts := strings.Split(m.Content, " ")
		command := parts[0]

		switch command {
		case "!help":
			SendDiscordMessage(s, m.ChannelID, FormatHelpMessage())
		case "!lookup":
			if len(parts) < 2 {
				SendDiscordMessage(s, m.ChannelID, "Please provide a domain to look up. *Example: `!lookup google.com`*")
				return
			}
			domain := parts[1]
			if !isValidDomain(domain) {
				SendDiscordMessage(s, m.ChannelID, fmt.Sprintf("`%s` is not a valid domain format.", domain))
				return
			}
			SendDiscordMessage(s, m.ChannelID, fmt.Sprintf("Performing WHOIS lookup for **%s**...", domain))

			rawWhois, err := PerformWhoisLookup(domain)
			if err != nil {
				SendDiscordMessage(s, m.ChannelID, fmt.Sprintf("An error occurred during lookup for **%s**: %v", domain, err))
				return
			}

			whoisData, err := ParseWhois(rawWhois)
			if err != nil {
				SendDiscordMessage(s, m.ChannelID, fmt.Sprintf("An error occurred while parsing WHOIS data for **%s**: %v", domain, err))
				return
			}

			response := FormatLookupResponse(domain, whoisData.RawText, whoisData.ExpiryDate)
			SendDiscordMessage(s, m.ChannelID, response)

		case "!add":
			if len(parts) < 2 {
				SendDiscordMessage(s, m.ChannelID, "Please provide a domain to add. *Example: `!add github.com`*")
				return
			}
			domainToAdd := strings.ToLower(parts[1])
			if !isValidDomain(domainToAdd) {
				SendDiscordMessage(s, m.ChannelID, fmt.Sprintf("`%s` is not a valid domain format.", domainToAdd))
				return
			}

			isMonitored, err := IsDomainMonitored(db, domainToAdd)
			if err != nil {
				log.Printf("ERROR: Failed to check if domain is monitored: %v", err)
				SendDiscordMessage(s, m.ChannelID, "An error occurred while checking the domain.")
				return
			}
			if isMonitored {
				SendDiscordMessage(s, m.ChannelID, fmt.Sprintf("**%s** is already on the monitoring list.", domainToAdd))
				return
			}

			// Add the domain to the database
			if err := AddMonitoredDomain(db, domainToAdd); err != nil {
				log.Printf("ERROR: Failed to add domain to database: %v", err)
				SendDiscordMessage(s, m.ChannelID, "An error occurred while trying to add the new domain.")
				return
			}
			log.Printf("DATABASE: Added '%s' to monitored_domains table.", domainToAdd)

			// Perform an immediate lookup and save the initial state
			SendDiscordMessage(s, m.ChannelID, fmt.Sprintf("✅ **%s** has been added to the monitoring list. Performing initial lookup...", domainToAdd))
			rawWhoisText, err := PerformWhoisLookup(domainToAdd)
			if err != nil {
				SendDiscordMessage(s, m.ChannelID, fmt.Sprintf("Could not perform initial WHOIS lookup for **%s**: %v", domainToAdd, err))
				return
			}
			parsedData, err := ParseWhois(rawWhoisText)
			if err != nil {
				SendDiscordMessage(s, m.ChannelID, fmt.Sprintf("Could not parse initial WHOIS data for **%s**: %v", domainToAdd, err))
				return
			}

			initialRecord := &WhoisRecord{
				DomainName: domainToAdd,
				CheckedAt:  time.Now(),
				Data:       parsedData,
				RawText:    rawWhoisText,
			}
			if err := SaveWhoisRecord(db, initialRecord); err != nil {
				log.Printf("ERROR: Failed to save initial WHOIS record for %s: %v", domainToAdd, err)
				SendDiscordMessage(s, m.ChannelID, fmt.Sprintf("Failed to save initial state for **%s**.", domainToAdd))
				return
			}

			// Respond with the detailed lookup information, mentioning the user
			responseMessage := fmt.Sprintf("<@%s> Initial state for **%s**:\n", m.Author.ID, domainToAdd) +
				FormatLookupResponse(domainToAdd, rawWhoisText, parsedData.ExpiryDate)
			SendDiscordMessage(s, m.ChannelID, responseMessage)
		case "!remove":
			if len(parts) < 2 {
				SendDiscordMessage(s, m.ChannelID, "Please provide a domain to remove. *Example: `!remove github.com`*")
				return
			}
			domainToRemove := strings.ToLower(parts[1])
			if !isValidDomain(domainToRemove) {
				SendDiscordMessage(s, m.ChannelID, fmt.Sprintf("`%s` is not a valid domain format.", domainToRemove))
				return
			}

			isMonitored, err := IsDomainMonitored(db, domainToRemove)
			if err != nil {
				log.Printf("ERROR: Failed to check if domain is monitored: %v", err)
				SendDiscordMessage(s, m.ChannelID, "An error occurred while checking the domain.")
				return
			}
			if !isMonitored {
				SendDiscordMessage(s, m.ChannelID, fmt.Sprintf("**%s** is not on the monitoring list.", domainToRemove))
				return
			}

			if err := RemoveMonitoredDomain(db, domainToRemove); err != nil {
				log.Printf("ERROR: Failed to remove domain from database: %v", err)
				SendDiscordMessage(s, m.ChannelID, "An error occurred while trying to remove the domain.")
				return
			}
			SendDiscordMessage(s, m.ChannelID, fmt.Sprintf("✅ **%s** has been removed from the monitoring list.", domainToRemove))

		case "!list":
			domains, err := GetMonitoredDomains(db)
			if err != nil {
				log.Printf("ERROR: Failed to get monitored domains: %v", err)
				SendDiscordMessage(s, m.ChannelID, "An error occurred while fetching the domain list.")
				return
			}

			var records []*WhoisRecord
			for _, domain := range domains {
				record, err := GetLatestWhoisRecord(db, domain)
				if err != nil {
					log.Printf("Error getting record for %s: %v", domain, err)
					continue
				}
				if record != nil {
					records = append(records, record)
				}
			}
			response := FormatListResponse(records)
			SendDiscordMessage(s, m.ChannelID, response)

		case "!stats":
			log.Println("DEBUG: Entered !stats command handler.")
			if len(parts) < 2 {
				SendDiscordMessage(s, m.ChannelID, "Please provide a domain. *Example: `!stats google.com [n]`*")
				return
			}
			domain := strings.ToLower(parts[1])
			log.Printf("DEBUG: Domain for stats: %s", domain)

			if !isValidDomain(domain) {
				SendDiscordMessage(s, m.ChannelID, fmt.Sprintf("`%s` is not a valid domain format.", domain))
				return
			}

			offset := 1
			if len(parts) > 2 {
				var err error
				offset, err = strconv.Atoi(parts[2])
				if err != nil || offset < 1 {
					SendDiscordMessage(s, m.ChannelID, "Invalid history offset. Please provide a number greater than 0.")
					return
				}
			}
			log.Printf("DEBUG: History offset: %d", offset)

			record, err := GetHistoricalWhoisRecord(db, domain, offset)
			if err != nil {
				log.Printf("ERROR: Failed to get historical record for %s with offset %d: %v", domain, offset, err)
				SendDiscordMessage(s, m.ChannelID, "An error occurred while fetching historical data.")
				return
			}
			log.Printf("DEBUG: Fetched record: %+v", record)

			response := FormatStatsResponse(record, offset)
			log.Printf("DEBUG: Formatted response: %s", response)
			SendDiscordReply(s, m.Message, response)

		case "!remindme":
			if len(parts) < 2 {
				// List existing reminders
				reminders, err := GetRemindersForUser(db, m.Author.ID)
				if err != nil {
					log.Printf("ERROR: failed to get reminders for user %s: %v", m.Author.ID, err)
					SendDiscordMessage(s, m.ChannelID, "An error occurred while fetching your reminders.")
					return
				}
				response := FormatRemindersList(reminders)
				SendDiscordMessage(s, m.ChannelID, response)
			} else {
				// Add a new reminder
				domainToRemind := strings.ToLower(parts[1])
				if !isValidDomain(domainToRemind) {
					SendDiscordMessage(s, m.ChannelID, fmt.Sprintf("`%s` is not a valid domain format.", domainToRemind))
					return
				}
				err := AddReminder(db, m.Author.ID, domainToRemind)
				if err != nil {
					log.Printf("ERROR: failed to add reminder for user %s: %v", m.Author.ID, err)
					SendDiscordMessage(s, m.ChannelID, "An error occurred while setting your reminder.")
					return
				}
				SendDiscordMessage(s, m.ChannelID, fmt.Sprintf("✅ Reminder set for **%s**. I will DM you when it's about to expire.", domainToRemind))
			}
		case "!testremindme":
			if len(parts) < 2 {
				SendDiscordMessage(s, m.ChannelID, "Please provide a domain to test. *Example: `!testremindme google.com`*")
				return
			}
			domainToTest := strings.ToLower(parts[1])
			if !isValidDomain(domainToTest) {
				SendDiscordMessage(s, m.ChannelID, fmt.Sprintf("`%s` is not a valid domain format.", domainToTest))
				return
			}

			// Check if the user has an active reminder for this domain
			reminders, err := GetRemindersForUser(db, m.Author.ID)
			if err != nil {
				log.Printf("ERROR: failed to get reminders for user %s: %v", m.Author.ID, err)
				SendDiscordMessage(s, m.ChannelID, "An error occurred while checking your reminders.")
				return
			}

			found := false
			for _, r := range reminders {
				if r == domainToTest {
					found = true
					break
				}
			}

			if !found {
				SendDiscordMessage(s, m.ChannelID, fmt.Sprintf("You don't have an active reminder for **%s**. Use `!remindme %s` to set one first.", domainToTest, domainToTest))
				return
			}

			// Trigger the loop with a fake expiry
			fakeExpiry := time.Now().Add(2 * time.Minute)
			SendDiscordMessage(s, m.ChannelID, fmt.Sprintf("✅ Starting test reminder for **%s**. Check your DMs! The test will run for 2 minutes.", domainToTest))
			go sendDMReminderLoop(db, s, m.Author.ID, domainToTest, fakeExpiry)
		}
	}
}
