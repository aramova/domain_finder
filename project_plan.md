# Project Plan: Domain Finder (Final State)

This document outlines the final architecture and feature set of the `domain_finder` project.

## 1. Project Overview

The `domain_finder` is a long-running, interactive Go application (a Discord bot) that monitors domain names. It runs as a persistent service, performing periodic `WHOIS` lookups and storing the results in a local SQLite database. The bot sends alerts to a designated Discord channel for significant changes or upcoming expirations. Users can interact with the bot through commands to add/list/remove domains, perform on-demand lookups, and manage personal expiration reminders via Direct Messages.

## 2. Core Features (as implemented)

### Functional Requirements:

*   **Secure Installation:** A production-ready installer script (`install_service.sh`) creates a dedicated non-privileged system user, sets up secure file permissions, and configures the application to run as a `systemd` service.
*   **Dynamic Domain Management:** The list of monitored domains is stored in the application's SQLite database, not in a configuration file. This allows the list to be managed dynamically via Discord commands without restarting the bot or requiring manual file edits.
*   **Scheduled Monitoring:** The bot runs an internal scheduler to periodically perform `WHOIS` lookups on all monitored domains from the database. The interval is configurable.
*   **Change Detection:** Compares the latest `WHOIS` data against the last known record and alerts on changes.
*   **Public & Personal Alerts:** The bot supports both public channel alerts for general monitoring and private, user-specific DM reminders for domains nearing expiration.
*   **Interactive Bot Commands:**
    *   `!help`: Displays a list of all available commands.
    *   `!lookup <domain>`: Performs an immediate on-demand `WHOIS` lookup.
    *   `!add <domain>`: Adds a domain to the database to be monitored.
    *   `!remove <domain>`: Removes a domain from the monitoring database.
    *   `!list`: Lists all currently monitored domains.
    *   `!stats <domain> [n]`: Shows historical WHOIS data. `n` is the optional history offset (1 = latest).
    *   `!remindme [domain]`: Manages personal DM reminders. When used without a domain, it lists active reminders.
    *   `!testremindme <domain>`: Allows a user to test the DM reminder loop.
*   **Input Sanitization:** All user-provided domain names are validated against a regular expression to prevent malformed data from entering the system.

### Non-Functional Requirements:

*   **Language:** Go (v1.19 compatible)
*   **Platform:** A single, self-contained binary deployable on Linux.
*   **Concurrency:** The application safely handles concurrent operations using mutexes to protect any shared state that is not already managed by the database.

## 3. Final Architecture

*   **`main.go`**: The application entry point. Handles command-line flag parsing (`-configdir`, `-dbdir`), initializes the database and Discord session, and registers all Discord event handlers.
*   **`database.go`**: Manages all SQLite database interactions. This includes tables for:
    *   `monitored_domains`: The source of truth for which domains to check.
    *   `domain_history`: Stores historical `WHOIS` lookup results.
    *   `active_alerts`: Tracks public alerts sent to the Discord channel.
    *   `domain_reminders`: Tracks user-specific DM reminder requests.
*   **`scheduler.go`**: Contains the core application loop. A `time.Ticker` triggers `runChecks`, which first queries the database for the list of domains to monitor, then proceeds to check each one.
*   **`config.go`**: Handles loading the `config.json` file, which **only** contains the bot token, channel ID, and check interval.
*   **Other files:** `state.go`, `discord.go`, and `whois.go` serve their respective purposes in managing state, formatting messages, and handling lookups.

## 4. Tooling & Dependencies

*   **Go Libraries:** `discordgo`, `go-sqlite3`, `whois`, `whois-parser`.
*   **External Tools:** `systemd`, `install_service.sh`.
