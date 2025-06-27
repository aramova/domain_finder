# Domain Finder: Testing Analysis

This document provides a comprehensive overview of the unit tests conducted for the `domain_finder` application.

## Files Tested

-   `config_test.go`
-   `database_test.go`
-   `discord_test.go`
-   `main_test.go`
-   `scheduler_test.go`
-   `whois_test.go`
-   `log_test.go`
-   `security.go`

---

## Test Breakdown by File

### 1. `config_test.go`

This file tests the loading and parsing of the `config.json` file.

| Test Function                       | Description                                                              | Test Cases                                                              |
| ----------------------------------- | ------------------------------------------------------------------------ | ----------------------------------------------------------------------- |
| `TestLoadConfiguration_Success`     | Tests the successful loading of a valid `config.json` file.              | A valid temporary config file is created and loaded successfully.       |
| `TestLoadConfiguration_FileNotExist`  | Tests the failure case where the config file does not exist.             | Attempts to load a non-existent file, expecting an error.               |
| `TestLoadConfiguration_InvalidJson`   | Tests the failure case where the config file contains invalid JSON.      | Attempts to load a file with malformed JSON, expecting an error.        |
| `TestLoadConfiguration_MissingFields` | Tests the loading of a config file with missing (but not essential) fields. | Loads a config file with a missing `discord_channel_id` to ensure it parses without error. |

### 2. `database_test.go`

This file tests all interactions with the SQLite database.

| Test Function                         | Description                                                              | Test Cases                                                              |
| ------------------------------------- | ------------------------------------------------------------------------ | ----------------------------------------------------------------------- |
| `TestInitializeDatabase`              | Tests that all required tables are created in the database.              | Checks for the existence of `domain_history`, `active_alerts`, `domain_reminders`, and `monitored_domains` tables after initialization. |
| `TestMonitoredDomains`                | Tests the full lifecycle of a monitored domain (add, check, remove).     | Adds two domains, verifies they are monitored, removes one, and verifies the list is correct. |
| `TestSaveAndGetLatestWhoisRecord`     | Tests saving and retrieving WHOIS records.                               | Saves a record, retrieves it, saves a newer record for the same domain, and verifies that the newer one is returned as the latest. |
| `TestGetLatestWhoisRecord_NoRecord`   | Tests retrieving a record for a domain that has no history.              | Attempts to get a record for a non-existent domain, expecting `nil`.    |
| `TestActiveAlerts`                    | Tests the lifecycle of an alert (creation and acknowledgment).           | Saves an active alert, verifies it's considered active, acknowledges it, and verifies it's no longer considered active. |
| `TestReminders`                       | Tests the full lifecycle of user-specific reminders.                     | Adds a reminder, retrieves it, checks which users should be reminded, sets the "alerting" status, and finally deactivates the reminder. |

### 3. `discord_test.go`

This file tests the formatting of messages sent to Discord.

| Test Function                      | Description                                                              | Test Cases                                                              |
| ---------------------------------- | ------------------------------------------------------------------------ | ----------------------------------------------------------------------- |
| `TestFormatHelpMessage`            | Ensures the help message contains all commands.                          | Checks for the presence of `!help`, `!lookup`, `!add`, `!remove`, `!list`, `!remindme`, and `!testremindme` in the output string. |
| `TestFormatChangeNotification`     | Tests the formatting of a domain change notification.                    | Formats a notification for a changed record and verifies that the output contains valid JSON and includes the correct new data. |
| `TestFormatExpiryNotification`     | Tests the formatting of a domain expiration warning.                     | Formats a warning for a domain expiring in 59 minutes and verifies the output string contains the correct details. |
| `TestFormatListResponse`           | Tests the formatting of the monitored domain list.                       | Formats a list containing two domains and verifies the output contains the correct titles and data for both. |
| `TestFormatListResponse_Empty`     | Tests the formatting of an empty domain list.                            | Formats an empty list and verifies the output contains the "No domains are currently being monitored" message. |

### 4. `main_test.go`

This file tests the core validation logic in the `main` package.

| Test Function         | Description                                       | Test Cases                                                              |
| --------------------- | ------------------------------------------------- | ----------------------------------------------------------------------- |
| `TestIsValidDomain`   | Tests the domain validation regular expression.   | - `google.com` (valid)<br>- `example.co.uk` (valid)<br>- `a-domain.net` (valid)<br>- `123.io` (valid)<br>- `xn--bcher-kva.de` (Punycode, valid)<br>- `""` (empty, invalid)<br>- `-invalid.com` (leading hyphen, invalid)<br>- `invalid-.com` (trailing hyphen, invalid)<br>- `invalid.c` (TLD too short, invalid)<br>- `invalid` (no TLD, invalid)<br>- `invalid.com-` (trailing hyphen on TLD, invalid)<br>- `invalid..com` (double dot, invalid)<br>- `!@#$%.com` (special characters, invalid) |

### 5. `scheduler_test.go`

This file tests the core domain processing logic of the scheduler.

| Test Function         | Description                                       | Test Cases                                                              |
| --------------------- | ------------------------------------------------- | ----------------------------------------------------------------------- |
| `TestProcessDomain`   | Tests the core domain processing logic.           | - **Change Detected**: Simulates a `WHOIS` lookup that returns data different from the stored record, expecting a "change" action.<br>- **Expiry Warning**: Simulates a `WHOIS` lookup for a domain that is about to expire, expecting an "expiry" action.<br>- **Alert Already Active**: Simulates a `WHOIS` lookup for a changed domain where an alert for that specific change has already been sent, expecting zero actions. |

### 6. `whois_test.go`

This file tests the parsing and comparison of WHOIS records.

| Test Function               | Description                                       | Test Cases                                                              |
| --------------------------- | ------------------------------------------------- | ----------------------------------------------------------------------- |
| `TestParseWhois`            | Tests the parsing of a raw WHOIS text block.      | Parses a sample `google.com` record and verifies that the domain name, registrar, registrant, expiry date, and name servers are all extracted correctly. |
| `TestCompareWhoisRecords`   | Tests the logic for comparing two `WHOIS` records. | - **No change**: Compares a record against itself, expecting no differences.<br>- **Expiry Date changed**: Compares two records where only the expiry date differs, expecting one specific change.<br>- **Registrant and Name Servers changed**: Compares two records with multiple changes, expecting two specific changes. |

---

## Security Testing

A series of tests were added to proactively identify and prevent common security vulnerabilities.

| Test Function               | File                | Description                                                                                                                                                                                                                                                                                                                                                     |
| --------------------------- | ------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `TestSQLInjection`          | `database_test.go`  | Ensures that a maliciously crafted domain name (e.g., `'; DROP TABLE monitored_domains; --`) cannot be used to execute arbitrary SQL commands. The test passes if the input is saved as a literal string and the database schema remains unharmed.                                                                                                                   |
| `TestIsValidDomain_ReDoS`   | `main_test.go`      | Checks for Regular Expression Denial of Service vulnerabilities. It passes a long, potentially problematic string to the domain validation regex and asserts that the function completes quickly (under 10ms), preventing the application from hanging on "evil" input.                                                                                             |
| `TestLogInjection`          | `log_test.go`       | Verifies that user input with newline characters cannot be used to forge log entries. The test passes if a multi-line malicious string is sanitized into a single line in the final log output. **Note:** The successful test output will contain the malicious string (e.g., `[FATAL]...`), but it will be on a single, harmless line, proving the injection was blocked. |
| `TestMarkdownInjection`     | `discord_test.go`   | Checks if user input containing markdown characters (like backticks) can break Discord message formatting. This test currently passes, indicating that the `discordgo` library provides automatic sanitization. It remains in the suite as a regression test.                                                                                             |

