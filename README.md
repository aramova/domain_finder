# Domain Finder

![Go Version](https://img.shields.io/badge/Go-1.19%2B-blue)
![License](https://img.shields.io/badge/License-MIT-green)
![Status](https://img.shields.io/badge/Status-Active-success)

**Domain Finder** is a robust, production-ready Discord bot written in Go. It autonomously monitors domain names for critical changes (WHOIS data) and upcoming expirations, alerting you directly in your Discord server. It features a persistent SQLite database, interactive commands, and a secure systemd service installer.

## ✨ Key Features

*   **🔍 Automated WHOIS Monitoring:** Periodically checks your domains against a configurable schedule.
*   **🚨 Smart Alerts:**
    *   **Change Detection:** Instantly notifies you of changes to `Updated Date`, `Expiry Date`, `Registrant`, or `Name Servers`.
    *   **Expiration Warnings:** alerts 48 hours before expiration.
    *   **High-Frequency Mode:** Automatically switches to 1-minute checks for domains expiring within 60 minutes.
*   **💬 Interactive Discord Integration:**
    *   **Public Alerts:** Post alerts to a specific channel.
    *   **Acknowledge:** React with ✅ to acknowledge and silence active alerts.
    *   **Personal Reminders:** Users can set private DM reminders for specific domains (`!remindme`).
*   **💾 Persistent Storage:** All domain data, history, and user preferences are stored locally in a SQLite database (`domains.db`).
*   **🛡️ Secure & Production-Ready:** Includes a `systemd` installer script that sets up a dedicated, non-privileged user and locks down file permissions.

## 🚀 Getting Started

### Prerequisites

*   **Go 1.19+** installed on your system.
*   A **Discord Bot Token** (see below).

### Installation

#### 1. Clone the Repository
```bash
git clone https://github.com/aramova/domain_finder.git
cd domain_finder
```

#### 2. Configure the Bot
Create a `config.json` file in the project root. You can use the example as a template:

```bash
cp config.example.json config.json
```

Edit `config.json` to add your credentials:
```json
{
  "discord_bot_token": "YOUR_BOT_TOKEN_HERE",
  "discord_channel_id": "YOUR_CHANNEL_ID_HERE",
  "check_interval_minutes": 60
}
```

> **How to get a Token:**
> 1. Go to the [Discord Developer Portal](https://discord.com/developers/applications).
> 2. Create a New Application -> **Bot** -> **Add Bot**.
> 3. **Reset Token** to get your secret token.
> 4. Enable **Message Content Intent** and **Server Members Intent**.
> 5. Use the **OAuth2 URL Generator** (scope: `bot`, permissions: `Send Messages`, `Read Message History`, `Add Reactions`) to invite the bot to your server.

#### 3. Build & Run (Development)
```bash
go build -o domain_finder
./domain_finder
```

### 📦 Production Deployment (Linux)

For a permanent installation, use the provided installer script. This sets up the bot as a systemd service running under a restricted user.

1.  **Build the binary:**
    ```bash
    go build -o domain_finder
    ```
2.  **Run the Installer (as root):**
    ```bash
    sudo ./install_service.sh
    ```
    *   Creates a system user `domain_finder`.
    *   Installs binary to `/usr/local/bin/domain_finder`.
    *   Configs go to `/etc/domain_finder/`.
    *   Database goes to `/var/lib/domain_finder/`.
    *   Enables the `domain_finder` systemd service.

3.  **Manage the Service:**
    ```bash
    sudo systemctl start domain_finder
    sudo systemctl status domain_finder
    sudo journalctl -u domain_finder -f
    ```

## 🤖 Commands

| Command | Description | Example |
| :--- | :--- | :--- |
| `!help` | Show this help message. | `!help` |
| `!lookup <domain>` | Perform an immediate WHOIS lookup. | `!lookup google.com` |
| `!add <domain>` | Add a domain to the monitoring list. | `!add github.com` |
| `!remove <domain>` | Stop monitoring a domain. | `!remove github.com` |
| `!list` | Show all currently monitored domains. | `!list` |
| `!stats <domain> [n]` | View historical WHOIS data (n=1 is latest). | `!stats google.com 2` |
| `!remindme [domain]` | Set a personal DM reminder for a domain. | `!remindme google.com` |
| `!testremindme <domain>` | Test the DM reminder flow. | `!testremindme google.com` |

## 🛠️ Architecture

*   **`main.go`**: Entry point, config loading, and service orchestration.
*   **`scheduler.go`**: The heartbeat. Manages the ticker and triggers domain checks.
*   **`database.go`**: SQLite interactions (schema, CRUD operations).
*   **`discord.go`**: Discord API wrapper and event handlers.
*   **`whois.go`**: WHOIS parsing and comparison logic.

## 🤝 Contributing

Contributions are welcome! Please check out the `CONTRIBUTING.md` (coming soon) or open an issue.

## 📄 License

This project is licensed under the MIT License.
