# Domain Finder

`domain_finder` is a Go-based bot that monitors a list of domain names for changes and upcoming expirations. It sends notifications to a Discord channel and allows for interactive acknowledgment of alerts.

## Features

-   **WHOIS Monitoring:** Regularly performs WHOIS lookups on a list of domains.
-   **Change Detection:** Detects changes in key WHOIS fields (`Updated Date`, `Expiry Date`, `Registrant Name`, `Name Servers`).
-   **Expiration Alerts:** Sends warnings for domains expiring within 48 hours.
-   **High-Frequency Expiration Alerts:** Switches to a 1-minute check interval for any domain that is within 60 minutes of expiring.
-   **Detailed Change Notifications:** When a change is detected, the bot sends a message containing the full, structured WHOIS data of the new record.
-   **Interactive Alerts:** Acknowledge public alerts by reacting with a ✅ emoji.
-   **Personal DM Reminders:** Users can request to be DMed when a specific domain is about to expire. These can be silenced by replying `ack`.
-   **Persistent Storage:** Uses a local SQLite database (`domains.db`) to store all data.
-   **Secure by Default:** Includes an installer that creates a non-privileged system user and sets secure file permissions.

## Getting Started

### 1. Prerequisites

-   Go (version 1.19 or newer is recommended)
-   A Discord Bot Token

### 2. Installation

#### a) Create Your Discord Bot

Before running the application, you need a Discord Bot Token.

1.  **Go to the [Discord Developer Portal](https://discord.com/developers/applications).**
2.  Create a **New Application**, then go to the **Bot** tab and **Add Bot**.
3.  **Get the Bot Token:** Click **Reset Token** and copy the revealed token. **This is a secret, do not share it.**
4.  **Enable Intents:** On the "Bot" page, enable the **`MESSAGE CONTENT INTENT`** and **`SERVER MEMBERS INTENT`**.
5.  **Invite the Bot:** Go to the **OAuth2 -> URL Generator** tab. Select the `bot` scope, then grant `Send Messages` and `Read Message History` permissions. Copy the generated URL and paste it into your browser to invite the bot to your server.
6.  **Enable DMs:** For the `!remindme` feature to work, users must **"Allow direct messages from server members"** in your server's privacy settings.

#### b) Build from Source

First, clone the repository:
```bash
git clone <repository-url>
cd domain_finder
```

Next, create your configuration file. The bot looks for a `config.json` file in its working directory.
```bash
cp config.example.json config.json
```
Now, edit `config.json` and add your Discord Bot Token and the ID of the channel you want alerts in.

Finally, build the binary.
```bash
go build
```

**Note on Go versions:**
If you encounter build errors related to the `go.mod` file, running `go mod tidy` will often resolve them by synchronizing the project's dependencies with your installed Go version.

### 3. Running the Bot

The recommended way to run the bot in a production environment is with the provided installer script.

#### Production (Systemd Service)

The `install_service.sh` script automates the process of setting up the bot to run as a secure `systemd` service.

1.  **Build the Executable:** Follow the build steps above.
2.  **Run the Installer:**
    ```bash
    sudo ./install_service.sh
    ```
    The installer will:
    -   Create a non-privileged system user `domain_finder`.
    -   Copy the binary to `/usr/local/bin`.
    -   Create the configuration directory `/etc/domain_finder` and copy your `config.json` into it.
    -   Set secure permissions for all files.
    -   Install and enable the `domain_finder.service` unit file.
3.  **Start the Service:**
    ```bash
    sudo systemctl start domain_finder
    ```

#### Development

For development, you can run the bot directly from the project directory after building it.
```bash
./domain_finder
```
The bot will use the `config.json` and `domains.db` files in the current directory.

## Bot Commands

-   `!help`: Shows a help message.
-   `!lookup <domain>`: Performs an on-demand WHOIS lookup.
-   `!add <domain>`: Adds a domain to the monitoring list.
-   `!remove <domain>`: Removes a domain from the monitoring list.
-   `!list`: Lists all monitored domains.
-   `!stats <domain> [n]`: Shows historical WHOIS data. `n` is the optional history offset (1 = latest).
-   `!remindme [domain]`: Manages personal DM reminders.
-   `!testremindme <domain>`: Tests the DM reminder functionality.
