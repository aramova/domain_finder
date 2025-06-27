#!/bin/bash
#
# Production Installer for the Domain Finder Service
#
# This script will:
#   1. Create a dedicated system user and group.
#   2. Install the application binary to /usr/local/bin.
#   3. Create a configuration directory in /etc.
#   4. Set secure permissions for all files and directories.
#   5. Install and enable a systemd service to run the bot.
#

set -e # Exit immediately if a command exits with a non-zero status.

# --- Configuration ---
APP_NAME="domain_finder"
SYSTEM_USER="${APP_NAME}"
SYSTEM_GROUP="${APP_NAME}"
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/${APP_NAME}"
DB_DIR="/var/lib/${APP_NAME}"
CONFIG_FILE_NAME="config.json"
SERVICE_FILE="/etc/systemd/system/${APP_NAME}.service"
# --- End Configuration ---

echo "Domain Finder Production Service Installer"
echo "------------------------------------------"

# 1. Check for root privileges
if [ "$EUID" -ne 0 ]; then
  echo "ERROR: This script must be run as root. Please use 'sudo ./install_service.sh'"
  exit 1
fi

# 2. Check if the executable exists and build if necessary
if [ ! -f "./${APP_NAME}" ]; then
    echo "WARNING: The '${APP_NAME}' executable does not exist."
    read -p "Do you want to attempt to build it now? (y/n) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        echo "Building..."
        if ! go build -o ${APP_NAME}; then
            echo "ERROR: Build failed. Please resolve build errors before running this installer."
            exit 1
        fi
        echo "Build successful."
    else
        echo "Installation aborted. Please build the executable first."
        exit 1
    fi
fi

# 3. Create dedicated system user and group
echo "Creating system user and group '${SYSTEM_USER}'..."
if ! getent group ${SYSTEM_GROUP} >/dev/null; then
    groupadd --system ${SYSTEM_GROUP}
else
    echo "Group '${SYSTEM_GROUP}' already exists. Skipping."
fi

if ! id -u ${SYSTEM_USER} >/dev/null 2>&1; then
    useradd --system --no-create-home --shell /usr/sbin/nologin -g ${SYSTEM_GROUP} ${SYSTEM_USER}
else
    echo "User '${SYSTEM_USER}' already exists. Skipping."
fi

# 4. Install binary
echo "Installing binary to ${INSTALL_DIR}/${APP_NAME}..."
install -m 755 "./${APP_NAME}" "${INSTALL_DIR}/"

# 5. Create directories
echo "Creating configuration directory at ${CONFIG_DIR}..."
mkdir -p "${CONFIG_DIR}"
echo "Creating database directory at ${DB_DIR}..."
mkdir -p "${DB_DIR}"

# 6. Install default configuration if one doesn't exist
if [ ! -f "${CONFIG_DIR}/${CONFIG_FILE_NAME}" ]; then
    echo "Installing default configuration to ${CONFIG_DIR}/${CONFIG_FILE_NAME}..."
    cat > "${CONFIG_DIR}/${CONFIG_FILE_NAME}" << EOL
{
  "discord_bot_token": "",
  "discord_channel_id": "",
  "check_interval_minutes": 60
}
EOL
else
    echo "Configuration file already exists at ${CONFIG_DIR}/${CONFIG_FILE_NAME}. Skipping default installation."
fi

# 7. Set secure permissions
echo "Setting ownership and permissions..."
chown -R root:${SYSTEM_GROUP} "${CONFIG_DIR}"
chmod 750 "${CONFIG_DIR}"
chmod 640 "${CONFIG_DIR}/${CONFIG_FILE_NAME}"
chown -R ${SYSTEM_USER}:${SYSTEM_GROUP} "${DB_DIR}"
chmod 750 "${DB_DIR}"

# 8. Create and install systemd service file
echo "Creating systemd service file at ${SERVICE_FILE}..."
cat > "${SERVICE_FILE}" << EOL
[Unit]
Description=Domain Finder Bot
After=network.target

[Service]
Type=simple
User=${SYSTEM_USER}
Group=${SYSTEM_GROUP}
# The application will look for config.json in its working directory
WorkingDirectory=${CONFIG_DIR}
# The database will be created in the working directory unless an absolute path is specified
ExecStart=${INSTALL_DIR}/${APP_NAME} -configdir=${CONFIG_DIR} -dbdir=${DB_DIR}
Restart=on-failure
RestartSec=5s
# Security Hardening
PrivateTmp=true
ProtectSystem=full
NoNewPrivileges=true
PrivateDevices=true
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
RestrictRealtime=true

[Install]
WantedBy=multi-user.target
EOL

# 9. Reload systemd and provide final instructions
echo "Reloading systemd daemon..."
systemctl daemon-reload

echo
echo "----------------------------------------------------------------"
echo "✅ Installation Complete!"
echo
echo "IMPORTANT: You must now edit the configuration file:"
echo "  sudo nano ${CONFIG_DIR}/${CONFIG_FILE_NAME}"
echo
echo "After editing the config, you can enable and start the service with:"
echo "  sudo systemctl enable --now ${APP_NAME}"
echo
echo "You can check the status and logs of the service with:"
echo "  sudo systemctl status ${APP_NAME}"
echo "  journalctl -u ${APP_NAME} -f"
echo "----------------------------------------------------------------"
