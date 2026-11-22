#!/usr/bin/env bash
set -e

# ==========================================================
# ProtonSocks: One-Step Linux Auto-Installer
# Pure Rust Userspace WireGuard SOCKS5 Proxy Gateway
# ==========================================================

REPO_OWNER="VindEi"
REPO_NAME="ProtonSocks"
INSTALL_DIR="/opt/ProtonSocks"
BIN_TARGET="/usr/local/bin/ProtonSocks"
CONFIG_DIR="/etc/ProtonSocks"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${CYAN}"
echo "  ____            _               ____             _        "
echo " |  _ \ _ __ ___ | |_ ___  _ __  / ___|  ___   ___| | _____ "
echo " | |_) | '__/ _ \| __/ _ \| '_ \ \___ \ / _ \ / __| |/ / __|"
echo " |  __/| | | (_) | || (_) | | | | ___) | (_) | (__|   <\__ \ "
echo " |_|   |_|  \___/ \__\___/|_| |_||____/ \___/ \___|_|\_\___/"
echo "     Pure-Rust Userspace Proton VPN SOCKS5 Gateway Installer"
echo -e "${NC}"

# Check root
if [ "$EUID" -ne 0 ]; then
  echo -e "${RED}[ERROR] Please run this installer as root (e.g. sudo bash install.sh)${NC}"
  exit 1
fi

# Detect architecture
ARCH="$(uname -m)"
case "$ARCH" in
  x86_64|amd64)
    RELEASE_ASSET="ProtonSocks-linux-amd64"
    ;;
  aarch64|arm64)
    RELEASE_ASSET="ProtonSocks-linux-arm64"
    ;;
  *)
    RELEASE_ASSET=""
    ;;
esac

echo -e "${GREEN}[1/4] Installing system dependencies...${NC}"
if command -v apt-get >/dev/null 2>&1; then
    apt-get update -y
    apt-get install -y curl tar git
elif command -v yum >/dev/null 2>&1; then
    yum install -y curl tar git
elif command -v pacman >/dev/null 2>&1; then
    pacman -Sy --noconfirm curl tar git
fi

# Try fast pre-built binary installation if not forced to build
INSTALLED_FROM_BIN=0
if [ "$1" != "--build" ] && [ -n "$RELEASE_ASSET" ]; then
    echo -e "${GREEN}[2/4] Checking for pre-built release binary (${RELEASE_ASSET})...${NC}"
    DOWNLOAD_URL="https://github.com/${REPO_OWNER}/${REPO_NAME}/releases/latest/download/${RELEASE_ASSET}"
    
    if curl -sLf "$DOWNLOAD_URL" -o /tmp/ProtonSocks_bin; then
        echo -e "${GREEN}Downloaded pre-built binary successfully!${NC}"
        mv /tmp/ProtonSocks_bin "$BIN_TARGET"
        chmod 755 "$BIN_TARGET"
        INSTALLED_FROM_BIN=1
    else
        echo -e "${YELLOW}Pre-built binary not found on latest release. Falling back to build from source...${NC}"
    fi
fi

# Build from source fallback
if [ "$INSTALLED_FROM_BIN" -eq 0 ]; then
    echo -e "${GREEN}[2/4] Building ProtonSocks from source...${NC}"
    
    if command -v apt-get >/dev/null 2>&1; then
        apt-get install -y build-essential pkg-config
    elif command -v yum >/dev/null 2>&1; then
        yum groupinstall -y "Development Tools"
        yum install -y pkgconfig
    elif command -v pacman >/dev/null 2>&1; then
        pacman -Sy --noconfirm base-devel
    fi

    # Ensure Rust is available
    if ! command -v cargo >/dev/null 2>&1; then
        echo -e "${YELLOW}Rust toolchain not detected. Installing via rustup...${NC}"
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
        source "$HOME/.cargo/env" || export PATH="$HOME/.cargo/bin:$PATH"
    fi

    # Check if we are inside the source directory or need to clone
    if [ ! -f "Cargo.toml" ]; then
        echo -e "${CYAN}Cloning ${REPO_NAME} into ${INSTALL_DIR}...${NC}"
        rm -rf "$INSTALL_DIR"
        git clone "https://github.com/${REPO_OWNER}/${REPO_NAME}.git" "$INSTALL_DIR"
        cd "$INSTALL_DIR"
    fi

    cargo build --release

    if [ -f "target/release/ProtonSocks" ]; then
        cp target/release/ProtonSocks "$BIN_TARGET"
    else
        cp target/release/proton-socks "$BIN_TARGET"
    fi
    chmod 755 "$BIN_TARGET"
fi

# Create convenient symlinks
ln -sf "$BIN_TARGET" /usr/local/bin/psocks
ln -sf "$BIN_TARGET" /usr/local/bin/proton-socks

echo -e "${GREEN}[3/4] Setting up configuration and systemd service...${NC}"
mkdir -p "${CONFIG_DIR}/accounts"
chmod 700 "$CONFIG_DIR"
ln -sfn "$CONFIG_DIR" /etc/proton-socks

if [ ! -f "${CONFIG_DIR}/config.json" ]; then
cat <<EOF > "${CONFIG_DIR}/config.json"
{
  "base_port": 25000,
  "bind_address": "127.0.0.1",
  "auth_required": false,
  "auth_username": "",
  "auth_password": "",
  "benchmark_interval_hours": 4,
  "auto_best_metric": "ping",
  "best_account_id": null
}
EOF
chmod 600 "${CONFIG_DIR}/config.json"
fi

cat <<EOF > /etc/systemd/system/ProtonSocks.service
[Unit]
Description=ProtonSocks Userspace WireGuard Multi-Account SOCKS5 Gateway
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=${CONFIG_DIR}
ExecStart=${BIN_TARGET} --config-dir ${CONFIG_DIR} daemon
Restart=on-failure
RestartSec=5s
LimitNOFILE=65535
AmbientCapabilities=
CapabilityBoundingSet=
NoNewPrivileges=true
ProtectSystem=full
ProtectHome=true

[Install]
WantedBy=multi-user.target
EOF

ln -sf /etc/systemd/system/ProtonSocks.service /etc/systemd/system/proton-socks.service

systemctl daemon-reload
systemctl enable ProtonSocks

echo -e "${GREEN}[4/4] Installation completed successfully!${NC}"
echo -e "${CYAN}Available commands:${NC}"
echo "  sudo ProtonSocks (or sudo psocks) -> Open interactive menu"
echo "  sudo ProtonSocks update           -> Check and apply updates"
echo "  systemctl start ProtonSocks       -> Start background daemon"
echo "  systemctl status ProtonSocks      -> Check daemon status"
echo "  journalctl -u ProtonSocks -f      -> View live daemon logs"
echo ""

if [ -t 0 ]; then
    read -p "Would you like to open the menu now? (y/n): " start_menu
    if [[ "$start_menu" =~ ^[Yy]$ ]]; then
        ProtonSocks menu
    fi
fi
