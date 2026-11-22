#!/usr/bin/env bash
set -e

# ==========================================================
# Proton-Socks: One-Step Linux Installer
# Pure Rust Userspace WireGuard SOCKS5 Proxy Gateway
# ==========================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

echo -e "${CYAN}"
echo "  ____            _               ____             _        "
echo " |  _ \ _ __ ___ | |_ ___  _ __  / ___|  ___   ___| | _____ "
echo " | |_) | '__/ _ \| __/ _ \| '_ \ \___ \ / _ \ / __| |/ / __|"
echo " |  __/| | | (_) | || (_) | | | | ___) | (_) | (__|   <\__ \ "
echo " |_|   |_|  \___/ \__\___/|_| |_||____/ \___/ \___|_|\_\___/"
echo "     Pure-Rust Userspace Proton VPN SOCKS5 Gateway Installer"
echo -e "${NC}"

# Check root permissions
if [ "$EUID" -ne 0 ]; then
  echo -e "${RED}[ERROR] Please run this installer as root (e.g. sudo bash install.sh)${NC}"
  exit 1
fi

echo -e "${GREEN}[1/5] Checking and installing dependencies...${NC}"
if command -v apt-get >/dev/null 2>&1; then
    apt-get update -y
    apt-get install -y build-essential curl pkg-config libssl-dev git
elif command -v yum >/dev/null 2>&1; then
    yum groupinstall -y "Development Tools"
    yum install -y curl pkgconfig openssl-devel git
elif command -v pacman >/dev/null 2>&1; then
    pacman -Sy --noconfirm base-devel curl openssl git
fi

# Ensure Rust is available
if ! command -v cargo >/dev/null 2>&1; then
    echo -e "${YELLOW}[INFO] Rust toolchain not detected. Installing via rustup...${NC}"
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source "$HOME/.cargo/env"
fi

echo -e "${GREEN}[2/5] Compiling proton-socks (Release build)...${NC}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

cargo build --release

echo -e "${GREEN}[3/5] Installing binary and symlinks...${NC}"
cp target/release/proton-socks /usr/local/bin/proton-socks
chmod 755 /usr/local/bin/proton-socks
ln -sf /usr/local/bin/proton-socks /usr/local/bin/psocks
ln -sf /usr/local/bin/proton-socks /usr/local/bin/ProtonSocks

echo -e "${GREEN}[4/5] Setting up configuration directories and systemd service...${NC}"
mkdir -p /etc/proton-socks/accounts
chmod 700 /etc/proton-socks

if [ ! -f /etc/proton-socks/config.json ]; then
cat <<EOF > /etc/proton-socks/config.json
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
chmod 600 /etc/proton-socks/config.json
fi

cp systemd/proton-socks.service /etc/systemd/system/proton-socks.service
systemctl daemon-reload
systemctl enable proton-socks

echo -e "${GREEN}[5/5] Installation complete!${NC}"
echo -e "${CYAN}Commands available:${NC}"
echo "  sudo ProtonSocks (or sudo psocks) -> Open interactive menu"
echo "  systemctl start proton-socks      -> Start background daemon"
echo "  systemctl status proton-socks     -> View daemon status"
echo "  journalctl -u proton-socks -f     -> View live logs"
echo ""

read -p "Would you like to start the interactive menu now? (y/n): " start_menu
if [[ "$start_menu" =~ ^[Yy]$ ]]; then
    proton-socks menu
fi
