# ProtonSocks

Linux daemon that exposes Proton VPN connections as local SOCKS5 proxies using userspace WireGuard.

The program runs WireGuard in userspace using boringtun and smoltcp. It does not create kernel network interfaces like `wg0`, does not modify host routing tables, and does not require root network administration privileges.

## Features

- Userspace WireGuard. Network packets stay inside the process and route through local SOCKS5 ports.
- Proton API integration. Handles SRP-6a login, detects free and paid tiers, and generates WireGuard keys. You can also import existing `.conf` files directly.
- Port routing. Port 25000 routes to the account with the lowest latency or highest speed. Each configured account gets a dedicated port starting at 25001.
- Background optimization. Every 4 hours, a background task tests latency and throughput, then assigns port 25000 to the fastest node.
- Interface security. Listens on 127.0.0.1 by default. Binding to 0.0.0.0 requires SOCKS5 username and password authentication.

## One-line auto installer

Run the one-step installer directly on any Linux machine (Ubuntu, Debian, CentOS, Arch):

```bash
curl -fsSL https://raw.githubusercontent.com/VindEi/ProtonSocks/main/install.sh | sudo bash
```

The script automatically detects your architecture (`x86_64` or `arm64`), installs the binary to `/usr/local/bin/ProtonSocks`, creates symlinks, initializes `/etc/ProtonSocks/`, and configures the `ProtonSocks.service` systemd unit.

## Configuration layout

Settings and accounts are stored as plain JSON files in `/etc/ProtonSocks/`:

```
/etc/ProtonSocks/
├── config.json
└── accounts/
    ├── acc_1_nl.json
    └── acc_2_us.json
```

### Global configuration (`config.json`)

```json
{
  "base_port": 25000,
  "bind_address": "127.0.0.1",
  "auth_required": false,
  "auth_username": "",
  "auth_password": "",
  "benchmark_interval_hours": 4,
  "auto_best_metric": "ping",
  "best_account_id": "acc_1_nl"
}
```

### Account file example (`accounts/acc_1_nl.json`)

```json
{
  "id": "acc_1_nl",
  "label": "Proton-NL",
  "username": "user",
  "country": "NL",
  "tier": 0,
  "port": 25001,
  "tokens": {
    "access_token": "...",
    "refresh_token": "...",
    "uid": "..."
  },
  "wireguard": {
    "private_key": "...",
    "public_key": "...",
    "client_ip": "10.2.0.2/32",
    "dns": "10.2.0.1",
    "server_name": "NL-FREE#135",
    "server_public_key": "...",
    "server_endpoint": "169.150.218.65:51820"
  },
  "created_at": 1715000000
}
```

You can edit or delete these files directly with any text editor. The daemon reloads them on startup.

## Usage

### Interactive menu

Run `ProtonSocks` or `psocks` with root permissions to open the menu:

```bash
sudo ProtonSocks
# or
sudo psocks
```

Menu options:

1. Dashboard and status
2. Add account (API login or .conf file import)
3. Remove account
4. Run latency and speed test
5. Set routing mode (latency or speed)
6. Settings (ports, bind address, authentication)
7. Check for updates / Update
8. Exit

### Service management

Control the background daemon with systemctl:

```bash
sudo systemctl start ProtonSocks
sudo systemctl enable ProtonSocks
sudo systemctl status ProtonSocks
```

Inspect daemon logs:

```bash
journalctl -u ProtonSocks -f
```

### Command line options

```bash
# Open interactive menu
sudo ProtonSocks

# Check for updates and rebuild
sudo ProtonSocks update

# Run daemon directly in the terminal
sudo ProtonSocks daemon

# Run latency and speed tests across accounts
sudo ProtonSocks benchmark --speed

# List configured accounts and ports
sudo ProtonSocks list
```

## Testing connection with curl

Test the auto-routing gateway on port 25000:

```bash
curl -x socks5h://127.0.0.1:25000 https://ipinfo.io/json
```

Test a specific country gateway on port 25001:

```bash
curl -x socks5h://127.0.0.1:25001 https://ipinfo.io/json
```

With authentication (if enabled):

```bash
curl -x socks5h://username:password@127.0.0.1:25000 https://ipinfo.io/json
```
