# Salt-GUI

Web-based remote administration platform for SaltStack. Designed for CCDC (Collegiate Cyber Defense Competition) environments where speed and reliability are critical.

## Overview

Salt-GUI provides centralized management of Linux and Windows systems through SaltStack. It functions as a command-and-control (C2) interface for defensive security operations, enabling rapid script deployment, command execution, and system monitoring across an entire network from a single dashboard.

```
┌─────────────────────────────────────────────────────────────────┐
│                         BROWSER                                  │
└─────────────────────────────────────────────────────────────────┘
                              │ HTTP (Port 3000)
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                       SALT-GUI SERVER                            │
│                    (Node.js + Express)                           │
└─────────────────────────────────────────────────────────────────┘
                              │ REST API (Port 8000)
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                        SALT MASTER                               │
│                      (salt-api)                                  │
└─────────────────────────────────────────────────────────────────┘
                              │ ZeroMQ (Ports 4505/4506)
                              ▼
              ┌───────────┬───────────┬───────────┐
              │  Minion   │  Minion   │  Minion   │
              │  (Linux)  │ (Windows) │  (Linux)  │
              └───────────┴───────────┴───────────┘
```

## Features

| Feature | Description |
|---------|-------------|
| **Device Management** | View all minions, status, OS info, IP addresses |
| **Key Management** | Accept, reject, delete minion keys from the UI |
| **Command Execution** | Run commands on selected targets with shell selection |
| **Script Deployment** | Deploy bash/PowerShell scripts to minions |
| **Service Management** | Start, stop, enable, disable services |
| **Process Management** | List and kill processes by PID or pattern |
| **Password Management** | Change passwords on remote Linux/Windows systems |
| **Emergency Lockdown** | Rapidly secure compromised systems |
| **Audit Logging** | Full audit trail of all administrative actions |

## Requirements

### Server Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| OS | Debian 11+, Ubuntu 20.04+, RHEL 8+, Rocky 8+ | Ubuntu 24.04, Rocky 9 |
| RAM | 512 MB | 1 GB |
| Disk | 100 MB | 500 MB |
| Node.js | 18.x | 20.x LTS |

### Supported Distributions

**Debian-based:**
- Ubuntu 20.04, 22.04, 24.04
- Debian 11, 12
- Linux Mint, Pop!_OS, Kali

**RHEL-based:**
- Rocky Linux 8, 9
- Oracle Linux 8, 9
- AlmaLinux 8, 9
- CentOS Stream 8, 9
- Fedora 38+
- Amazon Linux 2

## Installation

### Quick Install

```bash
# Clone or download Salt-GUI
cd /opt
git clone <repository-url> salt-gui
cd salt-gui

# Run installer (installs Node.js, Salt Master, Salt API, Salt Minion)
sudo ./install.sh
```

### Installation Options

```bash
# Interactive installation (default)
sudo ./install.sh

# Automated installation with defaults
sudo ./install.sh --unattended

# Skip Salt installation (if already installed)
sudo ./install.sh --skip-salt

# Skip Salt Minion on this host
sudo ./install.sh --skip-minion

# Force reinstallation
sudo ./install.sh --force

# Custom installation directory
sudo ./install.sh --install-dir /usr/local/salt-gui

# Uninstall
sudo ./install.sh --uninstall
```

### Manual Installation

```bash
# 1. Install Node.js 20.x
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo bash -
sudo apt-get install -y nodejs

# 2. Install Salt Master and API
sudo apt-get install -y salt-master salt-api salt-minion

# 3. Configure Salt API (see Configuration section)

# 4. Install Salt-GUI
cd /opt/salt-gui
npm install --production

# 5. Start services
sudo systemctl enable --now salt-master salt-api salt-minion salt-gui
```

## Configuration

### Salt API Configuration

Create `/etc/salt/master.d/api.conf`:

```yaml
rest_cherrypy:
  port: 8000
  ssl_crt: /etc/salt/pki/api/salt-api.crt
  ssl_key: /etc/salt/pki/api/salt-api.key

external_auth:
  pam:
    root:
      - .*
      - '@runner'
      - '@wheel'
    saltadmin:
      - .*
      - '@runner'
      - '@wheel'
```

Generate SSL certificates:

```bash
sudo mkdir -p /etc/salt/pki/api
sudo openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
  -keyout /etc/salt/pki/api/salt-api.key \
  -out /etc/salt/pki/api/salt-api.crt \
  -subj "/CN=salt-api"
```

### Salt-GUI Configuration

Configuration files are in `/opt/salt-gui/config/`:

**app.yaml** - Application settings:
```yaml
server:
  port: 3000
  host: "0.0.0.0"

session:
  timeout_minutes: 30
```

**salt.yaml** - Salt API connection:
```yaml
api:
  url: "https://localhost:8000"
  username: "root"
  password: ""  # Set this or use PAM authentication
  eauth: "pam"
  verify_ssl: false
```

**auth.yaml** - User credentials (created via UI):
```yaml
users:
  admin:
    password_hash: "$2b$12$..."
    role: admin
```

## Usage

### First Access

1. Open `http://<server-ip>:3000` in your browser
2. Create an admin account on first access
3. Configure Salt API credentials in Settings
4. Accept any pending minion keys in the Keys tab

### Device Management

- **Devices tab**: View all connected minions
- **Keys tab**: Accept, reject, or delete minion keys
- Select devices using checkboxes for bulk operations
- Filter devices by name, OS, or IP

### Command Execution

1. Select target devices in the Devices tab
2. Go to Commands tab
3. Enter command and select shell (auto-detect, bash, PowerShell, cmd)
4. Click Execute

### Script Deployment

1. Place scripts in the `scripts/` directory:
   - `scripts/linux/` for bash scripts
   - `scripts/windows/` for PowerShell scripts
2. Go to Scripts tab
3. Select a script and target devices
4. Click Execute Script

### Emergency Lockdown

The Emergency tab provides rapid system lockdown:
- Blocks all incoming connections except Salt ports (4505/4506)
- Stops SSH, web servers, and other potentially exploited services
- Preserves Salt connectivity for continued management

**Use only when a system is compromised and needs immediate isolation.**

## Directory Structure

```
salt-gui/
├── server.js              # Main application
├── package.json           # Dependencies
├── install.sh             # Installation script
├── config/                # Configuration files
│   ├── app.yaml          # Application settings
│   ├── salt.yaml         # Salt API connection
│   └── auth.yaml         # User credentials
├── src/
│   ├── routes/           # API route handlers
│   ├── lib/              # Core libraries
│   └── middleware/       # Express middleware
├── public/               # Frontend files
│   ├── index.html        # Single-page application
│   ├── css/styles.css    # Stylesheet
│   └── js/app.js         # Frontend JavaScript
├── scripts/              # Deployment scripts
│   ├── linux/            # Bash scripts
│   └── windows/          # PowerShell scripts
├── states/               # Salt states
│   ├── linux/
│   └── windows/
└── logs/                 # Log files
    └── audit.yaml        # Audit log
```

## API Reference

### Authentication

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/auth/login` | POST | Authenticate user |
| `/api/auth/logout` | POST | End session |
| `/api/auth/status` | GET | Check authentication |

### Devices

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/devices` | GET | List all minions |
| `/api/devices/:id` | GET | Get minion details |
| `/api/devices/keys/all` | GET | List all keys by status |
| `/api/devices/keys/accept` | POST | Accept a key |
| `/api/devices/keys/reject` | POST | Reject a key |
| `/api/devices/keys/:id` | DELETE | Delete a key |

### Commands

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/commands/run` | POST | Execute command on targets |

### Services

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/services/:target` | GET | List services |
| `/api/services/start` | POST | Start service |
| `/api/services/stop` | POST | Stop service |
| `/api/services/restart` | POST | Restart service |

### Emergency

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/emergency/lockdown` | POST | Initiate system lockdown |
| `/api/emergency/unlock` | POST | Reverse lockdown |

## Service Management

```bash
# Start Salt-GUI
sudo systemctl start salt-gui

# Stop Salt-GUI
sudo systemctl stop salt-gui

# Restart Salt-GUI
sudo systemctl restart salt-gui

# View logs
sudo journalctl -u salt-gui -f

# Check status
sudo systemctl status salt-gui
```

## Troubleshooting

### Salt-GUI won't start

```bash
# Check logs
journalctl -u salt-gui -n 50

# Verify Node.js
node --version  # Should be 18+

# Check config syntax
node -c server.js
```

### Cannot connect to Salt API

```bash
# Check salt-api is running
systemctl status salt-api

# Test Salt API directly
curl -k https://localhost:8000/login \
  -d username=root \
  -d password=yourpassword \
  -d eauth=pam

# Check firewall
firewall-cmd --list-ports  # RHEL
ufw status                  # Debian
```

### Minions not appearing

```bash
# Check minion is running
salt-minion --version
systemctl status salt-minion

# Check minion can reach master
salt-call test.ping

# List pending keys
salt-key -L

# Accept all pending keys
salt-key -A -y
```

### Authentication failures

```bash
# Verify PAM authentication works
su - saltadmin  # Test the user can login

# Check Salt API external_auth config
cat /etc/salt/master.d/api.conf

# Restart Salt services after config changes
systemctl restart salt-master salt-api
```

## Security Considerations

1. **Change default credentials** - Create a strong admin password on first access
2. **Use HTTPS** - Configure a reverse proxy (nginx/Apache) with TLS for production
3. **Restrict network access** - Limit access to Salt-GUI port (3000) to trusted networks
4. **Review audit logs** - All actions are logged in `logs/audit.yaml`
5. **Salt API credentials** - Store securely, consider using PAM authentication
6. **Firewall rules** - Only expose necessary ports (3000 for GUI, 4505/4506 for Salt)

## Ports Used

| Port | Service | Purpose |
|------|---------|---------|
| 3000 | Salt-GUI | Web interface |
| 4505 | Salt Master | Publisher (minion subscriptions) |
| 4506 | Salt Master | Request server (minion returns) |
| 8000 | Salt API | REST API for Salt-GUI |

## License

MIT License

## Author

Samuel Brucker

---

For detailed technical specifications, see [CLAUDE.md](CLAUDE.md).
