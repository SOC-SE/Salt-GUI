# Salt-GUI Platform Specification

> **Document Purpose**: Complete technical specification for building a SaltStack-based remote administration platform for CCDC (Collegiate Cyber Defense Competition) environments.

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Competition Context](#2-competition-context)
3. [System Architecture](#3-system-architecture)
4. [Technology Stack](#4-technology-stack)
5. [Feature Specifications](#5-feature-specifications)
6. [User Interface Design](#6-user-interface-design)
7. [API Design](#7-api-design)
8. [Security Model](#8-security-model)
9. [Data Persistence](#9-data-persistence)
10. [Installation & Deployment](#10-installation--deployment)
11. [Salt Integration Reference](#11-salt-integration-reference)
12. [Testing Procedures](#12-testing-procedures)
13. [Directory Structure](#13-directory-structure)
14. [External Documentation](#14-external-documentation)

---

## IMPORTANT: Development Guidelines

### Default Credentials

**The default password for Salt-GUI must ALWAYS be `Changeme1!`**

- Username: `admin`
- Password: `Changeme1!`
- The bcrypt hash for this password is: `$2b$12$fzH7uhWZxv9ssFBWmmUyn.aysvz7NJV4xFT1cWUW26BOQabWzKKhO`

When testing or deploying, always ensure `config/auth.yaml` contains:
```yaml
users:
  admin:
    password_hash: "$2b$12$fzH7uhWZxv9ssFBWmmUyn.aysvz7NJV4xFT1cWUW26BOQabWzKKhO"
    role: admin
```

### Two-Angle Testing Requirement

**All features MUST be tested from two perspectives:**

#### 1. Salt API Testing (First)
Test the underlying Salt functionality using SSH and Vagrant to verify Salt commands work correctly:

```bash
# SSH into the Salt master
vagrant ssh saltmaster

# Test Salt commands directly
sudo salt '*' test.ping
sudo salt 'minion-ubuntu' cmd.run 'whoami'
sudo salt '*' grains.item os
```

This verifies the Salt infrastructure is working before testing the web layer.

#### 2. Web Browser Testing (Second)
Simulate user activity through the Salt-GUI web interface:

```bash
# Login and get session cookie
curl -s -c /tmp/cookies.txt -X POST http://localhost:3000/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"Changeme1!"}'

# Test API endpoints as the browser would call them
curl -s -b /tmp/cookies.txt http://localhost:3000/api/devices

# Test feature-specific endpoints
curl -s -b /tmp/cookies.txt -X POST http://localhost:3000/api/commands/run \
  -H 'Content-Type: application/json' \
  -d '{"targets":"minion-ubuntu","command":"hostname","shell":"bash"}'
```

This verifies the web frontend and backend work correctly together.

**Why both angles?** Issues often occur at the integration layer - Salt commands may work perfectly, but the web frontend/backend may have bugs in how they call Salt or display results. Testing both angles catches these integration issues.

---

## 1. Executive Summary

### What Is Salt-GUI?

Salt-GUI is a web-based remote administration platform that provides centralized management of Linux and Windows systems through SaltStack. It functions as a command-and-control (C2) interface for defensive security operations, enabling rapid script deployment, command execution, and system monitoring across an entire network from a single dashboard.

### Core Design Principles

| Principle | Description |
|-----------|-------------|
| **Efficiency** | Fast to install, fast to use, minimal resource footprint |
| **Simplicity** | Clean interface, obvious workflows, no unnecessary complexity |
| **Reliability** | Must work under pressure, handle failures gracefully |
| **Security** | Protected against unauthorized access, audit everything |
| **Portability** | Runs on any standard Linux distribution without special dependencies |

### Primary Use Case

A competition team member deploys Salt-GUI on a Linux server, connects it to a Salt Master, and gains immediate administrative control over all Salt minions (Linux and Windows) in the network. From this single interface, they can:

- Deploy security scripts to all systems simultaneously
- Execute commands and see results in real-time
- Monitor system status and respond to incidents
- Lock down compromised systems with emergency controls

---

## 2. Competition Context

### CCDC Environment Characteristics

**Time Constraints:**
- Competitions run 6-8 hours
- First 15 minutes are critical for initial hardening
- Every second spent on tooling setup is a second not spent defending

**Network Environment:**
- Mixed Linux distributions (Ubuntu, Fedora, CentOS, Rocky, Oracle Linux, Debian, Alpine, Devuan)
- Windows servers (Server 2016, 2019, 2022) and workstations (Windows 10/11)
- Pre-compromised systems with red team implants (MWCCDC style)
- Active adversaries attempting to maintain access

**Operational Constraints:**
- SSH is typically disabled on minions for security
- PowerShell may be removed from Windows systems mid-competition
- Cannot rely on external services or internet connectivity during operation
- Must work with minimal pre-configuration

### Why Salt?

SaltStack provides:
- **Agentless feel with agent benefits**: Minions maintain persistent connection to master
- **No SSH required**: Communication over ZeroMQ (ports 4505/4506)
- **Cross-platform**: Same commands work on Linux and Windows
- **Speed**: Parallel execution across thousands of nodes
- **Flexibility**: Can run arbitrary commands, scripts, or structured states

---

## 3. System Architecture

### High-Level Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              TEAM WORKSTATION                                │
│                         (Browser - Any Device)                               │
└─────────────────────────────────────────────────────────────────────────────┘
                                      │
                                      │ HTTP/HTTPS (Port 3000)
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                              SALT-GUI SERVER                                 │
│                     (Linux: Oracle/Ubuntu/Rocky/Debian)                      │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │                         Web Application                                │  │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  │  │
│  │  │   Routes    │  │   Auth      │  │   Static    │  │   Audit     │  │  │
│  │  │   /api/*    │  │  Middleware │  │   Files     │  │   Logger    │  │  │
│  │  └──────┬──────┘  └─────────────┘  └─────────────┘  └─────────────┘  │  │
│  │         │                                                              │  │
│  │         ▼                                                              │  │
│  │  ┌─────────────────────────────────────────────────────────────────┐  │  │
│  │  │                    Salt API Client Module                        │  │  │
│  │  │         (Translates GUI requests to Salt API calls)              │  │  │
│  │  └─────────────────────────────────────────────────────────────────┘  │  │
│  └───────────────────────────────────────────────────────────────────────┘  │
│                                      │                                       │
│                                      │ REST API (Port 8000)                  │
│                                      ▼                                       │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │                         SALT MASTER                                    │  │
│  │                    (salt-api / CherryPy)                               │  │
│  └───────────────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────────┘
                                      │
                                      │ ZeroMQ (Ports 4505/4506)
                                      │ (Encrypted, No SSH Required)
                                      ▼
        ┌─────────────┬─────────────┬─────────────┬─────────────┐
        │             │             │             │             │
        ▼             ▼             ▼             ▼             ▼
   ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────┐
   │ Minion  │  │ Minion  │  │ Minion  │  │ Minion  │  │ Minion  │
   │ Ubuntu  │  │ Fedora  │  │ Windows │  │  Rocky  │  │ Oracle  │
   │         │  │         │  │ Server  │  │  Linux  │  │  Linux  │
   └─────────┘  └─────────┘  └─────────┘  └─────────┘  └─────────┘
```

### Component Responsibilities

| Component | Responsibility |
|-----------|----------------|
| **Browser** | User interface, displays data, sends commands |
| **Web Application** | Serves UI, handles authentication, routes API calls |
| **Salt API Client** | Translates requests to Salt API format, handles responses |
| **Salt Master** | Manages minion connections, executes commands |
| **Salt Minions** | Receive and execute commands, return results |

### Communication Flow Example: Script Deployment

```
1. User clicks "Deploy Script" in browser
2. Browser POSTs to /api/run-script with script content and targets
3. Web app authenticates request, logs action
4. Salt API Client formats request for Salt API
5. Salt API Client POSTs to Salt Master's /run endpoint
6. Salt Master sends script to selected minions via ZeroMQ
7. Minions execute script, return output
8. Salt Master aggregates results
9. Salt API Client receives results, formats for display
10. Web app returns JSON response
11. Browser displays results to user
```

---

## 4. Technology Stack

### Backend Options Analysis

| Framework | Pros | Cons | Verdict |
|-----------|------|------|---------|
| **Node.js + Express** | Fast, async-native, huge ecosystem, easy HTTP handling | npm dependency management | **Recommended** |
| **Python + Flask** | Native Salt integration possible, simple | Async more complex, GIL | Good alternative |
| **Go** | Single binary, fast, no runtime | More complex HTTP handling | Overkill for this |

**Recommendation: Node.js + Express**
- Excellent for API proxying (which is primary function)
- Async/await handles concurrent Salt API calls naturally
- Simple to install on any Linux distribution
- Minimal dependencies needed

### Frontend Approach

**Recommendation: Vanilla JavaScript with minimal CSS framework**

Rationale:
- No build step required
- Works immediately in any browser
- Easy to debug under pressure
- Smaller attack surface
- Fast loading

**UI Framework Options:**

| Option | Pros | Cons |
|--------|------|------|
| **Pure Vanilla JS** | No dependencies, full control | More boilerplate |
| **Alpine.js** | Lightweight (15KB), declarative | Another dependency |
| **htmx** | Server-driven, minimal JS | Different paradigm |

**Recommendation: Vanilla JS** - Zero dependencies, maximum reliability.

### Required Node.js Packages

```json
{
  "dependencies": {
    "express": "^4.18.x",      // Web framework
    "axios": "^1.6.x",          // HTTP client for Salt API
    "express-session": "^1.17.x", // Session management
    "bcrypt": "^5.1.x",         // Password hashing
    "js-yaml": "^4.1.x",        // YAML config parsing
    "uuid": "^9.x"              // Session IDs
  }
}
```

---

## 5. Feature Specifications

### 5.1 Device Inventory (Priority: HIGH)

**Purpose**: Display all connected Salt minions with their status and system information.

**Requirements:**
- List all accepted minions from Salt Master
- Show online/offline status (based on ping response)
- Display OS type, hostname, IP addresses
- Allow filtering by OS type (Linux/Windows)
- Allow selecting multiple devices for bulk operations
- Auto-refresh capability

**Salt Functions Used:**
```python
salt.wheel.key.list_all()      # Get all minion keys
salt.runner.manage.status()     # Get online/offline status
salt.local.grains.items()       # Get system information
salt.local.test.ping()          # Check connectivity
```

**Data to Display per Minion:**

| Field | Source | Notes |
|-------|--------|-------|
| Minion ID | key.list_all | Primary identifier |
| Status | test.ping | Online/Offline/Unknown |
| OS | grains['os'] | Windows, Ubuntu, etc. |
| OS Family | grains['os_family'] | Debian, RedHat, Windows |
| IP Address | grains['ipv4'] | May be multiple |
| Kernel | grains['kernel'] | Linux, Windows |
| Last Seen | manage.status | Timestamp if available |

---

### 5.2 Script Deployment (Priority: CRITICAL)

**Purpose**: Deploy and execute scripts on one or more minions. This is the most important feature.

**Requirements:**
- Support both Bash (Linux) and PowerShell (Windows) scripts
- Store scripts in organized directory structure
- Execute scripts on selected targets (single, multiple, or all)
- Display execution output in real-time or on completion
- Support script parameters/arguments
- Handle large script outputs without UI freeze
- Timeout handling for hung scripts

**Salt Functions Used:**
```python
# For Linux (bash scripts)
salt.local.cmd.script()         # Download and execute script
salt.local.cmd.run()            # Run inline command

# For Windows (PowerShell)
salt.local.cmd.script()         # Works for PS1 files
salt.local.cmd.run()            # With shell='powershell'
```

**Script Storage Structure:**
```
scripts/
├── linux/
│   ├── hardening/
│   │   ├── disable-services.sh
│   │   └── configure-firewall.sh
│   ├── monitoring/
│   │   └── install-falco.sh
│   └── hunting/
│       ├── find-persistence.sh
│       └── check-rootkits.sh
└── windows/
    ├── hardening/
    │   ├── Disable-Services.ps1
    │   └── Configure-Firewall.ps1
    └── hunting/
        └── Find-Persistence.ps1
```

**Execution Modes:**

| Mode | Use Case | Salt Function |
|------|----------|---------------|
| **Inline** | Small commands | cmd.run |
| **Script File** | Stored scripts | cmd.script (local file) |
| **Direct Content** | Paste-and-run | cmd.run with script content |

---

### 5.3 Command Execution (Priority: HIGH)

**Purpose**: Execute arbitrary commands on minions (C2 functionality).

**Requirements:**
- Text input for command entry
- Target selection (single minion, multiple, glob pattern, all)
- OS-aware command execution (bash vs cmd/powershell)
- Output display with minion identification
- Command history (current session)
- Copy output functionality

**Salt Functions Used:**
```python
# Linux
salt.local.cmd.run(command, shell='/bin/bash')

# Windows  
salt.local.cmd.run(command, shell='cmd')
salt.local.cmd.run(command, shell='powershell')
```

**Target Patterns Supported:**

| Pattern | Example | Matches |
|---------|---------|---------|
| Single | `web-server-01` | Exact minion |
| Glob | `web-*` | All matching pattern |
| List | `['web-01', 'db-01']` | Specific list |
| Grain | `os:Ubuntu` | All Ubuntu systems |
| All | `*` | Every minion |

---

### 5.4 Real-Time Logging (Priority: MEDIUM)

**Purpose**: Stream logs from minions for live monitoring.

**Requirements:**
- Tail log files on remote systems
- Support multiple log sources simultaneously
- Filter/search within log stream
- Pause/resume stream
- Clear display

**Salt Functions Used:**
```python
# Tail a file
salt.local.cmd.run('tail -f /var/log/auth.log', timeout=0)

# With Salt's built-in
salt.local.log.tail('/var/log/syslog', num_lines=100)
```

**Common Log Paths:**

| OS | Log | Path |
|----|-----|------|
| Linux | Auth | /var/log/auth.log, /var/log/secure |
| Linux | Syslog | /var/log/syslog, /var/log/messages |
| Linux | Salt Minion | /var/log/salt/minion |
| Windows | Security | Windows Event Log (requires PowerShell) |
| Windows | Application | Windows Event Log |

---

### 5.5 Salt State Management (Priority: MEDIUM)

**Purpose**: Apply Salt states to minions for declarative configuration.

**Requirements:**
- List available states from server
- Apply states to selected targets
- Support test mode (dry run)
- Display state results with success/failure per state
- Support both simple states and Jinja-templated states

**Salt Functions Used:**
```python
salt.local.state.apply(state_name)          # Apply named state
salt.local.state.apply(state_name, test=True)  # Dry run
salt.local.state.template_str(content)       # Apply inline state
salt.local.state.show_sls(state_name)        # Preview state
```

**State Application Methods:**

| Method | When to Use | Salt Function |
|--------|-------------|---------------|
| **Named State** | State exists in /srv/salt | state.apply('statename') |
| **Inline State** | Simple, no Jinja | state.template_str(content) |
| **Local Apply** | Self-contained with Jinja | cmd.run + salt-call --local |

---

### 5.6 System Auditing (Priority: MEDIUM)

**Purpose**: Quickly audit system configuration across all minions.

**Audit Categories:**

| Category | Information Gathered | Salt Method |
|----------|---------------------|-------------|
| **Users** | Local users, groups, sudo access | user.list_users, group.list_groups |
| **Processes** | Running processes, owners | ps.top, cmd.run('ps aux') |
| **Services** | Enabled/running services | service.get_all, service.status |
| **Network** | Listening ports, connections | network.netstat, cmd.run('ss -tlnp') |
| **Files** | Specific file contents, permissions | file.read, file.stats |
| **Scheduled Tasks** | Cron jobs, Windows tasks | cron.list_tab, cmd.run |

**Salt Functions Used:**
```python
# Users
salt.local.user.list_users()
salt.local.group.list_groups()
salt.local.user.info(username)

# Processes
salt.local.ps.top(num_processes=20)
salt.local.status.procs()

# Services
salt.local.service.get_all()
salt.local.service.status(service_name)

# Network
salt.local.network.netstat()
salt.local.network.active_tcp()

# Scheduled Tasks (Linux)
salt.local.cron.list_tab(user)
```

---

### 5.7 Service Management (Priority: MEDIUM)

**Purpose**: Start, stop, enable, disable services on minions.

**Requirements:**
- List all services with current status
- Start/stop individual services
- Enable/disable services at boot
- Bulk service operations
- Works on both Linux (systemd/sysvinit) and Windows

**Salt Functions Used:**
```python
salt.local.service.get_all()           # List services
salt.local.service.status(name)        # Check status
salt.local.service.start(name)         # Start service
salt.local.service.stop(name)          # Stop service
salt.local.service.enable(name)        # Enable at boot
salt.local.service.disable(name)       # Disable at boot
salt.local.service.restart(name)       # Restart service
```

---

### 5.8 Process Management (Priority: MEDIUM)

**Purpose**: View and kill processes on minions.

**Requirements:**
- List running processes with resource usage
- Kill processes by PID or name
- Filter processes by name/user
- Identify suspicious processes

**Salt Functions Used:**
```python
salt.local.ps.top(num_processes=50)     # Process list
salt.local.ps.kill_pid(pid)             # Kill by PID
salt.local.ps.pkill(pattern)            # Kill by name pattern
salt.local.status.procs()               # Process info
```

---

### 5.9 Password Management (Priority: HIGH)

**Purpose**: Change user passwords on the Salt-GUI server and on minions.

**Requirements:**
- Change local Salt-GUI admin password (highest priority)
- Change passwords on remote minions (Linux and Windows)
- Bulk password changes for same username across multiple minions
- Password strength validation
- Audit logging of all password changes

**Salt Functions Used:**
```python
# Linux
salt.local.shadow.set_password(user, password_hash)
salt.local.cmd.run('echo "user:password" | chpasswd')

# Windows
salt.local.user.setpassword(user, password)
salt.local.cmd.run('net user username newpassword')
```

**Local Password Change:**
The Salt-GUI's own admin password is stored in the local configuration file, hashed with bcrypt.

---

### 5.10 Emergency Lockdown (Priority: HIGH)

**Purpose**: Rapidly secure a compromised system by shutting down all non-essential services.

**Requirements:**
- Single-button activation
- Configurable lockdown profile
- Preserves only Salt minion connectivity
- Kills all user sessions
- Blocks all incoming connections except Salt ports
- Can be reversed (unlock)

**Lockdown Actions (Linux):**
```bash
# Kill all user shells except current Salt session
pkill -u $(whoami) -9 || true

# Block all incoming except Salt (4505, 4506) and established
iptables -P INPUT DROP
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A INPUT -p tcp --dport 4505 -j ACCEPT
iptables -A INPUT -p tcp --dport 4506 -j ACCEPT
iptables -A INPUT -i lo -j ACCEPT

# Stop common services red team might use
systemctl stop sshd apache2 nginx httpd smbd nmbd 2>/dev/null || true
```

**Lockdown Actions (Windows):**
```powershell
# Enable firewall, block all except Salt
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
New-NetFirewallRule -DisplayName "Allow Salt 4505" -Direction Inbound -Port 4505 -Protocol TCP -Action Allow
New-NetFirewallRule -DisplayName "Allow Salt 4506" -Direction Inbound -Port 4506 -Protocol TCP -Action Allow

# Stop potentially exploited services
Stop-Service -Name "W3SVC","MSSQLSERVER","FTPSVC" -Force -ErrorAction SilentlyContinue
```

---

### 5.11 Playbooks (Priority: LOW)

**Purpose**: Execute multi-step automation sequences.

**Requirements:**
- Define sequences of actions (scripts, commands, states)
- Execute steps in order
- Handle step failures (continue, stop, retry)
- Display progress
- Store playbook definitions in YAML

**Playbook Format:**
```yaml
name: Initial Hardening
description: First-response hardening playbook
steps:
  - name: Change default passwords
    type: script
    target: "*"
    script: linux/hardening/change-passwords.sh
    on_failure: continue
    
  - name: Disable unnecessary services
    type: command
    target: "os:Ubuntu"
    command: "systemctl disable --now cups avahi-daemon bluetooth"
    on_failure: continue
    
  - name: Apply firewall rules
    type: state
    target: "*"
    state: firewall
    on_failure: stop
```

---

### 5.12 Network Visualization (Priority: LOW)

**Purpose**: Display network topology and connections.

**Requirements:**
- Show minions and their network relationships
- Display which minions can reach which
- Identify network segments
- Simple visual (not complex graph)

**Implementation Approach:**
- Query each minion for IP addresses and routes
- Build adjacency map
- Simple table or grid display (not fancy graphics)

---

## 6. User Interface Design

### Design Principles

| Principle | Implementation |
|-----------|----------------|
| **Industrial** | Clean lines, monospace fonts for data, high contrast |
| **Information Dense** | Show more data, less whitespace, scrollable panels |
| **No Decorations** | No emojis, no icons (text labels only), no animations |
| **Fast Scanning** | Consistent layout, predictable locations, clear hierarchy |
| **Keyboard Friendly** | Tab navigation, Enter to submit, Escape to cancel |

### Color Palette

```css
:root {
  /* Background */
  --bg-primary: #1a1a1a;      /* Main background */
  --bg-secondary: #252525;     /* Panel backgrounds */
  --bg-tertiary: #2d2d2d;      /* Input backgrounds */
  
  /* Text */
  --text-primary: #e0e0e0;     /* Main text */
  --text-secondary: #888888;   /* Secondary text */
  --text-muted: #555555;       /* Disabled/muted text */
  
  /* Status */
  --status-success: #4caf50;   /* Online, success */
  --status-error: #f44336;     /* Offline, error */
  --status-warning: #ff9800;   /* Warning, pending */
  --status-info: #2196f3;      /* Information */
  
  /* Interactive */
  --border-color: #404040;     /* Borders */
  --hover-bg: #333333;         /* Hover state */
  --active-bg: #444444;        /* Active/selected state */
}
```

### Layout Structure

```
┌──────────────────────────────────────────────────────────────────────────┐
│ [Salt-GUI]  [Status: Connected]                    [Admin] [Logout]      │
├────────────────┬─────────────────────────────────────────────────────────┤
│                │                                                          │
│  NAVIGATION    │                    MAIN CONTENT AREA                     │
│                │                                                          │
│  [Devices]     │  ┌─────────────────────────────────────────────────────┐│
│  [Scripts]     │  │                                                     ││
│  [Commands]    │  │                                                     ││
│  [States]      │  │                                                     ││
│  [Audit]       │  │                                                     ││
│  [Services]    │  │                                                     ││
│  [Processes]   │  │                                                     ││
│  [Logs]        │  │                                                     ││
│  [Playbooks]   │  │                                                     ││
│  ────────────  │  │                                                     ││
│  [Passwords]   │  │                                                     ││
│  [Settings]    │  │                                                     ││
│  ────────────  │  └─────────────────────────────────────────────────────┘│
│  [EMERGENCY]   │                                                          │
│                │  ┌─────────────────────────────────────────────────────┐│
│                │  │              OUTPUT / RESULTS PANEL                 ││
│                │  │                                                     ││
│                │  └─────────────────────────────────────────────────────┘│
└────────────────┴─────────────────────────────────────────────────────────┘
```

### Component Specifications

**Device List:**
```
┌─────────────────────────────────────────────────────────────────────────┐
│ [Select All] [Select Linux] [Select Windows] [Refresh]     Filter: [___]│
├─────────────────────────────────────────────────────────────────────────┤
│ [ ] webserver-01          Ubuntu 24.04      192.168.1.10      ONLINE   │
│ [ ] webserver-02          Ubuntu 24.04      192.168.1.11      ONLINE   │
│ [x] database-01           Rocky Linux 9     192.168.1.20      ONLINE   │
│ [x] domain-controller     Windows 2019      192.168.1.5       ONLINE   │
│ [ ] fileserver            Windows 2022      192.168.1.6       OFFLINE  │
└─────────────────────────────────────────────────────────────────────────┘
```

**Command Input:**
```
┌─────────────────────────────────────────────────────────────────────────┐
│ Target: [Selected (2)]  Shell: [bash ▼]  Timeout: [30s ▼]              │
├─────────────────────────────────────────────────────────────────────────┤
│ $ whoami && id && hostname                                              │
│                                                                         │
│                                                   [Execute] [Clear]     │
└─────────────────────────────────────────────────────────────────────────┘
```

**Results Output:**
```
┌─────────────────────────────────────────────────────────────────────────┐
│ Results - 2 minions - 0.342s                              [Copy] [Clear]│
├─────────────────────────────────────────────────────────────────────────┤
│ ── database-01 ─────────────────────────────────────────────────────── │
│ root                                                                    │
│ uid=0(root) gid=0(root) groups=0(root)                                 │
│ database-01.internal                                                    │
│                                                                         │
│ ── domain-controller ───────────────────────────────────────────────── │
│ administrator                                                           │
│ User: DOMAIN\Administrator  Groups: Administrators, Domain Admins      │
│ DOMAIN-DC01                                                             │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 7. API Design

### RESTful Endpoints

#### Authentication

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/auth/login` | Authenticate user |
| POST | `/api/auth/logout` | End session |
| GET | `/api/auth/status` | Check authentication |
| POST | `/api/auth/change-password` | Change GUI password |

**Login Request:**
```json
POST /api/auth/login
{
  "username": "admin",
  "password": "secretpassword"
}
```

**Login Response:**
```json
{
  "success": true,
  "message": "Authenticated successfully"
}
```

#### Devices (Minions)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/devices` | List all minions with status |
| GET | `/api/devices/:id` | Get single minion details |
| GET | `/api/devices/:id/grains` | Get minion grains |
| POST | `/api/devices/ping` | Ping selected minions |

**List Devices Response:**
```json
{
  "success": true,
  "devices": [
    {
      "id": "webserver-01",
      "status": "online",
      "os": "Ubuntu",
      "os_family": "Debian",
      "ip_addresses": ["192.168.1.10"],
      "kernel": "Linux"
    }
  ]
}
```

#### Commands

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/commands/run` | Execute command on targets |

**Run Command Request:**
```json
POST /api/commands/run
{
  "targets": ["webserver-01", "database-01"],
  "command": "whoami && id",
  "shell": "bash",
  "timeout": 30
}
```

**Run Command Response:**
```json
{
  "success": true,
  "results": {
    "webserver-01": {
      "retcode": 0,
      "stdout": "root\nuid=0(root) gid=0(root)",
      "stderr": ""
    },
    "database-01": {
      "retcode": 0,
      "stdout": "root\nuid=0(root) gid=0(root)",
      "stderr": ""
    }
  },
  "execution_time": 0.342
}
```

#### Scripts

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/scripts` | List all scripts |
| GET | `/api/scripts/:os` | List scripts for OS |
| GET | `/api/scripts/:os/:path` | Get script content |
| POST | `/api/scripts/run` | Execute script on targets |

**Run Script Request:**
```json
POST /api/scripts/run
{
  "targets": ["*"],
  "script": "linux/hardening/disable-services.sh",
  "args": ["--aggressive"],
  "timeout": 120
}
```

#### States

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/states` | List all states |
| GET | `/api/states/:os` | List states for OS |
| POST | `/api/states/apply` | Apply state to targets |

**Apply State Request:**
```json
POST /api/states/apply
{
  "targets": ["webserver-*"],
  "state": "linux/hardening",
  "test_mode": false
}
```

#### Services

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/services/:target` | List services on target |
| POST | `/api/services/start` | Start service |
| POST | `/api/services/stop` | Stop service |
| POST | `/api/services/restart` | Restart service |
| POST | `/api/services/enable` | Enable service |
| POST | `/api/services/disable` | Disable service |

#### Processes

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/processes/:target` | List processes |
| POST | `/api/processes/kill` | Kill process |

#### Audit

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/audit/users/:target` | List users |
| GET | `/api/audit/network/:target` | Network connections |
| GET | `/api/audit/files/:target` | Audit file |

#### Passwords

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/passwords/change` | Change password on targets |

**Change Password Request:**
```json
POST /api/passwords/change
{
  "targets": ["webserver-01"],
  "username": "admin",
  "new_password": "NewSecurePass123!"
}
```

#### Emergency

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/emergency/lockdown` | Initiate lockdown |
| POST | `/api/emergency/unlock` | Reverse lockdown |

#### Settings

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/settings` | Get current settings |
| POST | `/api/settings` | Update settings |
| POST | `/api/settings/salt/test` | Test Salt connection |

---

## 8. Security Model

### Authentication

**Local Authentication (Recommended):**
- Username/password stored in local YAML config
- Password hashed with bcrypt (cost factor 12)
- Session-based with secure cookies
- Session timeout after inactivity (configurable, default 30 min)

**Configuration Example:**
```yaml
# config/auth.yaml
users:
  admin:
    password_hash: "$2b$12$..."  # bcrypt hash
    role: admin
```

**Session Security:**
```javascript
app.use(session({
  secret: crypto.randomBytes(32).toString('hex'),
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: false,      // Set true if using HTTPS
    httpOnly: true,     // Prevent XSS access to cookie
    maxAge: 1800000     // 30 minutes
  }
}));
```

### Salt API Authentication

Salt-GUI authenticates to the Salt API using Salt's external authentication (eauth) system.

**Supported eauth backends:**
- `pam` - Linux PAM authentication (most common)
- `file` - File-based authentication
- `ldap` - LDAP/Active Directory

**Configuration on Salt Master:**
```yaml
# /etc/salt/master.d/api.conf
external_auth:
  pam:
    saltadmin:
      - .*              # All minions
      - '@runner'       # All runners
      - '@wheel'        # All wheel modules
```

### Input Validation

All user inputs must be validated:

| Input | Validation |
|-------|------------|
| Minion IDs | Alphanumeric, hyphens, underscores only |
| Commands | Log all commands, no validation (intentional) |
| Script paths | Must exist in scripts/ directory, no path traversal |
| Usernames | Alphanumeric only |
| Passwords | Minimum length, complexity optional |

### Audit Logging

All administrative actions are logged:

```yaml
# Log format
- timestamp: "2026-01-25T14:30:00Z"
  user: "admin"
  action: "command.run"
  targets: ["webserver-01", "database-01"]
  details:
    command: "whoami"
  result: "success"
```

**Actions to Log:**
- Login/logout
- All command executions
- All script executions
- State applications
- Service changes
- Password changes
- Emergency actions
- Configuration changes

---

## 9. Data Persistence

### Configuration Files

```
config/
├── app.yaml          # Application settings
├── auth.yaml         # User credentials (hashed passwords)
├── salt.yaml         # Salt API connection settings
└── playbooks/        # Playbook definitions
    ├── initial-hardening.yaml
    └── incident-response.yaml
```

**app.yaml:**
```yaml
server:
  port: 3000
  host: "0.0.0.0"
  
session:
  timeout_minutes: 30
  
logging:
  level: "info"
  audit_file: "logs/audit.yaml"
```

**salt.yaml:**
```yaml
api:
  url: "https://localhost:8000"
  eauth: "pam"
  username: "saltadmin"
  # Password stored encrypted or prompted at startup
  
defaults:
  timeout: 30
  batch_size: 10
```

### Logs

```
logs/
├── audit.yaml        # Administrative action audit log
├── app.log           # Application logs
└── errors.log        # Error logs
```

**Audit Log Format (YAML for easy parsing):**
```yaml
---
- timestamp: "2026-01-25T14:30:00.000Z"
  user: "admin"
  ip: "192.168.1.100"
  action: "command.run"
  targets: ["webserver-01"]
  details:
    command: "systemctl status nginx"
  result: "success"
  duration_ms: 234
```

### Scripts and States Storage

```
scripts/
├── linux/
│   └── ... (bash scripts)
└── windows/
    └── ... (PowerShell scripts)

states/
├── linux/
│   └── ... (Salt states)
└── windows/
    └── ... (Salt states)
```

---

## 10. Installation & Deployment

### System Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| OS | Debian 11+, Ubuntu 20.04+, RHEL 8+, Rocky 8+ | Oracle Linux 9, Ubuntu 24.04 |
| RAM | 512 MB | 1 GB |
| Disk | 100 MB | 500 MB |
| Node.js | 18.x | 20.x LTS |

### Installation Script Requirements

The installation script (`install.sh`) must:

1. Detect OS family (Debian/RedHat) using package manager presence
2. Install Node.js if not present
3. Install npm dependencies
4. Generate initial configuration with secure defaults
5. Prompt for Salt API connection details
6. Prompt for admin password (hashed before storage)
7. Create systemd service file
8. Start the service
9. Display access URL

**Script Structure:**
```bash
#!/bin/bash
set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

# Detect OS
detect_os() {
    if command -v apt-get &>/dev/null; then
        OS_FAMILY="debian"
        PKG_MANAGER="apt-get"
    elif command -v dnf &>/dev/null; then
        OS_FAMILY="redhat"
        PKG_MANAGER="dnf"
    elif command -v yum &>/dev/null; then
        OS_FAMILY="redhat"
        PKG_MANAGER="yum"
    else
        log_error "Unsupported OS. Requires Debian or RHEL-based system."
    fi
}

# Install Node.js
install_nodejs() {
    if command -v node &>/dev/null; then
        NODE_VERSION=$(node --version | cut -d'v' -f2 | cut -d'.' -f1)
        if [ "$NODE_VERSION" -ge 18 ]; then
            log_info "Node.js $(node --version) already installed"
            return 0
        fi
    fi
    
    log_info "Installing Node.js..."
    if [ "$OS_FAMILY" = "debian" ]; then
        curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
        apt-get install -y nodejs
    else
        curl -fsSL https://rpm.nodesource.com/setup_20.x | bash -
        $PKG_MANAGER install -y nodejs
    fi
}

# Main installation
main() {
    detect_os
    install_nodejs
    
    # Install dependencies
    npm install --production
    
    # Interactive configuration
    # ... prompt for Salt API URL, credentials, admin password
    
    # Create systemd service
    # ... create /etc/systemd/system/salt-gui.service
    
    # Start service
    systemctl daemon-reload
    systemctl enable --now salt-gui
    
    log_info "Installation complete!"
    log_info "Access Salt-GUI at http://$(hostname -I | awk '{print $1}'):3000"
}

main "$@"
```

### Systemd Service File

```ini
# /etc/systemd/system/salt-gui.service
[Unit]
Description=Salt-GUI Web Interface
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/salt-gui
ExecStart=/usr/bin/node server.js
Restart=on-failure
RestartSec=5
Environment=NODE_ENV=production

[Install]
WantedBy=multi-user.target
```

### Salt Master Configuration

The Salt Master must have the API enabled:

```yaml
# /etc/salt/master.d/api.conf
rest_cherrypy:
  port: 8000
  ssl_crt: /etc/salt/pki/api/salt-api.crt
  ssl_key: /etc/salt/pki/api/salt-api.key
  # Or for testing without SSL:
  # disable_ssl: True

external_auth:
  pam:
    saltadmin:
      - .*
      - '@runner'
      - '@wheel'
```

**Generate SSL certificates (if needed):**
```bash
mkdir -p /etc/salt/pki/api
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout /etc/salt/pki/api/salt-api.key \
  -out /etc/salt/pki/api/salt-api.crt \
  -subj "/CN=salt-api"
```

**Install and start Salt API:**
```bash
# Debian/Ubuntu
apt-get install salt-api

# RHEL/Rocky
dnf install salt-api

# Start
systemctl enable --now salt-api
```

---

## 11. Salt Integration Reference

### Salt API Endpoints Used

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/login` | POST | Authenticate, get token |
| `/minions` | GET | List minion keys and grains |
| `/minions/:id` | GET | Get specific minion info |
| `/run` | POST | Execute Salt functions |
| `/events` | GET | Server-sent events stream |

### Common Salt Functions

**Execution Modules (salt.local.*):**

| Module | Function | Purpose |
|--------|----------|---------|
| `test` | `ping()` | Check minion connectivity |
| `cmd` | `run(command)` | Execute shell command |
| `cmd` | `script(source)` | Execute script file |
| `grains` | `items()` | Get all grains |
| `grains` | `item(key)` | Get specific grain |
| `service` | `get_all()` | List services |
| `service` | `start(name)` | Start service |
| `service` | `stop(name)` | Stop service |
| `service` | `status(name)` | Check service status |
| `user` | `list_users()` | List local users |
| `user` | `info(name)` | Get user details |
| `user` | `setpassword(name, password)` | Set password (Windows) |
| `shadow` | `set_password(name, hash)` | Set password (Linux) |
| `ps` | `top()` | List processes |
| `ps` | `kill_pid(pid)` | Kill process |
| `network` | `netstat()` | Network connections |
| `file` | `read(path)` | Read file contents |
| `state` | `apply(name)` | Apply Salt state |

**Wheel Modules (salt.wheel.*):**

| Module | Function | Purpose |
|--------|----------|---------|
| `key` | `list_all()` | List all minion keys |
| `key` | `accept(id)` | Accept minion key |
| `key` | `delete(id)` | Delete minion key |

**Runner Modules (salt.runner.*):**

| Module | Function | Purpose |
|--------|----------|---------|
| `manage` | `status()` | Online/offline status |
| `manage` | `present()` | List online minions |
| `manage` | `not_present()` | List offline minions |

### Salt API Request Format

**Authentication:**
```javascript
POST /login
Content-Type: application/json

{
  "username": "saltadmin",
  "password": "password",
  "eauth": "pam"
}

// Response
{
  "return": [{
    "token": "abc123...",
    "expire": 1234567890,
    "start": 1234567800,
    "user": "saltadmin",
    "eauth": "pam"
  }]
}
```

**Command Execution:**
```javascript
POST /run
X-Auth-Token: abc123...
Content-Type: application/json

{
  "client": "local",
  "tgt": "webserver-*",
  "tgt_type": "glob",
  "fun": "cmd.run",
  "arg": ["whoami"],
  "kwarg": {
    "shell": "/bin/bash",
    "timeout": 30
  }
}

// Response
{
  "return": [{
    "webserver-01": "root",
    "webserver-02": "root"
  }]
}
```

**Target Types:**

| Type | Example | Description |
|------|---------|-------------|
| `glob` | `web-*` | Shell-style wildcards |
| `list` | `['a', 'b']` | Explicit list |
| `grain` | `os:Ubuntu` | Match by grain |
| `compound` | `G@os:Ubuntu and web-*` | Complex matching |

### Salt API Client Implementation

```javascript
class SaltAPIClient {
  constructor(baseUrl, username, password, eauth = 'pam') {
    this.baseUrl = baseUrl;
    this.username = username;
    this.password = password;
    this.eauth = eauth;
    this.token = null;
    this.tokenExpiry = null;
  }

  async authenticate() {
    const response = await axios.post(`${this.baseUrl}/login`, {
      username: this.username,
      password: this.password,
      eauth: this.eauth
    });
    
    const auth = response.data.return[0];
    this.token = auth.token;
    this.tokenExpiry = auth.expire * 1000; // Convert to milliseconds
    return this.token;
  }

  async ensureAuthenticated() {
    if (!this.token || Date.now() >= this.tokenExpiry - 60000) {
      await this.authenticate();
    }
  }

  async run(client, target, fun, arg = [], kwarg = {}, tgtType = 'glob') {
    await this.ensureAuthenticated();
    
    const response = await axios.post(`${this.baseUrl}/run`, {
      client: client,
      tgt: target,
      tgt_type: tgtType,
      fun: fun,
      arg: arg,
      kwarg: kwarg
    }, {
      headers: { 'X-Auth-Token': this.token }
    });
    
    return response.data.return[0];
  }

  // Convenience methods
  async cmd(target, command, shell = '/bin/bash', timeout = 30) {
    return this.run('local', target, 'cmd.run', [command], { shell, timeout });
  }

  async ping(target = '*') {
    return this.run('local', target, 'test.ping');
  }

  async grains(target, item = null) {
    const fun = item ? 'grains.item' : 'grains.items';
    const arg = item ? [item] : [];
    return this.run('local', target, fun, arg);
  }

  async listMinions() {
    return this.run('wheel', null, 'key.list_all');
  }

  async minionStatus() {
    return this.run('runner', null, 'manage.status');
  }
}
```

---

## 12. Testing Procedures

### Unit Testing

Test individual components in isolation:

```javascript
// Test Salt API Client
describe('SaltAPIClient', () => {
  it('should authenticate successfully', async () => {
    const client = new SaltAPIClient('https://localhost:8000', 'admin', 'pass');
    const token = await client.authenticate();
    expect(token).toBeDefined();
  });

  it('should execute ping command', async () => {
    const result = await client.ping('*');
    expect(result).toHaveProperty('minion-01', true);
  });
});
```

### Integration Testing

Test API endpoints:

```bash
# Test login
curl -X POST http://localhost:3000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"password"}' \
  -c cookies.txt

# Test device list
curl -X GET http://localhost:3000/api/devices \
  -b cookies.txt

# Test command execution
curl -X POST http://localhost:3000/api/commands/run \
  -H "Content-Type: application/json" \
  -b cookies.txt \
  -d '{"targets":["*"],"command":"hostname","shell":"bash"}'
```

### Manual Testing Checklist

**Authentication:**
- [ ] Login with correct credentials succeeds
- [ ] Login with wrong credentials fails
- [ ] Session expires after timeout
- [ ] Logout clears session
- [ ] Password change works

**Devices:**
- [ ] All minions appear in list
- [ ] Online/offline status is accurate
- [ ] Grains data loads correctly
- [ ] Filtering by OS works
- [ ] Multi-select works

**Commands:**
- [ ] Single minion execution works
- [ ] Multi-minion execution works
- [ ] Glob targeting works
- [ ] Linux commands execute correctly
- [ ] Windows commands execute correctly
- [ ] Timeout is respected
- [ ] Large output displays correctly

**Scripts:**
- [ ] Script list loads
- [ ] Script content can be viewed
- [ ] Script execution works on Linux
- [ ] Script execution works on Windows
- [ ] Script with arguments works

**Emergency:**
- [ ] Lockdown button requires confirmation
- [ ] Lockdown executes on target
- [ ] Minion remains reachable after lockdown

### Salt Connectivity Testing

```bash
# Test Salt Master API directly
curl -k https://localhost:8000/login \
  -d username=saltadmin \
  -d password=password \
  -d eauth=pam

# Test minion connectivity
salt '*' test.ping

# Test command execution
salt '*' cmd.run 'hostname'

# Test grains
salt '*' grains.items
```

---

## 13. Directory Structure

### Complete Project Structure

```
salt-gui/
├── server.js                 # Main application entry point
├── package.json              # Node.js dependencies
├── package-lock.json         # Locked dependencies
├── install.sh                # Installation script
├── CLAUDE.md                 # This specification document
├── README.md                 # User documentation
│
├── config/                   # Configuration files
│   ├── app.yaml             # Application settings
│   ├── auth.yaml            # User credentials (gitignored)
│   ├── salt.yaml            # Salt API settings (gitignored)
│   └── app.yaml.example     # Example configuration
│
├── src/                      # Source code
│   ├── routes/              # Express route handlers
│   │   ├── auth.js          # Authentication routes
│   │   ├── devices.js       # Device management routes
│   │   ├── commands.js      # Command execution routes
│   │   ├── scripts.js       # Script management routes
│   │   ├── states.js        # State management routes
│   │   ├── services.js      # Service management routes
│   │   ├── processes.js     # Process management routes
│   │   ├── audit.js         # Audit routes
│   │   ├── passwords.js     # Password management routes
│   │   ├── emergency.js     # Emergency action routes
│   │   └── settings.js      # Settings routes
│   │
│   ├── lib/                 # Core libraries
│   │   ├── salt-client.js   # Salt API client
│   │   ├── auth.js          # Authentication logic
│   │   ├── config.js        # Configuration loader
│   │   └── logger.js        # Logging utilities
│   │
│   └── middleware/          # Express middleware
│       ├── auth.js          # Authentication middleware
│       └── audit.js         # Audit logging middleware
│
├── public/                   # Frontend static files
│   ├── index.html           # Main HTML page
│   ├── css/
│   │   └── styles.css       # Stylesheet
│   └── js/
│       └── app.js           # Frontend JavaScript
│
├── scripts/                  # Deployment scripts (user-managed)
│   ├── linux/
│   │   └── .gitkeep
│   └── windows/
│       └── .gitkeep
│
├── states/                   # Salt states (user-managed)
│   ├── linux/
│   │   └── .gitkeep
│   └── windows/
│       └── .gitkeep
│
├── playbooks/               # Playbook definitions (user-managed)
│   └── .gitkeep
│
├── logs/                    # Log files (gitignored)
│   └── .gitkeep
│
└── tests/                   # Test files
    ├── unit/
    └── integration/
```

### File Purposes

| File/Directory | Purpose |
|----------------|---------|
| `server.js` | Express app initialization, middleware setup, route mounting |
| `src/routes/*` | HTTP endpoint handlers, request validation, response formatting |
| `src/lib/salt-client.js` | All Salt API communication logic |
| `src/lib/auth.js` | Password hashing, session management |
| `src/lib/config.js` | YAML config file loading and validation |
| `src/lib/logger.js` | Structured logging, audit log writing |
| `public/index.html` | Single-page application shell |
| `public/js/app.js` | All frontend logic, API calls, UI updates |
| `public/css/styles.css` | All styling |

---

## 14. External Documentation

### SaltStack Documentation

| Resource | URL |
|----------|-----|
| Salt Documentation | https://docs.saltproject.io/en/latest/ |
| Salt API Reference | https://docs.saltproject.io/en/latest/ref/netapi/all/salt.netapi.rest_cherrypy.html |
| Execution Modules | https://docs.saltproject.io/en/latest/ref/modules/all/index.html |
| State Modules | https://docs.saltproject.io/en/latest/ref/states/all/index.html |
| Targeting Minions | https://docs.saltproject.io/en/latest/topics/targeting/index.html |
| External Authentication | https://docs.saltproject.io/en/latest/topics/eauth/index.html |

### Key Salt Modules Documentation

| Module | Documentation URL |
|--------|-------------------|
| cmd | https://docs.saltproject.io/en/latest/ref/modules/all/salt.modules.cmdmod.html |
| service | https://docs.saltproject.io/en/latest/ref/modules/all/salt.modules.service.html |
| user | https://docs.saltproject.io/en/latest/ref/modules/all/salt.modules.useradd.html |
| file | https://docs.saltproject.io/en/latest/ref/modules/all/salt.modules.file.html |
| network | https://docs.saltproject.io/en/latest/ref/modules/all/salt.modules.network.html |
| ps | https://docs.saltproject.io/en/latest/ref/modules/all/salt.modules.ps.html |
| grains | https://docs.saltproject.io/en/latest/ref/modules/all/salt.modules.grains.html |

### Node.js Documentation

| Resource | URL |
|----------|-----|
| Express.js | https://expressjs.com/en/4x/api.html |
| Axios | https://axios-http.com/docs/intro |
| bcrypt | https://github.com/kelektiv/node.bcrypt.js |
| js-yaml | https://github.com/nodeca/js-yaml |
| express-session | https://github.com/expressjs/session |

### CCDC Resources

| Resource | URL |
|----------|-----|
| NCCDC Rules | https://nationalccdc.org/rules.html |
| MWCCDC | https://www.caeepnc.org/mwccdc/ |

---

## Appendix A: Salt API Quick Reference

### Authentication Flow

```
1. POST /login with username, password, eauth
2. Receive token in response
3. Include token in X-Auth-Token header for subsequent requests
4. Token expires after ~12 hours (configurable on Salt Master)
```

### Common Request Patterns

**Local execution (run on minions):**
```json
{
  "client": "local",
  "tgt": "<target>",
  "fun": "<module.function>",
  "arg": ["arg1", "arg2"],
  "kwarg": {"key": "value"}
}
```

**Async execution (non-blocking):**
```json
{
  "client": "local_async",
  "tgt": "<target>",
  "fun": "<module.function>"
}
```

**Wheel (master operations):**
```json
{
  "client": "wheel",
  "fun": "key.list_all"
}
```

**Runner (master-side execution):**
```json
{
  "client": "runner",
  "fun": "manage.status"
}
```

---

## Appendix B: Example Configurations

### Minimal Salt Master API Config

```yaml
# /etc/salt/master.d/api.conf
rest_cherrypy:
  port: 8000
  disable_ssl: True  # For testing only!

external_auth:
  pam:
    root:
      - .*
      - '@runner'
      - '@wheel'
```

### Production Salt Master API Config

```yaml
# /etc/salt/master.d/api.conf
rest_cherrypy:
  port: 8000
  ssl_crt: /etc/salt/pki/api/salt-api.crt
  ssl_key: /etc/salt/pki/api/salt-api.key
  webhook_disable_auth: False
  webhook_url: /hook
  thread_pool: 100
  socket_queue_size: 30
  expire_responses: False

external_auth:
  pam:
    saltadmin:
      - .*
      - '@runner'
      - '@wheel'
```

---

*End of Specification Document*
