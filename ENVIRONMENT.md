# Salt-GUI Vagrant Environment

Network: `192.168.57.0/24` (private, host-only)

## Access

| Service | URL | Credentials |
|---------|-----|-------------|
| Salt-GUI | http://localhost:3000 | `admin` / `Changeme1!` |
| Salt API | https://192.168.57.10:8000 | `saltadmin` / `saltadmin` (PAM) |

Port forwarding from host: `localhost:3000` -> saltmaster:3000, `localhost:8000` -> saltmaster:8000

## Systems

| Hostname | OS | IP | SSH User/Pass | Autostart |
|----------|----|----|---------------|-----------|
| saltmaster | Rocky Linux 9 | 192.168.57.10 | `vagrant` / key-based | Yes (primary) |
| minion-ubuntu | Ubuntu 22.04 | 192.168.57.11 | `vagrant` / key-based | Yes |
| minion-rocky | Rocky Linux 9 | 192.168.57.12 | `vagrant` / key-based | Yes |
| minion-debian | Debian 12 | 192.168.57.13 | `vagrant` / key-based | Yes |
| minion-fedora | Fedora 40 | 192.168.57.14 | `vagrant` / key-based | Yes |
| minion-alma | AlmaLinux 9 | 192.168.57.15 | `vagrant` / key-based | No |
| minion-oracle | Oracle Linux 9 | 192.168.57.16 | `vagrant` / key-based | Yes |
| minion-centos | CentOS Stream 9 | 192.168.57.17 | `vagrant` / key-based | No |
| minion-win11 | Windows 11 | 192.168.57.20 | `vagrant` / `vagrant` (WinRM) | No |
| minion-winserver | Windows Server 2019 | 192.168.57.21 | `vagrant` / `vagrant` (WinRM) | No |

## Saltmaster Details

- **Salt Master**: runs as root (required for PAM auth)
- **Salt API**: CherryPy on port 8000 with self-signed SSL
- **Salt-GUI**: Node.js on port 3000, systemd service `salt-gui`
- **Salt version**: 3007.11
- **Auto-accept minion keys**: enabled (testing only)
- **netapi_enable_clients**: local, local_async, runner, wheel

## Quick Start

```bash
cd salt-gui

# Start master + one minion
vagrant up saltmaster minion-ubuntu

# Start all autostart VMs
vagrant up

# SSH into master
vagrant ssh saltmaster

# Check Salt connectivity
vagrant ssh saltmaster -- 'sudo salt "*" test.ping'
```

## Notes

- This network uses `192.168.57.x` to avoid conflicts with the CCDC testing environment on `192.168.56.x`
- Windows minions require the Vagrant boxes to be downloaded first (large downloads)
- The `saltadmin` system user is created during provisioning for Salt API PAM authentication
