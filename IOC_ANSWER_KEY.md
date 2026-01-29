# IoC Answer Key - SaltGUI Hunting Exercise

> Generated: 2026-01-28
> Total IoCs: ~70 across 5 Linux VMs

---

## minion-ubuntu (Ubuntu 22.04) - 14 IoCs

### Rogue Users
1. **User `backdoor_admin`** - has sudo privileges, password: `P@ssw0rd123`
2. **User `sysupdate`** - UID 0 (root-equivalent), password: `rootme`

### SSH Backdoors
3. **Root authorized_keys** - `/root/.ssh/authorized_keys` contains key for `redteam@attack-box`
4. **Vagrant authorized_keys** - `/home/vagrant/.ssh/authorized_keys` contains key for `redteam@c2-server`

### Cron Persistence
5. **`/etc/cron.d/system-update`** - downloads and executes beacon from `10.13.37.1` every 5 min
6. **`/etc/crontab`** - `@reboot` entry runs `/tmp/.hidden/persist.sh`
7. **Root crontab** - entry runs `/dev/shm/.x86_update` every 10 min

### Hidden Files
8. **`/tmp/.hidden/persist.sh`** - netcat reverse shell to `10.13.37.1:4444`
9. **`/dev/shm/.cache/update.sh`** - downloads and executes payload from `10.13.37.1`
10. **`/dev/shm/.x86_update`** - executable hidden file
11. **`/var/tmp/.nc_listener.sh`** - netcat bind shell on port 9999

### Persistence Mechanisms
12. **Systemd service `system-health.service`** - curl-based C2 loop contacting `10.13.37.1`
13. **`/etc/rc.local`** - starts netcat listener on boot

### System Modifications
14. **`/etc/hosts`** - `updates.ubuntu.com` and `security.ubuntu.com` redirected to `10.13.37.1`
15. **SUID shell** - `/usr/local/bin/.suid_shell` (SUID copy of bash)
16. **`/etc/ld.so.preload`** - points to `/tmp/.hidden/libhook.so` (LD_PRELOAD hijack)
17. **`/etc/pam.d/common-auth`** - commented-out `pam_permit.so` line appended
18. **`/etc/profile.d/system-init.sh`** - downloads and executes keylogger from `10.13.37.1`
19. **`/usr/bin/syshealth`** - bash reverse shell to `10.13.37.1:443`
20. **`/etc/ssh/sshd_config`** - `PermitRootLogin yes` and `PasswordAuthentication yes` appended

---

## minion-rocky (Rocky Linux 9) - 14 IoCs

### Rogue Users
1. **User `maint_worker`** - UID 0 (root-equivalent), password: `Summer2026!`
2. **User `operator`** - empty password (no password authentication)

### Cron Persistence
3. **`/etc/cron.d/logrotate-helper`** - runs `/opt/.config/health_check.sh` every 3 min
4. **`/etc/cron.d/py-maintenance`** - Python reverse shell to `10.13.37.2:8080` every 4 hours

### Hidden Files/Directories
5. **`/opt/.config/health_check.sh`** - curl-based C2 beacon to `10.13.37.2:8443`
6. **`/opt/.config/c2.conf`** - plaintext C2 configuration file
7. **`/var/tmp/.kmod_loader.sh`** - simulated rootkit module loader

### Persistence Mechanisms
8. **Systemd timer `rpm-verify.timer`** + `rpm-verify.service` - runs C2 beacon every 5 min
9. **`/etc/init.d/network-monitor`** - reverse shell to `10.13.37.2:53`
10. **Systemd service `sshd-backup.service`** - rogue SSH daemon on port 2222 with PermitRootLogin=yes

### SSH/Access Backdoors
11. **Root authorized_keys** - `/root/.ssh/authorized_keys` contains ed25519 key for `operator@c2`
12. **Sudoers backdoor** - `/etc/sudoers.d/operator` grants `operator` passwordless sudo

### System Modifications
13. **SUID binary** - `/usr/local/bin/.find_helper` (SUID+world-writable copy of `find`)
14. **iptables rule** - allows all traffic from `10.13.37.0/24`
15. **`/etc/resolv.conf`** - rogue nameserver `10.13.37.2` added
16. **`/etc/motd`** - social engineering message asking for credential re-entry

---

## minion-debian (Debian 12) - 15 IoCs

### Rogue Users
1. **User `dbadmin`** - system user with sudo, shell `/bin/bash`, password: `Passw0rd!`
2. **User `logger_svc`** - member of `shadow` group (can read `/etc/shadow`), password: `logger123`

### Persistence
3. **Vagrant `.bashrc`** - `/home/vagrant/.bashrc` contains reverse shell loop to `10.13.37.3:8888`
4. **`/var/spool/.maintenance.sh`** - downloads implant from `10.13.37.3`, re-schedules via `at`
5. **Vagrant crontab** - entry runs curl command to `10.13.37.3:9443` every 15 min
6. **Systemd path unit `config-watcher.path`** + `config-watcher.service` - exfiltrates `/etc/shadow` on change to `10.13.37.3:9443`
7. **Systemd service `docker-api.service`** - exposes Docker socket on TCP port 2375

### Webshell/Backdoors
8. **`/var/www/html/.status.php`** - PHP webshell (command execution via `?cmd=`)
9. **Trojanized `ls`** - `/usr/local/bin/ls` wraps real `ls`, exfils directory info to `10.13.37.3:9443`

### System Modifications
10. **`/etc/ssh/sshd_config`** - `PermitRootLogin yes`, `AllowAgentForwarding yes`, `GatewayPorts yes`
11. **`/etc/ld.so.conf.d/custom-libs.conf`** - adds `/tmp/.libs` to library path
12. **`/root/.gitconfig`** - credential helper exfils credentials to `10.13.37.3:9443`
13. **`/etc/environment`** - `http_proxy` and `https_proxy` set to `10.13.37.3:8080`
14. **SUID Python** - `/usr/local/bin/.python3_debug` (SUID copy of Python3)
15. **`/etc/hosts`** - `debian.org` and `packages.debian.org` redirected to `10.13.37.3`

---

## minion-fedora (Fedora 40) - 14 IoCs

### Rogue Users
1. **User `admin_backup`** - member of `wheel` group, password: `Fedora2026!`
2. **User `print_svc`** - password: `cups1234`

### Sudoers/Privilege Escalation
3. **`/etc/sudoers.d/90-print-service`** - grants `print_svc` passwordless sudo

### Persistence
4. **Systemd user service** - `/root/.config/systemd/user/clipboard-sync.service` - exfiltrates `/etc/shadow` to `10.13.37.4:5555`
5. **XDG autostart** - `/etc/xdg/autostart/desktop-sync.desktop` - runs `/opt/.fedora-tools/sync.sh`
6. **`/opt/.fedora-tools/sync.sh`** - tars and exfiltrates passwd/shadow/sudoers to `10.13.37.4:9090`
7. **`/etc/cron.d/sysstat-collector`** - base64-encoded reverse shell to `10.13.37.4:443` every 20 min
8. **`/etc/NetworkManager/dispatcher.d/99-callback`** - C2 callback on network interface up

### SSH Backdoors
9. **Vagrant authorized_keys** - `/home/vagrant/.ssh/authorized_keys` contains RSA key for `attacker@evil`

### Backdoor Scripts
10. **`/usr/local/sbin/maintenance-console`** - socat bind shell on port 31337
11. **`/tmp/.pam_logger.sh`** - PAM credential logger

### System Modifications
12. **`/etc/profile`** - `PROMPT_COMMAND` logs all commands to `/var/tmp/.cmd_history`
13. **Rogue DNF plugin** - `/usr/lib/python3.12/site-packages/dnf-plugins/telemetry.py` - executes C2 commands on package operations
14. **SUID vim** - `/usr/local/bin/.vim_debug` (SUID copy of vim)
15. **Firewall rule** - allows all traffic from `10.13.37.0/24`
16. **Root `.bashrc`** - `su` and `passwd` aliases that log credentials to `/var/tmp/`

---

## minion-oracle (Oracle Linux 9) - 16 IoCs

### Rogue Users
1. **User `ora_maint`** - member of `wheel` group, password: `Oracle123!`
2. **`nobody` user** - shell changed from `/sbin/nologin` to `/bin/bash`

### Persistence
3. **`/etc/bashrc`** - if root, exfiltrates `/etc/shadow` to `10.13.37.5:7777` (system-wide bashrc)
4. **Systemd socket `debug-console.socket`** + `debug-console@.service` - bind shell on port 4444 via socket activation
5. **`/etc/cron.d/oracle-inventory`** - runs beacon script every 30 min
6. **`/opt/.oracle/inventory.sh`** - exfiltrates system info to `10.13.37.5:7777`
7. **`/etc/cron.d/user-sync`** - re-creates `ora_maint` user every 10 min if deleted (self-healing persistence)

### SSH/Access Backdoors
8. **Root authorized_keys** - `/root/.ssh/authorized_keys` contains key for `oracle-admin@c2`
9. **`/root/.ssh/config`** - `StrictHostKeyChecking no` (disables SSH host verification)

### System Modifications
10. **`/etc/ld.so.preload`** - points to `/opt/.oracle/libpatch.so`
11. **`/etc/tmpfiles.d/cleanup.conf`** - creates SUID+world-writable bash copy at `/usr/local/bin/.emergency_shell` on boot
12. **Rogue yum repo** - `/etc/yum.repos.d/enterprise-updates.repo` points to `10.13.37.5:8080` with `gpgcheck=0`
13. **`/etc/environment`** - `LD_LIBRARY_PATH` includes `/opt/.oracle/libs`
14. **`/usr/local/bin/sysmon`** - Python reverse shell beacon to `10.13.37.5:9999`
15. **`/etc/logrotate.d/audit-forward`** - exfiltrates `/var/log/secure` to `10.13.37.5:7777` on rotation
16. **SUID netcat** - `/usr/local/bin/.netcat_debug` (SUID copy of nc/ncat)
17. **`/opt/.oracle/hide_proc.sh`** - process hiding script
18. **`/etc/hosts`** - `yum.oracle.com` and `linux.oracle.com` redirected to `10.13.37.5`

---

## Summary by IoC Category

| Category | Ubuntu | Rocky | Debian | Fedora | Oracle | Total |
|----------|--------|-------|--------|--------|--------|-------|
| Rogue Users | 2 | 2 | 2 | 2 | 2 | **10** |
| SSH Backdoor Keys | 2 | 1 | 0 | 1 | 1 | **5** |
| Cron Persistence | 3 | 2 | 1 | 1 | 2 | **9** |
| Systemd Persistence | 1 | 3 | 2 | 2 | 1 | **9** |
| Hidden Files/Scripts | 4 | 3 | 2 | 2 | 3 | **14** |
| SUID Binaries | 1 | 1 | 1 | 1 | 2 | **6** |
| Modified System Files | 4 | 3 | 5 | 4 | 5 | **21** |
| Sudoers Backdoors | 0 | 1 | 0 | 1 | 0 | **2** |
| Reverse/Bind Shells | 3 | 2 | 2 | 2 | 2 | **11** |
| Data Exfiltration | 0 | 0 | 2 | 2 | 3 | **7** |

### Attacker C2 IPs
- `10.13.37.1` - targets **minion-ubuntu**
- `10.13.37.2` - targets **minion-rocky**
- `10.13.37.3` - targets **minion-debian**
- `10.13.37.4` - targets **minion-fedora**
- `10.13.37.5` - targets **minion-oracle**

### Hunting Tips
- Check for users with UID 0: `awk -F: '$3==0' /etc/passwd`
- Check for passwordless users: `awk -F: '($2=="" || $2=="!")' /etc/shadow`
- Find SUID binaries: `find / -perm -4000 -type f 2>/dev/null`
- Check cron: `ls -la /etc/cron.d/ /etc/cron.daily/` + `crontab -l` for each user
- Check systemd: `systemctl list-unit-files --state=enabled`
- Check authorized_keys: `find / -name authorized_keys 2>/dev/null`
- Check /etc/hosts for redirects
- Check /etc/ld.so.preload
- Check /etc/sudoers.d/
- Check /etc/profile.d/ and /etc/bashrc for injected commands
- Look for hidden files: `find /tmp /dev/shm /var/tmp /opt -name ".*" 2>/dev/null`
