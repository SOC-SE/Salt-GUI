# Falco HIDS - CCDC Edition
# Deploys Falco with modern_ebpf and CCDC detection rules
# Apply: salt '*' state.apply linux.security.falco

{% set os_family = grains['os_family'] %}

# Install Falco repository and package
{% if os_family == 'Debian' %}
falco_gpg_key:
  cmd.run:
    - name: curl -fsSL https://falco.org/repo/falcosecurity-packages.asc | gpg --batch --yes --dearmor -o /usr/share/keyrings/falco-archive-keyring.gpg
    - creates: /usr/share/keyrings/falco-archive-keyring.gpg

falco_repo:
  file.managed:
    - name: /etc/apt/sources.list.d/falcosecurity.list
    - contents: "deb [signed-by=/usr/share/keyrings/falco-archive-keyring.gpg] https://download.falco.org/packages/deb stable main"
    - require:
      - cmd: falco_gpg_key

falco_apt_update:
  cmd.run:
    - name: apt-get update -qq
    - onchanges:
      - file: falco_repo

falco_package:
  pkg.installed:
    - name: falco
    - require:
      - cmd: falco_apt_update

{% elif os_family == 'RedHat' %}
falco_repo:
  file.managed:
    - name: /etc/yum.repos.d/falcosecurity.repo
    - contents: |
        [falcosecurity]
        name=Falco Security
        baseurl=https://download.falco.org/packages/rpm
        gpgcheck=1
        gpgkey=https://falco.org/repo/falcosecurity-packages.asc
        enabled=1

falco_package:
  pkg.installed:
    - name: falco
    - require:
      - file: falco_repo
{% endif %}

# Create log directory
falco_log_dir:
  file.directory:
    - name: /var/log/falco
    - mode: '0755'

falco_log_file:
  file.managed:
    - name: /var/log/falco/falco_alerts.log
    - replace: false
    - mode: '0644'
    - require:
      - file: falco_log_dir

# Falco configuration
falco_config:
  file.managed:
    - name: /etc/falco/falco.yaml
    - contents: |
        engine:
          kind: modern_ebpf
          modern_ebpf:
            cpus_for_each_buffer: 2
        rules_files:
          - /etc/falco/rules.d/ccdc_quick.yaml
        json_output: true
        json_include_output_property: true
        json_include_tags_property: true
        file_output:
          enabled: true
          keep_alive: true
          filename: /var/log/falco/falco_alerts.log
        stdout_output:
          enabled: true
        syslog_output:
          enabled: false
        http_output:
          enabled: false
        buffered_outputs: false
        priority: debug
        watch_config_files: false
    - require:
      - pkg: falco_package

# Rules directory
falco_rules_dir:
  file.directory:
    - name: /etc/falco/rules.d
    - require:
      - pkg: falco_package

# CCDC detection rules
falco_ccdc_rules:
  file.managed:
    - name: /etc/falco/rules.d/ccdc_quick.yaml
    - contents: |
        # CCDC Quick Deploy Rules

        - macro: spawned_process
          condition: evt.type in (execve, execveat)

        - macro: open_write
          condition: evt.type in (open, openat, openat2) and evt.is_open_write=true

        - macro: open_read
          condition: evt.type in (open, openat, openat2) and evt.is_open_read=true

        - rule: ROOTKIT - Kernel Module Loaded
          desc: Detect kernel module loading
          condition: evt.type in (init_module, finit_module) or (spawned_process and proc.name in (insmod, modprobe))
          output: "CRITICAL [ROOTKIT] Kernel module loaded (user=%user.name command=%proc.cmdline)"
          priority: CRITICAL
          tags: [ccdc, rootkit]

        - rule: ROOTKIT - LD_PRELOAD Injection
          desc: Detect LD_PRELOAD abuse
          condition: spawned_process and proc.env contains "LD_PRELOAD"
          output: "CRITICAL [ROOTKIT] LD_PRELOAD injection (user=%user.name command=%proc.cmdline)"
          priority: CRITICAL
          tags: [ccdc, rootkit]

        - rule: EBPF - BPF Program Loaded
          desc: Detect BPF loading (BPFDoor indicator)
          condition: evt.type = bpf and not proc.name in (falco, sysdig, cilium, systemd)
          output: "CRITICAL [EBPF] BPF program loaded (user=%user.name command=%proc.cmdline)"
          priority: CRITICAL
          tags: [ccdc, ebpf, bpfdoor]

        - rule: EBPF - Raw Socket Created
          desc: Detect raw socket (BPFDoor indicator)
          condition: evt.type in (socket) and evt.arg.domain = AF_PACKET and not proc.name in (tcpdump, dhclient)
          output: "CRITICAL [EBPF] Raw socket created (user=%user.name command=%proc.cmdline)"
          priority: CRITICAL
          tags: [ccdc, ebpf, bpfdoor]

        - rule: PERSIST - SSH Keys Modified
          desc: Detect authorized_keys changes
          condition: open_write and fd.name contains "authorized_keys"
          output: "CRITICAL [PERSIST] SSH keys modified (user=%user.name file=%fd.name)"
          priority: CRITICAL
          tags: [ccdc, persistence]

        - rule: PERSIST - Cron Modified
          desc: Detect cron changes
          condition: open_write and (fd.name startswith /etc/cron or fd.name startswith /var/spool/cron)
          output: "CRITICAL [PERSIST] Cron modified (user=%user.name file=%fd.name)"
          priority: CRITICAL
          tags: [ccdc, persistence]

        - rule: PERSIST - Systemd Service Created
          desc: Detect systemd service creation
          condition: open_write and fd.name startswith /etc/systemd/system and fd.name endswith ".service"
          output: "CRITICAL [PERSIST] Systemd service created (user=%user.name file=%fd.name)"
          priority: CRITICAL
          tags: [ccdc, persistence]

        - rule: CREDS - Shadow File Access
          desc: Detect /etc/shadow access
          condition: open_read and fd.name = /etc/shadow and not proc.name in (sshd, sudo, su, passwd, login)
          output: "CRITICAL [CREDS] Shadow file accessed (user=%user.name command=%proc.cmdline)"
          priority: CRITICAL
          tags: [ccdc, credentials]

        - rule: C2 - Reverse Shell
          desc: Detect reverse shell
          condition: >
            spawned_process and
            ((proc.name in (nc, ncat, netcat) and (proc.cmdline contains "-e" or proc.cmdline contains "-c")) or
             (proc.name = bash and proc.cmdline contains "/dev/tcp") or
             (proc.name in (python, python3) and proc.cmdline contains "socket"))
          output: "CRITICAL [C2] Reverse shell detected (user=%user.name command=%proc.cmdline)"
          priority: CRITICAL
          tags: [ccdc, c2]

        - rule: C2 - Netcat Listener
          desc: Detect netcat listener
          condition: spawned_process and proc.name in (nc, ncat, netcat) and proc.cmdline contains "-l"
          output: "CRITICAL [C2] Netcat listener (user=%user.name command=%proc.cmdline)"
          priority: CRITICAL
          tags: [ccdc, c2]

        - rule: WEBSHELL - Shell from Web Server
          desc: Detect shell from web process
          condition: spawned_process and proc.pname in (apache2, httpd, nginx, php-fpm, php, java) and proc.name in (bash, sh, python, perl)
          output: "CRITICAL [WEBSHELL] Shell from web server (user=%user.name command=%proc.cmdline parent=%proc.pname)"
          priority: CRITICAL
          tags: [ccdc, webshell]

        - rule: EVASION - Log Tampering
          desc: Detect log deletion
          condition: evt.type in (unlink, unlinkat) and evt.arg.name startswith /var/log and not proc.name = logrotate
          output: "CRITICAL [EVASION] Log tampering (user=%user.name file=%evt.arg.name)"
          priority: CRITICAL
          tags: [ccdc, evasion]

        - rule: EVASION - History Cleared
          desc: Detect history clearing
          condition: spawned_process and (proc.cmdline contains "history -c" or proc.cmdline contains "HISTFILE=/dev/null")
          output: "CRITICAL [EVASION] History cleared (user=%user.name command=%proc.cmdline)"
          priority: CRITICAL
          tags: [ccdc, evasion]

        - rule: BASELINE - Execution from /tmp
          desc: Detect execution from temp dirs
          condition: spawned_process and (proc.exepath startswith /tmp or proc.exepath startswith /dev/shm)
          output: "WARNING [BASELINE] Execution from temp (user=%user.name exe=%proc.exepath)"
          priority: WARNING
          tags: [ccdc, baseline]
    - require:
      - file: falco_rules_dir

# Enable BPF if restricted
falco_bpf_access:
  cmd.run:
    - name: echo 0 > /proc/sys/kernel/unprivileged_bpf_disabled
    - onlyif: test "$(cat /proc/sys/kernel/unprivileged_bpf_disabled 2>/dev/null)" != "0"

# Stop conflicting Falco services
{% for svc in ['falco', 'falco-bpf', 'falco-kmod'] %}
falco_stop_{{ svc }}:
  service.dead:
    - name: {{ svc }}
    - enable: false
    - require:
      - pkg: falco_package
{% endfor %}

# Start modern-bpf service
falco_modern_bpf:
  service.running:
    - name: falco-modern-bpf
    - enable: true
    - require:
      - file: falco_config
      - file: falco_ccdc_rules
      - cmd: falco_bpf_access
    - watch:
      - file: falco_config
      - file: falco_ccdc_rules
