# Auditd forensic monitoring - CCDC Edition
# Installs auditd with watch rules for key system files
# Apply: salt '*' state.apply linux.security.auditd

{% set os_family = grains['os_family'] %}

auditd_package:
  pkg.installed:
    {% if os_family == 'Debian' %}
    - name: auditd
    {% elif os_family == 'RedHat' %}
    - name: audit
    {% endif %}

auditd_rules_dir:
  file.directory:
    - name: /etc/audit/rules.d
    - require:
      - pkg: auditd_package

auditd_forensic_rules:
  file.managed:
    - name: /etc/audit/rules.d/saltgui-forensics.rules
    - contents: |
        ## Salt-GUI forensic watch rules
        -w /etc/passwd -p wa -k user_mod
        -w /etc/shadow -p wa -k user_mod
        -w /etc/sudoers -p wa -k sudo_mod
        -w /etc/ssh/sshd_config -p wa -k ssh_mod
        -w /etc/crontab -p wa -k cron_mod
        -w /etc/cron.d/ -p wa -k cron_mod
        -w /etc/pam.d/ -p wa -k pam_mod
        -w /etc/ld.so.preload -p wa -k preload_mod
        -w /etc/profile.d/ -p wa -k profile_mod
        -w /etc/systemd/system/ -p wa -k systemd_mod
        -a always,exit -F dir=/tmp -F perm=x -k tmp_exec
        -a always,exit -F dir=/dev/shm -F perm=x -k shm_exec
    - require:
      - file: auditd_rules_dir

auditd_load_rules:
  cmd.run:
    - name: augenrules --load
    - onchanges:
      - file: auditd_forensic_rules

auditd_service:
  service.running:
    - name: auditd
    - enable: true
    - require:
      - pkg: auditd_package
    - watch:
      - file: auditd_forensic_rules
