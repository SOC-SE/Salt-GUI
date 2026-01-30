/**
 * Forensics Routes
 *
 * Provides forensic collection, artifact browsing, analysis, findings,
 * timeline, and metadata endpoints for incident response.
 *
 * @module routes/forensics
 */

const express = require('express');
const router = express.Router();
const { client: saltClient } = require('../lib/salt-client');
const logger = require('../lib/logger');
const { requireAuth } = require('../middleware/auth');
const { auditAction } = require('../middleware/audit');

router.use(requireAuth);

// In-memory job tracking
const forensicJobs = new Map();

function generateJobId() {
  return Date.now().toString(36) + Math.random().toString(36).substr(2, 6);
}

// ============================================================
// Collection Endpoints
// ============================================================

/**
 * POST /api/forensics/collect
 * Standard forensic collection
 */
router.post('/collect', auditAction('forensics.collect'), async (req, res) => {
  const { targets, level = 'standard', timeout = 300 } = req.body;

  if (!targets) {
    return res.status(400).json({ success: false, error: 'Targets required' });
  }

  const jobId = generateJobId();
  forensicJobs.set(jobId, { id: jobId, status: 'running', level, targets, created: new Date().toISOString(), results: null });

  // Run async
  (async () => {
    try {
      const collectScript = buildCollectScript(level);
      const result = await saltClient.cmd(targets, collectScript, { shell: '/bin/bash', timeout });
      forensicJobs.set(jobId, { ...forensicJobs.get(jobId), status: 'completed', results: result });
    } catch (error) {
      forensicJobs.set(jobId, { ...forensicJobs.get(jobId), status: 'failed', error: error.message });
    }
  })();

  res.json({ success: true, job_id: jobId, message: 'Collection started' });
});

/**
 * POST /api/forensics/quick-collect
 * Quick forensic collection (minimal)
 */
router.post('/quick-collect', auditAction('forensics.quick_collect'), async (req, res) => {
  const { targets, timeout = 120 } = req.body;
  if (!targets) {
    return res.status(400).json({ success: false, error: 'Targets required' });
  }

  const jobId = generateJobId();
  forensicJobs.set(jobId, { id: jobId, status: 'running', level: 'quick', targets, created: new Date().toISOString(), results: null });

  (async () => {
    try {
      const script = buildCollectScript('quick');
      const result = await saltClient.cmd(targets, script, { shell: '/bin/bash', timeout });
      forensicJobs.set(jobId, { ...forensicJobs.get(jobId), status: 'completed', results: result });
    } catch (error) {
      forensicJobs.set(jobId, { ...forensicJobs.get(jobId), status: 'failed', error: error.message });
    }
  })();

  res.json({ success: true, job_id: jobId, message: 'Quick collection started' });
});

/**
 * POST /api/forensics/advanced
 * Advanced forensic collection
 */
router.post('/advanced', auditAction('forensics.advanced'), async (req, res) => {
  const { targets, timeout = 600 } = req.body;
  if (!targets) {
    return res.status(400).json({ success: false, error: 'Targets required' });
  }

  const jobId = generateJobId();
  forensicJobs.set(jobId, { id: jobId, status: 'running', level: 'advanced', targets, created: new Date().toISOString(), results: null });

  (async () => {
    try {
      const script = buildCollectScript('advanced');
      const result = await saltClient.cmd(targets, script, { shell: '/bin/bash', timeout });
      forensicJobs.set(jobId, { ...forensicJobs.get(jobId), status: 'completed', results: result });
    } catch (error) {
      forensicJobs.set(jobId, { ...forensicJobs.get(jobId), status: 'failed', error: error.message });
    }
  })();

  res.json({ success: true, job_id: jobId, message: 'Advanced collection started' });
});

/**
 * POST /api/forensics/comprehensive
 * Comprehensive forensic collection with all options
 */
router.post('/comprehensive', auditAction('forensics.comprehensive'), async (req, res) => {
  const { targets, memory_dump = false, volatility = false, quick_mode = false, skip_logs = false, timeout = 900 } = req.body;
  if (!targets) {
    return res.status(400).json({ success: false, error: 'Targets required' });
  }

  const jobId = generateJobId();
  const opts = { memory_dump, volatility, quick_mode, skip_logs };
  forensicJobs.set(jobId, { id: jobId, status: 'running', level: 'comprehensive', targets, options: opts, created: new Date().toISOString(), results: null });

  (async () => {
    try {
      const script = buildCollectScript('comprehensive', opts);
      const result = await saltClient.cmd(targets, script, { shell: '/bin/bash', timeout });
      forensicJobs.set(jobId, { ...forensicJobs.get(jobId), status: 'completed', results: result });
    } catch (error) {
      forensicJobs.set(jobId, { ...forensicJobs.get(jobId), status: 'failed', error: error.message });
    }
  })();

  res.json({ success: true, job_id: jobId, message: 'Comprehensive collection started' });
});

/**
 * GET /api/forensics/status/:id
 * Get job status
 */
router.get('/status/:id', async (req, res) => {
  const job = forensicJobs.get(req.params.id);
  if (!job) {
    return res.status(404).json({ success: false, error: 'Job not found' });
  }
  res.json({ success: true, job });
});

/**
 * GET /api/forensics/jobs
 * List all forensic jobs
 */
router.get('/jobs', async (req, res) => {
  const jobs = Array.from(forensicJobs.values()).sort((a, b) => new Date(b.created) - new Date(a.created));
  res.json({ success: true, jobs });
});

// ============================================================
// Artifact Endpoints
// ============================================================

/**
 * GET /api/forensics/collections
 * List all forensic collections across targets
 */
router.get('/collections', async (req, res) => {
  try {
    // Return structured file list: one filename per line (not ls -la)
    const result = await saltClient.cmd('*', 'find /tmp/forensics/ -maxdepth 1 -type f -printf "%f\\n" 2>/dev/null | sort || echo ""', { shell: '/bin/bash', timeout: 30 });
    res.json({ success: true, collections: result });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

/**
 * GET /api/forensics/artifacts/:target
 * List artifacts on a specific target
 */
router.get('/artifacts/:target', async (req, res) => {
  const { target } = req.params;
  try {
    const result = await saltClient.cmd(target, 'find /tmp/forensics/ -name "*.tar.gz" -o -name "*.log" -o -name "*.json" 2>/dev/null | head -100 || echo "No artifacts"', { shell: '/bin/bash', timeout: 30 });
    const artifacts = {};
    for (const [minion, output] of Object.entries(result)) {
      if (typeof output === 'string' && output !== 'No artifacts') {
        artifacts[minion] = output.split('\n').filter(f => f.trim()).map(f => ({ path: f.trim() }));
      } else {
        artifacts[minion] = [];
      }
    }
    res.json({ success: true, artifacts });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

/**
 * POST /api/forensics/artifact-contents
 * List contents of a tarball artifact
 */
router.post('/artifact-contents', async (req, res) => {
  const { target, artifact_path } = req.body;
  if (!target || !artifact_path) {
    return res.status(400).json({ success: false, error: 'Target and artifact_path required' });
  }
  try {
    const result = await saltClient.cmd(target, `tar tzf '${artifact_path.replace(/'/g, "\\'")}' 2>/dev/null | head -500`, { shell: '/bin/bash', timeout: 60 });
    const files = {};
    for (const [minion, output] of Object.entries(result)) {
      files[minion] = typeof output === 'string' ? output.split('\n').filter(f => f.trim()) : [];
    }
    res.json({ success: true, files });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

/**
 * POST /api/forensics/artifact-file
 * Extract and view a single file from a tarball
 */
router.post('/artifact-file', async (req, res) => {
  const { target, artifact_path, file_path } = req.body;
  if (!target || !artifact_path || !file_path) {
    return res.status(400).json({ success: false, error: 'Target, artifact_path, and file_path required' });
  }
  try {
    const result = await saltClient.cmd(target, `tar xzf '${artifact_path.replace(/'/g, "\\'")}' -O '${file_path.replace(/'/g, "\\'")}' 2>/dev/null | head -2000`, { shell: '/bin/bash', timeout: 60 });
    res.json({ success: true, content: result });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

/**
 * GET /api/forensics/artifact/:target/content
 * Alternative: list tarball contents for a target
 */
router.get('/artifact/:target/content', async (req, res) => {
  const { target } = req.params;
  const { path: artifactPath } = req.query;
  if (!artifactPath) {
    return res.status(400).json({ success: false, error: 'path query param required' });
  }
  try {
    const result = await saltClient.cmd(target, `tar tzf '${artifactPath.replace(/'/g, "\\'")}' 2>/dev/null | head -500`, { shell: '/bin/bash', timeout: 60 });
    res.json({ success: true, files: result });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

/**
 * POST /api/forensics/artifact/:target/extract
 * Extract a specific file from a tarball
 */
router.post('/artifact/:target/extract', async (req, res) => {
  const { target } = req.params;
  const { artifact_path, file_path } = req.body;
  if (!artifact_path || !file_path) {
    return res.status(400).json({ success: false, error: 'artifact_path and file_path required' });
  }
  try {
    const result = await saltClient.cmd(target, `tar xzf '${artifact_path.replace(/'/g, "\\'")}' -O '${file_path.replace(/'/g, "\\'")}' 2>/dev/null | head -2000`, { shell: '/bin/bash', timeout: 60 });
    res.json({ success: true, content: result });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

/**
 * POST /api/forensics/read-file
 * Read a plain file from /tmp/forensics/ on a minion
 */
router.post('/read-file', async (req, res) => {
  const { target, filename } = req.body;
  if (!target || !filename) {
    return res.status(400).json({ success: false, error: 'Target and filename required' });
  }
  // Sanitize: only allow simple filenames, no path traversal
  const safe = filename.replace(/[^a-zA-Z0-9._-]/g, '');
  if (!safe) {
    return res.status(400).json({ success: false, error: 'Invalid filename' });
  }
  try {
    const result = await saltClient.cmd(target, `head -2000 '/tmp/forensics/${safe}' 2>/dev/null || echo "File not found"`, { shell: '/bin/bash', timeout: 30 });
    res.json({ success: true, content: result });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

/**
 * POST /api/forensics/retrieve
 * Retrieve artifact to Salt master via cp.push
 */
router.post('/retrieve', auditAction('forensics.retrieve'), async (req, res) => {
  const { target, artifact_path } = req.body;
  if (!target || !artifact_path) {
    return res.status(400).json({ success: false, error: 'Target and artifact_path required' });
  }
  try {
    const result = await saltClient.run({
      client: 'local',
      tgt: target,
      fun: 'cp.push',
      arg: [artifact_path]
    });
    res.json({ success: true, result });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

/**
 * POST /api/forensics/cleanup
 * Clean up old forensic artifacts
 */
router.post('/cleanup', auditAction('forensics.cleanup'), async (req, res) => {
  const { targets = '*', age_hours = 24 } = req.body;
  try {
    const result = await saltClient.cmd(targets, `find /tmp/forensics/ -type f -mmin +${age_hours * 60} -delete 2>/dev/null; echo "Cleanup complete"`, { shell: '/bin/bash', timeout: 60 });
    res.json({ success: true, result });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// ============================================================
// Analysis Endpoints
// ============================================================

/**
 * POST /api/forensics/analyze
 * Live 16-category forensic analysis
 */
router.post('/analyze', auditAction('forensics.analyze'), async (req, res) => {
  const { target, timeout = 300 } = req.body;
  if (!target) {
    return res.status(400).json({ success: false, error: 'Target required' });
  }

  try {
    const script = buildAnalysisScript();
    const result = await saltClient.cmd(target, script, { shell: '/bin/bash', timeout });

    // Parse results into findings
    const findings = {};
    for (const [minion, output] of Object.entries(result)) {
      findings[minion] = parseAnalysisOutput(output);
    }

    res.json({ success: true, findings });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

/**
 * POST /api/forensics/analysis
 * Targeted analysis by type
 */
router.post('/analysis', auditAction('forensics.analysis'), async (req, res) => {
  const { target, tarball_path, types = [], timeout = 300 } = req.body;
  if (!target) {
    return res.status(400).json({ success: false, error: 'Target required' });
  }

  try {
    const analysisTypes = types.length > 0 ? types : ['rootkit', 'persistence', 'network', 'users', 'processes'];
    const script = buildTargetedAnalysisScript(analysisTypes, tarball_path);
    const result = await saltClient.cmd(target, script, { shell: '/bin/bash', timeout });

    const findings = {};
    for (const [minion, output] of Object.entries(result)) {
      findings[minion] = parseAnalysisOutput(output);
    }

    res.json({ success: true, findings, types: analysisTypes });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// ============================================================
// Findings, Timeline, Metadata Endpoints
// ============================================================

/**
 * GET /api/forensics/findings/:target
 * Get findings for a target
 */
router.get('/findings/:target', async (req, res) => {
  const { target } = req.params;
  const { collection, severity } = req.query;

  try {
    const script = `cat /tmp/forensics/findings_*.json 2>/dev/null || echo '{"findings":[]}'`;
    const result = await saltClient.cmd(target, script, { shell: '/bin/bash', timeout: 30 });

    const findings = {};
    for (const [minion, output] of Object.entries(result)) {
      try {
        const parsed = JSON.parse(output);
        let items = parsed.findings || [];
        if (severity) {
          items = items.filter(f => f.severity === severity || severityLevel(f.severity) >= severityLevel(severity));
        }
        findings[minion] = items;
      } catch {
        findings[minion] = parseAnalysisOutput(output);
      }
    }

    res.json({ success: true, findings });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

/**
 * GET /api/forensics/timeline/:target
 * Get file timeline for a target
 */
router.get('/timeline/:target', async (req, res) => {
  const { target } = req.params;
  const { collection, limit = 200 } = req.query;

  try {
    const script = `find /tmp/forensics/ /var/log/ /etc/ -maxdepth 2 -type f -printf '%T@ %m %u %s %p\\n' 2>/dev/null | sort -rn | head -${parseInt(limit)}`;
    const result = await saltClient.cmd(target, script, { shell: '/bin/bash', timeout: 60 });

    const timeline = {};
    for (const [minion, output] of Object.entries(result)) {
      if (typeof output === 'string') {
        timeline[minion] = output.split('\n').filter(l => l.trim()).map(line => {
          const parts = line.split(' ');
          const mtime = parseFloat(parts[0]) || 0;
          return {
            mtime: new Date(mtime * 1000).toISOString(),
            mode: parts[1] || '',
            uid: parts[2] || '',
            size: parseInt(parts[3]) || 0,
            path: parts.slice(4).join(' ')
          };
        });
      } else {
        timeline[minion] = [];
      }
    }

    res.json({ success: true, timeline });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

/**
 * GET /api/forensics/metadata/:target
 * Get collection metadata for a target
 */
router.get('/metadata/:target', async (req, res) => {
  const { target } = req.params;
  const { collection } = req.query;

  try {
    const script = `cat /tmp/forensics/metadata.json 2>/dev/null || echo '{"collected_at":"unknown","hostname":"unknown","level":"unknown"}'`;
    const result = await saltClient.cmd(target, script, { shell: '/bin/bash', timeout: 30 });

    const metadata = {};
    for (const [minion, output] of Object.entries(result)) {
      try {
        metadata[minion] = JSON.parse(output);
      } catch {
        metadata[minion] = { raw: output };
      }
    }

    res.json({ success: true, metadata });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// ============================================================
// Helper Functions
// ============================================================

function severityLevel(sev) {
  const levels = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };
  return levels[(sev || '').toLowerCase()] || 0;
}

function buildCollectScript(level, opts = {}) {
  const base = `
FDIR="/tmp/forensics"
mkdir -p "$FDIR"
TS=$(date +%Y%m%d_%H%M%S)
HOST=$(hostname)
echo '{"collected_at":"'$(date -Iseconds)'","hostname":"'$HOST'","level":"__LEVEL__"}' > "$FDIR/metadata.json"
`;

  const quickSteps = `
# Quick: basic system info
hostname > "$FDIR/hostname.txt"
date > "$FDIR/date.txt"
uname -a > "$FDIR/uname.txt"
id > "$FDIR/id.txt"
w > "$FDIR/who.txt" 2>/dev/null
ps auxf > "$FDIR/ps.txt" 2>/dev/null
ss -tlnp > "$FDIR/ss_listen.txt" 2>/dev/null
cat /etc/passwd > "$FDIR/passwd.txt" 2>/dev/null
last -20 > "$FDIR/last.txt" 2>/dev/null
echo "Quick collection complete"
`;

  const standardSteps = `
# Standard: add more detail
cp /etc/shadow "$FDIR/shadow.txt" 2>/dev/null
cp /etc/group "$FDIR/group.txt" 2>/dev/null
ss -anp > "$FDIR/ss_all.txt" 2>/dev/null
ip addr > "$FDIR/ip_addr.txt" 2>/dev/null
ip route > "$FDIR/ip_route.txt" 2>/dev/null
iptables -L -n -v > "$FDIR/iptables.txt" 2>/dev/null
systemctl list-units --type=service > "$FDIR/services.txt" 2>/dev/null
crontab -l > "$FDIR/crontab_root.txt" 2>/dev/null
ls -la /etc/cron.d/ > "$FDIR/cron_d.txt" 2>/dev/null
cat /etc/crontab > "$FDIR/etc_crontab.txt" 2>/dev/null
find /tmp /var/tmp -type f -mtime -1 -ls > "$FDIR/recent_tmp.txt" 2>/dev/null
echo "Standard collection complete"
`;

  const advancedSteps = `
# Advanced: deep forensics
find / -perm -4000 -type f -ls > "$FDIR/suid.txt" 2>/dev/null
find / -perm -2000 -type f -ls > "$FDIR/sgid.txt" 2>/dev/null
find /home -name ".*" -type f -ls > "$FDIR/hidden_home.txt" 2>/dev/null
lsmod > "$FDIR/lsmod.txt" 2>/dev/null
cat /proc/modules > "$FDIR/proc_modules.txt" 2>/dev/null
ls -la /dev/shm/ > "$FDIR/dev_shm.txt" 2>/dev/null
cat /etc/hosts > "$FDIR/hosts.txt" 2>/dev/null
cat /etc/resolv.conf > "$FDIR/resolv.txt" 2>/dev/null
ls -la /root/.ssh/ > "$FDIR/root_ssh.txt" 2>/dev/null
cat /root/.bash_history > "$FDIR/root_history.txt" 2>/dev/null
find /etc -name "*.conf" -newer /etc/hostname -ls > "$FDIR/recent_conf.txt" 2>/dev/null
echo "Advanced collection complete"
`;

  const comprehensiveSteps = `
# Comprehensive: full forensic collection (50+ categories)

# --- Log collection ---
${opts.skip_logs ? '' : `
timeout 30 bash -c 'cp /var/log/auth.log "$FDIR/auth.log" 2>/dev/null; cp /var/log/syslog "$FDIR/syslog.log" 2>/dev/null; cp /var/log/secure "$FDIR/secure.log" 2>/dev/null'
timeout 30 bash -c 'cp /var/log/kern.log "$FDIR/kern.log" 2>/dev/null; cp /var/log/daemon.log "$FDIR/daemon.log" 2>/dev/null'
timeout 30 bash -c 'cp /var/log/dpkg.log "$FDIR/dpkg.log" 2>/dev/null; cp /var/log/apt/history.log "$FDIR/apt_history.log" 2>/dev/null'
timeout 30 bash -c 'cp /var/log/salt/minion "$FDIR/salt_minion.log" 2>/dev/null'
`}

# --- Memory info ---
${opts.memory_dump ? `
timeout 30 bash -c 'cat /proc/meminfo > "$FDIR/meminfo.txt" 2>/dev/null; cat /proc/slabinfo > "$FDIR/slabinfo.txt" 2>/dev/null'
timeout 30 bash -c 'cat /proc/buddyinfo > "$FDIR/buddyinfo.txt" 2>/dev/null; cat /proc/vmstat > "$FDIR/vmstat.txt" 2>/dev/null'
` : ''}

# --- File hashing (critical binaries) ---
timeout 60 bash -c 'sha256sum /usr/bin/ssh /usr/bin/sudo /usr/bin/passwd /usr/sbin/sshd /usr/bin/login /usr/bin/su /usr/bin/crontab /usr/bin/at /usr/bin/wget /usr/bin/curl /usr/bin/nc /usr/bin/ncat /usr/bin/python3 /usr/bin/perl /usr/bin/whoami /usr/bin/id /bin/bash /bin/sh /usr/sbin/cron /usr/sbin/useradd /usr/sbin/usermod 2>/dev/null' > "$FDIR/file_hashes.txt"

# --- Package verification ---
timeout 120 bash -c 'if command -v debsums >/dev/null 2>&1; then debsums -c 2>/dev/null; elif command -v rpm >/dev/null 2>&1; then rpm -Va 2>/dev/null; fi' > "$FDIR/package_verify.txt"

# --- LD_PRELOAD / library injection ---
timeout 15 bash -c '{
  echo "=== /etc/ld.so.preload ==="; cat /etc/ld.so.preload 2>/dev/null || echo "(not found)"
  echo ""; echo "=== /etc/ld.so.conf.d/ ==="; ls -la /etc/ld.so.conf.d/ 2>/dev/null
  for f in /etc/ld.so.conf.d/*; do echo "--- $f ---"; cat "$f" 2>/dev/null; done
  echo ""; echo "=== LD_PRELOAD env ==="; grep -r LD_PRELOAD /etc/environment /etc/profile /etc/profile.d/ 2>/dev/null || echo "(none)"
}' > "$FDIR/ld_preload.txt"

# --- PAM config audit ---
timeout 15 bash -c '{
  echo "=== PAM configs ==="; ls -la /etc/pam.d/ 2>/dev/null
  echo ""; echo "=== pam_exec.so usage ==="; grep -r pam_exec /etc/pam.d/ 2>/dev/null || echo "(none)"
  echo ""; echo "=== suspicious PAM modules ==="; grep -rE "(pam_exec|pam_script|pam_permit)" /etc/pam.d/ 2>/dev/null || echo "(none)"
}' > "$FDIR/pam_config.txt"

# --- SSH key enumeration ---
timeout 30 bash -c '{
  echo "=== sshd_config ==="; cat /etc/ssh/sshd_config 2>/dev/null
  echo ""; echo "=== sshd_config.d ==="; cat /etc/ssh/sshd_config.d/* 2>/dev/null
  echo ""; echo "=== authorized_keys (all users) ===";
  while IFS=: read -r user _ _ _ _ home _; do
    [ -f "$home/.ssh/authorized_keys" ] && echo "--- $user ($home/.ssh/authorized_keys) ---" && cat "$home/.ssh/authorized_keys" 2>/dev/null
    ls "$home/.ssh/id_*" 2>/dev/null | while read k; do echo "Private key: $k"; done
  done < /etc/passwd
}' > "$FDIR/ssh_keys.txt"

# --- Systemd timer enumeration ---
timeout 15 bash -c '{
  echo "=== Active timers ==="; systemctl list-timers --all --no-pager 2>/dev/null
  echo ""; echo "=== Custom timer files ==="; find /etc/systemd/system /usr/lib/systemd/system -name "*.timer" -ls 2>/dev/null
}' > "$FDIR/systemd_timers.txt"

# --- At jobs ---
timeout 15 bash -c '{
  echo "=== atq ==="; atq 2>/dev/null || echo "(at not available)"
  echo ""; echo "=== /var/spool/at/ ==="; ls -la /var/spool/at/ 2>/dev/null
  echo ""; echo "=== at job contents ==="; for f in /var/spool/at/[a-z]*; do echo "--- $f ---"; cat "$f" 2>/dev/null; done
}' > "$FDIR/at_jobs.txt"

# --- Init.d scripts ---
timeout 15 bash -c '{
  echo "=== init.d listing ==="; ls -la /etc/init.d/ 2>/dev/null
  echo ""; echo "=== init.d script contents (first 10 lines each) ===";
  for f in /etc/init.d/*; do echo "--- $f ---"; head -10 "$f" 2>/dev/null; done
}' > "$FDIR/initd_scripts.txt"

# --- RC local ---
timeout 10 bash -c '{
  echo "=== /etc/rc.local ==="; cat /etc/rc.local 2>/dev/null || echo "(not found)"
  echo ""; echo "=== /etc/rc.d/rc.local ==="; cat /etc/rc.d/rc.local 2>/dev/null || echo "(not found)"
}' > "$FDIR/rc_local.txt"

# --- Profile.d enumeration ---
timeout 15 bash -c '{
  echo "=== /etc/profile.d/ listing ==="; ls -la /etc/profile.d/ 2>/dev/null
  echo ""; echo "=== /etc/profile.d/ contents ===";
  for f in /etc/profile.d/*.sh; do echo "--- $f ---"; cat "$f" 2>/dev/null; done
}' > "$FDIR/profile_d.txt"

# --- Bashrc/profile backdoor check ---
timeout 30 bash -c '{
  echo "=== /etc/bash.bashrc ==="; cat /etc/bash.bashrc 2>/dev/null
  echo ""; echo "=== /etc/profile ==="; cat /etc/profile 2>/dev/null
  echo ""; echo "=== User bashrc/profile ===";
  while IFS=: read -r user _ _ _ _ home _; do
    for rc in .bashrc .profile .bash_profile .bash_login .bash_logout; do
      [ -f "$home/$rc" ] && echo "--- $user: $home/$rc ---" && cat "$home/$rc" 2>/dev/null
    done
  done < /etc/passwd
}' > "$FDIR/bashrc_profiles.txt"

# --- /proc per-process analysis (top 50 by CPU) ---
timeout 60 bash -c '{
  echo "=== Top 50 processes - detailed ===";
  ps -eo pid --sort=-%cpu --no-headers | head -50 | while read pid; do
    echo "--- PID $pid ---"
    echo "exe: $(readlink /proc/$pid/exe 2>/dev/null)"
    echo "cmdline: $(tr "\\0" " " < /proc/$pid/cmdline 2>/dev/null)"
    echo "cwd: $(readlink /proc/$pid/cwd 2>/dev/null)"
    echo "environ (key vars): $(tr "\\0" "\\n" < /proc/$pid/environ 2>/dev/null | grep -E "^(LD_|PATH=|HOME=|USER=)" )"
    cat /proc/$pid/maps 2>/dev/null | head -5
    echo ""
  done
}' > "$FDIR/proc_analysis.txt"

# --- Deleted binaries running ---
timeout 30 bash -c '{
  echo "=== Deleted binaries still running ===";
  ls -la /proc/*/exe 2>/dev/null | while read line; do
    link=$(echo "$line" | awk "{print \\$NF}")
    echo "$line" | grep -q "(deleted)" && echo "DELETED: $line"
  done
  # Alternative check
  find /proc -maxdepth 2 -name exe -exec readlink {} \\; 2>/dev/null | grep "(deleted)"
}' > "$FDIR/deleted_binaries.txt"

# --- BPF/eBPF detection ---
timeout 15 bash -c '{
  echo "=== Raw sockets ==="; ss -0 2>/dev/null; cat /proc/net/raw 2>/dev/null
  echo ""; echo "=== bpftool ==="; bpftool prog list 2>/dev/null || echo "(bpftool not available)"
}' > "$FDIR/bpf_detection.txt"

# --- Network namespaces ---
timeout 10 bash -c 'ip netns list 2>/dev/null || echo "(none)"' > "$FDIR/net_namespaces.txt"

# --- Container indicators ---
timeout 10 bash -c '{
  echo "=== Container checks ===";
  [ -f /.dockerenv ] && echo "FOUND: /.dockerenv"
  grep -q docker /proc/1/cgroup 2>/dev/null && echo "FOUND: docker in cgroup"
  grep -q lxc /proc/1/cgroup 2>/dev/null && echo "FOUND: lxc in cgroup"
  cat /proc/1/cgroup 2>/dev/null
  echo ""; echo "=== Capabilities ==="; cat /proc/1/status 2>/dev/null | grep -i cap
}' > "$FDIR/container_indicators.txt"

# --- Webshell scanning ---
timeout 60 bash -c '{
  echo "=== Potential webshells ===";
  find /var/www /srv/www /opt -type f \\( -name "*.php" -o -name "*.jsp" -o -name "*.asp" -o -name "*.aspx" \\) 2>/dev/null | while read f; do
    grep -lE "(eval|exec|system|passthru|shell_exec|popen|proc_open|base64_decode|assert)" "$f" 2>/dev/null && echo "SUSPECT: $f"
  done
}' > "$FDIR/webshell_scan.txt"

# --- Crypto miner indicators ---
timeout 15 bash -c '{
  echo "=== Crypto miner process check ===";
  ps aux | grep -iE "(xmrig|minerd|stratum|cryptonight|hashrate|cpuminer|ethminer)" | grep -v grep
  echo ""; echo "=== Suspicious CPU usage ===";
  ps aux --sort=-%cpu | head -5
}' > "$FDIR/crypto_miner.txt"

# --- Capabilities audit ---
timeout 60 bash -c 'getcap -r / 2>/dev/null' > "$FDIR/capabilities.txt"

# --- Sudoers config ---
timeout 15 bash -c '{
  echo "=== /etc/sudoers ==="; cat /etc/sudoers 2>/dev/null
  echo ""; echo "=== /etc/sudoers.d/ ==="; ls -la /etc/sudoers.d/ 2>/dev/null
  for f in /etc/sudoers.d/*; do echo "--- $f ---"; cat "$f" 2>/dev/null; done
}' > "$FDIR/sudoers.txt"

# --- User shell histories (all users) ---
timeout 30 bash -c '{
  while IFS=: read -r user _ _ _ _ home _; do
    for hist in .bash_history .zsh_history .sh_history; do
      [ -f "$home/$hist" ] && echo "--- $user: $home/$hist ---" && tail -50 "$home/$hist" 2>/dev/null
    done
  done < /etc/passwd
}' > "$FDIR/shell_histories.txt"

# --- World-writable files in key directories ---
timeout 30 bash -c 'find /etc /usr /var -type f -perm -o+w -ls 2>/dev/null | head -100' > "$FDIR/world_writable.txt"

# --- Recently modified files (last 60 min) ---
timeout 60 bash -c 'find /etc /usr/bin /usr/sbin /bin /sbin /var/spool /tmp -type f -mmin -60 -ls 2>/dev/null | head -200' > "$FDIR/recent_modified.txt"

# --- Open file descriptors (lsof dump) ---
timeout 30 bash -c 'lsof -nP 2>/dev/null | head -500' > "$FDIR/lsof_full.txt"

# --- ARP cache + routing tables ---
timeout 10 bash -c '{
  echo "=== ARP cache ==="; arp -a 2>/dev/null || ip neigh 2>/dev/null
  echo ""; echo "=== Routing tables ==="; ip route show table all 2>/dev/null
}' > "$FDIR/arp_routes.txt"

# --- Full firewall dump ---
timeout 15 bash -c '{
  echo "=== iptables-save ==="; iptables-save 2>/dev/null
  echo ""; echo "=== nft list ruleset ==="; nft list ruleset 2>/dev/null
  echo ""; echo "=== ufw status ==="; ufw status verbose 2>/dev/null
}' > "$FDIR/firewall_full.txt"

# --- SELinux/AppArmor status ---
timeout 10 bash -c '{
  echo "=== SELinux ==="; getenforce 2>/dev/null; sestatus 2>/dev/null
  echo ""; echo "=== AppArmor ==="; aa-status 2>/dev/null; apparmor_status 2>/dev/null
}' > "$FDIR/mac_status.txt"

# --- Mounted filesystems + fstab ---
timeout 10 bash -c '{
  echo "=== mount ==="; mount
  echo ""; echo "=== fstab ==="; cat /etc/fstab 2>/dev/null
  echo ""; echo "=== df ==="; df -h
}' > "$FDIR/mounts_fstab.txt"

# --- Docker/Podman containers and images ---
timeout 15 bash -c '{
  echo "=== Docker containers ==="; docker ps -a 2>/dev/null
  echo ""; echo "=== Docker images ==="; docker images 2>/dev/null
  echo ""; echo "=== Podman containers ==="; podman ps -a 2>/dev/null
  echo ""; echo "=== Podman images ==="; podman images 2>/dev/null
}' > "$FDIR/docker_podman.txt"

# --- Installed packages list ---
timeout 30 bash -c '{
  if command -v dpkg >/dev/null 2>&1; then dpkg -l; elif command -v rpm >/dev/null 2>&1; then rpm -qa | sort; fi
}' > "$FDIR/installed_packages.txt"

# --- Failed login attempts ---
timeout 15 bash -c 'lastb 2>/dev/null | head -100' > "$FDIR/failed_logins.txt"

# --- Auditd rules ---
timeout 10 bash -c '{
  echo "=== auditctl -l ==="; auditctl -l 2>/dev/null || echo "(auditd not available)"
  echo ""; echo "=== audit.rules ==="; cat /etc/audit/audit.rules 2>/dev/null; cat /etc/audit/rules.d/*.rules 2>/dev/null
}' > "$FDIR/auditd_rules.txt"

# --- Socket and named pipe files ---
timeout 30 bash -c 'find /tmp /var/tmp /dev/shm /run -type s -o -type p 2>/dev/null | head -100' > "$FDIR/sockets_pipes.txt"

# --- Log tampering evidence ---
timeout 15 bash -c '{
  echo "=== Zero-length logs ==="; find /var/log -maxdepth 2 -type f -empty -ls 2>/dev/null
  echo ""; echo "=== Log file sizes ==="; ls -la /var/log/*.log /var/log/auth.log /var/log/syslog /var/log/secure 2>/dev/null
  echo ""; echo "=== Last log write times ==="; stat /var/log/auth.log /var/log/syslog /var/log/secure 2>/dev/null
}' > "$FDIR/log_tampering.txt"

# --- Kernel taint flags ---
timeout 5 bash -c '{
  echo "=== Kernel taint ==="; cat /proc/sys/kernel/tainted 2>/dev/null
  echo ""; echo "=== dmesg (last 50) ==="; dmesg 2>/dev/null | tail -50
}' > "$FDIR/kernel_taint.txt"

# --- /dev/shm deep listing ---
timeout 15 bash -c 'find /dev/shm -ls 2>/dev/null' > "$FDIR/dev_shm_deep.txt"

# --- /tmp deep listing with hidden files ---
timeout 15 bash -c 'find /tmp -ls 2>/dev/null | head -300' > "$FDIR/tmp_deep.txt"

# --- Environment variables ---
timeout 10 bash -c '{
  echo "=== /etc/environment ==="; cat /etc/environment 2>/dev/null
  echo ""; echo "=== Current env ==="; env | sort
}' > "$FDIR/environment.txt"

echo "Comprehensive collection complete"
`;

  let script = base.replace('__LEVEL__', level);
  script += quickSteps;
  if (level !== 'quick') script += standardSteps;
  if (level === 'advanced' || level === 'comprehensive') script += advancedSteps;
  if (level === 'comprehensive') script += comprehensiveSteps;

  // Create tarball
  script += `
cd /tmp && tar czf "$FDIR/forensics_${level}_$HOST_$TS.tar.gz" -C /tmp forensics/ 2>/dev/null
echo "FORENSICS_DONE: $FDIR"
`;

  return script;
}

function buildAnalysisScript() {
  return `
echo "=== FORENSIC ANALYSIS ==="
echo ""

echo "[CATEGORY:rootkit_indicators]"
echo "[SEVERITY:critical]"
# Check for hidden processes
HIDDEN=$(ps aux | awk '{print $2}' | sort -n | uniq -d)
if [ -n "$HIDDEN" ]; then echo "[FINDING] Duplicate PIDs detected: $HIDDEN"; fi
# Check for rootkit files
for f in /usr/bin/.sshd /tmp/.ice-unix/.x /dev/shm/.x; do
  [ -e "$f" ] && echo "[FINDING] Suspicious file: $f"
done
# Check /proc for hidden
ls /proc/*/exe 2>/dev/null | while read p; do
  readlink "$p" 2>/dev/null | grep -q '(deleted)' && echo "[FINDING] Deleted binary running: $p"
done
echo ""

echo "[CATEGORY:persistence_mechanisms]"
echo "[SEVERITY:high]"
# Cron
crontab -l 2>/dev/null | grep -v "^#" | grep -v "^$" | while read line; do echo "[FINDING] Root cron: $line"; done
ls /etc/cron.d/ 2>/dev/null | while read f; do echo "[FINDING] Cron.d entry: $f"; done
# Systemd
find /etc/systemd/system/ -name "*.service" -newer /etc/hostname 2>/dev/null | while read f; do echo "[FINDING] New systemd service: $f"; done
# Init
ls /etc/init.d/ 2>/dev/null | while read f; do echo "[FINDING] Init script: $f"; done
echo ""

echo "[CATEGORY:suspicious_users]"
echo "[SEVERITY:high]"
# UID 0 users
awk -F: '$3==0{print $1}' /etc/passwd | while read u; do
  [ "$u" != "root" ] && echo "[FINDING] Non-root UID 0 user: $u"
done
# Users with shells
awk -F: '$7 !~ /(nologin|false)/ {print $1":"$3":"$7}' /etc/passwd | while read u; do echo "[FINDING] User with shell: $u"; done
# Empty passwords
awk -F: '($2==""){print $1}' /etc/shadow 2>/dev/null | while read u; do echo "[FINDING] Empty password: $u"; done
echo ""

echo "[CATEGORY:network_anomalies]"
echo "[SEVERITY:high]"
ss -tlnp 2>/dev/null | tail -n+2 | while read line; do echo "[FINDING] Listening: $line"; done
ss -tnp state established 2>/dev/null | tail -n+2 | while read line; do echo "[FINDING] Established: $line"; done
echo ""

echo "[CATEGORY:suspicious_processes]"
echo "[SEVERITY:medium]"
ps aux --sort=-%cpu | head -20 | tail -n+2 | while read line; do echo "[FINDING] Top CPU: $line"; done
ps aux | grep -E '(nc |ncat |socat |/tmp/|/dev/shm/)' | grep -v grep | while read line; do echo "[FINDING] Suspicious proc: $line"; done
echo ""

echo "[CATEGORY:suid_binaries]"
echo "[SEVERITY:medium]"
find / -perm -4000 -type f 2>/dev/null | head -30 | while read f; do echo "[FINDING] SUID: $f"; done
echo ""

echo "[CATEGORY:ssh_config]"
echo "[SEVERITY:medium]"
cat /root/.ssh/authorized_keys 2>/dev/null | while read key; do echo "[FINDING] Root SSH key: $key"; done
ls -la /home/*/.ssh/authorized_keys 2>/dev/null | while read f; do echo "[FINDING] SSH authorized_keys: $f"; done
echo ""

echo "[CATEGORY:file_integrity]"
echo "[SEVERITY:medium]"
find /usr/bin /usr/sbin /bin /sbin -newer /etc/hostname -type f 2>/dev/null | head -20 | while read f; do echo "[FINDING] Modified binary: $f"; done
echo ""

echo "[CATEGORY:kernel_modules]"
echo "[SEVERITY:medium]"
lsmod 2>/dev/null | tail -n+2 | while read line; do echo "[FINDING] Module: $line"; done
echo ""

echo "[CATEGORY:scheduled_tasks]"
echo "[SEVERITY:medium]"
for user in $(cut -d: -f1 /etc/passwd); do
  crontab -u "$user" -l 2>/dev/null | grep -v "^#" | grep -v "^$" | while read line; do echo "[FINDING] Cron ($user): $line"; done
done
echo ""

echo "[CATEGORY:log_analysis]"
echo "[SEVERITY:low]"
grep -i "failed\|error\|denied" /var/log/auth.log 2>/dev/null | tail -10 | while read line; do echo "[FINDING] Auth log: $line"; done
echo ""

echo "[CATEGORY:open_files]"
echo "[SEVERITY:low]"
lsof -i -n -P 2>/dev/null | grep LISTEN | head -20 | while read line; do echo "[FINDING] Open listen: $line"; done
echo ""

echo "[CATEGORY:environment]"
echo "[SEVERITY:info]"
echo "[FINDING] Hostname: $(hostname)"
echo "[FINDING] Kernel: $(uname -r)"
echo "[FINDING] Uptime: $(uptime)"
echo "[FINDING] Date: $(date -Iseconds)"
echo ""

echo "[CATEGORY:docker_containers]"
echo "[SEVERITY:info]"
docker ps -a 2>/dev/null | while read line; do echo "[FINDING] Container: $line"; done
echo ""

echo "[CATEGORY:mounts]"
echo "[SEVERITY:info]"
mount | while read line; do echo "[FINDING] Mount: $line"; done
echo ""

echo "[CATEGORY:dns_config]"
echo "[SEVERITY:info]"
cat /etc/resolv.conf 2>/dev/null | while read line; do echo "[FINDING] DNS: $line"; done
cat /etc/hosts 2>/dev/null | grep -v "^#" | grep -v "^$" | while read line; do echo "[FINDING] Host entry: $line"; done
echo ""

echo "=== ANALYSIS COMPLETE ==="
`;
}

function buildTargetedAnalysisScript(types, tarball) {
  const sections = [];
  if (types.includes('rootkit')) {
    sections.push(`echo "[CATEGORY:rootkit_indicators]"; echo "[SEVERITY:critical]"; for f in /usr/bin/.sshd /tmp/.ice-unix/.x /dev/shm/.x; do [ -e "$f" ] && echo "[FINDING] Suspicious file: $f"; done; ls /proc/*/exe 2>/dev/null | while read p; do readlink "$p" 2>/dev/null | grep -q '(deleted)' && echo "[FINDING] Deleted binary: $p"; done`);
  }
  if (types.includes('persistence')) {
    sections.push(`echo "[CATEGORY:persistence_mechanisms]"; echo "[SEVERITY:high]"; crontab -l 2>/dev/null | grep -v "^#" | grep -v "^$" | while read line; do echo "[FINDING] Root cron: $line"; done; find /etc/systemd/system/ -name "*.service" -newer /etc/hostname 2>/dev/null | while read f; do echo "[FINDING] New service: $f"; done`);
  }
  if (types.includes('network')) {
    sections.push(`echo "[CATEGORY:network_anomalies]"; echo "[SEVERITY:high]"; ss -tlnp 2>/dev/null | tail -n+2 | while read line; do echo "[FINDING] Listening: $line"; done; ss -tnp state established 2>/dev/null | tail -n+2 | while read line; do echo "[FINDING] Established: $line"; done`);
  }
  if (types.includes('users')) {
    sections.push(`echo "[CATEGORY:suspicious_users]"; echo "[SEVERITY:high]"; awk -F: '$3==0{print $1}' /etc/passwd | while read u; do [ "$u" != "root" ] && echo "[FINDING] UID 0: $u"; done; awk -F: '($2==""){print $1}' /etc/shadow 2>/dev/null | while read u; do echo "[FINDING] Empty password: $u"; done`);
  }
  if (types.includes('processes')) {
    sections.push(`echo "[CATEGORY:suspicious_processes]"; echo "[SEVERITY:medium]"; ps aux | grep -E '(nc |ncat |socat |/tmp/|/dev/shm/)' | grep -v grep | while read line; do echo "[FINDING] Suspicious: $line"; done`);
  }
  return sections.join('\necho ""\n');
}

function parseAnalysisOutput(output) {
  if (typeof output !== 'string') return [];
  const findings = [];
  let currentCategory = 'unknown';
  let currentSeverity = 'info';

  for (const line of output.split('\n')) {
    const catMatch = line.match(/\[CATEGORY:(\w+)\]/);
    if (catMatch) { currentCategory = catMatch[1]; continue; }

    const sevMatch = line.match(/\[SEVERITY:(\w+)\]/);
    if (sevMatch) { currentSeverity = sevMatch[1]; continue; }

    const findMatch = line.match(/\[FINDING\]\s*(.*)/);
    if (findMatch) {
      findings.push({
        category: currentCategory,
        severity: currentSeverity,
        message: findMatch[1],
        timestamp: new Date().toISOString()
      });
    }
  }
  return findings;
}

module.exports = router;
