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
    const result = await saltClient.cmd('*', 'ls -la /tmp/forensics/ 2>/dev/null || echo "No collections"', { shell: '/bin/bash', timeout: 30 });
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
# Comprehensive extras
${opts.skip_logs ? '' : 'cp /var/log/auth.log "$FDIR/auth.log" 2>/dev/null; cp /var/log/syslog "$FDIR/syslog.log" 2>/dev/null; cp /var/log/secure "$FDIR/secure.log" 2>/dev/null'}
${opts.memory_dump ? 'cat /proc/meminfo > "$FDIR/meminfo.txt" 2>/dev/null; cat /proc/slabinfo > "$FDIR/slabinfo.txt" 2>/dev/null' : ''}
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
