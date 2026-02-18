/**
 * Windows Forensics Routes
 *
 * Provides forensic collection, artifact browsing, analysis, and scanning
 * endpoints for Windows minions using PowerShell scripts.
 *
 * Artifacts are stored as ZIP files at C:\Windows\Temp\forensics\ on each minion.
 *
 * @module routes/forensics-windows
 */

const express = require('express');
const router = express.Router();
const { client: saltClient } = require('../lib/salt-client');
const logger = require('../lib/logger');
const { requireAuth } = require('../middleware/auth');
const { auditAction } = require('../middleware/audit');

router.use(requireAuth);

// In-memory job tracking (same pattern as Linux forensics)
const winForensicJobs = new Map();

function generateJobId() {
  return 'w' + Date.now().toString(36) + Math.random().toString(36).substr(2, 6);
}

// ============================================================
// Collection Endpoints
// ============================================================

/**
 * POST /api/forensics-windows/collect
 * Start artifact collection on Windows targets
 */
router.post('/collect', auditAction('forensics_windows.collect'), async (req, res) => {
  const { targets, level = 'standard', timeout: reqTimeout } = req.body;

  if (!targets) {
    return res.status(400).json({ success: false, error: 'Targets required' });
  }

  const validLevels = ['quick', 'standard', 'advanced'];
  if (!validLevels.includes(level)) {
    return res.status(400).json({ success: false, error: `Invalid level. Must be one of: ${validLevels.join(', ')}` });
  }

  const timeoutMap = { quick: 60, standard: 180, advanced: 360 };
  const timeout = reqTimeout || timeoutMap[level] || 180;

  const jobId = generateJobId();
  winForensicJobs.set(jobId, {
    id: jobId,
    status: 'running',
    level,
    targets,
    created: new Date().toISOString(),
    results: null
  });

  // Run async
  (async () => {
    try {
      const script = buildWinCollectScript(level);
      const result = await saltClient.scriptContent(targets, script, {
        shell: 'powershell',
        timeout
      });
      winForensicJobs.set(jobId, {
        ...winForensicJobs.get(jobId),
        status: 'completed',
        results: result
      });
      logger.info(`Windows forensics collection job ${jobId} completed (level: ${level})`);
    } catch (error) {
      winForensicJobs.set(jobId, {
        ...winForensicJobs.get(jobId),
        status: 'failed',
        error: error.message
      });
      logger.error(`Windows forensics collection job ${jobId} failed: ${error.message}`);
    }
  })();

  res.json({ success: true, job_id: jobId, message: `Windows ${level} collection started` });
});

/**
 * GET /api/forensics-windows/jobs
 * List all Windows forensic jobs
 */
router.get('/jobs', async (req, res) => {
  const jobs = Array.from(winForensicJobs.values()).sort((a, b) =>
    new Date(b.created) - new Date(a.created)
  );
  res.json({ success: true, jobs });
});

/**
 * GET /api/forensics-windows/jobs/:jobId
 * Get job status/results
 */
router.get('/jobs/:jobId', async (req, res) => {
  const job = winForensicJobs.get(req.params.jobId);
  if (!job) {
    return res.status(404).json({ success: false, error: 'Job not found' });
  }
  res.json({ success: true, job });
});

// ============================================================
// Browse Endpoints (ZIP-based)
// ============================================================

/**
 * GET /api/forensics-windows/collections
 * List all forensic ZIP collections across Windows targets
 */
router.get('/collections', async (req, res) => {
  try {
    const target = req.query.target || 'G@kernel:Windows';
    const tgt_type = req.query.target ? 'glob' : 'compound';
    const psCmd = `$d='C:\\Windows\\Temp\\forensics'; if(Test-Path $d){Get-ChildItem $d -Filter '*.zip' | Sort-Object LastWriteTime -Descending | ForEach-Object { $_.Name }}else{''}`;
    const result = await saltClient.run({
      client: 'local',
      fun: 'cmd.run',
      tgt: target,
      tgt_type,
      kwarg: { cmd: psCmd, shell: 'powershell', timeout: 30 }
    });
    res.json({ success: true, collections: result });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

/**
 * POST /api/forensics-windows/browse
 * List contents of a ZIP artifact on a Windows minion
 */
router.post('/browse', async (req, res) => {
  const { target, zip_path } = req.body;
  if (!target || !zip_path) {
    return res.status(400).json({ success: false, error: 'Target and zip_path required' });
  }

  // Validate path stays within forensics dir
  if (!zip_path.match(/^C:\\Windows\\Temp\\forensics\\[a-zA-Z0-9_.-]+\.zip$/i)) {
    return res.status(400).json({ success: false, error: 'Invalid ZIP path' });
  }

  try {
    const psCmd = `
$ErrorActionPreference='SilentlyContinue'
Add-Type -AssemblyName System.IO.Compression.FileSystem
$zip=[System.IO.Compression.ZipFile]::OpenRead('${zip_path.replace(/'/g, "''")}')
$zip.Entries | ForEach-Object { $_.FullName }
$zip.Dispose()
`;
    const result = await saltClient.scriptContent(target, psCmd, { shell: 'powershell', timeout: 30 });
    const files = {};
    for (const [minion, output] of Object.entries(result)) {
      files[minion] = typeof output === 'string'
        ? output.split('\n').map(f => f.trim()).filter(f => f)
        : [];
    }
    res.json({ success: true, files });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

/**
 * POST /api/forensics-windows/browse/file
 * Read a specific file from a ZIP artifact
 */
router.post('/browse/file', async (req, res) => {
  const { target, zip_path, file_path } = req.body;
  if (!target || !zip_path || !file_path) {
    return res.status(400).json({ success: false, error: 'Target, zip_path, and file_path required' });
  }

  if (!zip_path.match(/^C:\\Windows\\Temp\\forensics\\[a-zA-Z0-9_.-]+\.zip$/i)) {
    return res.status(400).json({ success: false, error: 'Invalid ZIP path' });
  }

  try {
    // Escape single quotes in file_path for PowerShell
    const safeFilePath = file_path.replace(/'/g, "''");
    const psCmd = `
$ErrorActionPreference='SilentlyContinue'
Add-Type -AssemblyName System.IO.Compression.FileSystem
$zip=[System.IO.Compression.ZipFile]::OpenRead('${zip_path.replace(/'/g, "''")}')
$entry=$zip.Entries | Where-Object { $_.FullName -eq '${safeFilePath}' } | Select-Object -First 1
if($entry){
  $sr=New-Object System.IO.StreamReader($entry.Open())
  $lines=$sr.ReadToEnd() -split '\\n' | Select-Object -First 2000
  $sr.Close()
  $lines -join '\\n'
}else{
  'File not found in archive'
}
$zip.Dispose()
`;
    const result = await saltClient.scriptContent(target, psCmd, { shell: 'powershell', timeout: 30 });
    res.json({ success: true, content: result });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// ============================================================
// Analysis & Scan Endpoints
// ============================================================

/**
 * POST /api/forensics-windows/analyze
 * Run live analysis on a Windows target (examines collected artifacts)
 */
router.post('/analyze', auditAction('forensics_windows.analyze'), async (req, res) => {
  const { target, timeout = 180 } = req.body;
  if (!target) {
    return res.status(400).json({ success: false, error: 'Target required' });
  }

  try {
    const script = buildWinAnalysisScript();
    const result = await saltClient.scriptContent(target, script, {
      shell: 'powershell',
      timeout
    });

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
 * POST /api/forensics-windows/scan
 * Quick security scan without full collection
 */
router.post('/scan', auditAction('forensics_windows.scan'), async (req, res) => {
  const { targets, timeout = 120 } = req.body;
  if (!targets) {
    return res.status(400).json({ success: false, error: 'Targets required' });
  }

  const jobId = generateJobId();
  winForensicJobs.set(jobId, {
    id: jobId,
    status: 'running',
    type: 'scan',
    targets,
    created: new Date().toISOString(),
    results: null
  });

  (async () => {
    try {
      const script = buildWinQuickScanScript();
      const result = await saltClient.scriptContent(targets, script, {
        shell: 'powershell',
        timeout
      });

      const findings = {};
      for (const [minion, output] of Object.entries(result)) {
        findings[minion] = parseAnalysisOutput(output);
      }

      winForensicJobs.set(jobId, {
        ...winForensicJobs.get(jobId),
        status: 'completed',
        results: result,
        findings
      });
      logger.info(`Windows forensics scan job ${jobId} completed`);
    } catch (error) {
      winForensicJobs.set(jobId, {
        ...winForensicJobs.get(jobId),
        status: 'failed',
        error: error.message
      });
      logger.error(`Windows forensics scan job ${jobId} failed: ${error.message}`);
    }
  })();

  res.json({ success: true, job_id: jobId, message: 'Windows security scan started' });
});

/**
 * POST /api/forensics-windows/cleanup
 * Clean up old forensic artifacts on Windows targets
 */
router.post('/cleanup', auditAction('forensics_windows.cleanup'), async (req, res) => {
  const { targets = '*', age_hours = 24 } = req.body;
  try {
    const psCmd = `$d='C:\\Windows\\Temp\\forensics'; if(Test-Path $d){Get-ChildItem $d -File | Where-Object { $_.LastWriteTime -lt (Get-Date).AddHours(-${age_hours}) } | Remove-Item -Force; 'Cleanup complete'}else{'No forensics directory'}`;
    const result = await saltClient.cmd(targets, psCmd, { shell: 'powershell', timeout: 60 });
    res.json({ success: true, result });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// ============================================================
// Helper: Parse Analysis Output
// ============================================================

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

// ============================================================
// PowerShell Collection Scripts
// ============================================================

function buildWinCollectScript(level) {
  // Base collection that all levels include
  const base = `
$ErrorActionPreference='SilentlyContinue'
$ts=Get-Date -Format 'yyyyMMdd_HHmmss'
$hostname=$env:COMPUTERNAME
$baseDir="C:\\Windows\\Temp\\forensics"
$collectDir="$baseDir\\collect_$ts"
New-Item -ItemType Directory -Force -Path $collectDir | Out-Null
New-Item -ItemType Directory -Force -Path "$collectDir\\processes" | Out-Null
New-Item -ItemType Directory -Force -Path "$collectDir\\network" | Out-Null
New-Item -ItemType Directory -Force -Path "$collectDir\\users" | Out-Null
New-Item -ItemType Directory -Force -Path "$collectDir\\persistence" | Out-Null
New-Item -ItemType Directory -Force -Path "$collectDir\\system" | Out-Null

# Metadata
@{
  collected_at=(Get-Date -Format 'o')
  hostname=$hostname
  level='${level}'
  os=(Get-CimInstance Win32_OperatingSystem).Caption
  os_version=(Get-CimInstance Win32_OperatingSystem).Version
  domain=(Get-CimInstance Win32_ComputerSystem).Domain
  is_dc=((Get-CimInstance Win32_OperatingSystem).ProductType -eq 2)
} | ConvertTo-Json | Out-File "$collectDir\\metadata.json" -Encoding UTF8

Write-Output "[STATUS] Collecting process information..."
# Running processes
Get-Process | Select-Object Id,ProcessName,Path,StartTime,CPU,WorkingSet64,Company,Description |
  ConvertTo-Csv -NoTypeInformation | Out-File "$collectDir\\processes\\running_processes.csv" -Encoding UTF8

# Process command lines
Get-CimInstance Win32_Process | Select-Object ProcessId,Name,CommandLine,ExecutablePath,ParentProcessId,CreationDate |
  ConvertTo-Csv -NoTypeInformation | Out-File "$collectDir\\processes\\process_cmdlines.csv" -Encoding UTF8

Write-Output "[STATUS] Collecting network information..."
# Network connections
Get-NetTCPConnection | Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,State,OwningProcess,CreationTime |
  ConvertTo-Csv -NoTypeInformation | Out-File "$collectDir\\network\\tcp_connections.csv" -Encoding UTF8
Get-NetUDPEndpoint | Select-Object LocalAddress,LocalPort,OwningProcess,CreationTime |
  ConvertTo-Csv -NoTypeInformation | Out-File "$collectDir\\network\\udp_endpoints.csv" -Encoding UTF8

# Logged-in users
query user 2>$null | Out-File "$collectDir\\users\\logged_in_users.txt" -Encoding UTF8

Write-Output "[STATUS] Collecting persistence mechanisms..."
# Scheduled tasks summary
Get-ScheduledTask | Where-Object { $_.State -ne 'Disabled' } |
  Select-Object TaskName,TaskPath,State,@{N='Actions';E={($_.Actions | ForEach-Object { $_.Execute + ' ' + $_.Arguments }) -join '; '}} |
  ConvertTo-Csv -NoTypeInformation | Out-File "$collectDir\\persistence\\scheduled_tasks.csv" -Encoding UTF8

# Autorun registry keys
$autorunKeys = @(
  'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run',
  'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce',
  'HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run',
  'HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce'
)
$autoruns = foreach($key in $autorunKeys) {
  if(Test-Path $key) {
    $props = Get-ItemProperty $key
    $props.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object {
      [PSCustomObject]@{ Key=$key; Name=$_.Name; Value=$_.Value }
    }
  }
}
$autoruns | ConvertTo-Csv -NoTypeInformation | Out-File "$collectDir\\persistence\\autorun_registry.csv" -Encoding UTF8

# Active services
Get-Service | Select-Object Name,DisplayName,Status,StartType |
  ConvertTo-Csv -NoTypeInformation | Out-File "$collectDir\\system\\services.csv" -Encoding UTF8

Write-Output "[STATUS] Collecting event log entries..."
# Recent Security events (last 100)
Get-WinEvent -LogName Security -MaxEvents 100 2>$null |
  Select-Object TimeCreated,Id,LevelDisplayName,Message |
  ConvertTo-Csv -NoTypeInformation | Out-File "$collectDir\\system\\eventlog_security_recent.csv" -Encoding UTF8
# Recent System events (last 100)
Get-WinEvent -LogName System -MaxEvents 100 2>$null |
  Select-Object TimeCreated,Id,LevelDisplayName,Message |
  ConvertTo-Csv -NoTypeInformation | Out-File "$collectDir\\system\\eventlog_system_recent.csv" -Encoding UTF8
`;

  const standard = `
Write-Output "[STATUS] Collecting detailed scheduled tasks..."
# Detailed scheduled task info
Get-ScheduledTask | ForEach-Object {
  $info = Get-ScheduledTaskInfo $_.TaskName -ErrorAction SilentlyContinue
  [PSCustomObject]@{
    TaskName=$_.TaskName; TaskPath=$_.TaskPath; State=$_.State
    Actions=($_.Actions | ForEach-Object { $_.Execute + ' ' + $_.Arguments }) -join '; '
    Triggers=($_.Triggers | ForEach-Object { $_.ToString() }) -join '; '
    LastRunTime=$info.LastRunTime; NextRunTime=$info.NextRunTime
    Author=$_.Author; Principal=$_.Principal.UserId
  }
} | ConvertTo-Csv -NoTypeInformation | Out-File "$collectDir\\persistence\\scheduled_tasks_detail.csv" -Encoding UTF8

Write-Output "[STATUS] Checking WMI subscriptions..."
# WMI event subscriptions (common persistence)
Get-WmiObject -Namespace root\\subscription -Class __EventConsumer 2>$null |
  Select-Object __CLASS,Name,CommandLineTemplate,ScriptText |
  ConvertTo-Csv -NoTypeInformation | Out-File "$collectDir\\persistence\\wmi_consumers.csv" -Encoding UTF8
Get-WmiObject -Namespace root\\subscription -Class __EventFilter 2>$null |
  Select-Object Name,Query,QueryLanguage |
  ConvertTo-Csv -NoTypeInformation | Out-File "$collectDir\\persistence\\wmi_filters.csv" -Encoding UTF8

Write-Output "[STATUS] Collecting PowerShell history..."
# PowerShell history (all users)
$profiles = Get-ChildItem 'C:\\Users' -Directory -ErrorAction SilentlyContinue
foreach($profile in $profiles) {
  $histPath = Join-Path $profile.FullName 'AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt'
  if(Test-Path $histPath) {
    $content = Get-Content $histPath -Tail 200 -ErrorAction SilentlyContinue
    if($content) {
      "=== $($profile.Name) ===" | Out-File "$collectDir\\persistence\\powershell_history.txt" -Append -Encoding UTF8
      $content | Out-File "$collectDir\\persistence\\powershell_history.txt" -Append -Encoding UTF8
    }
  }
}

Write-Output "[STATUS] Collecting installed software..."
# Installed software
Get-ItemProperty HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*,
  HKLM:\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* 2>$null |
  Where-Object { $_.DisplayName } |
  Select-Object DisplayName,DisplayVersion,Publisher,InstallDate |
  Sort-Object DisplayName |
  ConvertTo-Csv -NoTypeInformation | Out-File "$collectDir\\system\\installed_software.csv" -Encoding UTF8

# Local users and groups
Get-LocalUser | Select-Object Name,Enabled,LastLogon,PasswordLastSet,Description |
  ConvertTo-Csv -NoTypeInformation | Out-File "$collectDir\\users\\local_users.csv" -Encoding UTF8
Get-LocalGroup | ForEach-Object {
  $members = Get-LocalGroupMember $_.Name -ErrorAction SilentlyContinue
  [PSCustomObject]@{ Group=$_.Name; Members=($members.Name -join ', ') }
} | ConvertTo-Csv -NoTypeInformation | Out-File "$collectDir\\users\\local_groups.csv" -Encoding UTF8

Write-Output "[STATUS] Collecting firewall rules..."
# Firewall rules (enabled only)
Get-NetFirewallRule -Enabled True 2>$null |
  Select-Object DisplayName,Direction,Action,Profile |
  ConvertTo-Csv -NoTypeInformation | Out-File "$collectDir\\network\\firewall_rules.csv" -Encoding UTF8

# DNS cache
Get-DnsClientCache 2>$null |
  Select-Object Entry,RecordName,RecordType,Data,TimeToLive |
  ConvertTo-Csv -NoTypeInformation | Out-File "$collectDir\\network\\dns_cache.csv" -Encoding UTF8

Write-Output "[STATUS] Checking recent file modifications..."
# Recent file modifications in key directories
$searchDirs = @('C:\\Windows\\System32', 'C:\\Windows\\Temp', 'C:\\Users')
$cutoff = (Get-Date).AddDays(-7)
foreach($dir in $searchDirs) {
  if(Test-Path $dir) {
    Get-ChildItem $dir -Recurse -File -ErrorAction SilentlyContinue |
      Where-Object { $_.LastWriteTime -gt $cutoff } |
      Select-Object -First 200 FullName,LastWriteTime,Length,Extension |
      ConvertTo-Csv -NoTypeInformation | Out-File "$collectDir\\system\\recent_files_$($dir.Replace('\\','_').Replace(':','')).csv" -Append -Encoding UTF8
  }
}

# Prefetch files listing
if(Test-Path 'C:\\Windows\\Prefetch') {
  Get-ChildItem 'C:\\Windows\\Prefetch' -Filter '*.pf' |
    Select-Object Name,LastWriteTime,Length |
    Sort-Object LastWriteTime -Descending |
    ConvertTo-Csv -NoTypeInformation | Out-File "$collectDir\\system\\prefetch.csv" -Encoding UTF8
}

# Alternate Data Streams on common paths
$adsResults = @()
foreach($dir in @('C:\\Users','C:\\Windows\\Temp')) {
  if(Test-Path $dir) {
    Get-ChildItem $dir -Recurse -File -ErrorAction SilentlyContinue |
      Select-Object -First 500 |
      ForEach-Object {
        $streams = Get-Item $_.FullName -Stream * -ErrorAction SilentlyContinue |
          Where-Object { $_.Stream -ne ':$DATA' -and $_.Stream -ne 'Zone.Identifier' }
        foreach($s in $streams) {
          $adsResults += [PSCustomObject]@{ File=$_.FullName; Stream=$s.Stream; Length=$s.Length }
        }
      }
  }
}
if($adsResults.Count -gt 0) {
  $adsResults | ConvertTo-Csv -NoTypeInformation | Out-File "$collectDir\\persistence\\alternate_data_streams.csv" -Encoding UTF8
}
`;

  const advanced = `
Write-Output "[STATUS] Exporting full event logs..."
# Full event log exports (last 1000 entries each)
foreach($logName in @('Security','System','Microsoft-Windows-PowerShell/Operational')) {
  $safeName = $logName -replace '[/\\\\]','_'
  Get-WinEvent -LogName $logName -MaxEvents 1000 2>$null |
    Select-Object TimeCreated,Id,LevelDisplayName,ProviderName,Message |
    ConvertTo-Csv -NoTypeInformation | Out-File "$collectDir\\system\\eventlog_\${safeName}_full.csv" -Encoding UTF8
}

Write-Output "[STATUS] Collecting registry persistence locations..."
# Extended registry persistence locations
New-Item -ItemType Directory -Force -Path "$collectDir\\persistence\\registry" | Out-Null
$persistKeys = @(
  'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run',
  'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce',
  'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunServices',
  'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunServicesOnce',
  'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon',
  'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows',
  'HKLM:\\SYSTEM\\CurrentControlSet\\Services',
  'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options',
  'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\SharedTaskScheduler',
  'HKLM:\\SOFTWARE\\Classes\\CLSID',
  'HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run',
  'HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce'
)
foreach($key in $persistKeys) {
  $safeName = ($key -replace '[:\\\\]','_') -replace '^_+',''
  if(Test-Path $key) {
    $shortName = $safeName.Substring([Math]::Max(0,$safeName.Length-80))
    Get-ItemProperty $key -ErrorAction SilentlyContinue |
      Out-File "$collectDir\\persistence\\registry\\$shortName.txt" -Encoding UTF8
  }
}

Write-Output "[STATUS] Collecting certificate store info..."
# Certificate store
Get-ChildItem Cert:\\LocalMachine\\Root |
  Select-Object Subject,Issuer,NotBefore,NotAfter,Thumbprint |
  ConvertTo-Csv -NoTypeInformation | Out-File "$collectDir\\system\\certificates_root.csv" -Encoding UTF8

Write-Output "[STATUS] Collecting driver list..."
# Drivers
Get-WindowsDriver -Online -All 2>$null |
  Select-Object OriginalFileName,ProviderName,Date,Version,ClassName |
  ConvertTo-Csv -NoTypeInformation | Out-File "$collectDir\\system\\drivers.csv" -Encoding UTF8
# Fallback if Get-WindowsDriver is not available
if(-not (Test-Path "$collectDir\\system\\drivers.csv") -or (Get-Item "$collectDir\\system\\drivers.csv").Length -lt 100) {
  driverquery /v /fo csv 2>$null | Out-File "$collectDir\\system\\drivers.csv" -Encoding UTF8
}

Write-Output "[STATUS] Collecting named pipes..."
# Named pipes
Get-ChildItem \\\\.\\pipe\\ -ErrorAction SilentlyContinue |
  Select-Object Name | Out-File "$collectDir\\system\\named_pipes.txt" -Encoding UTF8

Write-Output "[STATUS] Checking COM object hijacks..."
# COM object hijack checks (known hijack CLSIDs)
$suspectCLSIDs = @(
  '{b5f8350b-0548-48b1-a6ee-88bd00b4a5e7}',  # CLSID_TaskScheduler
  '{BCDE0395-E52F-467C-8E3D-C4579291692E}',  # MMDeviceEnumerator
  '{C08AFD90-F2A1-11D1-8455-00A0C91F3880}'   # ShellBrowserWindow
)
$comResults = @()
foreach($clsid in $suspectCLSIDs) {
  $regPath = "HKCU:\\SOFTWARE\\Classes\\CLSID\\$clsid\\InProcServer32"
  if(Test-Path $regPath) {
    $val = (Get-ItemProperty $regPath -ErrorAction SilentlyContinue).'(default)'
    $comResults += [PSCustomObject]@{ CLSID=$clsid; Path=$val; Source='HKCU' }
  }
}
if($comResults.Count -gt 0) {
  $comResults | ConvertTo-Csv -NoTypeInformation | Out-File "$collectDir\\persistence\\com_hijacks.csv" -Encoding UTF8
}

Write-Output "[STATUS] Checking Active Directory (if DC)..."
# AD-specific checks (if this is a DC)
$isDC = (Get-CimInstance Win32_OperatingSystem).ProductType -eq 2
if($isDC) {
  New-Item -ItemType Directory -Force -Path "$collectDir\\ad" | Out-Null
  try {
    Import-Module ActiveDirectory -ErrorAction Stop
    # KRBTGT info
    Get-ADUser krbtgt -Properties PasswordLastSet,Created |
      Select-Object Name,PasswordLastSet,Created |
      ConvertTo-Csv -NoTypeInformation | Out-File "$collectDir\\ad\\krbtgt_info.csv" -Encoding UTF8
    # AdminSDHolder protected accounts
    Get-ADObject -Filter {AdminCount -eq 1} -Properties Name,ObjectClass,WhenChanged |
      Select-Object Name,ObjectClass,WhenChanged |
      ConvertTo-Csv -NoTypeInformation | Out-File "$collectDir\\ad\\adminsdholder.csv" -Encoding UTF8
    # GPO list
    Get-GPO -All 2>$null |
      Select-Object DisplayName,GpoStatus,CreationTime,ModificationTime |
      ConvertTo-Csv -NoTypeInformation | Out-File "$collectDir\\ad\\gpo_list.csv" -Encoding UTF8
    # DC replication partners
    Get-ADReplicationPartnerMetadata -Target $hostname -ErrorAction SilentlyContinue |
      Select-Object Partner,LastReplicationSuccess,ConsecutiveReplicationFailures |
      ConvertTo-Csv -NoTypeInformation | Out-File "$collectDir\\ad\\replication.csv" -Encoding UTF8
  } catch {
    "AD module not available: $_" | Out-File "$collectDir\\ad\\ad_error.txt" -Encoding UTF8
  }
}
`;

  // Package into ZIP
  const packageScript = `
Write-Output "[STATUS] Packaging collection into ZIP..."
$zipName = ("forensics_{0}_{1}.zip" -f $hostname, $ts)
$zipPath = "$baseDir\\$zipName"
if(Test-Path $zipPath) { Remove-Item $zipPath -Force }
Add-Type -AssemblyName System.IO.Compression.FileSystem
[System.IO.Compression.ZipFile]::CreateFromDirectory($collectDir, $zipPath, 'Fastest', $false)
Remove-Item $collectDir -Recurse -Force -ErrorAction SilentlyContinue
Write-Output "[ZIP] $zipPath"
Write-Output "WIN_FORENSICS_DONE:$zipPath"
`;

  let script = base;
  if (level === 'standard' || level === 'advanced') {
    script += standard;
  }
  if (level === 'advanced') {
    script += advanced;
  }
  script += packageScript;

  return script;
}

// ============================================================
// Analysis Script
// ============================================================

function buildWinAnalysisScript() {
  return `
$ErrorActionPreference='SilentlyContinue'

# ===== PROCESSES =====
Write-Output "[CATEGORY:processes]"

# Check for encoded commands
Write-Output "[SEVERITY:high]"
$encodedProcs = Get-CimInstance Win32_Process | Where-Object {
  $_.CommandLine -match '-[Ee]nc[o]?[d]?[e]?[d]?[Cc]?[o]?[m]?[m]?[a]?[n]?[d]?\\s' -or
  $_.CommandLine -match '-[Ee][Cc]\\s' -or
  $_.CommandLine -match 'FromBase64String'
}
foreach($p in $encodedProcs) {
  Write-Output "[FINDING] Encoded command detected: PID $($p.ProcessId) - $($p.Name) - $($p.CommandLine.Substring(0,[Math]::Min(200,$p.CommandLine.Length)))"
}

# Processes running from temp directories
Write-Output "[SEVERITY:high]"
$tempProcs = Get-CimInstance Win32_Process | Where-Object {
  $_.ExecutablePath -match '\\\\Temp\\\\' -or
  $_.ExecutablePath -match '\\\\tmp\\\\' -or
  $_.ExecutablePath -match '\\\\AppData\\\\Local\\\\Temp' -or
  $_.ExecutablePath -match '\\\\Downloads\\\\'
}
foreach($p in $tempProcs) {
  Write-Output "[FINDING] Process from temp/download dir: PID $($p.ProcessId) - $($p.Name) - $($p.ExecutablePath)"
}

# Processes with no path (suspicious)
Write-Output "[SEVERITY:medium]"
$noPathProcs = Get-CimInstance Win32_Process | Where-Object {
  $_.Name -ne 'System' -and $_.Name -ne 'Idle' -and $_.Name -ne 'Registry' -and
  (-not $_.ExecutablePath -or $_.ExecutablePath -eq '')
}
foreach($p in $noPathProcs) {
  if($p.ProcessId -gt 4) {
    Write-Output "[FINDING] Process with no executable path: PID $($p.ProcessId) - $($p.Name)"
  }
}

# ===== PERSISTENCE =====
Write-Output "[CATEGORY:persistence]"

# Suspicious scheduled tasks
Write-Output "[SEVERITY:high]"
$suspTasks = Get-ScheduledTask | Where-Object { $_.State -ne 'Disabled' } | ForEach-Object {
  $actions = $_.Actions | ForEach-Object { $_.Execute + ' ' + $_.Arguments }
  $actionStr = $actions -join '; '
  if($actionStr -match '\\\\Temp\\\\|\\\\tmp\\\\|\\\\Downloads\\\\|powershell.*-[Ee]nc|cmd.*/[Cc].*http|mshta|regsvr32|rundll32.*javascript|certutil.*-urlcache|bitsadmin.*/transfer') {
    [PSCustomObject]@{ Name=$_.TaskName; Path=$_.TaskPath; Actions=$actionStr; Author=$_.Author }
  }
}
foreach($t in $suspTasks) {
  Write-Output "[FINDING] Suspicious scheduled task: $($t.Name) at $($t.Path) - Actions: $($t.Actions)"
}

# WMI event subscriptions
Write-Output "[SEVERITY:critical]"
$wmiConsumers = Get-WmiObject -Namespace root\\subscription -Class __EventConsumer 2>$null
foreach($c in $wmiConsumers) {
  $detail = if($c.CommandLineTemplate) { $c.CommandLineTemplate } elseif($c.ScriptText) { "Script: $($c.ScriptText.Substring(0,[Math]::Min(100,$c.ScriptText.Length)))" } else { $c.__CLASS }
  Write-Output "[FINDING] WMI event consumer (persistence): $($c.Name) - $detail"
}

# Suspicious autorun entries
Write-Output "[SEVERITY:high]"
$autorunKeys = @(
  'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run',
  'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce',
  'HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run',
  'HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce'
)
foreach($key in $autorunKeys) {
  if(Test-Path $key) {
    $props = Get-ItemProperty $key -ErrorAction SilentlyContinue
    $props.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object {
      $val = $_.Value
      if($val -match '\\\\Temp\\\\|\\\\tmp\\\\|\\\\Downloads\\\\|powershell.*-[Ee]nc|mshta|regsvr32|cmd.*/[Cc].*http|certutil') {
        Write-Output "[FINDING] Suspicious autorun: $key\\$($_.Name) = $val"
      }
    }
  }
}

# Winlogon modifications
Write-Output "[SEVERITY:high]"
$winlogon = Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon' -ErrorAction SilentlyContinue
if($winlogon.Shell -and $winlogon.Shell -ne 'explorer.exe') {
  Write-Output "[FINDING] Winlogon Shell modified: $($winlogon.Shell)"
}
if($winlogon.Userinit -and $winlogon.Userinit -notmatch '^C:\\\\Windows\\\\system32\\\\userinit.exe,?$') {
  Write-Output "[FINDING] Winlogon Userinit modified: $($winlogon.Userinit)"
}

# Image File Execution Options (debugger hijacks)
Write-Output "[SEVERITY:critical]"
$ifeo = Get-ChildItem 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options' -ErrorAction SilentlyContinue
foreach($entry in $ifeo) {
  $debugger = (Get-ItemProperty $entry.PSPath -ErrorAction SilentlyContinue).Debugger
  if($debugger) {
    Write-Output "[FINDING] IFEO debugger hijack: $($entry.PSChildName) -> $debugger"
  }
}

# ===== NETWORK =====
Write-Output "[CATEGORY:network]"

# Listening on unusual ports
Write-Output "[SEVERITY:medium]"
$commonPorts = @(22,80,443,445,135,139,389,636,3389,5985,5986,47001,53,88,464,3268,3269,4505,4506)
$seenPorts = @{}
$listening = Get-NetTCPConnection -State Listen | Where-Object { $_.LocalPort -notin $commonPorts -and $_.LocalPort -gt 1024 }
foreach($conn in $listening) {
  $key = "$($conn.LocalPort)-$($conn.OwningProcess)"
  if(-not $seenPorts[$key]) {
    $seenPorts[$key] = $true
    $proc = Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue
    Write-Output "[FINDING] Unusual listening port: $($conn.LocalAddress):$($conn.LocalPort) - PID $($conn.OwningProcess) ($($proc.ProcessName))"
  }
}

# Established connections to unusual destinations
Write-Output "[SEVERITY:medium]"
$established = Get-NetTCPConnection -State Established | Where-Object {
  $_.RemoteAddress -ne '127.0.0.1' -and $_.RemoteAddress -ne '::1' -and
  $_.RemoteAddress -notmatch '^10\\.' -and $_.RemoteAddress -notmatch '^172\\.(1[6-9]|2[0-9]|3[01])\\.' -and
  $_.RemoteAddress -notmatch '^192\\.168\\.'
} | Select-Object -First 20
foreach($conn in $established) {
  $proc = Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue
  Write-Output "[FINDING] External connection: $($conn.LocalAddress):$($conn.LocalPort) -> $($conn.RemoteAddress):$($conn.RemotePort) - PID $($conn.OwningProcess) ($($proc.ProcessName))"
}

# ===== USERS =====
Write-Output "[CATEGORY:users]"

# Recently created users (last 7 days)
Write-Output "[SEVERITY:high]"
$cutoff = (Get-Date).AddDays(-7)
$recentUsers = Get-LocalUser | Where-Object { $_.Created -gt $cutoff -or $_.PasswordLastSet -gt $cutoff }
foreach($u in $recentUsers) {
  Write-Output "[FINDING] Recently created/modified user: $($u.Name) - Created: $($u.Created) - Enabled: $($u.Enabled)"
}

# Hidden accounts ($ suffix)
Write-Output "[SEVERITY:critical]"
$hiddenUsers = Get-LocalUser | Where-Object { $_.Name -match '\\$$' -and $_.Enabled }
foreach($u in $hiddenUsers) {
  Write-Output "[FINDING] Hidden account detected ($ suffix): $($u.Name)"
}

# Users in Administrators group
Write-Output "[SEVERITY:info]"
$admins = Get-LocalGroupMember -Group 'Administrators' -ErrorAction SilentlyContinue
foreach($a in $admins) {
  Write-Output "[FINDING] Administrator group member: $($a.Name) ($($a.ObjectClass))"
}

# ===== AD-SPECIFIC (if DC) =====
$isDC = (Get-CimInstance Win32_OperatingSystem).ProductType -eq 2
if($isDC) {
  Write-Output "[CATEGORY:active_directory]"
  try {
    Import-Module ActiveDirectory -ErrorAction Stop

    # KRBTGT password age
    Write-Output "[SEVERITY:high]"
    $krbtgt = Get-ADUser krbtgt -Properties PasswordLastSet
    $krbtgtAge = ((Get-Date) - $krbtgt.PasswordLastSet).Days
    if($krbtgtAge -gt 180) {
      Write-Output "[FINDING] KRBTGT password is $krbtgtAge days old (should be rotated regularly)"
    }

    # AdminSDHolder protected objects
    Write-Output "[SEVERITY:medium]"
    $adminSD = Get-ADObject -Filter {AdminCount -eq 1} -Properties Name,ObjectClass,WhenChanged
    $unexpectedAdmin = $adminSD | Where-Object { $_.ObjectClass -eq 'user' -and $_.Name -notin @('Administrator','krbtgt') }
    foreach($obj in $unexpectedAdmin) {
      Write-Output "[FINDING] AdminSDHolder protected account: $($obj.Name) (class: $($obj.ObjectClass), changed: $($obj.WhenChanged))"
    }
  } catch {
    Write-Output "[SEVERITY:info]"
    Write-Output "[FINDING] AD module not available for DC checks"
  }
}

Write-Output "WIN_ANALYSIS_DONE"
`;
}

// ============================================================
// Quick Scan Script (no collection, live check)
// ============================================================

function buildWinQuickScanScript() {
  return `
$ErrorActionPreference='SilentlyContinue'
Write-Output "[CATEGORY:processes]"
Write-Output "[SEVERITY:high]"

# Encoded commands
Get-CimInstance Win32_Process | Where-Object {
  $_.CommandLine -match '-[Ee]nc[o]?[d]?\\s' -or $_.CommandLine -match 'FromBase64String'
} | ForEach-Object {
  Write-Output "[FINDING] Encoded command: PID $($_.ProcessId) - $($_.Name)"
}

# Temp dir processes
Get-CimInstance Win32_Process | Where-Object {
  $_.ExecutablePath -match '\\\\Temp\\\\|\\\\Downloads\\\\'
} | ForEach-Object {
  Write-Output "[FINDING] Process from temp/download: PID $($_.ProcessId) - $($_.Name) - $($_.ExecutablePath)"
}

Write-Output "[CATEGORY:persistence]"
Write-Output "[SEVERITY:critical]"

# WMI subscriptions
$wmi = Get-WmiObject -Namespace root\\subscription -Class __EventConsumer 2>$null
foreach($c in $wmi) {
  Write-Output "[FINDING] WMI persistence: $($c.Name)"
}

Write-Output "[SEVERITY:high]"
# Suspicious tasks
Get-ScheduledTask | Where-Object { $_.State -ne 'Disabled' } | ForEach-Object {
  $a = ($_.Actions | ForEach-Object { $_.Execute + ' ' + $_.Arguments }) -join '; '
  if($a -match '\\\\Temp\\\\|powershell.*-[Ee]nc|cmd.*/[Cc].*http|mshta|regsvr32') {
    Write-Output "[FINDING] Suspicious task: $($_.TaskName) - $a"
  }
}

Write-Output "[CATEGORY:network]"
Write-Output "[SEVERITY:medium]"

# Unusual listeners (deduplicate IPv4/IPv6)
$common = @(22,80,443,445,135,139,389,636,3389,5985,5986,47001,53,88,464,3268,3269,4505,4506)
$seen = @{}
Get-NetTCPConnection -State Listen | Where-Object { $_.LocalPort -notin $common -and $_.LocalPort -gt 1024 } | ForEach-Object {
  $key = "$($_.LocalPort)-$($_.OwningProcess)"
  if(-not $seen[$key]) {
    $seen[$key] = $true
    $proc = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
    Write-Output "[FINDING] Unusual listener: port $($_.LocalPort) - $($proc.ProcessName)"
  }
}

Write-Output "[CATEGORY:users]"
Write-Output "[SEVERITY:critical]"

# Hidden accounts
Get-LocalUser | Where-Object { $_.Name -match '\\$$' -and $_.Enabled } | ForEach-Object {
  Write-Output "[FINDING] Hidden account: $($_.Name)"
}

Write-Output "[SEVERITY:high]"
# Recent users
$cutoff = (Get-Date).AddDays(-7)
Get-LocalUser | Where-Object { $_.Created -gt $cutoff } | ForEach-Object {
  Write-Output "[FINDING] Recently created user: $($_.Name) - $($_.Created)"
}

Write-Output "WIN_SCAN_DONE"
`;
}

module.exports = router;
