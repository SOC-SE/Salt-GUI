/**
 * Log Viewer Routes
 *
 * Provides log viewing capabilities for minions.
 * Supports common log files on Linux and Windows.
 *
 * @module routes/logs
 */

const express = require('express');
const router = express.Router();
const { client: saltClient } = require('../lib/salt-client');
const logger = require('../lib/logger');
const { requireAuth } = require('../middleware/auth');
const { auditAction } = require('../middleware/audit');

// Apply authentication to all log routes
router.use(requireAuth);

// Common log file paths
const COMMON_LOGS = {
  linux: [
    { name: 'Auth Log', path: '/var/log/auth.log', alt: '/var/log/secure' },
    { name: 'Syslog', path: '/var/log/syslog', alt: '/var/log/messages' },
    { name: 'Kernel Log', path: '/var/log/kern.log', alt: '/var/log/dmesg' },
    { name: 'Salt Minion', path: '/var/log/salt/minion' },
    { name: 'Cron Log', path: '/var/log/cron' },
    { name: 'Apache Access', path: '/var/log/apache2/access.log', alt: '/var/log/httpd/access_log' },
    { name: 'Apache Error', path: '/var/log/apache2/error.log', alt: '/var/log/httpd/error_log' },
    { name: 'Nginx Access', path: '/var/log/nginx/access.log' },
    { name: 'Nginx Error', path: '/var/log/nginx/error.log' }
  ],
  windows: [
    { name: 'System Events', type: 'event', log: 'System' },
    { name: 'Security Events', type: 'event', log: 'Security' },
    { name: 'Application Events', type: 'event', log: 'Application' },
    { name: 'Salt Minion', path: 'C:\\salt\\var\\log\\salt\\minion' }
  ]
};

/**
 * GET /api/logs/sources
 * Get available log sources for a target
 */
router.get('/sources/:target', async (req, res) => {
  const { target } = req.params;

  if (!target) {
    return res.status(400).json({
      success: false,
      error: 'Target is required'
    });
  }

  try {
    // Get kernel type (uses cache for speed)
    const kernel = await saltClient.getKernel(target);

    const sources = kernel === 'Windows' ? COMMON_LOGS.windows : COMMON_LOGS.linux;

    res.json({
      success: true,
      target,
      kernel,
      sources
    });

  } catch (error) {
    logger.error('Failed to get log sources', error);
    res.status(500).json({
      success: false,
      error: 'Failed to get log sources',
      details: error.message
    });
  }
});

/**
 * GET /api/logs/:target/read
 * Read log file content
 *
 * Query params:
 *   path: string - Log file path
 *   lines: number - Number of lines to tail (default: 100)
 */
router.get('/:target/read', auditAction('logs.read'), async (req, res) => {
  const { target } = req.params;
  const { path, lines = 100 } = req.query;

  if (!target || !path) {
    return res.status(400).json({
      success: false,
      error: 'Target and path are required'
    });
  }

  const numLines = Math.min(Math.max(parseInt(lines, 10) || 100, 10), 1000);

  try {
    // Get kernel type (uses cache for speed)
    const kernel = await saltClient.getKernel(target);

    let command;
    if (kernel === 'Windows') {
      // PowerShell to get last N lines
      command = `powershell -Command "Get-Content -Path '${path}' -Tail ${numLines} -ErrorAction SilentlyContinue"`;
    } else {
      // Linux tail
      command = `tail -n ${numLines} "${path}" 2>/dev/null`;
    }

    const result = await saltClient.run({
      client: 'local',
      tgt: target,
      fun: 'cmd.run',
      arg: [command],
      kwarg: { timeout: 30 }
    });

    const output = result[target];

    if (!output || typeof output !== 'string') {
      return res.json({
        success: true,
        target,
        path,
        lines: [],
        message: 'No output or file not found'
      });
    }

    const logLines = output.split('\n');

    res.json({
      success: true,
      target,
      path,
      kernel,
      lines: logLines,
      total: logLines.length
    });

  } catch (error) {
    logger.error('Failed to read log', error);
    res.status(500).json({
      success: false,
      error: 'Failed to read log',
      details: error.message
    });
  }
});

/**
 * GET /api/logs/:target/events
 * Read Windows event log
 *
 * Query params:
 *   log: string - Event log name (System, Security, Application)
 *   count: number - Number of events (default: 50)
 */
router.get('/:target/events', auditAction('logs.events'), async (req, res) => {
  const { target } = req.params;
  const { log = 'System', count = 50 } = req.query;

  if (!target) {
    return res.status(400).json({
      success: false,
      error: 'Target is required'
    });
  }

  const numEvents = Math.min(Math.max(parseInt(count, 10) || 50, 10), 200);

  try {
    // PowerShell command to get event log entries
    const command = `powershell -Command "Get-EventLog -LogName '${log}' -Newest ${numEvents} | Select-Object TimeGenerated, EntryType, Source, Message | ConvertTo-Json -Compress"`;

    const result = await saltClient.run({
      client: 'local',
      tgt: target,
      fun: 'cmd.run',
      arg: [command],
      kwarg: { timeout: 60 }
    });

    const output = result[target];

    if (!output || typeof output !== 'string') {
      return res.json({
        success: true,
        target,
        log,
        events: [],
        message: 'No events or access denied'
      });
    }

    let events = [];
    try {
      const parsed = JSON.parse(output);
      events = Array.isArray(parsed) ? parsed : [parsed];
    } catch (e) {
      // If not JSON, return as raw lines
      events = output.split('\n').map(line => ({ raw: line }));
    }

    res.json({
      success: true,
      target,
      log,
      events,
      total: events.length
    });

  } catch (error) {
    logger.error('Failed to read event log', error);
    res.status(500).json({
      success: false,
      error: 'Failed to read event log',
      details: error.message
    });
  }
});

/**
 * GET /api/logs/:target/search
 * Search log file for pattern
 *
 * Query params:
 *   path: string - Log file path
 *   pattern: string - Search pattern (grep-compatible)
 *   lines: number - Max lines to return (default: 100)
 */
router.get('/:target/search', auditAction('logs.search'), async (req, res) => {
  const { target } = req.params;
  const { path, pattern, lines = 100 } = req.query;

  if (!target || !path || !pattern) {
    return res.status(400).json({
      success: false,
      error: 'Target, path, and pattern are required'
    });
  }

  const numLines = Math.min(Math.max(parseInt(lines, 10) || 100, 10), 500);

  try {
    // Get kernel type (uses cache for speed)
    const kernel = await saltClient.getKernel(target);

    let command;
    if (kernel === 'Windows') {
      command = `powershell -Command "Select-String -Path '${path}' -Pattern '${pattern}' | Select-Object -Last ${numLines} | ForEach-Object { $_.Line }"`;
    } else {
      command = `grep -i "${pattern}" "${path}" 2>/dev/null | tail -n ${numLines}`;
    }

    const result = await saltClient.run({
      client: 'local',
      tgt: target,
      fun: 'cmd.run',
      arg: [command],
      kwarg: { timeout: 30 }
    });

    const output = result[target];
    const matches = output ? output.split('\n').filter(l => l.trim()) : [];

    res.json({
      success: true,
      target,
      path,
      pattern,
      matches,
      total: matches.length
    });

  } catch (error) {
    logger.error('Failed to search log', error);
    res.status(500).json({
      success: false,
      error: 'Failed to search log',
      details: error.message
    });
  }
});

module.exports = router;
