/**
 * Reports Routes
 *
 * Generates and exports reports about system status,
 * audit logs, and suspicious findings.
 *
 * @module routes/reports
 */

const express = require('express');
const router = express.Router();
const { client: saltClient } = require('../lib/salt-client');
const { readAuditLog } = require('../lib/logger');
const logger = require('../lib/logger');
const { requireAuth } = require('../middleware/auth');
const { auditAction } = require('../middleware/audit');

// Apply authentication to all report routes
router.use(requireAuth);

/**
 * GET /api/reports/status
 * Generate system status report
 */
router.get('/status', auditAction('reports.status'), async (req, res) => {
  try {
    // Get all minion keys
    const keysResult = await saltClient.run({
      client: 'wheel',
      fun: 'key.list_all'
    });

    const keys = keysResult?.return?.[0]?.data?.return || keysResult;
    const accepted = keys.minions || [];

    // Ping all minions to get status
    const pingResult = await saltClient.run({
      client: 'local',
      tgt: '*',
      fun: 'test.ping',
      kwarg: { timeout: 10 }
    });

    // Get grains for all minions
    const grainsResult = await saltClient.run({
      client: 'local',
      tgt: '*',
      fun: 'grains.items',
      kwarg: { timeout: 30 }
    });

    const minions = [];
    let online = 0;
    let offline = 0;
    let linuxCount = 0;
    let windowsCount = 0;

    for (const minionId of accepted) {
      const isOnline = pingResult[minionId] === true;
      const grains = grainsResult[minionId] || {};

      if (isOnline) online++;
      else offline++;

      const kernel = grains.kernel || 'Unknown';
      if (kernel === 'Linux') linuxCount++;
      else if (kernel === 'Windows') windowsCount++;

      minions.push({
        id: minionId,
        status: isOnline ? 'online' : 'offline',
        os: grains.os || 'Unknown',
        osFamily: grains.os_family || 'Unknown',
        kernel,
        ip: grains.ipv4 ? grains.ipv4.filter(ip => ip !== '127.0.0.1')[0] : 'Unknown'
      });
    }

    const report = {
      generated: new Date().toISOString(),
      summary: {
        total: accepted.length,
        online,
        offline,
        linux: linuxCount,
        windows: windowsCount
      },
      minions
    };

    res.json({
      success: true,
      report
    });

  } catch (error) {
    logger.error('Failed to generate status report', error);
    res.status(500).json({
      success: false,
      error: 'Failed to generate report',
      details: error.message
    });
  }
});

/**
 * GET /api/reports/audit
 * Generate audit log report
 *
 * Query params:
 *   hours: number - Hours of logs to include (default: 24)
 */
router.get('/audit', auditAction('reports.audit'), async (req, res) => {
  const hours = parseInt(req.query.hours, 10) || 24;

  try {
    const entries = readAuditLog(10000);

    // Filter by time
    const cutoff = Date.now() - (hours * 60 * 60 * 1000);
    const filtered = entries.filter(e => {
      if (!e.timestamp) return false;
      return new Date(e.timestamp).getTime() >= cutoff;
    });

    // Generate summary
    const actionCounts = {};
    const userCounts = {};

    for (const entry of filtered) {
      const action = entry.action || 'unknown';
      const user = entry.user || 'unknown';

      actionCounts[action] = (actionCounts[action] || 0) + 1;
      userCounts[user] = (userCounts[user] || 0) + 1;
    }

    // Sort entries by timestamp (newest first)
    filtered.sort((a, b) =>
      new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime()
    );

    const report = {
      generated: new Date().toISOString(),
      period: `Last ${hours} hours`,
      summary: {
        totalActions: filtered.length,
        byAction: actionCounts,
        byUser: userCounts
      },
      entries: filtered.slice(0, 500) // Limit entries in report
    };

    res.json({
      success: true,
      report
    });

  } catch (error) {
    logger.error('Failed to generate audit report', error);
    res.status(500).json({
      success: false,
      error: 'Failed to generate report',
      details: error.message
    });
  }
});

/**
 * POST /api/reports/security
 * Generate security scan report for specified targets
 *
 * Body:
 *   targets: string[] - Target minions to scan
 */
router.post('/security', auditAction('reports.security'), async (req, res) => {
  const { targets } = req.body;

  if (!targets || (Array.isArray(targets) && targets.length === 0)) {
    return res.status(400).json({
      success: false,
      error: 'Targets are required'
    });
  }

  const targetList = Array.isArray(targets) ? targets : [targets];

  try {
    const findings = {};
    let totalCritical = 0;
    let totalHigh = 0;
    let totalMedium = 0;
    let totalLow = 0;

    // Import suspicious scanner logic
    const suspiciousRouter = require('./suspicious');

    for (const target of targetList) {
      findings[target] = {
        scanned: new Date().toISOString(),
        findings: []
      };

      // Determine OS
      const grainsResult = await saltClient.run({
        client: 'local',
        tgt: target,
        fun: 'grains.item',
        arg: ['kernel']
      });

      const kernel = grainsResult[target]?.kernel || 'Linux';
      findings[target].kernel = kernel;

      // Quick security checks (simplified version)
      if (kernel === 'Linux') {
        // Check for UID 0 users
        const uidCheck = await saltClient.run({
          client: 'local',
          tgt: target,
          fun: 'cmd.run',
          arg: ["awk -F: '($3 == 0 && $1 != \"root\") {print $1}' /etc/passwd"],
          kwarg: { timeout: 30 }
        });

        if (uidCheck[target] && uidCheck[target].trim()) {
          findings[target].findings.push({
            severity: 'critical',
            category: 'Users',
            finding: 'Non-root users with UID 0',
            details: uidCheck[target].trim()
          });
          totalCritical++;
        }

        // Check for SUID in temp
        const suidCheck = await saltClient.run({
          client: 'local',
          tgt: target,
          fun: 'cmd.run',
          arg: ["find /tmp /var/tmp /dev/shm -perm -4000 -type f 2>/dev/null | head -5"],
          kwarg: { timeout: 60 }
        });

        if (suidCheck[target] && suidCheck[target].trim()) {
          findings[target].findings.push({
            severity: 'critical',
            category: 'Files',
            finding: 'SUID binaries in temp directories',
            details: suidCheck[target].trim()
          });
          totalCritical++;
        }
      }

      // Count findings
      for (const f of findings[target].findings) {
        switch (f.severity) {
          case 'critical': totalCritical++; break;
          case 'high': totalHigh++; break;
          case 'medium': totalMedium++; break;
          case 'low': totalLow++; break;
        }
      }
    }

    const report = {
      generated: new Date().toISOString(),
      targets: targetList,
      summary: {
        totalTargets: targetList.length,
        critical: totalCritical,
        high: totalHigh,
        medium: totalMedium,
        low: totalLow,
        total: totalCritical + totalHigh + totalMedium + totalLow
      },
      findings
    };

    res.json({
      success: true,
      report
    });

  } catch (error) {
    logger.error('Failed to generate security report', error);
    res.status(500).json({
      success: false,
      error: 'Failed to generate report',
      details: error.message
    });
  }
});

/**
 * GET /api/reports/export/:type
 * Export report in various formats
 *
 * Params:
 *   type: string - Report type (status, audit, security)
 *
 * Query params:
 *   format: string - Export format (json, csv, text) - default: json
 */
router.get('/export/:type', async (req, res) => {
  const { type } = req.params;
  const format = req.query.format || 'json';

  // Redirect to appropriate report endpoint
  const reportTypes = ['status', 'audit'];

  if (!reportTypes.includes(type)) {
    return res.status(400).json({
      success: false,
      error: 'Invalid report type'
    });
  }

  try {
    // This is a placeholder - in a real implementation,
    // we would generate the report and format it accordingly
    res.json({
      success: true,
      message: `Export ${type} report in ${format} format`,
      note: 'Use the /api/reports/:type endpoints to get report data'
    });

  } catch (error) {
    res.status(500).json({
      success: false,
      error: 'Export failed'
    });
  }
});

module.exports = router;
