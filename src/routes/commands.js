/**
 * Command Execution Routes
 *
 * Handles command execution on minions (C2 functionality).
 * Supports both Linux (bash) and Windows (cmd/powershell).
 *
 * @module routes/commands
 */

const express = require('express');
const router = express.Router();
const { client: saltClient } = require('../lib/salt-client');
const logger = require('../lib/logger');
const { requireAuth, getClientIP } = require('../middleware/auth');
const { auditAction } = require('../middleware/audit');

// Apply authentication to all command routes
router.use(requireAuth);

/**
 * Validate and sanitize targets
 * @param {string|string[]} targets - Target input
 * @returns {{valid: boolean, targets: string[], error?: string}}
 */
function validateTargets(targets) {
  if (!targets) {
    return { valid: false, error: 'Targets are required' };
  }

  // Convert to array if string
  const targetList = Array.isArray(targets) ? targets : [targets];

  if (targetList.length === 0) {
    return { valid: false, error: 'At least one target is required' };
  }

  // Validate each target (allow glob patterns)
  for (const target of targetList) {
    if (typeof target !== 'string' || target.length === 0) {
      return { valid: false, error: 'Invalid target format' };
    }
    // Allow alphanumeric, dots, hyphens, underscores, and glob characters
    if (!/^[a-zA-Z0-9._*?[\]-]+$/.test(target)) {
      return { valid: false, error: `Invalid target: ${target}` };
    }
  }

  return { valid: true, targets: targetList };
}

/**
 * Determine shell based on target OS
 * @param {string} osKernel - OS kernel from grains
 * @param {string} requestedShell - User-requested shell
 * @returns {string} Shell to use
 */
function resolveShell(osKernel, requestedShell) {
  const kernel = (osKernel || '').toLowerCase();

  if (requestedShell) {
    return requestedShell;
  }

  if (kernel === 'windows') {
    return 'powershell'; // Default to PowerShell for Windows
  }

  return '/bin/bash'; // Default to bash for Linux
}

/**
 * POST /api/commands/run
 * Execute a command on target minions
 *
 * Body:
 *   targets: string | string[] - Target minions (can use globs)
 *   command: string - Command to execute
 *   shell: string (optional) - Shell to use (bash, powershell, cmd)
 *   timeout: number (optional) - Timeout in seconds (default: 30)
 *   cwd: string (optional) - Working directory
 *   runas: string (optional) - User to run as
 */
router.post('/run', auditAction('command.run'), async (req, res) => {
  const {
    targets,
    command,
    shell,
    timeout = 30,
    cwd,
    runas
  } = req.body;

  // Validate targets
  const targetValidation = validateTargets(targets);
  if (!targetValidation.valid) {
    return res.status(400).json({
      success: false,
      error: targetValidation.error
    });
  }

  // Validate command
  if (!command || typeof command !== 'string' || command.trim().length === 0) {
    return res.status(400).json({
      success: false,
      error: 'Command is required'
    });
  }

  // Validate timeout
  const timeoutSec = Math.min(Math.max(parseInt(timeout, 10) || 30, 1), 600);

  const startTime = Date.now();

  try {
    logger.debug(`Executing command on ${targetValidation.targets.join(', ')}: ${command.substring(0, 100)}`);

    const result = await saltClient.cmd(
      targetValidation.targets,
      command,
      {
        shell,
        timeout: timeoutSec,
        cwd,
        runas
      }
    );

    const executionTime = Date.now() - startTime;

    // Format results
    const formattedResults = {};
    let successCount = 0;
    let failCount = 0;

    for (const [minion, output] of Object.entries(result)) {
      // Check if the output indicates an error
      const isError = typeof output === 'string' &&
        (output.includes('Minion did not return') ||
         output.includes('No minions matched') ||
         output.startsWith('ERROR:'));

      if (isError) {
        failCount++;
        formattedResults[minion] = {
          success: false,
          output: output,
          error: true
        };
      } else {
        successCount++;
        formattedResults[minion] = {
          success: true,
          output: output
        };
      }
    }

    res.json({
      success: true,
      command,
      targets: targetValidation.targets,
      results: formattedResults,
      summary: {
        total: Object.keys(result).length,
        success: successCount,
        failed: failCount
      },
      execution_time_ms: executionTime
    });
  } catch (error) {
    logger.error('Command execution failed', error);
    res.status(500).json({
      success: false,
      error: 'Command execution failed',
      details: error.message
    });
  }
});

/**
 * POST /api/commands/run-all
 * Execute command and get detailed output (stdout, stderr, retcode)
 */
router.post('/run-all', auditAction('command.run_all'), async (req, res) => {
  const {
    targets,
    command,
    shell,
    timeout = 30,
    cwd,
    runas
  } = req.body;

  // Validate targets
  const targetValidation = validateTargets(targets);
  if (!targetValidation.valid) {
    return res.status(400).json({
      success: false,
      error: targetValidation.error
    });
  }

  // Validate command
  if (!command || typeof command !== 'string' || command.trim().length === 0) {
    return res.status(400).json({
      success: false,
      error: 'Command is required'
    });
  }

  const timeoutSec = Math.min(Math.max(parseInt(timeout, 10) || 30, 1), 600);
  const startTime = Date.now();

  try {
    const result = await saltClient.cmdAll(
      targetValidation.targets,
      command,
      {
        shell,
        timeout: timeoutSec,
        cwd,
        runas
      }
    );

    const executionTime = Date.now() - startTime;

    // Format results with detailed info
    const formattedResults = {};
    let successCount = 0;
    let failCount = 0;

    for (const [minion, data] of Object.entries(result)) {
      if (typeof data === 'object' && data !== null) {
        const success = data.retcode === 0;
        if (success) successCount++;
        else failCount++;

        formattedResults[minion] = {
          success,
          retcode: data.retcode,
          stdout: data.stdout || '',
          stderr: data.stderr || '',
          pid: data.pid
        };
      } else {
        failCount++;
        formattedResults[minion] = {
          success: false,
          error: data
        };
      }
    }

    res.json({
      success: true,
      command,
      targets: targetValidation.targets,
      results: formattedResults,
      summary: {
        total: Object.keys(result).length,
        success: successCount,
        failed: failCount
      },
      execution_time_ms: executionTime
    });
  } catch (error) {
    logger.error('Command execution failed', error);
    res.status(500).json({
      success: false,
      error: 'Command execution failed',
      details: error.message
    });
  }
});

/**
 * POST /api/commands/run-async
 * Execute command asynchronously (returns job ID)
 */
router.post('/run-async', auditAction('command.run_async'), async (req, res) => {
  const {
    targets,
    command,
    shell,
    timeout = 30
  } = req.body;

  // Validate targets
  const targetValidation = validateTargets(targets);
  if (!targetValidation.valid) {
    return res.status(400).json({
      success: false,
      error: targetValidation.error
    });
  }

  // Validate command
  if (!command || typeof command !== 'string') {
    return res.status(400).json({
      success: false,
      error: 'Command is required'
    });
  }

  try {
    const jid = await saltClient.runAsync({
      client: 'local_async',
      fun: 'cmd.run',
      tgt: targetValidation.targets,
      tgt_type: targetValidation.targets.length > 1 ? 'list' : 'glob',
      arg: [command],
      kwarg: {
        shell,
        timeout: Math.min(parseInt(timeout, 10) || 30, 600)
      }
    });

    logger.info(`Async command submitted: ${jid}`);

    res.json({
      success: true,
      jid,
      message: 'Command submitted asynchronously',
      command,
      targets: targetValidation.targets
    });
  } catch (error) {
    logger.error('Async command submission failed', error);
    res.status(500).json({
      success: false,
      error: 'Failed to submit async command',
      details: error.message
    });
  }
});

/**
 * GET /api/commands/job/:jid
 * Get results of an async job
 */
router.get('/job/:jid', async (req, res) => {
  const { jid } = req.params;

  if (!jid || !/^[0-9]+$/.test(jid)) {
    return res.status(400).json({
      success: false,
      error: 'Invalid job ID'
    });
  }

  try {
    const result = await saltClient.jobLookup(jid);

    const hasResults = result && Object.keys(result).length > 0;

    res.json({
      success: true,
      jid,
      status: hasResults ? 'completed' : 'running',
      results: result || {}
    });
  } catch (error) {
    logger.error(`Failed to lookup job ${jid}`, error);
    res.status(500).json({
      success: false,
      error: 'Failed to lookup job',
      details: error.message
    });
  }
});

/**
 * POST /api/commands/quick
 * Quick command execution helper (simpler interface)
 */
router.post('/quick', async (req, res) => {
  const { target, cmd } = req.body;

  if (!target || !cmd) {
    return res.status(400).json({
      success: false,
      error: 'Target and cmd are required'
    });
  }

  try {
    const result = await saltClient.cmd(target, cmd, { timeout: 30 });

    res.json({
      success: true,
      target,
      command: cmd,
      output: result
    });
  } catch (error) {
    logger.error('Quick command failed', error);
    res.status(500).json({
      success: false,
      error: 'Command failed',
      details: error.message
    });
  }
});

module.exports = router;
