/**
 * File Browser Routes
 *
 * Provides file browsing and editing capabilities on minions.
 * Uses Salt's file module for operations.
 *
 * @module routes/files
 */

const express = require('express');
const router = express.Router();
const { client: saltClient } = require('../lib/salt-client');
const logger = require('../lib/logger');
const { requireAuth } = require('../middleware/auth');
const { auditAction } = require('../middleware/audit');

// Apply authentication to all file routes
router.use(requireAuth);

/**
 * GET /api/files/:target/list
 * List files in a directory
 *
 * Query params:
 *   path: string - Directory path to list
 */
router.get('/:target/list', auditAction('files.list'), async (req, res) => {
  const { target } = req.params;
  const { path = '/' } = req.query;

  if (!target) {
    return res.status(400).json({
      success: false,
      error: 'Target is required'
    });
  }

  try {
    // Get kernel type (uses cache for speed)
    const kernel = await saltClient.getKernel(target);

    let command;
    if (kernel === 'Windows') {
      // Windows dir command - simpler approach
      const winPath = path.replace(/\//g, '\\') || 'C:\\';
      command = `cmd /c dir /b /a "${winPath}"`;
    } else {
      // Linux ls command with detailed output
      command = `ls -la "${path}" 2>/dev/null | tail -n +2 | awk '{print $1 "|" $5 "|" $9}'`;
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
        files: [],
        error: 'No output or access denied'
      });
    }

    // Parse the output
    const files = [];
    const lines = output.split('\n').filter(l => l.trim());

    if (kernel === 'Windows') {
      // Windows dir /b output - just filenames
      // Need another call to determine file vs directory
      for (const name of lines) {
        if (name && name !== '.' && name !== '..') {
          files.push({
            name: name.trim(),
            type: 'unknown', // Would need stat call to determine
            size: 0,
            permissions: ''
          });
        }
      }
    } else {
      // Linux ls -la output
      for (const line of lines) {
        const parts = line.split('|');
        if (parts.length >= 3) {
          const perms = parts[0];
          const size = parseInt(parts[1], 10) || 0;
          const name = parts.slice(2).join('|'); // Handle filenames with |

          if (name && name !== '.' && name !== '..') {
            files.push({
              name,
              type: perms.startsWith('d') ? 'directory' : 'file',
              size,
              permissions: perms
            });
          }
        }
      }
    }

    // Sort: directories first, then files
    files.sort((a, b) => {
      if (a.type === b.type) return a.name.localeCompare(b.name);
      return a.type === 'directory' ? -1 : 1;
    });

    res.json({
      success: true,
      target,
      kernel,
      path,
      files,
      total: files.length
    });

  } catch (error) {
    logger.error('Failed to list files', error);
    res.status(500).json({
      success: false,
      error: 'Failed to list files',
      details: error.message
    });
  }
});

/**
 * GET /api/files/:target/read
 * Read file contents
 *
 * Query params:
 *   path: string - File path to read
 *   limit: number - Max bytes to read (default: 100000)
 */
router.get('/:target/read', auditAction('files.read'), async (req, res) => {
  const { target } = req.params;
  const { path } = req.query;
  const limit = Math.min(parseInt(req.query.limit, 10) || 100000, 1000000);

  if (!target || !path) {
    return res.status(400).json({
      success: false,
      error: 'Target and path are required'
    });
  }

  try {
    // Get file info first
    const statResult = await saltClient.run({
      client: 'local',
      tgt: target,
      fun: 'file.stats',
      arg: [path]
    });

    const stats = statResult[target];

    if (!stats || stats.isdir) {
      return res.status(400).json({
        success: false,
        error: stats?.isdir ? 'Cannot read directory' : 'File not found'
      });
    }

    // Check file size
    if (stats.size > limit) {
      return res.json({
        success: true,
        target,
        path,
        content: null,
        truncated: true,
        size: stats.size,
        limit,
        message: `File too large (${stats.size} bytes). Reading first ${limit} bytes.`
      });
    }

    // Read file content
    const readResult = await saltClient.run({
      client: 'local',
      tgt: target,
      fun: 'file.read',
      arg: [path]
    });

    const content = readResult[target];

    res.json({
      success: true,
      target,
      path,
      content: typeof content === 'string' ? content : String(content),
      size: stats.size,
      mode: stats.mode,
      user: stats.user,
      group: stats.group
    });

  } catch (error) {
    logger.error('Failed to read file', error);
    res.status(500).json({
      success: false,
      error: 'Failed to read file',
      details: error.message
    });
  }
});

/**
 * POST /api/files/:target/write
 * Write content to a file
 *
 * Body:
 *   path: string - File path to write
 *   content: string - Content to write
 *   backup: boolean - Create backup (default: true)
 */
router.post('/:target/write', auditAction('files.write'), async (req, res) => {
  const { target } = req.params;
  const { path, content, backup = true } = req.body;

  if (!target || !path || content === undefined) {
    return res.status(400).json({
      success: false,
      error: 'Target, path, and content are required'
    });
  }

  try {
    // Create backup if requested
    if (backup) {
      const backupPath = `${path}.bak`;
      await saltClient.run({
        client: 'local',
        tgt: target,
        fun: 'file.copy',
        arg: [path, backupPath]
      });
    }

    // Write content using file.write
    const writeResult = await saltClient.run({
      client: 'local',
      tgt: target,
      fun: 'file.write',
      arg: [path, content]
    });

    const result = writeResult[target];

    res.json({
      success: true,
      target,
      path,
      result,
      backup: backup ? `${path}.bak` : null
    });

  } catch (error) {
    logger.error('Failed to write file', error);
    res.status(500).json({
      success: false,
      error: 'Failed to write file',
      details: error.message
    });
  }
});

/**
 * GET /api/files/:target/stat
 * Get file/directory information
 *
 * Query params:
 *   path: string - Path to stat
 */
router.get('/:target/stat', async (req, res) => {
  const { target } = req.params;
  const { path } = req.query;

  if (!target || !path) {
    return res.status(400).json({
      success: false,
      error: 'Target and path are required'
    });
  }

  try {
    const statResult = await saltClient.run({
      client: 'local',
      tgt: target,
      fun: 'file.stats',
      arg: [path]
    });

    const stats = statResult[target];

    if (!stats) {
      return res.status(404).json({
        success: false,
        error: 'Path not found'
      });
    }

    res.json({
      success: true,
      target,
      path,
      stats
    });

  } catch (error) {
    logger.error('Failed to stat file', error);
    res.status(500).json({
      success: false,
      error: 'Failed to get file info',
      details: error.message
    });
  }
});

module.exports = router;
