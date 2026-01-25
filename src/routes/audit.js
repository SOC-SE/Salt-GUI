/**
 * Audit Log Routes
 *
 * Provides access to the audit trail.
 *
 * @module routes/audit
 */

const express = require('express');
const router = express.Router();
const { readAuditLog, clearAuditLog } = require('../lib/logger');
const { requireAuth, requireAdmin } = require('../middleware/auth');

// Apply authentication to all audit routes
router.use(requireAuth);

/**
 * GET /api/audit
 * Get audit log entries
 *
 * Query params:
 *   limit: number - Maximum entries to return (default: 100, max: 1000)
 *   action: string - Filter by action type
 *   user: string - Filter by username
 */
router.get('/', (req, res) => {
  const limit = Math.min(parseInt(req.query.limit, 10) || 100, 1000);
  const actionFilter = req.query.action;
  const userFilter = req.query.user;

  try {
    let entries = readAuditLog(limit * 2); // Get extra for filtering

    // Apply filters
    if (actionFilter) {
      entries = entries.filter(e => e.action && e.action.includes(actionFilter));
    }
    if (userFilter) {
      entries = entries.filter(e => e.user === userFilter);
    }

    // Limit results
    entries = entries.slice(-limit);

    // Return in reverse chronological order
    entries.reverse();

    res.json({
      success: true,
      count: entries.length,
      entries
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: 'Failed to read audit log'
    });
  }
});

/**
 * GET /api/audit/actions
 * Get list of unique action types
 */
router.get('/actions', (req, res) => {
  try {
    const entries = readAuditLog(1000);
    const actions = [...new Set(entries.map(e => e.action).filter(Boolean))];
    actions.sort();

    res.json({
      success: true,
      actions
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: 'Failed to read audit log'
    });
  }
});

/**
 * GET /api/audit/users
 * Get list of unique users in audit log
 */
router.get('/users', (req, res) => {
  try {
    const entries = readAuditLog(1000);
    const users = [...new Set(entries.map(e => e.user).filter(Boolean))];
    users.sort();

    res.json({
      success: true,
      users
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: 'Failed to read audit log'
    });
  }
});

/**
 * DELETE /api/audit
 * Clear audit log (admin only)
 */
router.delete('/', requireAdmin, (req, res) => {
  try {
    clearAuditLog();

    res.json({
      success: true,
      message: 'Audit log cleared'
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: 'Failed to clear audit log'
    });
  }
});

module.exports = router;
