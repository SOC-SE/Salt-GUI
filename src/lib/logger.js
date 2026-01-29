/**
 * Logging Utilities
 *
 * Provides structured logging and audit trail functionality.
 * Audit logs are written in YAML format for easy parsing.
 *
 * @module lib/logger
 */

const fs = require('fs');
const path = require('path');
const yaml = require('js-yaml');
const { getAppConfig } = require('./config');

// Log levels
const LOG_LEVELS = {
  debug: 0,
  info: 1,
  warn: 2,
  error: 3
};

// ANSI color codes for console output
const COLORS = {
  reset: '\x1b[0m',
  dim: '\x1b[2m',
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  cyan: '\x1b[36m'
};

/**
 * Get current log level from configuration
 * @returns {number} Numeric log level
 */
function getCurrentLogLevel() {
  const config = getAppConfig();
  const levelName = config.logging?.level || 'info';
  return LOG_LEVELS[levelName] ?? LOG_LEVELS.info;
}

/**
 * Format timestamp for logging
 * @returns {string} ISO timestamp
 */
function timestamp() {
  return new Date().toISOString();
}

/**
 * Log a message to console with level and color
 * @param {string} level - Log level (debug, info, warn, error)
 * @param {string} message - Message to log
 * @param {Object} [data] - Optional additional data
 */
function log(level, message, data = null) {
  const levelNum = LOG_LEVELS[level] ?? LOG_LEVELS.info;
  if (levelNum < getCurrentLogLevel()) {
    return;
  }

  const ts = timestamp();
  const levelUpper = level.toUpperCase().padEnd(5);

  let color;
  switch (level) {
    case 'debug': color = COLORS.dim; break;
    case 'info': color = COLORS.green; break;
    case 'warn': color = COLORS.yellow; break;
    case 'error': color = COLORS.red; break;
    default: color = COLORS.reset;
  }

  const prefix = `${COLORS.dim}[${ts}]${COLORS.reset} ${color}[${levelUpper}]${COLORS.reset}`;

  if (data) {
    console.log(`${prefix} ${message}`, data);
  } else {
    console.log(`${prefix} ${message}`);
  }
}

/**
 * Debug level log
 * @param {string} message - Message to log
 * @param {Object} [data] - Optional data
 */
function debug(message, data = null) {
  log('debug', message, data);
}

/**
 * Info level log
 * @param {string} message - Message to log
 * @param {Object} [data] - Optional data
 */
function info(message, data = null) {
  log('info', message, data);
}

/**
 * Warning level log
 * @param {string} message - Message to log
 * @param {Object} [data] - Optional data
 */
function warn(message, data = null) {
  log('warn', message, data);
}

/**
 * Error level log
 * @param {string} message - Message to log
 * @param {Object|Error} [data] - Optional data or Error object
 */
function error(message, data = null) {
  if (data instanceof Error) {
    log('error', message, { message: data.message, stack: data.stack });
  } else {
    log('error', message, data);
  }
}

/**
 * Audit log entry structure
 * @typedef {Object} AuditEntry
 * @property {string} timestamp - ISO timestamp
 * @property {string} user - Username who performed action
 * @property {string} ip - Client IP address
 * @property {string} action - Action performed
 * @property {string|string[]} [targets] - Target minions
 * @property {Object} [details] - Additional details (sanitized)
 * @property {string} result - Result status
 * @property {number} [duration_ms] - Duration in milliseconds
 */

/**
 * Write an audit log entry
 * @param {Object} entry - Audit entry data
 * @param {string} entry.user - Username
 * @param {string} entry.ip - Client IP address
 * @param {string} entry.action - Action name (e.g., 'command.run')
 * @param {string|string[]} [entry.targets] - Target minions
 * @param {Object} [entry.details] - Additional details
 * @param {string} [entry.result='success'] - Result status
 * @param {number} [entry.duration_ms] - Duration in milliseconds
 */
function audit(entry) {
  const config = getAppConfig();
  const auditPath = path.resolve(config.logging?.audit_file || 'logs/audit.yaml');

  // Sanitize details - remove passwords and sensitive data
  const sanitizedDetails = entry.details ? sanitizeDetails(entry.details) : undefined;

  const auditEntry = {
    timestamp: timestamp(),
    user: entry.user || 'unknown',
    ip: entry.ip || 'unknown',
    action: entry.action,
    targets: entry.targets,
    details: sanitizedDetails,
    result: entry.result || 'success',
    duration_ms: entry.duration_ms
  };

  // Remove undefined fields
  Object.keys(auditEntry).forEach(key => {
    if (auditEntry[key] === undefined) {
      delete auditEntry[key];
    }
  });

  // Ensure directory exists
  const auditDir = path.dirname(auditPath);
  if (!fs.existsSync(auditDir)) {
    fs.mkdirSync(auditDir, { recursive: true });
  }

  // Append to YAML file
  try {
    const yamlEntry = yaml.dump([auditEntry], {
      indent: 2,
      lineWidth: 200,
      noRefs: true
    });

    // Remove the leading '- ' and add proper document separator for append
    const formattedEntry = '---\n' + yamlEntry;

    fs.appendFileSync(auditPath, formattedEntry);
    debug(`Audit logged: ${entry.action}`);
  } catch (err) {
    error('Failed to write audit log', err);
  }
}

/**
 * Sanitize details object by removing sensitive fields
 * @param {Object} details - Original details object
 * @returns {Object} Sanitized details
 */
function sanitizeDetails(details) {
  const sensitiveKeys = ['password', 'passwd', 'secret', 'token', 'key', 'credential', 'auth'];
  const sanitized = { ...details };

  for (const key of Object.keys(sanitized)) {
    const lowerKey = key.toLowerCase();
    if (sensitiveKeys.some(s => lowerKey.includes(s))) {
      sanitized[key] = '[REDACTED]';
    } else if (typeof sanitized[key] === 'object' && sanitized[key] !== null) {
      sanitized[key] = sanitizeDetails(sanitized[key]);
    }
  }

  return sanitized;
}

/**
 * Read audit log entries
 * @param {number} [limit=100] - Maximum entries to return
 * @returns {Array} Array of audit entries
 */
function readAuditLog(limit = 100) {
  const config = getAppConfig();
  const auditPath = path.resolve(config.logging?.audit_file || 'logs/audit.yaml');

  if (!fs.existsSync(auditPath)) {
    return [];
  }

  try {
    const content = fs.readFileSync(auditPath, 'utf8');
    // Parse YAML documents (separated by ---)
    const entries = yaml.loadAll(content).flat().filter(Boolean);
    // Return most recent entries
    return entries.slice(-limit);
  } catch (err) {
    error('Failed to read audit log', err);
    return [];
  }
}

/**
 * Clear audit log
 */
function clearAuditLog() {
  const config = getAppConfig();
  const auditPath = path.resolve(config.logging?.audit_file || 'logs/audit.yaml');

  try {
    if (fs.existsSync(auditPath)) {
      fs.writeFileSync(auditPath, '');
    }
    info('Audit log cleared');
  } catch (err) {
    error('Failed to clear audit log', err);
  }
}

/**
 * Create a request logger middleware
 * @returns {Function} Express middleware function
 */
function requestLogger() {
  return (req, res, next) => {
    const start = Date.now();

    // Log on response finish
    res.on('finish', () => {
      const duration = Date.now() - start;
      const level = res.statusCode >= 400 ? 'warn' : 'debug';
      log(level, `${req.method} ${req.path} ${res.statusCode} ${duration}ms`);
    });

    next();
  };
}

module.exports = {
  debug,
  info,
  warn,
  error,
  audit,
  readAuditLog,
  clearAuditLog,
  requestLogger,
  sanitizeDetails
};
