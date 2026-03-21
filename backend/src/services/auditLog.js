// auditLog.js — compliance audit trail
// Stored in /home/audit/{tenantId}.jsonl (newline-delimited JSON)

const fs   = require('fs');
const path = require('path');

const AUDIT_DIR = process.env.NODE_ENV === 'production'
  ? '/home/audit'
  : path.join(__dirname, '../../../audit');

if (!fs.existsSync(AUDIT_DIR)) fs.mkdirSync(AUDIT_DIR, { recursive: true });

const ACTIONS = {
  // Auth
  TENANT_CONNECTED:    'tenant.connected',
  TENANT_DISCONNECTED: 'tenant.disconnected',
  ADMIN_LOGIN:         'admin.login',
  ADMIN_LOGOUT:        'admin.logout',
  // Alert actions
  ALERT_DETECTED:      'alert.detected',
  ALERT_RESOLVED:      'alert.resolved',
  ALERT_DISMISSED:     'alert.dismissed',
  // Response actions
  SESSION_REVOKED:     'response.session_revoked',
  USER_DISABLED:       'response.user_disabled',
  MFA_REQUIRED:        'response.mfa_required',
  AUTO_REVOKE:         'response.auto_revoke',
  // Settings
  SETTINGS_UPDATED:    'settings.updated',
  ADMIN_ADDED:         'admin.added',
  ADMIN_REMOVED:       'admin.removed',
  WHITELIST_UPDATED:   'whitelist.updated',
  // System
  SCAN_TRIGGERED:      'scan.triggered',
  WEBHOOK_CREATED:     'webhook.created',
  TEST_SENT:           'test.sent'
};

function log(tenantId, action, details = {}, actor = 'system') {
  if (!tenantId) return;
  const entry = {
    timestamp: new Date().toISOString(),
    tenantId,
    action,
    actor,  // email or 'system' or 'auto'
    ...details
  };

  const filePath = path.join(AUDIT_DIR, tenantId + '.jsonl');
  try {
    fs.appendFileSync(filePath, JSON.stringify(entry) + '\n');
  } catch (err) {
    console.error('[AuditLog] Write error:', err.message);
  }
}

function getLog(tenantId, options = {}) {
  const filePath = path.join(AUDIT_DIR, tenantId + '.jsonl');
  if (!fs.existsSync(filePath)) return [];

  try {
    const lines = fs.readFileSync(filePath, 'utf8')
      .split('\n')
      .filter(Boolean)
      .map(l => JSON.parse(l));

    let entries = lines.reverse(); // newest first

    if (options.action)   entries = entries.filter(e => e.action === options.action);
    if (options.actor)    entries = entries.filter(e => e.actor  === options.actor);
    if (options.since)    entries = entries.filter(e => new Date(e.timestamp) >= new Date(options.since));
    if (options.limit)    entries = entries.slice(0, options.limit);

    return entries;
  } catch (err) {
    return [];
  }
}

function getStats(tenantId) {
  const entries = getLog(tenantId);
  return {
    total:           entries.length,
    last7Days:       entries.filter(e => new Date(e.timestamp) > new Date(Date.now() - 7*24*3600*1000)).length,
    alertsDetected:  entries.filter(e => e.action === ACTIONS.ALERT_DETECTED).length,
    sessionsRevoked: entries.filter(e => e.action === ACTIONS.SESSION_REVOKED).length,
    settingsChanges: entries.filter(e => e.action.startsWith('settings.')).length,
    lastActivity:    entries[0]?.timestamp || null
  };
}

module.exports = { log, getLog, getStats, ACTIONS };
