// auditLog.js — compliance audit trail
// Stored in /home/audit/{tenantId}.jsonl (newline-delimited JSON)
// Uses an in-memory write buffer + async flush to avoid blocking the event loop
// on Azure App Service's slow SMB-backed /home filesystem.

const fs   = require('fs');
const path = require('path');

const AUDIT_DIR = process.env.NODE_ENV === 'production'
  ? '/home/audit'
  : path.join(__dirname, '../../../audit');

if (!fs.existsSync(AUDIT_DIR)) fs.mkdirSync(AUDIT_DIR, { recursive: true });

// ── In-memory cache ───────────────────────────────────────────────────────────
// Keeps recent entries in memory to avoid repeated synchronous disk reads.
const _memCache  = new Map(); // tenantId → entry[]
const CACHE_MAX  = 2000;       // max entries per tenant in memory
const CACHE_TTL  = 5 * 60 * 1000; // 5-min TTL before re-reading from disk
const _cacheTime = new Map(); // tenantId → timestamp of last disk-read

function _ensureCache(tenantId) {
  const age = Date.now() - (_cacheTime.get(tenantId) || 0);
  if (_memCache.has(tenantId) && age < CACHE_TTL) return;
  // Read from disk (synchronous but only once per 5 min)
  const filePath = path.join(AUDIT_DIR, tenantId + '.jsonl');
  if (!fs.existsSync(filePath)) { _memCache.set(tenantId, []); _cacheTime.set(tenantId, Date.now()); return; }
  try {
    const lines = fs.readFileSync(filePath, 'utf8').split('\n').filter(Boolean).map(l => { try { return JSON.parse(l); } catch { return null; } }).filter(Boolean);
    _memCache.set(tenantId, lines.slice(-CACHE_MAX)); // keep newest CACHE_MAX
    _cacheTime.set(tenantId, Date.now());
  } catch { _memCache.set(tenantId, []); _cacheTime.set(tenantId, Date.now()); }
}

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

  // Update in-memory cache immediately (no disk read needed)
  _ensureCache(tenantId);
  const cached = _memCache.get(tenantId) || [];
  cached.push(entry);
  if (cached.length > CACHE_MAX) cached.splice(0, cached.length - CACHE_MAX);
  _memCache.set(tenantId, cached);

  // Async fire-and-forget — never blocks the event loop
  const filePath = path.join(AUDIT_DIR, tenantId + '.jsonl');
  fs.appendFile(filePath, JSON.stringify(entry) + '\n', err => {
    if (err) console.error('[AuditLog] Write error:', err.message);
  });
}

function getLog(tenantId, options = {}) {
  _ensureCache(tenantId);
  let entries = [...(_memCache.get(tenantId) || [])].reverse(); // newest first

  if (options.action)   entries = entries.filter(e => e.action === options.action);
  if (options.actor)    entries = entries.filter(e => e.actor  === options.actor);
  if (options.since)    entries = entries.filter(e => new Date(e.timestamp) >= new Date(options.since));
  if (options.limit)    entries = entries.slice(0, options.limit);

  return entries;
}

function getStats(tenantId) {
  _ensureCache(tenantId);
  const entries = _memCache.get(tenantId) || [];
  return {
    total:           entries.length,
    last7Days:       entries.filter(e => new Date(e.timestamp) > new Date(Date.now() - 7*24*3600*1000)).length,
    alertsDetected:  entries.filter(e => e.action === ACTIONS.ALERT_DETECTED).length,
    sessionsRevoked: entries.filter(e => e.action === ACTIONS.SESSION_REVOKED).length,
    settingsChanges: entries.filter(e => e.action.startsWith('settings.')).length,
    lastActivity:    entries[entries.length - 1]?.timestamp || null
  };
}

module.exports = { log, getLog, getStats, ACTIONS };
