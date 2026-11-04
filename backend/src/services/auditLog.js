// auditLog.js — compliance audit trail
// Stored in /home/audit/{tenantId}.jsonl (newline-delimited JSON)
// Uses an in-memory write buffer + async flush to avoid blocking the event loop
// on Azure App Service's slow SMB-backed /home filesystem.

const fs   = require('fs');
const path = require('path');

const AUDIT_DIR = process.env.AUDIT_DIR || (process.env.NODE_ENV === 'production'
  ? '/home/audit'
  : path.join(__dirname, '../../../audit'));

if (!fs.existsSync(AUDIT_DIR)) fs.mkdirSync(AUDIT_DIR, { recursive: true });

// Only allow tenant IDs that are safe to use as file names (UUIDs, domains, alphanumeric).
// Blocks path traversal: '../', '../../etc/passwd', etc.
function sanitizeTenantId(tenantId) {
  if (!tenantId || typeof tenantId !== 'string') return null;
  const safe = tenantId.replace(/[^a-zA-Z0-9._-]/g, '_').slice(0, 128);
  // Reject anything that still looks like a traversal after sanitization
  if (safe.includes('..') || safe.startsWith('.')) return null;
  return safe;
}

// ── In-memory cache ───────────────────────────────────────────────────────────
// Keeps recent entries in memory to avoid repeated synchronous disk reads.
const _memCache  = new Map(); // tenantId → entry[]
const CACHE_MAX  = 2000;       // max entries per tenant in memory
const CACHE_TTL  = 5 * 60 * 1000; // 5-min TTL before re-reading from disk
const _cacheTime = new Map(); // tenantId → timestamp of last disk-read

// _ensureCache — never does disk I/O on the request path.
// Cache is pre-populated at startup via warmCache(tenantId).
// If somehow a tenant wasn't warmed, we just serve an empty array
// (better than blocking the event loop with a synchronous SMB read).
function _ensureCache(tenantId) {
  if (!_memCache.has(tenantId)) {
    _memCache.set(tenantId, []);
    _cacheTime.set(tenantId, Date.now());
  }
}

// warmCache — async (non-blocking) — call from startup for each known tenant.
// Reads only file tails: the cache holds at most CACHE_MAX entries, and reading a multi-GB file
// whole fails (V8 string limit), which used to leave the audit view empty. When the live file
// holds fewer than CACHE_MAX entries (it was rotated recently), the rest of the window is filled
// from the tails of the newest archives, so recent history survives rotation plus a restart.
const WARM_TAIL_BYTES     = 4 * 1024 * 1024; // per file
const WARM_MAX_ARCHIVES   = 3;               // newest archives consulted at most

// Parsed entries from the last maxBytes of a JSONL file ([] if it cannot be read).
async function readTailEntries(filePath, maxBytes) {
  let content;
  try {
    const fh = await fs.promises.open(filePath, 'r');
    try {
      const { size } = await fh.stat();
      const start = Math.max(0, size - maxBytes);
      const buf = Buffer.alloc(size - start);
      await fh.read(buf, 0, buf.length, start);
      content = buf.toString('utf8');
      if (start > 0) content = content.slice(content.indexOf('\n') + 1); // drop the partial first line
    } finally {
      await fh.close();
    }
  } catch {
    return [];
  }
  return content.split('\n').filter(Boolean)
    .map(l => { try { return JSON.parse(l); } catch { return null; } })
    .filter(Boolean);
}

// This tenant's archive files, newest first. Names are `<safe>.<ISO stamp>.jsonl`; the stamp has
// a fixed shape, so another tenant whose id starts with `<safe>.` never matches, and the stamp
// sorts chronologically as text.
async function listArchives(safe) {
  const archiveDir = path.join(AUDIT_DIR, 'archive');
  const escaped = safe.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const re = new RegExp(`^${escaped}\\.(\\d{4}-\\d{2}-\\d{2}T\\d{2}-\\d{2}-\\d{2}-\\d{3}Z)\\.jsonl$`);
  let names;
  try { names = await fs.promises.readdir(archiveDir); } catch { return []; }
  return names
    .map(n => { const m = re.exec(n); return m ? { name: n, stamp: m[1] } : null; })
    .filter(Boolean)
    .sort((a, b) => (a.stamp < b.stamp ? 1 : a.stamp > b.stamp ? -1 : 0))
    .map(a => path.join(archiveDir, a.name));
}

async function warmCache(tenantId) {
  if (!tenantId) return;
  const safe = sanitizeTenantId(tenantId);
  if (!safe) return;
  try {
    let entries = await readTailEntries(path.join(AUDIT_DIR, safe + '.jsonl'), WARM_TAIL_BYTES);
    if (entries.length < CACHE_MAX) {
      const archives = (await listArchives(safe)).slice(0, WARM_MAX_ARCHIVES);
      for (const file of archives) {
        const older = await readTailEntries(file, WARM_TAIL_BYTES);
        entries = older.concat(entries);
        if (entries.length >= CACHE_MAX) break;
      }
    }
    _memCache.set(tenantId, entries.slice(-CACHE_MAX));
    _cacheTime.set(tenantId, Date.now());
  } catch {
    _memCache.set(tenantId, []);
    _cacheTime.set(tenantId, Date.now());
  }
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
  const safe = sanitizeTenantId(tenantId);
  if (!safe) return;
  const entry = {
    timestamp: new Date().toISOString(),
    tenantId: safe,
    action,
    actor,  // email or 'system' or 'auto'
    ...details
  };

  // Update in-memory cache immediately (no disk read needed)
  _ensureCache(safe);
  const cached = _memCache.get(safe) || [];
  cached.push(entry);
  if (cached.length > CACHE_MAX) cached.splice(0, cached.length - CACHE_MAX);
  _memCache.set(safe, cached);

  // Async fire-and-forget — never blocks the event loop
  const filePath = path.join(AUDIT_DIR, safe + '.jsonl');
  fs.appendFile(filePath, JSON.stringify(entry) + '\n', err => {
    if (err) console.error('[AuditLog] Write error:', err.message);
    else _maybeRotate(safe, filePath);
  });
}

// ── Rotation ──────────────────────────────────────────────────────────────────
// The live file is rotated into AUDIT_DIR/archive/ once it passes ROTATE_BYTES. Archived files
// are kept; nothing is deleted. archive/ is a directory, so tenantRegistry never reads it as a
// tenant file.
const ROTATE_BYTES       = Number(process.env.AUDIT_ROTATE_BYTES) || 50 * 1024 * 1024;
const ROTATE_CHECK_EVERY = 500;       // stat the file on the first write and every 500th after
const _writeCount = new Map();      // tenantId → writes since start

function _maybeRotate(safe, filePath) {
  const n = (_writeCount.get(safe) || 0) + 1;
  _writeCount.set(safe, n);
  if (n % ROTATE_CHECK_EVERY !== 1) return;
  fs.stat(filePath, (err, st) => {
    if (err || st.size < ROTATE_BYTES) return;
    const archiveDir = path.join(AUDIT_DIR, 'archive');
    fs.mkdir(archiveDir, { recursive: true }, mkErr => {
      if (mkErr) return console.error('[AuditLog] Rotate error:', mkErr.message);
      const stamp = new Date().toISOString().replace(/[:.]/g, '-');
      fs.rename(filePath, path.join(archiveDir, `${safe}.${stamp}.jsonl`), e => {
        if (e) console.error('[AuditLog] Rotate error:', e.message);
      });
    });
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

module.exports = { log, getLog, getStats, warmCache, ACTIONS };
