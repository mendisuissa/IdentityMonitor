// workflowStore.js — case workflow persisted to Azure Table Storage
// Table: workflows — PartitionKey=tenantId, RowKey=alertId
const { TableClient } = require('@azure/data-tables');
const alertsStore = require('./alertsStore');
const auditLog = require('./auditLog');
const notificationCenter = require('./notificationCenterService');

const TABLE_NAME = 'workflows';
let _client = null;

function getClient() {
  if (_client) return _client;
  const connStr = process.env.AZURE_STORAGE_CONNECTION_STRING;
  if (!connStr) throw new Error('AZURE_STORAGE_CONNECTION_STRING not configured');
  _client = TableClient.fromConnectionString(connStr, TABLE_NAME);
  return _client;
}

// Create table on first use (idempotent)
async function ensureTable() {
  try { await getClient().createTable(); } catch (err) { if (err.statusCode !== 409) throw err; }
}
ensureTable().catch(err => console.warn('[WorkflowStore] Table init:', err.message));

// ─── Serialization helpers ────────────────────────────────────────────────
function toEntity(tenantId, alertId, wf) {
  return {
    partitionKey: tenantId,
    rowKey:       alertId.replace(/[^a-zA-Z0-9_-]/g, '_'),
    owner:           wf.owner || '',
    note:            wf.note || '',
    suppressReason:  wf.suppressReason || '',
    confidence:      wf.confidence || 'medium',
    caseStatus:      wf.caseStatus || 'open',
    approvalStatus:  wf.approvalStatus || 'pending',
    requestedAction: wf.requestedAction || 'monitor',
    dueAt:           wf.dueAt || new Date(Date.now() + 24*3600*1000).toISOString(),
    escalationLevel: wf.escalationLevel || 0,
    slaBreachedAt:   wf.slaBreachedAt || '',
    updatedAt:       wf.updatedAt || new Date().toISOString(),
    comments:        JSON.stringify(wf.comments || []),
    mentions:        JSON.stringify(wf.mentions || []),
    approvalSteps:   JSON.stringify(wf.approvalSteps || []),
    approvalHistory: JSON.stringify(wf.approvalHistory || []),
    notifications:   JSON.stringify(wf.notifications || []),
    automationActions: JSON.stringify(wf.automationActions || []),
    runbookSteps:    JSON.stringify(wf.runbookSteps || [])
  };
}

function fromEntity(entity) {
  function tryParse(v, fallback = []) { try { return typeof v === 'string' ? JSON.parse(v) : (v ?? fallback); } catch { return fallback; } }
  return {
    owner:            entity.owner || '',
    note:             entity.note || '',
    suppressReason:   entity.suppressReason || '',
    confidence:       entity.confidence || 'medium',
    caseStatus:       entity.caseStatus || 'open',
    approvalStatus:   entity.approvalStatus || 'pending',
    requestedAction:  entity.requestedAction || 'monitor',
    dueAt:            entity.dueAt || new Date(Date.now() + 24*3600*1000).toISOString(),
    escalationLevel:  entity.escalationLevel || 0,
    slaBreachedAt:    entity.slaBreachedAt || '',
    updatedAt:        entity.updatedAt || new Date().toISOString(),
    comments:         tryParse(entity.comments),
    mentions:         tryParse(entity.mentions),
    approvalSteps:    tryParse(entity.approvalSteps),
    approvalHistory:  tryParse(entity.approvalHistory),
    notifications:    tryParse(entity.notifications),
    automationActions: tryParse(entity.automationActions),
    runbookSteps:     tryParse(entity.runbookSteps)
  };
}

function defaultWorkflow() {
  return {
    owner: '', note: '', suppressReason: '', confidence: 'medium',
    caseStatus: 'open', approvalStatus: 'pending', requestedAction: 'monitor',
    dueAt: new Date(Date.now() + 24*3600*1000).toISOString(),
    escalationLevel: 0, slaBreachedAt: '', updatedAt: new Date().toISOString(),
    comments: [], mentions: [], approvalSteps: [], approvalHistory: [],
    notifications: [], automationActions: [], runbookSteps: []
  };
}

function normalizeWorkflow(wf) {
  const now = Date.now();
  const dueTs = wf.dueAt ? new Date(wf.dueAt).getTime() : null;
  wf.isOverdue = !!dueTs && dueTs < now && wf.caseStatus !== 'closed';
  ['comments','mentions','approvalSteps','approvalHistory','notifications','automationActions','runbookSteps'].forEach(k => { if (!Array.isArray(wf[k])) wf[k] = []; });
  return wf;
}

// ─── In-memory write-through cache ───────────────────────────────────────
// _cache holds the newest known state of each workflow, which may be ahead of Table Storage.
// Writes go through a per-workflow persist loop that always writes the newest cached state, one
// upsert at a time, so a slow earlier Replace can never land after (and erase) a later one.
// A workflow whose newest state has not been written yet is in _dirty; a failed upsert is
// retried with backoff, and any later patch (even one that changes nothing) retries it at once.
const _cache = new Map();   // `${tenantId}:${alertId}` → wf
const _dirty = new Set();   // keys whose cached state is not yet persisted
const _persist = new Map(); // key → { running, promise, attempt, timer }
const _loads = new Map();   // key → in-flight Table read (shared by concurrent callers)
const _chains = new Map();  // key → tail of the queue of patches waiting for the first read

const RETRY_BASE_MS = Number(process.env.WORKFLOW_PERSIST_RETRY_MS) || 2000;
const RETRY_MAX_MS  = 5 * 60 * 1000;

function _key(tenantId, alertId) { return `${tenantId}:${alertId}`; }

// Reads the stored workflow once per key at a time. Resolves null when the row does not exist;
// rejects on any other read error.
function loadStored(tenantId, alertId) {
  const k = _key(tenantId, alertId);
  if (_loads.has(k)) return _loads.get(k);
  const p = (async () => {
    try {
      const rowKey = alertId.replace(/[^a-zA-Z0-9_-]/g, '_');
      const entity = await getClient().getEntity(tenantId, rowKey);
      return normalizeWorkflow({ ...defaultWorkflow(), ...fromEntity(entity) });
    } catch (err) {
      if (err.statusCode === 404) return null;
      throw err;
    }
  })();
  _loads.set(k, p);
  p.then(() => _loads.delete(k), () => _loads.delete(k));
  return p;
}

// ─── Core CRUD ────────────────────────────────────────────────────────────
async function getAlertWorkflowAsync(tenantId, alertId) {
  const k = _key(tenantId, alertId);
  if (_cache.has(k)) return normalizeWorkflow({ ..._cache.get(k) });
  try {
    const wf = await loadStored(tenantId, alertId);
    if (!wf) return normalizeWorkflow({ ...defaultWorkflow() });
    if (!_cache.has(k)) _cache.set(k, wf); // a patch queued behind this read may already have set it
    return normalizeWorkflow({ ..._cache.get(k) });
  } catch (err) {
    console.warn('[WorkflowStore] getAlertWorkflow error:', err.message);
    return normalizeWorkflow({ ...defaultWorkflow() });
  }
}

// Sync version for backward compat — returns cache or default, fires async fetch
function getAlertWorkflow(tenantId, alertId) {
  const k = _key(tenantId, alertId);
  if (_cache.has(k)) return normalizeWorkflow({ ..._cache.get(k) });
  // Fire async fetch to warm cache for next call
  getAlertWorkflowAsync(tenantId, alertId).catch(() => {});
  return normalizeWorkflow({ ...defaultWorkflow() });
}

// Fields of `patch` whose value differs from `existing`. updatedAt is ignored.
function changedFields(existing, patch) {
  return Object.keys(patch || {}).filter(key =>
    key !== 'updatedAt' && JSON.stringify(patch[key]) !== JSON.stringify(existing[key]));
}

// One audit entry per real change. Automated (system) patches record only the changed field
// names: the automation sweep re-patches every open alert, and logging the full patch (with its
// growing automationActions list) filled /home/audit with multiple GB.
function logUpdate(tenantId, alertId, patch, fields, actor) {
  const details = actor === 'system' ? { alertId, fields } : { alertId, patch };
  auditLog.log(tenantId, 'workflow.updated', details, actor);
}

// Writes the newest cached state of a workflow. Only one upsert per workflow runs at a time; a
// change made while one is in flight is written right after it. Resolves when the workflow is
// clean or the current attempt failed (a retry is then scheduled). Never rejects.
function schedulePersist(tenantId, alertId) {
  const k = _key(tenantId, alertId);
  _dirty.add(k);
  let st = _persist.get(k);
  if (!st) { st = { running: false, promise: null, attempt: 0, timer: null }; _persist.set(k, st); }
  if (st.running) return st.promise; // the running loop re-checks the cache after its upsert
  if (st.timer) { clearTimeout(st.timer); st.timer = null; }
  st.running = true;
  st.promise = (async () => {
    try {
      while (_dirty.has(k)) {
        const snapshot = _cache.get(k);
        if (!snapshot) { _dirty.delete(k); break; }
        try {
          await getClient().upsertEntity(toEntity(tenantId, alertId, snapshot), 'Replace');
        } catch (err) {
          st.attempt += 1;
          const delay = Math.min(RETRY_MAX_MS, RETRY_BASE_MS * 2 ** (st.attempt - 1));
          console.error(`[WorkflowStore] patch error (attempt ${st.attempt}, retry in ${delay} ms):`, err.message);
          st.timer = setTimeout(() => { st.timer = null; schedulePersist(tenantId, alertId); }, delay);
          if (st.timer.unref) st.timer.unref();
          return;
        }
        st.attempt = 0;
        if (_cache.get(k) === snapshot) _dirty.delete(k); // otherwise a newer change arrived: loop
      }
    } finally {
      st.running = false;
    }
  })();
  return st.promise;
}

// Merges a patch into `base` (the latest known state). A patch that changes nothing is not
// written or logged, but it does retry a workflow whose last write failed.
function applyLocal(tenantId, alertId, base, patch, actor) {
  const k = _key(tenantId, alertId);
  const existing = normalizeWorkflow({ ...base });
  const fields = changedFields(existing, patch);
  if (!fields.length) {
    if (_dirty.has(k)) schedulePersist(tenantId, alertId);
    return existing;
  }
  const next = normalizeWorkflow({ ...existing, ...patch, updatedAt: new Date().toISOString() });
  _cache.set(k, next);
  logUpdate(tenantId, alertId, patch, fields, actor);
  schedulePersist(tenantId, alertId);
  return next;
}

// Runs fn after every patch already queued for this workflow.
function enqueue(k, fn) {
  const prev = _chains.get(k) || Promise.resolve();
  const run = prev.then(fn);
  const tail = run.catch(() => {});
  _chains.set(k, tail);
  tail.then(() => { if (_chains.get(k) === tail) _chains.delete(k); });
  return run;
}

// Queued patch step: merge against the cache if it is warm, else against the stored row (read
// once and cached). A read error other than 404 rejects instead of merging into defaults, which
// would overwrite the stored workflow with a Replace.
async function queuedApply(tenantId, alertId, patch, actor) {
  const k = _key(tenantId, alertId);
  if (!_cache.has(k)) {
    const stored = await loadStored(tenantId, alertId);
    if (stored && !_cache.has(k)) _cache.set(k, stored);
  }
  return applyLocal(tenantId, alertId, _cache.get(k) || defaultWorkflow(), patch, actor);
}

async function patchAlertWorkflowAsync(tenantId, alertId, patch, actor = 'system') {
  const k = _key(tenantId, alertId);
  const next = await enqueue(k, () => queuedApply(tenantId, alertId, patch, actor));
  const st = _persist.get(k);
  if (st && st.running) await st.promise;
  return next;
}

function patchAlertWorkflow(tenantId, alertId, patch, actor = 'system') {
  const k = _key(tenantId, alertId);
  if (_cache.has(k) && !_chains.has(k)) {
    // Warm cache and nothing queued: merge now, persist in the background.
    return applyLocal(tenantId, alertId, _cache.get(k), patch, actor);
  }
  // Cache miss, or earlier patches still wait for the first read: queue behind them, so each
  // patch merges against the state left by the one before it (never an independent snapshot).
  enqueue(k, () => queuedApply(tenantId, alertId, patch, actor)).catch(err =>
    console.error('[WorkflowStore] async patch error:', err.message)
  );
  return normalizeWorkflow({ ...(_cache.get(k) || defaultWorkflow()), ...patch, updatedAt: new Date().toISOString() });
}

// Number of workflows whose newest state is not yet in Table Storage (for health checks/tests).
function unpersistedCount() { return _dirty.size; }

function parseMentions(message = '') {
  return Array.from(new Set((String(message).match(/@[a-zA-Z0-9._-]+@[a-zA-Z0-9.-]+/g) || []).map(m => m.slice(1).toLowerCase())));
}

function addComment(tenantId, alertId, comment, actor = 'system') {
  const wf = getAlertWorkflow(tenantId, alertId);
  const mentions = parseMentions(comment);
  const comments = [...(wf.comments || []), { id: `c_${Date.now()}`, actor, message: comment, mentions, createdAt: new Date().toISOString() }];
  const updated = patchAlertWorkflow(tenantId, alertId, {
    comments,
    mentions: Array.from(new Set([...(wf.mentions || []), ...mentions]))
  }, actor);
  for (const mention of mentions) {
    notificationCenter.enqueue(tenantId, { type: 'mention', severity: 'medium', target: mention, title: `Mentioned in case ${alertId}`, detail: `${actor} mentioned @${mention}`, metadata: { alertId, actor } });
  }
  return updated;
}

function progressApproval(tenantId, alertId, decision = 'approved', actor = 'system', note = '') {
  const wf = getAlertWorkflow(tenantId, alertId);
  const steps = (wf.approvalSteps || []).map(s => ({ ...s }));
  const current = steps.find(s => s.status === 'pending');
  if (!current) return wf;
  current.status = decision; current.actor = actor; current.decidedAt = new Date().toISOString();
  if (note) current.note = note;
  const history = [...(wf.approvalHistory || []), { step: current.step, role: current.role, decision, actor, note, timestamp: new Date().toISOString() }];
  const approvedAll = steps.every(s => s.status === 'approved');
  const rejectedAny = steps.some(s => s.status === 'rejected');
  return patchAlertWorkflow(tenantId, alertId, {
    approvalSteps: steps, approvalHistory: history,
    approvalStatus: rejectedAny ? 'rejected' : approvedAll ? 'approved' : 'pending',
    caseStatus: rejectedAny ? 'triage' : approvedAll ? 'ready_to_execute' : wf.caseStatus
  }, actor);
}

function getCases(tenantId) {
  const alerts = alertsStore.getAll(tenantId);
  const now = Date.now();
  return alerts.map(alert => {
    const wf = getAlertWorkflow(tenantId, alert.id);
    const dueTs = wf.dueAt ? new Date(wf.dueAt).getTime() : null;
    const isOverdue = !!dueTs && dueTs < now && wf.caseStatus !== 'closed';
    if (isOverdue && !wf.slaBreachedAt) {
      wf.slaBreachedAt = new Date().toISOString();
      wf.escalationLevel = Math.max(1, wf.escalationLevel || 0);
      patchAlertWorkflow(tenantId, alert.id, wf, 'system');
      auditLog.log(tenantId, 'case.sla_breached', { alertId: alert.id, severity: alert.severity }, 'system');
    }
    return {
      alertId: alert.id, title: alert.anomalyLabel, severity: alert.severity,
      status: alert.status, detectedAt: alert.detectedAt,
      userDisplayName: alert.userDisplayName, userPrincipalName: alert.userPrincipalName,
      tenantId: alert.tenantId || tenantId, ...wf,
      activeApprovalStep: (wf.approvalSteps || []).find(s => s.status === 'pending') || null,
      isOverdue
    };
  }).sort((a, b) => new Date(b.detectedAt) - new Date(a.detectedAt));
}

function getWorkflowStats(tenantId) {
  const cases = getCases(tenantId).filter(c => c.status === 'open');
  return {
    total: cases.length,
    overdue: cases.filter(c => c.isOverdue).length,
    pendingApproval: cases.filter(c => c.approvalStatus === 'pending').length,
    approved: cases.filter(c => c.approvalStatus === 'approved').length,
    commented: cases.filter(c => (c.comments || []).length > 0).length,
    assigned: cases.filter(c => c.owner).length,
    mentioned: cases.filter(c => (c.mentions || []).length > 0).length
  };
}

// Pre-warm cache for a tenant (call on startup or after scan)
async function warmCache(tenantId) {
  try {
    const iter = getClient().listEntities({ queryOptions: { filter: `PartitionKey eq '${tenantId}'` } });
    for await (const entity of iter) {
      const alertId = entity.rowKey;
      const k = _key(tenantId, alertId);
      // Never replace a newer, not-yet-persisted or queued state with the stored row.
      if (_dirty.has(k) || _chains.has(k)) continue;
      const wf = normalizeWorkflow({ ...defaultWorkflow(), ...fromEntity(entity) });
      _cache.set(k, wf);
    }
    console.log('[WorkflowStore] Cache warmed for tenant:', tenantId);
  } catch (err) {
    console.warn('[WorkflowStore] warmCache error:', err.message);
  }
}

module.exports = { getAlertWorkflow, getAlertWorkflowAsync, patchAlertWorkflow, patchAlertWorkflowAsync, changedFields, addComment, progressApproval, getCases, getWorkflowStats, parseMentions, warmCache, unpersistedCount };
