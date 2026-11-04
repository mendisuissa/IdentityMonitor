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
//
// Every change is an updater: a function of the current workflow that returns a patch (or null
// for no change). While a workflow is not cached yet, updaters wait in its queue (_queues) for
// the stored row; they then run in order, each on the state left by the one before. If the read
// fails, the queued updaters are kept and the read is retried with backoff; nothing is dropped.
const _cache = new Map();   // `${tenantId}:${alertId}` → wf
const _dirty = new Set();   // keys whose cached state is not yet persisted
const _persist = new Map(); // key → { running, promise, attempt, timer }
const _loads = new Map();   // key → in-flight Table read (shared by concurrent callers)
const _queues = new Map();  // key → { ops, view, draining, attempt, timer } waiting for the read

const RETRY_BASE_MS = Number(process.env.WORKFLOW_PERSIST_RETRY_MS) || 2000;
const RETRY_MAX_MS  = 5 * 60 * 1000;
function retryDelay(attempt) { return Math.min(RETRY_MAX_MS, RETRY_BASE_MS * 2 ** (attempt - 1)); }

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
    // a patch queued behind this read may already have set it; a missing row caches the defaults
    if (!_cache.has(k)) _cache.set(k, wf || normalizeWorkflow({ ...defaultWorkflow() }));
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
  if (_queues.has(k)) return normalizeWorkflow({ ..._queues.get(k).view }); // optimistic, pending read
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
          const delay = retryDelay(st.attempt);
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

// Runs an updater against `base` and applies its patch. The updater gets its own copy.
function applyUpdate(tenantId, alertId, base, updater, actor) {
  const patch = updater(normalizeWorkflow({ ...base }), { preview: false });
  return applyLocal(tenantId, alertId, base, patch, actor);
}

// The optimistic result of an updater on `base`, without caching, writing or logging anything.
// Updaters receive { preview: true } here and must not cause side effects in that case.
function previewUpdate(base, updater) {
  const current = normalizeWorkflow({ ...base });
  const patch = updater(normalizeWorkflow({ ...base }), { preview: true });
  if (!changedFields(current, patch).length) return current;
  return normalizeWorkflow({ ...current, ...patch, updatedAt: new Date().toISOString() });
}

// Reads the stored row for a queued workflow, then runs every queued updater in order. On a read
// error the updaters stay queued and the read is retried with backoff. Callers awaiting an
// updater get its optimistic result then, so a request never hangs on a Table outage.
async function drainQueue(tenantId, alertId, fromTimer = false) {
  const k = _key(tenantId, alertId);
  const q = _queues.get(k);
  if (!q || q.draining) return;
  if (q.timer && !fromTimer) return; // a read retry is already scheduled; keep the backoff
  q.timer = null;
  q.draining = true;
  try {
    let stored;
    if (!_cache.has(k)) {
      try {
        stored = await loadStored(tenantId, alertId);
      } catch (err) {
        q.attempt += 1;
        const delay = retryDelay(q.attempt);
        console.error(`[WorkflowStore] read error, ${q.ops.length} queued update(s) kept (attempt ${q.attempt}, retry in ${delay} ms):`, err.message);
        q.timer = setTimeout(() => drainQueue(tenantId, alertId, true), delay);
        if (q.timer.unref) q.timer.unref();
        for (const op of q.ops) if (op.resolve) { op.resolve(normalizeWorkflow({ ...op.optimistic })); op.resolve = null; }
        return;
      }
      if (!_cache.has(k)) _cache.set(k, stored || normalizeWorkflow({ ...defaultWorkflow() }));
    }
    while (q.ops.length) {
      const op = q.ops.shift();
      const base = _cache.get(k) || defaultWorkflow();
      let next;
      try {
        next = applyUpdate(tenantId, alertId, base, op.updater, op.actor);
      } catch (err) {
        console.error('[WorkflowStore] update error:', err.message);
        next = normalizeWorkflow({ ...base });
      }
      if (op.resolve) op.resolve(next);
    }
    _queues.delete(k);
  } finally {
    q.draining = false;
  }
}

// Applies `updater(currentWorkflow, { preview }) → patch | null` to a workflow. The updater runs
// once on the real state (preview false) and possibly once for the optimistic view (preview true). Returns { value, done }:
// value is the result now (exact when the workflow is cached and nothing is queued, otherwise
// the best-effort optimistic view), done resolves once the updater has run on the real state.
function submitUpdate(tenantId, alertId, updater, actor = 'system') {
  const k = _key(tenantId, alertId);
  if (_cache.has(k) && !_queues.has(k)) {
    const value = applyUpdate(tenantId, alertId, _cache.get(k), updater, actor);
    return { value, done: Promise.resolve(value) };
  }
  let q = _queues.get(k);
  if (!q) {
    q = { ops: [], view: normalizeWorkflow({ ...(_cache.get(k) || defaultWorkflow()) }), draining: false, attempt: 0, timer: null };
    _queues.set(k, q);
  }
  q.view = previewUpdate(q.view, updater);
  let resolve;
  const done = new Promise((r) => { resolve = r; });
  const op = { updater, actor, resolve, optimistic: q.view };
  q.ops.push(op);
  if (q.timer) {
    // The read is in error backoff: answer now with the optimistic view, keep the op queued.
    resolve(normalizeWorkflow({ ...q.view }));
    op.resolve = null;
  }
  drainQueue(tenantId, alertId).catch(err => console.error('[WorkflowStore] queue error:', err.message));
  return { value: normalizeWorkflow({ ...q.view }), done };
}

async function patchAlertWorkflowAsync(tenantId, alertId, patch, actor = 'system') {
  const k = _key(tenantId, alertId);
  const next = await submitUpdate(tenantId, alertId, () => patch, actor).done;
  const st = _persist.get(k);
  if (st && st.running) await st.promise;
  return next;
}

function patchAlertWorkflow(tenantId, alertId, patch, actor = 'system') {
  return submitUpdate(tenantId, alertId, () => patch, actor).value;
}

// Read-modify-write: `updater(currentWorkflow, { preview })` returns a patch or null. Use this
// instead of patching with values computed from getAlertWorkflow(), which on a cold cache is
// defaults or an optimistic view, never the stored workflow.
function updateAlertWorkflow(tenantId, alertId, updater, actor = 'system') {
  return submitUpdate(tenantId, alertId, updater, actor).value;
}

// True when the workflow's stored state is in the cache and no update is waiting for its read.
// On false, starts the read so a later call can return true.
function isWorkflowLoaded(tenantId, alertId) {
  const k = _key(tenantId, alertId);
  if (_cache.has(k) && !_queues.has(k)) return true;
  if (!_cache.has(k)) getAlertWorkflowAsync(tenantId, alertId).catch(() => {});
  return false;
}

// Number of workflows with changes not yet in Table Storage: failed or pending writes, plus
// updates still waiting for the stored row (for health checks/tests).
function unpersistedCount() { return new Set([..._dirty, ..._queues.keys()]).size; }

function parseMentions(message = '') {
  return Array.from(new Set((String(message).match(/@[a-zA-Z0-9._-]+@[a-zA-Z0-9.-]+/g) || []).map(m => m.slice(1).toLowerCase())));
}

// Read-modify-write helpers run as updaters, so on a cold cache they see the stored workflow plus
// every update queued before them, not defaults.
function addComment(tenantId, alertId, comment, actor = 'system') {
  const mentions = parseMentions(comment);
  const entry = { id: `c_${Date.now()}`, actor, message: comment, mentions, createdAt: new Date().toISOString() };
  const { value } = submitUpdate(tenantId, alertId, wf => ({
    comments: [...(wf.comments || []), entry],
    mentions: Array.from(new Set([...(wf.mentions || []), ...mentions]))
  }), actor);
  for (const mention of mentions) {
    notificationCenter.enqueue(tenantId, { type: 'mention', severity: 'medium', target: mention, title: `Mentioned in case ${alertId}`, detail: `${actor} mentioned @${mention}`, metadata: { alertId, actor } });
  }
  return value;
}

function progressApproval(tenantId, alertId, decision = 'approved', actor = 'system', note = '') {
  const decidedAt = new Date().toISOString();
  return submitUpdate(tenantId, alertId, wf => {
    const steps = (wf.approvalSteps || []).map(s => ({ ...s }));
    const current = steps.find(s => s.status === 'pending');
    if (!current) return null;
    current.status = decision; current.actor = actor; current.decidedAt = decidedAt;
    if (note) current.note = note;
    const history = [...(wf.approvalHistory || []), { step: current.step, role: current.role, decision, actor, note, timestamp: decidedAt }];
    const approvedAll = steps.every(s => s.status === 'approved');
    const rejectedAny = steps.some(s => s.status === 'rejected');
    return {
      approvalSteps: steps, approvalHistory: history,
      approvalStatus: rejectedAny ? 'rejected' : approvedAll ? 'approved' : 'pending',
      caseStatus: rejectedAny ? 'triage' : approvedAll ? 'ready_to_execute' : wf.caseStatus
    };
  }, actor).value;
}

function getCases(tenantId) {
  const alerts = alertsStore.getAll(tenantId);
  const now = Date.now();
  return alerts.map(alert => {
    const wf = getAlertWorkflow(tenantId, alert.id);
    const dueTs = wf.dueAt ? new Date(wf.dueAt).getTime() : null;
    const isOverdue = !!dueTs && dueTs < now && wf.caseStatus !== 'closed';
    if (isOverdue && !wf.slaBreachedAt) {
      // Decide and apply the breach on the loaded state; never write the (possibly optimistic)
      // view back as a patch, which would overwrite stored owner, comments and approvals.
      const breachedAt = new Date().toISOString();
      const updated = updateAlertWorkflow(tenantId, alert.id, (cur, { preview }) => {
        const curDue = cur.dueAt ? new Date(cur.dueAt).getTime() : null;
        if (!curDue || curDue >= Date.now() || cur.caseStatus === 'closed' || cur.slaBreachedAt) return null;
        if (!preview) auditLog.log(tenantId, 'case.sla_breached', { alertId: alert.id, severity: alert.severity }, 'system');
        return { slaBreachedAt: breachedAt, escalationLevel: Math.max(1, cur.escalationLevel || 0) };
      }, 'system');
      Object.assign(wf, { slaBreachedAt: updated.slaBreachedAt, escalationLevel: updated.escalationLevel });
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
      if (_dirty.has(k) || _queues.has(k)) continue;
      const wf = normalizeWorkflow({ ...defaultWorkflow(), ...fromEntity(entity) });
      _cache.set(k, wf);
    }
    console.log('[WorkflowStore] Cache warmed for tenant:', tenantId);
  } catch (err) {
    console.warn('[WorkflowStore] warmCache error:', err.message);
  }
}

module.exports = { getAlertWorkflow, getAlertWorkflowAsync, patchAlertWorkflow, patchAlertWorkflowAsync, changedFields, addComment, progressApproval, getCases, getWorkflowStats, parseMentions, warmCache, unpersistedCount, submitUpdate, updateAlertWorkflow, isWorkflowLoaded };
