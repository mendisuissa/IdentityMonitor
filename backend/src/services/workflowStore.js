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
const _cache = new Map(); // `${tenantId}:${alertId}` → wf

function _key(tenantId, alertId) { return `${tenantId}:${alertId}`; }

// ─── Core CRUD ────────────────────────────────────────────────────────────
async function getAlertWorkflowAsync(tenantId, alertId) {
  const k = _key(tenantId, alertId);
  if (_cache.has(k)) return normalizeWorkflow({ ..._cache.get(k) });
  try {
    const rowKey = alertId.replace(/[^a-zA-Z0-9_-]/g, '_');
    const entity = await getClient().getEntity(tenantId, rowKey);
    const wf = normalizeWorkflow({ ...defaultWorkflow(), ...fromEntity(entity) });
    _cache.set(k, wf);
    return wf;
  } catch (err) {
    if (err.statusCode === 404) {
      const wf = normalizeWorkflow({ ...defaultWorkflow() });
      return wf;
    }
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

async function patchAlertWorkflowAsync(tenantId, alertId, patch, actor = 'system') {
  const existing = await getAlertWorkflowAsync(tenantId, alertId);
  const next = normalizeWorkflow({ ...existing, ...patch, updatedAt: new Date().toISOString() });
  const k = _key(tenantId, alertId);
  _cache.set(k, next);
  try {
    await getClient().upsertEntity(toEntity(tenantId, alertId, next), 'Replace');
  } catch (err) {
    console.error('[WorkflowStore] patch error:', err.message);
  }
  auditLog.log(tenantId, 'workflow.updated', { alertId, patch }, actor);
  return next;
}

function patchAlertWorkflow(tenantId, alertId, patch, actor = 'system') {
  // Optimistic cache update, async persist
  const k = _key(tenantId, alertId);
  const existing = _cache.get(k) || defaultWorkflow();
  const next = normalizeWorkflow({ ...existing, ...patch, updatedAt: new Date().toISOString() });
  _cache.set(k, next);
  patchAlertWorkflowAsync(tenantId, alertId, patch, actor).catch(err =>
    console.error('[WorkflowStore] async patch error:', err.message)
  );
  auditLog.log(tenantId, 'workflow.updated', { alertId, patch }, actor);
  return next;
}

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
      const wf = normalizeWorkflow({ ...defaultWorkflow(), ...fromEntity(entity) });
      _cache.set(_key(tenantId, alertId), wf);
    }
    console.log('[WorkflowStore] Cache warmed for tenant:', tenantId);
  } catch (err) {
    console.warn('[WorkflowStore] warmCache error:', err.message);
  }
}

module.exports = { getAlertWorkflow, getAlertWorkflowAsync, patchAlertWorkflow, patchAlertWorkflowAsync, addComment, progressApproval, getCases, getWorkflowStats, parseMentions, warmCache };
