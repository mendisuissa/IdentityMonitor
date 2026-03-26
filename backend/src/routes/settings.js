const express  = require('express');
const router   = express.Router();
const settingsService = require('../services/settingsService');
const auditLog = require('../services/auditLog');
const workflowStore = require('../services/workflowStore');
const { ROLE_MATRIX, requirePermission, getAccessForRequest } = require('../services/accessControl');
const automationService = require('../services/automationService');
const notificationCenter = require('../services/notificationCenterService');

function getTenantId(req) {
  return req.session?.tenant?.tenantId || null;
}
function getActor(req) {
  return req.session?.tenant?.userEmail || 'unknown';
}
function requireAuth(req, res) {
  const tenantId = getTenantId(req);
  if (!tenantId && process.env.MOCK_MODE !== 'true') {
    res.status(401).json({ error: 'Not authenticated' });
    return null;
  }
  return tenantId || 'mock-tenant';
}

// GET /api/settings
router.get('/', (req, res) => {
  const tenantId = requireAuth(req, res);
  if (!tenantId) return;
  const settings = settingsService.getSettings(tenantId);
  const trial    = settingsService.getTrialStatus(tenantId);
  res.json({ ...settings, trialStatus: trial });
});

// PATCH /api/settings — update any settings section
router.patch('/', requirePermission('settings.manage'), (req, res) => {
  const tenantId = requireAuth(req, res);
  if (!tenantId) return;
  try {
    const updated = settingsService.saveSettings(tenantId, req.body);
    auditLog.log(tenantId, auditLog.ACTIONS.SETTINGS_UPDATED, {
      sections: Object.keys(req.body)
    }, getActor(req));
    res.json(updated);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/settings/trial
router.get('/trial', (req, res) => {
  const tenantId = requireAuth(req, res);
  if (!tenantId) return;
  res.json(settingsService.getTrialStatus(tenantId));
});

// POST /api/settings/admins — add admin
router.post('/admins', requirePermission('settings.manage'), (req, res) => {
  const tenantId = requireAuth(req, res);
  if (!tenantId) return;
  const { email, name, role = 'admin', telegramChatId } = req.body;
  if (!email) return res.status(400).json({ error: 'email required' });
  const updated = settingsService.addAdmin(tenantId, { email, name, role, telegramChatId });
  auditLog.log(tenantId, auditLog.ACTIONS.ADMIN_ADDED, { email, role }, getActor(req));
  res.json(updated.admins);
});

// DELETE /api/settings/admins/:email — remove admin
router.delete('/admins/:email', requirePermission('settings.manage'), (req, res) => {
  const tenantId = requireAuth(req, res);
  if (!tenantId) return;
  const updated = settingsService.removeAdmin(tenantId, req.params.email);
  auditLog.log(tenantId, auditLog.ACTIONS.ADMIN_REMOVED, { email: req.params.email }, getActor(req));
  res.json(updated.admins);
});

// POST /api/settings/whitelist/:type — add to whitelist
router.post('/whitelist/:type', (req, res) => {
  const tenantId = requireAuth(req, res);
  if (!tenantId) return;
  const { type } = req.params;
  const { value } = req.body;
  if (!['ips','countries','devices','users'].includes(type)) return res.status(400).json({ error: 'Invalid type' });
  if (!value) return res.status(400).json({ error: 'value required' });

  const s = settingsService.getSettings(tenantId);
  if (!s.whitelist[type].includes(value)) s.whitelist[type].push(value);
  const updated = settingsService.saveSettings(tenantId, { whitelist: s.whitelist });
  auditLog.log(tenantId, auditLog.ACTIONS.WHITELIST_UPDATED, { type, action: 'add', value }, getActor(req));
  res.json(updated.whitelist);
});

// DELETE /api/settings/whitelist/:type/:value
router.delete('/whitelist/:type/:value', (req, res) => {
  const tenantId = requireAuth(req, res);
  if (!tenantId) return;
  const { type, value } = req.params;
  const s = settingsService.getSettings(tenantId);
  s.whitelist[type] = (s.whitelist[type] || []).filter(v => v !== value);
  const updated = settingsService.saveSettings(tenantId, { whitelist: s.whitelist });
  auditLog.log(tenantId, auditLog.ACTIONS.WHITELIST_UPDATED, { type, action: 'remove', value }, getActor(req));
  res.json(updated.whitelist);
});

// GET /api/settings/audit
router.get('/audit', (req, res) => {
  const tenantId = requireAuth(req, res);
  if (!tenantId) return;
  const { limit = 100, action, since } = req.query;
  const entries = auditLog.getLog(tenantId, {
    limit: parseInt(limit),
    action, since
  });
  const stats = auditLog.getStats(tenantId);
  res.json({ entries, stats });
});

// ─── SIEM Configuration ────────────────────────────────────────────────────

// GET /api/settings/siem
router.get('/siem', (req, res) => {
  const tenantId = requireAuth(req, res);
  if (!tenantId) return;
  const s = settingsService.getSettings(tenantId);
  res.json(s.siem || { logAnalytics: { enabled: false }, webhooks: [] });
});

// PATCH /api/settings/siem
router.patch('/siem', (req, res) => {
  const tenantId = requireAuth(req, res);
  if (!tenantId) return;
  const updated = settingsService.saveSettings(tenantId, { siem: req.body });
  auditLog.log(tenantId, auditLog.ACTIONS.SETTINGS_UPDATED, { sections: ['siem'] }, getActor(req));
  res.json(updated.siem);
});

// POST /api/settings/siem/test — test Log Analytics connectivity
router.post('/siem/test', async (req, res) => {
  const tenantId = requireAuth(req, res);
  if (!tenantId) return;
  const { workspaceId, sharedKey } = req.body;
  try {
    const siemService = require('../services/siemService');
    const result = await siemService.testLogAnalytics(workspaceId, sharedKey);
    auditLog.log(tenantId, auditLog.ACTIONS.TEST_SENT, { type: 'siem_log_analytics' }, getActor(req));
    res.json(result);
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});



router.get('/notifications/inbox', requirePermission('ops.view'), (req, res) => {
  const tenantId = requireAuth(req, res);
  if (!tenantId) return;
  const { status, limit = 100, dedupe = 'false' } = req.query;
  res.json({ items: notificationCenter.list(tenantId, { status, limit: parseInt(limit), dedupe: String(dedupe) === 'true' }), stats: notificationCenter.stats(tenantId) });
});

router.post('/notifications/:id/ack', requirePermission('ops.view'), (req, res) => {
  const tenantId = requireAuth(req, res);
  if (!tenantId) return;
  const item = notificationCenter.ack(tenantId, req.params.id, getActor(req));
  if (!item) return res.status(404).json({ error: 'Notification not found' });
  auditLog.log(tenantId, 'notification.acked', { notificationId: req.params.id }, getActor(req));
  res.json(item);
});

router.patch('/assignment-rules', requirePermission('settings.manage'), (req, res) => {
  const tenantId = requireAuth(req, res);
  if (!tenantId) return;
  const updated = settingsService.saveSettings(tenantId, { assignmentRules: req.body || {} });
  auditLog.log(tenantId, 'assignment.rules_updated', { assignmentRules: req.body || {} }, getActor(req));
  res.json(updated.assignmentRules);
});

router.patch('/approval-policies', requirePermission('settings.manage'), (req, res) => {
  const tenantId = requireAuth(req, res);
  if (!tenantId) return;
  const updated = settingsService.saveSettings(tenantId, { approvalPolicies: req.body || {} });
  auditLog.log(tenantId, 'approval.policies_updated', { approvalPolicies: req.body || {} }, getActor(req));
  res.json(updated.approvalPolicies);
});

router.patch('/runbooks', requirePermission('settings.manage'), (req, res) => {
  const tenantId = requireAuth(req, res);
  if (!tenantId) return;
  const updated = settingsService.saveSettings(tenantId, { runbooks: req.body || {} });
  auditLog.log(tenantId, 'runbooks.updated', { severities: Object.keys(req.body || {}) }, getActor(req));
  res.json(updated.runbooks);
});

router.post('/ops/orchestrate', requirePermission('ops.view'), (req, res) => {
  const tenantId = requireAuth(req, res);
  if (!tenantId) return;
  const { tenantIds = [], action = 'sweep' } = req.body || {};
  const all = automationService.getMultiTenantOps(tenantId).tenants;
  const targets = all.filter(t => !tenantIds.length || tenantIds.includes(t.tenantId));
  const executedAt = new Date().toISOString();
  const results = targets.map(t => ({
    tenantId: t.tenantId,
    action,
    status: action === 'sweep' ? 'completed' : 'queued',
    executedAt,
    summary: action === 'sweep' ? automationService.runAutomationSweep(t.tenantId)[0] : { notificationBacklog: t.notificationBacklog, pendingApproval: t.pendingApproval }
  }));
  auditLog.log(tenantId, 'tenant.orchestration.executed', { action, tenantIds: results.map(r => r.tenantId) }, getActor(req));
  res.json({ ok: true, action, executedAt, results });
});

// Enhanced audit and operations endpoints
router.get('/roles-matrix', requirePermission('ops.view'), (req, res) => {
  res.json({ current: getAccessForRequest(req), matrix: ROLE_MATRIX });
});

router.get('/tenant-health', requirePermission('ops.view'), (req, res) => {
  const tenantId = requireAuth(req, res);
  if (!tenantId) return;
  const settings = settingsService.getSettings(tenantId);
  const workflow = workflowStore.getWorkflowStats(tenantId);
  const audit = auditLog.getStats(tenantId);
  const controls = [
    { id: 'notifications', score: settings.notifications?.adminEmails?.length ? 100 : 60 },
    { id: 'policyPack', score: settings.policyPack === 'strict' ? 100 : settings.policyPack === 'balanced' ? 82 : 68 },
    { id: 'workflow', score: workflow.overdue === 0 ? 92 : Math.max(45, 92 - workflow.overdue * 8) },
    { id: 'coverage', score: Math.min(100, (settings.monitoredRoles || []).length * 18) }
  ];
  const score = Math.round(controls.reduce((a,c)=>a+c.score,0) / controls.length);
  const grade = score >= 90 ? 'A' : score >= 80 ? 'B' : score >= 70 ? 'C' : 'D';
  res.json({ score, grade, controls, workflow, audit, policyPack: settings.policyPack, escalation: settings.escalation, notificationCenter: notificationCenter.stats(tenantId) });
});

router.get('/ops-dashboard', requirePermission('ops.view'), (req, res) => {
  const tenantId = requireAuth(req, res);
  if (!tenantId) return;
  const workflow = workflowStore.getWorkflowStats(tenantId);
  const entries = auditLog.getLog(tenantId, { limit: 50 });
  const trendMap = {};
  for (const e of entries) {
    const day = String(e.timestamp).slice(0,10);
    trendMap[day] = trendMap[day] || { day, workflow: 0, response: 0 };
    if (String(e.action).startsWith('workflow') || String(e.action).startsWith('playbook')) trendMap[day].workflow += 1;
    if (String(e.action).startsWith('response') || String(e.action).includes('resolved') || String(e.action).includes('dismissed')) trendMap[day].response += 1;
  }
  res.json({
    queuePressure: workflow,
    trend: Object.values(trendMap).sort((a,b)=>a.day.localeCompare(b.day)).slice(-7),
    lastActivity: entries[0]?.timestamp || null,
    actionsLast7Days: auditLog.getStats(tenantId).last7Days,
    notificationCenter: notificationCenter.stats(tenantId)
  });
});


router.get('/ops/orchestration', requirePermission('ops.view'), (req, res) => {
  const tenantId = requireAuth(req, res);
  if (!tenantId) return;
  automationService.runAutomationSweep();
  res.json(automationService.getMultiTenantOps(tenantId));
});

router.get('/audit/export', requirePermission('audit.export'), (req, res) => {
  const tenantId = requireAuth(req, res);
  if (!tenantId) return;
  const { action, actor, since } = req.query;
  const entries = auditLog.getLog(tenantId, { action, actor, since, limit: 1000 });
  const rows = [['timestamp','action','actor','details']].concat(entries.map(e => [e.timestamp, e.action, e.actor, JSON.stringify(e)]));
  const csv = rows.map(r => r.map(v => '"' + String(v ?? '').replace(/"/g,'""') + '"').join(',')).join('\n');
  res.setHeader('Content-Type', 'text/csv');
  res.setHeader('Content-Disposition', 'attachment; filename="audit-export.csv"');
  res.send(csv);
});

router.get('/policy-pack', requirePermission('ops.view'), (req, res) => {
  const tenantId = requireAuth(req, res);
  if (!tenantId) return;
  const settings = settingsService.getSettings(tenantId);
  res.json({ policyPack: settings.policyPack || 'balanced', escalation: settings.escalation, autoActions: settings.autoActions, detectionRules: settings.detectionRules });
});

router.patch('/policy-pack', requirePermission('settings.manage'), (req, res) => {
  const tenantId = requireAuth(req, res);
  if (!tenantId) return;
  const { policyPack } = req.body || {};
  const packs = {
    conservative: {
      autoActions: { critical: { revokeSession: false, disableUser: false, telegramPlaybook: true }, high: { revokeSession: false, disableUser: false, telegramPlaybook: true } }
    },
    balanced: {
      autoActions: { critical: { revokeSession: true, disableUser: false, telegramPlaybook: true }, high: { revokeSession: true, disableUser: false, telegramPlaybook: true } }
    },
    strict: {
      autoActions: { critical: { revokeSession: true, disableUser: true, telegramPlaybook: true }, high: { revokeSession: true, disableUser: false, telegramPlaybook: true } }
    }
  };
  const selected = packs[policyPack] || packs.balanced;
  const updated = settingsService.saveSettings(tenantId, { policyPack: policyPack || 'balanced', ...selected });
  auditLog.log(tenantId, 'policy.pack_updated', { policyPack: policyPack || 'balanced' }, getActor(req));
  res.json({ policyPack: updated.policyPack, autoActions: updated.autoActions });
});

// PUT alias for policy-pack (frontend uses PUT)
router.put('/policy-pack', requirePermission('settings.manage'), (req, res, next) => {
  req.method = 'PATCH';
  router.handle(req, res, next);
});

// ─── GET /admins (list) ───────────────────────────────────────────────────
router.get('/admins', (req, res) => {
  const tenantId = requireAuth(req, res);
  if (!tenantId) return;
  const s = settingsService.getSettings(tenantId);
  res.json(s.admins || []);
});

// ─── GET + PUT /whitelist ─────────────────────────────────────────────────
router.get('/whitelist', (req, res) => {
  const tenantId = requireAuth(req, res);
  if (!tenantId) return;
  const s = settingsService.getSettings(tenantId);
  res.json(s.whitelist || { ips: [], countries: [], devices: [], users: [] });
});

router.put('/whitelist', (req, res) => {
  const tenantId = requireAuth(req, res);
  if (!tenantId) return;
  const updated = settingsService.saveSettings(tenantId, { whitelist: req.body });
  auditLog.log(tenantId, auditLog.ACTIONS.WHITELIST_UPDATED, { action: 'bulk_update' }, getActor(req));
  res.json(updated.whitelist);
});

// ─── SIEM POST alias (frontend uses POST, backend has PATCH) ──────────────
router.post('/siem', (req, res) => {
  const tenantId = requireAuth(req, res);
  if (!tenantId) return;
  const updated = settingsService.saveSettings(tenantId, { siem: req.body });
  auditLog.log(tenantId, auditLog.ACTIONS.SETTINGS_UPDATED, { sections: ['siem'] }, getActor(req));
  res.json(updated.siem);
});

// POST /siem/test-log-analytics alias (frontend calls this, backend has /siem/test)
router.post('/siem/test-log-analytics', async (req, res) => {
  const tenantId = requireAuth(req, res);
  if (!tenantId) return;
  const { workspaceId, sharedKey } = req.body;
  try {
    const siemService = require('../services/siemService');
    const result = await siemService.testLogAnalytics(workspaceId, sharedKey);
    auditLog.log(tenantId, auditLog.ACTIONS.TEST_SENT, { type: 'siem_log_analytics' }, getActor(req));
    res.json(result);
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// ─── PUT aliases for workflow settings (frontend uses PUT, backend has PATCH) ──
router.put('/assignment-rules', requirePermission('settings.manage'), (req, res) => {
  const tenantId = requireAuth(req, res);
  if (!tenantId) return;
  const updated = settingsService.saveSettings(tenantId, { assignmentRules: req.body || {} });
  auditLog.log(tenantId, 'assignment.rules_updated', { assignmentRules: req.body || {} }, getActor(req));
  res.json(updated.assignmentRules);
});

router.put('/approval-policies', requirePermission('settings.manage'), (req, res) => {
  const tenantId = requireAuth(req, res);
  if (!tenantId) return;
  const updated = settingsService.saveSettings(tenantId, { approvalPolicies: req.body || {} });
  auditLog.log(tenantId, 'approval.policies_updated', { approvalPolicies: req.body || {} }, getActor(req));
  res.json(updated.approvalPolicies);
});

router.put('/runbooks', requirePermission('settings.manage'), (req, res) => {
  const tenantId = requireAuth(req, res);
  if (!tenantId) return;
  const updated = settingsService.saveSettings(tenantId, { runbooks: req.body || {} });
  auditLog.log(tenantId, 'runbooks.updated', { severities: Object.keys(req.body || {}) }, getActor(req));
  res.json(updated.runbooks);
});

// ─── Section-based settings (generic GET/PUT pattern) ────────────────────

function getSection(req, res, key, defaultVal = {}) {
  const tenantId = requireAuth(req, res);
  if (!tenantId) return;
  const s = settingsService.getSettings(tenantId);
  res.json(s[key] !== undefined ? s[key] : defaultVal);
}

function saveSection(req, res, key, auditAction) {
  const tenantId = requireAuth(req, res);
  if (!tenantId) return;
  const updated = settingsService.saveSettings(tenantId, { [key]: req.body });
  auditLog.log(tenantId, auditAction || 'settings.section_updated', { section: key }, getActor(req));
  res.json(updated[key] !== undefined ? updated[key] : req.body);
}

// GET/PUT /response-policies
router.get('/response-policies', requirePermission('settings.manage'), (req, res) =>
  getSection(req, res, 'responsePolicies', { autoRevoke: false, autoDisable: false, requireApproval: true }));
router.put('/response-policies', requirePermission('settings.manage'), (req, res) =>
  saveSection(req, res, 'responsePolicies', 'response_policies.updated'));

// GET/PUT /suppression-rules
router.get('/suppression-rules', requirePermission('settings.manage'), (req, res) =>
  getSection(req, res, 'suppressionRules', { rules: [] }));
router.put('/suppression-rules', requirePermission('settings.manage'), (req, res) =>
  saveSection(req, res, 'suppressionRules', 'suppression_rules.updated'));

// GET/PUT /response-exceptions
router.get('/response-exceptions', requirePermission('settings.manage'), (req, res) =>
  getSection(req, res, 'responseExceptions', { exceptions: [] }));
router.put('/response-exceptions', requirePermission('settings.manage'), (req, res) =>
  saveSection(req, res, 'responseExceptions', 'response_exceptions.updated'));

// GET/PUT /retention-policy + GET /retention-preview
router.get('/retention-policy', requirePermission('settings.manage'), (req, res) =>
  getSection(req, res, 'retentionPolicy', { alertRetentionDays: 90, auditRetentionDays: 365, autoArchive: false }));
router.put('/retention-policy', requirePermission('settings.manage'), (req, res) =>
  saveSection(req, res, 'retentionPolicy', 'retention_policy.updated'));
router.get('/retention-preview', requirePermission('settings.manage'), (req, res) => {
  const tenantId = requireAuth(req, res);
  if (!tenantId) return;
  const s = settingsService.getSettings(tenantId);
  const policy = s.retentionPolicy || { alertRetentionDays: 90, auditRetentionDays: 365 };
  const cutoffAlert = new Date(Date.now() - policy.alertRetentionDays * 86400000).toISOString();
  const cutoffAudit = new Date(Date.now() - policy.auditRetentionDays * 86400000).toISOString();
  res.json({ alertsCutoff: cutoffAlert, auditCutoff: cutoffAudit, policy });
});

// GET/PUT /business-hours
router.get('/business-hours', requirePermission('settings.manage'), (req, res) =>
  getSection(req, res, 'businessHours', { enabled: false, start: '09:00', end: '17:00', timezone: 'UTC', days: [1,2,3,4,5] }));
router.put('/business-hours', requirePermission('settings.manage'), (req, res) =>
  saveSection(req, res, 'businessHours', 'business_hours.updated'));

// GET/PUT /detection
router.get('/detection', requirePermission('settings.manage'), (req, res) => {
  const tenantId = requireAuth(req, res);
  if (!tenantId) return;
  const s = settingsService.getSettings(tenantId);
  res.json(s.detectionRules || s.detection || {});
});
router.put('/detection', requirePermission('settings.manage'), (req, res) => {
  const tenantId = requireAuth(req, res);
  if (!tenantId) return;
  const updated = settingsService.saveSettings(tenantId, { detectionRules: req.body, detection: req.body });
  auditLog.log(tenantId, 'detection.rules_updated', {}, getActor(req));
  res.json(updated.detectionRules || req.body);
});

// GET/PUT /auto-actions
router.get('/auto-actions', requirePermission('settings.manage'), (req, res) => {
  const tenantId = requireAuth(req, res);
  if (!tenantId) return;
  const s = settingsService.getSettings(tenantId);
  res.json(s.autoActions || {});
});
router.put('/auto-actions', requirePermission('settings.manage'), (req, res) => {
  const tenantId = requireAuth(req, res);
  if (!tenantId) return;
  const updated = settingsService.saveSettings(tenantId, { autoActions: req.body });
  auditLog.log(tenantId, 'auto_actions.updated', {}, getActor(req));
  res.json(updated.autoActions || req.body);
});

// GET/PUT /plan-trial
router.get('/plan-trial', (req, res) => {
  const tenantId = requireAuth(req, res);
  if (!tenantId) return;
  const trial = settingsService.getTrialStatus(tenantId);
  const s = settingsService.getSettings(tenantId);
  res.json({ ...trial, plan: s.plan || 'trial' });
});
router.put('/plan-trial', requirePermission('settings.manage'), (req, res) =>
  saveSection(req, res, 'plan', 'plan.updated'));

// GET/PUT /telegram + POST /telegram/test
router.get('/telegram', (req, res) => {
  const tenantId = requireAuth(req, res);
  if (!tenantId) return;
  const s = settingsService.getSettings(tenantId);
  res.json(s.telegram || { botToken: '', chatId: '', enabled: false });
});
router.put('/telegram', requirePermission('settings.manage'), (req, res) =>
  saveSection(req, res, 'telegram', 'telegram.settings_updated'));
router.post('/telegram/test', async (req, res) => {
  const tenantId = requireAuth(req, res);
  if (!tenantId) return;
  try {
    const telegramService = require('../services/telegramService');
    await telegramService.sendMessage('🧪 Test message from IdentityMonitor settings');
    auditLog.log(tenantId, auditLog.ACTIONS.TEST_SENT, { type: 'telegram' }, getActor(req));
    res.json({ success: true, message: 'Test message sent' });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// ─── POST /policy-simulator (frontend calls this, maps to alerts policy engine) ──
router.post('/policy-simulator', requirePermission('settings.manage'), (req, res) => {
  const tenantId = requireAuth(req, res);
  if (!tenantId) return;
  try {
    const policyEngine = require('../services/policyEngineService');
    const decision = policyEngine.simulateDecision(tenantId, req.body || {});
    const executionCheck = policyEngine.getExecutionCheck(tenantId, req.body || {}, (req.body || {}).requestedAction || 'monitor', { approvalStatus: req.body?.approvalStatus || 'pending' });
    res.json({ decision, executionCheck, sample: req.body || {} });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ─── GET/PUT /ops/orchestration/policies ─────────────────────────────────
router.get('/ops/orchestration/policies', requirePermission('ops.view'), (req, res) =>
  getSection(req, res, 'orchestrationPolicies', { autoSweep: true, sweepIntervalMinutes: 15, escalationEnabled: true }));
router.put('/ops/orchestration/policies', requirePermission('settings.manage'), (req, res) =>
  saveSection(req, res, 'orchestrationPolicies', 'orchestration.policies_updated'));

module.exports = router;
