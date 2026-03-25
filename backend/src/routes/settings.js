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

module.exports = router;

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

// PUT alias for policy-pack (frontend uses PUT)
router.put('/policy-pack', requirePermission('settings.manage'), (req, res) => {
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

// ─── Missing GET/PUT endpoints ──────────────────────────────────────────────

// GET /api/settings/admins
router.get('/admins', requirePermission('settings.manage'), (req, res) => {
  const tenantId = requireAuth(req, res);
  if (!tenantId) return;
  res.json(settingsService.getSettings(tenantId).admins || []);
});

// GET /api/settings/whitelist
router.get('/whitelist', (req, res) => {
  const tenantId = requireAuth(req, res);
  if (!tenantId) return;
  res.json(settingsService.getSettings(tenantId).whitelist || { ips: [], countries: [], devices: [], users: [] });
});

// PUT /api/settings/whitelist — save full whitelist object
router.put('/whitelist', (req, res) => {
  const tenantId = requireAuth(req, res);
  if (!tenantId) return;
  const updated = settingsService.saveSettings(tenantId, { whitelist: req.body });
  auditLog.log(tenantId, auditLog.ACTIONS.WHITELIST_UPDATED, { action: 'bulk-save' }, getActor(req));
  res.json(updated.whitelist);
});

// GET /api/settings/detection
router.get('/detection', (req, res) => {
  const tenantId = requireAuth(req, res);
  if (!tenantId) return;
  res.json(settingsService.getSettings(tenantId).detectionRules || {});
});

// PUT /api/settings/detection
router.put('/detection', requirePermission('settings.manage'), (req, res) => {
  const tenantId = requireAuth(req, res);
  if (!tenantId) return;
  const updated = settingsService.saveSettings(tenantId, { detectionRules: req.body });
  auditLog.log(tenantId, auditLog.ACTIONS.SETTINGS_UPDATED, { sections: ['detectionRules'] }, getActor(req));
  res.json(updated.detectionRules);
});

// GET /api/settings/auto-actions
router.get('/auto-actions', (req, res) => {
  const tenantId = requireAuth(req, res);
  if (!tenantId) return;
  res.json(settingsService.getSettings(tenantId).autoActions || {});
});

// PUT /api/settings/auto-actions
router.put('/auto-actions', requirePermission('settings.manage'), (req, res) => {
  const tenantId = requireAuth(req, res);
  if (!tenantId) return;
  const updated = settingsService.saveSettings(tenantId, { autoActions: req.body });
  auditLog.log(tenantId, auditLog.ACTIONS.SETTINGS_UPDATED, { sections: ['autoActions'] }, getActor(req));
  res.json(updated.autoActions);
});

// GET /api/settings/response-policies
router.get('/response-policies', (req, res) => {
  const tenantId = requireAuth(req, res);
  if (!tenantId) return;
  res.json(settingsService.getSettings(tenantId).responsePolicies || {});
});

// PUT /api/settings/response-policies
router.put('/response-policies', requirePermission('settings.manage'), (req, res) => {
  const tenantId = requireAuth(req, res);
  if (!tenantId) return;
  const updated = settingsService.saveSettings(tenantId, { responsePolicies: req.body });
  auditLog.log(tenantId, auditLog.ACTIONS.SETTINGS_UPDATED, { sections: ['responsePolicies'] }, getActor(req));
  res.json(updated.responsePolicies);
});

// GET /api/settings/suppression-rules
router.get('/suppression-rules', (req, res) => {
  const tenantId = requireAuth(req, res);
  if (!tenantId) return;
  res.json(settingsService.getSettings(tenantId).suppressionRules || []);
});

// PUT /api/settings/suppression-rules
router.put('/suppression-rules', requirePermission('settings.manage'), (req, res) => {
  const tenantId = requireAuth(req, res);
  if (!tenantId) return;
  const updated = settingsService.saveSettings(tenantId, { suppressionRules: req.body });
  auditLog.log(tenantId, auditLog.ACTIONS.SETTINGS_UPDATED, { sections: ['suppressionRules'] }, getActor(req));
  res.json(updated.suppressionRules);
});

// GET /api/settings/response-exceptions
router.get('/response-exceptions', (req, res) => {
  const tenantId = requireAuth(req, res);
  if (!tenantId) return;
  res.json(settingsService.getSettings(tenantId).responseExceptions || {});
});

// PUT /api/settings/response-exceptions
router.put('/response-exceptions', requirePermission('settings.manage'), (req, res) => {
  const tenantId = requireAuth(req, res);
  if (!tenantId) return;
  const updated = settingsService.saveSettings(tenantId, { responseExceptions: req.body });
  auditLog.log(tenantId, auditLog.ACTIONS.SETTINGS_UPDATED, { sections: ['responseExceptions'] }, getActor(req));
  res.json(updated.responseExceptions);
});

// GET /api/settings/retention-policy
router.get('/retention-policy', (req, res) => {
  const tenantId = requireAuth(req, res);
  if (!tenantId) return;
  res.json(settingsService.getSettings(tenantId).retentionPolicy || {});
});

// PUT /api/settings/retention-policy
router.put('/retention-policy', requirePermission('settings.manage'), (req, res) => {
  const tenantId = requireAuth(req, res);
  if (!tenantId) return;
  const updated = settingsService.saveSettings(tenantId, { retentionPolicy: req.body });
  auditLog.log(tenantId, auditLog.ACTIONS.SETTINGS_UPDATED, { sections: ['retentionPolicy'] }, getActor(req));
  res.json(updated.retentionPolicy);
});

// GET /api/settings/retention-preview
router.get('/retention-preview', (req, res) => {
  const tenantId = requireAuth(req, res);
  if (!tenantId) return;
  const s = settingsService.getSettings(tenantId);
  const rp = s.retentionPolicy || {};
  const cutoffs = {
    incidents: rp.incidentDays ? new Date(Date.now() - rp.incidentDays * 86400000).toISOString() : null,
    audit:     rp.auditDays    ? new Date(Date.now() - rp.auditDays    * 86400000).toISOString() : null,
    reports:   rp.reportDays   ? new Date(Date.now() - rp.reportDays   * 86400000).toISOString() : null,
  };
  res.json({ retentionPolicy: rp, cutoffs, previewGeneratedAt: new Date().toISOString() });
});

// GET /api/settings/business-hours
router.get('/business-hours', (req, res) => {
  const tenantId = requireAuth(req, res);
  if (!tenantId) return;
  const s = settingsService.getSettings(tenantId);
  res.json(s.businessHours || s.workHours || {});
});

// PUT /api/settings/business-hours
router.put('/business-hours', requirePermission('settings.manage'), (req, res) => {
  const tenantId = requireAuth(req, res);
  if (!tenantId) return;
  const updated = settingsService.saveSettings(tenantId, { businessHours: req.body, workHours: req.body });
  auditLog.log(tenantId, auditLog.ACTIONS.SETTINGS_UPDATED, { sections: ['businessHours'] }, getActor(req));
  res.json(updated.businessHours);
});

// POST /api/settings/policy-simulator
router.post('/policy-simulator', requirePermission('settings.manage'), (req, res) => {
  const tenantId = requireAuth(req, res);
  if (!tenantId) return;
  const policyEngine = require('../services/policyEngineService');
  const decision = policyEngine.simulateDecision(tenantId, req.body || {});
  const executionCheck = policyEngine.getExecutionCheck(tenantId, req.body || {}, (req.body || {}).requestedAction || 'monitor', { approvalStatus: req.body?.approvalStatus || 'pending' });
  res.json({ decision, executionCheck, sample: req.body || {} });
});

// GET /api/settings/ops/orchestration/policies
router.get('/ops/orchestration/policies', requirePermission('ops.view'), (req, res) => {
  const tenantId = requireAuth(req, res);
  if (!tenantId) return;
  res.json(settingsService.getSettings(tenantId).orchestrationPolicies || {});
});

// PUT /api/settings/ops/orchestration/policies
router.put('/ops/orchestration/policies', requirePermission('settings.manage'), (req, res) => {
  const tenantId = requireAuth(req, res);
  if (!tenantId) return;
  const updated = settingsService.saveSettings(tenantId, { orchestrationPolicies: req.body });
  auditLog.log(tenantId, auditLog.ACTIONS.SETTINGS_UPDATED, { sections: ['orchestrationPolicies'] }, getActor(req));
  res.json(updated.orchestrationPolicies);
});

// GET /api/settings/plan-trial
router.get('/plan-trial', (req, res) => {
  const tenantId = requireAuth(req, res);
  if (!tenantId) return;
  const s = settingsService.getSettings(tenantId);
  res.json({ billing: s.billing || {}, trialStatus: settingsService.getTrialStatus(tenantId) });
});

// PUT /api/settings/plan-trial
router.put('/plan-trial', requirePermission('settings.manage'), (req, res) => {
  const tenantId = requireAuth(req, res);
  if (!tenantId) return;
  const updated = settingsService.saveSettings(tenantId, { billing: req.body });
  auditLog.log(tenantId, auditLog.ACTIONS.SETTINGS_UPDATED, { sections: ['billing'] }, getActor(req));
  res.json({ billing: updated.billing, trialStatus: settingsService.getTrialStatus(tenantId) });
});

// GET /api/settings/telegram
router.get('/telegram', (req, res) => {
  const tenantId = requireAuth(req, res);
  if (!tenantId) return;
  const s = settingsService.getSettings(tenantId);
  const n = s.notifications || {};
  res.json({ telegramBotToken: n.telegramBotToken || '', telegramChatId: n.telegramChatId || '', telegramOnSeverity: n.telegramOnSeverity || ['critical', 'high'] });
});

// PUT /api/settings/telegram
router.put('/telegram', requirePermission('settings.manage'), (req, res) => {
  const tenantId = requireAuth(req, res);
  if (!tenantId) return;
  const s = settingsService.getSettings(tenantId);
  const merged = { ...(s.notifications || {}), ...req.body };
  const updated = settingsService.saveSettings(tenantId, { notifications: merged });
  auditLog.log(tenantId, auditLog.ACTIONS.SETTINGS_UPDATED, { sections: ['telegram'] }, getActor(req));
  res.json({ telegramBotToken: merged.telegramBotToken || '', telegramChatId: merged.telegramChatId || '', telegramOnSeverity: merged.telegramOnSeverity || ['critical', 'high'] });
});

// POST /api/settings/telegram/test
router.post('/telegram/test', async (req, res) => {
  const tenantId = requireAuth(req, res);
  if (!tenantId) return;
  try {
    const telegramService = require('../services/telegramService');
    await telegramService.sendMessage('🔔 *Test message* from Privileged Identity Monitor');
    auditLog.log(tenantId, auditLog.ACTIONS.TEST_SENT || 'test.sent', { type: 'telegram' }, getActor(req));
    res.json({ ok: true, message: 'Test message sent' });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

// PUT aliases for PATCH endpoints (frontend uses PUT)
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

// POST alias for PATCH /siem (frontend uses POST)
router.post('/siem', (req, res) => {
  const tenantId = requireAuth(req, res);
  if (!tenantId) return;
  const updated = settingsService.saveSettings(tenantId, { siem: req.body });
  auditLog.log(tenantId, auditLog.ACTIONS.SETTINGS_UPDATED, { sections: ['siem'] }, getActor(req));
  res.json(updated.siem);
});

// POST /api/settings/siem/test-log-analytics (alias for /siem/test)
router.post('/siem/test-log-analytics', async (req, res) => {
  const tenantId = requireAuth(req, res);
  if (!tenantId) return;
  const { workspaceId, sharedKey } = req.body;
  try {
    const siemService = require('../services/siemService');
    const result = await siemService.testLogAnalytics(workspaceId, sharedKey);
    auditLog.log(tenantId, auditLog.ACTIONS.TEST_SENT || 'test.sent', { type: 'siem_log_analytics' }, getActor(req));
    res.json(result);
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});
