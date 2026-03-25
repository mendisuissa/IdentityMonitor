const express = require('express');
const router  = express.Router();
const alertsStore    = require('../services/alertsStore');
const anomalyService = require('../services/anomalyService');
const workflowStore  = require('../services/workflowStore');
const auditLog       = require('../services/auditLog');
const { getMockAlerts, getMockStats } = require('../services/mockData');
const { requirePermission, getActor } = require('../services/accessControl');
const automationService = require('../services/automationService');
const incidentStore = require('../services/incidentStore');
const policyEngine = require('../services/policyEngineService');
const settingsService = require('../services/settingsService');

const isMock = () => process.env.MOCK_MODE === 'true';

let _mockAlerts = null;
function getMockAlertsState() {
  if (!_mockAlerts) _mockAlerts = getMockAlerts();
  return _mockAlerts;
}

function getTenantId(req) {
  return req.session && req.session.tenant ? req.session.tenant.tenantId : null;
}

// GET /api/alerts
router.get('/', requirePermission('alerts.view'), async (req, res) => {
  const { status, severity, userId } = req.query;
  const tenantId = getTenantId(req);

  if (tenantId && !isMock()) await alertsStore.loadFromAzure(tenantId);

  let alerts = isMock() ? getMockAlertsState() : alertsStore.getAll(tenantId);
  if (status) alerts = alerts.filter(a => a.status === status);
  if (severity) alerts = alerts.filter(a => a.severity === severity);
  if (userId) alerts = alerts.filter(a => a.userId === userId);

  const withWorkflow = alerts.map(a => ({ ...a, workflow: tenantId ? workflowStore.getAlertWorkflow(tenantId, a.id) : undefined }));
  res.json(withWorkflow);
});

router.get('/stats', requirePermission('alerts.view'), async (req, res) => {
  const tenantId = getTenantId(req);
  if (isMock()) return res.json(getMockStats(getMockAlertsState()));
  if (tenantId) await alertsStore.loadFromAzure(tenantId);
  res.json({ ...alertsStore.getStats(tenantId), workflow: workflowStore.getWorkflowStats(tenantId) });
});

router.get('/cases', requirePermission('alerts.view'), (req, res) => {
  const tenantId = getTenantId(req);
  const { caseStatus, owner, approvalStatus } = req.query;
  automationService.runAutomationSweep(tenantId);
  let cases = workflowStore.getCases(tenantId);
  if (caseStatus) cases = cases.filter(c => c.caseStatus === caseStatus);
  if (owner) cases = cases.filter(c => (c.owner || '').toLowerCase().includes(String(owner).toLowerCase()));
  if (approvalStatus) cases = cases.filter(c => c.approvalStatus === approvalStatus);
  res.json(cases);
});

router.get('/cases/:id', requirePermission('alerts.view'), (req, res) => {
  const tenantId = getTenantId(req);
  const cases = workflowStore.getCases(tenantId);
  const found = cases.find(c => c.alertId === req.params.id);
  if (!found) return res.status(404).json({ error: 'Case not found' });
  res.json(found);
});

router.post('/cases', requirePermission('alerts.respond'), (req, res) => {
  const tenantId = getTenantId(req);
  const { alertId, ...body } = req.body || {};
  if (!alertId) return res.status(400).json({ error: 'alertId required' });
  const updated = workflowStore.patchAlertWorkflow(tenantId, alertId, body, getActor(req));
  auditLog.log(tenantId, 'cases.created', { alertId }, getActor(req));
  res.json(updated);
});

router.patch('/cases/:id', requirePermission('alerts.respond'), (req, res) => {
  const tenantId = getTenantId(req);
  const updated = workflowStore.patchAlertWorkflow(tenantId, req.params.id, req.body || {}, getActor(req));
  auditLog.log(tenantId, 'cases.updated', { alertId: req.params.id }, getActor(req));
  res.json(updated);
});


router.get('/:id/investigation', requirePermission('alerts.view'), (req, res) => {
  const tenantId = getTenantId(req);
  const alert = alertsStore.getById(req.params.id);
  if (!alert || (tenantId && alert.tenantId !== tenantId)) return res.status(404).json({ error: 'Alert not found' });
  const workflow = workflowStore.getAlertWorkflow(tenantId, alert.id);
  const view = incidentStore.buildInvestigation(tenantId, alert, workflow);
  view.policyDecision = policyEngine.buildPolicyDecision(tenantId, alert);
  view.executionCheck = policyEngine.getExecutionCheck(tenantId, alert, workflow.requestedAction || 'monitor', workflow);
  view.caseLinks = workflowStore.getCases(tenantId)
    .filter(c => c.alertId !== alert.id && (c.userPrincipalName === alert.userPrincipalName || c.userDisplayName === alert.userDisplayName))
    .slice(0, 5)
    .map(c => ({ alertId: c.alertId, severity: c.severity, caseStatus: c.caseStatus, approvalStatus: c.approvalStatus, detectedAt: c.detectedAt, title: c.title }));
  res.json(view);
});

router.get('/workflow/recent', requirePermission('alerts.view'), (req, res) => {
  const tenantId = getTenantId(req);
  const cases = workflowStore.getCases(tenantId).slice(0, 8);
  res.json(cases);
});

router.patch('/:id/workflow', requirePermission('alerts.respond'), (req, res) => {
  const tenantId = getTenantId(req);
  const updated = workflowStore.patchAlertWorkflow(tenantId, req.params.id, req.body, getActor(req));
  res.json(updated);
});

router.get('/:id/comments', requirePermission('alerts.view'), (req, res) => {
  const tenantId = getTenantId(req);
  const workflow = workflowStore.getAlertWorkflow(tenantId, req.params.id);
  res.json(workflow?.comments || []);
});

router.post('/:id/comments', requirePermission('alerts.respond'), (req, res) => {
  const tenantId = getTenantId(req);
  if (!req.body?.message) return res.status(400).json({ error: 'message required' });
  const updated = workflowStore.addComment(tenantId, req.params.id, req.body.message, getActor(req));
  res.json(updated);
});

router.post('/policy/simulate', requirePermission('settings.manage'), (req, res) => {
  const tenantId = getTenantId(req);
  const decision = policyEngine.simulateDecision(tenantId, req.body || {});
  const executionCheck = policyEngine.getExecutionCheck(tenantId, req.body || {}, (req.body || {}).requestedAction || 'monitor', { approvalStatus: req.body?.approvalStatus || 'pending' });
  res.json({ decision, executionCheck, sample: req.body || {} });
});

router.post('/:id/execute', requirePermission('alerts.respond'), (req, res) => {
  const tenantId = getTenantId(req);
  const alert = alertsStore.getById(req.params.id);
  if (!alert) return res.status(404).json({ error: 'Alert not found' });
  const workflow = workflowStore.getAlertWorkflow(tenantId, alert.id);
  const action = req.body?.action || workflow.requestedAction || 'monitor';
  const check = policyEngine.getExecutionCheck(tenantId, alert, action, workflow);
  if (!check.canExecute) return res.status(409).json({ error: check.reason, state: check.state, decision: check.decision });
  alertsStore.addAction(alert.id, action);
  const updatedWorkflow = workflowStore.patchAlertWorkflow(tenantId, alert.id, {
    caseStatus: action === 'monitor' ? workflow.caseStatus : 'executed',
    automationActions: [
      ...(workflow.automationActions || []),
      { type: 'manual-execution', key: `exec-${alert.id}-${Date.now()}`, createdAt: new Date().toISOString(), detail: `${getActor(req)} executed ${action}`, state: 'executed' }
    ]
  }, getActor(req));
  auditLog.log(tenantId, `response.${action}_executed`, { alertId: alert.id, action }, getActor(req));
  res.json({ ok: true, action, executionCheck: check, workflow: updatedWorkflow, alert: alertsStore.getById(alert.id) });
});

router.patch('/:id/playbook', requirePermission('alerts.approve'), (req, res) => {
  const tenantId = getTenantId(req);
  const { approvalStatus = 'approved', requestedAction = 'monitor', note = '' } = req.body || {};
  let updated;
  if (approvalStatus === 'approved' || approvalStatus === 'rejected') {
    updated = workflowStore.progressApproval(tenantId, req.params.id, approvalStatus, getActor(req), note);
    updated = workflowStore.patchAlertWorkflow(tenantId, req.params.id, { requestedAction }, getActor(req));
  } else {
    updated = workflowStore.patchAlertWorkflow(tenantId, req.params.id, { approvalStatus, requestedAction }, getActor(req));
  }
  auditLog.log(tenantId, 'playbook.decision', { alertId: req.params.id, approvalStatus, requestedAction, note }, getActor(req));
  res.json(updated);
});

router.patch('/:id/resolve', requirePermission('alerts.respond'), (req, res) => {
  if (isMock()) {
    const alert = getMockAlertsState().find(a => a.id === req.params.id);
    if (!alert) return res.status(404).json({ error: 'Alert not found' });
    alert.status = 'resolved';
    alert.resolvedBy = req.body.resolvedBy || 'admin';
    alert.resolvedAt = new Date().toISOString();
    return res.json(alert);
  }
  const tenantId = getTenantId(req);
  const alert = alertsStore.updateStatus(req.params.id, 'resolved', req.body.resolvedBy || 'admin');
  if (!alert) return res.status(404).json({ error: 'Alert not found' });
  workflowStore.patchAlertWorkflow(tenantId, req.params.id, { caseStatus: 'closed' }, getActor(req));
  incidentStore.recordResolution(tenantId, alert, { action: 'resolved', actor: getActor(req) });
  auditLog.log(tenantId, auditLog.ACTIONS.ALERT_RESOLVED, { alertId: req.params.id }, getActor(req));
  res.json(alert);
});

router.patch('/:id/dismiss', requirePermission('alerts.respond'), (req, res) => {
  if (isMock()) {
    const alert = getMockAlertsState().find(a => a.id === req.params.id);
    if (!alert) return res.status(404).json({ error: 'Alert not found' });
    alert.status = 'dismissed';
    alert.resolvedAt = new Date().toISOString();
    return res.json(alert);
  }
  const tenantId = getTenantId(req);
  const alert = alertsStore.updateStatus(req.params.id, 'dismissed');
  if (!alert) return res.status(404).json({ error: 'Alert not found' });
  workflowStore.patchAlertWorkflow(tenantId, req.params.id, { caseStatus: 'closed' }, getActor(req));
  incidentStore.recordResolution(tenantId, alert, { action: 'dismissed', actor: getActor(req) });
  auditLog.log(tenantId, auditLog.ACTIONS.ALERT_DISMISSED, { alertId: req.params.id }, getActor(req));
  res.json(alert);
});




router.post('/bulk', requirePermission('alerts.respond'), async (req, res) => {
  const tenantId = getTenantId(req);
  const { alertIds = [], action = '', owner = '', comment = '' } = req.body || {};
  if (!Array.isArray(alertIds) || !alertIds.length) return res.status(400).json({ error: 'alertIds required' });
  const actor = getActor(req);
  const results = [];
  for (const id of alertIds) {
    if (action === 'assign') {
      results.push(workflowStore.patchAlertWorkflow(tenantId, id, { owner }, actor));
    } else if (action === 'resolve') {
      const alert = alertsStore.updateStatus(id, 'resolved', actor);
      if (alert) {
        workflowStore.patchAlertWorkflow(tenantId, id, { caseStatus: 'closed' }, actor);
        results.push(alert);
      }
    } else if (action === 'dismiss') {
      const alert = alertsStore.updateStatus(id, 'dismissed', actor);
      if (alert) {
        workflowStore.patchAlertWorkflow(tenantId, id, { caseStatus: 'closed' }, actor);
        results.push(alert);
      }
    } else if (action === 'approve') {
      results.push(workflowStore.progressApproval(tenantId, id, 'approved', actor, 'Bulk approved'));
    } else if (action === 'comment' && comment) {
      results.push(workflowStore.addComment(tenantId, id, comment, actor));
    }
  }
  auditLog.log(tenantId, 'cases.bulk_action', { action, count: alertIds.length, owner, hasComment: !!comment }, actor);
  res.json({ ok: true, count: results.length, action, results });
});

router.post('/automation/run', requirePermission('ops.view'), (req, res) => {
  const tenantId = getTenantId(req);
  const result = automationService.runAutomationSweep(tenantId);
  res.json({ ok: true, result });
});

router.post('/scan', requirePermission('alerts.respond'), async (req, res) => {
  if (isMock()) {
    return res.json({ newAlerts: 0, alerts: [], message: 'Mock mode — use /api/mock/trigger-alert' });
  }
  try {
    const tenantId = getTenantId(req);
    if (!tenantId) return res.status(401).json({ error: 'Not authenticated' });

    // ── Pre-flight: verify Graph permissions before running full scan ──
    const graphService = require('../services/graphService');
    let users = [];
    try {
      users = await graphService.getPrivilegedUsers(tenantId);
    } catch (err) {
      const msg = err.message || '';
      if (msg.includes('403') || msg.includes('Forbidden') || msg.includes('Authorization_RequestDenied')) {
        return res.status(403).json({
          error: 'Graph API permission denied',
          detail: 'Missing required permissions: AuditLog.Read.All, Directory.Read.All, or RoleManagement.Read.Directory. Re-authenticate via Settings → Disconnect → Connect with elevated permissions.',
          code: 'GRAPH_PERMISSION_DENIED'
        });
      }
      if (msg.includes('401') || msg.includes('Unauthorized') || msg.includes('token')) {
        return res.status(401).json({
          error: 'Graph API authentication failed',
          detail: 'Your session token has expired. Please sign out and sign back in.',
          code: 'GRAPH_AUTH_EXPIRED'
        });
      }
      return res.status(502).json({
        error: 'Graph API unreachable',
        detail: msg,
        code: 'GRAPH_UNAVAILABLE'
      });
    }

    if (users.length === 0) {
      return res.json({
        newAlerts: 0,
        alerts: [],
        message: 'No privileged users found in tenant. Check monitored roles in Settings or verify Graph permissions.',
        code: 'NO_PRIVILEGED_USERS'
      });
    }

    const newAlerts = await anomalyService.runFullScan(tenantId);
    auditLog.log(tenantId, auditLog.ACTIONS.SCAN_TRIGGERED, { newAlerts: newAlerts.length, usersScanned: users.length }, getActor(req));
    res.json({
      newAlerts: newAlerts.length,
      alerts: newAlerts,
      usersScanned: users.length,
      message: newAlerts.length > 0
        ? `Scan complete — ${newAlerts.length} new alert${newAlerts.length !== 1 ? 's' : ''} detected across ${users.length} privileged accounts`
        : `Scan complete — no new anomalies in ${users.length} privileged accounts`
    });
  } catch (err) {
    console.error('[Scan] Unexpected error:', err.message);
    res.status(500).json({ error: err.message, code: 'SCAN_FAILED' });
  }
});

// GET /api/alerts/:id — single alert with workflow
router.get('/:id', requirePermission('alerts.view'), async (req, res) => {
  const tenantId = getTenantId(req);
  if (tenantId && !isMock()) await alertsStore.loadFromAzure(tenantId);
  const alert = isMock()
    ? getMockAlertsState().find(a => a.id === req.params.id)
    : alertsStore.getById(req.params.id);
  if (!alert || (tenantId && !isMock() && alert.tenantId !== tenantId)) {
    return res.status(404).json({ error: 'Alert not found' });
  }
  const workflow = tenantId ? workflowStore.getAlertWorkflow(tenantId, alert.id) : undefined;
  res.json({ ...alert, workflow });
});

// POST /api/alerts/refresh — reload alerts from store
router.post('/refresh', requirePermission('alerts.view'), async (req, res) => {
  const tenantId = getTenantId(req);
  if (tenantId && !isMock()) await alertsStore.loadFromAzure(tenantId);
  const alerts = isMock() ? getMockAlertsState() : alertsStore.getAll(tenantId);
  const withWorkflow = alerts.map(a => ({ ...a, workflow: tenantId ? workflowStore.getAlertWorkflow(tenantId, a.id) : undefined }));
  res.json(withWorkflow);
});

module.exports = router;
