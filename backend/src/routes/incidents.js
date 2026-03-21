const express         = require('express');
const router          = express.Router();
const incidentService = require('../services/incidentService');
const approvalService = require('../services/approvalService');
const playbookService = require('../services/playbookService');
const evidencePack    = require('../services/evidencePack');
const alertsStore     = require('../services/alertsStore');

function getTenantId(req) {
  return req.session?.tenant?.tenantId || (process.env.MOCK_MODE === 'true' ? 'mock-tenant' : null);
}
function getActor(req) {
  return req.session?.tenant?.userEmail || 'admin';
}

// GET /api/incidents/:alertId/timeline
router.get('/:alertId/timeline', (req, res) => {
  const tenantId = getTenantId(req);
  if (!tenantId) return res.status(401).json({ error: 'Not authenticated' });
  res.json(incidentService.getTimeline(tenantId, req.params.alertId));
});

// POST /api/incidents/:alertId/note
router.post('/:alertId/note', (req, res) => {
  const tenantId = getTenantId(req);
  if (!tenantId) return res.status(401).json({ error: 'Not authenticated' });
  const { note } = req.body;
  if (!note) return res.status(400).json({ error: 'note required' });
  const ev = incidentService.addEvent(tenantId, req.params.alertId, 'NOTE_ADDED', { note }, getActor(req));
  res.json(ev);
});

// POST /api/incidents/:alertId/assign
router.post('/:alertId/assign', (req, res) => {
  const tenantId = getTenantId(req);
  if (!tenantId) return res.status(401).json({ error: 'Not authenticated' });
  const { ownerEmail } = req.body;
  const ev = incidentService.addEvent(tenantId, req.params.alertId, 'OWNER_ASSIGNED', { ownerEmail }, getActor(req));
  res.json(ev);
});

// GET /api/incidents/:alertId/playbook
router.get('/:alertId/playbook', (req, res) => {
  const tenantId = getTenantId(req);
  if (!tenantId) return res.status(401).json({ error: 'Not authenticated' });
  const alert  = alertsStore.getAll(tenantId).find(a => a.id === req.params.alertId);
  const mockAlerts = process.env.MOCK_MODE === 'true' ? require('../services/mockData').getMockAlerts() : [];
  const a = alert || mockAlerts.find(x => x.id === req.params.alertId);
  if (!a) return res.status(404).json({ error: 'Alert not found' });
  res.json(playbookService.getPlaybook(a.anomalyType));
});

// GET /api/incidents/:alertId/evidence — returns HTML
router.get('/:alertId/evidence', (req, res) => {
  const tenantId = getTenantId(req);
  if (!tenantId) return res.status(401).json({ error: 'Not authenticated' });

  const allAlerts  = alertsStore.getAll(tenantId);
  const mockAlerts = process.env.MOCK_MODE === 'true' ? require('../services/mockData').getMockAlerts() : [];
  const alert      = allAlerts.find(a => a.id === req.params.alertId) || mockAlerts.find(a => a.id === req.params.alertId);

  if (!alert) return res.status(404).json({ error: 'Alert not found' });

  const timeline = incidentService.getTimeline(tenantId, req.params.alertId);
  incidentService.addEvent(tenantId, req.params.alertId, 'EVIDENCE_EXPORTED', {}, getActor(req));

  const html = evidencePack.generateEvidenceHtml(alert, timeline);
  res.setHeader('Content-Type', 'text/html');
  res.setHeader('Content-Disposition', 'attachment; filename="evidence-' + req.params.alertId.substring(0,12) + '.html"');
  res.send(html);
});

// POST /api/incidents/:alertId/whitelist-ip
router.post('/:alertId/whitelist-ip', async (req, res) => {
  const tenantId = getTenantId(req);
  if (!tenantId) return res.status(401).json({ error: 'Not authenticated' });

  const allAlerts  = alertsStore.getAll(tenantId);
  const mockAlerts = process.env.MOCK_MODE === 'true' ? require('../services/mockData').getMockAlerts() : [];
  const alert      = allAlerts.find(a => a.id === req.params.alertId) || mockAlerts.find(a => a.id === req.params.alertId);
  if (!alert || !alert.ipAddress) return res.status(400).json({ error: 'No IP to whitelist' });

  const settingsService = require('../services/settingsService');
  const s = settingsService.getSettings(tenantId);
  if (!s.whitelist.ips.includes(alert.ipAddress)) s.whitelist.ips.push(alert.ipAddress);
  settingsService.saveSettings(tenantId, { whitelist: s.whitelist });

  incidentService.addEvent(tenantId, req.params.alertId, 'WHITELIST_ADDED',
    { type: 'ip', value: alert.ipAddress }, getActor(req));

  alertsStore.updateStatus(req.params.alertId, 'dismissed', getActor(req));
  res.json({ success: true, whitelistedIp: alert.ipAddress });
});

// GET /api/incidents/approvals/pending
router.get('/approvals/pending', (req, res) => {
  const tenantId = getTenantId(req);
  if (!tenantId) return res.status(401).json({ error: 'Not authenticated' });
  res.json(approvalService.getPendingApprovals(tenantId));
});

// POST /api/incidents/approvals/:id/resolve
router.post('/approvals/:id/resolve', (req, res) => {
  const { decision } = req.body; // 'approve' or 'deny'
  const result = approvalService.resolveApproval(req.params.id, decision, getActor(req));
  if (!result) return res.status(404).json({ error: 'Approval not found' });
  res.json(result);
});

module.exports = router;
