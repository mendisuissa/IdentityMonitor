const express = require('express');
const router = express.Router();
const { requirePermission } = require('../services/accessControl');
const alertsStore = require('../services/alertsStore');
const workflowStore = require('../services/workflowStore');
const riskPostureService = require('../services/riskPostureService');
const settingsService = require('../services/settingsService');

// GET /api/tenant/health
router.get('/health', requirePermission('ops.view'), (req, res) => {
  try {
    const tenantId = req.session?.tenant?.tenantId;
    if (!tenantId) return res.status(401).json({ error: 'Not authenticated' });
    const stats = alertsStore.getStats(tenantId);
    const settings = settingsService.getSettings(tenantId);
    res.json({
      tenantId,
      status: stats.critical > 0 ? 'critical' : stats.high > 0 ? 'warning' : 'healthy',
      stats,
      monitoringActive: true,
      mockMode: settings.mockMode || false,
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/tenant/ops-dashboard
router.get('/ops-dashboard', requirePermission('ops.view'), (req, res) => {
  try {
    const tenantId = req.session?.tenant?.tenantId;
    if (!tenantId) return res.status(401).json({ error: 'Not authenticated' });
    const stats = alertsStore.getStats(tenantId);
    const cases = workflowStore.getCases(tenantId);
    const wfStats = workflowStore.getWorkflowStats(tenantId);
    res.json({
      tenantId,
      stats,
      workflowStats: wfStats,
      openCases: cases.filter(c => c.caseStatus !== 'closed').length,
      overdueCount: cases.filter(c => c.isOverdue).length,
      criticalOpen: cases.filter(c => c.severity === 'critical' && c.status === 'open').length,
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/tenant/roles-matrix
router.get('/roles-matrix', requirePermission('ops.view'), (req, res) => {
  try {
    const tenantId = req.session?.tenant?.tenantId;
    if (!tenantId) return res.status(401).json({ error: 'Not authenticated' });
    const settings = settingsService.getSettings(tenantId);
    res.json({ roles: settings.admins || [], tenantId });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/tenant/orchestrate
router.post('/orchestrate', requirePermission('ops.view'), (req, res) => {
  try {
    const tenantId = req.session?.tenant?.tenantId;
    if (!tenantId) return res.status(401).json({ error: 'Not authenticated' });
    const { action, comment } = req.body;
    res.json({ ok: true, action, tenantId, comment, timestamp: new Date().toISOString() });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
