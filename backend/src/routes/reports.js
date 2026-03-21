const express = require('express');
const router = express.Router();
const { requirePermission } = require('../services/accessControl');
const riskPostureService = require('../services/riskPostureService');
const alertsStore = require('../services/alertsStore');
const workflowStore = require('../services/workflowStore');
const settingsService = require('../services/settingsService');

// GET /api/reports/risk-posture
router.get('/risk-posture', requirePermission('alerts.view'), (req, res) => {
  try {
    const tenantId = req.session?.tenant?.tenantId;
    if (!tenantId) return res.status(401).json({ error: 'Not authenticated' });
    const posture = riskPostureService.getRiskPosture(tenantId);
    res.json(posture);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/reports/executive-snapshot
router.get('/executive-snapshot', requirePermission('alerts.view'), (req, res) => {
  try {
    const tenantId = req.session?.tenant?.tenantId;
    if (!tenantId) return res.status(401).json({ error: 'Not authenticated' });

    const alerts = alertsStore.getAll(tenantId);
    const stats = alertsStore.getStats(tenantId);
    const cases = workflowStore.getCases(tenantId);
    const wfStats = workflowStore.getWorkflowStats(tenantId);
    const posture = riskPostureService.getRiskPosture(tenantId);

    const resolved = alerts.filter(a => a.status === 'resolved').length;
    const resolutionRate = alerts.length > 0
      ? Math.round((resolved / alerts.length) * 100)
      : 0;

    const byType = alerts.reduce((acc, a) => {
      acc[a.anomalyLabel] = (acc[a.anomalyLabel] || 0) + 1;
      return acc;
    }, {});

    const topAnomalyTypes = Object.entries(byType)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 5)
      .map(([type, count]) => ({ type, count }));

    res.json({
      generatedAt: new Date().toISOString(),
      tenantId,
      stats,
      resolutionRate,
      topAnomalyTypes,
      riskPosture: posture,
      workflowStats: wfStats,
      openCases: cases.filter(c => c.caseStatus !== 'closed').length,
      overdueCount: cases.filter(c => c.isOverdue).length,
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/reports/executive/export
router.get('/executive/export', requirePermission('alerts.view'), (req, res) => {
  try {
    const tenantId = req.session?.tenant?.tenantId;
    if (!tenantId) return res.status(401).json({ error: 'Not authenticated' });
    const alerts = alertsStore.getAll(tenantId);
    const format = req.query.format || 'csv';

    if (format === 'csv') {
      const headers = ['id','severity','anomalyLabel','userDisplayName','userPrincipalName','status','detectedAt','ipAddress','country'];
      const rows = alerts.map(a => headers.map(h => JSON.stringify(a[h] ?? '')).join(','));
      res.setHeader('Content-Type', 'text/csv');
      res.setHeader('Content-Disposition', 'attachment; filename="executive-report.csv"');
      res.send([headers.join(','), ...rows].join('\n'));
    } else {
      res.json(alerts);
    }
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
