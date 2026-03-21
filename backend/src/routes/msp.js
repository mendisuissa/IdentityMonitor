const express        = require('express');
const router         = express.Router();
const tenantRegistry = require('../services/tenantRegistry');
const alertsStore    = require('../services/alertsStore');
const settingsService = require('../services/settingsService');

// GET /api/msp/tenants
router.get('/tenants', (req, res) => {
  if (process.env.MOCK_MODE === 'true') {
    return res.json(getMockTenants());
  }
  const tenants = tenantRegistry.getAllTenants();
  const summary = tenants.map(t => {
    const alerts    = alertsStore.getAll(t.tenantId);
    const open      = alerts.filter(a => a.status === 'open');
    const trial     = settingsService.getTrialStatus(t.tenantId);
    const riskScore = Math.min(100, open.filter(a => a.severity === 'critical').length * 25 +
                                    open.filter(a => a.severity === 'high').length * 15 +
                                    open.filter(a => a.severity === 'medium').length * 5);
    return {
      tenantId:       t.tenantId,
      tenantName:     t.tenantName || t.primaryEmail?.split('@')[1] || t.tenantId,
      userEmail:      t.primaryEmail,
      connectedAt:    t.connectedAt,
      alertStats:     { open: open.length, critical: open.filter(a => a.severity === 'critical').length, high: open.filter(a => a.severity === 'high').length || 0, total: alerts.length },
      riskScore,
      lastAlertAt:    alerts[0]?.detectedAt || null,
      privilegedUsers: t.health?.privilegedUserCount || 0,
      trialStatus:    trial.status,
      daysLeft:       trial.daysLeft,
      health:         t.health
    };
  });
  res.json(summary);
});

function getMockTenants() {
  return [
    { tenantId: 't1', tenantName: 'Contoso Ltd', userEmail: 'admin@contoso.com', connectedAt: new Date(Date.now() - 5*86400000).toISOString(), alertStats: { open: 3, critical: 1, high: 2, total: 12 }, riskScore: 72, lastAlertAt: new Date(Date.now() - 3600000).toISOString(), privilegedUsers: 4, trialStatus: 'trial', daysLeft: 9 },
    { tenantId: 't2', tenantName: 'Fabrikam Inc', userEmail: 'it@fabrikam.com', connectedAt: new Date(Date.now() - 12*86400000).toISOString(), alertStats: { open: 0, critical: 0, high: 0, total: 3 }, riskScore: 8, lastAlertAt: null, privilegedUsers: 2, trialStatus: 'active', daysLeft: null },
    { tenantId: 't3', tenantName: 'Northwind Corp', userEmail: 'admin@northwind.com', connectedAt: new Date(Date.now() - 2*86400000).toISOString(), alertStats: { open: 7, critical: 3, high: 3, total: 7 }, riskScore: 95, lastAlertAt: new Date(Date.now() - 1800000).toISOString(), privilegedUsers: 8, trialStatus: 'trial', daysLeft: 12 },
    { tenantId: 't4', tenantName: 'Alpine Ski House', userEmail: 'secops@alpine.com', connectedAt: new Date(Date.now() - 30*86400000).toISOString(), alertStats: { open: 1, critical: 0, high: 1, total: 25 }, riskScore: 35, lastAlertAt: new Date(Date.now() - 7200000).toISOString(), privilegedUsers: 3, trialStatus: 'active', daysLeft: null },
  ];
}

module.exports = router;
