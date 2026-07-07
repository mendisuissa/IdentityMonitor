const express        = require('express');
const router         = express.Router();
const tenantRegistry = require('../services/tenantRegistry');
const alertsStore    = require('../services/alertsStore');
const settingsService = require('../services/settingsService');

const SUPERADMIN_EMAILS = (process.env.SUPERADMIN_EMAILS || '')
  .split(',').map(e => e.trim().toLowerCase()).filter(Boolean);

function isSuperAdmin(req) {
  const email = (req.session?.tenant?.userEmail || '').toLowerCase().trim();
  return SUPERADMIN_EMAILS.includes(email);
}

// GET /api/msp/tenants — superadmin only (auth required even in MOCK_MODE)
router.get('/tenants', async (req, res) => {
  if (!req.session?.tenant?.tenantId) {
    return res.status(401).json({ error: 'Authentication required' });
  }
  if (!isSuperAdmin(req)) {
    return res.status(403).json({ error: 'Access denied' });
  }
  try {
    const tenants = await tenantRegistry.getAllTenants();
    const summary = tenants.map(t => {
      try {
        const alerts    = alertsStore.getAll(t.tenantId);
        const open      = alerts.filter(a => a.status === 'open');
        const trial     = settingsService.getTrialStatus(t.tenantId);
        const riskScore = Math.min(100, open.filter(a => a.severity === 'critical').length * 25 +
                                        open.filter(a => a.severity === 'high').length * 15 +
                                        open.filter(a => a.severity === 'medium').length * 5);
        return {
          tenantId:        t.tenantId,
          tenantName:      t.tenantName || t.primaryEmail?.split('@')[1] || t.tenantId,
          userEmail:       t.primaryEmail,
          connectedAt:     t.connectedAt,
          alertStats:      { open: open.length, critical: open.filter(a => a.severity === 'critical').length, high: open.filter(a => a.severity === 'high').length || 0, total: alerts.length },
          riskScore,
          lastAlertAt:     alerts[0]?.detectedAt || null,
          privilegedUsers: t.health?.privilegedUserCount || 0,
          trialStatus:     trial.status,
          daysLeft:        trial.daysLeft,
          health:          t.health
        };
      } catch (e) {
        return { tenantId: t.tenantId, tenantName: t.tenantId, error: e.message };
      }
    });
    res.json(summary);
  } catch (err) {
    console.error('[MSP] /tenants error:', err.message);
    res.status(500).json({ error: 'Failed to load tenant list', detail: err.message });
  }
});

module.exports = router;
