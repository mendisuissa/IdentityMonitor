const express = require('express');
const router  = express.Router();
const graphService = require('../services/graphService');
const alertsStore  = require('../services/alertsStore');
const auditLog = require('../services/auditLog');
const { requirePermission, getActor } = require('../services/accessControl');
const { MOCK_USERS, MOCK_SIGN_INS } = require('../services/mockData');

const isMock = () => process.env.MOCK_MODE === 'true';

function getTenantId(req) {
  return req.session && req.session.tenant ? req.session.tenant.tenantId : null;
}

function requireTenant(req, res) {
  const tenantId = getTenantId(req);
  if (!tenantId && !isMock()) {
    res.status(401).json({ error: 'Not authenticated — please sign in first' });
    return null;
  }
  return tenantId;
}

// GET /api/users
router.get('/', async (req, res) => {
  try {
    if (isMock()) return res.json(MOCK_USERS);

    const tenantId = requireTenant(req, res);
    if (!tenantId) return;

    const users      = await graphService.getPrivilegedUsers(tenantId);
    const allAlerts  = alertsStore.getAll(tenantId);  // ← tenant-scoped

    const enriched = users.map(user => {
      const userAlerts = allAlerts.filter(a => a.userId === user.id);
      return {
        ...user,
        alertCount: userAlerts.filter(a => a.status === 'open').length,
        lastAlert:  userAlerts[0] || null,
        riskLevel:  calcUserRisk(userAlerts)
      };
    });

    res.json(enriched);
  } catch (err) {
    console.error('[API] GET /users:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// GET /api/users/:userId/signins
router.get('/:userId/signins', async (req, res) => {
  try {
    if (isMock()) return res.json(MOCK_SIGN_INS.filter(s => s.userId === req.params.userId));
    const tenantId = requireTenant(req, res);
    if (!tenantId) return;
    const signIns = await graphService.getUserSignIns(tenantId, req.params.userId, 72);
    res.json(signIns);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/users/:userId/revoke
router.post('/:userId/revoke', async (req, res) => {
  try {
    if (isMock()) return res.json({ success: true, message: '[MOCK] Sessions revoked.' });
    const tenantId = requireTenant(req, res);
    if (!tenantId) return;
    await graphService.revokeUserSessions(tenantId, req.params.userId);
    res.json({ success: true, message: 'Sessions revoked. User will need MFA on next sign-in.' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});


// POST /api/users/:userId/disable
router.post('/:userId/disable', requirePermission('users.respond'), async (req, res) => {
  try {
    if (isMock()) return res.json({ success: true, message: '[MOCK] User disabled.' });
    const tenantId = requireTenant(req, res);
    if (!tenantId) return;
    await graphService.disableUser(tenantId, req.params.userId);
    auditLog.log(tenantId, auditLog.ACTIONS.USER_DISABLED, { userId: req.params.userId }, getActor(req));
    res.json({ success: true, message: 'User account disabled.' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.post('/:userId/enable', requirePermission('users.respond'), async (req, res) => {
  try {
    if (isMock()) return res.json({ success: true, message: '[MOCK] User enabled.' });
    const tenantId = requireTenant(req, res);
    if (!tenantId) return;
    await graphService.enableUser(tenantId, req.params.userId);
    auditLog.log(tenantId, 'response.user_enabled', { userId: req.params.userId }, getActor(req));
    res.json({ success: true, message: 'User account enabled.' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

function calcUserRisk(alerts) {
  const open = alerts.filter(a => a.status === 'open');
  if (open.some(a => a.severity === 'critical')) return 'critical';
  if (open.some(a => a.severity === 'high'))     return 'high';
  if (open.some(a => a.severity === 'medium'))   return 'medium';
  if (open.length > 0)                           return 'low';
  return 'clean';
}

module.exports = router;
