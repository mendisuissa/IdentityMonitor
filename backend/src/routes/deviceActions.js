const express = require('express');
const router = express.Router();
const { requirePermission } = require('../services/accessControl');
const auditLog = require('../services/auditLog');

const MOCK_DEVICE_ACTIONS = [
  { id: 'da-1', type: 'wipe', deviceName: 'LAPTOP-XF892', userPrincipalName: 'alex.johnson@company.com', userDisplayName: 'Alex Johnson', initiatedBy: 'sarah.chen@company.com', timestamp: new Date(Date.now() - 5 * 60000).toISOString(), severity: 'critical', status: 'completed', os: 'Windows 11', deviceId: 'dev-001' },
  { id: 'da-2', type: 'reset', deviceName: 'DESKTOP-KL445', userPrincipalName: 'daniel.kim@company.com', userDisplayName: 'Daniel Kim', initiatedBy: 'IT Admin', timestamp: new Date(Date.now() - 22 * 60000).toISOString(), severity: 'high', status: 'in_progress', os: 'Windows 10', deviceId: 'dev-002' },
  { id: 'da-3', type: 'delete', deviceName: 'SURFACE-PRO-9', userPrincipalName: 'rachel.green@company.com', userDisplayName: 'Rachel Green', initiatedBy: 'rachel.green@company.com', timestamp: new Date(Date.now() - 48 * 60000).toISOString(), severity: 'high', status: 'completed', os: 'Windows 11', deviceId: 'dev-003' },
  { id: 'da-4', type: 'wipe', deviceName: 'LAPTOP-MK221', userPrincipalName: 'mike.turner@company.com', userDisplayName: 'Mike Turner', initiatedBy: 'IT Admin', timestamp: new Date(Date.now() - 3 * 3600000).toISOString(), severity: 'critical', status: 'completed', os: 'macOS Ventura', deviceId: 'dev-004' },
];

// GET /api/device-actions
router.get('/', requirePermission('alerts.view'), async (req, res) => {
  try {
    const tenantId = req.session?.tenant?.tenantId;
    const isMock = process.env.MOCK_MODE === 'true';

    if (isMock || !tenantId) {
      return res.json(MOCK_DEVICE_ACTIONS);
    }

    // In live mode — try Intune via Graph API
    try {
      const graphService = require('../services/graphService');
      const actions = await graphService.getDeviceActions(tenantId).catch((err) => {
        console.error('[DeviceActions] graphService.getDeviceActions threw:', err?.message);
        return null;
      });
      console.log('[DeviceActions] live result: actions=', Array.isArray(actions) ? actions.length : actions);
      if (Array.isArray(actions) && actions.length > 0) {
        return res.json(actions);
      }
      // No real actions found — return mock with a flag so frontend can show it
      console.log('[DeviceActions] no real Intune actions found, returning mock');
      return res.json(MOCK_DEVICE_ACTIONS.map(a => ({ ...a, _isMock: true })));
    } catch (err) {
      console.error('[DeviceActions] unexpected error:', err?.message);
      return res.json(MOCK_DEVICE_ACTIONS.map(a => ({ ...a, _isMock: true })));
    }
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/device-actions/:id/acknowledge
router.post('/:id/acknowledge', requirePermission('alerts.respond'), (req, res) => {
  const tenantId = req.session?.tenant?.tenantId || 'mock-tenant';
  const actor = req.session?.tenant?.userEmail || 'unknown';
  auditLog.log(tenantId, 'device_action.acknowledged', { deviceActionId: req.params.id }, actor);
  res.json({ ok: true, id: req.params.id });
});

module.exports = router;
