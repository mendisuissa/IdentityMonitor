const express = require('express');
const router  = express.Router();
const graphService    = require('../services/graphService');
const { MOCK_SIGN_INS } = require('../services/mockData');

const isMock = () => process.env.MOCK_MODE === 'true';

router.get('/', async (req, res) => {
  try {
    if (isMock()) return res.json(MOCK_SIGN_INS);

    const tenantId = req.session && req.session.tenant ? req.session.tenant.tenantId : null;
    if (!tenantId) return res.status(401).json({ error: 'Not authenticated' });

    const hours   = parseInt(req.query.hours) || 24;

    try {
      const signIns = await graphService.getAllPrivilegedSignIns(tenantId, hours);
      res.json(signIns);
    } catch (graphErr) {
      // Provide helpful error if it's a license/permission issue
      const msg = graphErr.message || '';
      if (msg.includes('Authorization_RequestDenied') || msg.includes('Forbidden')) {
        return res.status(403).json({
          error: 'Access denied to sign-in logs',
          hint:  'AuditLog.Read.All permission requires Entra ID P1 or P2 license. Ensure admin consent was granted and the tenant has the required license.',
          graphError: msg
        });
      }
      throw graphErr;
    }
  } catch (err) {
    console.error('[API] GET /signins:', err.message);
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
