const express    = require('express');
const router     = express.Router();
const pimService = require('../services/pimService');

function getTenantId(req) {
  return req.session?.tenant?.tenantId || (process.env.MOCK_MODE === 'true' ? 'mock-tenant' : null);
}

// GET /api/pim/analyze
router.get('/analyze', async (req, res) => {
  const tenantId = getTenantId(req);
  if (!tenantId) return res.status(401).json({ error: 'Not authenticated' });

  if (process.env.MOCK_MODE === 'true') {
    return res.json(getMockPimAnalysis());
  }

  try {
    const result = await pimService.analyzePimStatus(tenantId);
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

function getMockPimAnalysis() {
  return {
    score: 42,
    grade: { letter: 'D', label: 'Poor', color: '#ff6b35' },
    findings: [
      {
        type: 'PIM_NOT_CONFIGURED', severity: 'critical', count: 4,
        title: 'PIM (Just-in-Time) is not configured',
        detail: 'All 4 privileged role assignments are permanent. No JIT access found.',
        recommendation: 'Enable Privileged Identity Management. Requires Entra ID P2 license.'
      },
      {
        type: 'PERMANENT_CRITICAL_ROLE', severity: 'critical', count: 2,
        title: '2 permanent Global Administrator assignments',
        detail: 'Global Administrator should use Just-in-Time access only.',
        users: [
          { userId: 'u1', roleName: 'Global Administrator', assignedAt: '2024-01-15' },
          { userId: 'u2', roleName: 'Global Administrator', assignedAt: '2023-08-20' }
        ],
        recommendation: 'Convert to Eligible assignment in PIM.'
      }
    ],
    recommendations: [
      {
        priority: 'critical',
        action: 'Enable Privileged Identity Management (PIM)',
        impact: 'JIT access eliminates 80%+ of insider threat and credential theft risk',
        effort: 'medium',
        howTo: 'Entra Admin → Identity Governance → Privileged Identity Management → Discover',
        requiresLicense: 'Entra ID P2'
      },
      {
        priority: 'high',
        action: 'Convert permanent Global Admins to PIM Eligible',
        impact: 'Standing access eliminated — attack window reduced to activation duration only',
        effort: 'low',
        howTo: 'PIM → Azure AD roles → Assignments → Add eligible assignment'
      }
    ],
    stats: { permanentCount: 4, eligibleCount: 0, globalAdmins: 2, criticalPermanent: 2, pimEnabled: false },
    analyzedAt: new Date().toISOString()
  };
}

module.exports = router;
