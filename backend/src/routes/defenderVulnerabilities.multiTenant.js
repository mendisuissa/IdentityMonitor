const express = require('express');
const { getTenantIntegration } = require('../services/tenantIntegrationStore');
const {
  listTenantVulnerabilities,
  listTenantRecommendations
} = require('../services/tenantDefenderClient');

const router = express.Router();

function resolveActiveTenantId(req) {
  return (
    req.headers['x-tenant-id'] ||
    req.user?.tenantId ||
    req.session?.tenantId ||
    req.query?.tenantId ||
    null
  );
}

function getFriendlyErrorMessage(error) {
  const raw = String(error?.message || '').toLowerCase();

  if (raw.includes('no tvm license')) {
    return 'Live Defender vulnerability data is not available for this customer tenant. A Microsoft Defender Vulnerability Management or eligible TVM license is required.';
  }

  if (raw.includes('unauthorized')) {
    return 'The Defender integration is connected, but this customer tenant is not authorized to return vulnerability data.';
  }

  return error?.message || 'Failed to load Defender vulnerability data.';
}

router.get('/health', (_req, res) => {
  res.json({ ok: true, service: 'defender-vulnerability-ingest-multi-tenant' });
});

router.get('/tenant/config', async (req, res) => {
  try {
    const tenantId = resolveActiveTenantId(req);
    if (!tenantId) {
      return res.status(400).json({ ok: false, error: 'No tenant id was resolved for this request.' });
    }

    const config = await getTenantIntegration(tenantId);

    res.json({
      ok: true,
      tenantId,
      configured: !!config,
      defenderEnabled: !!config?.defenderEnabled,
      hasClientId: !!config?.defenderClientId,
      hasClientSecret: !!config?.defenderClientSecret,
      tenantName: config?.tenantName || null,
      status: config?.status || null
    });
  } catch (error) {
    res.status(error.status || 500).json({ ok: false, error: error.message });
  }
});

router.get('/vulnerabilities', async (req, res) => {
  try {
    const tenantId = resolveActiveTenantId(req);
    if (!tenantId) {
      return res.status(400).json({ ok: false, error: 'No tenant id was resolved for this request.' });
    }

    const top = Number(req.query.top || 100);
    const items = await listTenantVulnerabilities(tenantId, top);

    res.json({ ok: true, tenantId, count: items.length, items });
  } catch (error) {
    res.status(error.status || 500).json({
      ok: false,
      error: getFriendlyErrorMessage(error),
      details: error.details || null
    });
  }
});

router.get('/recommendations', async (req, res) => {
  try {
    const tenantId = resolveActiveTenantId(req);
    if (!tenantId) {
      return res.status(400).json({ ok: false, error: 'No tenant id was resolved for this request.' });
    }

    const top = Number(req.query.top || 100);
    const items = await listTenantRecommendations(tenantId, top);

    res.json({ ok: true, tenantId, count: items.length, items });
  } catch (error) {
    res.status(error.status || 500).json({
      ok: false,
      error: getFriendlyErrorMessage(error),
      details: error.details || null
    });
  }
});

module.exports = router;
