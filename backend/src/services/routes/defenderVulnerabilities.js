const express = require('express');
const { getTenantIntegration } = require('../services/tenantIntegrationStore');
const {
  listTenantVulnerabilities,
  listTenantRecommendations
} = require('../services/tenantDefenderClient');

const router = express.Router();

function resolveActiveTenantId(req) {
  return req.session?.tenant?.tenantId || null;
}

function buildAdminConsentUrl(req, tenantId) {
  const base = `${req.protocol}://${req.get('host')}`;
  return `${base}/api/auth/admin-consent`;
}

function buildConsentResponse(req, tenantId, message, details = null, statusCode = 403) {
  return {
    statusCode,
    payload: {
      ok: false,
      tenantId,
      error: message,
      needsAdminConsent: true,
      adminConsentUrl: buildAdminConsentUrl(req, tenantId),
      details
    }
  };
}

function getFriendlyError(error) {
  const rawMessage = String(error?.message || '');
  const normalized = rawMessage.toLowerCase();
  const details = error?.details || null;

  if (normalized.includes('missing application roles') || normalized.includes('application roles: .')) {
    return {
      statusCode: 403,
      message: 'This customer tenant has not granted the required Defender admin consent yet.',
      requiresAdminConsent: true,
      details
    };
  }

  if (normalized.includes('consent') && normalized.includes('admin')) {
    return {
      statusCode: 403,
      message: 'This customer tenant must complete Defender admin consent before vulnerability data can be loaded.',
      requiresAdminConsent: true,
      details
    };
  }

  if (normalized.includes('no tvm license')) {
    return {
      statusCode: 403,
      message: 'Live Defender vulnerability data is not available for this customer tenant. A Microsoft Defender Vulnerability Management or eligible TVM license is required.',
      requiresAdminConsent: false,
      details
    };
  }

  if (normalized.includes('unauthorized')) {
    return {
      statusCode: 403,
      message: 'The Defender integration is connected, but this customer tenant is not authorized to return vulnerability data.',
      requiresAdminConsent: false,
      details
    };
  }

  if (normalized.includes('missing for this customer tenant')) {
    return {
      statusCode: 403,
      message: 'The Defender integration is missing credentials for this customer tenant. Check admin consent or shared Defender app credentials.',
      requiresAdminConsent: true,
      details
    };
  }

  if (normalized.includes('not configured for this customer tenant')) {
    return {
      statusCode: 403,
      message: 'The Defender integration is not configured for this customer tenant yet.',
      requiresAdminConsent: true,
      details
    };
  }

  return {
    statusCode: error.status || error.statusCode || 500,
    message: rawMessage || 'Failed to load Defender vulnerability data.',
    requiresAdminConsent: false,
    details
  };
}

router.get('/health', (_req, res) => {
  res.json({ ok: true, service: 'defender-vulnerability-ingest-multi-tenant' });
});

router.get('/tenant/config', async (req, res) => {
  try {
    const tenantId = resolveActiveTenantId(req);
    if (!tenantId) {
      return res.status(401).json({ ok: false, error: 'No authenticated tenant session was found for this request.' });
    }

    const config = await getTenantIntegration(tenantId);
    const consentGrantedAt = config?.consentGrantedAt || req.session?.defenderConsent?.grantedAt || null;
    const configured = !!config;
    const needsAdminConsent = !consentGrantedAt;

    res.json({
      ok: true,
      tenantId,
      configured,
      defenderEnabled: !!config?.defenderEnabled,
      hasClientId: !!config?.defenderClientId,
      hasClientSecret: !!config?.defenderClientSecret,
      tenantName: req.session?.tenant?.tenantName || config?.tenantName || null,
      status: config?.status || null,
      consentGrantedAt,
      needsAdminConsent,
      adminConsentUrl: needsAdminConsent ? buildAdminConsentUrl(req, tenantId) : null
    });
  } catch (error) {
    res.status(error.status || error.statusCode || 500).json({
      ok: false,
      error: error.message,
      details: error.details || null
    });
  }
});

router.get('/vulnerabilities', async (req, res) => {
  try {
    const tenantId = resolveActiveTenantId(req);
    if (!tenantId) {
      return res.status(401).json({ ok: false, error: 'No authenticated tenant session was found for this request.' });
    }

    const top = Number(req.query.top || 100);
    const items = await listTenantVulnerabilities(tenantId, top);

    res.json({ ok: true, tenantId, count: items.length, items });
  } catch (error) {
    const friendly = getFriendlyError(error);
    if (friendly.requiresAdminConsent) {
      const consent = buildConsentResponse(req, resolveActiveTenantId(req), friendly.message, friendly.details, friendly.statusCode);
      return res.status(consent.statusCode).json(consent.payload);
    }

    res.status(friendly.statusCode).json({
      ok: false,
      error: friendly.message,
      details: friendly.details
    });
  }
});

router.get('/recommendations', async (req, res) => {
  try {
    const tenantId = resolveActiveTenantId(req);
    if (!tenantId) {
      return res.status(401).json({ ok: false, error: 'No authenticated tenant session was found for this request.' });
    }

    const top = Number(req.query.top || 100);
    const items = await listTenantRecommendations(tenantId, top);

    res.json({ ok: true, tenantId, count: items.length, items });
  } catch (error) {
    const friendly = getFriendlyError(error);
    if (friendly.requiresAdminConsent) {
      const consent = buildConsentResponse(req, resolveActiveTenantId(req), friendly.message, friendly.details, friendly.statusCode);
      return res.status(consent.statusCode).json(consent.payload);
    }

    res.status(friendly.statusCode).json({
      ok: false,
      error: friendly.message,
      details: friendly.details
    });
  }
});

router.get('/vulnerabilities/:cveId/machines', async (req, res) => {
  const tenantId = resolveActiveTenantId(req);
  return res.status(501).json({
    ok: false,
    tenantId,
    error: 'Machine-level drill-down is not enabled yet for the multi-tenant Defender route.',
  });
});

module.exports = router;
