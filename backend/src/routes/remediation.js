const express = require('express');
const { classifyFinding } = require('../services/remediationCatalog');
const nativeExecutor = require('../services/nativeRemediationExecutor');
const {
  getExternalHealth,
  resolveApplicationRemediation,
  executeApplicationRemediation
} = require('../services/webappExecutionClient');

const router = express.Router();

function buildStatusCard(code, label, tone, message) {
  return { code, label, tone, message };
}

function buildExternalNotConnectedPlan(classification, externalHealth) {
  const message = externalHealth?.details?.message || externalHealth?.error || 'Not connected. Click Connect first.';

  return {
    executor: 'webapp',
    supported: false,
    remediationType: 'manual-review',
    autoRemediate: false,
    app: null,
    candidates: [],
    checkedSources: [],
    message,
    executionMode: 'external-not-connected',
    statusCard: buildStatusCard('external-not-connected', 'external not connected', 'danger', message),
    executionPath: {
      classification: classification.type,
      family: classification.family,
      executor: 'webapp',
      status: 'external-not-connected',
      route: 'Application -> Webapp external remediation'
    },
    external: {
      connected: false,
      status: externalHealth?.status || 401,
      details: externalHealth?.details || { message },
      baseUrl: externalHealth?.baseUrl || null,
      tokenConfigured: !!externalHealth?.tokenConfigured,
      sharedTokenConfigured: !!externalHealth?.sharedTokenConfigured,
      sharedTokenAccepted: !!externalHealth?.sharedTokenAccepted
    }
  };
}

router.get('/health', async (_req, res) => {
  const external = await getExternalHealth();
  res.json({ ok: true, service: 'identity-remediation-orchestrator', external });
});

router.post('/plan', async (req, res) => {
  try {
    const sessionTenantId = req.session?.tenant?.tenantId || null;
    const requestedTenantId = req.body?.tenantId || null;

    if (!sessionTenantId) {
      return res.status(401).json({ ok: false, error: 'No authenticated tenant session was found.' });
    }

    if (requestedTenantId && requestedTenantId !== sessionTenantId) {
      return res.status(403).json({ ok: false, error: 'Cross-tenant remediation requests are not allowed.' });
    }

    const { finding = {} } = req.body || {};
    const tenantId = sessionTenantId;
    const classification = classifyFinding(finding);

    if (classification.type === 'application') {
      try {
        const resolution = await resolveApplicationRemediation(finding);
        const plan = {
          executor: 'webapp',
          supported: !!resolution?.resolution?.supported,
          remediationType: resolution?.resolution?.remediationType || 'manual-review',
          autoRemediate: !!resolution?.resolution?.autoRemediate,
          app: resolution?.resolution?.app || null,
          candidates: resolution?.resolution?.candidates || [],
          checkedSources: resolution?.resolution?.checkedSources || [],
          message: resolution?.resolution?.message || null,
          executionMode: resolution?.resolution?.executionMode || (resolution?.resolution?.supported ? 'live-deploy' : 'guided-manual'),
          statusCard: resolution?.resolution?.statusCard || buildStatusCard(
            resolution?.resolution?.supported ? 'live-deploy' : 'manual-review-required',
            resolution?.resolution?.supported ? 'live deploy' : 'manual review required',
            resolution?.resolution?.supported ? 'success' : 'warning',
            resolution?.resolution?.message || null
          ),
          executionPath: resolution?.resolution?.executionPath || {
            classification: classification.type,
            family: classification.family,
            executor: 'webapp',
            status: resolution?.resolution?.supported ? 'live-deploy' : 'manual-review-required',
            route: 'Application -> Webapp external remediation'
          },
          rawResolution: resolution
        };
        return res.json({ ok: true, tenantId, classification, finding, plan });
      } catch (error) {
        const externalHealth = await getExternalHealth();
        const plan = buildExternalNotConnectedPlan(classification, externalHealth);
        return res.json({
          ok: true,
          tenantId,
          classification,
          finding,
          plan,
          warning: 'External app remediation is not connected.'
        });
      }
    }

    const nativePlan = nativeExecutor.plan(classification, finding);
    return res.json({ ok: true, tenantId, classification, finding, plan: nativePlan });
  } catch (error) {
    return res.status(error.status || 500).json({ ok: false, error: error.message, details: error.details || null });
  }
});

router.post('/execute', async (req, res) => {
  try {
    const sessionTenantId = req.session?.tenant?.tenantId || null;
    const requestedTenantId = req.body?.tenantId || null;

    if (!sessionTenantId) {
      return res.status(401).json({ ok: false, error: 'No authenticated tenant session was found.' });
    }

    if (requestedTenantId && requestedTenantId !== sessionTenantId) {
      return res.status(403).json({ ok: false, error: 'Cross-tenant remediation requests are not allowed.' });
    }

    const { approvalId = null, finding = {}, devices = [], plan = {} } = req.body || {};
    const tenantId = sessionTenantId;
    const classification = classifyFinding(finding);

    if (plan.executor === 'webapp' || classification.type === 'application') {
      try {
        const result = await executeApplicationRemediation({
          tenantId,
          approvalId,
          finding,
          devices,
          plan
        });

        return res.json({ ok: true, tenantId, approvalId, forwardedTo: 'webapp', result });
      } catch (error) {
        const externalHealth = await getExternalHealth();
        return res.json({
          ok: true,
          tenantId,
          approvalId,
          forwardedTo: 'webapp',
          result: {
            supported: false,
            status: 'external-not-connected',
            executionMode: 'guided-manual',
            message: 'External application remediation is not connected. Review the plan and connect the Webapp remediation service first.',
            external: externalHealth
          }
        });
      }
    }

    const result = nativeExecutor.execute(classification, {
      approvalId,
      finding,
      devices,
      plan,
      tenantId
    });

    return res.json({ ok: true, tenantId, approvalId, result });
  } catch (error) {
    return res.status(error.status || 500).json({
      ok: false,
      error: error.message,
      details: error.details || null
    });
  }
});

module.exports = router;
