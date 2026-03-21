const express = require('express');
const { classifyFinding } = require('../services/remediationCatalog');
const {
  resolveApplicationRemediation,
  executeApplicationRemediation
} = require('../services/webappExecutionClient');
const {
  planNativeRemediation,
  executeNativeRemediation,
} = require('../services/nativeRemediationExecutor');

const router = express.Router();

function getTenantId(req) {
  const sessionTenantId = req.session?.tenant?.tenantId || null;
  const requestedTenantId = req.body?.tenantId || null;

  if (!sessionTenantId) {
    const err = new Error('No authenticated tenant session was found.');
    err.status = 401;
    throw err;
  }

  if (requestedTenantId && requestedTenantId !== sessionTenantId) {
    const err = new Error('Cross-tenant remediation requests are not allowed.');
    err.status = 403;
    throw err;
  }

  return sessionTenantId;
}

function buildExecutionPathForApplication(plan = {}) {
  const base = ['IdentityMonitor'];
  if (plan?.executor === 'webapp') {
    base.push('Webapp remediation executor');
  }
  if (plan?.status === 'bundle created' || plan?.remediationType === 'bundle-created') {
    base.push('Bundle package');
    base.push('Manual operator deployment');
  } else {
    base.push('Live application remediation');
  }
  return base;
}

router.get('/health', (_req, res) => {
  res.json({ ok: true, service: 'identity-remediation-orchestrator' });
});

router.post('/plan', async (req, res) => {
  try {
    const { finding = {}, options = {} } = req.body || {};
    const tenantId = getTenantId(req);
    const classification = classifyFinding(finding);

    if (classification.type === 'application') {
      try {
        const resolution = await resolveApplicationRemediation(finding);
        const external = resolution?.resolution || {};
        const remediationType = external?.remediationType || 'manual-review';
        const bundleCreated = remediationType === 'bundle-created';
        const supported = !!external?.supported;

        const plan = {
          executor: 'webapp',
          executionMode: bundleCreated ? 'external-bundle' : supported ? 'external-live' : 'external-manual',
          status: bundleCreated ? 'bundle created' : supported ? 'live deploy' : 'external not connected',
          remediationType,
          autoRemediate: !!external?.autoRemediate,
          supported,
          app: external?.app || null,
          candidates: external?.candidates || [],
          checkedSources: external?.checkedSources || [],
          message: external?.message || null,
          externalConnected: supported,
          executionPath: buildExecutionPathForApplication({ executor: 'webapp', status: bundleCreated ? 'bundle created' : supported ? 'live deploy' : 'external not connected', remediationType }),
          rawResolution: resolution
        };
        return res.json({ ok: true, tenantId, classification, finding, plan });
      } catch (error) {
        return res.status(error.status || 502).json({
          ok: false,
          tenantId,
          classification,
          error: 'External app remediation is not connected.',
          details: error.details || { message: error.message }
        });
      }
    }

    const native = planNativeRemediation({ tenantId, finding, classification, options });
    return res.json({ ok: true, tenantId, classification, finding, plan: native.plan });
  } catch (error) {
    return res.status(error.status || 500).json({ ok: false, error: error.message, details: error.details || null });
  }
});

router.post('/execute', async (req, res) => {
  try {
    const { approvalId = null, finding = {}, devices = [], plan = {}, options = {} } = req.body || {};
    const tenantId = getTenantId(req);
    const classification = classifyFinding(finding);

    if (classification.type === 'application') {
      if (plan.executor !== 'webapp') {
        return res.status(400).json({ ok: false, error: `Application findings must use the webapp executor. Received: ${plan.executor || 'unknown'}` });
      }

      const result = await executeApplicationRemediation({
        tenantId,
        approvalId,
        finding,
        devices,
        plan,
        options,
      });

      const raw = result?.result || result;
      const remediationType = raw?.remediationType || plan?.remediationType || null;
      const bundleCreated = remediationType === 'bundle-created' || raw?.outcome === 'bundle-created';
      return res.json({
        ok: true,
        tenantId,
        approvalId,
        forwardedTo: 'webapp',
        result: {
          ...raw,
          status: bundleCreated ? 'bundle created' : 'live deploy',
          executionPath: buildExecutionPathForApplication({ executor: 'webapp', status: bundleCreated ? 'bundle created' : 'live deploy', remediationType }),
        }
      });
    }

    if (plan.executor === 'webapp') {
      return res.status(400).json({ ok: false, error: `Native findings cannot be sent to the webapp executor.` });
    }

    const native = executeNativeRemediation({
      tenantId,
      finding,
      classification,
      plan,
      options: { ...options, targetDeviceIds: devices },
    });

    return res.json({ ok: true, tenantId, approvalId, forwardedTo: 'native', result: native.result });
  } catch (error) {
    return res.status(error.status || 500).json({
      ok: false,
      error: error.message,
      details: error.details || null
    });
  }
});

module.exports = router;
