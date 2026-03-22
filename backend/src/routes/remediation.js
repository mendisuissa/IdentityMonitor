const express = require('express');
const { classifyFinding } = require('../services/remediationCatalog');
const {
  getExternalHealth,
  resolveApplicationRemediation,
  executeApplicationRemediation
} = require('../services/webappExecutionClient');
const {
  planNativeRemediation,
  executeNativeRemediation
} = require('../services/nativeRemediationExecutor');

const router = express.Router();

function getTenantIdFromRequest(req) {
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

router.get('/health', async (_req, res) => {
  const external = await getExternalHealth();
  res.json({ ok: true, service: 'identity-remediation-orchestrator', external });
});

router.post('/plan', async (req, res) => {
  try {
    const tenantId = getTenantIdFromRequest(req);
    const { finding = {}, options = {} } = req.body || {};
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
          executionMode: resolution?.resolution?.executionMode || 'webapp-live',
          statusCard: resolution?.resolution?.statusCard || null,
          executionPath: resolution?.resolution?.executionPath || {
            classification: 'application',
            family: 'software',
            executor: 'webapp',
            status: 'ready',
            route: 'Application -> Webapp external remediation'
          },
          rawResolution: resolution
        };
        return res.json({ ok: true, tenantId, classification, finding, plan });
      } catch (error) {
        return res.json({
          ok: true,
          tenantId,
          classification,
          finding,
          plan: {
            executor: 'webapp',
            supported: false,
            remediationType: 'manual-review',
            autoRemediate: false,
            app: null,
            candidates: [],
            checkedSources: [],
            message: error?.details?.message || 'Not connected. Click Connect first.',
            executionMode: 'external-not-connected',
            statusCard: {
              code: 'external-not-connected',
              label: 'external not connected',
              tone: 'danger',
              message: error?.details?.message || 'Not connected. Click Connect first.'
            },
            executionPath: {
              classification: 'application',
              family: 'software',
              executor: 'webapp',
              status: 'external-not-connected',
              route: 'Application -> Webapp external remediation'
            },
            external: {
              connected: false,
              status: error.status || 401,
              details: error.details || { message: error.message }
            }
          },
          warning: 'External app remediation is not connected.'
        });
      }
    }

    const plan = await planNativeRemediation({ classification, finding, options });
    return res.json({ ok: true, tenantId, classification, finding, plan });
  } catch (error) {
    return res.status(error.status || 500).json({ ok: false, error: error.message, details: error.details || null });
  }
});

router.post('/execute', async (req, res) => {
  try {
    const tenantId = getTenantIdFromRequest(req);
    const { approvalId = null, finding = {}, devices = [], plan = {}, options = {} } = req.body || {};
    const classification = classifyFinding(finding);

    if (plan.executor === 'webapp' || classification.type === 'application') {
      try {
        const result = await executeApplicationRemediation({
          tenantId,
          approvalId,
          finding,
          devices,
          plan,
          options
        });

        return res.json({ ok: true, tenantId, approvalId, forwardedTo: 'webapp', result });
      } catch (error) {
        return res.json({
          ok: true,
          tenantId,
          approvalId,
          forwardedTo: 'webapp',
          result: {
            supported: false,
            status: 'external-not-connected',
            executionMode: 'guided-manual',
            message: 'External application remediation is not connected. Review the plan and connect the Webapp remediation service first.'
          }
        });
      }
    }

    const result = await executeNativeRemediation({
      tenantId,
      finding,
      classification,
      options: {
        ...options,
        deviceIds: options.deviceIds || devices
      }
    });

    return res.json({ ok: true, tenantId, approvalId, forwardedTo: 'native', result });
  } catch (error) {
    return res.status(error.status || 500).json({
      ok: false,
      error: error.message,
      details: error.details || null
    });
  }
});

module.exports = router;
