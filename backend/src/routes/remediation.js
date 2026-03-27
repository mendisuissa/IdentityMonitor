const express = require('express');
const { classifyFinding, enrichFinding } = require('../services/remediationCatalog');
const {
  getExternalHealth,
  resolveApplicationRemediation,
  executeApplicationRemediation
} = require('../services/webappExecutionClient');
const {
  planNativeRemediation,
  executeNativeRemediation,
  listTenantConfigurationPolicies
} = require('../services/nativeRemediationExecutor');
const { BUILT_IN_POLICY_TEMPLATES, getRecommendedPolicyTemplates } = require('../services/builtInPolicyTemplates');

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


router.get('/catalog/intune-policies', async (req, res) => {
  try {
    const tenantId = getTenantIdFromRequest({ session: req.session, body: { tenantId: req.query?.tenantId || null } });
    const finding = enrichFinding({
      cveId: req.query?.cveId || null,
      productName: req.query?.productName || null,
      displayProductName: req.query?.displayProductName || null,
      category: req.query?.category || null,
      description: req.query?.description || null,
      classification: {
        type: req.query?.classificationType || null,
        family: req.query?.classificationFamily || null,
      },
    });
    const recommended = getRecommendedPolicyTemplates(finding);
    const tenantPolicies = await listTenantConfigurationPolicies(tenantId);
    res.json({
      ok: true,
      tenantId,
      recommended,
      builtIn: BUILT_IN_POLICY_TEMPLATES,
      tenantPolicies,
    });
  } catch (error) {
    return res.status(error.status || 500).json({ ok: false, error: error.message, details: error.details || null });
  }
});

router.get('/health', async (_req, res) => {
  const external = await getExternalHealth();
  res.json({
    ok: true,
    service: 'identity-remediation-orchestrator',
    graphConfigured: !!process.env.CLIENT_ID && !!process.env.CLIENT_SECRET,
    external
  });
});

router.post('/plan', async (req, res) => {
  try {
    const tenantId = getTenantIdFromRequest(req);
    const { finding = {}, options = {} } = req.body || {};
    const enrichedFinding = enrichFinding(finding);
    const classification = enrichedFinding.classification || classifyFinding(enrichedFinding);

    if (classification.type === 'application') {
      try {
        const resolution = await resolveApplicationRemediation(enrichedFinding);
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
          external: { connected: true },
          rawResolution: resolution
        };
        return res.json({ ok: true, tenantId, classification, finding, plan });
      } catch (error) {
        return res.json({
          ok: true,
          tenantId,
          classification,
          finding: enrichedFinding,
          plan: {
            executor: 'webapp',
            supported: false,
            remediationType: 'manual-review',
            autoRemediate: false,
            app: null,
            candidates: [],
            checkedSources: [],
            message: 'No external remediation service is configured for this tenant. Use manual remediation steps below.',
            executionMode: 'guided-manual',
            statusCard: {
              code: 'no-external-service',
              label: 'manual remediation',
              tone: 'warning',
              message: 'No external remediation service is connected. Follow the manual steps to remediate this finding.'
            },
            executionPath: {
              classification: 'application',
              family: 'software',
              executor: 'guided-manual',
              status: 'manual',
              route: 'Application -> Manual remediation'
            },
            manualSteps: [
              'Identify all affected devices using the Exposed devices tab.',
              'Apply the vendor-recommended update or patch on each affected device.',
              'Verify remediation by re-running a Defender scan.',
              'Document the action taken and mark the case as resolved.'
            ],
            external: {
              connected: false,
              status: error.status || 503,
              details: error.details || { message: error.message }
            }
          },
          warning: 'No external remediation service configured — showing manual steps.'
        });
      }
    }

    const plan = await planNativeRemediation({ classification, finding: enrichedFinding, options });
    return res.json({ ok: true, tenantId, classification, finding: enrichedFinding, plan });
  } catch (error) {
    return res.status(error.status || 500).json({ ok: false, error: error.message, details: error.details || null });
  }
});

router.post('/execute', async (req, res) => {
  try {
    const tenantId = getTenantIdFromRequest(req);
    const { approvalId = null, finding = {}, devices = [], plan = {}, options = {} } = req.body || {};
    const enrichedFinding = enrichFinding(finding);
    const classification = enrichedFinding.classification || classifyFinding(enrichedFinding);

    if (plan.executor === 'webapp' || classification.type === 'application') {
      try {
        const result = await executeApplicationRemediation({ tenantId, approvalId, finding: enrichedFinding, devices, plan, options });
        return res.json({ ok: true, tenantId, approvalId, forwardedTo: 'webapp', result });
      } catch (_error) {
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
      finding: enrichedFinding,
      classification,
      options: {
        ...options,
        deviceIds: options.deviceIds || devices,
        affectedDeviceNames: options.affectedDeviceNames || enrichedFinding.affectedMachines || []
      }
    });
    return res.json({ ok: true, tenantId, approvalId, forwardedTo: 'native', result });
  } catch (error) {
    return res.status(error.status || 500).json({ ok: false, error: error.message, details: error.details || null });
  }
});

module.exports = router;
