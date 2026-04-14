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
  executeImmediateWindowsUpdate,
  listTenantConfigurationPolicies,
  listTenantDeviceScripts
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

router.get('/catalog/intune-scripts', async (req, res) => {
  try {
    const tenantId = getTenantIdFromRequest({ session: req.session, body: { tenantId: req.query?.tenantId || null } });
    const scripts = await listTenantDeviceScripts(tenantId);
    res.json({ ok: true, tenantId, scripts });
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

// Debug: resolve a finding against the Webapp — call from browser to diagnose
// GET /api/remediation/debug-resolve?productName=microsoft_edge&publisher=microsoft
router.get('/debug-resolve', async (req, res) => {
  try {
    const { resolveApplicationRemediation } = require('../services/webappExecutionClient');
    const { enrichFinding } = require('../services/remediationCatalog');
    const finding = enrichFinding({
      productName: req.query.productName || null,
      softwareName: req.query.softwareName || null,
      publisher: req.query.publisher || null,
      description: req.query.description || null,
      category: req.query.category || 'application',
      cveId: req.query.cveId || null,
    });
    const result = await resolveApplicationRemediation(finding);
    return res.json({ ok: true, finding, result });
  } catch (err) {
    return res.json({ ok: false, error: err?.message, status: err?.status, details: err?.details });
  }
});

router.post('/plan', async (req, res) => {
  try {
    const tenantId = getTenantIdFromRequest(req);
    const { finding = {}, options = {} } = req.body || {};
    const enrichedFinding = enrichFinding(finding);
    const classification = enrichedFinding.classification || classifyFinding(enrichedFinding);

    if (classification.type === 'application') {
      // Plan step: health-check only — fast (~1s). Full WinGet resolve happens during Execute.
      // Doing a full resolve here causes 30s+ timeouts due to deep package lookups.
      const externalHealth = await getExternalHealth();
      if (externalHealth.ok) {
        const plan = {
          executor: 'webapp',
          supported: true,
          remediationType: 'winget-intune-upgrade',
          autoRemediate: true,
          app: null,
          candidates: [],
          checkedSources: [],
          message: 'External remediation service is connected. Click Execute to resolve the package and deploy via Intune.',
          executionMode: 'webapp-live',
          statusCard: {
            code: 'webapp-ready',
            label: 'webapp remediation',
            tone: 'success',
            message: 'Webapp is connected — package resolution and Intune deployment will happen on Execute.'
          },
          executionPath: {
            classification: 'application',
            family: 'software',
            executor: 'webapp',
            status: 'ready',
            route: 'Application → Webapp external remediation'
          },
          external: { connected: true, service: externalHealth.service || 'webapp-remediation-executor', baseUrl: externalHealth.baseUrl }
        };
        return res.json({ ok: true, tenantId, classification, finding, plan });
      }
      // Webapp unreachable
      console.error('[Remediation/plan] webapp health failed:', externalHealth.error, '| status:', externalHealth.status);
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
          message: `External remediation service unreachable: ${externalHealth.error || 'health check failed'}`,
          executionMode: 'guided-manual',
          statusCard: {
            code: 'no-external-service',
            label: 'manual remediation',
            tone: 'warning',
            message: `Webapp unreachable (HTTP ${externalHealth.status || '?'}): ${externalHealth.error || 'health check failed'}`
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
            status: externalHealth.status || 503,
            details: { message: externalHealth.error }
          }
        },
        warning: 'External remediation service is unreachable — showing manual steps.'
      });
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
      } catch (execError) {
        const webappDebug = execError?.details?.debug || null;
        const webappResolution = execError?.details?.resolution || null;
        console.error('[Remediation/execute] webapp call failed:', execError?.message, execError?.status,
          'debug:', JSON.stringify(webappDebug || {}),
          'resolution:', JSON.stringify(webappResolution || {}));
        const isNotSupported = execError?.status === 400;
        return res.json({
          ok: true,
          tenantId,
          approvalId,
          forwardedTo: 'webapp',
          result: {
            supported: false,
            status: isNotSupported ? 'unsupported-application' : 'external-error',
            executionMode: 'guided-manual',
            message: isNotSupported
              ? 'No automated remediation path was found for this application. Use the bundle or manual steps below.'
              : (execError?.message || 'The external remediation service returned an unexpected error.'),
            debug: webappDebug,
          }
        });
      }
    }

    // Immediate Windows Update (Update Now button)
    if ((classification.type === 'windows-update' || options.updateMode === 'immediate') && options.updateMode === 'immediate') {
      const updateType = options.updateType === 'feature' ? 'feature' : 'security';
      const deviceIds = options.deviceIds || devices || [];
      const affectedDeviceNames = options.affectedDeviceNames || enrichedFinding.affectedMachines || [];

      const result = await executeImmediateWindowsUpdate(tenantId, updateType, deviceIds, affectedDeviceNames);
      return res.json({ ok: true, tenantId, approvalId, forwardedTo: 'native', result });
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
