const express = require('express');
const { classifyFinding } = require('../services/remediationCatalog');
const {
  resolveApplicationRemediation,
  executeApplicationRemediation
} = require('../services/webappExecutionClient');
const {
  planNativeRemediation,
  executeNativeRemediation
} = require('../services/nativeRemediationExecutor');

const router = express.Router();

function normalizeRebootBehavior(value) {
  const normalized = String(value || '').toLowerCase();
  if (['force', 'force-reboot', 'forcerestart'].includes(normalized)) return 'force-reboot';
  if (['defer', 'defer-reboot', 'suppress'].includes(normalized)) return 'defer-reboot';
  return 'reboot-if-required';
}

function normalizeOptions(options = {}) {
  return {
    updateType: String(options.updateType || 'security').toLowerCase() === 'feature' ? 'feature' : 'security',
    rebootBehavior: normalizeRebootBehavior(options.rebootBehavior),
    targetDeviceIds: Array.isArray(options.targetDeviceIds)
      ? options.targetDeviceIds.filter(Boolean)
      : String(options.targetDeviceIds || '')
          .split(/[\n,;]+/)
          .map((value) => value.trim())
          .filter(Boolean)
  };
}

function buildExecutionPath(classification, executor, status) {
  const route = classification?.type === 'application'
    ? 'Application -> Webapp external remediation'
    : classification?.type === 'windows-update'
      ? 'Platform -> Native Windows Update executor'
      : classification?.type === 'intune-policy'
        ? 'Configuration -> Native Intune policy executor'
        : classification?.type === 'script'
          ? 'Configuration -> Native Script / Proactive Remediation executor'
          : 'Guided manual review';

  return {
    classification: classification?.type || 'manual',
    family: classification?.family || 'manual',
    executor: executor || 'manual',
    status: status || 'manual-review-required',
    route
  };
}

function buildStatusCard(status, message) {
  const cards = {
    'live-deploy': {
      code: 'live-deploy',
      label: 'live deploy',
      tone: 'success',
      message: message || 'Live remediation execution is available for this finding.'
    },
    'bundle-created': {
      code: 'bundle-created',
      label: 'bundle created',
      tone: 'info',
      message: message || 'A remediation bundle was created and can be downloaded.'
    },
    'manual-review-required': {
      code: 'manual-review-required',
      label: 'manual review required',
      tone: 'warning',
      message: message || 'Review the remediation guidance before executing changes.'
    },
    'external-not-connected': {
      code: 'external-not-connected',
      label: 'external not connected',
      tone: 'danger',
      message: message || 'External application remediation is not connected.'
    },
    'native-queued': {
      code: 'native-queued',
      label: 'live deploy',
      tone: 'success',
      message: message || 'Native remediation request was queued.'
    },
    'guided': {
      code: 'guided',
      label: 'manual review required',
      tone: 'warning',
      message: message || 'Guided remediation is available, but live execution is not enabled yet.'
    }
  };

  return cards[status] || cards['manual-review-required'];
}

function inferExecutionStatus(result = {}, plan = {}) {
  const delivery = result?.delivery || result?.result?.delivery || {};
  const bundle = delivery?.bundle || result?.bundle || null;

  if (bundle?.downloadUrl || bundle?.base64 || result?.bundleCreated || result?.status === 'bundle-created') {
    return 'bundle-created';
  }

  if (result?.queued || result?.deployed || result?.live || result?.status === 'live-deploy') {
    return 'live-deploy';
  }

  if (plan?.statusCard?.code === 'external-not-connected') {
    return 'external-not-connected';
  }

  return 'manual-review-required';
}

router.get('/health', (_req, res) => {
  res.json({ ok: true, service: 'identity-remediation-orchestrator' });
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

    const { finding = {}, options = {} } = req.body || {};
    const tenantId = sessionTenantId;
    const classification = classifyFinding(finding);
    const normalizedOptions = normalizeOptions(options);

    if (classification.type === 'application') {
      try {
        const resolution = await resolveApplicationRemediation(finding);
        const remediationType = resolution?.resolution?.remediationType || 'manual-review';
        const supported = !!resolution?.resolution?.supported;
        const live = !!resolution?.resolution?.autoRemediate;
        const status = remediationType === 'bundle-created' ? 'bundle-created' : live ? 'live-deploy' : 'manual-review-required';
        const plan = {
          executor: 'webapp',
          supported,
          remediationType,
          autoRemediate: live,
          app: resolution?.resolution?.app || null,
          candidates: resolution?.resolution?.candidates || [],
          checkedSources: resolution?.resolution?.checkedSources || [],
          message: resolution?.resolution?.message || null,
          executionMode: live ? 'external-live-deploy' : remediationType,
          statusCard: buildStatusCard(status, resolution?.resolution?.message),
          executionPath: buildExecutionPath(classification, 'webapp', status),
          rawResolution: resolution
        };
        return res.json({ ok: true, tenantId, classification, finding, plan });
      } catch (error) {
        const message = error?.details?.details?.message || error?.details?.message || error.message;
        const plan = {
          executor: 'webapp',
          supported: false,
          remediationType: 'manual-review',
          autoRemediate: false,
          app: null,
          candidates: [],
          checkedSources: [],
          message,
          executionMode: 'external-not-connected',
          statusCard: buildStatusCard('external-not-connected', message),
          executionPath: buildExecutionPath(classification, 'webapp', 'external-not-connected'),
          external: {
            connected: false,
            status: error.status || 502,
            details: error.details || null
          }
        };
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

    const nativePlan = await planNativeRemediation({ classification, finding, options: normalizedOptions });
    const nativeStatus = classification.type === 'windows-update' ? 'live-deploy' : nativePlan?.supported ? 'guided' : 'manual-review-required';
    const plan = {
      ...nativePlan,
      options: normalizedOptions,
      statusCard: buildStatusCard(nativeStatus, nativePlan?.message || nativePlan?.note),
      executionPath: buildExecutionPath(classification, nativePlan.executor || classification.type, nativeStatus)
    };

    return res.json({ ok: true, tenantId, classification, finding, plan });
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

    const { approvalId = null, finding = {}, devices = [], plan = {}, options = {} } = req.body || {};
    const tenantId = sessionTenantId;
    const classification = classifyFinding(finding);
    const normalizedOptions = normalizeOptions(options);

    if (classification.type === 'application') {
      if (plan?.statusCard?.code === 'external-not-connected' || plan?.executionMode === 'external-not-connected') {
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

      const result = await executeApplicationRemediation({
        tenantId,
        approvalId,
        finding,
        devices,
        plan,
        options: normalizedOptions
      });

      const derivedStatus = inferExecutionStatus(result, plan);

      return res.json({
        ok: true,
        tenantId,
        approvalId,
        forwardedTo: 'webapp',
        result: {
          ...result,
          status: derivedStatus,
          statusCard: buildStatusCard(derivedStatus, result?.message)
        }
      });
    }

    const result = await executeNativeRemediation({
      tenantId,
      finding,
      classification,
      options: normalizedOptions,
      devices,
      plan
    });

    const status = result?.queued ? 'native-queued' : result?.supported ? 'guided' : 'manual-review-required';

    return res.json({
      ok: true,
      tenantId,
      approvalId,
      forwardedTo: 'native',
      result: {
        ...result,
        status,
        statusCard: buildStatusCard(status, result?.message)
      }
    });
  } catch (error) {
    return res.status(error.status || 500).json({
      ok: false,
      error: error.message,
      details: error.details || null
    });
  }
});

module.exports = router;
