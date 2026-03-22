require('isomorphic-fetch');

const GRAPH_BETA_BASE = 'https://graph.microsoft.com/beta';
const graphTokenCache = new Map();

function toArray(input) {
  if (!input) return [];
  if (Array.isArray(input)) return input.map(String).map((s) => s.trim()).filter(Boolean);
  return String(input)
    .split(/[\n,;]+/)
    .map((s) => s.trim())
    .filter(Boolean);
}

async function getGraphAccessToken(tenantId) {
  const cacheKey = `${tenantId}:${process.env.CLIENT_ID}`;
  const cached = graphTokenCache.get(cacheKey);
  if (cached && cached.expiresAt > Date.now() + 60_000) {
    return cached.accessToken;
  }

  const clientId = process.env.CLIENT_ID;
  const clientSecret = process.env.CLIENT_SECRET;

  if (!clientId || !clientSecret) {
    throw new Error('CLIENT_ID and CLIENT_SECRET must be configured for native remediation execution.');
  }

  const tokenRes = await fetch(`https://login.microsoftonline.com/${tenantId}/oauth2/v2.0/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      client_id: clientId,
      client_secret: clientSecret,
      scope: 'https://graph.microsoft.com/.default',
      grant_type: 'client_credentials'
    }).toString()
  });

  const data = await tokenRes.json().catch(() => ({}));
  if (!tokenRes.ok || data.error) {
    const message = data.error_description || data.error || `Token request failed: ${tokenRes.status}`;
    const err = new Error(message);
    err.status = tokenRes.status || 500;
    err.details = data;
    throw err;
  }

  graphTokenCache.set(cacheKey, {
    accessToken: data.access_token,
    expiresAt: Date.now() + ((data.expires_in || 3600) * 1000)
  });

  return data.access_token;
}

async function graphBetaRequest(tenantId, path, options = {}) {
  const accessToken = await getGraphAccessToken(tenantId);
  const response = await fetch(`${GRAPH_BETA_BASE}${path}`, {
    method: options.method || 'GET',
    headers: {
      Authorization: `Bearer ${accessToken}`,
      'Content-Type': 'application/json',
      ...(options.headers || {})
    },
    body: options.body ? JSON.stringify(options.body) : undefined
  });

  const payload = await response.json().catch(() => ({}));
  if (!response.ok) {
    const err = new Error(payload?.error?.message || payload?.message || `Graph beta request failed: ${response.status}`);
    err.status = response.status;
    err.details = payload;
    throw err;
  }
  return payload;
}

async function enrollAssetsForCategory(tenantId, category, deviceIds) {
  return graphBetaRequest(tenantId, '/admin/windows/updates/updatableAssets/enrollAssets', {
    method: 'POST',
    body: {
      updateCategory: category,
      assets: deviceIds.map((id) => ({
        '@odata.type': '#microsoft.graph.windowsUpdates.azureADDevice',
        id
      }))
    }
  });
}

async function getLatestSecurityCatalogEntry(tenantId) {
  const result = await graphBetaRequest(
    tenantId,
    "/admin/windows/updates/catalog/entries?$filter=isof('microsoft.graph.windowsUpdates.qualityUpdateCatalogEntry') and microsoft.graph.windowsUpdates.qualityUpdateCatalogEntry/isExpeditable eq true and microsoft.graph.windowsUpdates.qualityUpdateCatalogEntry/qualityUpdateClassification eq 'security'&$orderby=releaseDateTime desc&$top=1"
  );

  const entry = result?.value?.[0] || null;
  if (!entry) {
    throw new Error('No deployable expedited security update was found for this tenant.');
  }
  return entry;
}

async function getLatestFeatureCatalogEntry(tenantId) {
  const result = await graphBetaRequest(
    tenantId,
    "/admin/windows/updates/catalog/entries?$filter=isof('microsoft.graph.windowsUpdates.featureUpdateCatalogEntry')&$orderby=releaseDateTime desc&$top=1"
  );

  const entry = result?.value?.[0] || null;
  if (!entry) {
    throw new Error('No deployable feature update catalog entry was found for this tenant.');
  }
  return entry;
}

function buildDeploymentSettings({ rebootBehavior = 'reboot-if-required' } = {}) {
  const userExperience = {
    offerAsOptional: false,
    daysUntilForcedReboot: rebootBehavior === 'force-reboot' ? 0 : null
  };

  return {
    '@odata.type': 'microsoft.graph.windowsUpdates.deploymentSettings',
    userExperience,
    monitoring: {
      monitoringRules: [
        {
          '@odata.type': '#microsoft.graph.windowsUpdates.monitoringRule',
          signal: 'rollback',
          threshold: 5,
          action: 'pauseDeployment'
        }
      ]
    }
  };
}

async function createDeployment(tenantId, updateKind, catalogEntry, options = {}) {
  const isFeature = updateKind === 'feature';
  return graphBetaRequest(tenantId, '/admin/windows/updates/deployments', {
    method: 'POST',
    body: {
      '@odata.type': '#microsoft.graph.windowsUpdates.deployment',
      content: {
        '@odata.type': '#microsoft.graph.windowsUpdates.catalogContent',
        catalogEntry: {
          '@odata.type': isFeature
            ? '#microsoft.graph.windowsUpdates.featureUpdateCatalogEntry'
            : '#microsoft.graph.windowsUpdates.qualityUpdateCatalogEntry',
          id: catalogEntry.id
        }
      },
      settings: buildDeploymentSettings(options)
    }
  });
}

async function updateAudience(tenantId, deploymentId, deviceIds) {
  return graphBetaRequest(tenantId, `/admin/windows/updates/deployments/${deploymentId}/audience/updateAudience`, {
    method: 'POST',
    body: {
      addMembers: deviceIds.map((id) => ({
        '@odata.type': '#microsoft.graph.windowsUpdates.azureADDevice',
        id
      }))
    }
  });
}

function buildStatusCard(code, label, tone, message) {
  return { code, label, tone, message };
}

function buildPlanForWindowsUpdate(classification, finding, options = {}) {
  return {
    executor: 'native-windows-update',
    supported: true,
    remediationType: classification.type,
    autoRemediate: true,
    executionMode: 'native-update-now',
    recommendedUpdateType: options.updateType || 'security',
    rebootBehavior: options.rebootBehavior || 'reboot-if-required',
    targetHint: finding?.productName || finding?.name || finding?.cveId || 'Windows update exposure',
    message: 'Windows Update native executor is ready. Provide device IDs and run Update now.',
    statusCard: buildStatusCard('native-ready', 'native ready', 'success', 'Windows Update execution is ready.'),
    executionPath: {
      classification: classification.type,
      family: classification.family,
      executor: 'native-windows-update',
      status: 'ready',
      route: 'Windows Update -> Native executor'
    },
    fields: {
      requiresDeviceIds: true,
      supportsUpdateType: true,
      supportsRebootBehavior: true
    },
    manualSteps: [
      'Provide Microsoft Entra device IDs for the devices that should receive the update.',
      'Ensure the app registration has WindowsUpdates.ReadWrite.All and required device permissions.',
      'Ensure devices meet Windows Autopatch / WUfB deployment prerequisites before execution.'
    ]
  };
}

function buildPlanForIntunePolicy(classification, finding, options = {}) {
  return {
    executor: 'native-intune-policy',
    supported: true,
    remediationType: classification.type,
    autoRemediate: false,
    executionMode: 'native-queued',
    targetHint: finding?.productName || finding?.name || finding?.cveId || 'Intune policy issue',
    message: 'Intune policy executor is staged. Execution will queue a guided policy remediation task.',
    statusCard: buildStatusCard('native-queued', 'native queued', 'warning', 'Intune policy remediation will be queued as a guided task.'),
    executionPath: {
      classification: classification.type,
      family: classification.family,
      executor: 'native-intune-policy',
      status: 'queued',
      route: 'Intune Policy -> Native guided executor'
    },
    fields: {
      requiresTargetHint: true,
      supportsNotes: true
    },
    policyTarget: options.policyTarget || '',
    manualSteps: [
      'Select or enter the target Intune configuration/compliance policy name.',
      'Review the affected devices and scope tags before rollout.',
      'Implement the real Graph mutation in the next phase when policy mapping is finalized.'
    ]
  };
}

function buildPlanForScript(classification, finding, options = {}) {
  return {
    executor: 'native-script',
    supported: true,
    remediationType: classification.type,
    autoRemediate: false,
    executionMode: 'native-queued',
    targetHint: finding?.productName || finding?.name || finding?.cveId || 'Script remediation',
    message: 'Script / proactive remediation executor is staged. Execution will queue a guided remediation task.',
    statusCard: buildStatusCard('native-queued', 'native queued', 'warning', 'Script remediation will be queued as a guided task.'),
    executionPath: {
      classification: classification.type,
      family: classification.family,
      executor: 'native-script',
      status: 'queued',
      route: 'Script / Proactive Remediation -> Native guided executor'
    },
    fields: {
      requiresScriptName: true,
      supportsNotes: true
    },
    scriptName: options.scriptName || '',
    manualSteps: [
      'Select the remediation script or proactive remediation package.',
      'Validate detection and remediation logic in a pilot group.',
      'Wire the real Intune/Graph script assignment in the next phase.'
    ]
  };
}

function buildPlanForManual(classification, finding) {
  return {
    executor: 'guided-manual',
    supported: true,
    remediationType: classification.type,
    autoRemediate: false,
    executionMode: 'guided-manual',
    targetHint: finding?.productName || finding?.name || finding?.cveId || 'Manual remediation',
    message: 'No live executor exists yet for this finding. Use guided/manual remediation.',
    statusCard: buildStatusCard('manual-review-required', 'manual review required', 'warning', 'This finding needs guided manual remediation.'),
    executionPath: {
      classification: classification.type,
      family: classification.family,
      executor: 'guided-manual',
      status: 'manual',
      route: 'Manual -> Guided remediation'
    },
    manualSteps: [
      'Review vendor guidance and impacted devices.',
      'Document the remediation action taken outside the platform.',
      'Return to the case and record the change window / evidence.'
    ]
  };
}

async function planNativeRemediation({ classification, finding = {}, options = {} }) {
  switch (classification.type) {
    case 'windows-update':
      return buildPlanForWindowsUpdate(classification, finding, options);
    case 'intune-policy':
      return buildPlanForIntunePolicy(classification, finding, options);
    case 'script':
      return buildPlanForScript(classification, finding, options);
    default:
      return buildPlanForManual(classification, finding, options);
  }
}

async function executeWindowsUpdate({ tenantId, finding = {}, options = {} }) {
  const updateType = String(options.updateType || 'security').toLowerCase() === 'feature' ? 'feature' : 'security';
  const rebootBehavior = String(options.rebootBehavior || 'reboot-if-required');
  const deviceIds = toArray(options.targetDeviceIds || options.deviceIds || []);

  if (!deviceIds.length) {
    const err = new Error('At least one Microsoft Entra device ID is required for Update now execution.');
    err.status = 400;
    throw err;
  }

  const category = updateType === 'feature' ? 'feature' : 'quality';
  await enrollAssetsForCategory(tenantId, category, deviceIds);

  const catalogEntry = updateType === 'feature'
    ? await getLatestFeatureCatalogEntry(tenantId)
    : await getLatestSecurityCatalogEntry(tenantId);

  const deployment = await createDeployment(tenantId, updateType, catalogEntry, { rebootBehavior });
  await updateAudience(tenantId, deployment.id, deviceIds);

  return {
    queued: true,
    supported: true,
    status: 'live-deploy',
    executionMode: 'native-update-now',
    updateType,
    rebootBehavior,
    targetDeviceIds: deviceIds,
    deploymentId: deployment.id,
    deploymentState: deployment?.state?.value || 'offering',
    catalogEntry: {
      id: catalogEntry.id,
      displayName: catalogEntry.displayName,
      releaseDateTime: catalogEntry.releaseDateTime || null,
      qualityUpdateClassification: catalogEntry.qualityUpdateClassification || null
    },
    message: updateType === 'feature'
      ? 'Feature update deployment created and audience assigned.'
      : 'Security quality update deployment created and audience assigned.',
    sourceFinding: {
      cveId: finding?.cveId || null,
      productName: finding?.productName || finding?.name || null
    }
  };
}

async function executeIntunePolicy({ finding = {}, options = {} }) {
  return {
    queued: true,
    supported: true,
    status: 'native-queued',
    executionMode: 'native-queued',
    target: options.policyTarget || finding?.productName || finding?.name || 'Policy target not specified',
    notes: options.notes || '',
    message: 'Intune policy remediation was queued as a guided native task. Live Graph policy mutation is not enabled yet.'
  };
}

async function executeScriptRemediation({ finding = {}, options = {} }) {
  return {
    queued: true,
    supported: true,
    status: 'native-queued',
    executionMode: 'native-queued',
    scriptName: options.scriptName || finding?.productName || finding?.name || 'Script target not specified',
    notes: options.notes || '',
    message: 'Script / proactive remediation was queued as a guided native task. Live Intune script assignment is not enabled yet.'
  };
}

async function executeNativeRemediation({ tenantId, finding = {}, classification, options = {} }) {
  switch (classification.type) {
    case 'windows-update':
      return executeWindowsUpdate({ tenantId, finding, options });
    case 'intune-policy':
      return executeIntunePolicy({ finding, options });
    case 'script':
      return executeScriptRemediation({ finding, options });
    default:
      return {
        queued: false,
        supported: true,
        status: 'manual-review-required',
        executionMode: 'guided-manual',
        message: 'This finding requires guided manual remediation.'
      };
  }
}

module.exports = {
  planNativeRemediation,
  executeNativeRemediation
};
