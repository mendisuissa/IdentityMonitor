require('isomorphic-fetch');
const { getClientForTenant } = require('./graphService');

const GRAPH_BETA_BASE = 'https://graph.microsoft.com/beta';
const graphTokenCache = new Map();

function toArray(input) {
  if (!input) return [];
  if (Array.isArray(input)) return input.map(String).map((s) => s.trim()).filter(Boolean);
  return String(input).split(/[\n,;]+/).map((s) => s.trim()).filter(Boolean);
}
function unique(values) { return Array.from(new Set(values.filter(Boolean))); }
function isGuid(value) { return /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(String(value || '').trim()); }
function normalizeDeviceLookupValue(value) { const t = String(value || '').trim(); return t ? t.split('.')[0].trim() : ''; }
function normalizeRebootBehavior(value) {
  const n = String(value || '').trim().toLowerCase();
  if (n === 'force' || n === 'force-reboot') return 'force';
  if (n === 'defer' || n === 'suppress-reboot') return 'defer';
  return 'ifRequired';
}

async function getGraphAccessToken(tenantId) {
  const cacheKey = `${tenantId}:${process.env.CLIENT_ID}`;
  const cached = graphTokenCache.get(cacheKey);
  if (cached && cached.expiresAt > Date.now() + 60000) return cached.accessToken;
  const { CLIENT_ID: clientId, CLIENT_SECRET: clientSecret } = process.env;
  if (!clientId || !clientSecret) throw new Error('CLIENT_ID and CLIENT_SECRET must be configured for native remediation execution.');
  const tokenRes = await fetch(`https://login.microsoftonline.com/${tenantId}/oauth2/v2.0/token`, {
    method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ client_id: clientId, client_secret: clientSecret, scope: 'https://graph.microsoft.com/.default', grant_type: 'client_credentials' }).toString()
  });
  const data = await tokenRes.json().catch(() => ({}));
  if (!tokenRes.ok || data.error) {
    const err = new Error(data.error_description || data.error || `Token request failed: ${tokenRes.status}`);
    err.status = tokenRes.status || 500; err.details = data; throw err;
  }
  graphTokenCache.set(cacheKey, { accessToken: data.access_token, expiresAt: Date.now() + ((data.expires_in || 3600) * 1000) });
  return data.access_token;
}

async function graphBetaRequest(tenantId, path, options = {}) {
  const accessToken = await getGraphAccessToken(tenantId);
  const response = await fetch(`${GRAPH_BETA_BASE}${path}`, {
    method: options.method || 'GET',
    headers: { Authorization: `Bearer ${accessToken}`, 'Content-Type': 'application/json', ...(options.headers || {}) },
    body: options.body ? JSON.stringify(options.body) : undefined
  });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) {
    const err = new Error(payload?.error?.message || payload?.message || `Graph beta request failed: ${response.status}`);
    err.status = response.status; err.details = payload; throw err;
  }
  return payload;
}
async function enrollAssetsForCategory(tenantId, category, deviceIds) {
  return graphBetaRequest(tenantId, '/admin/windows/updates/updatableAssets/enrollAssets', {
    method: 'POST', body: { updateCategory: category, assets: deviceIds.map((id) => ({ '@odata.type': '#microsoft.graph.windowsUpdates.azureADDevice', id })) }
  });
}
async function getLatestSecurityCatalogEntry(tenantId) {
  const result = await graphBetaRequest(tenantId, "/admin/windows/updates/catalog/entries?$filter=isof('microsoft.graph.windowsUpdates.qualityUpdateCatalogEntry') and microsoft.graph.windowsUpdates.qualityUpdateCatalogEntry/isExpeditable eq true and microsoft.graph.windowsUpdates.qualityUpdateCatalogEntry/qualityUpdateClassification eq 'security'&$orderby=releaseDateTime desc&$top=1");
  const entry = result?.value?.[0] || null; if (!entry) throw new Error('No deployable expedited security update was found for this tenant.'); return entry;
}
async function getLatestFeatureCatalogEntry(tenantId) {
  const result = await graphBetaRequest(tenantId, "/admin/windows/updates/catalog/entries?$filter=isof('microsoft.graph.windowsUpdates.featureUpdateCatalogEntry')&$orderby=releaseDateTime desc&$top=1");
  const entry = result?.value?.[0] || null; if (!entry) throw new Error('No deployable feature update catalog entry was found for this tenant.'); return entry;
}
function buildDeploymentSettings({ rebootBehavior = 'ifRequired' } = {}) {
  const normalized = normalizeRebootBehavior(rebootBehavior);
  return {
    '@odata.type': 'microsoft.graph.windowsUpdates.deploymentSettings',
    userExperience: { offerAsOptional: false, daysUntilForcedReboot: normalized === 'force' ? 0 : null },
    monitoring: { monitoringRules: [{ '@odata.type': '#microsoft.graph.windowsUpdates.monitoringRule', signal: 'rollback', threshold: 5, action: 'pauseDeployment' }] }
  };
}
async function createDeployment(tenantId, updateKind, catalogEntry, options = {}) {
  const isFeature = updateKind === 'feature';
  return graphBetaRequest(tenantId, '/admin/windows/updates/deployments', {
    method: 'POST',
    body: {
      '@odata.type': '#microsoft.graph.windowsUpdates.deployment',
      content: { '@odata.type': '#microsoft.graph.windowsUpdates.catalogContent', catalogEntry: { '@odata.type': isFeature ? '#microsoft.graph.windowsUpdates.featureUpdateCatalogEntry' : '#microsoft.graph.windowsUpdates.qualityUpdateCatalogEntry', id: catalogEntry.id } },
      settings: buildDeploymentSettings(options)
    }
  });
}
async function updateAudience(tenantId, deploymentId, deviceIds) {
  return graphBetaRequest(tenantId, `/admin/windows/updates/deployments/${deploymentId}/audience/updateAudience`, {
    method: 'POST', body: { addMembers: deviceIds.map((id) => ({ '@odata.type': '#microsoft.graph.windowsUpdates.azureADDevice', id })) }
  });
}
function buildStatusCard(code, label, tone, message) { return { code, label, tone, message }; }

function extractGraphError(error) {
  const details = error?.details || {};
  const nested = details?.error || {};
  const rawMessage = nested?.message || details?.message || error?.message || 'Unknown Graph error.';
  const lower = String(rawMessage).toLowerCase();
  const status = Number(error?.status || 500);

  if (status === 403) {
    return {
      code: 'graph-permission-denied',
      message: 'The app registration is missing Windows Update Graph permissions or admin consent for this tenant.',
      technical: rawMessage,
    };
  }

  if (status === 400) {
    return {
      code: 'graph-bad-request',
      message: 'The Windows Update request was rejected. Verify the target devices and Windows Update deployment prerequisites.',
      technical: rawMessage,
    };
  }

  if (status >= 500 || lower.includes('unknownerror') || lower.includes('internal error')) {
    return {
      code: 'windows-update-service-unavailable',
      message: 'Microsoft Graph Windows Update deployment APIs returned an internal error for this tenant. This usually means the tenant or targeted devices are not ready for Windows Update deployment service execution yet.',
      technical: rawMessage,
    };
  }

  return {
    code: 'windows-update-execution-failed',
    message: rawMessage,
    technical: rawMessage,
  };
}

async function resolveEntraDeviceIds(tenantId, options = {}, finding = {}) {
  const explicitInputs = unique(toArray(options.targetDeviceIds || options.deviceIds || []));
  const directGuids = explicitInputs.filter(isGuid);
  const pendingNames = explicitInputs.filter((value) => !isGuid(value));
  const candidateNames = unique([...pendingNames, ...toArray(options.deviceNames || []), ...toArray(options.affectedDeviceNames || []), ...toArray(finding.affectedMachines || [])]);
  const resolved = [...directGuids];
  const unmatched = [];
  if (candidateNames.length) {
    const client = await getClientForTenant(tenantId);
    for (const rawName of candidateNames) {
      const normalized = normalizeDeviceLookupValue(rawName); if (!normalized) continue;
      try {
        const safe = normalized.replace(/'/g, "''");
        const result = await client.api(`/devices?$select=id,deviceId,displayName&$filter=displayName eq '${safe}' or startswith(displayName,'${safe}')`).top(5).get();
        const match = (result?.value || []).find((device) => {
          const display = normalizeDeviceLookupValue(device.displayName || '');
          return display === normalized || display.startsWith(normalized);
        }) || (result?.value || [])[0];
        if (match?.deviceId) resolved.push(match.deviceId); else if (match?.id) resolved.push(match.id); else unmatched.push(rawName);
      } catch {
        unmatched.push(rawName);
      }
    }
  }
  return { resolvedDeviceIds: unique(resolved), unmatchedInputs: unique(unmatched), sourceInputs: unique([...explicitInputs, ...candidateNames]) };
}

function buildPlanForWindowsUpdate(classification, finding, options = {}) {
  return {
    executor: 'native-windows-update', supported: true, remediationType: classification.type, autoRemediate: true,
    executionMode: 'native-update-now', recommendedUpdateType: options.updateType || 'security', rebootBehavior: normalizeRebootBehavior(options.rebootBehavior || 'ifRequired'),
    targetHint: finding?.productName || finding?.name || finding?.cveId || 'Windows update exposure',
    message: 'Windows Update native executor is ready. You can run the update immediately from this plan.',
    statusCard: buildStatusCard('native-ready', 'native ready', 'success', 'Windows Update execution is ready.'),
    executionPath: { classification: classification.type, family: classification.family, executor: 'native-windows-update', status: 'ready', route: 'Windows Update -> Native executor' },
    fields: { requiresDeviceIds: true, supportsUpdateType: true, supportsRebootBehavior: true, supportsImmediateRun: true },
    inferredDeviceNames: toArray(options.affectedDeviceNames || []).length ? toArray(options.affectedDeviceNames || []) : toArray(finding.affectedMachines || []),
    preflight: { graphConfigured: !!process.env.CLIENT_ID && !!process.env.CLIENT_SECRET, requiresEntraDeviceIds: true, ready: !!process.env.CLIENT_ID && !!process.env.CLIENT_SECRET },
    manualSteps: ['Review the affected devices before rollout.', 'Ensure the app registration has WindowsUpdates.ReadWrite.All and required device permissions.', 'Ensure devices meet Windows Autopatch / WUfB deployment prerequisites before execution.']
  };
}
function buildPlanForIntunePolicy(classification, finding, options = {}) {
  return { executor: 'native-intune-policy', supported: true, remediationType: classification.type, autoRemediate: false, executionMode: 'native-queued', targetHint: finding?.productName || finding?.name || finding?.cveId || 'Intune policy issue', message: 'Intune policy executor is staged. Execution will queue a guided policy remediation task.', statusCard: buildStatusCard('native-queued', 'native queued', 'warning', 'Intune policy remediation will be queued as a guided task.'), executionPath: { classification: classification.type, family: classification.family, executor: 'native-intune-policy', status: 'queued', route: 'Intune Policy -> Native guided executor' }, fields: { requiresTargetHint: true, supportsNotes: true }, policyTarget: options.policyTarget || '', preflight: { graphConfigured: !!process.env.CLIENT_ID && !!process.env.CLIENT_SECRET, ready: !!process.env.CLIENT_ID && !!process.env.CLIENT_SECRET }, manualSteps: ['Select or enter the target Intune configuration/compliance policy name.', 'Review the affected devices and scope tags before rollout.', 'Implement the real Graph mutation in the next phase when policy mapping is finalized.'] };
}
function buildPlanForScript(classification, finding, options = {}) {
  return { executor: 'native-script', supported: true, remediationType: classification.type, autoRemediate: false, executionMode: 'native-queued', targetHint: finding?.productName || finding?.name || finding?.cveId || 'Script remediation', message: 'Script / proactive remediation executor is staged. Execution will queue a guided remediation task.', statusCard: buildStatusCard('native-queued', 'native queued', 'warning', 'Script remediation will be queued as a guided task.'), executionPath: { classification: classification.type, family: classification.family, executor: 'native-script', status: 'queued', route: 'Script / Proactive Remediation -> Native guided executor' }, fields: { requiresScriptName: true, supportsNotes: true }, scriptName: options.scriptName || '', preflight: { graphConfigured: !!process.env.CLIENT_ID && !!process.env.CLIENT_SECRET, ready: !!process.env.CLIENT_ID && !!process.env.CLIENT_SECRET }, manualSteps: ['Select the remediation script or proactive remediation package.', 'Validate detection and remediation logic in a pilot group.', 'Wire the real Intune/Graph script assignment in the next phase.'] };
}
function buildPlanForManual(classification, finding) {
  return { executor: 'guided-manual', supported: true, remediationType: classification.type, autoRemediate: false, executionMode: 'guided-manual', targetHint: finding?.productName || finding?.name || finding?.cveId || 'Manual remediation', message: 'No live executor exists yet for this finding. Use guided/manual remediation.', statusCard: buildStatusCard('manual-review-required', 'manual review required', 'warning', 'This finding needs guided manual remediation.'), executionPath: { classification: classification.type, family: classification.family, executor: 'guided-manual', status: 'manual', route: 'Manual -> Guided remediation' }, manualSteps: ['Review vendor guidance and impacted devices.', 'Document the remediation action taken outside the platform.', 'Return to the case and record the change window / evidence.'] };
}
async function planNativeRemediation({ classification, finding = {}, options = {} }) {
  switch (classification.type) { case 'windows-update': return buildPlanForWindowsUpdate(classification, finding, options); case 'intune-policy': return buildPlanForIntunePolicy(classification, finding, options); case 'script': return buildPlanForScript(classification, finding, options); default: return buildPlanForManual(classification, finding, options); }
}
async function executeWindowsUpdate({ tenantId, finding = {}, options = {} }) {
  const updateType = String(options.updateType || 'security').toLowerCase() === 'feature' ? 'feature' : 'security';
  const rebootBehavior = normalizeRebootBehavior(options.rebootBehavior || 'ifRequired');
  const resolution = await resolveEntraDeviceIds(tenantId, options, finding);
  const deviceIds = resolution.resolvedDeviceIds;
  if (!deviceIds.length) {
    const err = new Error('No Microsoft Entra device IDs could be resolved. Provide Entra device IDs or affected device names before running Windows Update now.');
    err.status = 400;
    err.details = { unmatchedInputs: resolution.unmatchedInputs, sourceInputs: resolution.sourceInputs };
    throw err;
  }

  try {
    const category = updateType === 'feature' ? 'feature' : 'quality';
    await enrollAssetsForCategory(tenantId, category, deviceIds);
    const catalogEntry = updateType === 'feature' ? await getLatestFeatureCatalogEntry(tenantId) : await getLatestSecurityCatalogEntry(tenantId);
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
      resolvedTargets: { sourceInputs: resolution.sourceInputs, resolvedDeviceIds: deviceIds, unmatchedInputs: resolution.unmatchedInputs },
      deploymentId: deployment.id,
      deploymentState: deployment?.state?.value || 'offering',
      catalogEntry: {
        id: catalogEntry.id,
        displayName: catalogEntry.displayName,
        releaseDateTime: catalogEntry.releaseDateTime || null,
        qualityUpdateClassification: catalogEntry.qualityUpdateClassification || null,
      },
      message: updateType === 'feature' ? 'Feature update deployment created and audience assigned.' : 'Security quality update deployment created and audience assigned.',
      sourceFinding: { cveId: finding?.cveId || null, productName: finding?.productName || finding?.name || null },
    };
  } catch (error) {
    const graphError = extractGraphError(error);
    return {
      queued: false,
      supported: false,
      status: graphError.code,
      executionMode: 'guided-windows-update',
      updateType,
      rebootBehavior,
      targetDeviceIds: deviceIds,
      resolvedTargets: { sourceInputs: resolution.sourceInputs, resolvedDeviceIds: deviceIds, unmatchedInputs: resolution.unmatchedInputs },
      message: graphError.message,
      technicalMessage: graphError.technical,
      manualSteps: [
        'Verify the tenant is onboarded for Windows Update for Business deployment service / Autopatch scenarios supported by Microsoft Graph.',
        'Confirm the app registration has WindowsUpdates.ReadWrite.All and the required device read permissions with admin consent.',
        'Validate that the targeted Entra devices are eligible Windows clients and retry the deployment.',
      ],
      sourceFinding: { cveId: finding?.cveId || null, productName: finding?.productName || finding?.name || null },
    };
  }
}
async function executeIntunePolicy({ finding = {}, options = {} }) { const taskId = `intune-${Date.now()}`; return { queued: true, supported: true, status: 'native-queued', executionMode: 'native-queued', taskId, queuedAt: new Date().toISOString(), target: options.policyTarget || finding?.productName || finding?.name || 'Policy target not specified', notes: options.notes || '', summary: 'Queued a guided Intune policy remediation task.', message: 'Intune policy remediation was queued as a guided native task. Live Graph policy mutation is not enabled yet.' }; }
async function executeScriptRemediation({ finding = {}, options = {} }) { const taskId = `script-${Date.now()}`; return { queued: true, supported: true, status: 'native-queued', executionMode: 'native-queued', taskId, queuedAt: new Date().toISOString(), scriptName: options.scriptName || finding?.productName || finding?.name || 'Script target not specified', notes: options.notes || '', summary: 'Queued a guided remediation script task.', message: 'Script / proactive remediation was queued as a guided native task. Live Intune script assignment is not enabled yet.' }; }
async function executeNativeRemediation({ tenantId, finding = {}, classification, options = {} }) {
  switch (classification.type) { case 'windows-update': return executeWindowsUpdate({ tenantId, finding, options }); case 'intune-policy': return executeIntunePolicy({ finding, options }); case 'script': return executeScriptRemediation({ finding, options }); default: return { queued: false, supported: true, status: 'manual-review-required', executionMode: 'guided-manual', message: 'This finding requires guided manual remediation.' }; }
}
module.exports = { planNativeRemediation, executeNativeRemediation, resolveEntraDeviceIds };
