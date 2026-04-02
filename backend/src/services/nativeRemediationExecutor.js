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
      message: [
        'Microsoft Graph Windows Update deployment APIs returned an internal error for this tenant.',
        '',
        'Common causes:',
        '• The targeted device is a Windows Server — WUfB Deployment Service only supports Windows 10/11 Client devices. Use Azure Update Manager for servers.',
        '• Devices are not yet enrolled in the Windows Update for Business deployment service. Enrollment happens automatically when Intune-managed Windows 10 21H2+ / Windows 11 devices check in.',
        '• The WindowsUpdates.ReadWrite.All Application permission is missing or admin consent has not been granted.',
        '• No active Windows Update ring policy exists in Intune for this tenant.',
      ].join('\n'),
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


async function resolveManagedDeviceTargets(tenantId, options = {}, finding = {}) {
  const entraResolution = await resolveEntraDeviceIds(tenantId, options, finding);
  const client = await getClientForTenant(tenantId);
  const managedTargets = [];
  const unmatchedEntra = [];
  for (const entraId of entraResolution.resolvedDeviceIds) {
    try {
      const safe = String(entraId).replace(/'/g, "''");
      const page = await client.api(`/deviceManagement/managedDevices?$select=id,azureADDeviceId,deviceName,userPrincipalName,managedDeviceName&$filter=azureADDeviceId eq '${safe}'`).top(5).get();
      const match = (page?.value || [])[0];
      if (match?.id) {
        managedTargets.push({
          managedDeviceId: match.id,
          azureADDeviceId: match.azureADDeviceId || entraId,
          deviceName: match.deviceName || match.managedDeviceName || null,
          userPrincipalName: match.userPrincipalName || null,
        });
      } else {
        unmatchedEntra.push(entraId);
      }
    } catch {
      unmatchedEntra.push(entraId);
    }
  }
  return {
    ...entraResolution,
    managedTargets,
    unmatchedManagedDeviceInputs: unique(unmatchedEntra),
  };
}

const POWERSHELL_SCRIPT_TEMPLATES = {
  'Update Microsoft Edge': `$ErrorActionPreference = 'Continue'
$paths = @("${env:ProgramFiles(x86)}\\Microsoft\\EdgeUpdate\\MicrosoftEdgeUpdate.exe","${env:ProgramFiles}\\Microsoft\\EdgeUpdate\\MicrosoftEdgeUpdate.exe")
$updater = $paths | Where-Object { Test-Path $_ } | Select-Object -First 1
if ($updater) { Start-Process -FilePath $updater -ArgumentList "/silent /update" -Wait; Write-Output "Microsoft Edge update triggered." }
else { Write-Output "MicrosoftEdgeUpdate.exe not found."; exit 1 }`,

  'Update Google Chrome': `$ErrorActionPreference = 'Continue'
$paths = @("${env:ProgramFiles(x86)}\\Google\\Update\\GoogleUpdate.exe","${env:ProgramFiles}\\Google\\Update\\GoogleUpdate.exe")
$updater = $paths | Where-Object { Test-Path $_ } | Select-Object -First 1
if ($updater) { Start-Process -FilePath $updater -ArgumentList "/ua /installsource scheduler" -Wait; Write-Output "Google Chrome update triggered." }
else { Write-Output "GoogleUpdate.exe not found."; exit 1 }`,

  'Restart Microsoft Edge': `Get-Process -Name "msedge" -ErrorAction SilentlyContinue | Stop-Process -Force
Write-Output "Microsoft Edge processes stopped."`,

  'Clear Edge cache': `$ErrorActionPreference = 'Continue'
Get-Process -Name "msedge" -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Sleep -Seconds 2
$cachePath = "$env:LOCALAPPDATA\\Microsoft\\Edge\\User Data\\Default\\Cache"
if (Test-Path $cachePath) { Remove-Item -Path "$cachePath\\*" -Recurse -Force -ErrorAction SilentlyContinue; Write-Output "Edge cache cleared." }
else { Write-Output "Edge cache path not found." }`,

  'Reset Windows Update components': `$ErrorActionPreference = 'Continue'
$svcs = @('wuauserv','cryptsvc','bits','msiserver')
foreach ($s in $svcs) { Stop-Service -Name $s -Force -ErrorAction SilentlyContinue }
Rename-Item "$env:SystemRoot\\SoftwareDistribution" "SoftwareDistribution.bak" -ErrorAction SilentlyContinue
Rename-Item "$env:SystemRoot\\System32\\catroot2" "catroot2.bak" -ErrorAction SilentlyContinue
foreach ($s in $svcs) { Start-Service -Name $s -ErrorAction SilentlyContinue }
Write-Output "Windows Update components reset."`,

  'Trigger Windows Update scan': `UsoClient.exe StartScan
Write-Output "Windows Update scan triggered."`,

  'Repair Windows Update services': `$ErrorActionPreference = 'Continue'
Stop-Service wuauserv -Force -ErrorAction SilentlyContinue
$dlls = @('wuapi.dll','wuaueng.dll','wucltui.dll','wups.dll','wups2.dll','wuweb.dll','qmgr.dll','qmgrprxy.dll','wucltux.dll','muweb.dll','wuwebv.dll','atl.dll','urlmon.dll','mshtml.dll','softpub.dll','wintrust.dll','initpki.dll','dssenh.dll','rsaenh.dll','ole32.dll','oleaut32.dll')
foreach ($dll in $dlls) { regsvr32.exe /s $dll 2>$null }
Start-Service wuauserv -ErrorAction SilentlyContinue
Write-Output "Windows Update services repaired."`,

  'Force Intune device sync': `$ErrorActionPreference = 'Continue'
Get-ScheduledTask -TaskName "Schedule*" -TaskPath "\\Microsoft\\Windows\\EnterpriseMgmt\\" -ErrorAction SilentlyContinue | Start-ScheduledTask -ErrorAction SilentlyContinue
Write-Output "Intune device sync triggered."`,

  'Repair MDM enrollment tasks': `$ErrorActionPreference = 'Continue'
Get-ScheduledTask -TaskPath "\\Microsoft\\Windows\\EnterpriseMgmt\\" -ErrorAction SilentlyContinue | Start-ScheduledTask -ErrorAction SilentlyContinue
Get-ScheduledTask -TaskPath "\\Microsoft\\Windows\\EnterpriseMgmtNonCritical\\" -ErrorAction SilentlyContinue | Start-ScheduledTask -ErrorAction SilentlyContinue
Write-Output "MDM enrollment tasks triggered."`,

  'Clear Teams cache': `$ErrorActionPreference = 'Continue'
Get-Process -Name "Teams","ms-teams" -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Sleep -Seconds 2
$paths = @("$env:APPDATA\\Microsoft\\Teams\\Cache","$env:APPDATA\\Microsoft\\Teams\\blob_storage","$env:APPDATA\\Microsoft\\Teams\\databases","$env:APPDATA\\Microsoft\\Teams\\GPUCache","$env:APPDATA\\Microsoft\\Teams\\IndexedDB","$env:APPDATA\\Microsoft\\Teams\\Local Storage","$env:APPDATA\\Microsoft\\Teams\\tmp")
foreach ($p in $paths) { if (Test-Path $p) { Remove-Item -Path "$p\\*" -Recurse -Force -ErrorAction SilentlyContinue } }
Write-Output "Teams cache cleared."`,

  'Repair Office Click-to-Run': `$ErrorActionPreference = 'Continue'
$paths = @("${env:ProgramFiles}\\Common Files\\microsoft shared\\ClickToRun\\OfficeClickToRun.exe","${env:ProgramFiles(x86)}\\Common Files\\microsoft shared\\ClickToRun\\OfficeClickToRun.exe")
$c2r = $paths | Where-Object { Test-Path $_ } | Select-Object -First 1
if ($c2r) { Start-Process -FilePath $c2r -ArgumentList "scenario=Repair RepairType=FullRepair DisplayLevel=None AcceptEula=True" -Wait; Write-Output "Office Click-to-Run repair started." }
else { Write-Output "Office Click-to-Run not found."; exit 1 }`,

  'Refresh Defender signatures': `Update-MpSignature -ErrorAction SilentlyContinue
Write-Output "Microsoft Defender signatures refresh triggered."`,
};

async function findExistingDeviceManagementScript(tenantId, displayName) {
  try {
    const safe = String(displayName || '').replace(/'/g, "''");
    const result = await graphBetaRequest(tenantId, `/deviceManagement/deviceManagementScripts?$filter=displayName eq '${safe}'&$select=id,displayName`);
    return (result?.value || [])[0] || null;
  } catch (err) {
    console.warn('[Remediation] deviceManagementScripts lookup failed:', err?.message);
    return null;
  }
}

async function createDeviceManagementScript(tenantId, displayName, scriptContent) {
  const fileName = displayName.replace(/[^a-zA-Z0-9_\- ]/g, '').replace(/\s+/g, '_').replace(/_+/g, '_').substring(0, 64) + '.ps1';
  const scriptContentBase64 = Buffer.from(scriptContent, 'utf8').toString('base64');
  return graphBetaRequest(tenantId, '/deviceManagement/deviceManagementScripts', {
    method: 'POST',
    body: { displayName, description: `Auto-created by IdentityMonitor remediation — ${new Date().toISOString()}`, scriptContent: scriptContentBase64, runAsAccount: 'system', enforceSignatureCheck: false, runAs32Bit: false, fileName },
  });
}

async function assignDeviceManagementScriptAllDevices(tenantId, scriptId) {
  return graphBetaRequest(tenantId, `/deviceManagement/deviceManagementScripts/${scriptId}/assign`, {
    method: 'POST',
    body: { deviceManagementScriptAssignments: [{ target: { '@odata.type': '#microsoft.graph.allDevicesAssignmentTarget' } }] },
  });
}

async function listTenantDeviceScripts(tenantId) {
  try {
    const page = await graphBetaRequest(tenantId, '/deviceManagement/deviceManagementScripts?$select=id,displayName,description,fileName,runAsAccount&$top=50');
    return (page?.value || []).map((item) => ({ id: item.id, displayName: item.displayName, description: item.description || '', fileName: item.fileName || null, runAsAccount: item.runAsAccount || null }));
  } catch (err) {
    console.warn('[Remediation] Could not list deviceManagementScripts:', err?.message);
    return [];
  }
}

async function resolveDeviceHealthScriptId(tenantId, input = '') {
  const raw = String(input || '').trim();
  if (!raw) return null;
  if (isGuid(raw)) return raw;
  try {
    const client = await getClientForTenant(tenantId);
    const safe = raw.replace(/'/g, "''");
    const page = await client.api(`/deviceManagement/deviceHealthScripts?$select=id,displayName&$filter=displayName eq '${safe}' or startswith(displayName,'${safe}')`).top(10).get();
    const match = (page?.value || []).find((item) => String(item.displayName || '').toLowerCase() === raw.toLowerCase()) || (page?.value || [])[0];
    return match?.id || null;
  } catch (err) {
    // deviceHealthScripts requires Intune Suite / Plan 2 — gracefully return null
    console.warn('[Remediation] deviceHealthScripts not available for this tenant (requires Intune Suite/Plan 2):', err?.message);
    return null;
  }
}

async function resolveConfigurationPolicyId(tenantId, input = '') {
  const raw = String(input || '').trim();
  if (!raw) return null;
  if (isGuid(raw)) return raw;
  const client = await getClientForTenant(tenantId);
  const safe = raw.replace(/'/g, "''");
  const page = await client.api(`/deviceManagement/configurationPolicies?$select=id,name&$filter=name eq '${safe}' or startswith(name,'${safe}')`).top(10).get();
  const match = (page?.value || []).find((item) => String(item.name || '').toLowerCase() === raw.toLowerCase()) || (page?.value || [])[0];
  return match?.id || null;
}

function parsePolicyTarget(raw = '') {
  const value = String(raw || '').trim();
  if (!value) return { policyInput: '', groupId: '' };
  const parts = value.split(/[|,;]/).map((s) => s.trim()).filter(Boolean);
  if (parts.length >= 2 && isGuid(parts[parts.length - 1])) {
    return { policyInput: parts.slice(0, -1).join(' '), groupId: parts[parts.length - 1] };
  }
  return { policyInput: value, groupId: '' };
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
  return { executor: 'native-intune-policy', supported: true, remediationType: classification.type, autoRemediate: true, executionMode: 'native-policy-assign', targetHint: finding?.productName || finding?.name || finding?.cveId || 'Intune policy issue', message: 'Intune policy executor is ready when you provide a configuration policy and target group.', statusCard: buildStatusCard('native-ready', 'native ready', 'success', 'Intune policy assignment is ready when policy and group IDs are provided.'), executionPath: { classification: classification.type, family: classification.family, executor: 'native-intune-policy', status: 'ready', route: 'Intune Policy -> Native assignment executor' }, fields: { requiresTargetHint: true, supportsNotes: true }, policyTarget: options.policyTarget || '', preflight: { graphConfigured: !!process.env.CLIENT_ID && !!process.env.CLIENT_SECRET, ready: !!process.env.CLIENT_ID && !!process.env.CLIENT_SECRET }, manualSteps: ['Enter the Intune configuration policy as a policy ID or exact policy name.', 'Append the Entra group object ID using policy|groupId (example: Windows Baseline|00000000-0000-0000-0000-000000000000).', 'The executor will assign that policy to the supplied group through Microsoft Graph.'] };
}
function buildPlanForScript(classification, finding, options = {}) {
  return { executor: 'native-script', supported: true, remediationType: classification.type, autoRemediate: true, executionMode: 'native-script-now', targetHint: finding?.productName || finding?.name || finding?.cveId || 'Script remediation', message: 'Script / proactive remediation executor is ready when you provide a device health script policy.', statusCard: buildStatusCard('native-ready', 'native ready', 'success', 'On-demand proactive remediation can run immediately on targeted devices.'), executionPath: { classification: classification.type, family: classification.family, executor: 'native-script', status: 'ready', route: 'Script / Proactive Remediation -> Native on-demand executor' }, fields: { requiresScriptName: true, supportsNotes: true, requiresDeviceIds: true }, scriptName: options.scriptName || '', preflight: { graphConfigured: !!process.env.CLIENT_ID && !!process.env.CLIENT_SECRET, ready: !!process.env.CLIENT_ID && !!process.env.CLIENT_SECRET }, manualSteps: ['Enter the device health script policy ID or exact display name.', 'Review the targeted devices before rollout.', 'The executor will call initiateOnDemandProactiveRemediation for each resolved managed device.'] };
}
function buildPlanForManual(classification, finding) {
  return { executor: 'guided-manual', supported: true, remediationType: classification.type, autoRemediate: false, executionMode: 'guided-manual', targetHint: finding?.productName || finding?.name || finding?.cveId || 'Manual remediation', message: 'No live executor exists yet for this finding. Use guided/manual remediation.', statusCard: buildStatusCard('manual-review-required', 'manual review required', 'warning', 'This finding needs guided manual remediation.'), executionPath: { classification: classification.type, family: classification.family, executor: 'guided-manual', status: 'manual', route: 'Manual -> Guided remediation' }, manualSteps: ['Review vendor guidance and impacted devices.', 'Document the remediation action taken outside the platform.', 'Return to the case and record the change window / evidence.'] };
}
async function planNativeRemediation({ classification, finding = {}, options = {} }) {
  switch (classification.type) { case 'windows-update': return buildPlanForWindowsUpdate(classification, finding, options); case 'intune-policy': return buildPlanForIntunePolicy(classification, finding, options); case 'script': return buildPlanForScript(classification, finding, options); default: return buildPlanForManual(classification, finding, options); }
}

async function listTenantConfigurationPolicies(tenantId) {
  const client = await getClientForTenant(tenantId);
  const page = await client.api('/deviceManagement/configurationPolicies?$select=id,name,description,platforms,technologies,roleScopeTagIds').top(100).get();
  return (page?.value || []).map((item) => ({
    id: item.id,
    name: item.name,
    description: item.description || '',
    platforms: item.platforms || null,
    technologies: item.technologies || null,
  }));
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
async function executeIntunePolicy({ tenantId, finding = {}, options = {} }) {
  const { policyInput, groupId } = parsePolicyTarget(options.policyTarget || finding?.productName || finding?.name || '');
  if (!groupId || !isGuid(groupId)) {
    const err = new Error('Provide the target as policyId|groupId (or policy name|groupId) before running Intune policy remediation.');
    err.status = 400;
    err.details = { policyTarget: options.policyTarget || '', expectedFormat: 'policyId|groupId' };
    throw err;
  }
  const policyId = await resolveConfigurationPolicyId(tenantId, policyInput);
  if (!policyId) {
    const err = new Error('The Intune configuration policy could not be resolved. Use an exact policy name or policy ID.');
    err.status = 404;
    err.details = { policyInput };
    throw err;
  }
  await graphBetaRequest(tenantId, `/deviceManagement/configurationPolicies/${policyId}/assign`, {
    method: 'POST',
    body: { assignments: [{ target: { '@odata.type': '#microsoft.graph.groupAssignmentTarget', groupId } }] }
  });
  return { queued: true, supported: true, status: 'live-deploy', executionMode: 'native-policy-assign', policyId, groupId, target: `${policyInput || policyId}|${groupId}`, notes: options.notes || '', summary: 'Assigned the Intune configuration policy to the supplied Entra group.', message: 'Intune policy assignment was submitted through Microsoft Graph.' };
}
async function executeScriptRemediation({ tenantId, finding = {}, options = {} }) {
  const scriptInput = options.scriptPolicyId || options.scriptName || finding?.productName || finding?.name || '';
  const scriptPolicyId = await resolveDeviceHealthScriptId(tenantId, scriptInput);

  if (scriptPolicyId) {
    // Path 1: Device Health Script (on-demand, requires Intune Suite / Plan 2)
    const targets = await resolveManagedDeviceTargets(tenantId, options, finding);
    if (!targets.managedTargets.length) {
      const err = new Error('No Intune managed devices could be resolved from the supplied devices. Load Exposed devices first or enter Microsoft Entra device IDs manually.');
      err.status = 400;
      err.details = { sourceInputs: targets.sourceInputs, unmatchedInputs: targets.unmatchedManagedDeviceInputs };
      throw err;
    }
    const results = [];
    for (const target of targets.managedTargets) {
      try {
        await graphBetaRequest(tenantId, `/deviceManagement/managedDevices/${target.managedDeviceId}/initiateOnDemandProactiveRemediation`, {
          method: 'POST',
          body: { scriptPolicyId }
        });
        results.push({ ok: true, managedDeviceId: target.managedDeviceId, azureADDeviceId: target.azureADDeviceId, deviceName: target.deviceName || null });
      } catch (error) {
        results.push({ ok: false, managedDeviceId: target.managedDeviceId, azureADDeviceId: target.azureADDeviceId, deviceName: target.deviceName || null, error: error?.message || 'Failed to start proactive remediation.' });
      }
    }
    const successCount = results.filter((item) => item.ok).length;
    const failed = results.filter((item) => !item.ok);
    return {
      queued: successCount > 0,
      supported: successCount > 0,
      status: failed.length ? (successCount ? 'partial-success' : 'script-execution-failed') : 'live-deploy',
      executionMode: 'native-script-now',
      scriptPolicyId,
      resolvedTargets: { sourceInputs: targets.sourceInputs, resolvedDeviceIds: targets.resolvedDeviceIds, unmatchedInputs: targets.unmatchedManagedDeviceInputs },
      targetDevices: results,
      summary: failed.length ? `Started proactive remediation on ${successCount} device(s); ${failed.length} device(s) failed.` : `Started proactive remediation on ${successCount} device(s).`,
      message: failed.length ? 'On-demand proactive remediation was started for some devices. Review per-device results.' : 'On-demand proactive remediation was started successfully.',
      notes: options.notes || ''
    };
  }

  // Path 2: Create/assign a deviceManagementScript (standard Intune, no Suite required)
  // Script will run on all Intune-managed devices at next check-in (~30 min).
  const templateContent = POWERSHELL_SCRIPT_TEMPLATES[scriptInput] || null;
  const scriptDisplayName = scriptInput
    ? scriptInput.substring(0, 100)
    : `Remediation — ${(finding?.productName || finding?.name || 'unknown').substring(0, 80)}`;

  if (!templateContent && !isGuid(scriptInput)) {
    return {
      queued: false,
      supported: false,
      status: 'manual-review-required',
      executionMode: 'guided-manual',
      message: `No Device Health Script found matching "${scriptInput}" and no built-in script template is available for this name. Select a built-in script option from the dropdown or enter an existing Intune script ID.`,
      statusCard: { code: 'script-not-found', label: 'script not found', tone: 'warning', message: 'Select a built-in script option or enter a valid script ID.' },
      manualSteps: [
        'Open Microsoft Intune admin center > Devices > Scripts.',
        `Create a PowerShell script for "${finding?.productName || finding?.name || 'this vulnerability'}".`,
        'Assign it to the affected device group.',
        'Monitor the script run status in Intune.'
      ],
      notes: options.notes || ''
    };
  }

  try {
    let existing = await findExistingDeviceManagementScript(tenantId, scriptDisplayName);
    let scriptId;
    let created = false;
    if (existing) {
      scriptId = existing.id;
    } else {
      const newScript = await createDeviceManagementScript(tenantId, scriptDisplayName, templateContent);
      scriptId = newScript.id;
      created = true;
    }
    await assignDeviceManagementScriptAllDevices(tenantId, scriptId);
    return {
      queued: true,
      supported: true,
      status: 'script-scheduled',
      executionMode: 'native-script-scheduled',
      scriptId,
      scriptDisplayName,
      created,
      assigned: true,
      assignmentTarget: 'all-devices',
      message: created
        ? `PowerShell script "${scriptDisplayName}" created in Intune and assigned to all managed devices. It will run at next device check-in (within ~30 minutes). View at: Intune > Devices > Scripts.`
        : `Existing PowerShell script "${scriptDisplayName}" re-assigned to all managed devices. It will run at next device check-in (within ~30 minutes).`,
      manualUrl: 'https://intune.microsoft.com/#view/Microsoft_Intune_DeviceSettings/DevicesMenu/~/scripts',
      notes: options.notes || ''
    };
  } catch (scriptErr) {
    return {
      queued: false,
      supported: false,
      status: 'manual-review-required',
      executionMode: 'guided-manual',
      message: `Script deployment failed: ${scriptErr?.message || 'Unknown error'}. Ensure the app registration has DeviceManagementConfiguration.ReadWrite.All with admin consent.`,
      statusCard: { code: 'script-deploy-failed', label: 'script deploy failed', tone: 'danger', message: scriptErr?.message || 'Script creation or assignment failed.' },
      manualSteps: [
        'Verify the app registration has DeviceManagementConfiguration.ReadWrite.All Application permission with admin consent.',
        'Open Microsoft Intune admin center > Devices > Scripts and create the script manually.',
        'Assign it to the affected device group.',
      ],
      notes: options.notes || ''
    };
  }
}
async function executeNativeRemediation({ tenantId, finding = {}, classification, options = {} }) {
  switch (classification.type) { case 'windows-update': return executeWindowsUpdate({ tenantId, finding, options }); case 'intune-policy': return executeIntunePolicy({ tenantId, finding, options }); case 'script': return executeScriptRemediation({ tenantId, finding, options }); default: return { queued: false, supported: true, status: 'manual-review-required', executionMode: 'guided-manual', message: 'This finding requires guided manual remediation.' }; }
}
module.exports = { planNativeRemediation, executeNativeRemediation, resolveEntraDeviceIds, resolveManagedDeviceTargets, listTenantConfigurationPolicies, listTenantDeviceScripts };
