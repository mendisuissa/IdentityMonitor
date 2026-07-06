/**
 * wingetService.js
 * Local WinGet / Intune deployment — no dependency on localhost:4000.
 * Ported from Webapp wingetDeploy.ts + remediationCatalog.ts.
 */

'use strict';

const { getAccessTokenForTenant } = require('./graphService');

// ─── Catalog ─────────────────────────────────────────────────────────────────
// Common apps with known WinGet IDs. Used as fast-path before fuzzy resolution.

const WINGET_CATALOG = [
  { names: ['google chrome', 'chrome'],             publishers: ['google'],          wingetId: 'Google.Chrome',                displayName: 'Google Chrome',         publisher: 'Google' },
  { names: ['microsoft edge', 'edge'],              publishers: ['microsoft'],       wingetId: 'Microsoft.Edge',               displayName: 'Microsoft Edge',        publisher: 'Microsoft' },
  { names: ['mozilla firefox', 'firefox'],          publishers: ['mozilla'],         wingetId: 'Mozilla.Firefox',              displayName: 'Mozilla Firefox',       publisher: 'Mozilla' },
  { names: ['7-zip', '7zip'],                       publishers: ['igor pavlov'],     wingetId: '7zip.7zip',                    displayName: '7-Zip',                 publisher: 'Igor Pavlov' },
  { names: ['notepad++', 'notepad plus'],           publishers: [],                  wingetId: 'Notepad++.Notepad++',          displayName: 'Notepad++',             publisher: 'Notepad++ Team' },
  { names: ['vlc', 'vlc media player'],             publishers: ['videolan'],        wingetId: 'VideoLAN.VLC',                 displayName: 'VLC media player',      publisher: 'VideoLAN' },
  { names: ['zoom', 'zoom client'],                 publishers: ['zoom'],            wingetId: 'Zoom.Zoom',                    displayName: 'Zoom',                  publisher: 'Zoom Video Communications' },
  { names: ['adobe acrobat reader', 'acrobat reader', 'adobe reader'], publishers: ['adobe'], wingetId: 'Adobe.Acrobat.Reader.64-bit', displayName: 'Adobe Acrobat Reader', publisher: 'Adobe' },
  { names: ['adobe acrobat'],                       publishers: ['adobe'],           wingetId: 'Adobe.Acrobat.Reader.64-bit', displayName: 'Adobe Acrobat Reader', publisher: 'Adobe' },
  { names: ['microsoft teams', 'teams'],            publishers: ['microsoft'],       wingetId: 'Microsoft.Teams',              displayName: 'Microsoft Teams',       publisher: 'Microsoft' },
  { names: ['slack'],                               publishers: ['slack'],           wingetId: 'SlackTechnologies.Slack',      displayName: 'Slack',                 publisher: 'Slack Technologies' },
  { names: ['visual studio code', 'vscode'],        publishers: ['microsoft'],       wingetId: 'Microsoft.VisualStudioCode',   displayName: 'Visual Studio Code',    publisher: 'Microsoft' },
  { names: ['git'],                                 publishers: ['git'],             wingetId: 'Git.Git',                      displayName: 'Git',                   publisher: 'Git' },
  { names: ['python'],                              publishers: ['python'],          wingetId: 'Python.Python.3',              displayName: 'Python 3',              publisher: 'Python Software Foundation' },
  { names: ['nodejs', 'node.js', 'node js'],        publishers: ['node.js'],         wingetId: 'OpenJS.NodeJS.LTS',            displayName: 'Node.js LTS',           publisher: 'OpenJS Foundation' },
  { names: ['java runtime', 'jre', 'jdk', 'openjdk'], publishers: ['oracle', 'eclipse'], wingetId: 'EclipseAdoptium.Temurin.21.JRE', displayName: 'Eclipse Temurin JRE 21', publisher: 'Eclipse Adoptium' },
  { names: ['putty'],                               publishers: ['simon tatham'],    wingetId: 'PuTTY.PuTTY',                  displayName: 'PuTTY',                 publisher: 'Simon Tatham' },
  { names: ['winrar', 'win rar'],                   publishers: ['win.rar'],         wingetId: 'RARLab.WinRAR',                displayName: 'WinRAR',                publisher: 'RARLab' },
  { names: ['winzip'],                              publishers: ['corel'],           wingetId: 'Corel.WinZip',                 displayName: 'WinZip',                publisher: 'Corel' },
  { names: ['teamviewer'],                          publishers: ['teamviewer'],      wingetId: 'TeamViewer.TeamViewer',        displayName: 'TeamViewer',            publisher: 'TeamViewer' },
  { names: ['anydesk'],                             publishers: ['anydesk'],         wingetId: 'AnyDeskSoftwareGmbH.AnyDesk',  displayName: 'AnyDesk',               publisher: 'AnyDesk Software GmbH' },
  { names: ['malwarebytes'],                        publishers: ['malwarebytes'],    wingetId: 'Malwarebytes.Malwarebytes',    displayName: 'Malwarebytes',          publisher: 'Malwarebytes' },
  { names: ['keepass'],                             publishers: ['dominik reichl'],  wingetId: 'DominikReichl.KeePass',        displayName: 'KeePass',               publisher: 'Dominik Reichl' },
  { names: ['bitwarden'],                           publishers: ['bitwarden'],       wingetId: 'Bitwarden.Bitwarden',          displayName: 'Bitwarden',             publisher: 'Bitwarden' },
  { names: ['1password'],                           publishers: ['1password'],       wingetId: '1password.1password',          displayName: '1Password',             publisher: '1Password' },
  { names: ['dropbox'],                             publishers: ['dropbox'],         wingetId: 'Dropbox.Dropbox',              displayName: 'Dropbox',               publisher: 'Dropbox' },
  { names: ['onedrive'],                            publishers: ['microsoft'],       wingetId: 'Microsoft.OneDrive',           displayName: 'Microsoft OneDrive',    publisher: 'Microsoft' },
  { names: ['skype'],                               publishers: ['microsoft'],       wingetId: 'Microsoft.Skype',              displayName: 'Skype',                 publisher: 'Microsoft' },
  { names: ['office', 'microsoft office', 'microsoft 365'],publishers: ['microsoft'],wingetId: 'Microsoft.Office',            displayName: 'Microsoft Office',      publisher: 'Microsoft' },
  { names: ['powershell'],                          publishers: ['microsoft'],       wingetId: 'Microsoft.PowerShell',         displayName: 'PowerShell',            publisher: 'Microsoft' },
  { names: ['windows terminal'],                    publishers: ['microsoft'],       wingetId: 'Microsoft.WindowsTerminal',    displayName: 'Windows Terminal',      publisher: 'Microsoft' },
];

function norm(s) { return String(s || '').toLowerCase().trim(); }

/**
 * Look up a WinGet ID from the catalog given product name and publisher.
 * Returns { wingetId, displayName, publisher } or null.
 */
function lookupCatalog(productName, publisher) {
  const pn = norm(productName);
  const pub = norm(publisher);
  for (const entry of WINGET_CATALOG) {
    const nameHit = entry.names.some(n => pn.includes(norm(n)) || norm(n).includes(pn));
    const pubHit = !entry.publishers.length || entry.publishers.some(p => pub.includes(norm(p)) || norm(p).includes(pub));
    if (nameHit && pubHit) return { wingetId: entry.wingetId, displayName: entry.displayName, publisher: entry.publisher };
    // Also try without publisher constraint if name match is strong
    if (nameHit && !pub) return { wingetId: entry.wingetId, displayName: entry.displayName, publisher: entry.publisher };
  }
  return null;
}

// ─── Graph helpers ────────────────────────────────────────────────────────────

async function graphPost(accessToken, path, body) {
  const res = await fetch(`https://graph.microsoft.com${path}`, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${accessToken}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(body),
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    const msg = data?.error?.message || data?.message || `Graph POST failed: ${res.status}`;
    const err = new Error(msg);
    err.status = res.status;
    err.graphError = data?.error;
    throw err;
  }
  return data;
}

async function graphGet(accessToken, path) {
  const res = await fetch(`https://graph.microsoft.com${path}`, {
    headers: { 'Authorization': `Bearer ${accessToken}` },
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    const msg = data?.error?.message || `Graph GET failed: ${res.status}`;
    const err = new Error(msg);
    err.status = res.status;
    throw err;
  }
  return data;
}

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

// ─── WinGet Intune operations ─────────────────────────────────────────────────

async function createWinGetApp(accessToken, { packageIdentifier, displayName, publisher, runAsAccount = 'system', updateMode = 'auto' }) {
  return graphPost(accessToken, '/beta/deviceAppManagement/mobileApps', {
    '@odata.type': '#microsoft.graph.winGetApp',
    displayName,
    publisher,
    packageIdentifier,
    description: `Managed by IdentityMonitor · Auto-remediation · Update mode: ${updateMode}`,
    notes: `Managed by IdentityMonitor · package: ${packageIdentifier}`,
    installExperience: { runAsAccount },
    isFeatured: false,
    roleScopeTagIds: ['0'],
  });
}

async function waitForPublished(accessToken, appId, { timeoutMs = 90000, intervalMs = 5000 } = {}) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const app = await graphGet(accessToken, `/beta/deviceAppManagement/mobileApps/${appId}?$select=id,publishingState`);
    if (String(app.publishingState || '').toLowerCase() === 'published') return { published: true, publishingState: 'published' };
    await sleep(intervalMs);
  }
  return { published: false, publishingState: 'pending' };
}

async function assignToAllDevices(accessToken, appId, installIntent = 'required') {
  return graphPost(accessToken, `/beta/deviceAppManagement/mobileApps/${appId}/assignments`, {
    '@odata.type': '#microsoft.graph.mobileAppAssignment',
    intent: installIntent,
    target: { '@odata.type': '#microsoft.graph.allDevicesAssignmentTarget' },
  });
}

// ─── Main entry points ────────────────────────────────────────────────────────

/**
 * Resolve a finding to a WinGet app entry.
 * Returns { ok, wingetId, displayName, publisher, source } or { ok: false, reason }.
 */
function resolveWingetId(finding) {
  // Priority 1: already-enriched winget ID
  if (finding.suggestedWingetId) {
    return {
      ok: true,
      wingetId: finding.suggestedWingetId,
      displayName: finding.displayProductName || finding.productName || finding.suggestedWingetId,
      publisher: finding.publisher || 'Unknown',
      source: 'enriched',
    };
  }

  // Priority 2: catalog lookup
  const product = finding.displayProductName || finding.productName || finding.softwareName || finding.name || '';
  const pub = finding.publisher || finding.displayPublisher || '';
  const catalogHit = lookupCatalog(product, pub);
  if (catalogHit) {
    return { ok: true, ...catalogHit, source: 'catalog' };
  }

  return {
    ok: false,
    reason: `No WinGet package found for "${product}" (publisher: "${pub || 'unknown'}"). Manual remediation required.`,
  };
}

/**
 * Full pipeline: resolve → create Intune WinGet app → wait for publish → assign to All Devices.
 * @param {string} tenantId
 * @param {object} finding  — normalized finding from Defender
 * @returns {{ ok, message, appId?, wingetId?, displayName?, publishingState? }}
 */
async function deployRemediationForFinding(tenantId, finding) {
  // 1. Resolve WinGet ID
  const resolved = resolveWingetId(finding);
  if (!resolved.ok) {
    return { ok: false, message: resolved.reason, executor: 'local-winget' };
  }

  const { wingetId, displayName, publisher } = resolved;

  // 2. Get access token
  let accessToken;
  try {
    accessToken = await getAccessTokenForTenant(tenantId, [
      'https://graph.microsoft.com/.default',
    ]);
  } catch (err) {
    return {
      ok: false,
      message: `Could not acquire Graph token for tenant ${tenantId}: ${err.message}`,
      executor: 'local-winget',
    };
  }

  // 3. Create WinGet app in Intune
  let app;
  try {
    app = await createWinGetApp(accessToken, { packageIdentifier: wingetId, displayName, publisher });
  } catch (err) {
    // If it's a permissions error, give a clear message
    if (err.status === 403 || err.status === 401) {
      return {
        ok: false,
        message: `Intune permission missing: DeviceManagementApps.ReadWrite.All must be granted. Error: ${err.message}`,
        executor: 'local-winget',
        permissionError: true,
      };
    }
    return {
      ok: false,
      message: `Failed to create Intune WinGet app for ${displayName}: ${err.message}`,
      executor: 'local-winget',
    };
  }

  const appId = String(app.id || '').trim();
  if (!appId) {
    return { ok: false, message: 'Intune app creation returned no app ID.', executor: 'local-winget' };
  }

  // 4. Wait for Intune to finish publishing
  const { published, publishingState } = await waitForPublished(accessToken, appId);

  // 5. Assign to All Devices
  let assigned = false;
  if (published) {
    try {
      await assignToAllDevices(accessToken, appId);
      assigned = true;
    } catch (err) {
      console.error('[wingetService] assignment failed:', err.message);
      // Don't fail — app was created, assignment can be done manually
    }
  }

  return {
    ok: true,
    executor: 'local-winget',
    appId,
    wingetId,
    displayName,
    publisher,
    publishingState: published ? 'published' : publishingState,
    assigned,
    timedOut: !published,
    message: assigned
      ? `WinGet app "${displayName}" (${wingetId}) created and assigned to All Devices via Intune.`
      : published
        ? `WinGet app "${displayName}" created and published. Assignment failed — assign manually in Intune.`
        : `WinGet app "${displayName}" created. Intune is still publishing it (assignment pending — check Intune portal).`,
  };
}

module.exports = {
  resolveWingetId,
  lookupCatalog,
  deployRemediationForFinding,
};
