'use strict';

/**
 * webappExecutionClient.js
 *
 * Provides resolve + execute for CVE remediation.
 * Primary path: local wingetService (no external dependency).
 * Fallback: localhost:4000 Webapp (if WEBAPP_REMEDIATION_BASE_URL is set and reachable).
 */

const { resolveWingetId, deployRemediationForFinding } = require('./wingetService');

// ─── Optional external Webapp fallback ───────────────────────────────────────

function getWebappConfig() {
  const baseUrl = String(
    process.env.WEBAPP_REMEDIATION_BASE_URL ||
    process.env.WEBAPP_BASE_URL ||
    ''
  ).replace(/\/$/, '');

  const token = String(
    process.env.WEBAPP_REMEDIATION_TOKEN ||
    process.env.REMEDIATION_SHARED_TOKEN ||
    ''
  ).trim();

  return { baseUrl, token, configured: !!baseUrl };
}

async function tryExternalHealth() {
  const { baseUrl, token } = getWebappConfig();
  if (!baseUrl) return { ok: false, reason: 'not configured' };
  try {
    const headers = { Accept: 'application/json' };
    if (token) headers.Authorization = `Bearer ${token}`;
    const res = await fetch(`${baseUrl}/api/remediation/health`, {
      headers,
      signal: AbortSignal.timeout(4000),
    });
    if (!res.ok) return { ok: false, reason: `HTTP ${res.status}` };
    const data = await res.json().catch(() => ({}));
    return { ok: true, service: data?.service || 'webapp', baseUrl };
  } catch (err) {
    return { ok: false, reason: err.message, baseUrl };
  }
}

// ─── Public API ───────────────────────────────────────────────────────────────

/**
 * Health check — always returns ok:true now that we have a local executor.
 * Still tries external as an advisory (shown in /api/remediation/health).
 */
async function getExternalHealth() {
  const external = await tryExternalHealth();
  return {
    ok: true,                         // local executor is always available
    service: 'local-winget-executor',
    executor: 'local',
    external,                         // advisory only
    baseUrl: 'local',
  };
}

/**
 * Resolve a finding to a remediation plan (catalog lookup — fast, no Graph call).
 */
async function resolveApplicationRemediation(finding) {
  const resolved = resolveWingetId(finding);
  if (!resolved.ok) {
    return {
      ok: false,
      supported: false,
      remediationType: 'manual-review',
      autoRemediate: false,
      message: resolved.reason,
      executor: 'local-winget',
    };
  }
  return {
    ok: true,
    supported: true,
    remediationType: 'winget-intune-upgrade',
    autoRemediate: true,
    executor: 'local-winget',
    app: {
      wingetId: resolved.wingetId,
      packageIdentifier: resolved.wingetId,
      displayName: resolved.displayName,
      publisher: resolved.publisher,
      installerType: 'winget',
      source: resolved.source,
      installCommand: `winget install --id ${resolved.wingetId} --silent --accept-package-agreements --accept-source-agreements`,
    },
    message: `Resolved: ${resolved.displayName} (${resolved.wingetId}) from ${resolved.source}.`,
  };
}

/**
 * Execute remediation: deploy WinGet app to Intune via Graph API.
 * payload = { tenantId, finding, options }
 */
async function executeApplicationRemediation(payload) {
  const { tenantId, finding = {}, options = {} } = payload || {};

  if (!tenantId) {
    throw Object.assign(new Error('tenantId is required for local WinGet execution.'), { status: 400 });
  }

  // Merge any wingetId hint from options into the finding
  const enrichedFinding = {
    ...finding,
    suggestedWingetId: finding.suggestedWingetId || options.wingetId || options.suggestedWingetId || null,
  };

  const result = await deployRemediationForFinding(tenantId, enrichedFinding);

  if (!result.ok) {
    const err = new Error(result.message);
    err.status = result.permissionError ? 403 : 502;
    err.details = result;
    throw err;
  }

  return {
    ok: true,
    executor: 'local-winget',
    appId: result.appId,
    wingetId: result.wingetId,
    displayName: result.displayName,
    publishingState: result.publishingState,
    assigned: result.assigned,
    timedOut: result.timedOut,
    message: result.message,
    steps: [
      { step: 'resolve',  status: 'ok', detail: `Package: ${result.wingetId}` },
      { step: 'create',   status: 'ok', detail: `Intune app ID: ${result.appId}` },
      { step: 'publish',  status: result.timedOut ? 'pending' : 'ok', detail: result.publishingState },
      { step: 'assign',   status: result.assigned ? 'ok' : 'pending', detail: result.assigned ? 'All Devices' : 'pending' },
    ],
  };
}

module.exports = {
  getExternalHealth,
  getWebappConfig,
  resolveApplicationRemediation,
  executeApplicationRemediation,
};
