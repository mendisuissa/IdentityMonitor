// conditionalAccessService.js — Microsoft Graph Conditional Access management
// Requires Policy.Read.ConditionalAccess + Policy.ReadWrite.ConditionalAccess permissions

const graphService = require('./graphService');

// ─── Helper: get Graph client for tenant ─────────────────────────────────
async function _client(tenantId) {
  return graphService.getClientForTenant(tenantId);
}

// ─── Helper: is this a 403 / permission error? ────────────────────────────
function _is403(err) {
  return err && (
    err.statusCode === 403 ||
    err.status === 403 ||
    (err.code && (err.code === 'Authorization_RequestDenied' || err.code === 'Forbidden'))
  );
}

// ─── Helper: wrap 403 errors with a helpful message ───────────────────────
function _wrapError(err) {
  if (_is403(err)) {
    const e = new Error(
      'Access denied. Ensure the application has Policy.ReadWrite.ConditionalAccess ' +
      'permission granted via admin consent.'
    );
    e.statusCode = 403;
    e.isPermissionError = true;
    throw e;
  }
  throw err;
}

// ─── Helper: run a Graph call, auto-clear cache + retry once on 403 ──────
// This handles the case where consent was just granted but the cached token
// pre-dates the consent grant.
async function _withRetry(tenantId, fn) {
  try {
    const client = await _client(tenantId);
    return await fn(client);
  } catch (err) {
    if (_is403(err)) {
      // Clear stale token and retry with fresh one
      graphService.clearTokenCache(tenantId);
      try {
        const client = await _client(tenantId);
        return await fn(client);
      } catch (retryErr) {
        _wrapError(retryErr);
      }
    }
    throw err;
  }
}

// ─── List all CA policies ─────────────────────────────────────────────────
async function listCaPolicies(tenantId) {
  return _withRetry(tenantId, client =>
    client.api('/identity/conditionalAccess/policies').get().then(r => r.value || [])
  );
}

// ─── List named locations ─────────────────────────────────────────────────
async function listNamedLocations(tenantId) {
  return _withRetry(tenantId, client =>
    client.api('/identity/conditionalAccess/namedLocations').get().then(r => r.value || [])
  );
}

// ─── Get a single CA policy ───────────────────────────────────────────────
async function getCaPolicy(tenantId, policyId) {
  return _withRetry(tenantId, client =>
    client.api(`/identity/conditionalAccess/policies/${policyId}`).get()
  );
}

// ─── Toggle CA policy state ───────────────────────────────────────────────
// state: 'enabled' | 'disabled' | 'enabledForReportingButNotEnforced'
async function toggleCaPolicy(tenantId, policyId, state) {
  return _withRetry(tenantId, client =>
    client.api(`/identity/conditionalAccess/policies/${policyId}`).patch({ state })
  );
}

// ─── Delete a CA policy ───────────────────────────────────────────────────
async function deleteCaPolicy(tenantId, policyId) {
  return _withRetry(tenantId, client =>
    client.api(`/identity/conditionalAccess/policies/${policyId}`).delete()
  );
}

// ─── Block an IP address via Named Location ───────────────────────────────
async function blockIpAddress(tenantId, ipAddress, locationName = 'IdentityMonitor-Blocked-IPs') {
  const cidr = ipAddress.includes('/') ? ipAddress : ipAddress + '/32';

  return _withRetry(tenantId, async client => {
    const locRes = await client.api('/identity/conditionalAccess/namedLocations').get();
    const existing = (locRes.value || []).find(l => l.displayName === locationName);

    if (existing) {
      const currentRanges = existing.ipRanges || [];
      if (currentRanges.some(r => r.cidrAddress === cidr)) return existing;

      return client
        .api(`/identity/conditionalAccess/namedLocations/${existing.id}`)
        .patch({
          '@odata.type': '#microsoft.graph.ipNamedLocation',
          ipRanges: [
            ...currentRanges,
            { '@odata.type': '#microsoft.graph.iPv4CidrRange', cidrAddress: cidr }
          ]
        });
    }

    return client.api('/identity/conditionalAccess/namedLocations').post({
      '@odata.type': '#microsoft.graph.ipNamedLocation',
      displayName:   locationName,
      isTrusted:     false,
      ipRanges: [
        { '@odata.type': '#microsoft.graph.iPv4CidrRange', cidrAddress: cidr }
      ]
    });
  });
}

// ─── Require MFA for a specific user via a new CA policy ─────────────────
async function requireMfaForUser(tenantId, userId, policyName) {
  const displayName = policyName || `IdentityMonitor-RequireMFA-${userId}`;
  return _withRetry(tenantId, client =>
    client.api('/identity/conditionalAccess/policies').post({
      displayName,
      state: 'enabled',
      conditions: {
        users:        { includeUsers: [userId] },
        applications: { includeApplications: ['All'] }
      },
      grantControls: { operator: 'OR', builtInControls: ['mfa'] }
    })
  );
}

// ─── Block a user's sign-in via a new CA policy ───────────────────────────
async function blockUserSignIn(tenantId, userId, policyName) {
  const displayName = policyName || `IdentityMonitor-BlockUser-${userId}`;
  return _withRetry(tenantId, client =>
    client.api('/identity/conditionalAccess/policies').post({
      displayName,
      state: 'enabled',
      conditions: {
        users:        { includeUsers: [userId] },
        applications: { includeApplications: ['All'] }
      },
      grantControls: { operator: 'OR', builtInControls: ['block'] }
    })
  );
}

// ─── Remove a specific IP from a named location ───────────────────────────
async function removeIpBlock(tenantId, ipAddress, locationName = 'IdentityMonitor-Blocked-IPs') {
  const cidr = ipAddress.includes('/') ? ipAddress : ipAddress + '/32';

  return _withRetry(tenantId, async client => {
    const locRes = await client.api('/identity/conditionalAccess/namedLocations').get();
    const existing = (locRes.value || []).find(l => l.displayName === locationName);

    if (!existing) throw new Error(`Named location "${locationName}" not found`);

    const updatedRanges = (existing.ipRanges || []).filter(r => r.cidrAddress !== cidr);
    return client
      .api(`/identity/conditionalAccess/namedLocations/${existing.id}`)
      .patch({ '@odata.type': '#microsoft.graph.ipNamedLocation', ipRanges: updatedRanges });
  });
}

module.exports = {
  listCaPolicies,
  listNamedLocations,
  getCaPolicy,
  toggleCaPolicy,
  deleteCaPolicy,
  blockIpAddress,
  requireMfaForUser,
  blockUserSignIn,
  removeIpBlock
};
