// conditionalAccessService.js — Microsoft Graph Conditional Access management
// Requires Policy.Read.ConditionalAccess + Policy.ReadWrite.ConditionalAccess permissions

const graphService = require('./graphService');

// ─── Helper: get Graph client ─────────────────────────────────────────────
// Prefers delegated (user) token — CA Policy API requires it.
// Falls back to service-principal token for background/playbook use.
async function _client(tenantId, accessToken) {
  if (accessToken) return graphService.getClientFromToken(accessToken);
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

// ─── Helper: run a Graph call, retry once on 403 ─────────────────────────
async function _withRetry(tenantId, fn, accessToken) {
  try {
    const client = await _client(tenantId, accessToken);
    return await fn(client);
  } catch (err) {
    if (_is403(err) && !accessToken) {
      // Only retry with cache-clear for service-principal tokens
      graphService.clearTokenCache(tenantId);
      try {
        const client = await _client(tenantId, null);
        return await fn(client);
      } catch (retryErr) {
        _wrapError(retryErr);
      }
    }
    if (_is403(err)) _wrapError(err);
    throw err;
  }
}

async function listCaPolicies(tenantId, accessToken) {
  return _withRetry(tenantId, client =>
    client.api('/identity/conditionalAccess/policies').get().then(r => r.value || [])
  , accessToken);
}

async function listNamedLocations(tenantId, accessToken) {
  return _withRetry(tenantId, client =>
    client.api('/identity/conditionalAccess/namedLocations').get().then(r => r.value || [])
  , accessToken);
}

async function getCaPolicy(tenantId, policyId, accessToken) {
  return _withRetry(tenantId, client =>
    client.api(`/identity/conditionalAccess/policies/${policyId}`).get()
  , accessToken);
}

async function toggleCaPolicy(tenantId, policyId, state, accessToken) {
  return _withRetry(tenantId, client =>
    client.api(`/identity/conditionalAccess/policies/${policyId}`).patch({ state })
  , accessToken);
}

async function deleteCaPolicy(tenantId, policyId, accessToken) {
  return _withRetry(tenantId, client =>
    client.api(`/identity/conditionalAccess/policies/${policyId}`).delete()
  , accessToken);
}

async function blockIpAddress(tenantId, ipAddress, locationName = 'IdentityMonitor-Blocked-IPs', accessToken) {
  const cidr = ipAddress.includes('/') ? ipAddress : ipAddress + '/32';
  return _withRetry(tenantId, async client => {
    const locRes = await client.api('/identity/conditionalAccess/namedLocations').get();
    const existing = (locRes.value || []).find(l => l.displayName === locationName);
    if (existing) {
      const currentRanges = existing.ipRanges || [];
      if (currentRanges.some(r => r.cidrAddress === cidr)) return existing;
      return client.api(`/identity/conditionalAccess/namedLocations/${existing.id}`)
        .patch({ '@odata.type': '#microsoft.graph.ipNamedLocation', ipRanges: [...currentRanges, { '@odata.type': '#microsoft.graph.iPv4CidrRange', cidrAddress: cidr }] });
    }
    return client.api('/identity/conditionalAccess/namedLocations').post({
      '@odata.type': '#microsoft.graph.ipNamedLocation', displayName: locationName, isTrusted: false,
      ipRanges: [{ '@odata.type': '#microsoft.graph.iPv4CidrRange', cidrAddress: cidr }]
    });
  }, accessToken);
}

async function requireMfaForUser(tenantId, userId, policyName, accessToken) {
  const displayName = policyName || `IdentityMonitor-RequireMFA-${userId}`;
  return _withRetry(tenantId, client =>
    client.api('/identity/conditionalAccess/policies').post({
      displayName, state: 'enabled',
      conditions: { users: { includeUsers: [userId] }, applications: { includeApplications: ['All'] } },
      grantControls: { operator: 'OR', builtInControls: ['mfa'] }
    })
  , accessToken);
}

async function blockUserSignIn(tenantId, userId, policyName, accessToken) {
  const displayName = policyName || `IdentityMonitor-BlockUser-${userId}`;
  return _withRetry(tenantId, client =>
    client.api('/identity/conditionalAccess/policies').post({
      displayName, state: 'enabled',
      conditions: { users: { includeUsers: [userId] }, applications: { includeApplications: ['All'] } },
      grantControls: { operator: 'OR', builtInControls: ['block'] }
    })
  , accessToken);
}

async function removeIpBlock(tenantId, ipAddress, locationName = 'IdentityMonitor-Blocked-IPs', accessToken) {
  const cidr = ipAddress.includes('/') ? ipAddress : ipAddress + '/32';
  return _withRetry(tenantId, async client => {
    const locRes = await client.api('/identity/conditionalAccess/namedLocations').get();
    const existing = (locRes.value || []).find(l => l.displayName === locationName);
    if (!existing) throw new Error(`Named location "${locationName}" not found`);
    const updatedRanges = (existing.ipRanges || []).filter(r => r.cidrAddress !== cidr);
    return client.api(`/identity/conditionalAccess/namedLocations/${existing.id}`)
      .patch({ '@odata.type': '#microsoft.graph.ipNamedLocation', ipRanges: updatedRanges });
  }, accessToken);
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
