// conditionalAccessService.js — Microsoft Graph Conditional Access management
// Requires Policy.Read.ConditionalAccess + Policy.ReadWrite.ConditionalAccess permissions

const graphService = require('./graphService');

// ─── Helper: get Graph client for tenant ─────────────────────────────────
async function _client(tenantId) {
  return graphService.getClientForTenant(tenantId);
}

// ─── Helper: wrap 403 errors with a helpful message ───────────────────────
function _wrapError(err) {
  if (err && (err.statusCode === 403 || (err.code && err.code === 'Authorization_RequestDenied'))) {
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

// ─── List all CA policies ─────────────────────────────────────────────────
async function listCaPolicies(tenantId) {
  try {
    const client = await _client(tenantId);
    const res = await client.api('/identity/conditionalAccess/policies').get();
    return res.value || [];
  } catch (err) {
    _wrapError(err);
  }
}

// ─── List named locations ─────────────────────────────────────────────────
async function listNamedLocations(tenantId) {
  try {
    const client = await _client(tenantId);
    const res = await client.api('/identity/conditionalAccess/namedLocations').get();
    return res.value || [];
  } catch (err) {
    _wrapError(err);
  }
}

// ─── Get a single CA policy ───────────────────────────────────────────────
async function getCaPolicy(tenantId, policyId) {
  try {
    const client = await _client(tenantId);
    return await client.api(`/identity/conditionalAccess/policies/${policyId}`).get();
  } catch (err) {
    _wrapError(err);
  }
}

// ─── Toggle CA policy state ───────────────────────────────────────────────
// state: 'enabled' | 'disabled' | 'enabledForReportingButNotEnforced'
async function toggleCaPolicy(tenantId, policyId, state) {
  try {
    const client = await _client(tenantId);
    return await client.api(`/identity/conditionalAccess/policies/${policyId}`).patch({ state });
  } catch (err) {
    _wrapError(err);
  }
}

// ─── Delete a CA policy ───────────────────────────────────────────────────
async function deleteCaPolicy(tenantId, policyId) {
  try {
    const client = await _client(tenantId);
    return await client.api(`/identity/conditionalAccess/policies/${policyId}`).delete();
  } catch (err) {
    _wrapError(err);
  }
}

// ─── Block an IP address via Named Location ───────────────────────────────
async function blockIpAddress(tenantId, ipAddress, locationName = 'IdentityMonitor-Blocked-IPs') {
  try {
    const client = await _client(tenantId);

    // Normalize the CIDR
    const cidr = ipAddress.includes('/') ? ipAddress : ipAddress + '/32';

    // Look for an existing named location with that display name
    const locRes = await client.api('/identity/conditionalAccess/namedLocations').get();
    const existing = (locRes.value || []).find(l => l.displayName === locationName);

    if (existing) {
      // Add the new CIDR if not already present
      const currentRanges = existing.ipRanges || [];
      const alreadyBlocked = currentRanges.some(r => r.cidrAddress === cidr);

      if (alreadyBlocked) return existing;

      const updatedRanges = [
        ...currentRanges,
        { '@odata.type': '#microsoft.graph.iPv4CidrRange', cidrAddress: cidr }
      ];

      return await client
        .api(`/identity/conditionalAccess/namedLocations/${existing.id}`)
        .patch({
          '@odata.type': '#microsoft.graph.ipNamedLocation',
          ipRanges: updatedRanges
        });
    }

    // Create a new named location
    return await client.api('/identity/conditionalAccess/namedLocations').post({
      '@odata.type': '#microsoft.graph.ipNamedLocation',
      displayName:   locationName,
      isTrusted:     false,
      ipRanges: [
        { '@odata.type': '#microsoft.graph.iPv4CidrRange', cidrAddress: cidr }
      ]
    });
  } catch (err) {
    _wrapError(err);
  }
}

// ─── Require MFA for a specific user via a new CA policy ─────────────────
async function requireMfaForUser(tenantId, userId, policyName) {
  const displayName = policyName || `IdentityMonitor-RequireMFA-${userId}`;
  try {
    const client = await _client(tenantId);
    return await client.api('/identity/conditionalAccess/policies').post({
      displayName,
      state: 'enabled',
      conditions: {
        users: {
          includeUsers: [userId]
        },
        applications: {
          includeApplications: ['All']
        }
      },
      grantControls: {
        operator:         'OR',
        builtInControls:  ['mfa']
      }
    });
  } catch (err) {
    _wrapError(err);
  }
}

// ─── Block a user's sign-in via a new CA policy ───────────────────────────
async function blockUserSignIn(tenantId, userId, policyName) {
  const displayName = policyName || `IdentityMonitor-BlockUser-${userId}`;
  try {
    const client = await _client(tenantId);
    return await client.api('/identity/conditionalAccess/policies').post({
      displayName,
      state: 'enabled',
      conditions: {
        users: {
          includeUsers: [userId]
        },
        applications: {
          includeApplications: ['All']
        }
      },
      grantControls: {
        operator:        'OR',
        builtInControls: ['block']
      }
    });
  } catch (err) {
    _wrapError(err);
  }
}

// ─── Remove a specific IP from a named location ───────────────────────────
async function removeIpBlock(tenantId, ipAddress, locationName = 'IdentityMonitor-Blocked-IPs') {
  try {
    const client = await _client(tenantId);
    const cidr = ipAddress.includes('/') ? ipAddress : ipAddress + '/32';

    const locRes = await client.api('/identity/conditionalAccess/namedLocations').get();
    const existing = (locRes.value || []).find(l => l.displayName === locationName);

    if (!existing) throw new Error(`Named location "${locationName}" not found`);

    const updatedRanges = (existing.ipRanges || []).filter(r => r.cidrAddress !== cidr);

    return await client
      .api(`/identity/conditionalAccess/namedLocations/${existing.id}`)
      .patch({
        '@odata.type': '#microsoft.graph.ipNamedLocation',
        ipRanges: updatedRanges
      });
  } catch (err) {
    _wrapError(err);
  }
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
