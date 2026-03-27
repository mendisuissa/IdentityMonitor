// graphService.js
// Multi-tenant aware — uses the session token for the connected tenant
// Falls back to service principal (CLIENT_SECRET) for background scans

require('isomorphic-fetch');
const { ClientSecretCredential } = require('@azure/identity');
const { Client } = require('@microsoft/microsoft-graph-client');
const { TokenCredentialAuthenticationProvider } = require('@microsoft/microsoft-graph-client/authProviders/azureTokenCredentials');

// ─── Token cache per tenant (for background scans) ────────────────────────
const tokenCache = new Map(); // tenantId → { accessToken, expiresAt }

// ─── Build Graph client from a bearer token (delegated / from session) ─────
function getClientFromToken(accessToken) {
  return Client.init({
    authProvider: (done) => done(null, accessToken)
  });
}

// ─── Build Graph client using client credentials for a specific tenant ──────
// Used for background cron scans — requires admin_consent was already granted
async function getClientForTenant(tenantId) {
  const CLIENT_ID     = process.env.CLIENT_ID;
  const CLIENT_SECRET = process.env.CLIENT_SECRET;

  if (!CLIENT_ID || !CLIENT_SECRET) {
    throw new Error('CLIENT_ID and CLIENT_SECRET must be configured');
  }

  // Check token cache
  const cached = tokenCache.get(tenantId);
  if (cached && cached.expiresAt > Date.now() + 60000) {
    return getClientFromToken(cached.accessToken);
  }

  // Get new token using client_credentials for this tenant
  // This works because admin already granted consent via the OAuth flow
  const tokenRes = await fetch(
    'https://login.microsoftonline.com/' + tenantId + '/oauth2/v2.0/token',
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id:     CLIENT_ID,
        client_secret: CLIENT_SECRET,
        scope:         'https://graph.microsoft.com/.default',
        grant_type:    'client_credentials'
      }).toString()
    }
  );

  const data = await tokenRes.json();
  if (data.error) throw new Error(data.error_description || data.error);

  // Cache the token
  tokenCache.set(tenantId, {
    accessToken: data.access_token,
    expiresAt:   Date.now() + (data.expires_in * 1000)
  });

  return getClientFromToken(data.access_token);
}

async function graphGetAll(client, apiPath, pageSize = 999) {
  const items = [];
  let req = client.api(apiPath).top(pageSize);
  while (req) {
    const page = await req.get();
    items.push(...(page.value || []));
    req = page['@odata.nextLink'] ? client.api(page['@odata.nextLink']) : null;
  }
  return items;
}

function isPrivilegedRoleName(name) {
  const value = String(name || '').toLowerCase();
  if (!value) return false;
  return [
    'global administrator',
    'privileged role administrator',
    'security administrator',
    'conditional access administrator',
    'authentication administrator',
    'application administrator',
    'cloud application administrator',
    'exchange administrator',
    'sharepoint administrator',
    'teams administrator',
    'intune administrator',
    'cloud device administrator',
    'hybrid identity administrator',
    'user administrator',
    'helpdesk administrator',
    'password administrator'
  ].some(r => value.includes(r));
}

// ─── Get privileged users for a tenant ────────────────────────────────────
async function getPrivilegedUsers(tenantId) {
  const client = await getClientForTenant(tenantId);
  const allUsers = new Map();

  try {
    // PIM endpoints (roleEligibilitySchedules) require Azure AD P2 — fall back to [] if unavailable
    const [roleDefinitions, activeAssignments, eligibleAssignments, activatedRoles] = await Promise.all([
      graphGetAll(client, '/roleManagement/directory/roleDefinitions?$select=id,displayName,isBuiltIn'),
      graphGetAll(client, '/roleManagement/directory/roleAssignments?$select=id,principalId,roleDefinitionId,endDateTime'),
      graphGetAll(client, '/roleManagement/directory/roleEligibilitySchedules?$select=id,principalId,roleDefinitionId').catch(err => {
        console.warn('[Graph] roleEligibilitySchedules unavailable (requires P2/PIM):', err.message);
        return [];
      }),
      graphGetAll(client, '/directoryRoles?$select=id,displayName'),
    ]);

    const roleMap = new Map((roleDefinitions || []).map(r => [r.id, r.displayName]));
    const privilegedRoleIds = new Set((roleDefinitions || []).filter(r => isPrivilegedRoleName(r.displayName)).map(r => r.id));
    const principalRoles = new Map();

    for (const assignment of (activeAssignments || [])) {
      if (!privilegedRoleIds.has(assignment.roleDefinitionId)) continue;
      const roleName = roleMap.get(assignment.roleDefinitionId) || assignment.roleDefinitionId;
      const entry = principalRoles.get(assignment.principalId) || new Set();
      entry.add(roleName);
      principalRoles.set(assignment.principalId, entry);
    }

    for (const assignment of (eligibleAssignments || [])) {
      if (!privilegedRoleIds.has(assignment.roleDefinitionId)) continue;
      const roleName = (roleMap.get(assignment.roleDefinitionId) || assignment.roleDefinitionId) + ' (Eligible)';
      const entry = principalRoles.get(assignment.principalId) || new Set();
      entry.add(roleName);
      principalRoles.set(assignment.principalId, entry);
    }

    for (const role of (activatedRoles || []).filter(r => isPrivilegedRoleName(r.displayName))) {
      try {
        const members = await graphGetAll(client, `/directoryRoles/${role.id}/members?$select=id,displayName,userPrincipalName,mail,accountEnabled`);
        for (const user of members) {
          if (!user?.id) continue;
          const entry = principalRoles.get(user.id) || new Set();
          entry.add(role.displayName);
          principalRoles.set(user.id, entry);
          if (!allUsers.has(user.id)) allUsers.set(user.id, { ...user, roles: [] });
        }
      } catch (err) {
        console.error('[Graph] Error fetching activated role members', role.displayName, err.message);
      }
    }

    const principalIds = Array.from(principalRoles.keys());
    const detailResults = await Promise.allSettled(principalIds.map(id =>
      client.api(`/users/${id}`).select('id,displayName,userPrincipalName,mail,accountEnabled').get()
    ));

    detailResults.forEach((result, index) => {
      const id = principalIds[index];
      const roles = Array.from(principalRoles.get(id) || []);
      if (result.status === 'fulfilled' && result.value?.id) {
        const user = result.value;
        allUsers.set(user.id, { ...user, roles });
      } else if (allUsers.has(id)) {
        allUsers.get(id).roles = roles;
      }
    });
  } catch (err) {
    console.error('[Graph] Error building privileged user set:', err.message);
  }

  return Array.from(allUsers.values()).sort((a, b) => String(a.displayName || '').localeCompare(String(b.displayName || '')));
}

// ─── Get sign-in logs for a user ──────────────────────────────────────────
async function getUserSignIns(tenantId, userId, hoursBack) {
  hoursBack = hoursBack || 72;
  const client = await getClientForTenant(tenantId);
  const since  = new Date(Date.now() - hoursBack * 3600000).toISOString();

  try {
    const result = await client
      .api('/auditLogs/signIns')
      .filter("userId eq '" + userId + "' and createdDateTime ge " + since)
      .select('id,createdDateTime,userDisplayName,userPrincipalName,userId,ipAddress,location,deviceDetail,status,conditionalAccessStatus,riskLevelAggregated,clientAppUsed,appDisplayName')
      .orderby('createdDateTime desc')
      .top(100)
      .get();

    return result.value || [];
  } catch (err) {
    console.error('[Graph] Error fetching sign-ins for ' + userId + ':', err.message);
    return [];
  }
}

// ─── Get all privileged sign-ins (last N hours) ────────────────────────────
async function getAllPrivilegedSignIns(tenantId, hoursBack) {
  hoursBack = hoursBack || 24;
  const client = await getClientForTenant(tenantId);
  const since  = new Date(Date.now() - hoursBack * 3600000).toISOString();

  try {
    const result = await client
      .api('/auditLogs/signIns')
      .filter('createdDateTime ge ' + since)
      .select('id,createdDateTime,userDisplayName,userPrincipalName,userId,ipAddress,location,deviceDetail,status,conditionalAccessStatus,riskLevelAggregated,clientAppUsed,appDisplayName')
      .orderby('createdDateTime desc')
      .top(500)
      .get();

    return result.value || [];
  } catch (err) {
    console.error('[Graph] Error fetching all sign-ins:', err.message);
    return [];
  }
}

// ─── Send alert email via Graph ────────────────────────────────────────────
async function sendAlertEmail(tenantId, { to, subject, body }) {
  const client      = await getClientForTenant(tenantId);
  const senderEmail = process.env.ALERT_SENDER_EMAIL;

  const message = {
    subject,
    body:         { contentType: 'HTML', content: body },
    toRecipients: [{ emailAddress: { address: to } }]
  };

  await client
    .api('/users/' + senderEmail + '/sendMail')
    .post({ message, saveToSentItems: true });
}

// ─── Revoke all refresh tokens for a user ─────────────────────────────────
async function revokeUserSessions(tenantId, userId) {
  const client = await getClientForTenant(tenantId);
  await client.api('/users/' + userId + '/revokeSignInSessions').post({});
}


// ─── Disable a user account ────────────────────────────────────────────────
async function disableUser(tenantId, userId) {
  const client = await getClientForTenant(tenantId);
  await client.api('/users/' + userId).patch({ accountEnabled: false });
}

// ─── Enable a user account ────────────────────────────────────────────────
async function enableUser(tenantId, userId) {
  const client = await getClientForTenant(tenantId);
  await client.api('/users/' + userId).patch({ accountEnabled: true });
}

// ─── Get device actions (wipe/delete/reset) from Intune ───────────────────
async function getDeviceActions(tenantId) {
  const ACTION_MAP = {
    wipe:           { type: 'wipe',   severity: 'critical' },
    factoryReset:   { type: 'wipe',   severity: 'critical' },
    deleteUserData: { type: 'delete', severity: 'high'     },
    retire:         { type: 'delete', severity: 'high'     },
    resetPasscode:  { type: 'reset',  severity: 'medium'   },
    rebootNow:      { type: 'reset',  severity: 'medium'   },
  };
  const STATUS_MAP = { done: 'completed', pending: 'pending', failed: 'completed' };

  try {
    const client = await getClientForTenant(tenantId);
    const response = await client
      .api('/deviceManagement/managedDevices')
      .select('id,deviceName,userDisplayName,userPrincipalName,deviceActionResults,operatingSystem')
      .top(200)
      .get();

    const actions = [];
    for (const device of (response.value || [])) {
      for (const action of (device.deviceActionResults || [])) {
        const mapped = ACTION_MAP[action.actionName];
        if (!mapped || !action.actionState || action.actionState === 'none' || action.actionState === 'notStarted') continue;
        actions.push({
          id:                `${device.id}-${action.actionName}-${action.startDateTime}`,
          type:              mapped.type,
          deviceName:        device.deviceName        || 'Unknown Device',
          userDisplayName:   device.userDisplayName   || device.userPrincipalName || 'Unknown',
          userPrincipalName: device.userPrincipalName || '',
          initiatedBy:       'IT Admin',
          timestamp:         action.startDateTime || action.lastUpdatedDateTime || new Date().toISOString(),
          severity:          mapped.severity,
          status:            STATUS_MAP[action.actionState] || 'in_progress',
          os:                device.operatingSystem || undefined,
        });
      }
    }
    actions.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
    return actions.slice(0, 50);
  } catch (err) {
    console.warn('[GraphService] getDeviceActions failed:', err.message);
    return null;
  }
}

module.exports = {
  getClientForTenant,
  getClientFromToken,
  getPrivilegedUsers,
  getUserSignIns,
  getAllPrivilegedSignIns,
  sendAlertEmail,
  revokeUserSessions,
  disableUser,
  enableUser,
  getDeviceActions,
};
