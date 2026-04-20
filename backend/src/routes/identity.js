// identity.js — Express router for Identity/Conditional Access endpoints
// Mounted at /api/identity

const express = require('express');
const router  = express.Router();

const caService        = require('../services/conditionalAccessService');
const { requirePermission } = require('../services/accessControl');

// ─── Helpers ──────────────────────────────────────────────────────────────
function getTenantId(req) {
  return req.session?.tenant?.tenantId || null;
}

const _CA_SCOPES = [
  'openid', 'profile', 'email', 'offline_access',
  'https://graph.microsoft.com/AuditLog.Read.All',
  'https://graph.microsoft.com/Directory.Read.All',
  'https://graph.microsoft.com/User.Read.All',
  'https://graph.microsoft.com/RoleManagement.Read.Directory',
  'https://graph.microsoft.com/Mail.Send',
  'https://graph.microsoft.com/Policy.Read.ConditionalAccess',
  'https://graph.microsoft.com/Policy.ReadWrite.ConditionalAccess',
].join(' ');

// Returns a valid delegated token, refreshing silently if expired.
async function getOrRefreshToken(req) {
  const tokens = req.session?.tokens;
  if (!tokens?.accessToken) return null;
  // Token still valid (2-min buffer)
  if (!tokens.expiresAt || tokens.expiresAt >= Date.now() + 120000) {
    return tokens.accessToken;
  }
  // Expired — try refresh_token
  if (!tokens.refreshToken) return null;
  const tenantId = getTenantId(req);
  const tokenEndpoint = tenantId
    ? `https://login.microsoftonline.com/${tenantId}/oauth2/v2.0/token`
    : 'https://login.microsoftonline.com/common/oauth2/v2.0/token';
  try {
    const resp = await fetch(tokenEndpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id:     process.env.CLIENT_ID,
        client_secret: process.env.CLIENT_SECRET,
        refresh_token: tokens.refreshToken,
        grant_type:    'refresh_token',
        scope:         _CA_SCOPES
      }).toString()
    });
    const data = await resp.json();
    if (data.error || !data.access_token) {
      console.warn('[Identity] Token refresh failed:', data.error_description || data.error);
      return null;
    }
    req.session.tokens = {
      accessToken:  data.access_token,
      refreshToken: data.refresh_token || tokens.refreshToken,
      expiresAt:    Date.now() + (data.expires_in * 1000)
    };
    await new Promise((resolve, reject) => req.session.save(e => e ? reject(e) : resolve()));
    console.log('[Identity] Token refreshed silently for tenant', getTenantId(req));
    return data.access_token;
  } catch (err) {
    console.warn('[Identity] Token refresh error:', err.message);
    return null;
  }
}

// ─── Helper: send error response, detecting 403 permission errors ─────────
function sendError(res, err, defaultStatus) {
  const status = err.statusCode || defaultStatus || 500;
  const body   = { error: err.message || String(err) };
  if (err.isPermissionError || status === 403) {
    body.needsConsent = true;
    if (err.graphErrorCode) body.graphErrorCode = err.graphErrorCode;
  }
  return res.status(status).json(body);
}

// ─────────────────────────────────────────────────────────────────────────
// CA POLICIES
// ─────────────────────────────────────────────────────────────────────────

// ─── Helper: return 401 with re-login hint when delegated token is missing/expired ──
async function requireDelegatedToken(req, res) {
  const token = await getOrRefreshToken(req);
  if (!token) {
    res.status(401).json({
      error: 'Session token expired. Please log out and log in again to use Conditional Access features.',
      reloginRequired: true
    });
    return null;
  }
  return token;
}

// GET /api/identity/ca-policies
router.get('/ca-policies', async (req, res) => {
  const tenantId = getTenantId(req);
  if (!tenantId) return res.status(401).json({ error: 'Not authenticated' });
  const token = await requireDelegatedToken(req, res);
  if (!token) return;
  try {
    const policies = await caService.listCaPolicies(tenantId, token);
    res.json(policies);
  } catch (err) {
    sendError(res, err);
  }
});

// GET /api/identity/ca-policies/:id
router.get('/ca-policies/:id', async (req, res) => {
  const tenantId = getTenantId(req);
  if (!tenantId) return res.status(401).json({ error: 'Not authenticated' });
  const token = await requireDelegatedToken(req, res);
  if (!token) return;
  try {
    const policy = await caService.getCaPolicy(tenantId, req.params.id, token);
    res.json(policy);
  } catch (err) {
    sendError(res, err);
  }
});

// PATCH /api/identity/ca-policies/:id — toggle state
router.patch('/ca-policies/:id', requirePermission('settings.manage'), async (req, res) => {
  const tenantId = getTenantId(req);
  if (!tenantId) return res.status(401).json({ error: 'Not authenticated' });
  const token = await requireDelegatedToken(req, res);
  if (!token) return;
  const { state } = req.body || {};
  if (!state) return res.status(400).json({ error: 'state is required' });
  try {
    const result = await caService.toggleCaPolicy(tenantId, req.params.id, state, token);
    res.json(result || { ok: true });
  } catch (err) {
    sendError(res, err);
  }
});

// DELETE /api/identity/ca-policies/:id
router.delete('/ca-policies/:id', requirePermission('settings.manage'), async (req, res) => {
  const tenantId = getTenantId(req);
  if (!tenantId) return res.status(401).json({ error: 'Not authenticated' });
  const token = await requireDelegatedToken(req, res);
  if (!token) return;
  try {
    await caService.deleteCaPolicy(tenantId, req.params.id, token);
    res.json({ ok: true });
  } catch (err) {
    sendError(res, err);
  }
});

// ─────────────────────────────────────────────────────────────────────────
// NAMED LOCATIONS
// ─────────────────────────────────────────────────────────────────────────

// GET /api/identity/named-locations
router.get('/named-locations', async (req, res) => {
  const tenantId = getTenantId(req);
  if (!tenantId) return res.status(401).json({ error: 'Not authenticated' });
  const token = await requireDelegatedToken(req, res);
  if (!token) return;
  try {
    const locations = await caService.listNamedLocations(tenantId, token);
    res.json(locations);
  } catch (err) {
    sendError(res, err);
  }
});

// ─────────────────────────────────────────────────────────────────────────
// IP BLOCKING
// ─────────────────────────────────────────────────────────────────────────

// POST /api/identity/block-ip
router.post('/block-ip', requirePermission('settings.manage'), async (req, res) => {
  const tenantId = getTenantId(req);
  if (!tenantId) return res.status(401).json({ error: 'Not authenticated' });
  const token = await requireDelegatedToken(req, res);
  if (!token) return;
  const { ipAddress, locationName } = req.body || {};
  if (!ipAddress) return res.status(400).json({ error: 'ipAddress is required' });
  try {
    const result = await caService.blockIpAddress(tenantId, ipAddress, locationName, token);
    res.json(result);
  } catch (err) {
    sendError(res, err);
  }
});

// DELETE /api/identity/block-ip
router.delete('/block-ip', requirePermission('settings.manage'), async (req, res) => {
  const tenantId = getTenantId(req);
  if (!tenantId) return res.status(401).json({ error: 'Not authenticated' });
  const token = await requireDelegatedToken(req, res);
  if (!token) return;
  const { ipAddress, locationName } = req.body || {};
  if (!ipAddress) return res.status(400).json({ error: 'ipAddress is required' });
  try {
    const result = await caService.removeIpBlock(tenantId, ipAddress, locationName, token);
    res.json(result || { ok: true });
  } catch (err) {
    sendError(res, err);
  }
});

// ─────────────────────────────────────────────────────────────────────────
// MFA / BLOCK USER POLICIES
// ─────────────────────────────────────────────────────────────────────────

// POST /api/identity/require-mfa
router.post('/require-mfa', requirePermission('settings.manage'), async (req, res) => {
  const tenantId = getTenantId(req);
  if (!tenantId) return res.status(401).json({ error: 'Not authenticated' });
  const token = await requireDelegatedToken(req, res);
  if (!token) return;
  const { userId, policyName } = req.body || {};
  if (!userId) return res.status(400).json({ error: 'userId is required' });
  try {
    const result = await caService.requireMfaForUser(tenantId, userId, policyName, token);
    res.json(result);
  } catch (err) {
    sendError(res, err);
  }
});

// POST /api/identity/block-user
router.post('/block-user', requirePermission('settings.manage'), async (req, res) => {
  const tenantId = getTenantId(req);
  if (!tenantId) return res.status(401).json({ error: 'Not authenticated' });
  const token = await requireDelegatedToken(req, res);
  if (!token) return;
  const { userId, policyName } = req.body || {};
  if (!userId) return res.status(400).json({ error: 'userId is required' });
  try {
    const result = await caService.blockUserSignIn(tenantId, userId, policyName, token);
    res.json(result);
  } catch (err) {
    sendError(res, err);
  }
});

// GET /api/identity/debug-token
// Shows exactly which permissions are in the service-principal token for this tenant.
// Use this to verify that Application permissions are granted (not just Delegated).
router.get('/debug-token', async (req, res) => {
  const tenantId = getTenantId(req);
  if (!tenantId) return res.status(401).json({ error: 'Not authenticated' });

  try {
    const graphService = require('../services/graphService');
    graphService.clearTokenCache(tenantId); // always fetch fresh

    const CLIENT_ID     = process.env.CLIENT_ID;
    const CLIENT_SECRET = process.env.CLIENT_SECRET;

    const tokenRes = await fetch(
      `https://login.microsoftonline.com/${tenantId}/oauth2/v2.0/token`,
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
    if (data.error) return res.status(400).json({ error: data.error_description || data.error });

    // Decode the JWT payload (middle segment)
    const parts   = data.access_token.split('.');
    const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));

    const roles = payload.roles || [];
    const hasCaRead  = roles.includes('Policy.Read.ConditionalAccess')  || roles.includes('Policy.Read.All');
    const hasCaWrite = roles.includes('Policy.ReadWrite.ConditionalAccess');

    // Actually call the CA policies endpoint to see the real error
    let caCallResult;
    try {
      const caRes = await fetch('https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies', {
        headers: { Authorization: 'Bearer ' + data.access_token }
      });
      const caBody = await caRes.json();
      caCallResult = { httpStatus: caRes.status, body: caBody };
    } catch (caErr) {
      caCallResult = { error: caErr.message };
    }

    res.json({
      tenantId,
      clientId:    CLIENT_ID?.substring(0, 8) + '...',
      tokenExpiry: new Date(payload.exp * 1000).toISOString(),
      roles,
      caPermissions: {
        read:  hasCaRead,
        write: hasCaWrite,
        verdict: hasCaRead && hasCaWrite ? '✅ All CA permissions present' :
                 hasCaRead               ? '⚠️ Read-only — missing Policy.ReadWrite.ConditionalAccess' :
                                           '❌ Missing CA permissions — check Application (not Delegated) consent'
      },
      caApiCall: caCallResult
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/identity/debug-session-token
// Decodes the delegated session token (with auto-refresh) and makes a live CA call.
// Shows aud, ver, scp so you can see exactly what Graph receives.
router.get('/debug-session-token', async (req, res) => {
  const tenantId = getTenantId(req);
  if (!tenantId) return res.status(401).json({ error: 'Not authenticated' });

  // Use the same refresh logic the CA routes use — so we see the actual token Graph gets
  const rawTokens = req.session?.tokens;
  const accessToken = await getOrRefreshToken(req);
  if (!accessToken) {
    return res.status(401).json({ error: 'No valid session token. Please log in again.' });
  }

  try {
    const parts = accessToken.split('.');
    const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));

    const scp        = (payload.scp || '').split(' ').filter(Boolean);
    const hasCaRead  = scp.includes('Policy.Read.ConditionalAccess');
    const hasCaWrite = scp.includes('Policy.ReadWrite.ConditionalAccess');
    const wasRefreshed = rawTokens?.accessToken !== accessToken;

    // Make the actual CA call directly with fetch (no SDK) so there's no SDK interference
    let caCallResult;
    try {
      const caRes = await fetch('https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies', {
        headers: { Authorization: 'Bearer ' + accessToken }
      });
      const caBody = await caRes.json();
      caCallResult = { httpStatus: caRes.status, body: caBody };
    } catch (caErr) {
      caCallResult = { error: caErr.message };
    }

    res.json({
      tenantId,
      userEmail:    payload.upn || payload.preferred_username || payload.unique_name || '?',
      tokenVersion: payload.ver || '?',
      audience:     payload.aud || '?',
      issuedAt:     payload.iat ? new Date(payload.iat * 1000).toISOString() : null,
      tokenExpiry:  new Date(payload.exp * 1000).toISOString(),
      tokenType:    payload.idtyp || (payload.scp ? 'delegated' : 'app-only'),
      wasAutoRefreshed: wasRefreshed,
      scp,
      caPermissions: {
        read:  hasCaRead,
        write: hasCaWrite,
        verdict: hasCaRead && hasCaWrite
          ? '✅ CA scopes present'
          : hasCaRead
          ? '⚠️ Read-only — Policy.ReadWrite.ConditionalAccess missing from scp'
          : '❌ CA scopes missing — need fresh login with CA scopes consented'
      },
      caApiCall: caCallResult
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
