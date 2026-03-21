const express = require('express');
const crypto = require('crypto');
const router  = express.Router();

const CLIENT_ID     = process.env.CLIENT_ID;
const CLIENT_SECRET = process.env.CLIENT_SECRET;
const { upsertTenantIntegration } = require('../services/tenantIntegrationStore');
const REDIRECT_URI  = process.env.REDIRECT_URI  || 'http://localhost:3001/api/auth/callback';
const FRONTEND_URL  = process.env.FRONTEND_URL  || 'http://localhost:5173';
const ADMIN_CONSENT_REDIRECT_URI = process.env.ADMIN_CONSENT_REDIRECT_URI || REDIRECT_URI;

const REQUIRED_SCOPES = [
  'https://graph.microsoft.com/AuditLog.Read.All',
  'https://graph.microsoft.com/Directory.Read.All',
  'https://graph.microsoft.com/User.Read.All',
  'https://graph.microsoft.com/RoleManagement.Read.Directory',
  'https://graph.microsoft.com/Mail.Send'
].join(' ');

function buildAdminConsentUrl(tenantId, state) {
  const params = new URLSearchParams({
    client_id: CLIENT_ID,
    redirect_uri: ADMIN_CONSENT_REDIRECT_URI,
    state,
  });
  return `https://login.microsoftonline.com/${encodeURIComponent(tenantId)}/adminconsent?${params.toString()}`;
}

// GET /api/auth/status
router.get('/status', (req, res) => {
  if (req.session && req.session.tenant) {
    return res.json({ authenticated: true, tenant: req.session.tenant });
  }
  res.json({ authenticated: false });
});

// GET /api/auth/login
router.get('/login', (req, res) => {
  if (!CLIENT_ID) return res.status(500).json({ error: 'CLIENT_ID not configured' });

  const params = new URLSearchParams({
    client_id:     CLIENT_ID,
    response_type: 'code',
    redirect_uri:  REDIRECT_URI,
    scope:         'openid profile email offline_access ' + REQUIRED_SCOPES,
    response_mode: 'query',
    prompt:        'consent',
    state:         'login'
  });

  res.redirect('https://login.microsoftonline.com/common/oauth2/v2.0/authorize?' + params.toString());
});

// GET /api/auth/callback
router.get('/callback', async (req, res) => {
  const { code, error, error_description } = req.query;

  if (error) {
    return res.redirect(FRONTEND_URL + '/login?error=' + encodeURIComponent(String(error_description || error)));
  }
  if (!code) return res.redirect(FRONTEND_URL + '/login?error=no_code');

  try {
    const tokenRes = await fetch(
      'https://login.microsoftonline.com/common/oauth2/v2.0/token',
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          client_id:     CLIENT_ID,
          client_secret: CLIENT_SECRET,
          code:          String(code),
          redirect_uri:  REDIRECT_URI,
          grant_type:    'authorization_code',
          scope:         'openid profile email offline_access ' + REQUIRED_SCOPES
        }).toString()
      }
    );

    const tokens = await tokenRes.json();
    if (tokens.error) throw new Error(tokens.error_description || tokens.error);

    const claims   = decodeJwtClaims(tokens.id_token);
    const tenantId = claims.tid;
    if (!tenantId) throw new Error('Could not determine tenant ID');

    req.session.tenant = {
      tenantId,
      tenantName:  claims.tenant_display_name || tenantId,
      userEmail:   claims.preferred_username || claims.email || '',
      userName:    claims.name || '',
      connectedAt: new Date().toISOString()
    };

    req.session.tokens = {
      accessToken:  tokens.access_token,
      refreshToken: tokens.refresh_token,
      expiresAt:    Date.now() + (tokens.expires_in * 1000)
    };

    const existingConsent = req.session?.defenderConsent || {};
    req.session.defenderConsent = {
      ...existingConsent,
      tenantId,
      lastLoginAt: new Date().toISOString()
    };

    await upsertTenantIntegration({
      tenantId,
      tenantName: claims.tenant_display_name || claims.name || tenantId,
      defenderTenantId: tenantId,
      defenderEnabled: true,
      status: existingConsent?.grantedAt ? 'configured' : 'connected',
      lastValidatedAt: new Date().toISOString(),
      consentGrantedAt: existingConsent?.grantedAt || ''
    }).catch((err) => {
      console.warn('[Auth] Tenant integration upsert failed (non-fatal):', err.message);
    });

    console.log('[Auth] Tenant connected:', tenantId, '(' + req.session.tenant.userEmail + ')');

    setImmediate(async () => {
      try {
        const alertsStore = require('../services/alertsStore');
        await alertsStore.loadFromAzure(tenantId);
      } catch (err) {
        console.warn('[Auth] loadFromAzure failed (non-fatal):', err.message);
      }
    });

    setImmediate(async () => {
      try {
        const webhookService = require('../services/webhookService');
        const existing = await require('../services/tableStorage').getWebhookSubscriptions(tenantId);
        if (existing.length === 0) {
          console.log('[Auth] Setting up webhook for new tenant:', tenantId);
          await webhookService.createSignInSubscription(tenantId);
        }
      } catch (err) {
        console.warn('[Auth] Webhook auto-setup failed (non-fatal):', err.message);
      }
    });

    setImmediate(async () => {
      try {
        const telegram = require('../services/telegramService');
        await telegram.sendMessage(
          '🏢 *New tenant connected*\n\n' +
          '*User:* ' + escMd(req.session.tenant.userName) + '\n' +
          '*Email:* `' + escMd(req.session.tenant.userEmail) + '`\n' +
          '*Tenant ID:* `' + tenantId + '`\n' +
          '*Time:* ' + escMd(new Date().toLocaleString('en-GB'))
        );
      } catch (err) { /* non-fatal */ }
    });

    req.session.save(function(err) {
      if (err) {
        console.error('[Auth] Session save error:', err.message);
        return res.redirect(FRONTEND_URL + '/login?error=session_save_failed');
      }
      res.redirect(FRONTEND_URL);
    });

  } catch (err) {
    console.error('[Auth] Callback error:', err.message);
    res.redirect(FRONTEND_URL + '/login?error=' + encodeURIComponent(err.message));
  }
});

router.get('/admin-consent', (req, res) => {
  const tenantId = req.session?.tenant?.tenantId;
  if (!CLIENT_ID) return res.status(500).json({ ok: false, error: 'CLIENT_ID not configured' });
  if (!tenantId) return res.status(401).json({ ok: false, error: 'No authenticated tenant session was found.' });

  const state = crypto.randomBytes(16).toString('hex');
  req.session.defenderConsent = {
    ...(req.session.defenderConsent || {}),
    tenantId,
    state,
    startedAt: new Date().toISOString()
  };

  req.session.save((err) => {
    if (err) {
      return res.status(500).json({ ok: false, error: 'Failed to persist consent session state.' });
    }
    res.redirect(buildAdminConsentUrl(tenantId, state));
  });
});

router.get('/admin-consent/callback', async (req, res) => {
  const { tenant, admin_consent, state, error, error_description } = req.query;
  const expectedState = req.session?.defenderConsent?.state || null;
  const sessionTenantId = req.session?.tenant?.tenantId || req.session?.defenderConsent?.tenantId || null;

  if (error) {
    return res.redirect(FRONTEND_URL + '/remediation?consent=error&message=' + encodeURIComponent(String(error_description || error)));
  }

  if (!tenant || !sessionTenantId || String(tenant).toLowerCase() != String(sessionTenantId).toLowerCase()) {
    return res.redirect(FRONTEND_URL + '/remediation?consent=error&message=' + encodeURIComponent('Admin consent returned for an unexpected tenant.'));
  }

  if (expectedState && state && expectedState !== state) {
    return res.redirect(FRONTEND_URL + '/remediation?consent=error&message=' + encodeURIComponent('Consent state verification failed.'));
  }

  if (String(admin_consent).toLowerCase() !== 'true') {
    return res.redirect(FRONTEND_URL + '/remediation?consent=error&message=' + encodeURIComponent('Admin consent was not granted.'));
  }

  try {
    await upsertTenantIntegration({
      tenantId: sessionTenantId,
      tenantName: req.session?.tenant?.tenantName || sessionTenantId,
      defenderTenantId: sessionTenantId,
      defenderEnabled: true,
      status: 'configured',
      lastValidatedAt: new Date().toISOString(),
      consentGrantedAt: new Date().toISOString()
    });

    req.session.defenderConsent = {
      ...(req.session.defenderConsent || {}),
      tenantId: sessionTenantId,
      state: null,
      grantedAt: new Date().toISOString()
    };

    req.session.save(() => {
      res.redirect(FRONTEND_URL + '/remediation?consent=granted');
    });
  } catch (err) {
    console.error('[Auth] Admin consent callback error:', err.message);
    res.redirect(FRONTEND_URL + '/remediation?consent=error&message=' + encodeURIComponent(err.message));
  }
});

// GET /api/auth/logout
router.get('/logout', (req, res) => {
  const tenantId = req.session && req.session.tenant ? req.session.tenant.tenantId : null;
  req.session.destroy(function() {
    const logoutUrl = tenantId
      ? 'https://login.microsoftonline.com/' + tenantId + '/oauth2/v2.0/logout?post_logout_redirect_uri=' + encodeURIComponent(FRONTEND_URL + '/login')
      : FRONTEND_URL + '/login';
    res.redirect(logoutUrl);
  });
});

// GET /api/auth/debug — dev only
router.get('/debug', (req, res) => {
  if (process.env.NODE_ENV === 'production') {
    return res.status(404).json({ error: 'Not found.' });
  }
  res.json({
    sessionID:   req.sessionID,
    hasTenant:   !!(req.session && req.session.tenant),
    tenant:      req.session ? req.session.tenant : null,
    redirectUri: REDIRECT_URI,
    adminConsentRedirectUri: ADMIN_CONSENT_REDIRECT_URI,
    clientId:    CLIENT_ID ? CLIENT_ID.substring(0, 8) + '...' : 'MISSING'
  });
});

function decodeJwtClaims(token) {
  if (!token) return {};
  try {
    const parts  = token.split('.');
    if (parts.length < 2) return {};
    const padded  = parts[1].replace(/-/g, '+').replace(/_/g, '/');
    return JSON.parse(Buffer.from(padded, 'base64').toString('utf8'));
  } catch (e) { return {}; }
}

function escMd(str) {
  if (!str) return '';
  return String(str).replace(/[_*[\]()~`>#+=|{}.!\\-]/g, '\\$&');
}

// GET /api/auth/access
router.get('/access', (req, res) => {
  const { getAccessForRequest } = require('../services/accessControl');
  const access = getAccessForRequest(req);
  res.json(access);
});

module.exports = router;
