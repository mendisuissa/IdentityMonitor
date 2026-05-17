const express = require('express');
const crypto = require('crypto');
const router  = express.Router();

const CLIENT_ID     = process.env.CLIENT_ID;
const CLIENT_SECRET = process.env.CLIENT_SECRET;
const WEBAPP_CLIENT_ID = process.env.WEBAPP_CLIENT_ID || '';
const { upsertTenantIntegration, getTenantIntegration, markWebappConsent } = require('../services/tenantIntegrationStore');
const { clearGraphTokenCache } = require('../services/nativeRemediationExecutor');
const graphService = require('../services/graphService');
const tenantRegistry = require('../services/tenantRegistry');
const REDIRECT_URI  = process.env.REDIRECT_URI  || 'http://localhost:3001/api/auth/callback';
const FRONTEND_URL  = process.env.FRONTEND_URL  || 'http://localhost:5173';
const ADMIN_CONSENT_REDIRECT_URI = process.env.ADMIN_CONSENT_REDIRECT_URI || REDIRECT_URI;

const REQUIRED_SCOPES = [
  'https://graph.microsoft.com/AuditLog.Read.All',
  'https://graph.microsoft.com/Directory.Read.All',
  'https://graph.microsoft.com/User.Read.All',
  'https://graph.microsoft.com/RoleManagement.Read.Directory',
  'https://graph.microsoft.com/Mail.Send',
  'https://graph.microsoft.com/Policy.Read.All',
  'https://graph.microsoft.com/Policy.Read.ConditionalAccess',
  'https://graph.microsoft.com/Policy.ReadWrite.ConditionalAccess'
].join(' ');

function encodeConsentState(payload) {
  return Buffer.from(JSON.stringify(payload), 'utf8').toString('base64url');
}

function decodeConsentState(value) {
  if (!value) return null;
  try {
    return JSON.parse(Buffer.from(String(value), 'base64url').toString('utf8'));
  } catch (_err) {
    return null;
  }
}

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

// GET /api/auth/mock-login  — dev/screenshot only, requires MOCK_MODE=true
router.get('/mock-login', (req, res) => {
  if (process.env.MOCK_MODE !== 'true') {
    return res.status(403).json({ error: 'Only available in MOCK_MODE' });
  }
  req.session.tenant = {
    tenantId:   'demo-tenant-id',
    tenantName: 'Demo Organisation',
    userEmail:  'admin@demo.onmicrosoft.com',
    userName:   'Demo Admin',
  };
  req.session.tokens = { accessToken: 'mock-token', expiresAt: Date.now() + 86400000 };
  tenantRegistry.registerTenant(req.session.tenant);
  const FRONTEND_URL = process.env.FRONTEND_URL || 'http://localhost:5173';
  res.redirect(FRONTEND_URL + '/');
});

// GET /api/auth/login
// Flow: admin consent first (grants all app permissions) → then OAuth login
// Microsoft skips the consent UI on repeat visits when permissions are unchanged.
router.get('/login', (req, res) => {
  if (!CLIENT_ID) return res.status(500).json({ error: 'CLIENT_ID not configured' });

  const nonce = crypto.randomBytes(16).toString('hex');
  const statePayload = {
    nonce,
    step: 'consent_then_login',
    createdAt: new Date().toISOString()
  };
  const encodedState = encodeConsentState(statePayload);

  req.session.loginConsent = { nonce, startedAt: new Date().toISOString() };

  req.session.save((err) => {
    if (err) return res.status(500).json({ error: 'Session error' });
    const params = new URLSearchParams({
      client_id:    CLIENT_ID,
      redirect_uri: ADMIN_CONSENT_REDIRECT_URI,
      state:        encodedState
    });
    res.redirect('https://login.microsoftonline.com/common/adminconsent?' + params.toString());
  });
});

// GET /api/auth/callback
router.get('/callback', async (req, res) => {
  const { code, error, error_description, admin_consent, tenant, state } = req.query;

  // Handle admin consent that landed here because ADMIN_CONSENT_REDIRECT_URI = REDIRECT_URI
  if (!code && String(admin_consent).toLowerCase() === 'true' && tenant) {
    const statePayload = decodeConsentState(String(state || ''));
    const effectiveTenantId = String(tenant).trim();
    graphService.clearTokenCache(effectiveTenantId);
    clearGraphTokenCache(effectiveTenantId);
    const returnTo = statePayload?.returnTo || '/';
    const oauthState = statePayload?.step === 'consent_then_login'
      ? 'login'
      : 'post_consent__' + encodeURIComponent(returnTo);
    const loginParams = new URLSearchParams({
      client_id:     CLIENT_ID,
      response_type: 'code',
      redirect_uri:  REDIRECT_URI,
      scope:         'openid profile email offline_access ' + REQUIRED_SCOPES,
      response_mode: 'query',
      state:         oauthState
    });
    return res.redirect(
      'https://login.microsoftonline.com/' + effectiveTenantId +
      '/oauth2/v2.0/authorize?' + loginParams.toString()
    );
  }

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

    // Register tenant in the in-memory registry so health/posture/MSP routes work
    tenantRegistry.registerTenant(req.session.tenant);

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

    // Determine if this is a genuinely new tenant BEFORE upserting
    let isNewTenant = true;
    let existingIntegration = null;
    try {
      existingIntegration = await getTenantIntegration(tenantId).catch(() => null);
      if (existingIntegration) isNewTenant = false;
    } catch (_) {
      // Azure Storage not configured — fall back to filesystem check
      isNewTenant = !tenantRegistry.getAllTenantIds().includes(tenantId);
    }

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

    if (isNewTenant) {
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
    }

    req.session.save(function(err) {
      if (err) {
        console.error('[Auth] Session save error:', err.message);
        return res.redirect(FRONTEND_URL + '/login?error=session_save_failed');
      }
      const stateStr = String(req.query.state || '');
      if (stateStr.startsWith('post_consent__')) {
        const returnTo = decodeURIComponent(stateStr.replace('post_consent__', ''));
        return res.redirect(FRONTEND_URL + returnTo + '?consent=granted');
      }

      // If webapp consent not yet granted, redirect silently as part of onboarding
      if (WEBAPP_CLIENT_ID && !existingIntegration?.webappConsentGrantedAt) {
        const base = process.env.API_BASE_URL || (req.protocol + '://' + req.get('host'));
        const webappConsentCallbackUri = base + '/api/auth/webapp-consent/callback';
        const consentUrl = 'https://login.microsoftonline.com/' + tenantId +
          '/adminconsent?client_id=' + WEBAPP_CLIENT_ID +
          '&redirect_uri=' + encodeURIComponent(webappConsentCallbackUri) +
          '&state=' + encodeURIComponent(JSON.stringify({ isNewTenant }));
        return res.redirect(consentUrl);
      }

      // Append ?first_login=1 for brand-new tenants so the frontend shows the welcome screen
      const suffix = isNewTenant ? '?first_login=1' : '';
      res.redirect(FRONTEND_URL + suffix);
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

  // Allow callers to pass ?returnTo=/identity so we redirect back after consent
  const ALLOWED_RETURN_PATHS = ['/remediation', '/identity', '/settings', '/'];
  const rawReturnTo = String(req.query.returnTo || '/remediation');
  const returnTo = ALLOWED_RETURN_PATHS.includes(rawReturnTo) ? rawReturnTo : '/remediation';

  const nonce = crypto.randomBytes(16).toString('hex');
  const statePayload = {
    nonce,
    tenantId,
    returnTo,
    createdAt: new Date().toISOString()
  };
  const encodedState = encodeConsentState(statePayload);

  req.session.defenderConsent = {
    ...(req.session.defenderConsent || {}),
    tenantId,
    nonce,
    encodedState,
    startedAt: new Date().toISOString()
  };

  req.session.save((err) => {
    if (err) {
      return res.status(500).json({ ok: false, error: 'Failed to persist consent session state.' });
    }
    res.redirect(buildAdminConsentUrl(tenantId, encodedState));
  });
});

router.get('/admin-consent/callback', async (req, res) => {
  const { tenant, tenant_id, admin_consent, state, error, error_description } = req.query;
  const statePayload = decodeConsentState(state);
  const returnedTenantId = String(tenant || tenant_id || '').trim() || null;
  const sessionTenantId = req.session?.tenant?.tenantId || req.session?.defenderConsent?.tenantId || null;
  const expectedTenantId = statePayload?.tenantId || sessionTenantId || null;
  const expectedNonce = req.session?.defenderConsent?.nonce || null;
  const returnedNonce = statePayload?.nonce || null;

  if (error) {
    return res.redirect(FRONTEND_URL + '/remediation?consent=error&message=' + encodeURIComponent(String(error_description || error)));
  }

  if (expectedNonce && returnedNonce && expectedNonce !== returnedNonce) {
    return res.redirect(FRONTEND_URL + '/remediation?consent=error&message=' + encodeURIComponent('Consent state verification failed.'));
  }

  if (String(admin_consent).toLowerCase() !== 'true') {
    return res.redirect(FRONTEND_URL + '/remediation?consent=error&message=' + encodeURIComponent('Admin consent was not granted.'));
  }

  const effectiveTenantId = returnedTenantId || expectedTenantId;
  if (!effectiveTenantId) {
    return res.redirect(FRONTEND_URL + '/remediation?consent=error&message=' + encodeURIComponent('Admin consent completed but no tenant could be resolved.'));
  }

  if (expectedTenantId && returnedTenantId && String(expectedTenantId).toLowerCase() !== String(returnedTenantId).toLowerCase()) {
    console.warn('[Auth] Admin consent tenant mismatch, accepting returned tenant as canonical for this public app flow.', {
      expectedTenantId,
      returnedTenantId,
      sessionTenantId
    });
  }

  try {
    const tenantName = req.session?.tenant?.tenantName || effectiveTenantId;

    await upsertTenantIntegration({
      tenantId: effectiveTenantId,
      tenantName,
      defenderTenantId: effectiveTenantId,
      defenderEnabled: true,
      status: 'configured',
      lastValidatedAt: new Date().toISOString(),
      consentGrantedAt: new Date().toISOString()
    });

    req.session.tenant = {
      ...(req.session.tenant || {}),
      tenantId: effectiveTenantId,
      tenantName
    };

    req.session.defenderConsent = {
      ...(req.session.defenderConsent || {}),
      tenantId: effectiveTenantId,
      nonce: null,
      encodedState: null,
      state: null,
      grantedAt: new Date().toISOString()
    };

    // Clear ALL Graph token caches so next request gets a fresh token
    clearGraphTokenCache(effectiveTenantId);
    graphService.clearTokenCache(effectiveTenantId);

    // Always redirect to OAuth login to issue a fresh token with all consented scopes.
    // For the initial consent_then_login flow, state='login' → redirects to home.
    // For re-grant flows, state carries the returnTo path so we land back on the right page.
    const returnTo = statePayload?.returnTo || '/identity';
    const oauthState = statePayload?.step === 'consent_then_login'
      ? 'login'
      : 'post_consent__' + encodeURIComponent(returnTo);
    const loginParams = new URLSearchParams({
      client_id:     CLIENT_ID,
      response_type: 'code',
      redirect_uri:  REDIRECT_URI,
      scope:         'openid profile email offline_access ' + REQUIRED_SCOPES,
      response_mode: 'query',
      state:         oauthState
    });
    return req.session.save(() => {
      res.redirect(
        'https://login.microsoftonline.com/' + effectiveTenantId +
        '/oauth2/v2.0/authorize?' + loginParams.toString()
      );
    });
  } catch (err) {
    console.error('[Auth] Admin consent callback error:', err.message);
    const returnTo = statePayload?.returnTo || '/identity';
    res.redirect(FRONTEND_URL + returnTo + '?consent=error&message=' + encodeURIComponent(err.message));
  }
});

// GET /api/auth/webapp-consent-redirect — initiates webapp consent from within the app (wizard)
router.get('/webapp-consent-redirect', (req, res) => {
  const tenantId = req.session?.tenant?.tenantId;
  if (!WEBAPP_CLIENT_ID) return res.redirect(FRONTEND_URL + '?webapp_consent=error&reason=not_configured');
  if (!tenantId)        return res.redirect(FRONTEND_URL + '/login?error=not_authenticated');

  const base = process.env.API_BASE_URL || (req.protocol + '://' + req.get('host'));
  const webappConsentCallbackUri = base + '/api/auth/webapp-consent/callback';
  const consentUrl = 'https://login.microsoftonline.com/' + tenantId +
    '/adminconsent?client_id=' + WEBAPP_CLIENT_ID +
    '&redirect_uri=' + encodeURIComponent(webappConsentCallbackUri);
  return res.redirect(consentUrl);
});

// GET /api/auth/webapp-consent/callback
// Microsoft redirects here after the customer grants Intune consent to the webapp.
// We record the grant and send them to the dashboard — fully transparent.
router.get('/webapp-consent/callback', async (req, res) => {
  const { admin_consent, tenant, error, error_description } = req.query;

  if (error) {
    console.warn('[Auth] Webapp consent declined:', error_description || error);
    return res.redirect(FRONTEND_URL + '?webapp_consent=declined');
  }

  const tenantId = String(tenant || req.session?.tenant?.tenantId || '').trim();
  let isNewTenant = false;
  try {
    const stateData = req.query.state ? JSON.parse(decodeURIComponent(String(req.query.state))) : {};
    isNewTenant = !!stateData.isNewTenant;
  } catch (_) {}

  if (String(admin_consent).toLowerCase() === 'true' && tenantId) {
    try {
      await markWebappConsent(tenantId);
      console.log('[Auth] Webapp consent granted for tenant:', tenantId);
    } catch (err) {
      console.warn('[Auth] markWebappConsent failed (non-fatal):', err.message);
    }
    const suffix = isNewTenant ? '?first_login=1&webapp_connected=1' : '?webapp_connected=1';
    return res.redirect(FRONTEND_URL + suffix);
  }

  res.redirect(FRONTEND_URL);
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

// GET /api/auth/onboarding-status — returns what's been set up for this tenant
router.get('/onboarding-status', async (req, res) => {
  const tenantId = req.session?.tenant?.tenantId;
  if (!tenantId) return res.status(401).json({ ok: false, error: 'Not authenticated' });

  let webappConsent = false;
  try {
    const integration = await getTenantIntegration(tenantId).catch(() => null);
    webappConsent = !!integration?.webappConsentGrantedAt;
  } catch (_) {}

  const settings = (() => {
    try { return require('../services/settingsService').getSettings(tenantId); } catch (_) { return {}; }
  })();

  return res.json({
    ok:               true,
    tenantId,
    defenderConsent:  true, // granted during login flow
    webappConsent,
    webappClientId:   !!WEBAPP_CLIENT_ID,
    telegramEnabled:  !!(settings?.telegramBotToken || process.env.TELEGRAM_BOT_TOKEN),
    adminEmailSet:    !!(settings?.alertAdminEmail || process.env.ALERT_ADMIN_EMAIL),
    autoRemediation:  process.env.AUTO_REMEDIATION_ENABLED === 'true',
  });
});

// GET /api/auth/access
router.get('/access', (req, res) => {
  const { getAccessForRequest } = require('../services/accessControl');
  const access = getAccessForRequest(req);
  res.json(access);
});

module.exports = router;
