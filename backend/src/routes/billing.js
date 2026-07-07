// billing.js — Gumroad billing integration
// Mounted at /api/billing

const express        = require('express');
const router         = express.Router();
const settingsService = require('../services/settingsService');
const tenantRegistry  = require('../services/tenantRegistry');
const auditLog        = require('../services/auditLog');

const GUMROAD_PRODUCT_URL    = process.env.GUMROAD_PRODUCT_URL    || 'https://moderne.gumroad.com/l/azxxv';
const GUMROAD_WEBHOOK_SECRET = process.env.GUMROAD_WEBHOOK_SECRET || '';

// ── Helper: require authenticated session ─────────────────────────────────
function requireAuth(req, res) {
  if (!req.session?.tenant?.tenantId) {
    res.status(401).json({ error: 'Not authenticated' });
    return null;
  }
  return req.session.tenant.tenantId;
}

// ── Helper: find a tenant whose admin/login email matches the buyer email ─
async function findTenantByEmail(email) {
  const lower = email.toLowerCase().trim();

  // Pass 1: in-memory registry (tenants currently/recently logged in)
  const activeTenants = tenantRegistry.getActiveTenants();
  for (const t of activeTenants) {
    if (t.primaryEmail?.toLowerCase().trim() === lower) return t.tenantId;
  }

  // Pass 2: settings admin emails (covers all tenants on disk/Azure)
  const tenantIds = tenantRegistry.getAllTenantIds();
  for (const tenantId of tenantIds) {
    try {
      const settings = await settingsService.getSettingsAsync(tenantId);
      const adminEmails = [
        ...(settings?.notifications?.adminEmails || []),
        ...(settings?.admins || []).map(a => a.email)
      ].filter(Boolean);
      if (adminEmails.some(e => e.toLowerCase().trim() === lower)) return tenantId;
    } catch (_) {}
  }

  // Pass 3: full Azure profiles (survived restarts)
  try {
    const allTenants = await tenantRegistry.getAllTenants();
    for (const t of allTenants) {
      if (t.primaryEmail?.toLowerCase().trim() === lower) return t.tenantId;
    }
  } catch (_) {}

  return null;
}

// ---------------------------------------------------------------------------
// GET /api/billing/plans — public, no auth required
// ---------------------------------------------------------------------------
router.get('/plans', (req, res) => {
  res.json({
    plans: [
      {
        id:          'pro',
        name:        'Pro',
        description: 'Full real-time identity monitoring for one Microsoft 365 tenant',
        price:       15,
        currency:    'USD',
        interval:    'month',
        url:         GUMROAD_PRODUCT_URL,
        features: [
          'Single Microsoft 365 tenant',
          'Real-time anomaly detection (60s scan cycle)',
          'Telegram alerts with action buttons',
          'Email notifications',
          'Conditional Access analysis',
          'PIM privilege monitoring',
          'Automated session revoke & remediation',
          '180-day alert retention',
          'Audit Center'
        ]
      }
    ]
  });
});

// ---------------------------------------------------------------------------
// GET /api/billing/checkout — redirect user to Gumroad with email + redirect_url pre-filled
// After purchase Gumroad sends the buyer back to /billing automatically.
// ---------------------------------------------------------------------------
router.get('/checkout', (req, res) => {
  const tenantId = requireAuth(req, res);
  if (!tenantId) return;

  try {
    const email   = req.session?.tenant?.userEmail || '';
    const appUrl  = process.env.APP_URL || 'https://identitymonitor.modernendpoint.tech';

    const params = new URLSearchParams();
    if (email) params.set('email', email);
    params.set('redirect_url', `${appUrl}/billing`);

    const url = `${GUMROAD_PRODUCT_URL}?${params.toString()}`;

    auditLog.log(tenantId, 'billing.checkout_started', { url }, req.session.tenant.userEmail || 'system');
    res.json({ url });
  } catch (err) {
    console.error('[Billing] /checkout error:', err.message);
    res.status(500).json({ error: "Internal server error" });
  }
});

// ---------------------------------------------------------------------------
// POST /api/billing/gumroad-webhook
// Gumroad sends application/x-www-form-urlencoded — NOT JSON.
// Secret is verified via X-Webhook-Secret header (set in Gumroad Ping settings).
// Never pass secrets as URL query parameters — they appear in server logs.
// ---------------------------------------------------------------------------
router.post('/gumroad-webhook', express.urlencoded({ extended: true }), async (req, res) => {
  const providedSecret = req.headers['x-webhook-secret'];
  if (GUMROAD_WEBHOOK_SECRET && providedSecret !== GUMROAD_WEBHOOK_SECRET) {
    console.warn('[Billing] Gumroad webhook: invalid secret from', req.ip);
    return res.status(403).json({ error: 'Invalid secret' });
  }

  const {
    email,
    subscription_id,
    sale_id,
    is_subscription_purchase,
    is_subscription_cancellation,
    is_subscription_restarted,
    refunded
  } = req.body;

  console.log('[Billing] Gumroad ping:', {
    email, subscription_id,
    is_subscription_purchase,
    is_subscription_cancellation,
    is_subscription_restarted,
    refunded
  });

  // Always respond 200 quickly
  res.json({ ok: true });

  if (!email) return;

  try {
    const tenantId = await findTenantByEmail(email);
    if (!tenantId) {
      console.warn(`[Billing] Gumroad webhook: no tenant found for email "${email}"`);
      return;
    }

    const isCancelled  = is_subscription_cancellation === 'true' || refunded === 'true';
    const isActivation = !isCancelled; // new purchase, renewal, restart

    if (isCancelled) {
      await settingsService.saveSettingsAsync(tenantId, {
        billing: {
          plan:                  'cancelled',
          cancelledAt:           new Date().toISOString(),
          gumroadSubscriptionId: subscription_id || null
        }
      });
      auditLog.log(tenantId, 'billing.cancelled', { subscription_id, sale_id }, 'gumroad');
      console.log(`[Billing] Plan cancelled for tenant: ${tenantId}`);
    } else {
      await settingsService.saveSettingsAsync(tenantId, {
        billing: {
          plan:                  'active',
          activatedAt:           new Date().toISOString(),
          gumroadSubscriptionId: subscription_id || null,
          gumroadSaleId:         sale_id         || null
        }
      });
      auditLog.log(tenantId, 'billing.activated', { subscription_id, sale_id }, 'gumroad');
      console.log(`[Billing] Plan activated for tenant: ${tenantId}`);
    }
  } catch (err) {
    console.error('[Billing] Webhook handler error:', err.message);
  }
});

// ---------------------------------------------------------------------------
// GET /api/billing/status — current plan for the authenticated tenant
// ---------------------------------------------------------------------------
router.get('/status', async (req, res) => {
  const tenantId = requireAuth(req, res);
  if (!tenantId) return;

  try {
    const settings = await settingsService.getSettingsAsync(tenantId);
    const billing  = settings?.billing || {};
    const userEmail = (req.session?.tenant?.userEmail || '').toLowerCase();

    // Owner check — use trial status which handles internal domain exemptions
    const trialStatus = settingsService.getTrialStatus(tenantId, userEmail);
    const effectivePlan = trialStatus.status === 'active' ? 'active' : (billing.plan || 'free');

    const trialEndsAt = billing.trialEndsAt || null;
    let daysLeft = null;
    if (trialEndsAt) {
      const msLeft = new Date(trialEndsAt).getTime() - Date.now();
      daysLeft = Math.max(0, Math.ceil(msLeft / (24 * 60 * 60 * 1000)));
    }

    res.json({
      plan:                  effectivePlan,
      trialEndsAt,
      daysLeft,
      activatedAt:           billing.activatedAt           || null,
      cancelledAt:           billing.cancelledAt           || null,
      gumroadSubscriptionId: billing.gumroadSubscriptionId || null,
      gumroadUrl:            GUMROAD_PRODUCT_URL
    });
  } catch (err) {
    console.error('[Billing] /status error:', err.message);
    res.status(500).json({ error: "Internal server error" });
  }
});

module.exports = router;
