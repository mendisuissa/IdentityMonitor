// billing.js — Stripe billing routes for IdentityMonitor SaaS
// Mounted at /api/billing

const express = require('express');
const router = express.Router();

const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
const settingsService = require('../services/settingsService');
const auditLog = require('../services/auditLog');

const PLANS = [
  {
    id: 'pro',
    name: 'Pro',
    description: 'Full monitoring for a single tenant',
    price: 29,
    currency: 'USD',
    interval: 'month',
    features: ['Single tenant', 'Real-time alerts', 'Conditional Access analysis', 'Email & Telegram notifications'],
    stripePriceId: process.env.STRIPE_PRICE_PRO
  },
  {
    id: 'msp',
    name: 'MSP',
    description: 'Managed Service Provider fleet — up to 10 tenants',
    price: 99,
    currency: 'USD',
    interval: 'month',
    features: ['Up to 10 tenants', 'MSP fleet dashboard', 'Cross-tenant sweep', 'Priority support', 'All Pro features'],
    stripePriceId: process.env.STRIPE_PRICE_MSP
  }
];

const PLAN_MAP = Object.fromEntries(PLANS.map(p => [p.id, p]));

// ---------------------------------------------------------------------------
// Helper: extract tenantId from session, or send 401 and return null
// ---------------------------------------------------------------------------
function requireAuth(req, res) {
  if (!req.session?.tenant?.tenantId) {
    res.status(401).json({ error: 'Not authenticated' });
    return null;
  }
  return req.session.tenant.tenantId;
}

// ---------------------------------------------------------------------------
// GET /api/billing/plans — public, no auth required
// ---------------------------------------------------------------------------
router.get('/plans', (req, res) => {
  try {
    // Omit the internal stripePriceId from the public response
    const plans = PLANS.map(({ stripePriceId, ...plan }) => plan);
    res.json({ plans });
  } catch (err) {
    console.error('[Billing] /plans error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// ---------------------------------------------------------------------------
// POST /api/billing/checkout — create a Stripe Checkout session
// ---------------------------------------------------------------------------
router.post('/checkout', async (req, res) => {
  const tenantId = requireAuth(req, res);
  if (!tenantId) return;

  try {
    const { plan: planId } = req.body;

    if (!planId || !PLAN_MAP[planId]) {
      return res.status(400).json({ error: `Invalid plan. Valid options: ${Object.keys(PLAN_MAP).join(', ')}` });
    }

    const plan = PLAN_MAP[planId];

    if (!plan.stripePriceId) {
      return res.status(500).json({ error: `Stripe price ID for plan "${planId}" is not configured (set STRIPE_PRICE_${planId.toUpperCase()})` });
    }

    const appUrl = process.env.APP_URL || 'https://localhost:3001';

    const checkoutSession = await stripe.checkout.sessions.create({
      mode: 'subscription',
      line_items: [
        {
          price: plan.stripePriceId,
          quantity: 1
        }
      ],
      success_url: `${appUrl}/billing/success?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${appUrl}/settings`,
      metadata: { tenantId, planId },
      client_reference_id: tenantId,
      subscription_data: {
        metadata: { tenantId, planId }
      }
    });

    auditLog.log(tenantId, 'billing.checkout_started', { planId, sessionId: checkoutSession.id }, req.session.tenant.userEmail || 'system');

    res.json({ url: checkoutSession.url });
  } catch (err) {
    console.error('[Billing] /checkout error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// ---------------------------------------------------------------------------
// POST /api/billing/webhook — Stripe webhook (raw body, no session auth)
// ---------------------------------------------------------------------------
router.post('/webhook', express.raw({ type: 'application/json' }), async (req, res) => {
  const sig = req.headers['stripe-signature'];
  const webhookSecret = process.env.STRIPE_WEBHOOK_SECRET;

  if (!webhookSecret) {
    console.error('[Billing] STRIPE_WEBHOOK_SECRET is not set');
    return res.status(500).json({ error: 'Webhook secret not configured' });
  }

  let event;
  try {
    event = stripe.webhooks.constructEvent(req.body, sig, webhookSecret);
  } catch (err) {
    console.error('[Billing] Webhook signature verification failed:', err.message);
    return res.status(400).json({ error: `Webhook error: ${err.message}` });
  }

  console.log('[Billing] Webhook event received:', event.type);

  try {
    switch (event.type) {

      case 'checkout.session.completed': {
        const session = event.data.object;
        const tenantId = session.metadata?.tenantId || session.client_reference_id;
        if (!tenantId) { console.warn('[Billing] checkout.session.completed — no tenantId in metadata'); break; }

        const subscriptionId = session.subscription;
        const customerId = session.customer;

        // Fetch the subscription to get the price ID
        let stripePriceId = null;
        if (subscriptionId) {
          try {
            const subscription = await stripe.subscriptions.retrieve(subscriptionId);
            stripePriceId = subscription.items?.data?.[0]?.price?.id || null;
          } catch (subErr) {
            console.warn('[Billing] Could not retrieve subscription:', subErr.message);
          }
        }

        await settingsService.saveSettingsAsync(tenantId, {
          billing: {
            plan: 'active',
            stripeCustomerId: customerId,
            stripePriceId,
            stripeSubscriptionId: subscriptionId,
            activatedAt: new Date().toISOString()
          }
        });

        auditLog.log(tenantId, 'billing.activated', { customerId, subscriptionId, stripePriceId }, 'stripe');
        console.log('[Billing] Tenant activated:', tenantId);
        break;
      }

      case 'customer.subscription.deleted': {
        const subscription = event.data.object;
        const tenantId = subscription.metadata?.tenantId;
        if (!tenantId) { console.warn('[Billing] customer.subscription.deleted — no tenantId in metadata'); break; }

        await settingsService.saveSettingsAsync(tenantId, {
          billing: {
            plan: 'cancelled',
            cancelledAt: new Date().toISOString()
          }
        });

        auditLog.log(tenantId, 'billing.cancelled', { subscriptionId: subscription.id }, 'stripe');
        console.log('[Billing] Subscription cancelled for tenant:', tenantId);
        break;
      }

      case 'customer.subscription.updated': {
        const subscription = event.data.object;
        const tenantId = subscription.metadata?.tenantId;
        if (!tenantId) { console.warn('[Billing] customer.subscription.updated — no tenantId in metadata'); break; }

        // Map Stripe subscription status to our plan status
        const statusMap = {
          active: 'active',
          trialing: 'trial',
          past_due: 'past_due',
          unpaid: 'past_due',
          canceled: 'cancelled',
          incomplete: 'incomplete',
          incomplete_expired: 'cancelled',
          paused: 'paused'
        };
        const planStatus = statusMap[subscription.status] || subscription.status;
        const stripePriceId = subscription.items?.data?.[0]?.price?.id || null;

        await settingsService.saveSettingsAsync(tenantId, {
          billing: {
            plan: planStatus,
            stripePriceId,
            stripeSubscriptionId: subscription.id,
            updatedAt: new Date().toISOString()
          }
        });

        auditLog.log(tenantId, 'billing.updated', { status: subscription.status, planStatus, subscriptionId: subscription.id }, 'stripe');
        console.log('[Billing] Subscription updated for tenant:', tenantId, '→', planStatus);
        break;
      }

      default:
        // Unhandled event type — not an error, just ignore
        console.log('[Billing] Unhandled webhook event:', event.type);
    }
  } catch (err) {
    console.error('[Billing] Webhook handler error:', err.message);
    // Return 200 anyway so Stripe doesn't retry — the error is on our side
  }

  res.json({ received: true });
});

// ---------------------------------------------------------------------------
// GET /api/billing/portal — create a Stripe Customer Portal session
// ---------------------------------------------------------------------------
router.get('/portal', async (req, res) => {
  const tenantId = requireAuth(req, res);
  if (!tenantId) return;

  try {
    const settings = await settingsService.getSettingsAsync(tenantId);
    const customerId = settings?.billing?.stripeCustomerId;

    if (!customerId) {
      return res.status(400).json({ error: 'No Stripe customer found for this tenant. Please subscribe first.' });
    }

    const appUrl = process.env.APP_URL || 'https://localhost:3001';

    const portalSession = await stripe.billingPortal.sessions.create({
      customer: customerId,
      return_url: `${appUrl}/settings`
    });

    auditLog.log(tenantId, 'billing.portal_accessed', {}, req.session.tenant.userEmail || 'system');

    res.json({ url: portalSession.url });
  } catch (err) {
    console.error('[Billing] /portal error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// ---------------------------------------------------------------------------
// GET /api/billing/status — return current billing status for the tenant
// ---------------------------------------------------------------------------
router.get('/status', async (req, res) => {
  const tenantId = requireAuth(req, res);
  if (!tenantId) return;

  try {
    const settings = await settingsService.getSettingsAsync(tenantId);
    const billing = settings?.billing || {};

    const trialEndsAt = billing.trialEndsAt || null;
    let daysLeft = null;
    if (trialEndsAt) {
      const msLeft = new Date(trialEndsAt).getTime() - Date.now();
      daysLeft = Math.max(0, Math.ceil(msLeft / (24 * 60 * 60 * 1000)));
    }

    res.json({
      plan: billing.plan || 'trial',
      trialEndsAt,
      daysLeft,
      stripeCustomerId: billing.stripeCustomerId || null,
      stripeSubscriptionId: billing.stripeSubscriptionId || null,
      stripePriceId: billing.stripePriceId || null,
      activatedAt: billing.activatedAt || null,
      cancelledAt: billing.cancelledAt || null
    });
  } catch (err) {
    console.error('[Billing] /status error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
