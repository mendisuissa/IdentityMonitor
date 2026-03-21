// webhookService.js — Graph API Change Notifications (Webhooks)
// Microsoft pushes sign-in events to us in near real-time
// Much faster than polling every 15 min

const tableStorage = require('./tableStorage');

const NOTIFICATION_URL = process.env.WEBHOOK_NOTIFICATION_URL;
// e.g. https://identitymonitor.modernendpoint.tech/api/webhook/notify

// ─── Create subscription for sign-in logs ────────────────────────────────
async function createSignInSubscription(tenantId) {
  if (!NOTIFICATION_URL) {
    console.warn('[Webhook] WEBHOOK_NOTIFICATION_URL not set — skipping webhook setup');
    return null;
  }

  const { getClientForTenant } = require('./graphService');
  const client = await getClientForTenant(tenantId);

  // Expiry: max 3 days for auditLogs, we renew daily
  const expiresAt = new Date(Date.now() + 2 * 24 * 60 * 60 * 1000).toISOString();

  try {
    const sub = await client.api('/subscriptions').post({
      changeType:            'created',
      notificationUrl:       NOTIFICATION_URL,
      resource:              'auditLogs/signIns',
      expirationDateTime:    expiresAt,
      clientState:           process.env.WEBHOOK_CLIENT_STATE || 'priv-monitor-secret',
      includeResourceData:   false  // We'll fetch the full sign-in on notification
    });

    await tableStorage.saveWebhookSubscription(tenantId, sub);
    console.log('[Webhook] ✅ Subscription created for tenant', tenantId, '— ID:', sub.id);
    return sub;
  } catch (err) {
    console.error('[Webhook] ❌ Failed to create subscription for', tenantId, ':', err.message);
    return null;
  }
}

// ─── Renew subscription before it expires ────────────────────────────────
async function renewSubscription(tenantId, subscriptionId) {
  const { getClientForTenant } = require('./graphService');
  const client = await getClientForTenant(tenantId);

  const newExpiry = new Date(Date.now() + 2 * 24 * 60 * 60 * 1000).toISOString();

  try {
    await client.api('/subscriptions/' + subscriptionId).patch({
      expirationDateTime: newExpiry
    });
    console.log('[Webhook] ✅ Renewed subscription', subscriptionId);
    return true;
  } catch (err) {
    console.error('[Webhook] ❌ Renewal failed:', err.message);
    return false;
  }
}

// ─── Delete subscription ──────────────────────────────────────────────────
async function deleteSubscription(tenantId, subscriptionId) {
  const { getClientForTenant } = require('./graphService');
  try {
    const client = await getClientForTenant(tenantId);
    await client.api('/subscriptions/' + subscriptionId).delete();
    await tableStorage.deleteWebhookSubscription(tenantId, subscriptionId);
    console.log('[Webhook] Deleted subscription', subscriptionId);
  } catch (err) {
    console.error('[Webhook] Delete error:', err.message);
  }
}

// ─── Renew all expiring subscriptions (run daily via cron) ───────────────
async function renewAllExpiring(tenantIds) {
  for (const tenantId of tenantIds) {
    const subs = await tableStorage.getWebhookSubscriptions(tenantId);
    for (const sub of subs) {
      const expiresAt = new Date(sub.expiresAt);
      const hoursUntilExpiry = (expiresAt - Date.now()) / (1000 * 60 * 60);

      if (hoursUntilExpiry < 12) {
        console.log('[Webhook] Renewing subscription', sub.subscriptionId, 'for tenant', tenantId);
        const ok = await renewSubscription(tenantId, sub.subscriptionId);
        if (!ok) {
          // Renewal failed — recreate
          await deleteSubscription(tenantId, sub.subscriptionId);
          await createSignInSubscription(tenantId);
        }
      }
    }
  }
}

module.exports = {
  createSignInSubscription,
  renewSubscription,
  deleteSubscription,
  renewAllExpiring
};
