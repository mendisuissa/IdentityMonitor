// jobRunner.js — background jobs for ALL tenants
// Replaces the TODO comments in index.js

const cron           = require('node-cron');
const tenantRegistry = require('./tenantRegistry');
const anomalyService = require('./anomalyService');
const webhookService = require('./webhookService');
const weeklyDigest   = require('./weeklyDigest');
const wsService      = require('./wsService');

let initialized = false;

function init() {
  if (initialized) return;
  initialized = true;

  // ── Scan all active tenants every 15 minutes ──────────────────────────
  cron.schedule('*/15 * * * *', async () => {
    const tenants = tenantRegistry.getActiveTenants();
    if (tenants.length === 0) return;
    console.log('[Jobs] Running scan for', tenants.length, 'tenants...');

    for (const tenant of tenants) {
      try {
        const newAlerts = await anomalyService.runFullScan(tenant.tenantId);

        tenantRegistry.updateTenantHealth(tenant.tenantId, {
          lastScanAt:         new Date().toISOString(),
          lastSuccessfulScan: new Date().toISOString(),
          lastScanAlertCount: newAlerts.length
        });

        tenantRegistry.updateOnboarding(tenant.tenantId, 'firstScanDone');

        if (newAlerts.length > 0) {
          wsService.broadcastScanComplete(tenant.tenantId, newAlerts.length);
          tenantRegistry.updateTenantStats(tenant.tenantId, {
            lastAlertAt: new Date().toISOString()
          });
        }
      } catch (err) {
        console.error('[Jobs] Scan failed for', tenant.tenantId, ':', err.message);
        tenantRegistry.updateTenantHealth(tenant.tenantId, {
          lastScanAt: new Date().toISOString()
        });
      }
    }
  });

  // ── Renew webhook subscriptions — daily at 3am ────────────────────────
  cron.schedule('0 3 * * *', async () => {
    const tenants = tenantRegistry.getActiveTenants();
    console.log('[Jobs] Renewing webhooks for', tenants.length, 'tenants...');

    for (const tenant of tenants) {
      try {
        const subs = await require('./tableStorage').getWebhookSubscriptions(tenant.tenantId)
          .catch(() => []);

        if (subs.length === 0) {
          // Create webhook if none exists
          const WEBHOOK_URL = process.env.WEBHOOK_NOTIFICATION_URL;
          if (WEBHOOK_URL) {
            const sub = await webhookService.createSignInSubscription(tenant.tenantId);
            if (sub) {
              tenantRegistry.updateTenantHealth(tenant.tenantId, {
                webhookActive:   true,
                webhookId:       sub.id,
                webhookExpiresAt: sub.expirationDateTime
              });
              tenantRegistry.updateOnboarding(tenant.tenantId, 'webhookActive');
            }
          }
        } else {
          await webhookService.renewAllExpiring([tenant.tenantId]);
        }
      } catch (err) {
        console.error('[Jobs] Webhook renewal failed for', tenant.tenantId, ':', err.message);
        tenantRegistry.updateTenantHealth(tenant.tenantId, { webhookActive: false });
      }
    }
  });

  // ── Weekly digest — every Sunday at 8am ──────────────────────────────
  cron.schedule('0 8 * * 0', async () => {
    const tenants = tenantRegistry.getActiveTenants();
    console.log('[Jobs] Sending weekly digests to', tenants.length, 'tenants...');

    for (const tenant of tenants) {
      try {
        await weeklyDigest.generateAndSend(tenant.tenantId);
      } catch (err) {
        console.error('[Jobs] Digest failed for', tenant.tenantId, ':', err.message);
      }
    }
  });

  // ── Health check — every hour ─────────────────────────────────────────
  cron.schedule('0 * * * *', async () => {
    const tenants = tenantRegistry.getActiveTenants();
    for (const tenant of tenants) {
      await checkTenantHealth(tenant.tenantId).catch(() => {});
    }
  });

  console.log('[Jobs] Background job runner initialized');
}

// ─── Health check for a single tenant ────────────────────────────────────
async function checkTenantHealth(tenantId) {
  const settingsService = require('./settingsService');
  const graphService    = require('./graphService');
  const settings        = settingsService.getSettings(tenantId);
  const patch           = {};

  // Check Graph API permissions
  try {
    const users = await graphService.getPrivilegedUsers(tenantId);
    patch.graphPermissionsOk  = true;
    patch.privilegedUserCount = users.length;
    if (users.length > 0) tenantRegistry.updateOnboarding(tenantId, 'permissionsGranted');
  } catch (err) {
    patch.graphPermissionsOk = false;
    console.warn('[Jobs] Graph check failed for', tenantId, ':', err.message);
  }

  // Check sign-in logs access
  try {
    const since = new Date(Date.now() - 3600000).toISOString();
    await graphService.getClientForTenant(tenantId)
      .then(c => c.api('/auditLogs/signIns').filter('createdDateTime ge ' + since).top(1).get());
    patch.signInLogsAvailable = true;
  } catch (err) {
    patch.signInLogsAvailable = false;
  }

  // Check Telegram
  if (settings.notifications?.telegramBotToken && settings.notifications?.telegramChatId) {
    try {
      const res = await fetch('https://api.telegram.org/bot' + settings.notifications.telegramBotToken + '/getMe');
      patch.telegramOk = res.ok;
    } catch { patch.telegramOk = false; }
  }

  tenantRegistry.updateTenantHealth(tenantId, patch);
  return patch;
}

module.exports = { init, checkTenantHealth };
