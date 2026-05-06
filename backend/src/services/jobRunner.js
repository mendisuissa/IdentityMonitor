// jobRunner.js — background jobs for ALL tenants
// Replaces the TODO comments in index.js

const cron           = require('node-cron');
const tenantRegistry = require('./tenantRegistry');
const anomalyService = require('./anomalyService');
const webhookService = require('./webhookService');
const weeklyDigest   = require('./weeklyDigest');
const wsService      = require('./wsService');

let initialized = false;
let _scanRunning = false; // prevent overlapping scans

async function _runScanCycle() {
  if (_scanRunning) return; // skip if previous cycle still in progress
  _scanRunning = true;
  try {
    const tenantIds = Array.from(new Set([
      ...tenantRegistry.getActiveTenants().map(t => t.tenantId),
      ...tenantRegistry.getAllTenantIds()
    ])).filter(Boolean);

    if (tenantIds.length === 0) return;
    console.log('[Jobs] Running scan for', tenantIds.length, 'tenants...');

    for (const tenantId of tenantIds) {
      try {
        const newAlerts = await anomalyService.runFullScan(tenantId);

        tenantRegistry.updateTenantHealth(tenantId, {
          lastScanAt:         new Date().toISOString(),
          lastSuccessfulScan: new Date().toISOString(),
          lastScanAlertCount: newAlerts.length
        });

        tenantRegistry.updateOnboarding(tenantId, 'firstScanDone');

        if (newAlerts.length > 0) {
          wsService.broadcastScanComplete(tenantId, newAlerts.length);
          tenantRegistry.updateTenantStats(tenantId, {
            lastAlertAt: new Date().toISOString()
          });
        }
      } catch (err) {
        console.error('[Jobs] Scan failed for', tenantId, ':', err.message);
        tenantRegistry.updateTenantHealth(tenantId, {
          lastScanAt: new Date().toISOString()
        });
      }
    }
  } finally {
    _scanRunning = false;
  }
}

function init() {
  if (initialized) return;
  initialized = true;

  // ── Scan all known tenants every 60 seconds ───────────────────────────
  // setInterval instead of cron so we can go sub-minute.
  // _scanRunning flag prevents overlap if a scan takes > 60s.
  // Real-time first alerts come from Graph webhooks (webhook.js);
  // this loop is a reliable fallback that catches anything missed.
  setInterval(_runScanCycle, 60 * 1000);
  // Also run immediately on startup (after a short delay so sessions load)
  setTimeout(_runScanCycle, 15 * 1000);

  // ── Renew webhook subscriptions — daily at 3am ────────────────────────
  cron.schedule('0 3 * * *', async () => {
    const tenantIds = Array.from(new Set([
      ...tenantRegistry.getActiveTenants().map(t => t.tenantId),
      ...tenantRegistry.getAllTenantIds()
    ])).filter(Boolean);
    console.log('[Jobs] Renewing webhooks for', tenantIds.length, 'tenants...');

    for (const tenantId of tenantIds) {
      try {
        const subs = await require('./tableStorage').getWebhookSubscriptions(tenantId)
          .catch(() => []);

        if (subs.length === 0) {
          const WEBHOOK_URL = process.env.WEBHOOK_NOTIFICATION_URL;
          if (WEBHOOK_URL) {
            const sub = await webhookService.createSignInSubscription(tenantId);
            if (sub) {
              tenantRegistry.updateTenantHealth(tenantId, {
                webhookActive:    true,
                webhookId:        sub.id,
                webhookExpiresAt: sub.expirationDateTime
              });
              tenantRegistry.updateOnboarding(tenantId, 'webhookActive');
            }
          }
        } else {
          await webhookService.renewAllExpiring([tenantId]);
        }
      } catch (err) {
        console.error('[Jobs] Webhook renewal failed for', tenantId, ':', err.message);
        tenantRegistry.updateTenantHealth(tenantId, { webhookActive: false });
      }
    }
  });

  // ── Weekly digest — every Sunday at 8am ──────────────────────────────
  cron.schedule('0 8 * * 0', async () => {
    const tenantIds = Array.from(new Set([
      ...tenantRegistry.getActiveTenants().map(t => t.tenantId),
      ...tenantRegistry.getAllTenantIds()
    ])).filter(Boolean);
    console.log('[Jobs] Sending weekly digests to', tenantIds.length, 'tenants...');

    for (const tenantId of tenantIds) {
      try {
        await weeklyDigest.generateAndSend(tenantId);
      } catch (err) {
        console.error('[Jobs] Digest failed for', tenantId, ':', err.message);
      }
    }
  });

  // ── Retention enforcement — daily at 2am ─────────────────────────────
  cron.schedule('0 2 * * *', async () => {
    const settingsService = require('./settingsService');
    const tableStorage    = require('./tableStorage');
    const tenantIds = Array.from(new Set([
      ...tenantRegistry.getActiveTenants().map(t => t.tenantId),
      ...tenantRegistry.getAllTenantIds()
    ])).filter(Boolean);

    for (const tenantId of tenantIds) {
      try {
        const rp = settingsService.getSettings(tenantId).retentionPolicy || {};
        if (rp.incidentDays) {
          const cutoff = new Date(Date.now() - rp.incidentDays * 86400000).toISOString();
          const n = await tableStorage.purgeOldAlerts(tenantId, cutoff);
          if (n > 0) console.log('[Retention] Purged', n, 'old alerts for tenant', tenantId);
        }
      } catch (err) {
        console.error('[Retention] Failed for', tenantId, ':', err.message);
      }
    }
  });

  // ── Health check — every hour ─────────────────────────────────────────
  cron.schedule('0 * * * *', async () => {
    const tenantIds = Array.from(new Set([
      ...tenantRegistry.getActiveTenants().map(t => t.tenantId),
      ...tenantRegistry.getAllTenantIds()
    ])).filter(Boolean);
    for (const tenantId of tenantIds) {
      await checkTenantHealth(tenantId).catch(() => {});
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
