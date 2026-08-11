// webhook.js — receives Microsoft Graph change notifications
// Microsoft POSTs here when a new sign-in occurs for subscribed tenants

const express = require('express');
const router  = express.Router();
const anomalyService = require('../services/anomalyService');
const telegramService = require('../services/telegramService');
const wsService       = require('../services/wsService');
const graphService    = require('../services/graphService');

const CLIENT_STATE = (() => {
  if (!process.env.WEBHOOK_CLIENT_STATE) {
    if (process.env.NODE_ENV === 'production') {
      console.error('[FATAL] WEBHOOK_CLIENT_STATE env var is not set. Refusing to start in production.');
      process.exit(1);
    }
    return 'priv-monitor-dev-webhook-DO-NOT-USE-IN-PROD';
  }
  return process.env.WEBHOOK_CLIENT_STATE;
})();

// ─── GET /api/webhook/notify — validation (Microsoft calls this on subscription create) ──
router.get('/notify', (req, res) => {
  const token = req.query.validationToken;
  if (token) {
    console.log('[Webhook] Validation request received');
    res.setHeader('Content-Type', 'text/plain');
    return res.send(token);
  }
  res.status(400).send('Missing validationToken');
});

// ─── POST /api/webhook/notify — real-time sign-in notification ────────────
router.post('/notify', async (req, res) => {
  // Must respond within 3 seconds or Microsoft will retry/disable
  res.status(202).send('Accepted');

  const { value: notifications } = req.body || {};
  if (!notifications || !Array.isArray(notifications)) return;

  for (const notification of notifications) {
    // Verify client state to prevent spoofing
    if (notification.clientState !== CLIENT_STATE) {
      console.warn('[Webhook] Invalid clientState — ignoring notification');
      continue;
    }

    const tenantId       = notification.tenantId;
    const subscriptionId = notification.subscriptionId;
    const resourceId     = notification.resourceData ? notification.resourceData.id : null;

    console.log('[Webhook] 🔔 Notification received — tenant:', tenantId, 'resource:', resourceId);

    // Process async — don't block the 202 response
    processNotification(tenantId, resourceId, subscriptionId).catch(err => {
      console.error('[Webhook] processNotification error:', err.message);
    });
  }
});

// ─── POST /api/webhook/telegram — Telegram bot callback + text messages ──
router.post('/telegram', async (req, res) => {
  res.status(200).send('OK');
  const update = req.body || {};

  // Button presses (inline keyboard callbacks)
  if (update.callback_query) {
    await telegramService.handleCallbackQuery(update.callback_query);
    return;
  }

  // Text messages from the admin
  const msg = update.message || update.edited_message;
  if (msg && msg.text) {
    await telegramService.handleTextMessage(msg).catch(err =>
      console.error('[Webhook/Telegram] handleTextMessage error:', err.message)
    );
  }
});

// ─── Process a single notification ────────────────────────────────────────
async function processNotification(tenantId, signInId, subscriptionId) {
  if (!tenantId) return;

  try {
    // Fetch the actual sign-in record from Graph
    let signIn = null;
    if (signInId) {
      try {
        const client = await graphService.getClientForTenant(tenantId);
        const result = await client
          .api('/auditLogs/signIns/' + signInId)
          .select('id,createdDateTime,userDisplayName,userPrincipalName,userId,ipAddress,location,deviceDetail,status,riskLevelAggregated,appDisplayName,conditionalAccessStatus')
          .get();
        signIn = result;
      } catch (err) {
        console.warn('[Webhook] Could not fetch signIn', signInId, ':', err.message);
      }
    }

    if (!signIn) {
      // Fallback: just run a quick scan for recent sign-ins
      console.log('[Webhook] No signIn details — running quick scan for tenant', tenantId);
      const newAlerts = await anomalyService.runFullScan(tenantId);
      if (newAlerts.length > 0) {
        wsService.broadcastScanComplete(tenantId, newAlerts.length);
      }
      return;
    }

    // Check if this is a privileged user
    const privilegedUsers = await getPrivilegedUserIds(tenantId);
    if (!privilegedUsers.has(signIn.userId)) {
      // Not a privileged user — ignore
      return;
    }

    console.log('[Webhook] Privileged user sign-in detected (userId:', signIn.userId, ')');

    // Run anomaly detection on this single sign-in via the same pipeline the
    // periodic scan uses (anomalyService.scanUser → behavioralEngine.scoreSignIn).
    //
    // This used to call detectAnomaliesOnSignIn()/buildAlert() — neither
    // function exists anywhere in this codebase (confirmed 2026-08-11), so
    // every real-time privileged-user sign-in notification threw a silent
    // TypeError here, caught by the outer try/catch below, and did nothing.
    // Real-time detection has been dead code since whenever those functions
    // were refactored away; only the 60s-interval periodic scan (jobRunner.js)
    // was actually catching anomalies.
    //
    // This block also used to unconditionally revoke sessions on any single
    // 'critical'-scored sign-in with zero human involvement and zero
    // corroboration — more dangerous than the (now-fixed) 15-minute
    // Telegram-approval auto-revoke below, which at least gives a human a
    // window to intervene. Removed in favor of routing through
    // sendAlertWithPlaybook, whose auto-revoke now requires 2+ corroborating
    // risk factors (see telegramService.js) before acting autonomously.
    const settingsService = require('../services/settingsService');
    const settings = await settingsService.getSettingsAsync(tenantId).catch(() => ({ whitelist: {} }));
    const user = privilegedUsers.get(signIn.userId);

    // scanUser() itself has no whitelist check — runFullScan() (the periodic
    // path) filters whitelisted users before calling it, so this path needs
    // the same guard or a whitelisted user's real-time sign-in would bypass
    // whitelisting entirely.
    if (settings.whitelist?.users?.includes(user?.userPrincipalName)) return;

    const newAlerts = await anomalyService.scanUser(tenantId, user, [signIn], settings);

    for (const alert of newAlerts) {
      // Push to dashboard live
      wsService.broadcastNewAlert(alert);

      // Send email
      try {
        const emailService = require('../services/emailService');
        await emailService.sendAdminAlert(alert);
      } catch (err) {
        console.error('[Webhook] Email failed:', err.message);
      }

      // Telegram playbook for medium+ severity — use tenant-configured credentials only
      if (['critical', 'high', 'medium'].includes(alert.severity)) {
        try {
          const telegramToken  = settings?.notifications?.telegramBotToken;
          const telegramChatId = settings?.notifications?.telegramChatId;
          if (telegramToken && telegramChatId) {
            await telegramService.sendAlertWithPlaybook(alert, telegramToken, telegramChatId);
          }
        } catch (err) {
          console.error('[Webhook] Telegram failed:', err.message);
        }
      }
    }

  } catch (err) {
    console.error('[Webhook] processNotification error:', err.message);
  }
}

// Cache privileged user IDs per tenant (TTL: 5 min)
const _privCache = new Map();
async function getPrivilegedUserIds(tenantId) {
  const cached = _privCache.get(tenantId);
  if (cached && cached.expiresAt > Date.now()) return cached.users;

  const users = await graphService.getPrivilegedUsers(tenantId);
  const userMap = new Map(users.map(u => [u.id, u]));
  _privCache.set(tenantId, { users: userMap, expiresAt: Date.now() + 5 * 60 * 1000 });
  return userMap;
}

module.exports = router;
