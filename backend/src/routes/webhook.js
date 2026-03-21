// webhook.js — receives Microsoft Graph change notifications
// Microsoft POSTs here when a new sign-in occurs for subscribed tenants

const express = require('express');
const router  = express.Router();
const anomalyService = require('../services/anomalyService');
const telegramService = require('../services/telegramService');
const wsService       = require('../services/wsService');
const tableStorage    = require('../services/tableStorage');
const graphService    = require('../services/graphService');

const CLIENT_STATE = process.env.WEBHOOK_CLIENT_STATE || 'priv-monitor-secret';

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

// ─── POST /api/webhook/telegram — Telegram bot callback ──────────────────
router.post('/telegram', async (req, res) => {
  res.status(200).send('OK');
  const { callback_query } = req.body || {};
  if (callback_query) {
    await telegramService.handleCallbackQuery(callback_query);
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

    console.log('[Webhook] 🎯 Privileged user sign-in:', signIn.userPrincipalName);

    // Get user's baseline
    const baseline = await tableStorage.getBaseline(tenantId, signIn.userId);

    // Run anomaly detection on this single sign-in
    const { detectAnomaliesOnSignIn, buildAlert } = require('../services/anomalyService');
    const anomalies = detectAnomaliesOnSignIn(signIn, baseline);

    if (anomalies.length === 0) {
      // Normal sign-in — update baseline
      updateBaselineFromSignIn(baseline, signIn);
      await tableStorage.saveBaseline(tenantId, signIn.userId, baseline);
      return;
    }

    // Anomalies detected!
    for (const anomaly of anomalies) {
      const alert = buildAlert(tenantId, signIn, anomaly, privilegedUsers.get(signIn.userId));

      // Save to Table Storage
      await tableStorage.saveAlert(alert);

      // Push to dashboard live
      wsService.broadcastNewAlert(alert);

      // Send email
      try {
        const emailService = require('../services/emailService');
        await emailService.sendAdminAlert(alert);
      } catch (err) {
        console.error('[Webhook] Email failed:', err.message);
      }

      // Telegram playbook for medium+ severity
      if (['critical', 'high', 'medium'].includes(alert.severity)) {
        try {
          await telegramService.sendAlertWithPlaybook(alert);
        } catch (err) {
          console.error('[Webhook] Telegram failed:', err.message);
        }
      }

      // Auto-actions for critical
      if (alert.severity === 'critical') {
        try {
          await graphService.revokeUserSessions(tenantId, signIn.userId);
          alert.actionsTriggered.push({ action: 'sessions_revoked', timestamp: new Date().toISOString() });
          console.log('[Webhook] 🔒 Auto-revoked sessions for', signIn.userPrincipalName);
        } catch (err) {
          console.error('[Webhook] Auto-revoke failed:', err.message);
        }
      }

      // Update baseline after alert
      updateBaselineFromSignIn(baseline, signIn);
      await tableStorage.saveBaseline(tenantId, signIn.userId, baseline);
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

function updateBaselineFromSignIn(baseline, signIn) {
  if (signIn.ipAddress) {
    if (!baseline.knownIPs.includes(signIn.ipAddress)) baseline.knownIPs.push(signIn.ipAddress);
  }
  if (signIn.location?.countryOrRegion) {
    if (!baseline.knownCountries.includes(signIn.location.countryOrRegion)) baseline.knownCountries.push(signIn.location.countryOrRegion);
  }
  if (signIn.deviceDetail?.deviceId) {
    if (!baseline.knownDevices.includes(signIn.deviceDetail.deviceId)) baseline.knownDevices.push(signIn.deviceDetail.deviceId);
  }
  baseline.recentSignIns.push({
    time: signIn.createdDateTime,
    lat:  signIn.location?.geoCoordinates?.latitude,
    lon:  signIn.location?.geoCoordinates?.longitude,
    ip:   signIn.ipAddress
  });
}

module.exports = router;
