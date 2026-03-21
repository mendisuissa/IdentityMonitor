// siemService.js — SIEM integration: Azure Log Analytics + outbound webhooks
// Sends every alert to configured SIEM endpoints

const SIEM_TYPES = { LOG_ANALYTICS: 'log_analytics', WEBHOOK: 'webhook' };

// ─── Azure Log Analytics (Custom Logs API) ────────────────────────────────
async function sendToLogAnalytics(alert, workspaceId, sharedKey) {
  if (!workspaceId || !sharedKey) return;

  const body = JSON.stringify([{
    TimeGenerated:      alert.detectedAt,
    TenantId_s:         alert.tenantId,
    UserId_s:           alert.userId,
    UserDisplayName_s:  alert.userDisplayName,
    UserUPN_s:          alert.userPrincipalName,
    Roles_s:            (alert.roles || []).join(', '),
    AnomalyType_s:      alert.anomalyType,
    AnomalyLabel_s:     alert.anomalyLabel,
    Severity_s:         alert.severity,
    RiskScore_d:        alert.riskScore || 0,
    Detail_s:           alert.detail,
    IPAddress_s:        alert.ipAddress || '',
    Country_s:          alert.country  || '',
    City_s:             alert.city     || '',
    DeviceName_s:       alert.deviceName || '',
    DeviceOS_s:         alert.deviceOs   || '',
    AppName_s:          alert.appName    || '',
    AppTier_s:          alert.appTier    || '',
    SignInTime_t:        alert.signInTime,
    AlertStatus_s:       alert.status,
    ActionsTriggered_s:  (alert.actionsTriggered || []).map(a => a.action).join(', '),
    // Standard fields for Sentinel
    SourceSystem:        'PrivilegedIdentityMonitor',
    Category:            'SecurityAlert',
    AlertType:           'PrivilegedUserAnomaly'
  }]);

  const date = new Date().toUTCString();
  const contentLength = Buffer.byteLength(body, 'utf8');
  const contentType = 'application/json';
  const resource = '/api/logs';

  // HMAC-SHA256 signature
  const crypto = require('crypto');
  const stringToSign = `POST\n${contentLength}\n${contentType}\nx-ms-date:${date}\n${resource}`;
  const signature = crypto
    .createHmac('sha256', Buffer.from(sharedKey, 'base64'))
    .update(stringToSign, 'utf-8')
    .digest('base64');

  const authorization = `SharedKey ${workspaceId}:${signature}`;

  try {
    const res = await fetch(
      `https://${workspaceId}.ods.opinsights.azure.com${resource}?api-version=2016-04-01`,
      {
        method: 'POST',
        headers: {
          'Content-Type':  contentType,
          'Log-Type':      'PrivilegedIdentityMonitor',  // Table name in Log Analytics
          'x-ms-date':     date,
          'Authorization': authorization,
          'time-generated-field': 'TimeGenerated'
        },
        body
      }
    );

    if (res.status === 200) {
      console.log('[SIEM] ✅ Log Analytics — alert sent:', alert.id);
    } else {
      const err = await res.text();
      console.error('[SIEM] ❌ Log Analytics error:', res.status, err);
    }
  } catch (err) {
    console.error('[SIEM] Log Analytics fetch error:', err.message);
  }
}

// ─── Outbound Webhook (Splunk, Elastic, custom SIEM) ─────────────────────
async function sendToWebhook(alert, webhookUrl, secret) {
  if (!webhookUrl) return;

  const payload = {
    // Standard CEF-like fields
    version:   '1.0',
    id:        alert.id,
    source:    'PrivilegedIdentityMonitor',
    category:  'authentication',
    severity:  alert.severity,
    riskScore: alert.riskScore || 0,
    timestamp: alert.detectedAt,

    // User
    user: {
      id:    alert.userId,
      name:  alert.userDisplayName,
      upn:   alert.userPrincipalName,
      roles: alert.roles || []
    },

    // Event
    event: {
      type:       alert.anomalyType,
      label:      alert.anomalyLabel,
      detail:     alert.detail,
      signInTime: alert.signInTime,
      appName:    alert.appName,
      appTier:    alert.appTier
    },

    // Location/Device
    network: {
      ipAddress: alert.ipAddress,
      country:   alert.country,
      city:      alert.city
    },
    device: {
      name: alert.deviceName,
      os:   alert.deviceOs
    },

    // Response
    actions: (alert.actionsTriggered || []).map(a => a.action),
    status:  alert.status
  };

  const headers = { 'Content-Type': 'application/json' };
  if (secret) headers['X-Signature'] = require('crypto')
    .createHmac('sha256', secret)
    .update(JSON.stringify(payload))
    .digest('hex');

  try {
    const res = await fetch(webhookUrl, { method: 'POST', headers, body: JSON.stringify(payload) });
    console.log('[SIEM] ✅ Webhook sent:', res.status, webhookUrl);
  } catch (err) {
    console.error('[SIEM] ❌ Webhook error:', err.message);
  }
}

// ─── Main: send alert to all configured SIEM targets ─────────────────────
async function forwardAlert(alert, siemConfig) {
  if (!siemConfig) return;
  const promises = [];

  // Azure Log Analytics
  if (siemConfig.logAnalytics?.enabled && siemConfig.logAnalytics?.workspaceId) {
    promises.push(
      sendToLogAnalytics(alert, siemConfig.logAnalytics.workspaceId, siemConfig.logAnalytics.sharedKey)
    );
  }

  // Outbound webhooks (array — can have multiple)
  for (const wh of (siemConfig.webhooks || [])) {
    if (wh.enabled && wh.url) {
      promises.push(sendToWebhook(alert, wh.url, wh.secret));
    }
  }

  await Promise.allSettled(promises);
}

// ─── Test connectivity ────────────────────────────────────────────────────
async function testLogAnalytics(workspaceId, sharedKey) {
  const testAlert = {
    id:              'test-' + Date.now(),
    tenantId:        'test',
    userId:          'test-user',
    userDisplayName: 'Test User',
    userPrincipalName: 'test@test.com',
    roles:           ['Global Administrator'],
    anomalyType:     'TEST',
    anomalyLabel:    'Test Alert — Connectivity Check',
    severity:        'low',
    riskScore:       5,
    detail:          'This is a test event from Privileged Identity Monitor',
    ipAddress:       '1.2.3.4',
    country:         'Test',
    city:            'Test',
    deviceName:      'Test Device',
    deviceOs:        'Windows',
    appName:         'Test App',
    appTier:         'LOW',
    signInTime:      new Date().toISOString(),
    detectedAt:      new Date().toISOString(),
    status:          'open',
    actionsTriggered: []
  };

  try {
    await sendToLogAnalytics(testAlert, workspaceId, sharedKey);
    return { success: true, message: 'Test event sent. Check Log Analytics in ~5 minutes under table: PrivilegedIdentityMonitor_CL' };
  } catch (err) {
    return { success: false, error: err.message };
  }
}

module.exports = { forwardAlert, sendToLogAnalytics, sendToWebhook, testLogAnalytics, SIEM_TYPES };
