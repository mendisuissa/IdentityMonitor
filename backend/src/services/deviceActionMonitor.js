// deviceActionMonitor.js
// Polls Intune every CRON cycle for new destructive device actions (wipe/delete/reset)
// and creates alerts in the alerts store so they appear in the Alerts feed.

const alertsStore = require('./alertsStore');
const tenantRegistry = require('./tenantRegistry');
const notificationCenter = require('./notificationCenterService');
const graphService = require('./graphService');

// Track which action IDs we've already alerted on (in-memory, resets on restart — dedup via alertsStore.exists)
const _seenActionIds = new Map(); // tenantId → Set<actionId>

const SEVERITY_MAP = {
  critical: 'critical',
  high: 'high',
  medium: 'medium',
};

const TYPE_LABEL = {
  wipe: 'Device Wipe',
  delete: 'Device Delete / Retire',
  reset: 'Device Reset / Passcode Reset',
};

const TYPE_DETAIL = {
  wipe: 'A destructive WIPE action was executed on a managed device. All data has been erased.',
  delete: 'A DELETE or RETIRE action was executed — the device has been removed from Intune management.',
  reset: 'A RESET or passcode-reset action was executed on a managed device.',
};

function buildAlertId(tenantId, actionId) {
  return `device-action-${tenantId}-${actionId}`;
}

function enqueueUniqueNotification(tenantId, type, uniqueKey, payload) {
  try {
    const existing = notificationCenter.list(tenantId, { limit: 300 }).find(n => n.type === type && n.uniqueKey === uniqueKey);
    if (existing) return;
    notificationCenter.enqueue(tenantId, { type, uniqueKey, ...payload });
  } catch (err) {
    console.warn('[DeviceActionMonitor] Failed to enqueue notification:', err.message);
  }
}

async function checkTenant(tenantId) {
  try {
    const actions = await graphService.getDeviceActions(tenantId);
    if (!Array.isArray(actions) || actions.length === 0) return 0;

    if (!_seenActionIds.has(tenantId)) _seenActionIds.set(tenantId, new Set());
    const seen = _seenActionIds.get(tenantId);

    let created = 0;
    for (const action of actions) {
      const alertId = buildAlertId(tenantId, action.id);

      // Skip if already seen in this session or already in alerts store
      if (seen.has(action.id) || alertsStore.exists(alertId)) {
        seen.add(action.id);
        continue;
      }
      seen.add(action.id);

      const severity = SEVERITY_MAP[action.severity] || 'high';
      const typeLabel = TYPE_LABEL[action.type] || action.type;
      const detail = TYPE_DETAIL[action.type] || `Destructive action ${action.type} detected on device ${action.deviceName}.`;

      const alert = {
        id: alertId,
        tenantId,
        userId: action.userPrincipalName || '',
        userDisplayName: action.userDisplayName || action.userPrincipalName || 'Unknown user',
        userPrincipalName: action.userPrincipalName || '',
        roles: [],
        signInId: null,
        signInTime: action.timestamp,
        ipAddress: null,
        country: null,
        city: null,
        deviceName: action.deviceName || null,
        deviceOs: action.os || null,
        appName: 'Intune Device Management',
        anomalyType: `device_action_${action.type}`,
        anomalyLabel: typeLabel,
        severity,
        riskScore: severity === 'critical' ? 95 : severity === 'high' ? 80 : 60,
        appTier: 'device-management',
        riskFactors: [
          `Action type: ${action.type.toUpperCase()}`,
          `Initiated by: ${action.initiatedBy || 'unknown'}`,
          `Device: ${action.deviceName || 'unknown'}`,
          `Status: ${action.status || 'unknown'}`,
        ],
        detail: `${detail} | Initiated by: ${action.initiatedBy || 'unknown'} | Device: ${action.deviceName || 'unknown'}`,
        status: 'open',
        detectedAt: action.timestamp || new Date().toISOString(),
        actionsTriggered: [],
        _source: 'intune-device-action',
      };

      alertsStore.add(alert);
      created++;

      // Also push to notification center (bell icon)
      enqueueUniqueNotification(tenantId, 'device-action', alertId, {
        severity,
        title: `${typeLabel} detected`,
        detail: `Device: ${action.deviceName || 'unknown'} · Initiated by: ${action.initiatedBy || 'unknown'}`,
        metadata: { alertId, deviceName: action.deviceName, actionType: action.type },
      });

      console.log(`[DeviceActionMonitor] ⚠️  New alert created: ${typeLabel} on ${action.deviceName} for tenant ${tenantId}`);
    }

    return created;
  } catch (err) {
    console.warn(`[DeviceActionMonitor] Failed to check tenant ${tenantId}:`, err.message);
    return 0;
  }
}

async function runDeviceActionCheck() {
  const tenantIds = tenantRegistry.getAllTenantIds();
  if (!tenantIds.length) return;
  let total = 0;
  for (const tenantId of tenantIds) {
    total += await checkTenant(tenantId);
  }
  if (total > 0) console.log(`[DeviceActionMonitor] Created ${total} new device-action alerts across ${tenantIds.length} tenants`);
}

module.exports = { runDeviceActionCheck, checkTenant };
