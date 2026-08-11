// tableStorage.js — Azure Table Storage for persistent alerts + baselines
// Cost: ~$0.045 per million operations = essentially free for this use case
// Connection string from: Azure Portal → Storage Account → Access keys

const { TableClient, AzureNamedKeyCredential } = require('@azure/data-tables');

const TABLES = {
  ALERTS:    'alerts',
  BASELINES: 'baselines',
  TENANTS:   'tenants',
  WEBHOOKS:  'webhooks',
  WORKFLOWS: 'workflows',
  INCIDENTS: 'incidents',
  SEENCVES:  'seencves'
};

let _clients = {};

function getClient(tableName) {
  if (_clients[tableName]) return _clients[tableName];

  const connStr = process.env.AZURE_STORAGE_CONNECTION_STRING;
  if (!connStr) {
    throw new Error('AZURE_STORAGE_CONNECTION_STRING not configured');
  }

  _clients[tableName] = TableClient.fromConnectionString(connStr, tableName);
  return _clients[tableName];
}

// ─── Initialize tables (create if not exist) ──────────────────────────────
async function initTables() {
  for (const table of Object.values(TABLES)) {
    try {
      await getClient(table).createTable();
      console.log('[TableStorage] Table ready:', table);
    } catch (err) {
      if (err.statusCode === 409) {
        // Table already exists — fine
      } else {
        console.error('[TableStorage] Error creating table', table, ':', err.message);
      }
    }
  }
}

// ─── ALERTS ───────────────────────────────────────────────────────────────
// PartitionKey = tenantId, RowKey = alertId

async function saveAlert(alert) {
  const client = getClient(TABLES.ALERTS);
  const entity = {
    partitionKey: alert.tenantId || 'default',
    rowKey:       alert.id.replace(/[^a-zA-Z0-9_-]/g, '_'),
    ...flattenForTable(alert)
  };
  await client.upsertEntity(entity, 'Replace');
}

const VALID_STATUSES  = new Set(['open', 'resolved', 'dismissed', 'acknowledged']);
const VALID_SEVERITIES = new Set(['critical', 'high', 'medium', 'low', 'informational']);

function escapeOData(value) {
  // Escape single quotes in OData string literals
  return String(value || '').replace(/'/g, "''");
}

async function getAlerts(tenantId, filters = {}) {
  const client = getClient(TABLES.ALERTS);
  const pk = escapeOData(tenantId || 'default');
  let query = `PartitionKey eq '${pk}'`;

  if (filters.status && VALID_STATUSES.has(filters.status))
    query += ` and status eq '${filters.status}'`;
  if (filters.severity && VALID_SEVERITIES.has(filters.severity))
    query += ` and severity eq '${filters.severity}'`;

  const results = [];
  const iter = client.listEntities({ queryOptions: { filter: query } });
  for await (const entity of iter) {
    results.push(unflattenFromTable(entity));
  }

  return results.sort((a, b) => new Date(b.detectedAt).getTime() - new Date(a.detectedAt).getTime());
}

async function updateAlertStatus(tenantId, alertId, status, resolvedBy) {
  const client = getClient(TABLES.ALERTS);
  const rowKey = alertId.replace(/[^a-zA-Z0-9_-]/g, '_');
  try {
    const entity = await client.getEntity(tenantId || 'default', rowKey);
    entity.status = status;
    if (resolvedBy) entity.resolvedBy = resolvedBy;
    entity.resolvedAt = new Date().toISOString();
    await client.upsertEntity(entity, 'Replace');
    return unflattenFromTable(entity);
  } catch (err) {
    console.error('[TableStorage] updateAlertStatus error:', err.message);
    return null;
  }
}

// ─── BASELINES ────────────────────────────────────────────────────────────
// PartitionKey = tenantId, RowKey = userId

async function getBaseline(tenantId, userId) {
  const client = getClient(TABLES.BASELINES);
  try {
    const entity = await client.getEntity(tenantId, userId);
    return {
      knownIPs:       JSON.parse(entity.knownIPs || '[]'),
      knownCountries: JSON.parse(entity.knownCountries || '[]'),
      knownDevices:   JSON.parse(entity.knownDevices || '[]'),
      recentSignIns:  JSON.parse(entity.recentSignIns || '[]'),
      lastUpdated:    entity.lastUpdated
    };
  } catch (err) {
    // Not found = new user, return empty baseline
    return { knownIPs: [], knownCountries: [], knownDevices: [], recentSignIns: [], lastUpdated: null };
  }
}

async function saveBaseline(tenantId, userId, baseline) {
  const client = getClient(TABLES.BASELINES);
  // Keep recent sign-ins capped at 50
  const recentCapped = (baseline.recentSignIns || []).slice(-50);
  await client.upsertEntity({
    partitionKey:   tenantId,
    rowKey:         userId,
    knownIPs:       JSON.stringify([...new Set(baseline.knownIPs || [])].slice(-100)),
    knownCountries: JSON.stringify([...new Set(baseline.knownCountries || [])].slice(-50)),
    knownDevices:   JSON.stringify([...new Set(baseline.knownDevices || [])].slice(-50)),
    recentSignIns:  JSON.stringify(recentCapped),
    lastUpdated:    new Date().toISOString()
  }, 'Replace');
}

// ─── SEEN CVEs (auto-remediation new-CVE detection) ──────────────────────
// PartitionKey = tenantId, RowKey = 'seen'
//
// Was an in-memory Map in autoRemediationService.js — reset to empty on
// every app restart, and the first scan after any restart silently
// re-baselines "current CVEs = seen" without ever alerting on them (see
// that file's comment). Confirmed live (2026-08-11): IdentityMonitor's App
// Service was hitting a Kudu deploy-conflict on every attempt from
// 2026-07-15 to 2026-08-10, almost certainly restarting repeatedly during
// that whole window — explains a full silence on new-CVE Telegram alerts
// starting around then. Persisting this here means a restart no longer
// wipes what's already been alerted on.

async function getSeenCves(tenantId) {
  const client = getClient(TABLES.SEENCVES);
  try {
    const entity = await client.getEntity(tenantId, 'seen');
    return new Set(JSON.parse(entity.cveIds || '[]'));
  } catch (err) {
    return null; // not found = never scanned before, distinct from "scanned, found nothing"
  }
}

async function saveSeenCves(tenantId, cveIdSet) {
  const client = getClient(TABLES.SEENCVES);
  await client.upsertEntity({
    partitionKey: tenantId,
    rowKey:       'seen',
    cveIds:       JSON.stringify([...cveIdSet].slice(0, 2000)),
    lastUpdated:  new Date().toISOString()
  }, 'Replace');
}

// ─── WEBHOOK SUBSCRIPTIONS ────────────────────────────────────────────────
// Track active Graph webhook subscriptions per tenant

async function saveWebhookSubscription(tenantId, sub) {
  const client = getClient(TABLES.WEBHOOKS);
  await client.upsertEntity({
    partitionKey: tenantId,
    rowKey:       sub.id,
    subscriptionId: sub.id,
    resource:     sub.resource,
    expiresAt:    sub.expirationDateTime,
    createdAt:    new Date().toISOString()
  }, 'Replace');
}

async function getWebhookSubscriptions(tenantId) {
  const client = getClient(TABLES.WEBHOOKS);
  const results = [];
  try {
    const iter = client.listEntities({
      queryOptions: { filter: `PartitionKey eq '${tenantId}'` }
    });
    for await (const entity of iter) results.push(entity);
  } catch (err) { /* table might not exist yet */ }
  return results;
}

async function deleteWebhookSubscription(tenantId, subscriptionId) {
  const client = getClient(TABLES.WEBHOOKS);
  try {
    await client.deleteEntity(tenantId, subscriptionId);
  } catch (err) { /* ignore */ }
}

// ─── TENANT REGISTRY (profile + health, survives restarts) ───────────────
async function saveTenantProfile(tenantId, profile) {
  if (!tenantId) return;
  const client = getClient(TABLES.TENANTS);
  await client.upsertEntity({
    partitionKey: 'profile',
    rowKey:       tenantId,
    tenantId,
    tenantName:   profile.tenantName   || tenantId,
    primaryEmail: profile.primaryEmail || '',
    userName:     profile.userName     || '',
    connectedAt:  profile.connectedAt  || new Date().toISOString(),
    lastSeenAt:   new Date().toISOString()
  }, 'Merge');
}

async function getAllTenantProfiles() {
  const client = getClient(TABLES.TENANTS);
  const profiles = [];
  try {
    const iter = client.listEntities({ queryOptions: { filter: `PartitionKey eq 'profile'` } });
    for await (const entity of iter) {
      profiles.push({
        tenantId:     entity.rowKey,
        tenantName:   entity.tenantName   || entity.rowKey,
        primaryEmail: entity.primaryEmail || '',
        userName:     entity.userName     || '',
        connectedAt:  entity.connectedAt  || null,
        lastSeenAt:   entity.lastSeenAt   || null
      });
    }
  } catch (err) { console.warn('[TableStorage] getAllTenantProfiles:', err.message); }
  return profiles;
}

// ─── TENANT SETTINGS ─────────────────────────────────────────────────────
async function saveTenantSettings(tenantId, settings) {
  const client = getClient(TABLES.TENANTS);
  await client.upsertEntity({
    partitionKey: 'settings',
    rowKey:       tenantId,
    ...flattenForTable(settings),
    updatedAt: new Date().toISOString()
  }, 'Replace');
}

async function getTenantSettings(tenantId) {
  const client = getClient(TABLES.TENANTS);
  try {
    const entity = await client.getEntity('settings', tenantId);
    return unflattenFromTable(entity);
  } catch (err) {
    return {};
  }
}

// ─── Helpers ──────────────────────────────────────────────────────────────
function flattenForTable(obj) {
  const flat = {};
  for (const [k, v] of Object.entries(obj)) {
    if (k === 'partitionKey' || k === 'rowKey') continue;
    if (v === null || v === undefined) continue;
    if (typeof v === 'object') {
      flat[k] = JSON.stringify(v);
    } else {
      flat[k] = v;
    }
  }
  return flat;
}

function unflattenFromTable(entity) {
  const result = {};
  const SYSTEM_KEYS = new Set(['partitionKey', 'rowKey', 'etag', 'timestamp', 'odata.etag']);
  for (const [k, v] of Object.entries(entity)) {
    if (SYSTEM_KEYS.has(k)) continue;
    if (typeof v === 'string' && (v.startsWith('{') || v.startsWith('['))) {
      try { result[k] = JSON.parse(v); continue; } catch (e) {}
    }
    result[k] = v;
  }
  // Restore id from rowKey
  if (!result.id && entity.rowKey) result.id = entity.rowKey;
  if (!result.tenantId && entity.partitionKey) result.tenantId = entity.partitionKey;
  return result;
}

// ─── RETENTION ENFORCEMENT ───────────────────────────────────────────────
// Deletes alert rows older than `cutoffIso` for a specific tenant.
async function purgeOldAlerts(tenantId, cutoffIso) {
  const client = getClient(TABLES.ALERTS);
  const pk = tenantId || 'default';
  const filter = `PartitionKey eq '${pk}' and detectedAt lt '${cutoffIso}'`;
  const toDelete = [];
  try {
    const iter = client.listEntities({ queryOptions: { filter } });
    for await (const entity of iter) toDelete.push({ partitionKey: entity.partitionKey, rowKey: entity.rowKey });
  } catch (err) { console.warn('[Retention] purgeOldAlerts list error:', err.message); return 0; }
  for (const { partitionKey, rowKey } of toDelete) {
    await client.deleteEntity(partitionKey, rowKey).catch(() => {});
  }
  return toDelete.length;
}

// Purge baseline entries older than `cutoffIso` (based on lastUpdated field).
async function purgeOldBaselines(tenantId, cutoffIso) {
  const client = getClient(TABLES.BASELINES);
  const filter = `PartitionKey eq '${tenantId}' and lastUpdated lt '${cutoffIso}'`;
  const toDelete = [];
  try {
    const iter = client.listEntities({ queryOptions: { filter } });
    for await (const entity of iter) toDelete.push({ partitionKey: entity.partitionKey, rowKey: entity.rowKey });
  } catch (err) { console.warn('[Retention] purgeOldBaselines list error:', err.message); return 0; }
  for (const { partitionKey, rowKey } of toDelete) {
    await client.deleteEntity(partitionKey, rowKey).catch(() => {});
  }
  return toDelete.length;
}

// ─── GDPR RIGHT TO ERASURE ────────────────────────────────────────────────
// Deletes ALL data for a tenant across every table. Irreversible.
async function eraseAllTenantData(tenantId) {
  const deleted = {};

  async function _purgeTable(tableName, partitionKey) {
    const client = getClient(tableName);
    const rows = [];
    try {
      const iter = client.listEntities({ queryOptions: { filter: `PartitionKey eq '${partitionKey}'` } });
      for await (const e of iter) rows.push({ partitionKey: e.partitionKey, rowKey: e.rowKey });
    } catch (err) { console.warn('[Erasure] list error in', tableName, ':', err.message); }
    for (const { partitionKey: pk, rowKey } of rows) {
      await client.deleteEntity(pk, rowKey).catch(() => {});
    }
    return rows.length;
  }

  deleted.alerts    = await _purgeTable(TABLES.ALERTS,    tenantId);
  deleted.baselines = await _purgeTable(TABLES.BASELINES, tenantId);
  deleted.webhooks  = await _purgeTable(TABLES.WEBHOOKS,  tenantId);
  deleted.incidents = await _purgeTable(TABLES.INCIDENTS, tenantId);
  deleted.workflows = await _purgeTable(TABLES.WORKFLOWS, tenantId);
  deleted.seenCves  = await _purgeTable(TABLES.SEENCVES,  tenantId);

  // Tenant profile (partitionKey = 'profile') and settings (partitionKey = 'settings')
  const tenantsClient = getClient(TABLES.TENANTS);
  await tenantsClient.deleteEntity('profile',  tenantId).catch(() => {});
  await tenantsClient.deleteEntity('settings', tenantId).catch(() => {});
  deleted.tenantProfile  = 1;
  deleted.tenantSettings = 1;

  console.log('[Erasure] Tenant data erased for', tenantId, ':', JSON.stringify(deleted));
  return deleted;
}

module.exports = {
  initTables,
  saveAlert, getAlerts, updateAlertStatus,
  getBaseline, saveBaseline,
  getSeenCves, saveSeenCves,
  saveWebhookSubscription, getWebhookSubscriptions, deleteWebhookSubscription,
  saveTenantSettings, getTenantSettings,
  saveTenantProfile, getAllTenantProfiles,
  purgeOldAlerts, purgeOldBaselines, eraseAllTenantData,
  TABLES
};
