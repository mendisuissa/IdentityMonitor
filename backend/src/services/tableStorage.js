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
  INCIDENTS: 'incidents'
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

async function getAlerts(tenantId, filters = {}) {
  const client = getClient(TABLES.ALERTS);
  const pk = tenantId || 'default';
  let query = `PartitionKey eq '${pk}'`;

  if (filters.status)   query += ` and status eq '${filters.status}'`;
  if (filters.severity) query += ` and severity eq '${filters.severity}'`;

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

module.exports = {
  initTables,
  saveAlert, getAlerts, updateAlertStatus,
  getBaseline, saveBaseline,
  saveWebhookSubscription, getWebhookSubscriptions, deleteWebhookSubscription,
  saveTenantSettings, getTenantSettings,
  TABLES
};
