/**
 * remediationHistoryStore.js
 * Persists every plan+execute action (auto or manual) to Azure Table Storage.
 * Table: remediationHistory  PartitionKey=tenantId  RowKey=cveId__epochMs
 */

const { TableClient, TableServiceClient } = require('@azure/data-tables');

const TABLE_NAME = 'remediationHistory';
const IN_MEMORY  = new Map(); // fallback when Azure Storage is not configured

// ── Azure helpers ────────────────────────────────────────────────────────────

function getTableClient() {
  const conn = process.env.AZURE_STORAGE_CONNECTION_STRING;
  if (!conn) return null;
  return TableClient.fromConnectionString(conn, TABLE_NAME);
}

async function ensureTable() {
  const conn = process.env.AZURE_STORAGE_CONNECTION_STRING;
  if (!conn) return;
  try {
    const svc = TableServiceClient.fromConnectionString(conn);
    await svc.createTable(TABLE_NAME);
  } catch (_) { /* already exists */ }
}

// ── Write ─────────────────────────────────────────────────────────────────────

/**
 * Save one remediation record.
 * @param {object} record
 * @param {string} record.tenantId
 * @param {string} record.cveId
 * @param {string} record.productName
 * @param {string} record.category          // 'application'|'windows-update'|'unsupported-platform'|…
 * @param {string} record.status            // 'success'|'failed'|'skipped'|'pending'|'unsupported'
 * @param {string} [record.executor]        // 'auto'|'manual'
 * @param {string} [record.triggeredBy]     // 'cron'|'ui'|'webhook'
 * @param {object} [record.result]          // raw API response
 * @param {string} [record.message]
 */
async function saveRemediationRecord(record) {
  const now    = new Date().toISOString();
  const safeId = String(record.cveId || 'unknown').replace(/[^a-zA-Z0-9-]/g, '_');
  const rowKey = `${safeId}__${Date.now()}`;

  const entity = {
    tenantId:    record.tenantId,
    cveId:       record.cveId       || '',
    productName: record.productName || '',
    category:    record.category    || '',
    severity:    record.severity    || '',
    status:      record.status      || 'unknown',
    executor:    record.executor    || 'manual',
    triggeredBy: record.triggeredBy || 'ui',
    message:     record.message     || '',
    result:      JSON.stringify(record.result || {}),
    executedAt:  now,
  };

  // Always write to in-memory so polling can find the record immediately,
  // even if the Azure write is slow or fails.
  const key = record.tenantId;
  if (!IN_MEMORY.has(key)) IN_MEMORY.set(key, []);
  IN_MEMORY.get(key).unshift({ id: rowKey, ...entity });
  const list = IN_MEMORY.get(key);
  if (list.length > 500) list.splice(500);

  const client = getTableClient();
  if (client) {
    try {
      await ensureTable();
      await client.createEntity({ partitionKey: record.tenantId, rowKey, ...entity });
    } catch (azErr) {
      console.error('[remediationHistoryStore] Azure write failed (record kept in-memory):', azErr?.message);
    }
  }

  return { id: rowKey, ...entity };
}

// ── Read ──────────────────────────────────────────────────────────────────────

/**
 * List remediation history for a tenant, newest first.
 */
async function getRemediationHistory(tenantId, options = {}) {
  const limit = Number(options.limit || 200);

  // Always include in-memory records (written immediately on save, even when Azure is configured)
  const memRecords = IN_MEMORY.get(tenantId) || [];
  const memIds = new Set(memRecords.map(r => r.id));

  const client = getTableClient();
  if (!client) {
    return limit > 0 ? memRecords.slice(0, limit) : memRecords;
  }

  // No ensureTable() here — table is guaranteed to exist after startup init.
  const records = [...memRecords];
  const fetchLimit = limit > 0 ? limit * 3 : 600;
  try {
    const iterator = client.listEntities({
      queryOptions: { filter: `PartitionKey eq '${tenantId.replace(/'/g, "''")}'` }
    });
    for await (const e of iterator) {
      if (memIds.has(e.rowKey)) continue; // skip duplicates already in-memory
      records.push({
        id:          e.rowKey,
        tenantId:    e.partitionKey,
        cveId:       e.cveId       || '',
        productName: e.productName || '',
        category:    e.category    || '',
        severity:    e.severity    || '',
        status:      e.status      || '',
        executor:    e.executor    || '',
        triggeredBy: e.triggeredBy || '',
        message:     e.message     || '',
        result:      (() => { try { return JSON.parse(e.result || '{}'); } catch { return {}; } })(),
        executedAt:  e.executedAt  || '',
      });
      if (records.length >= fetchLimit) break;
    }
  } catch (azErr) {
    console.error('[remediationHistoryStore] Azure read failed, returning in-memory only:', azErr?.message);
  }

  records.sort((a, b) => b.executedAt.localeCompare(a.executedAt));
  return limit > 0 ? records.slice(0, limit) : records;
}

/**
 * Aggregate stats for the dashboard.
 * Accepts an already-loaded record list to avoid a second Azure round-trip.
 */
async function getRemediationStats(tenantId, preloadedRecords) {
  const records = preloadedRecords ?? await getRemediationHistory(tenantId, { limit: 500 });
  const byStatus   = {};
  const byCategory = {};
  const bySeverity = {};
  const recent     = records.slice(0, 10);

  for (const r of records) {
    byStatus[r.status]     = (byStatus[r.status]     || 0) + 1;
    byCategory[r.category] = (byCategory[r.category] || 0) + 1;
    if (r.severity) bySeverity[r.severity.toLowerCase()] = (bySeverity[r.severity.toLowerCase()] || 0) + 1;
  }

  return {
    total:      records.length,
    byStatus,
    byCategory,
    bySeverity,
    recent,
    lastRunAt:  records[0]?.executedAt || null,
  };
}

/**
 * Check if a CVE was already successfully remediated within `withinHours` hours.
 * Returns the record or null.
 */
async function getRecentSuccessForCve(tenantId, cveId, withinHours = 24) {
  const cutoff    = Date.now() - withinHours * 60 * 60 * 1000;
  const safeCveId = String(cveId || '').toUpperCase();

  const client = getTableClient();
  if (!client) {
    const list = IN_MEMORY.get(tenantId) || [];
    return list.find(r =>
      r.cveId.toUpperCase() === safeCveId &&
      r.status === 'success' &&
      new Date(r.executedAt).getTime() >= cutoff
    ) || null;
  }

  await ensureTable();
  const tISO     = new Date(cutoff).toISOString();
  const safeTid  = tenantId.replace(/'/g, "''");
  const safeCve  = safeCveId.replace(/'/g, "''");
  const iterator = client.listEntities({
    queryOptions: {
      filter: `PartitionKey eq '${safeTid}' and cveId eq '${safeCve}' and status eq 'success' and executedAt ge '${tISO}'`
    }
  });
  for await (const e of iterator) return e;
  return null;
}

module.exports = { saveRemediationRecord, getRemediationHistory, getRemediationStats, getRecentSuccessForCve, ensureTable };
