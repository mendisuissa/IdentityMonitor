// alertsStore.js — in-memory alert store with Azure Table Storage persistence
// On startup: loads all alerts from Azure Tables into memory
// On add/update: writes through to Azure Tables

const tableStorage = require('./tableStorage');

const alerts = new Map();
let _loaded = new Set(); // tenants already loaded from Azure

// ─── Load alerts from Azure Tables for a tenant ───────────────────────────
async function loadFromAzure(tenantId) {
  if (_loaded.has(tenantId)) return; // already loaded — idempotent
  _loaded.add(tenantId); // mark immediately to prevent concurrent duplicate loads
  try {
    const rows = await tableStorage.getAlerts(tenantId);
    for (const alert of rows) {
      alerts.set(alert.id, { ...alert, tenantId: alert.tenantId || tenantId });
    }
    console.log(`[AlertsStore] Loaded ${rows.length} alerts for tenant ${tenantId}`);
  } catch (err) {
    _loaded.delete(tenantId); // allow retry on next request if load failed
    console.warn('[AlertsStore] Failed to load from Azure:', err.message);
  }
}

function add(alert) {
  if (!alert.tenantId) console.warn('[AlertsStore] Alert missing tenantId:', alert.id);
  alerts.set(alert.id, { ...alert });
  // Persist async
  tableStorage.saveAlert(alert).catch(err =>
    console.error('[AlertsStore] saveAlert error:', err.message)
  );
}

function exists(id) { return alerts.has(id); }

function getAll(tenantId) {
  // Trigger lazy load if not yet loaded
  if (tenantId && !_loaded.has(tenantId)) {
    loadFromAzure(tenantId).catch(() => {});
  }
  const all = Array.from(alerts.values()).sort(
    (a, b) => new Date(b.detectedAt) - new Date(a.detectedAt)
  );
  if (tenantId) return all.filter(a => a.tenantId === tenantId);
  return all;
}

function getByUser(userId, tenantId) { return getAll(tenantId).filter(a => a.userId === userId); }
function getOpen(tenantId) { return getAll(tenantId).filter(a => a.status === 'open'); }
function getById(id) { return alerts.get(id) || null; }

function updateStatus(id, status, resolvedBy) {
  if (!alerts.has(id)) return null;
  const alert = alerts.get(id);
  alert.status = status;
  if (resolvedBy) alert.resolvedBy = resolvedBy;
  alert.resolvedAt = new Date().toISOString();
  // Persist async
  tableStorage.updateAlertStatus(alert.tenantId || 'default', id, status, resolvedBy).catch(err =>
    console.error('[AlertsStore] updateStatus error:', err.message)
  );
  return alert;
}

function addAction(id, action) {
  if (!alerts.has(id)) return;
  const alert = alerts.get(id);
  if (!alert.actionsTriggered) alert.actionsTriggered = [];
  alert.actionsTriggered.push({ action, timestamp: new Date().toISOString() });
  tableStorage.saveAlert(alert).catch(() => {});
}

function getStats(tenantId) {
  const all  = getAll(tenantId);
  const open = all.filter(a => a.status === 'open');
  return {
    total:         all.length,
    open:          open.length,
    critical:      open.filter(a => a.severity === 'critical').length,
    high:          open.filter(a => a.severity === 'high').length,
    medium:        open.filter(a => a.severity === 'medium').length,
    low:           open.filter(a => a.severity === 'low').length,
    resolvedToday: all.filter(a => {
      if (a.status !== 'resolved') return false;
      return new Date(a.resolvedAt).toDateString() === new Date().toDateString();
    }).length
  };
}

module.exports = { add, exists, getAll, getById, getByUser, getOpen, updateStatus, addAction, getStats, loadFromAzure };
