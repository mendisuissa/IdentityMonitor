// tenantRegistry.js — In-memory registry of connected tenants
// Tracks active sessions, health data, onboarding status, and stats
// Supplemented by filesystem scan + Azure Table Storage (survives restarts)

const fs = require('fs');
const path = require('path');
const tableStorage = require('./tableStorage');

const DIRS = {
  settings:  process.env.NODE_ENV === 'production' ? '/home/settings'  : path.join(__dirname, '../../../settings'),
  audit:     process.env.NODE_ENV === 'production' ? '/home/audit'     : path.join(__dirname, '../../../audit'),
  workflows: process.env.NODE_ENV === 'production' ? '/home/workflows' : path.join(__dirname, '../../../workflows')
};

// ── In-memory stores ──────────────────────────────────────────────────────
/** @type {Map<string, object>} tenantId → tenant profile */
const _tenants = new Map();

/** @type {Map<string, object>} tenantId → health state */
const _health  = new Map();

// ── Filesystem helper ─────────────────────────────────────────────────────
function collectIdsFromDir(dir) {
  if (!fs.existsSync(dir)) return [];
  return fs.readdirSync(dir)
    .filter(name => name.endsWith('.json') || name.endsWith('.jsonl'))
    .map(name => name.replace(/\.jsonl?$/, ''));
}

// ─── Tenant management ────────────────────────────────────────────────────

/**
 * Register (or refresh) a tenant when a user logs in.
 * @param {{ tenantId: string, tenantName?: string, userEmail?: string, userName?: string, connectedAt?: string }} tenant
 */
function registerTenant(tenant) {
  if (!tenant?.tenantId) return;
  const existing = _tenants.get(tenant.tenantId) || {};
  const record = {
    ...existing,
    tenantId:     tenant.tenantId,
    tenantName:   tenant.tenantName  || existing.tenantName  || tenant.tenantId,
    primaryEmail: tenant.userEmail   || existing.primaryEmail || '',
    userName:     tenant.userName    || existing.userName     || '',
    connectedAt:  existing.connectedAt || tenant.connectedAt || new Date().toISOString(),
    lastSeenAt:   new Date().toISOString(),
    onboarding:   existing.onboarding || { connected: true }
  };
  _tenants.set(tenant.tenantId, record);
  // Persist to Azure so tenant name/email survive restarts
  tableStorage.saveTenantProfile(tenant.tenantId, record).catch(() => {});
  // Mark onboarding step
  updateOnboarding(tenant.tenantId, 'connected');
}

/** Returns all tenants that have logged in during this process lifetime */
function getActiveTenants() {
  return Array.from(_tenants.values());
}

/**
 * Returns all tenants — async version that merges:
 *   1. in-memory (richest, most recent)
 *   2. Azure Table Storage profiles (survive restarts)
 *   3. filesystem IDs (last resort, no metadata)
 */
async function getAllTenants() {
  const result = new Map(_tenants);

  // Layer 2: Azure profiles (have name, email, connectedAt)
  try {
    const azureProfiles = await tableStorage.getAllTenantProfiles();
    for (const p of azureProfiles) {
      if (!result.has(p.tenantId)) {
        result.set(p.tenantId, p);
      } else {
        // Backfill missing fields from Azure into the in-memory record
        const existing = result.get(p.tenantId);
        result.set(p.tenantId, {
          tenantName:   existing.tenantName   || p.tenantName,
          primaryEmail: existing.primaryEmail || p.primaryEmail,
          userName:     existing.userName     || p.userName,
          connectedAt:  existing.connectedAt  || p.connectedAt,
          ...existing
        });
      }
    }
  } catch (_) {}

  // Layer 3: filesystem IDs (just IDs, no metadata)
  const fsIds = getAllTenantIds();
  for (const id of fsIds) {
    if (!result.has(id)) {
      result.set(id, { tenantId: id, tenantName: id, primaryEmail: '', connectedAt: null });
    }
  }

  return Array.from(result.values()).map(t => ({
    ...t,
    health: _health.get(t.tenantId) || {}
  }));
}

/** Returns unique tenant IDs found in settings/audit/workflow directories */
function getAllTenantIds() {
  return Array.from(new Set([
    ..._tenants.keys(),                    // in-memory (logged-in sessions)
    ...collectIdsFromDir(DIRS.settings),
    ...collectIdsFromDir(DIRS.audit),
    ...collectIdsFromDir(DIRS.workflows)
  ])).filter(Boolean);
}

/** Returns a single tenant by id (in-memory or null) */
function getTenant(tenantId) {
  const t = _tenants.get(tenantId);
  if (!t) return null;
  return { ...t, health: _health.get(tenantId) || {} };
}

// ─── Health management ────────────────────────────────────────────────────

/**
 * Merge a health patch into the tenant's health record.
 * @param {string} tenantId
 * @param {object} patch
 */
function updateTenantHealth(tenantId, patch) {
  if (!tenantId) return;
  const existing = _health.get(tenantId) || {};
  _health.set(tenantId, { ...existing, ...patch, updatedAt: new Date().toISOString() });
}

/** Returns the health record for a tenant */
function getTenantHealth(tenantId) {
  return _health.get(tenantId) || {};
}

// ─── Onboarding management ────────────────────────────────────────────────
const ONBOARDING_STEPS = ['connected', 'permissionsGranted', 'firstScanDone', 'alertChannelTested', 'webhookActive', 'workHoursSet'];

/**
 * Mark an onboarding step as complete.
 * @param {string} tenantId
 * @param {keyof typeof ONBOARDING_STEPS} step
 */
function updateOnboarding(tenantId, step) {
  if (!tenantId || !step) return;
  const t = _tenants.get(tenantId);
  if (!t) return;
  const onboarding = { ...(t.onboarding || {}), [step]: true };
  _tenants.set(tenantId, { ...t, onboarding });
}

/** Returns the onboarding object for a tenant */
function getOnboarding(tenantId) {
  return _tenants.get(tenantId)?.onboarding || {};
}

// ─── Stats management ─────────────────────────────────────────────────────

/**
 * Merge a stats patch (e.g. lastAlertAt) into the tenant record.
 * @param {string} tenantId
 * @param {object} stats
 */
function updateTenantStats(tenantId, stats) {
  if (!tenantId) return;
  const t = _tenants.get(tenantId) || { tenantId };
  _tenants.set(tenantId, { ...t, ...stats });
}

module.exports = {
  registerTenant,
  getActiveTenants,
  getAllTenants,
  getAllTenantIds,
  getTenant,
  updateTenantHealth,
  getTenantHealth,
  updateOnboarding,
  getOnboarding,
  updateTenantStats
};
