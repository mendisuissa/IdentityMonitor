// #105: the 60s scan blocked the event loop. Its duplicate check downloaded, parsed and sorted
// the tenant's whole alert partition once per candidate alert, and a row found in Azure was
// never cached, so the same full read repeated every cycle for every anomalous sign-in in the
// 48h window. These tests pin the bound: the check is a point read whose cost does not depend on
// how many alerts the tenant has stored, it runs at most once per alert, and no synchronous
// slice of the scan or of an alert listing grows past ~1s with a large history.
// Run: node --test backend/tests/scan-duplicate-check.test.js
const test = require('node:test');
const assert = require('node:assert');

// No real Azure: every Table client call is stubbed before the services load.
process.env.AZURE_STORAGE_CONNECTION_STRING =
  'DefaultEndpointsProtocol=https;AccountName=test;AccountKey=dGVzdA==;TableEndpoint=http://127.0.0.1:9/test';
const { TableClient } = require('@azure/data-tables');
TableClient.prototype.createTable = async () => {};
TableClient.prototype.upsertEntity = async () => {};
TableClient.prototype.getEntity = async () => { const e = new Error('not found'); e.statusCode = 404; throw e; };

const tableStorage = require('../src/services/tableStorage');
const io = (v) => new Promise((r) => setImmediate(() => r(v)));

const TENANT = 'tenant-105';
const STORED = 200000;           // a large alert history for one tenant
const BOUND_MS = 1000;           // longest allowed synchronous slice

function storedAlert(i) {
  return {
    id: `${TENANT}-old-${i}`, tenantId: TENANT, status: 'open', severity: 'medium',
    detectedAt: new Date(Date.parse('2026-05-01T00:00:00Z') + ((i * 7919) % STORED) * 60000).toISOString(),
    riskFactors: [{ type: 'FAILED_SIGN_IN', score: 20, detail: 'Authentication failed (error 50126)' }],
  };
}

// The stored partition, plus the alert rows the scan is about to rediscover.
const partition = new Map();
for (let i = 0; i < STORED; i++) { const a = storedAlert(i); partition.set(a.id, a); }

const calls = { getAlerts: 0, getAlert: 0, found: 0, ids: new Set() };
tableStorage.getAlerts = async () => {
  calls.getAlerts += 1;
  await io();
  return tableStorage.sortByDetectedAtDesc([...partition.values()].map((a) => ({ ...a })));
};
tableStorage.getAlert = async (tenantId, id) => {
  calls.getAlert += 1;
  calls.ids.add(id);
  await io();
  const a = partition.get(id);
  if (a) calls.found += 1;
  return a ? { ...a } : null;
};
tableStorage.saveAlert = async () => io();
tableStorage.saveBaseline = async () => io();
tableStorage.getBaseline = async () => io({ knownIPs: [], knownCountries: [], knownDevices: [], recentSignIns: [], lastUpdated: null });
tableStorage.getTenantSettings = async () => io({});

const anomalyService = require('../src/services/anomalyService');
const alertsStore = require('../src/services/alertsStore');
const settingsService = require('../src/services/settingsService');

// Records the longest gap between heartbeats while fn runs: a gap is a synchronous slice.
async function longestSlice(fn) {
  let last = performance.now();
  let worst = 0;
  const hb = setInterval(() => { const t = performance.now(); worst = Math.max(worst, t - last); last = t; }, 5);
  try { await fn(); } finally {
    clearInterval(hb);
    worst = Math.max(worst, performance.now() - last);
  }
  return worst;
}

const user = { id: 'admin-1', displayName: 'Admin One', userPrincipalName: 'admin1@example.test', roles: ['Global Administrator'] };
// 60 failed sign-ins in the 48h window (a password spray): each one yields a FAILED_SIGN_IN alert.
// They are 15 min apart so the velocity rule stays out of this test.
const signIns = Array.from({ length: 60 }, (_, i) => ({
  id: `si-${i}`,
  createdDateTime: new Date(Date.parse('2026-11-10T10:00:00Z') - i * 15 * 60000).toISOString(),
  ipAddress: `203.0.113.${i}`,
  location: { countryOrRegion: 'NL', city: 'Amsterdam' },
  deviceDetail: {},
  status: { errorCode: 50126 },
  appDisplayName: 'Azure Portal',
}));
// The first 40 were already alerted on in an earlier process: they are in Azure, not in memory.
for (const s of signIns.slice(0, 40)) {
  const id = `${TENANT}-${user.id}-${s.id}-FAILED_SIGN_IN`;
  partition.set(id, { id, tenantId: TENANT, status: 'open', detectedAt: s.createdDateTime, anomalyType: 'FAILED_SIGN_IN' });
}

test('the duplicate check is a point read, bounded per alert and cached across cycles', async () => {
  const settings = settingsService.getSettings(TENANT);
  let created;
  const worst = await longestSlice(async () => {
    created = await anomalyService.scanUser(TENANT, user, signIns, settings);
  });

  assert.strictEqual(calls.getAlerts, 0, 'the scan must never list the whole alert partition');
  assert.strictEqual(calls.getAlert, calls.ids.size, 'at most one point read per candidate alert');
  assert.strictEqual(calls.found, 40, 'the 40 alerts already in Azure are found');
  assert.strictEqual(created.length, calls.getAlert - 40, 'only alerts missing from Azure are created');
  assert.ok(created.some((a) => a.anomalyType === 'FAILED_SIGN_IN'));
  for (const s of signIns.slice(0, 40)) {
    assert.ok(alertsStore.exists(`${TENANT}-${user.id}-${s.id}-FAILED_SIGN_IN`), 'a row found in Azure is cached');
  }
  assert.ok(worst < BOUND_MS, `longest synchronous slice ${Math.round(worst)}ms must stay under ${BOUND_MS}ms`);

  // Next cycle: same 48h window. Every id checked above is now in memory, so none is read again.
  // (The replayed sign-ins can still raise other anomaly types, which are new ids.)
  const firstCycle = new Set(calls.ids);
  calls.ids.clear();
  calls.getAlert = 0;
  await anomalyService.scanUser(TENANT, user, signIns, settings);
  const reread = [...calls.ids].filter((id) => firstCycle.has(id));
  assert.deepStrictEqual(reread, [], 'known alerts are not looked up again');
  assert.strictEqual(calls.getAlerts, 0);
});

test('sorting a large alert history parses each date once and stays under the bound', () => {
  const rows = [...partition.values()].map((a) => ({ ...a }));
  rows.push({ id: 'undated', tenantId: TENANT });
  const t0 = performance.now();
  const sorted = tableStorage.sortByDetectedAtDesc(rows);
  const ms = performance.now() - t0;
  assert.strictEqual(sorted.length, rows.length);
  for (let i = 1; i < sorted.length - 1; i++) {
    assert.ok(Date.parse(sorted[i - 1].detectedAt) >= Date.parse(sorted[i].detectedAt), `out of order at ${i}`);
  }
  assert.strictEqual(sorted[sorted.length - 1].id, 'undated', 'rows without a date go last');
  assert.ok(ms < BOUND_MS, `sorting ${rows.length} alerts took ${Math.round(ms)}ms`);
});

test('alertsStore.getAll filters to the tenant before sorting', () => {
  alertsStore.remember({ id: 'other-tenant-alert', tenantId: 'someone-else', detectedAt: '2026-11-10T00:00:00Z' });
  const mine = alertsStore.getAll(TENANT);
  assert.ok(mine.length >= 40);
  assert.ok(mine.every((a) => a.tenantId === TENANT));
  for (let i = 1; i < mine.length; i++) {
    assert.ok(Date.parse(mine[i - 1].detectedAt) >= Date.parse(mine[i].detectedAt));
  }
});
