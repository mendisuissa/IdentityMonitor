// #105 round 3: the 15-minute automation sweep blocked the event loop for minutes. For every open
// alert with a pending approval or an SLA breach, its dedupe check read, parsed and decorated the
// whole notification store (up to 500 items) and searched only the first 300, so keys stored
// further down were never found and were enqueued again: one more full read plus a full write,
// every sweep, for every alert. These tests pin the bound: the store is read at most twice and
// written at most once per tenant per sweep, dedupe covers every stored key, and no synchronous
// slice of the cron sweep grows with the number of open alerts.
// Run: node --test backend/tests/automation-sweep-stall.test.js
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');

const NC_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'nc-105-'));
process.env.NOTIFICATION_CENTER_DIR = NC_DIR;
process.env.AUDIT_DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'audit-105-'));

// No real Azure: every Table client call is stubbed before the services load.
process.env.AZURE_STORAGE_CONNECTION_STRING =
  'DefaultEndpointsProtocol=https;AccountName=test;AccountKey=dGVzdA==;TableEndpoint=http://127.0.0.1:9/test';
const { TableClient } = require('@azure/data-tables');
TableClient.prototype.createTable = async () => {};
TableClient.prototype.upsertEntity = async () => {};
TableClient.prototype.getEntity = async () => { const e = new Error('not found'); e.statusCode = 404; throw e; };

const tableStorage = require('../src/services/tableStorage');
const io = (v) => new Promise((r) => setImmediate(() => r(v)));

const TENANT = 'tenant-105-sweep';
const SMALL = 'tenant-105-small';
const OPEN_ALERTS = Number(process.env.BENCH_OPEN_ALERTS || 1000);
const SLICE_BOUND_MS = Number(process.env.SWEEP_SLICE_BOUND_MS || 100); // target ~50ms, headroom for CI
const SEVERITIES = ['critical', 'high', 'medium', 'low'];
const OLD = new Date(Date.now() - 3 * 24 * 3600 * 1000).toISOString(); // past every SLA

function openAlert(tenantId, i) {
  return {
    id: `${tenantId}-alert-${i}`, tenantId, status: 'open', severity: SEVERITIES[i % 4],
    anomalyType: 'NEW_COUNTRY', anomalyLabel: `New country ${i}`, userPrincipalName: `user${i}@example.test`,
    roles: ['Global Administrator'], detectedAt: OLD,
  };
}
const partitions = {
  [TENANT]: Array.from({ length: OPEN_ALERTS }, (_, i) => openAlert(TENANT, i)),
  [SMALL]: [{ ...openAlert(SMALL, 0), severity: 'critical' }],
};
tableStorage.getAlerts = async (tenantId) => { await io(); return (partitions[tenantId] || []).map((a) => ({ ...a })); };
tableStorage.saveAlert = async () => io();
tableStorage.getTenantSettings = async () => io({});
tableStorage.saveTenantSettings = async () => io();

const tenantRegistry = require('../src/services/tenantRegistry');
let sweepTenants = [TENANT];
tenantRegistry.getAllTenantIds = () => sweepTenants.slice();

const alertsStore = require('../src/services/alertsStore');
const workflowStore = require('../src/services/workflowStore');
const settingsService = require('../src/services/settingsService');
const notificationCenter = require('../src/services/notificationCenterService');
const automationService = require('../src/services/automationService');

// Counts synchronous reads and writes of notification store files.
const ioCount = { reads: 0, writes: 0 };
const realRead = fs.readFileSync;
const realWrite = fs.writeFileSync;
fs.readFileSync = function (p, ...rest) { if (String(p).startsWith(NC_DIR)) ioCount.reads += 1; return realRead.call(this, p, ...rest); };
fs.writeFileSync = function (p, ...rest) { if (String(p).startsWith(NC_DIR)) ioCount.writes += 1; return realWrite.call(this, p, ...rest); };

const storeFile = (tenantId) => path.join(NC_DIR, `${tenantId}.json`);
const readStored = (tenantId) => JSON.parse(realRead(storeFile(tenantId), 'utf8'));

// Records the longest gap between heartbeats while fn runs: a gap is a synchronous slice.
async function longestSlice(fn) {
  let last = performance.now();
  let worst = 0;
  const hb = setInterval(() => { const t = performance.now(); worst = Math.max(worst, t - last); last = t; }, 2);
  try { await fn(); } finally {
    clearInterval(hb);
    worst = Math.max(worst, performance.now() - last);
  }
  return worst;
}

async function prepare(tenantId) {
  await settingsService.getSettingsAsync(tenantId);
  await alertsStore.loadFromAzure(tenantId);
  const open = alertsStore.getOpen(tenantId);
  await Promise.all(open.map((a) => workflowStore.getAlertWorkflowAsync(tenantId, a.id)));
  // Cases past their SLA, as in production: each sweep escalates them and queues notifications.
  for (const a of open) workflowStore.patchAlertWorkflow(tenantId, a.id, { dueAt: OLD }, 'system');
}

test(`the cron sweep of ${OPEN_ALERTS} open alerts reads the store once and never blocks long`, async () => {
  await prepare(TENANT);
  // Earlier sweeps fill the store to its 500 cap and escalate every case to level 3; the measured
  // one is the steady state seen every 15 minutes.
  for (let i = 0; i < 3; i++) await automationService.runAutomationSweepAsync();
  assert.strictEqual(readStored(TENANT).length, 500);

  ioCount.reads = 0; ioCount.writes = 0;
  const t0 = performance.now();
  let results;
  const worst = await longestSlice(async () => { results = await automationService.runAutomationSweepAsync(); });
  const totalMs = performance.now() - t0;
  console.log(`[bench] open alerts=${OPEN_ALERTS} sweep total=${Math.round(totalMs)}ms longest slice=${Math.round(worst)}ms store reads=${ioCount.reads} writes=${ioCount.writes}`);

  assert.strictEqual(results.length, 1);
  assert.strictEqual(results[0].openAlerts, OPEN_ALERTS);
  assert.ok(ioCount.reads <= 2, `store read ${ioCount.reads} times in one sweep`);
  assert.ok(ioCount.writes <= 1, `store written ${ioCount.writes} times in one sweep`);
  assert.strictEqual(readStored(TENANT).length, 500, 'the 500 cap still holds');
  assert.ok(worst < SLICE_BOUND_MS, `longest synchronous slice ${Math.round(worst)}ms must stay under ${SLICE_BOUND_MS}ms`);

  // The synchronous single-tenant path (GET /alerts/cases) does the same store I/O.
  ioCount.reads = 0; ioCount.writes = 0;
  const s0 = performance.now();
  const sync = automationService.runAutomationSweep(TENANT);
  const syncMs = performance.now() - s0;
  console.log(`[bench] single-tenant sync sweep=${Math.round(syncMs)}ms store reads=${ioCount.reads} writes=${ioCount.writes}`);
  assert.strictEqual(sync[0].openAlerts, OPEN_ALERTS);
  assert.ok(ioCount.reads <= 2 && ioCount.writes <= 1);
});

test('dedupe covers every stored key, not only the first 300', async () => {
  await prepare(SMALL);
  const alertId = `${SMALL}-alert-0`;
  // A full store whose only copy of the alert's approval notification sits at position 450.
  const filler = Array.from({ length: 499 }, (_, i) => notificationCenter.decorate({
    id: `filler-${i}`, type: 'mention', uniqueKey: `filler-${i}`, status: 'unread',
    createdAt: new Date(Date.now() - (i + 1) * 60000).toISOString(),
  }));
  const approval = notificationCenter.decorate({
    id: 'kept-approval', type: 'approval', uniqueKey: `approval-${alertId}-1`, status: 'unread',
    createdAt: new Date(Date.now() - 451 * 60000).toISOString(),
  });
  filler.splice(450, 0, approval);
  realWrite(storeFile(SMALL), JSON.stringify(filler));

  // Single-tenant sweeps (GET /alerts/cases, POST /alerts/automation/run) stay synchronous.
  const out = automationService.runAutomationSweep(SMALL);
  assert.ok(Array.isArray(out), 'a single-tenant sweep returns its summary synchronously');
  assert.strictEqual(out[0].tenantId, SMALL);
  assert.strictEqual(out[0].pendingApprovals, 1);

  const after = readStored(SMALL);
  assert.strictEqual(after.length, 500, 'the 500 cap still holds');
  const count = (key) => after.filter((n) => n.uniqueKey === key).length;
  assert.strictEqual(count(`approval-${alertId}-1`), 1, 'the stored approval at position 450 is not enqueued again');
  assert.strictEqual(count(`sla-${alertId}-1`), 1, 'a new SLA breach is enqueued once');
  assert.strictEqual(after.filter((n) => n.metadata?.alertId === alertId && n.type !== 'approval').length, 2);
  for (let i = 1; i < after.length; i++) {
    assert.ok(after[i - 1].createdAt >= after[i].createdAt, `store out of order at ${i}`);
  }

  // The next sweep escalates to level 2: only that one key is new.
  const snapshot = JSON.stringify(after.map((n) => n.uniqueKey));
  automationService.runAutomationSweep(SMALL);
  const next = readStored(SMALL).map((n) => n.uniqueKey);
  assert.strictEqual(next[0], `sla-${alertId}-2`);
  assert.strictEqual(JSON.stringify(next.slice(1)), JSON.stringify(JSON.parse(snapshot).slice(0, 499)));
});

test('a batch flush keeps notifications written by others while the sweep ran', () => {
  const tenantId = 'tenant-105-batch';
  notificationCenter.enqueue(tenantId, { type: 'mention', uniqueKey: 'first', title: 'first' });
  const batch = notificationCenter.openBatch(tenantId);
  assert.strictEqual(batch.enqueueUnique({ type: 'mention', uniqueKey: 'first' }), false, 'a stored key is not queued');
  assert.strictEqual(batch.enqueueUnique({ type: 'approval', uniqueKey: 'a' }), true);
  assert.strictEqual(batch.enqueueUnique({ type: 'approval', uniqueKey: 'a' }), false, 'a key queued in this batch is not queued twice');
  assert.strictEqual(batch.enqueueUnique({ type: 'approval', uniqueKey: 'b' }), true);
  // Written by someone else between the batch's read and its flush.
  notificationCenter.enqueue(tenantId, { type: 'mention', uniqueKey: 'other' });
  notificationCenter.enqueue(tenantId, { type: 'approval', uniqueKey: 'b' });
  assert.strictEqual(batch.flush(), 1);
  assert.deepStrictEqual(readStored(tenantId).map((n) => n.uniqueKey), ['a', 'b', 'other', 'first']);
  assert.strictEqual(batch.flush(), 0, 'nothing is written twice');
});
