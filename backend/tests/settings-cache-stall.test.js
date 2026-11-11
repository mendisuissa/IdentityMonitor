// #105 round 2: event-loop stalls of up to 317 s after the scan fix, pure CPU, low GC share and
// RSS far above the JS heap. The cause: every settings cache miss started its own Azure read,
// and every read decrypted the stored Telegram token with a key derived by crypto.scryptSync
// (~40 ms of CPU and a 16 MB off-heap buffer per call, never cached). The 15-min automation
// sweep calls getSettings 2-4 times per open alert; once the 60 s TTL has lapsed, each call
// missed, so N open alerts queued ~3N reads whose completions then ran ~3N scrypt derivations
// back to back. These tests pin the bound: concurrent misses share one read, the key is derived
// once per process, and the sweep pattern over a large alert backlog has no long sync slice.
// Run: node --test backend/tests/settings-cache-stall.test.js
const test = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');

process.env.AZURE_STORAGE_CONNECTION_STRING =
  'DefaultEndpointsProtocol=https;AccountName=test;AccountKey=dGVzdA==;TableEndpoint=http://127.0.0.1:9/test';
// A passphrase (not 64 hex chars), as in production: this is the path that runs scrypt.
process.env.ENCRYPTION_KEY = 'a-passphrase-not-a-hex-key-105';

const calls = { scrypt: 0, reads: 0 };
const realScrypt = crypto.scryptSync;
crypto.scryptSync = (...args) => { calls.scrypt += 1; return realScrypt(...args); };

const { TableClient } = require('@azure/data-tables');
TableClient.prototype.createTable = async () => {};
TableClient.prototype.upsertEntity = async () => {};

const tableStorage = require('../src/services/tableStorage');
const { encrypt } = require('../src/services/encryptionService');
const io = (v) => new Promise((r) => setImmediate(() => r(v)));

const TENANT = 'tenant-105-settings';
const OPEN_ALERTS = 2000;        // open-alert backlog the sweep walks
const BOUND_MS = 1000;           // longest allowed synchronous slice

const stored = {
  tenantId: TENANT,
  updatedAt: '2026-11-01T00:00:00.000Z',
  billing: { plan: 'active' },
  notifications: { telegramBotToken: encrypt('123456:telegram-token'), telegramChatId: '42', adminEmails: [] },
  responsePolicies: { critical: { requireApproval: true, allowedActions: ['monitor', 'revoke'] } },
};
tableStorage.getTenantSettings = async () => { calls.reads += 1; await io(); return { ...stored }; };
tableStorage.saveTenantSettings = async () => io();

const settingsService = require('../src/services/settingsService');
const policyEngine = require('../src/services/policyEngineService');

// Moves Date.now() forward so the 60 s settings TTL lapses without waiting.
let skewMs = 0;
const realNow = Date.now;
Date.now = () => realNow() + skewMs;

// Longest gap between heartbeats while fn runs and its follow-up I/O settles.
async function longestSlice(fn) {
  let worst = 0;
  let last = performance.now();
  const hb = setInterval(() => { const t = performance.now(); worst = Math.max(worst, t - last); last = t; }, 5);
  try {
    await fn();
    for (let i = 0; i < 50; i++) await new Promise((r) => setTimeout(r, 5));
  } finally {
    clearInterval(hb);
  }
  return Math.max(worst, performance.now() - last);
}

test('the encryption key is derived once, not on every decrypt', async () => {
  const { decrypt } = require('../src/services/encryptionService');
  const before = calls.scrypt;
  const token = encrypt('abc');
  for (let i = 0; i < 50; i++) assert.strictEqual(decrypt(token), 'abc');
  assert.ok(calls.scrypt - before <= 1, `scryptSync ran ${calls.scrypt - before} times for 51 encrypt/decrypt calls`);
});

test('concurrent settings misses share one Azure read', async () => {
  const s = await settingsService.getSettingsAsync(TENANT);
  assert.strictEqual(s.notifications.telegramBotToken, '123456:telegram-token');
  skewMs += 61 * 1000; // TTL lapsed
  const readsBefore = calls.reads;
  for (let i = 0; i < 500; i++) settingsService.getSettings(TENANT);
  await Promise.all(Array.from({ length: 20 }, () => settingsService.getSettingsAsync(TENANT)));
  for (let i = 0; i < 20; i++) await io();
  assert.strictEqual(calls.reads - readsBefore, 1, `${calls.reads - readsBefore} reads for one lapsed entry`);
});

test('an expired entry keeps serving the tenant\'s real settings while it refreshes', async () => {
  await settingsService.getSettingsAsync(TENANT);
  skewMs += 61 * 1000;
  const s = settingsService.getSettings(TENANT);
  assert.strictEqual(s.billing.plan, 'active', 'fell back to free-plan defaults on a lapsed cache');
  assert.strictEqual(s.notifications.telegramChatId, '42');
  for (let i = 0; i < 5; i++) await io();
});

test(`the sweep pattern over ${OPEN_ALERTS} open alerts has no sync slice over ${BOUND_MS} ms`, async () => {
  await settingsService.getSettingsAsync(TENANT);
  skewMs += 61 * 1000;
  const scryptBefore = calls.scrypt;
  const readsBefore = calls.reads;
  const alerts = Array.from({ length: OPEN_ALERTS }, (_, i) => ({
    id: `a-${i}`, tenantId: TENANT, severity: i % 2 ? 'critical' : 'high', roles: ['Global Administrator'],
  }));
  const worst = await longestSlice(async () => {
    // automationService.evaluateTenant: getSettings + buildPolicyDecision (+ getExecutionCheck) per alert.
    for (const a of alerts) {
      settingsService.getSettings(TENANT);
      policyEngine.buildPolicyDecision(TENANT, a);
      policyEngine.getExecutionCheck(TENANT, a, 'revoke', {});
    }
  });
  const reads = calls.reads - readsBefore;
  const scrypts = calls.scrypt - scryptBefore;
  console.log(`[105] sweep over ${OPEN_ALERTS} alerts: ${reads} settings reads, ${scrypts} scrypt derivations, longest sync slice ${Math.round(worst)} ms`);
  assert.ok(reads <= 1, `${reads} settings reads for one lapsed entry`);
  assert.ok(scrypts <= 1, `${scrypts} scrypt derivations`);
  assert.ok(worst < BOUND_MS, `longest synchronous slice ${Math.round(worst)} ms`);
});
