#!/usr/bin/env node
/**
 * Smoke Tests — IdentityMonitor
 * Run against staging before promoting to production.
 *
 * Usage:
 *   TEST_URL=https://my-staging.azurewebsites.net node backend/tests/smoke.js
 */

const BASE_URL = process.env.TEST_URL || 'http://localhost:3001';

let passed = 0;
let failed = 0;
const results = [];

async function check(name, fn) {
  try {
    await fn();
    console.log(`  ✅ ${name}`);
    results.push({ name, ok: true });
    passed++;
  } catch (err) {
    console.error(`  ❌ ${name}: ${err.message}`);
    results.push({ name, ok: false, error: err.message });
    failed++;
  }
}

async function get(path, expectedStatus = 200, retries = 3) {
  let lastErr;
  for (let i = 0; i < retries; i++) {
    try {
      const res = await fetch(`${BASE_URL}${path}`, {
        headers: { 'Accept': 'application/json' },
        signal: AbortSignal.timeout(10000)
      });
      if (res.status !== expectedStatus) {
        throw new Error(`Expected ${expectedStatus}, got ${res.status}`);
      }
      return res;
    } catch (err) {
      lastErr = err;
      if (i < retries - 1) await new Promise(r => setTimeout(r, 3000));
    }
  }
  throw lastErr;
}

async function run() {
  console.log(`\n🔍 Smoke Tests — ${BASE_URL}\n`);

  // ── Health ────────────────────────────────────────────────────────
  await check('GET /api/health returns 200', async () => {
    const res = await get('/api/health');
    const body = await res.json();
    if (body.status !== 'ok') throw new Error(`status = ${body.status}`);
  });

  await check('GET /api/health includes version', async () => {
    const res = await get('/api/health');
    const body = await res.json();
    if (!body.version) throw new Error('missing version field');
  });

  // ── Frontend ──────────────────────────────────────────────────────
  await check('GET / returns HTML (React app)', async () => {
    const res = await fetch(`${BASE_URL}/`);
    if (res.status !== 200) throw new Error(`status ${res.status}`);
    const text = await res.text();
    if (!text.includes('<div id="root">')) throw new Error('missing React root div');
  });

  // ── API Endpoints (accept 200 or 401 — app is secured, auth required) ──
  await check('GET /api/alerts responds (200 or 401)', async () => {
    const res = await fetch(`${BASE_URL}/api/alerts`, { signal: AbortSignal.timeout(10000) });
    if (![200, 401].includes(res.status)) throw new Error(`unexpected status ${res.status}`);
  });

  await check('GET /api/alerts/stats responds (200 or 401)', async () => {
    const res = await fetch(`${BASE_URL}/api/alerts/stats`, { signal: AbortSignal.timeout(10000) });
    if (![200, 401].includes(res.status)) throw new Error(`unexpected status ${res.status}`);
  });

  await check('GET /api/settings responds (200 or 401)', async () => {
    const res = await fetch(`${BASE_URL}/api/settings`, { signal: AbortSignal.timeout(10000) });
    if (![200, 401].includes(res.status)) throw new Error(`unexpected status ${res.status}`);
  });

  await check('GET /api/device-actions responds (200 or 401)', async () => {
    const res = await fetch(`${BASE_URL}/api/device-actions`, { signal: AbortSignal.timeout(10000) });
    if (![200, 401].includes(res.status)) throw new Error(`unexpected status ${res.status}`);
  });

  await check('GET /api/reports/risk-posture responds (200 or 401)', async () => {
    const res = await fetch(`${BASE_URL}/api/reports/risk-posture`, { signal: AbortSignal.timeout(10000) });
    if (![200, 401].includes(res.status)) throw new Error(`unexpected status ${res.status}`);
  });

  await check('GET /api/audit responds (200 or 401)', async () => {
    const res = await fetch(`${BASE_URL}/api/audit`, { signal: AbortSignal.timeout(10000) });
    if (![200, 401].includes(res.status)) throw new Error(`unexpected status ${res.status}`);
  });

  await check('GET /api/alerts/cases responds (200 or 401)', async () => {
    const res = await fetch(`${BASE_URL}/api/alerts/cases`, { signal: AbortSignal.timeout(10000) });
    if (![200, 401].includes(res.status)) throw new Error(`unexpected status ${res.status}`);
  });

  // ── Summary ───────────────────────────────────────────────────────
  console.log('\n' + '─'.repeat(40));
  console.log(`  Total:  ${passed + failed}`);
  console.log(`  Passed: ${passed} ✅`);
  console.log(`  Failed: ${failed} ${failed > 0 ? '❌' : ''}`);
  console.log('─'.repeat(40) + '\n');

  if (failed > 0) {
    console.error('Smoke tests FAILED — do not promote to production.\n');
    process.exit(1);
  } else {
    console.log('All smoke tests PASSED ✅ — safe to promote to production.\n');
    process.exit(0);
  }
}

run().catch(err => {
  console.error('Smoke test runner crashed:', err.message);
  process.exit(1);
});
