// #105: the stall monitor must record event-loop stalls and slow requests,
// and keep ids and query strings out of what it exposes.
// Run: node --test backend/tests/stall-monitor.test.js
const test = require('node:test');
const assert = require('node:assert');
const { EventEmitter } = require('events');
const { createStallMonitor } = require('../src/services/stallMonitor');

function clock(start = Date.parse('2026-11-09T16:00:00Z')) {
  let t = start;
  return { now: () => t, advance: (ms) => { t += ms; } };
}

function fakeReq(url, method = 'GET') { return { method, originalUrl: url }; }
function fakeRes(status = 200) { const r = new EventEmitter(); r.statusCode = status; return r; }

test('a late heartbeat is recorded as a stall with the in-flight route', () => {
  const c = clock();
  const logs = [];
  const m = createStallMonitor({ now: c.now, log: (x) => logs.push(x), intervalMs: 500, stallMs: 1000 });
  m.tick();                       // arms the first expectation
  const res = fakeRes();
  m.middleware(fakeReq('/api/alerts/cases?tenant=abc'), res, () => {});
  c.advance(500); m.tick();       // on time: no stall
  c.advance(3500); m.tick();      // 3000ms late
  const s = m.snapshot();
  assert.strictEqual(s.stalls24h, 1);
  assert.strictEqual(s.worstStallMs, 3000);
  assert.deepStrictEqual(s.lastStall.active, ['GET /api/alerts/cases']);
  assert.strictEqual(s.inFlight, 1);
  assert.strictEqual(s.oldestInFlightMs, 4000);
  assert.ok(logs.some((l) => l.includes('event loop blocked 3000ms')));
});

test('a slow request is recorded once, with ids stripped', () => {
  const c = clock();
  const m = createStallMonitor({ now: c.now, log: () => {}, slowRequestMs: 5000 });
  const res = fakeRes(504);
  m.middleware(fakeReq('/api/users/0f3a9c12-77aa-4b1e-9d2c-123456789abc/signins?x=1'), res, () => {});
  c.advance(6000);
  res.emit('finish'); res.emit('close');
  const s = m.snapshot();
  assert.strictEqual(s.slowRequests24h, 1);
  assert.strictEqual(s.lastSlowRequest.route, '/api/users/:id/signins');
  assert.strictEqual(s.lastSlowRequest.status, 504);
  assert.strictEqual(s.inFlight, 0);
});

test('fast requests and events older than 24 hours are not counted', () => {
  const c = clock();
  const m = createStallMonitor({ now: c.now, log: () => {} });
  m.tick(); c.advance(5000); m.tick();          // one stall
  const res = fakeRes();
  m.middleware(fakeReq('/api/health'), res, () => {});
  c.advance(100); res.emit('finish');
  assert.strictEqual(m.snapshot().slowRequests24h, 0);
  c.advance(25 * 60 * 60 * 1000);
  assert.strictEqual(m.snapshot().stalls24h, 0);
});

test('start and stop leave no timer running', () => {
  const m = createStallMonitor({ log: () => {} });
  m.start(); m.start(); m.stop();
  assert.ok(m.snapshot().since);
});
