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
  assert.deepStrictEqual(s.lastStall.active, ['GET /api/alerts/…']);
  assert.strictEqual(s.inFlight, 1);
  assert.strictEqual(s.oldestInFlightMs, 4000);
  assert.ok(logs.some((l) => l.includes('event loop blocked 3000ms')));
});

test('a slow request is recorded once, with ids stripped', () => {
  const c = clock();
  const m = createStallMonitor({ now: c.now, log: () => {}, slowRequestMs: 5000 });
  const res = fakeRes(504);
  const req = fakeReq('/api/users/0f3a9c12-77aa-4b1e-9d2c-123456789abc/signins?x=1');
  m.middleware(req, res, () => {});
  req.baseUrl = '/api/users'; req.route = { path: '/:id/signins' };   // set by Express routing
  c.advance(6000);
  res.emit('finish'); res.emit('close');
  const s = m.snapshot();
  assert.strictEqual(s.slowRequests24h, 1);
  assert.strictEqual(s.lastSlowRequest.route, '/api/users/:id/signins');
  assert.ok(!JSON.stringify(s).includes('0f3a9c12'));
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

test('request values without digits never reach the snapshot or the log', () => {
  const c = clock();
  const logs = [];
  const m = createStallMonitor({ now: c.now, log: (x) => logs.push(x) });
  m.tick();
  const res = fakeRes();
  m.middleware(fakeReq('/api/settings/whitelist/devices/CEO-LAPTOP', 'DELETE'), res, () => {});
  c.advance(7000); m.tick();                       // stall while in flight, before routing
  res.emit('finish');                              // unmatched route: prefix only
  const out = JSON.stringify(m.snapshot()) + logs.join('\n');
  assert.ok(!out.includes('CEO-LAPTOP'));
  assert.ok(out.includes('DELETE /api/settings/…'));
});

test('a request that blocks and then finishes before the heartbeat is still blamed', () => {
  const c = clock();
  const m = createStallMonitor({ now: c.now, log: () => {}, intervalMs: 500, stallMs: 1000 });
  m.tick();
  const req = fakeReq('/api/reports/export');
  const res = fakeRes();
  m.middleware(req, res, () => {});
  req.baseUrl = '/api/reports'; req.route = { path: '/export' };
  c.advance(2500);                                 // synchronous block, below slowRequestMs
  res.emit('finish');                              // finishes before the late heartbeat runs
  m.tick();
  const s = m.snapshot();
  assert.strictEqual(s.stalls24h, 1);
  assert.deepStrictEqual(s.lastStall.active, ['GET /api/reports/export']);
  assert.strictEqual(s.slowRequests24h, 0);
});

test('24-hour counters and the worst stall are not capped by the detail buffer', () => {
  const c = clock();
  const m = createStallMonitor({ now: c.now, log: () => {}, keep: 50 });
  for (let i = 0; i < 51; i++) {                   // heartbeat not armed yet: slow requests only
    const res = fakeRes();
    m.middleware(fakeReq('/api/health'), res, () => {});
    c.advance(6000); res.emit('finish');
  }
  m.tick(); c.advance(9000); m.tick();             // worst stall first: 8500ms late, later evicted
  for (let i = 0; i < 60; i++) { m.tick(); c.advance(2000); m.tick(); }
  const s = m.snapshot();
  assert.strictEqual(s.slowRequests24h, 51);
  assert.strictEqual(s.worstStallMs, 8500);
  assert.ok(s.stalls24h > 50);
});
