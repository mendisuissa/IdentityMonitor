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

test('an event stays counted for the full 24 hours across hour boundaries', () => {
  const c = clock(Date.parse('2026-11-09T16:59:40Z'));
  const m = createStallMonitor({ now: c.now, log: () => {} });
  m.tick(); c.advance(5000); m.tick();             // stall at 16:59:45
  c.advance(Date.parse('2026-11-10T16:00:00Z') - c.now());
  assert.strictEqual(m.snapshot().stalls24h, 1);   // 23h later: still counted
  assert.strictEqual(m.snapshot().worstStallMs, 4500);
  c.advance(Date.parse('2026-11-10T17:01:00Z') - c.now());
  assert.strictEqual(m.snapshot().stalls24h, 0);   // past 24h (+1 min bucket): expired
});

test('an in-flight request that already matched a route is reported by its template', () => {
  const c = clock();
  const m = createStallMonitor({ now: c.now, log: () => {} });
  m.tick();
  const req = fakeReq('/api/remediation/auto-remediation/trigger', 'POST');
  m.middleware(req, fakeRes(), () => {});
  req.baseUrl = '/api/remediation'; req.route = { path: '/auto-remediation/trigger' };
  c.advance(4000); m.tick();                       // stall while still in flight
  assert.deepStrictEqual(m.snapshot().lastStall.active, ['POST /api/remediation/auto-remediation/trigger']);
});

test('a sync background job that blocked the loop is named in the stall', () => {
  const c = clock();
  const m = createStallMonitor({ now: c.now, log: () => {}, intervalMs: 500, stallMs: 1000 });
  m.tick();
  const job = m.track('automation-sweep', () => { c.advance(8000); return 3; });
  assert.strictEqual(job(), 3);                 // return value passes through
  m.tick();                                     // heartbeat fires after the job returned
  const s = m.snapshot();
  assert.strictEqual(s.stalls24h, 1);
  assert.deepStrictEqual(s.lastStall.active, ['job automation-sweep']);
  assert.deepStrictEqual(s.jobsRunning, []);
  c.advance(500); m.tick();                     // blame does not leak into the next stall
  c.advance(2000); m.tick();
  assert.deepStrictEqual(m.snapshot().lastStall.active, []);
});

test('an async background job is listed while it runs and removed when it settles', async () => {
  const c = clock();
  const logs = [];
  const m = createStallMonitor({ now: c.now, log: (x) => logs.push(x), slowRequestMs: 5000 });
  m.tick();
  let release;
  const job = m.track('scan-cycle', () => new Promise((r) => { release = r; }));
  const p = job();
  c.advance(3000); m.tick();                    // stall while the async job is running
  assert.deepStrictEqual(m.snapshot().lastStall.active, ['job scan-cycle']);
  assert.strictEqual(m.snapshot().jobsRunning[0].label, 'scan-cycle');
  c.advance(4000);
  release(); await p; await null;
  assert.deepStrictEqual(m.snapshot().jobsRunning, []);
  assert.ok(logs.some((l) => l.includes('slow job scan-cycle 7000ms')));
});

test('a job that throws or rejects is still removed', async () => {
  const m = createStallMonitor({ log: () => {} });
  assert.throws(() => m.track('boom', () => { throw new Error('x'); })(), /x/);
  await assert.rejects(m.track('reject', async () => { throw new Error('y'); })(), /y/);
  await null;
  assert.deepStrictEqual(m.snapshot().jobsRunning, []);
});

test('the shared monitor is one instance per process', () => {
  const { getStallMonitor } = require('../src/services/stallMonitor');
  assert.strictEqual(getStallMonitor(), getStallMonitor());
});

test('a stall records the CPU spent and calls it cpu or idle (#105)', () => {
  const c = clock();
  let cpuUs = 0;
  const logs = [];
  const m = createStallMonitor({
    now: c.now, log: (x) => logs.push(x), intervalMs: 500, stallMs: 1000,
    cpuUsage: () => ({ user: cpuUs, system: 0 }),
    memoryUsage: () => ({ rss: 300 * 1048576 }),
  });
  m.tick();
  c.advance(4500); cpuUs += 4400 * 1000; m.tick();   // 4000ms late, busy the whole time
  let s = m.snapshot();
  assert.strictEqual(s.lastStall.kind, 'cpu');
  assert.strictEqual(s.lastStall.cpuMs, 4400);
  assert.strictEqual(s.lastStall.rssMb, 300);
  c.advance(500); cpuUs += 10 * 1000; m.tick();      // on time: no stall, CPU baseline moves
  c.advance(6500); cpuUs += 50 * 1000; m.tick();     // 6000ms late, almost no CPU
  s = m.snapshot();
  assert.strictEqual(s.lastStall.kind, 'idle');
  assert.strictEqual(s.lastStall.cpuMs, 50);
  assert.deepStrictEqual(s.stallKinds24h, { cpu: 1, idle: 1 });
  assert.ok(logs.some((l) => l.includes('(idle, cpu 50ms, rss 300MB)')));
});

test('a failing CPU or memory reading never breaks the heartbeat', () => {
  const c = clock();
  const m = createStallMonitor({
    now: c.now, log: () => {},
    cpuUsage: () => { throw new Error('no cpu'); },
    memoryUsage: () => { throw new Error('no mem'); },
  });
  m.tick();
  c.advance(3000);
  assert.doesNotThrow(() => m.tick());
  const s = m.snapshot();
  assert.strictEqual(s.stalls24h, 1);
  assert.strictEqual(s.lastStall.rssMb, null);
  assert.strictEqual(s.lastStall.kind, 'idle');
});
