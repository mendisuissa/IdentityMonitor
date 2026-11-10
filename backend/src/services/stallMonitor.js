// Measures why IdentityMonitor hangs (KillWindowsApp-Mvp #105).
//
// Two signals, kept in memory and exposed as non-sensitive numbers:
// 1. Event-loop stalls: a heartbeat timer that fires late means synchronous work
//    (sync I/O, a large JSON parse, a tight loop) blocked every request.
// 2. Slow requests: a request that takes long while the loop stays healthy means
//    the wait is on I/O (Graph, Table Storage, the session store), not on CPU.
// Each stall and slow request is also logged once, so App Service logs show
// which route or timer was active when it happened.

const { monitorEventLoopDelay, PerformanceObserver } = require('perf_hooks');
const v8 = require('v8');

// Garbage-collection time, summed from V8's own gc performance entries. A stall
// that ran no job and no request but spent most of its time in GC means the heap
// is too full (a leak or an oversized cache), not that some code looped.
function createGcMeter() {
  const total = { count: 0, ms: 0, maxPauseMs: 0 };
  let obs = null;
  return {
    start() {
      if (obs) return;
      try {
        obs = new PerformanceObserver((list) => {
          for (const e of list.getEntries()) {
            total.count += 1;
            total.ms += e.duration;
            total.maxPauseMs = Math.max(total.maxPauseMs, e.duration);
          }
        });
        obs.observe({ entryTypes: ['gc'] });
      } catch { obs = null; }
    },
    stop() { if (obs) obs.disconnect(); obs = null; },
    read() { return { ...total }; },
  };
}

const DEFAULTS = {
  intervalMs: 500,          // heartbeat period
  stallMs: 1000,            // heartbeat late by more than this = stall
  slowRequestMs: 5000,      // request slower than this = slow request
  keep: 50,                 // most recent events kept per kind
  windowMs: 24 * 60 * 60 * 1000,
};

function createStallMonitor(opts = {}) {
  const cfg = { ...DEFAULTS, ...opts };
  const now = opts.now || (() => Date.now());
  const log = opts.log || ((msg) => console.warn(msg));
  // CPU and memory readings let a stall say what kind it was: CPU spent during
  // the late window close to lateMs means JavaScript kept the loop busy; CPU
  // near zero means the process was not running at all (blocked in sync I/O
  // such as the /home network share, or the host paused or swapped it).
  const cpuUsage = opts.cpuUsage || (() => process.cpuUsage());
  const memoryUsage = opts.memoryUsage || (() => process.memoryUsage());
  const heapLimit = opts.heapLimit || (() => v8.getHeapStatistics().heap_size_limit);
  const gc = opts.gcMeter || createGcMeter();
  let lastGcMs = 0;
  const mb = (n) => (Number.isFinite(n) ? Math.round(n / 1048576) : null);
  function memory() {
    try {
      const u = memoryUsage();
      let limit = null;
      try { limit = heapLimit(); } catch { limit = null; }
      return { rssMb: mb(u.rss), heapUsedMb: mb(u.heapUsed), heapLimitMb: mb(limit) };
    } catch { return { rssMb: null, heapUsedMb: null, heapLimitMb: null }; }
  }
  const cpuNow = () => { const u = cpuUsage(); return (u.user + u.system) / 1000; };
  let lastCpuMs = 0;
  const stalls = [];
  const slow = [];
  const inFlight = new Map();
  const jobs = new Map();    // background jobs (timers, cron) currently running
  let nextId = 0;
  let timer = null;
  let histogram = null;
  let expected = 0;
  let blamed = [];           // requests that finished while the loop was overdue
  const startedAt = now();
  // Rolling 24h counters in one-minute buckets, independent of the capped detail
  // lists. A bucket counts while any part of its minute is inside the window, so
  // an event is never dropped early (it may count for up to one extra minute).
  const BUCKET_MS = 60000;
  const buckets = new Map(); // minuteIndex -> { stalls, worstStallMs, slow }
  const inWindow = (k, t) => (k + 1) * BUCKET_MS > t - cfg.windowMs;

  function bucket(t) {
    const k = Math.floor(t / BUCKET_MS);
    if (!buckets.has(k)) {
      buckets.set(k, { stalls: 0, worstStallMs: 0, slow: 0 });
      for (const old of buckets.keys()) if (!inWindow(old, t)) buckets.delete(old);
    }
    return buckets.get(k);
  }

  function rolling(t) {
    const out = { stalls: 0, worstStallMs: 0, slow: 0, kinds: { cpu: 0, idle: 0 }, gcMs: 0, stallMs: 0 };
    for (const [k, b] of buckets) {
      if (!inWindow(k, t)) continue;
      out.stalls += b.stalls; out.slow += b.slow;
      if (b.kinds) { out.kinds.cpu += b.kinds.cpu; out.kinds.idle += b.kinds.idle; }
      out.worstStallMs = Math.max(out.worstStallMs, b.worstStallMs);
      out.gcMs += b.gcMs || 0; out.stallMs += b.stallMs || 0;
    }
    return out;
  }

  function push(list, item) {
    list.push(item);
    if (list.length > cfg.keep) list.shift();
  }

  // Called by the heartbeat; exported for tests.
  function tick() {
    const t = now();
    let cpuMs_ = lastCpuMs;
    try { cpuMs_ = cpuNow(); } catch { /* keep the last reading */ }
    let gcNow = lastGcMs;
    try { gcNow = gc.read().ms; } catch { /* keep the last reading */ }
    const lateMs = t - expected;
    if (expected && lateMs > cfg.stallMs) {
      const active = [...new Set([
        ...blamed,
        ...[...jobs.values()].map((j) => `job ${j.label}`),
        ...[...inFlight.values()].map((r) => `${r.method} ${templateOf(r.req, r.route)}`),
      ])].slice(0, 5);
      const b = bucket(t);
      b.stalls += 1;
      b.worstStallMs = Math.max(b.worstStallMs, lateMs);
      const cpuMs = Math.max(0, Math.round(cpuMs_ - lastCpuMs));
      const busy = cpuMs / Math.max(1, lateMs + cfg.intervalMs);
      const kind = busy >= 0.5 ? 'cpu' : 'idle';
      const { rssMb, heapUsedMb, heapLimitMb } = memory();
      const gcMs = Math.max(0, Math.round(gcNow - lastGcMs));
      push(stalls, { at: new Date(t).toISOString(), lateMs, cpuMs, gcMs, kind, rssMb, heapUsedMb, heapLimitMb, active });
      b.kinds = b.kinds || { cpu: 0, idle: 0 };
      b.kinds[kind] += 1;
      b.gcMs = (b.gcMs || 0) + gcMs;
      b.stallMs = (b.stallMs || 0) + lateMs;
      log(`[stall-monitor] event loop blocked ${lateMs}ms (${kind}, cpu ${cpuMs}ms, gc ${gcMs}ms, rss ${rssMb}MB, heap ${heapUsedMb}/${heapLimitMb}MB); in-flight: ${active.join(', ') || 'none'}`);
    }
    lastCpuMs = cpuMs_;
    lastGcMs = gcNow;
    blamed = [];
    expected = t + cfg.intervalMs;
  }

  function start() {
    if (timer) return;
    expected = now() + cfg.intervalMs;
    try { lastCpuMs = cpuNow(); } catch { lastCpuMs = 0; }
    try { gc.start(); lastGcMs = gc.read().ms; } catch { lastGcMs = 0; }
    timer = setInterval(tick, cfg.intervalMs);
    timer.unref();
    try {
      histogram = monitorEventLoopDelay({ resolution: 20 });
      histogram.enable();
    } catch { histogram = null; }
  }

  function stop() {
    if (timer) clearInterval(timer);
    timer = null;
    if (histogram) histogram.disable();
    try { gc.stop(); } catch { /* already stopped */ }
  }

  // Route labels never carry request values. Before routing, only the first two
  // path segments are kept (e.g. /api/settings); once Express has matched a
  // route, its template is used (e.g. /api/settings/whitelist/devices/:name).
  function prefixOf(req) {
    const p = String(req.originalUrl || req.url || '').split('?')[0];
    return p.split('/').slice(0, 3).join('/').slice(0, 40) + '/…';
  }
  function templateOf(req, fallback) {
    const tpl = req.route && typeof req.route.path === 'string' ? req.route.path : null;
    return tpl ? `${req.baseUrl || ''}${tpl}`.slice(0, 80) : fallback;
  }

  function middleware(req, res, next) {
    const id = ++nextId;
    const begin = now();
    const entry = { method: req.method, route: prefixOf(req), begin, req };
    inFlight.set(id, entry);
    let done = false;
    const finish = () => {
      if (done) return;
      done = true;
      inFlight.delete(id);
      entry.route = templateOf(req, entry.route);
      entry.req = null;
      const t = now();
      // The heartbeat is overdue: this request may be what blocked the loop.
      if (expected && t - expected > cfg.stallMs) blamed.push(`${entry.method} ${entry.route}`);
      const ms = t - begin;
      if (ms > cfg.slowRequestMs) {
        bucket(t).slow += 1;
        push(slow, { at: new Date(begin).toISOString(), method: entry.method, route: entry.route, ms, status: res.statusCode });
        log(`[stall-monitor] slow request ${entry.method} ${entry.route} ${ms}ms status ${res.statusCode}`);
      }
    };
    res.on('finish', finish);
    res.on('close', finish);
    next();
  }

  // Wraps a background job (setInterval / cron callback) so a stall names it.
  // A sync job that blocked the loop has already returned when the heartbeat
  // fires, so a job that finishes while the heartbeat is overdue is blamed, just
  // like a request. An async job is listed as active for as long as it runs.
  // Labels are fixed strings chosen by the caller, never request data.
  function track(label, fn) {
    const name = String(label).slice(0, 60);
    return function trackedJob(...args) {
      const id = ++nextId;
      const begin = now();
      jobs.set(id, { label: name, begin });
      const finish = () => {
        if (!jobs.delete(id)) return;
        const t = now();
        if (expected && t - expected > cfg.stallMs) blamed.push(`job ${name}`);
        const ms = t - begin;
        if (ms > cfg.slowRequestMs) log(`[stall-monitor] slow job ${name} ${ms}ms`);
      };
      let out;
      try {
        out = fn.apply(this, args);
      } catch (err) {
        finish();
        throw err;
      }
      if (out && typeof out.then === 'function') {
        out.then(finish, finish);
      } else {
        finish();
      }
      return out;
    };
  }

  function snapshot() {
    const t = now();
    const recent = (list) => list.filter((e) => t - Date.parse(e.at) <= cfg.windowMs);
    const r = recent(stalls);
    const roll = rolling(t);
    const oldest = [...inFlight.values()].reduce((m, e) => Math.max(m, t - e.begin), 0);
    // The histogram includes its own 20ms sampling period; report only the delay beyond it.
    const ms = (ns) => Math.max(0, Math.round(ns / 1e6) - 20);
    return {
      since: new Date(startedAt).toISOString(),
      eventLoop: histogram
        ? { p50Ms: ms(histogram.percentile(50)), p99Ms: ms(histogram.percentile(99)), maxMs: ms(histogram.max) }
        : null,
      stalls24h: roll.stalls,
      worstStallMs: roll.worstStallMs,
      stallKinds24h: roll.kinds,
      // Share of stalled time spent in garbage collection: near 1 means a full heap.
      stallGcShare24h: roll.stallMs ? Math.round((roll.gcMs / roll.stallMs) * 100) / 100 : null,
      memory: memory(),
      gc: (() => { try { const g = gc.read(); return { count: g.count, totalMs: Math.round(g.ms), maxPauseMs: Math.round(g.maxPauseMs) }; } catch { return null; } })(),
      lastStall: r.length ? r[r.length - 1] : null,
      slowRequests24h: roll.slow,
      lastSlowRequest: slow.length ? slow[slow.length - 1] : null,
      inFlight: inFlight.size,
      oldestInFlightMs: oldest,
      jobsRunning: [...jobs.values()].map((j) => ({ label: j.label, ms: t - j.begin })).slice(0, 10),
    };
  }

  return { start, stop, tick, middleware, track, snapshot };
}

// One monitor per process, shared by index.js and the job runners.
let shared = null;
function getStallMonitor() {
  if (!shared) shared = createStallMonitor();
  return shared;
}

module.exports = { createStallMonitor, getStallMonitor, createGcMeter };
