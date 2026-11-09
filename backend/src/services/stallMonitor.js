// Measures why IdentityMonitor hangs (KillWindowsApp-Mvp #105).
//
// Two signals, kept in memory and exposed as non-sensitive numbers:
// 1. Event-loop stalls: a heartbeat timer that fires late means synchronous work
//    (sync I/O, a large JSON parse, a tight loop) blocked every request.
// 2. Slow requests: a request that takes long while the loop stays healthy means
//    the wait is on I/O (Graph, Table Storage, the session store), not on CPU.
// Each stall and slow request is also logged once, so App Service logs show
// which route or timer was active when it happened.

const { monitorEventLoopDelay } = require('perf_hooks');

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
  const stalls = [];
  const slow = [];
  const inFlight = new Map();
  let nextId = 0;
  let timer = null;
  let histogram = null;
  let expected = 0;
  const startedAt = now();

  function push(list, item) {
    list.push(item);
    if (list.length > cfg.keep) list.shift();
  }

  // Called by the heartbeat; exported for tests.
  function tick() {
    const t = now();
    const lateMs = t - expected;
    if (expected && lateMs > cfg.stallMs) {
      const active = [...inFlight.values()].map((r) => `${r.method} ${r.route}`).slice(0, 5);
      push(stalls, { at: new Date(t).toISOString(), lateMs, active });
      log(`[stall-monitor] event loop blocked ${lateMs}ms; in-flight: ${active.join(', ') || 'none'}`);
    }
    expected = t + cfg.intervalMs;
  }

  function start() {
    if (timer) return;
    expected = now() + cfg.intervalMs;
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
  }

  // Route label without ids or query strings, so nothing sensitive is kept.
  function routeOf(req) {
    const p = String(req.originalUrl || req.url || '').split('?')[0];
    return p.split('/').map((seg) => (/\d/.test(seg) && seg.length > 6 ? ':id' : seg)).join('/').slice(0, 80);
  }

  function middleware(req, res, next) {
    const id = ++nextId;
    const begin = now();
    const entry = { method: req.method, route: routeOf(req), begin };
    inFlight.set(id, entry);
    let done = false;
    const finish = () => {
      if (done) return;
      done = true;
      inFlight.delete(id);
      const ms = now() - begin;
      if (ms > cfg.slowRequestMs) {
        push(slow, { at: new Date(begin).toISOString(), method: entry.method, route: entry.route, ms, status: res.statusCode });
        log(`[stall-monitor] slow request ${entry.method} ${entry.route} ${ms}ms status ${res.statusCode}`);
      }
    };
    res.on('finish', finish);
    res.on('close', finish);
    next();
  }

  function snapshot() {
    const t = now();
    const recent = (list) => list.filter((e) => t - Date.parse(e.at) <= cfg.windowMs);
    const r = recent(stalls);
    const oldest = [...inFlight.values()].reduce((m, e) => Math.max(m, t - e.begin), 0);
    // The histogram includes its own 20ms sampling period; report only the delay beyond it.
    const ms = (ns) => Math.max(0, Math.round(ns / 1e6) - 20);
    return {
      since: new Date(startedAt).toISOString(),
      eventLoop: histogram
        ? { p50Ms: ms(histogram.percentile(50)), p99Ms: ms(histogram.percentile(99)), maxMs: ms(histogram.max) }
        : null,
      stalls24h: r.length,
      worstStallMs: r.reduce((m, e) => Math.max(m, e.lateMs), 0),
      lastStall: r.length ? r[r.length - 1] : null,
      slowRequests24h: recent(slow).length,
      lastSlowRequest: slow.length ? slow[slow.length - 1] : null,
      inFlight: inFlight.size,
      oldestInFlightMs: oldest,
    };
  }

  return { start, stop, tick, middleware, snapshot };
}

module.exports = { createStallMonitor };
