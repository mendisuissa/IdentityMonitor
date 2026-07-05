'use strict';
/**
 * internal.js — machine-to-machine API for credibility-agent (cloud-relay).
 *
 * Auth: Authorization: Bearer {IDENTITY_MONITOR_TOKEN}
 * All endpoints are read-only and return JSON.
 */

const express = require('express');
const { getRemediationHistory } = require('../services/remediationHistoryStore');
const tenantRegistry = require('../services/tenantRegistry');

const router = express.Router();

// ── Auth middleware ───────────────────────────────────────────────────────────

function requireInternalToken(req, res, next) {
  const expected = process.env.IDENTITY_MONITOR_TOKEN;
  if (!expected) {
    return res.status(503).json({ ok: false, error: 'Internal API not configured (IDENTITY_MONITOR_TOKEN missing).' });
  }
  const header = req.headers['authorization'] || '';
  const token  = header.startsWith('Bearer ') ? header.slice(7).trim() : '';
  if (!token || token !== expected) {
    return res.status(401).json({ ok: false, error: 'Unauthorized.' });
  }
  next();
}

router.use(requireInternalToken);

// ── GET /api/internal/health ──────────────────────────────────────────────────

router.get('/health', (_req, res) => {
  res.json({ ok: true, timestamp: new Date().toISOString() });
});

// ── GET /api/internal/remediation-history ────────────────────────────────────
// Returns remediation history across all tenants.
// Query params: limit (default 500), tenantId (optional filter)

router.get('/remediation-history', async (req, res) => {
  try {
    const limit    = Math.min(Number(req.query.limit || 500), 2000);
    const tenantId = req.query.tenantId || null;

    let tenantIds = [];
    if (tenantId) {
      tenantIds = [tenantId];
    } else {
      try {
        tenantIds = tenantRegistry.getActiveTenants().map(t => t.tenantId);
      } catch (_) {
        tenantIds = [];
      }
    }

    // Aggregate history across tenants
    const allRecords = [];
    for (const tid of tenantIds) {
      try {
        const records = await getRemediationHistory(tid, { limit });
        allRecords.push(...records);
      } catch (_) {}
    }

    // Sort newest first
    allRecords.sort((a, b) => (b.executedAt || '').localeCompare(a.executedAt || ''));
    const trimmed = allRecords.slice(0, limit);

    // Summary stats
    const byStatus = trimmed.reduce((acc, r) => {
      acc[r.status] = (acc[r.status] || 0) + 1;
      return acc;
    }, {});

    const failedIds = [...new Set(
      trimmed.filter(r => r.status === 'failed').map(r => r.cveId).filter(Boolean)
    )];

    const repeatedFailures = failedIds.filter(id =>
      trimmed.filter(r => r.cveId === id && r.status === 'failed').length >= 2
    );

    res.json({
      ok:      true,
      count:   trimmed.length,
      tenants: tenantIds.length,
      summary: byStatus,
      repeatedFailures,
      records: trimmed,
      fetchedAt: new Date().toISOString(),
    });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

// ── GET /api/internal/failed-vulnerabilities ──────────────────────────────────
// Returns only failed remediation items, grouped by cveId.

router.get('/failed-vulnerabilities', async (req, res) => {
  try {
    const tenantId = req.query.tenantId || null;

    let tenantIds = [];
    if (tenantId) {
      tenantIds = [tenantId];
    } else {
      try {
        tenantIds = tenantRegistry.getActiveTenants().map(t => t.tenantId);
      } catch (_) {
        tenantIds = [];
      }
    }

    const allFailed = [];
    for (const tid of tenantIds) {
      try {
        const records = await getRemediationHistory(tid, { limit: 1000 });
        allFailed.push(...records.filter(r => r.status === 'failed'));
      } catch (_) {}
    }

    // Group by cveId
    const grouped = {};
    for (const r of allFailed) {
      const key = r.cveId || 'unknown';
      if (!grouped[key]) {
        grouped[key] = {
          cveId:       key,
          productName: r.productName,
          category:    r.category,
          severity:    r.severity,
          failCount:   0,
          lastFailed:  r.executedAt,
          messages:    [],
          tenants:     new Set(),
        };
      }
      grouped[key].failCount++;
      grouped[key].tenants.add(r.tenantId);
      if (r.message) grouped[key].messages.push(r.message);
      if (r.executedAt > grouped[key].lastFailed) grouped[key].lastFailed = r.executedAt;
    }

    const items = Object.values(grouped)
      .map(g => ({ ...g, tenants: g.tenants.size, messages: [...new Set(g.messages)].slice(0, 3) }))
      .sort((a, b) => b.failCount - a.failCount);

    res.json({
      ok:        true,
      count:     items.length,
      items,
      fetchedAt: new Date().toISOString(),
    });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

module.exports = router;
