// audit.js — mounted at /api/audit
// Proxies to the audit logic already in settingsService / auditLog
const express  = require('express');
const router   = express.Router();
const auditLog = require('../services/auditLog');
const { requirePermission } = require('../services/accessControl');

function getTenantId(req) {
  return req.session?.tenant?.tenantId || (process.env.MOCK_MODE === 'true' ? 'mock-tenant' : null);
}

// GET /api/audit
router.get('/', (req, res) => {
  const tenantId = getTenantId(req);
  if (!tenantId) return res.status(401).json({ error: 'Not authenticated' });
  const { limit = 100, action, since, actor, q } = req.query;
  const entries = auditLog.getLog(tenantId, { limit: parseInt(limit), action, since, actor });
  const filtered = q
    ? entries.filter(e => JSON.stringify(e).toLowerCase().includes(String(q).toLowerCase()))
    : entries;
  const stats = auditLog.getStats(tenantId);
  res.json({ entries: filtered, stats });
});

// GET /api/audit/export
router.get('/export', requirePermission('audit.export'), (req, res) => {
  const tenantId = getTenantId(req);
  if (!tenantId) return res.status(401).json({ error: 'Not authenticated' });
  const { action, actor, since } = req.query;
  const entries = auditLog.getLog(tenantId, { action, actor, since, limit: 1000 });
  const rows = [['timestamp', 'action', 'actor', 'details']].concat(
    entries.map(e => [e.timestamp, e.action, e.actor, JSON.stringify(e)])
  );
  const csv = rows.map(r =>
    r.map(v => '"' + String(v ?? '').replace(/"/g, '""') + '"').join(',')
  ).join('\n');
  res.setHeader('Content-Type', 'text/csv');
  res.setHeader('Content-Disposition', 'attachment; filename="audit-export.csv"');
  res.send(csv);
});

module.exports = router;
