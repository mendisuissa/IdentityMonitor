// superadmin.js — Hidden super-admin view: all tenants connected to the system
// Access restricted to a fixed allowlist of email addresses.

const express        = require('express');
const router         = express.Router();
const tenantRegistry = require('../services/tenantRegistry');
const settingsService = require('../services/settingsService');
const tableStorage   = require('../services/tableStorage');
const jobRunner      = require('../services/jobRunner');

const SUPERADMIN_EMAILS = (process.env.SUPERADMIN_EMAILS || '')
  .split(',').map(e => e.trim().toLowerCase()).filter(Boolean);

function isSuperAdmin(req) {
  if (!SUPERADMIN_EMAILS.length) return false;
  const email = (req.session?.tenant?.userEmail || '').toLowerCase().trim();
  return SUPERADMIN_EMAILS.includes(email);
}

// GET /api/superadmin/tenants
router.get('/tenants', async (req, res) => {
  if (!isSuperAdmin(req)) return res.status(403).json({ error: 'Access denied' });

  try {
    const tenants = await tenantRegistry.getAllTenants();

    // Run health check for any tenant that has no health data yet (fire-and-forget)
    tenants.forEach(t => {
      if (!t.health || Object.keys(t.health).length === 0) {
        jobRunner.checkTenantHealth(t.tenantId).catch(() => {});
      }
    });

    // Enrich each tenant with settings + alert count
    const enriched = await Promise.all(tenants.map(async t => {
      let alertCount = 0;
      let plan = 'unknown';
      let trialEndsAt = null;
      let adminEmails = [];
      let telegramConfigured = false;

      try {
        const settings = await settingsService.getSettingsAsync(t.tenantId);
        plan = settings.billing?.plan || 'trial';
        trialEndsAt = settings.billing?.trialEndsAt || null;
        adminEmails = settingsService.getAdminEmails(settings);
        telegramConfigured = !!(settings.notifications?.telegramBotToken && settings.notifications?.telegramChatId);
      } catch (_) {}

      try {
        const alerts = await tableStorage.getAlerts(t.tenantId, {});
        alertCount = (alerts || []).length;
      } catch (_) {}

      return {
        tenantId:          t.tenantId,
        tenantName:        t.tenantName || t.tenantId,
        primaryEmail:      t.primaryEmail || '',
        connectedAt:       t.connectedAt || null,
        lastSeenAt:        t.lastSeenAt  || null,
        lastScanAt:        t.health?.lastScanAt || null,
        lastAlertAt:       t.lastAlertAt || null,
        graphPermissions:  t.health?.graphPermissionsOk ?? null,
        signInLogsOk:      t.health?.signInLogsAvailable ?? null,
        webhookActive:     t.health?.webhookActive ?? false,
        privilegedUsers:   t.health?.privilegedUserCount ?? null,
        telegramOk:        t.health?.telegramOk ?? null,
        plan,
        trialEndsAt,
        adminEmails,
        telegramConfigured,
        alertCount
      };
    }));

    // Sort: most recently seen first
    enriched.sort((a, b) => {
      const ta = a.lastSeenAt || a.connectedAt || '';
      const tb = b.lastSeenAt || b.connectedAt || '';
      return tb.localeCompare(ta);
    });

    res.json({ tenants: enriched, count: enriched.length, asOf: new Date().toISOString() });
  } catch (err) {
    console.error('[SuperAdmin] Error:', err.message);
    res.status(500).json({ error: "Internal server error" });
  }
});

// GET /api/superadmin/supervisor — proxy to cloud-relay supervisor status
router.get('/supervisor', async (req, res) => {
  if (!isSuperAdmin(req)) return res.status(403).json({ error: 'Access denied' });

  const relayUrl   = process.env.CLOUD_RELAY_URL;
  const relayToken = process.env.KERNEL_API_SECRET;
  if (!relayUrl || !relayToken) {
    return res.json({ ok: false, error: 'CLOUD_RELAY_URL or KERNEL_API_SECRET not configured', recentRuns: [], summary: { stuckMissions: 0, openCriticals: 0, lastEscalated: false } });
  }

  try {
    const r = await fetch(`${relayUrl}/api/supervisor/status`, {
      headers: { Authorization: `Bearer ${relayToken}` },
      signal:  AbortSignal.timeout(8000),
    });
    if (!r.ok) return res.json({ ok: false, error: `Relay returned ${r.status}`, recentRuns: [], summary: { stuckMissions: 0, openCriticals: 0, lastEscalated: false } });
    const data = await r.json();
    res.json(data);
  } catch (err) {
    res.json({ ok: false, error: err.message, recentRuns: [], summary: { stuckMissions: 0, openCriticals: 0, lastEscalated: false } });
  }
});

module.exports = router;
