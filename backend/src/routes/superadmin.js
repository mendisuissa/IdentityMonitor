// superadmin.js — Hidden super-admin view: all tenants connected to the system
// Access restricted to a fixed allowlist of email addresses.

const express        = require('express');
const router         = express.Router();
const tenantRegistry = require('../services/tenantRegistry');
const settingsService = require('../services/settingsService');
const tableStorage   = require('../services/tableStorage');

const SUPERADMIN_EMAILS = [
  'menahem@modernendpoint.tech',
  'menahem@365-poc.com'
];

function isSuperAdmin(req) {
  const email = (req.session?.tenant?.userEmail || '').toLowerCase().trim();
  return SUPERADMIN_EMAILS.map(e => e.toLowerCase()).includes(email);
}

// GET /api/superadmin/tenants
router.get('/tenants', async (req, res) => {
  if (!isSuperAdmin(req)) return res.status(403).json({ error: 'Access denied' });

  try {
    const tenants = tenantRegistry.getAllTenants();

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
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
