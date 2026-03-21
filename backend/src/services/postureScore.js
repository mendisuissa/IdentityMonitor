// postureScore.js — Security Posture Score engine
// Composite score 0-100 with breakdown across 5 dimensions

const alertsStore    = require('./alertsStore');
const settingsService = require('./settingsService');

// ─── Dimension weights ────────────────────────────────────────────────────
const DIMENSIONS = {
  adminExposure:      { weight: 0.30, label: 'Admin Exposure',     icon: '👤' },
  alertHygiene:       { weight: 0.25, label: 'Alert Hygiene',      icon: '🚨' },
  pimMaturity:        { weight: 0.20, label: 'PIM Maturity',       icon: '🔐' },
  notificationReady:  { weight: 0.15, label: 'Notification Setup', icon: '📡' },
  coverageDepth:      { weight: 0.10, label: 'Detection Coverage', icon: '🔍' }
};

function calculatePostureScore(tenantId, tenantHealth, pimData) {
  const settings = settingsService.getSettings(tenantId);
  const alerts   = alertsStore.getAll(tenantId);
  const now      = Date.now();
  const weekAgo  = now - 7 * 24 * 3600 * 1000;

  // ── 1. Admin Exposure (30%) ───────────────────────────────────────────
  // Fewer permanent admins + PIM configured = better score
  let adminScore = 100;
  const globalAdmins = tenantHealth?.privilegedUserCount || 0;
  if (globalAdmins > 10) adminScore -= 40;
  else if (globalAdmins > 5) adminScore -= 20;
  else if (globalAdmins > 2) adminScore -= 10;
  if (pimData) {
    if (!pimData.stats?.pimEnabled) adminScore -= 30;
    if (pimData.stats?.criticalPermanent > 0) adminScore -= 20;
  }
  adminScore = Math.max(0, adminScore);

  // ── 2. Alert Hygiene (25%) ────────────────────────────────────────────
  // Open critical/high = bad. Fast resolution = good.
  let alertScore = 100;
  const openCritical = alerts.filter(a => a.status === 'open' && a.severity === 'critical').length;
  const openHigh     = alerts.filter(a => a.status === 'open' && a.severity === 'high').length;
  const weekAlerts   = alerts.filter(a => new Date(a.detectedAt).getTime() > weekAgo);
  const resolved     = weekAlerts.filter(a => a.status === 'resolved').length;
  const resolutionRate = weekAlerts.length > 0 ? resolved / weekAlerts.length : 1;

  alertScore -= openCritical * 20;
  alertScore -= openHigh * 10;
  alertScore += Math.round((resolutionRate - 0.5) * 20); // bonus for high resolution
  alertScore = Math.max(0, Math.min(100, alertScore));

  // ── 3. PIM Maturity (20%) ─────────────────────────────────────────────
  let pimScore = pimData?.score || 50; // default 50 if not analyzed

  // ── 4. Notification Setup (15%) ───────────────────────────────────────
  let notifScore = 0;
  const notif = settings.notifications || {};
  if ((notif.adminEmails || []).length > 0)  notifScore += 40;
  if (notif.telegramBotToken && notif.telegramChatId) notifScore += 40;
  if (tenantHealth?.mailDeliveryOk)          notifScore += 10;
  if (tenantHealth?.telegramOk)              notifScore += 10;
  notifScore = Math.min(100, notifScore);

  // ── 5. Coverage Depth (10%) ───────────────────────────────────────────
  let coverageScore = 0;
  const rules = settings.detectionRules || {};
  const enabledRules = Object.values(rules).filter(r => r.enabled).length;
  const totalRules   = Object.keys(rules).length || 7;
  coverageScore += Math.round((enabledRules / totalRules) * 60);
  if (tenantHealth?.webhookActive)           coverageScore += 25;
  if (tenantHealth?.signInLogsAvailable)     coverageScore += 15;
  coverageScore = Math.min(100, coverageScore);

  // ── Weighted composite ────────────────────────────────────────────────
  const breakdown = {
    adminExposure:     { score: adminScore,   ...DIMENSIONS.adminExposure },
    alertHygiene:      { score: alertScore,   ...DIMENSIONS.alertHygiene },
    pimMaturity:       { score: pimScore,     ...DIMENSIONS.pimMaturity },
    notificationReady: { score: notifScore,   ...DIMENSIONS.notificationReady },
    coverageDepth:     { score: coverageScore,...DIMENSIONS.coverageDepth }
  };

  const composite = Math.round(
    Object.values(breakdown).reduce((sum, d) => sum + d.score * d.weight, 0)
  );

  const grade = composite >= 85 ? { letter: 'A', label: 'Excellent', color: '#2ecc71' }
              : composite >= 70 ? { letter: 'B', label: 'Good',      color: '#4a90d9' }
              : composite >= 55 ? { letter: 'C', label: 'Fair',      color: '#f5a623' }
              : composite >= 35 ? { letter: 'D', label: 'Poor',      color: '#ff6b35' }
              :                   { letter: 'F', label: 'Critical',  color: '#ff3b3b' };

  // ── Top recommendations based on lowest scores ─────────────────────────
  const recommendations = Object.entries(breakdown)
    .sort((a, b) => a[1].score - b[1].score)
    .slice(0, 3)
    .map(([key, dim]) => ({
      dimension: key,
      label:     dim.label,
      score:     dim.score,
      action:    getDimAction(key, dim.score, settings, pimData, tenantHealth)
    }))
    .filter(r => r.score < 80);

  return { composite, grade, breakdown, recommendations, calculatedAt: new Date().toISOString() };
}

function getDimAction(dim, score, settings, pimData, health) {
  const actions = {
    adminExposure:     score < 50 ? 'Enable PIM Just-in-Time for all permanent Global Admins'
                     : score < 80 ? 'Reduce permanent Global Admin count to ≤2'
                     : 'Review stale role assignments',
    alertHygiene:      score < 50 ? 'Resolve or dismiss all open Critical/High alerts'
                     : score < 80 ? 'Improve alert resolution rate — aim for >80% weekly'
                     : 'Maintain current alert hygiene',
    pimMaturity:       !pimData?.stats?.pimEnabled ? 'Enable Privileged Identity Management (requires Entra P2)'
                     : score < 70 ? 'Convert permanent Critical role assignments to Eligible'
                     : 'Review PIM activation policies and approval workflows',
    notificationReady: !settings.notifications?.telegramBotToken ? 'Configure Telegram bot for real-time interactive alerts'
                     : (settings.notifications?.adminEmails || []).length === 0 ? 'Add admin email addresses for alert notifications'
                     : 'Test alert delivery channels',
    coverageDepth:     !health?.webhookActive ? 'Enable Graph Webhooks for real-time sign-in detection'
                     : score < 70 ? 'Enable all detection rules in Settings → Detection'
                     : 'Consider enabling Off-Hours detection'
  };
  return actions[dim] || 'Review configuration';
}

module.exports = { calculatePostureScore, DIMENSIONS };
