// weeklyDigest.js — automated weekly security digest email
// Sent every Sunday to CISO/admin with PDF-quality HTML email

const emailService   = require('./emailService');
const alertsStore    = require('./alertsStore');
const settingsService = require('./settingsService');

async function generateAndSend(tenantId) {
  const settings = settingsService.getSettings(tenantId);
  const now      = new Date();
  const weekAgo  = new Date(now - 7 * 24 * 3600 * 1000);

  // Get alerts from last 7 days
  const allAlerts  = alertsStore.getAll(tenantId);
  const weekAlerts = allAlerts.filter(a => new Date(a.detectedAt) >= weekAgo);
  const prevAlerts = allAlerts.filter(a => {
    const d = new Date(a.detectedAt);
    return d >= new Date(weekAgo - 7 * 24 * 3600 * 1000) && d < weekAgo;
  });

  // Stats
  const stats = {
    total:    weekAlerts.length,
    critical: weekAlerts.filter(a => a.severity === 'critical').length,
    high:     weekAlerts.filter(a => a.severity === 'high').length,
    medium:   weekAlerts.filter(a => a.severity === 'medium').length,
    low:      weekAlerts.filter(a => a.severity === 'low').length,
    resolved: weekAlerts.filter(a => a.status === 'resolved').length,
    open:     weekAlerts.filter(a => a.status === 'open').length,
    prevTotal: prevAlerts.length
  };

  const trend = stats.total > stats.prevTotal ? 'up' :
                stats.total < stats.prevTotal ? 'down' : 'same';
  const trendPct = stats.prevTotal > 0
    ? Math.round(Math.abs(stats.total - stats.prevTotal) / stats.prevTotal * 100)
    : 0;

  // Risk score (0-100)
  const riskScore = Math.min(100, Math.round(
    (stats.critical * 4 + stats.high * 2 + stats.medium * 1) / Math.max(1, stats.total) * 25
  ));

  // Top anomaly types
  const byType = {};
  weekAlerts.forEach(a => { byType[a.anomalyLabel] = (byType[a.anomalyLabel] || 0) + 1; });
  const topTypes = Object.entries(byType).sort((a, b) => b[1] - a[1]).slice(0, 5);

  // Top affected users
  const byUser = {};
  weekAlerts.forEach(a => { byUser[a.userPrincipalName] = (byUser[a.userPrincipalName] || 0) + 1; });
  const topUsers = Object.entries(byUser).sort((a, b) => b[1] - a[1]).slice(0, 5);

  // Critical open alerts
  const criticalOpen = weekAlerts.filter(a => a.severity === 'critical' && a.status === 'open').slice(0, 5);

  const html = buildDigestHtml({
    tenantId, stats, trend, trendPct, riskScore,
    topTypes, topUsers, criticalOpen,
    weekStart: weekAgo.toLocaleDateString('en-GB', { dateStyle: 'medium' }),
    weekEnd:   now.toLocaleDateString('en-GB', { dateStyle: 'medium' })
  });

  const emails = settingsService.getAdminEmails(settings);
  if (emails.length === 0) {
    console.warn('[WeeklyDigest] No admin emails configured for tenant:', tenantId);
    return null;
  }

  for (const email of emails) {
    await emailService.sendRaw(tenantId, {
      to:      email,
      subject: `📊 Weekly Security Digest — ${now.toLocaleDateString('en-GB', { dateStyle: 'medium' })} — Risk Score ${riskScore}/100`,
      body:    html
    });
  }

  console.log('[WeeklyDigest] Sent to', emails.length, 'recipients for tenant:', tenantId);
  return { sent: true, recipients: emails.length, stats };
}

function buildDigestHtml({ tenantId, stats, trend, trendPct, riskScore, topTypes, topUsers, criticalOpen, weekStart, weekEnd }) {
  const riskColor = riskScore >= 75 ? '#ff3b3b' : riskScore >= 50 ? '#ff6b35' : riskScore >= 25 ? '#f5a623' : '#2ecc71';
  const trendEmoji = trend === 'up' ? '📈' : trend === 'down' ? '📉' : '➡️';
  const trendText  = trend === 'up'   ? `+${trendPct}% vs last week` :
                     trend === 'down' ? `-${trendPct}% vs last week` : 'Same as last week';

  return `<!DOCTYPE html>
<html><head><meta charset="UTF-8"/>
<style>
  body{margin:0;padding:0;background:#f0f4f8;font-family:'Segoe UI',Arial,sans-serif}
  .wrap{max-width:640px;margin:0 auto;background:#fff}
  .header{background:#060c18;padding:28px 32px;border-bottom:4px solid ${riskColor}}
  .brand{font-family:'Courier New',monospace;font-size:11px;color:#f5a623;letter-spacing:1px;text-transform:uppercase;margin-bottom:6px}
  .title{font-size:22px;font-weight:700;color:#e8edf8}
  .period{font-size:12px;color:#8ba3cc;margin-top:4px}
  .risk-banner{padding:20px 32px;background:${riskColor}18;border-bottom:1px solid ${riskColor}30;display:flex;align-items:center;gap:20px}
  .risk-score{font-family:'Courier New',monospace;font-size:52px;font-weight:700;color:${riskColor};line-height:1}
  .risk-label{font-size:12px;color:#64748b;text-transform:uppercase;letter-spacing:.5px}
  .risk-trend{font-size:13px;color:#1a2540;margin-top:4px}
  .body{padding:24px 32px}
  .stats-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:10px;margin-bottom:24px}
  .stat-box{background:#f8fafc;border:1px solid #e5e7eb;border-radius:8px;padding:14px 12px;text-align:center}
  .stat-n{font-family:'Courier New',monospace;font-size:28px;font-weight:700;line-height:1}
  .stat-l{font-size:10px;color:#94a3b8;text-transform:uppercase;letter-spacing:.5px;margin-top:3px}
  .section-title{font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.8px;color:#94a3b8;margin:20px 0 10px;font-family:'Courier New',monospace}
  .alert-row{display:flex;align-items:center;gap:10px;padding:10px 14px;background:#f8fafc;border-radius:6px;margin-bottom:6px;border-left:3px solid}
  .badge{display:inline-block;padding:2px 8px;border-radius:3px;font-size:9px;font-weight:700;font-family:'Courier New',monospace;text-transform:uppercase}
  .type-row{display:flex;justify-content:space-between;align-items:center;padding:7px 0;border-bottom:1px solid #f1f5f9;font-size:13px}
  .bar{height:4px;background:#e5e7eb;border-radius:2px;margin-top:4px}
  .bar-fill{height:4px;border-radius:2px;background:${riskColor}}
  .footer{background:#f8fafc;padding:16px 32px;border-top:1px solid #e5e7eb;text-align:center;font-size:11px;color:#94a3b8}
  .cta-btn{display:inline-block;padding:10px 24px;background:#f5a623;color:#000;border-radius:6px;font-weight:700;text-decoration:none;font-size:13px;margin-top:16px}
</style>
</head><body>
<div class="wrap">

<div class="header">
  <div class="brand">⬡ Modern Endpoint · Privileged Identity Monitor</div>
  <div class="title">Weekly Security Digest</div>
  <div class="period">${weekStart} — ${weekEnd}</div>
</div>

<div class="risk-banner">
  <div>
    <div class="risk-score">${riskScore}</div>
    <div class="risk-label">/ 100 Risk Score</div>
  </div>
  <div>
    <div style="font-size:18px;font-weight:700;color:#1a2540">
      ${riskScore >= 75 ? '🚨 Critical Risk' : riskScore >= 50 ? '⚠️ High Risk' : riskScore >= 25 ? '🔶 Medium Risk' : '✅ Low Risk'}
    </div>
    <div class="risk-trend">${trendEmoji} ${trendText}</div>
    <div style="font-size:12px;color:#64748b;margin-top:2px">${stats.total} total alerts this week</div>
  </div>
</div>

<div class="body">

  <div class="stats-grid">
    <div class="stat-box" style="border-top:3px solid #ff3b3b"><div class="stat-n" style="color:#ff3b3b">${stats.critical}</div><div class="stat-l">Critical</div></div>
    <div class="stat-box" style="border-top:3px solid #ff6b35"><div class="stat-n" style="color:#ff6b35">${stats.high}</div><div class="stat-l">High</div></div>
    <div class="stat-box" style="border-top:3px solid #f5a623"><div class="stat-n" style="color:#d97706">${stats.medium}</div><div class="stat-l">Medium</div></div>
    <div class="stat-box" style="border-top:3px solid #1a2540"><div class="stat-n" style="color:#1a2540">${stats.open}</div><div class="stat-l">Still Open</div></div>
    <div class="stat-box" style="border-top:3px solid #2ecc71"><div class="stat-n" style="color:#16a34a">${stats.resolved}</div><div class="stat-l">Resolved</div></div>
    <div class="stat-box" style="border-top:3px solid #7c3aed"><div class="stat-n" style="color:#7c3aed">${stats.resolved > 0 ? Math.round(stats.resolved/stats.total*100) : 0}%</div><div class="stat-l">Resolution</div></div>
  </div>

  ${criticalOpen.length > 0 ? `
  <div class="section-title">⚠️ Unresolved Critical Alerts</div>
  ${criticalOpen.map(a => `
    <div class="alert-row" style="border-color:#ff3b3b">
      <span class="badge" style="background:#fff0f0;color:#dc2626">CRITICAL</span>
      <div style="flex:1">
        <div style="font-weight:600;font-size:13px;color:#1a2540">${a.userDisplayName} — ${a.anomalyLabel}</div>
        <div style="font-size:11px;color:#64748b">${a.detail}</div>
      </div>
      <div style="font-size:10px;color:#94a3b8">${new Date(a.detectedAt).toLocaleDateString('en-GB')}</div>
    </div>`).join('')}` : ''}

  ${topTypes.length > 0 ? `
  <div class="section-title">📊 Top Anomaly Types</div>
  ${topTypes.map(([type, count]) => `
    <div class="type-row">
      <span style="color:#1a2540">${type}</span>
      <div style="text-align:right">
        <span style="font-family:'Courier New',monospace;font-weight:700;color:#1a2540">${count}</span>
        <div class="bar" style="width:80px"><div class="bar-fill" style="width:${Math.round(count/stats.total*100)}%"></div></div>
      </div>
    </div>`).join('')}` : ''}

  ${topUsers.length > 0 ? `
  <div class="section-title">👤 Most Alerted Users</div>
  ${topUsers.map(([upn, count]) => `
    <div class="type-row">
      <span style="font-family:'Courier New',monospace;font-size:11px;color:#64748b">${upn}</span>
      <span style="font-family:'Courier New',monospace;font-weight:700;color:#1a2540">${count} alerts</span>
    </div>`).join('')}` : ''}

  <div style="text-align:center;padding:20px 0">
    <a href="https://identitymonitor.modernendpoint.tech" class="cta-btn">→ View Full Dashboard</a>
  </div>

</div>

<div class="footer">
  Modern Endpoint — Privileged Identity Monitor<br/>
  You're receiving this because you're configured as a security admin.<br/>
  <a href="https://identitymonitor.modernendpoint.tech/settings" style="color:#64748b">Manage notification preferences</a>
</div>
</div>
</body></html>`;
}

module.exports = { generateAndSend };
