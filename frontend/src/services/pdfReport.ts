// pdfReport.ts — generates PDFs entirely in the browser using Canvas + jsPDF-style approach
// No external PDF library needed — we build HTML and use window.print() with print CSS
// For per-alert PDFs and monthly reports

export interface AlertData {
  id: string;
  userDisplayName: string;
  userPrincipalName: string;
  roles: string[];
  anomalyLabel: string;
  severity: string;
  detail: string;
  ipAddress?: string;
  city?: string;
  country?: string;
  deviceName?: string;
  deviceOs?: string;
  appName?: string;
  signInTime: string;
  detectedAt: string;
  status: string;
  actionsTriggered: { action: string; timestamp: string }[];
}

export interface StatsData {
  total: number;
  open: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  resolvedToday: number;
}

function severityColor(s: string): string {
  return ({ critical: '#ff3b3b', high: '#ff6b35', medium: '#f5a623', low: '#4a90d9' } as any)[s] || '#8ba3cc';
}

function fmtDate(iso: string): string {
  return new Date(iso).toLocaleString('en-GB', { dateStyle: 'medium', timeStyle: 'short' });
}

function openPrintWindow(html: string, title: string) {
  const w = window.open('', '_blank', 'width=900,height=700');
  if (!w) { alert('Please allow popups to generate PDF'); return; }
  w.document.write(html);
  w.document.close();
  w.focus();
  setTimeout(() => { w.print(); }, 800);
}

// ─── BASE HTML WRAPPER ────────────────────────────────────────────────────
function baseHtml(title: string, body: string): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<title>${title}</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=DM+Sans:wght@300;400;500;600;700&family=Space+Mono:wght@400;700&display=swap');
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: 'DM Sans', sans-serif; background: #fff; color: #1a2540; font-size: 13px; line-height: 1.6; }
  .mono { font-family: 'Space Mono', monospace; }

  /* Header */
  .report-header { background: #0b1628; color: #fff; padding: 28px 40px; display: flex; justify-content: space-between; align-items: flex-start; }
  .report-brand { font-family: 'Space Mono', monospace; font-size: 11px; color: #f5a623; letter-spacing: 1px; text-transform: uppercase; margin-bottom: 6px; }
  .report-title { font-size: 22px; font-weight: 700; color: #e8edf8; }
  .report-meta { text-align: right; font-size: 11px; color: #8ba3cc; line-height: 1.8; }
  .report-meta strong { color: #f5a623; font-family: 'Space Mono', monospace; }

  /* Content */
  .report-body { padding: 32px 40px; }
  .section { margin-bottom: 28px; }
  .section-title { font-family: 'Space Mono', monospace; font-size: 10px; font-weight: 700; text-transform: uppercase; letter-spacing: 1px; color: #4a6490; border-bottom: 1px solid #e2e8f0; padding-bottom: 6px; margin-bottom: 14px; }

  /* Severity badge */
  .badge { display: inline-block; padding: 2px 10px; border-radius: 4px; font-size: 10px; font-weight: 700; font-family: 'Space Mono', monospace; text-transform: uppercase; letter-spacing: 0.5px; }
  .badge-critical { background: #fff0f0; color: #ff3b3b; border: 1px solid #ffcccc; }
  .badge-high     { background: #fff4f0; color: #ff6b35; border: 1px solid #ffd4c0; }
  .badge-medium   { background: #fffbf0; color: #d4870a; border: 1px solid #ffeab0; }
  .badge-low      { background: #f0f6ff; color: #2563eb; border: 1px solid #bfd4ff; }

  /* Detail rows */
  .detail-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 0; border: 1px solid #e2e8f0; border-radius: 8px; overflow: hidden; }
  .detail-row { display: flex; border-bottom: 1px solid #e2e8f0; }
  .detail-row:last-child { border-bottom: none; }
  .detail-label { width: 140px; padding: 9px 14px; background: #f8fafc; font-weight: 600; font-size: 11px; color: #4a6490; flex-shrink: 0; border-right: 1px solid #e2e8f0; }
  .detail-value { padding: 9px 14px; color: #1a2540; font-size: 12px; }

  /* Alert card */
  .alert-card { border: 1px solid #e2e8f0; border-radius: 8px; overflow: hidden; margin-bottom: 16px; }
  .alert-card-header { padding: 12px 16px; display: flex; align-items: center; gap: 12px; border-bottom: 1px solid #e2e8f0; }
  .alert-card-body { padding: 12px 16px; display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 8px; }
  .alert-card-field { font-size: 11px; }
  .alert-card-field-label { color: #8ba3cc; margin-bottom: 2px; }
  .alert-card-field-value { color: #1a2540; font-weight: 500; }

  /* Stats row */
  .stats-row { display: grid; grid-template-columns: repeat(6, 1fr); gap: 12px; margin-bottom: 24px; }
  .stat-box { border: 1px solid #e2e8f0; border-radius: 8px; padding: 14px 12px; text-align: center; }
  .stat-box-value { font-family: 'Space Mono', monospace; font-size: 28px; font-weight: 700; line-height: 1; margin-bottom: 4px; }
  .stat-box-label { font-size: 10px; font-weight: 600; color: #8ba3cc; text-transform: uppercase; letter-spacing: 0.5px; }
  .stat-critical { border-top: 3px solid #ff3b3b; } .stat-critical .stat-box-value { color: #ff3b3b; }
  .stat-high     { border-top: 3px solid #ff6b35; } .stat-high .stat-box-value { color: #ff6b35; }
  .stat-medium   { border-top: 3px solid #f5a623; } .stat-medium .stat-box-value { color: #d4870a; }
  .stat-low      { border-top: 3px solid #4a90d9; } .stat-low .stat-box-value { color: #2563eb; }
  .stat-open     { border-top: 3px solid #1a2540; } .stat-open .stat-box-value { color: #1a2540; }
  .stat-resolved { border-top: 3px solid #2ecc71; } .stat-resolved .stat-box-value { color: #16a34a; }

  /* Actions */
  .action-item { display: flex; align-items: center; gap: 6px; font-size: 11px; color: #16a34a; margin-bottom: 3px; }
  .action-item::before { content: '✓'; font-weight: 700; }

  /* Footer */
  .report-footer { border-top: 1px solid #e2e8f0; padding: 16px 40px; display: flex; justify-content: space-between; font-size: 10px; color: #8ba3cc; font-family: 'Space Mono', monospace; }

  /* Severity accent bar */
  .severity-bar { height: 4px; width: 100%; }

  @media print {
    body { -webkit-print-color-adjust: exact; print-color-adjust: exact; }
    .report-header { -webkit-print-color-adjust: exact; }
    .no-print { display: none; }
    @page { margin: 0; size: A4; }
  }
</style>
</head>
<body>
${body}
</body>
</html>`;
}

// ─── 1. SINGLE ALERT PDF ──────────────────────────────────────────────────
export function generateAlertPDF(alert: AlertData) {
  const color = severityColor(alert.severity);
  const body = `
    <div class="report-header">
      <div>
        <div class="report-brand">⬡ Modern Endpoint · Privileged Identity Monitor</div>
        <div class="report-title">Security Alert Report</div>
      </div>
      <div class="report-meta">
        <div>Generated: <strong>${fmtDate(new Date().toISOString())}</strong></div>
        <div>Alert ID: <strong>${alert.id.substring(0, 20)}...</strong></div>
        <div>Status: <strong>${alert.status.toUpperCase()}</strong></div>
      </div>
    </div>
    <div style="height:4px;background:${color};"></div>

    <div class="report-body">

      <div class="section">
        <div class="section-title">Alert Summary</div>
        <div style="display:flex;align-items:center;gap:12px;margin-bottom:16px;">
          <span class="badge badge-${alert.severity}">${alert.severity.toUpperCase()}</span>
          <span style="font-size:18px;font-weight:700;color:#1a2540;">${alert.anomalyLabel}</span>
        </div>
        <div style="background:#f8fafc;border:1px solid #e2e8f0;border-left:4px solid ${color};border-radius:0 6px 6px 0;padding:12px 16px;font-size:13px;color:#1a2540;">
          ${alert.detail}
        </div>
      </div>

      <div class="section">
        <div class="section-title">Affected User</div>
        <div class="detail-grid">
          <div class="detail-row"><div class="detail-label">Display Name</div><div class="detail-value">${alert.userDisplayName}</div></div>
          <div class="detail-row"><div class="detail-label">UPN</div><div class="detail-value mono">${alert.userPrincipalName}</div></div>
          <div class="detail-row"><div class="detail-label">Privileged Roles</div><div class="detail-value">${(alert.roles || []).join(', ')}</div></div>
        </div>
      </div>

      <div class="section">
        <div class="section-title">Sign-in Details</div>
        <div class="detail-grid">
          <div class="detail-row"><div class="detail-label">Sign-in Time</div><div class="detail-value">${fmtDate(alert.signInTime)}</div></div>
          <div class="detail-row"><div class="detail-label">Detected At</div><div class="detail-value">${fmtDate(alert.detectedAt)}</div></div>
          <div class="detail-row"><div class="detail-label">IP Address</div><div class="detail-value mono">${alert.ipAddress || '—'}</div></div>
          <div class="detail-row"><div class="detail-label">Location</div><div class="detail-value">${[alert.city, alert.country].filter(Boolean).join(', ') || '—'}</div></div>
          <div class="detail-row"><div class="detail-label">Device</div><div class="detail-value">${alert.deviceName || 'Unknown'} ${alert.deviceOs ? '(' + alert.deviceOs + ')' : ''}</div></div>
          <div class="detail-row"><div class="detail-label">Application</div><div class="detail-value">${alert.appName || '—'}</div></div>
        </div>
      </div>

      <div class="section">
        <div class="section-title">Automated Response Actions</div>
        ${(alert.actionsTriggered || []).length > 0
          ? (alert.actionsTriggered || []).map(a => `
              <div class="action-item">${a.action.replace(/_/g, ' ')} — ${fmtDate(a.timestamp)}</div>
            `).join('')
          : '<div style="color:#8ba3cc;font-size:12px;">No automated actions were triggered for this alert.</div>'
        }
      </div>

    </div>

    <div class="report-footer">
      <span>Modern Endpoint — Privileged Identity Monitor</span>
      <span>Confidential — For authorized personnel only</span>
    </div>
  `;

  openPrintWindow(baseHtml(`Alert — ${alert.anomalyLabel}`, body), 'alert-report');
}

// ─── 2. MONTHLY SUMMARY PDF ───────────────────────────────────────────────
export function generateMonthlySummaryPDF(alerts: AlertData[], stats: StatsData, month?: string) {
  const now = new Date();
  const monthLabel = month || now.toLocaleString('en-GB', { month: 'long', year: 'numeric' });

  const bySeverity = { critical: 0, high: 0, medium: 0, low: 0 } as any;
  alerts.forEach(a => { if (bySeverity[a.severity] !== undefined) bySeverity[a.severity]++; });

  const byType = alerts.reduce((acc: any, a) => {
    acc[a.anomalyLabel] = (acc[a.anomalyLabel] || 0) + 1;
    return acc;
  }, {});

  const topUsers = Object.entries(
    alerts.reduce((acc: any, a) => {
      acc[a.userPrincipalName] = (acc[a.userPrincipalName] || 0) + 1;
      return acc;
    }, {})
  ).sort((a: any, b: any) => b[1] - a[1]).slice(0, 5);

  const body = `
    <div class="report-header">
      <div>
        <div class="report-brand">⬡ Modern Endpoint · Privileged Identity Monitor</div>
        <div class="report-title">Monthly Security Summary</div>
        <div style="color:#8ba3cc;font-size:13px;margin-top:4px;">${monthLabel}</div>
      </div>
      <div class="report-meta">
        <div>Generated: <strong>${fmtDate(now.toISOString())}</strong></div>
        <div>Period: <strong>${monthLabel}</strong></div>
        <div>Total alerts: <strong>${alerts.length}</strong></div>
      </div>
    </div>
    <div style="height:4px;background:linear-gradient(90deg,#ff3b3b,#f5a623,#2ecc71);"></div>

    <div class="report-body">

      <div class="section">
        <div class="section-title">Alert Statistics</div>
        <div class="stats-row">
          <div class="stat-box stat-critical"><div class="stat-box-value">${bySeverity.critical}</div><div class="stat-box-label">Critical</div></div>
          <div class="stat-box stat-high"><div class="stat-box-value">${bySeverity.high}</div><div class="stat-box-label">High</div></div>
          <div class="stat-box stat-medium"><div class="stat-box-value">${bySeverity.medium}</div><div class="stat-box-label">Medium</div></div>
          <div class="stat-box stat-low"><div class="stat-box-value">${bySeverity.low}</div><div class="stat-box-label">Low</div></div>
          <div class="stat-box stat-open"><div class="stat-box-value">${stats.open}</div><div class="stat-box-label">Open</div></div>
          <div class="stat-box stat-resolved"><div class="stat-box-value">${alerts.filter(a=>a.status==='resolved').length}</div><div class="stat-box-label">Resolved</div></div>
        </div>
      </div>

      <div style="display:grid;grid-template-columns:1fr 1fr;gap:20px;margin-bottom:28px;">
        <div class="section" style="margin:0;">
          <div class="section-title">Anomaly Types</div>
          ${Object.entries(byType).sort((a:any,b:any)=>b[1]-a[1]).map(([type, count]:any) => `
            <div style="display:flex;justify-content:space-between;align-items:center;padding:7px 0;border-bottom:1px solid #f0f4f8;">
              <span style="font-size:12px;">${type}</span>
              <span style="font-family:'Space Mono',monospace;font-size:13px;font-weight:700;color:#1a2540;">${count}</span>
            </div>
          `).join('')}
        </div>
        <div class="section" style="margin:0;">
          <div class="section-title">Most Alerted Users</div>
          ${topUsers.map(([upn, count]:any, i) => `
            <div style="display:flex;justify-content:space-between;align-items:center;padding:7px 0;border-bottom:1px solid #f0f4f8;">
              <span style="font-size:11px;color:#4a6490;font-family:'Space Mono',monospace;">${upn}</span>
              <span style="font-family:'Space Mono',monospace;font-size:13px;font-weight:700;color:#1a2540;">${count}</span>
            </div>
          `).join('')}
        </div>
      </div>

      <div class="section">
        <div class="section-title">Alert Log (${alerts.length} total)</div>
        ${alerts.slice(0, 50).map(a => `
          <div class="alert-card">
            <div class="alert-card-header" style="border-left:3px solid ${severityColor(a.severity)};">
              <span class="badge badge-${a.severity}">${a.severity}</span>
              <span style="font-weight:600;font-size:13px;">${a.anomalyLabel}</span>
              <span style="color:#4a6490;font-size:11px;margin-left:auto;">${a.userDisplayName}</span>
              <span style="color:#8ba3cc;font-size:11px;">${fmtDate(a.detectedAt)}</span>
            </div>
            <div class="alert-card-body">
              <div class="alert-card-field"><div class="alert-card-field-label">IP Address</div><div class="alert-card-field-value mono">${a.ipAddress || '—'}</div></div>
              <div class="alert-card-field"><div class="alert-card-field-label">Location</div><div class="alert-card-field-value">${[a.city,a.country].filter(Boolean).join(', ')||'—'}</div></div>
              <div class="alert-card-field"><div class="alert-card-field-label">Status</div><div class="alert-card-field-value">${a.status}</div></div>
            </div>
          </div>
        `).join('')}
        ${alerts.length > 50 ? `<div style="text-align:center;color:#8ba3cc;font-size:11px;padding:12px;">... and ${alerts.length - 50} more alerts</div>` : ''}
      </div>

    </div>

    <div class="report-footer">
      <span>Modern Endpoint — Privileged Identity Monitor</span>
      <span>Confidential — For authorized personnel only</span>
    </div>
  `;

  openPrintWindow(baseHtml(`Monthly Summary — ${monthLabel}`, body), 'monthly-report');
}

// ─── 3. EXECUTIVE SUMMARY PDF ─────────────────────────────────────────────
export function generateExecutiveSummaryPDF(alerts: AlertData[], stats: StatsData) {
  const now = new Date();
  const resolved   = alerts.filter(a => a.status === 'resolved').length;
  const resolutionRate = alerts.length > 0 ? Math.round((resolved / alerts.length) * 100) : 0;
  const criticalHigh = alerts.filter(a => ['critical','high'].includes(a.severity)).length;
  const riskScore = alerts.length === 0 ? 0 :
    Math.min(100, Math.round(
      (stats.critical * 4 + stats.high * 2 + stats.medium * 1) /
      Math.max(1, alerts.length) * 25
    ));

  const riskLabel = riskScore >= 75 ? 'CRITICAL' : riskScore >= 50 ? 'HIGH' : riskScore >= 25 ? 'MEDIUM' : 'LOW';
  const riskColor = riskScore >= 75 ? '#ff3b3b' : riskScore >= 50 ? '#ff6b35' : riskScore >= 25 ? '#f5a623' : '#2ecc71';

  const body = `
    <div class="report-header">
      <div>
        <div class="report-brand">⬡ Modern Endpoint · Privileged Identity Monitor</div>
        <div class="report-title">Executive Security Summary</div>
        <div style="color:#8ba3cc;font-size:13px;margin-top:4px;">Privileged Identity Risk Report</div>
      </div>
      <div class="report-meta">
        <div>Generated: <strong>${fmtDate(now.toISOString())}</strong></div>
        <div>Risk Level: <strong style="color:${riskColor};">${riskLabel}</strong></div>
        <div>Risk Score: <strong>${riskScore}/100</strong></div>
      </div>
    </div>
    <div style="height:6px;background:${riskColor};"></div>

    <div class="report-body">

      <!-- Risk Score Banner -->
      <div style="background:#f8fafc;border:1px solid #e2e8f0;border-radius:10px;padding:20px 28px;margin-bottom:28px;display:flex;align-items:center;gap:28px;">
        <div style="text-align:center;flex-shrink:0;">
          <div style="font-family:'Space Mono',monospace;font-size:52px;font-weight:700;color:${riskColor};line-height:1;">${riskScore}</div>
          <div style="font-size:11px;font-weight:700;color:#8ba3cc;text-transform:uppercase;letter-spacing:0.5px;">Risk Score</div>
        </div>
        <div style="flex:1;border-left:1px solid #e2e8f0;padding-left:28px;">
          <div style="font-size:18px;font-weight:700;color:#1a2540;margin-bottom:8px;">Overall Security Posture: <span style="color:${riskColor};">${riskLabel}</span></div>
          <div style="font-size:13px;color:#4a6490;line-height:1.6;">
            ${alerts.length} total anomalies detected across privileged accounts.
            ${criticalHigh} require immediate attention.
            Resolution rate: ${resolutionRate}%.
          </div>
        </div>
      </div>

      <!-- Key Metrics -->
      <div class="section">
        <div class="section-title">Key Security Metrics</div>
        <div class="stats-row">
          <div class="stat-box stat-critical"><div class="stat-box-value">${stats.critical}</div><div class="stat-box-label">Critical</div></div>
          <div class="stat-box stat-high"><div class="stat-box-value">${stats.high}</div><div class="stat-box-label">High</div></div>
          <div class="stat-box stat-medium"><div class="stat-box-value">${stats.medium}</div><div class="stat-box-label">Medium</div></div>
          <div class="stat-box stat-open"><div class="stat-box-value">${stats.open}</div><div class="stat-box-label">Open</div></div>
          <div class="stat-box stat-resolved"><div class="stat-box-value">${resolved}</div><div class="stat-box-label">Resolved</div></div>
          <div class="stat-box" style="border-top:3px solid #7c3aed;"><div class="stat-box-value" style="color:#7c3aed;">${resolutionRate}%</div><div class="stat-box-label">Resolution</div></div>
        </div>
      </div>

      <!-- Key Findings -->
      <div class="section">
        <div class="section-title">Key Findings & Recommendations</div>
        ${stats.critical > 0 ? `
          <div style="display:flex;gap:10px;padding:12px;background:#fff0f0;border-radius:6px;margin-bottom:8px;border-left:4px solid #ff3b3b;">
            <span style="font-size:16px;">🚨</span>
            <div><strong style="color:#ff3b3b;">Critical:</strong> ${stats.critical} critical alert${stats.critical>1?'s':''} require immediate investigation. Review affected accounts and consider temporary access suspension.</div>
          </div>` : ''}
        ${stats.high > 0 ? `
          <div style="display:flex;gap:10px;padding:12px;background:#fff4f0;border-radius:6px;margin-bottom:8px;border-left:4px solid #ff6b35;">
            <span style="font-size:16px;">⚠️</span>
            <div><strong style="color:#ff6b35;">High Priority:</strong> ${stats.high} high-severity alert${stats.high>1?'s':''} detected. Verify sign-in legitimacy with affected users within 24 hours.</div>
          </div>` : ''}
        ${resolutionRate < 50 && alerts.length > 0 ? `
          <div style="display:flex;gap:10px;padding:12px;background:#fffbf0;border-radius:6px;margin-bottom:8px;border-left:4px solid #f5a623;">
            <span style="font-size:16px;">📊</span>
            <div><strong style="color:#d4870a;">Resolution Rate:</strong> Only ${resolutionRate}% of alerts have been resolved. Consider reviewing alert triage process.</div>
          </div>` : ''}
        ${alerts.length === 0 ? `
          <div style="display:flex;gap:10px;padding:12px;background:#f0fff4;border-radius:6px;border-left:4px solid #2ecc71;">
            <span style="font-size:16px;">✅</span>
            <div><strong style="color:#16a34a;">All Clear:</strong> No anomalies detected. Privileged accounts operating within normal parameters.</div>
          </div>` : ''}
      </div>

      <!-- Top Alerts -->
      ${alerts.filter(a=>['critical','high'].includes(a.severity)).length > 0 ? `
      <div class="section">
        <div class="section-title">Critical & High Severity Alerts</div>
        ${alerts.filter(a=>['critical','high'].includes(a.severity)).slice(0,10).map(a=>`
          <div style="display:flex;align-items:center;gap:12px;padding:10px 14px;border:1px solid #e2e8f0;border-radius:6px;margin-bottom:6px;border-left:3px solid ${severityColor(a.severity)};">
            <span class="badge badge-${a.severity}">${a.severity}</span>
            <div style="flex:1;">
              <div style="font-weight:600;font-size:12px;">${a.userDisplayName} — ${a.anomalyLabel}</div>
              <div style="font-size:11px;color:#4a6490;">${a.detail}</div>
            </div>
            <div style="text-align:right;font-size:11px;color:#8ba3cc;white-space:nowrap;">${fmtDate(a.detectedAt)}</div>
          </div>
        `).join('')}
      </div>` : ''}

    </div>

    <div class="report-footer">
      <span>Modern Endpoint — Privileged Identity Monitor</span>
      <span>CONFIDENTIAL — Executive Use Only</span>
    </div>
  `;

  openPrintWindow(baseHtml('Executive Summary — Privileged Identity Monitor', body), 'executive-summary');
}
