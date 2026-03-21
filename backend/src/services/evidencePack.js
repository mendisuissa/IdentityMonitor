// evidencePack.js — Generate HTML evidence pack for compliance/legal

const incidentService  = require('./incidentService');
const playbookService  = require('./playbookService');

function generateEvidenceHtml(alert, timeline) {
  const playbook = playbookService.getPlaybook(alert.anomalyType);
  const now      = new Date();

  const timelineRows = timeline.map(ev =>
    `<tr>
      <td style="padding:8px 12px;border-bottom:1px solid #f0f4f8;font-family:monospace;font-size:11px;white-space:nowrap;color:#64748b">${new Date(ev.timestamp).toLocaleString('en-GB')}</td>
      <td style="padding:8px 12px;border-bottom:1px solid #f0f4f8;font-size:20px;width:30px">${ev.icon || '•'}</td>
      <td style="padding:8px 12px;border-bottom:1px solid #f0f4f8;font-weight:600;font-size:13px">${ev.label}</td>
      <td style="padding:8px 12px;border-bottom:1px solid #f0f4f8;font-size:12px;color:#64748b">${ev.actor || 'system'}</td>
      <td style="padding:8px 12px;border-bottom:1px solid #f0f4f8;font-size:12px;color:#64748b">${ev.details ? JSON.stringify(ev.details).substring(0, 80) : '—'}</td>
    </tr>`
  ).join('');

  const sevColor = { critical: '#ff3b3b', high: '#ff6b35', medium: '#f5a623', low: '#4a90d9' }[alert.severity] || '#8ba3cc';

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<title>Evidence Pack — ${alert.id}</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;600;700&family=Space+Mono:wght@400;700&display=swap');
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: 'DM Sans', sans-serif; background: #fff; color: #1a2540; font-size: 14px; line-height: 1.6; }
  .page { max-width: 800px; margin: 0 auto; padding: 40px; }
  .header { background: #060c18; color: #fff; padding: 28px 32px; border-bottom: 4px solid ${sevColor}; border-radius: 8px 8px 0 0; }
  .brand { font-family: 'Space Mono', monospace; font-size: 11px; color: #f5a623; letter-spacing: 1px; text-transform: uppercase; margin-bottom: 6px; }
  .doc-title { font-size: 22px; font-weight: 700; color: #e8edf8; margin-bottom: 4px; }
  .doc-meta { font-size: 12px; color: #8ba3cc; }
  .section { margin: 28px 0; }
  .section-title { font-family: 'Space Mono', monospace; font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: 1px; color: #8ba3cc; border-bottom: 2px solid #f0f4f8; padding-bottom: 6px; margin-bottom: 14px; }
  .detail-table { width: 100%; border-collapse: collapse; }
  .detail-table td { padding: 9px 14px; border-bottom: 1px solid #f0f4f8; font-size: 13px; }
  .detail-table td:first-child { width: 160px; font-weight: 600; color: #64748b; background: #f8fafc; border-right: 1px solid #f0f4f8; }
  .badge { display: inline-block; padding: 2px 10px; border-radius: 4px; font-family: 'Space Mono', monospace; font-size: 10px; font-weight: 700; text-transform: uppercase; }
  .badge-${alert.severity} { background: ${sevColor}15; color: ${sevColor}; border: 1px solid ${sevColor}30; }
  .detail-box { background: #f8fafc; border: 1px solid #e5e7eb; border-left: 4px solid ${sevColor}; border-radius: 0 6px 6px 0; padding: 12px 16px; font-size: 13px; margin: 12px 0; }
  .timeline-table { width: 100%; border-collapse: collapse; }
  .timeline-table th { padding: 8px 12px; text-align: left; font-family: 'Space Mono', monospace; font-size: 10px; text-transform: uppercase; letter-spacing: .8px; color: #94a3b8; background: #f8fafc; border-bottom: 2px solid #e5e7eb; }
  .playbook-step { display: flex; gap: 12px; padding: 10px 0; border-bottom: 1px solid #f0f4f8; align-items: flex-start; }
  .step-num { width: 24px; height: 24px; border-radius: 50%; background: #1a2540; color: #fff; font-family: 'Space Mono', monospace; font-size: 11px; font-weight: 700; display: flex; align-items: center; justify-content: center; flex-shrink: 0; }
  .step-auto { font-size: 10px; padding: 1px 6px; border-radius: 3px; background: #dcfce7; color: #16a34a; font-weight: 700; margin-left: 6px; }
  .footer { border-top: 1px solid #e5e7eb; margin-top: 40px; padding-top: 16px; text-align: center; font-size: 11px; color: #94a3b8; font-family: 'Space Mono', monospace; }
  .warning-box { background: #fffbf0; border: 1px solid #f59e0b; border-radius: 6px; padding: 12px 16px; font-size: 12px; color: #92400e; margin: 12px 0; }
  @media print { body { -webkit-print-color-adjust: exact; } @page { margin: 20px; } }
</style>
</head>
<body>
<div class="page">

  <div class="header">
    <div class="brand">⬡ Modern Endpoint · Privileged Identity Monitor</div>
    <div class="doc-title">Security Incident Evidence Pack</div>
    <div class="doc-meta">
      Generated: ${now.toLocaleString('en-GB', { dateStyle: 'full', timeStyle: 'medium' })} ·
      Alert ID: ${alert.id} ·
      Classification: CONFIDENTIAL
    </div>
  </div>

  <!-- Alert Summary -->
  <div class="section">
    <div class="section-title">Incident Summary</div>
    <div style="display:flex;align-items:center;gap:12px;margin-bottom:12px">
      <span class="badge badge-${alert.severity}">${alert.severity.toUpperCase()}</span>
      <span style="font-size:18px;font-weight:700">${alert.anomalyLabel}</span>
    </div>
    <div class="detail-box">${alert.detail}</div>
    ${playbook ? `
    <div class="warning-box">
      <strong>⚠️ Why this matters:</strong> ${playbook.whyItMatters}<br/>
      <strong>💥 Blast radius:</strong> ${playbook.blastRadius}
    </div>` : ''}
  </div>

  <!-- Affected User -->
  <div class="section">
    <div class="section-title">Affected Privileged Account</div>
    <table class="detail-table">
      <tr><td>Display Name</td><td>${alert.userDisplayName}</td></tr>
      <tr><td>UPN</td><td style="font-family:monospace">${alert.userPrincipalName}</td></tr>
      <tr><td>Privileged Roles</td><td>${(alert.roles || []).join(', ')}</td></tr>
      <tr><td>Alert Status</td><td>${alert.status.toUpperCase()}</td></tr>
      ${alert.resolvedBy ? `<tr><td>Resolved By</td><td>${alert.resolvedBy}</td></tr>` : ''}
    </table>
  </div>

  <!-- Sign-in Details -->
  <div class="section">
    <div class="section-title">Sign-in Event Details</div>
    <table class="detail-table">
      <tr><td>Sign-in Time</td><td>${new Date(alert.signInTime).toLocaleString('en-GB', { dateStyle: 'full', timeStyle: 'long' })}</td></tr>
      <tr><td>Detected At</td><td>${new Date(alert.detectedAt).toLocaleString('en-GB', { dateStyle: 'full', timeStyle: 'long' })}</td></tr>
      <tr><td>IP Address</td><td style="font-family:monospace">${alert.ipAddress || '—'}</td></tr>
      <tr><td>Location</td><td>${[alert.city, alert.country].filter(Boolean).join(', ') || '—'}</td></tr>
      <tr><td>Device</td><td>${alert.deviceName || 'Unknown'} (${alert.deviceOs || 'Unknown OS'})</td></tr>
      <tr><td>Application</td><td>${alert.appName || '—'} ${alert.appTier ? '· Tier: ' + alert.appTier : ''}</td></tr>
      <tr><td>Risk Score</td><td style="font-weight:700;color:${sevColor}">${alert.riskScore || '—'}/100</td></tr>
    </table>
  </div>

  <!-- Incident Timeline -->
  <div class="section">
    <div class="section-title">Incident Timeline (${timeline.length} events)</div>
    ${timeline.length === 0
      ? '<div style="color:#94a3b8;font-size:13px;padding:12px">No recorded events yet</div>'
      : `<table class="timeline-table">
          <thead><tr><th>Timestamp</th><th></th><th>Event</th><th>Actor</th><th>Details</th></tr></thead>
          <tbody>${timelineRows}</tbody>
        </table>`}
  </div>

  <!-- Automated Response -->
  <div class="section">
    <div class="section-title">Automated Response Actions</div>
    ${(alert.actionsTriggered || []).length === 0
      ? '<div style="color:#94a3b8;font-size:13px">No automated actions were triggered for this alert.</div>'
      : (alert.actionsTriggered || []).map(a => `
        <div style="display:flex;gap:8px;padding:6px 0;font-size:13px;color:#16a34a">
          <span>✓</span><span>${a.action.replace(/_/g, ' ')}</span>
          <span style="color:#94a3b8;font-size:11px;margin-left:auto">${new Date(a.timestamp).toLocaleString('en-GB')}</span>
        </div>`).join('')}
  </div>

  <!-- Recommended Playbook -->
  ${playbook ? `
  <div class="section">
    <div class="section-title">Recommended Response Playbook: ${playbook.name}</div>
    ${playbook.steps.map(s => `
      <div class="playbook-step">
        <div class="step-num">${s.order}</div>
        <div>
          <div style="font-weight:600;font-size:13px">${s.label}
            ${s.auto ? '<span class="step-auto">AUTO</span>' : ''}
            ${s.requiresApproval ? '<span style="font-size:10px;padding:1px 6px;border-radius:3px;background:#fff0f0;color:#dc2626;font-weight:700;margin-left:6px">APPROVAL REQUIRED</span>' : ''}
          </div>
          <div style="font-size:12px;color:#64748b;margin-top:2px">${s.description}</div>
        </div>
      </div>`).join('')}
  </div>` : ''}

  <!-- Compliance Note -->
  <div class="section">
    <div class="section-title">Compliance & Retention</div>
    <div style="font-size:13px;color:#64748b;line-height:1.7">
      This evidence pack was automatically generated by Modern Endpoint Privileged Identity Monitor.<br/>
      <strong>ISO 27001:</strong> This incident record satisfies A.16.1 (Management of information security incidents).<br/>
      <strong>SOC 2:</strong> Supports CC7.2 (Monitor system components) and CC7.3 (Evaluate security events).<br/>
      <strong>GDPR:</strong> Incident detection supports Art. 32 (Security of processing) obligations.<br/>
      <em>Retain this document for a minimum of 3 years per security incident management policy.</em>
    </div>
  </div>

  <div class="footer">
    Modern Endpoint — Privileged Identity Monitor · identitymonitor.modernendpoint.tech<br/>
    CONFIDENTIAL — For authorized security personnel only · Do not distribute without authorization<br/>
    Document generated: ${now.toISOString()}
  </div>

</div>
</body>
</html>`;
}

module.exports = { generateEvidenceHtml };
