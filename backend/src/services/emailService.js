const graphService = require('./graphService');

const SEVERITY_COLOR = {
  critical: '#FF3B3B',
  high: '#FF8C00',
  medium: '#F5A623',
  low: '#4A90D9'
};

const SEVERITY_EMOJI = {
  critical: '🚨',
  high: '⚠️',
  medium: '🔶',
  low: 'ℹ️'
};

function buildAdminAlertHtml(alert) {
  const color = SEVERITY_COLOR[alert.severity] || '#FF8C00';
  const emoji = SEVERITY_EMOJI[alert.severity] || '⚠️';

  return `
<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"></head>
<body style="margin:0;padding:0;background:#0d1117;font-family:'Segoe UI',Arial,sans-serif;">
  <div style="max-width:600px;margin:0 auto;background:#0d1117;border:1px solid #30363d;border-radius:8px;overflow:hidden;">
    
    <!-- Header -->
    <div style="background:${color};padding:20px 24px;">
      <div style="font-size:12px;color:rgba(255,255,255,0.8);text-transform:uppercase;letter-spacing:1px;margin-bottom:4px;">
        Privileged Identity Monitor
      </div>
      <div style="font-size:22px;font-weight:700;color:#fff;">
        ${emoji} ${alert.severity.toUpperCase()} ALERT — ${alert.anomalyLabel}
      </div>
    </div>

    <!-- User Info -->
    <div style="padding:24px;border-bottom:1px solid #30363d;">
      <div style="font-size:11px;color:#8b949e;text-transform:uppercase;letter-spacing:0.5px;margin-bottom:8px;">Affected User</div>
      <div style="font-size:18px;font-weight:600;color:#e6edf3;">${alert.userDisplayName}</div>
      <div style="font-size:14px;color:#8b949e;margin-top:4px;">${alert.userPrincipalName}</div>
      <div style="margin-top:8px;">
        ${(alert.roles || []).map(r => `<span style="display:inline-block;padding:2px 10px;background:#21262d;color:#f5a623;border-radius:12px;font-size:11px;font-weight:600;margin-right:6px;">${r}</span>`).join('')}
      </div>
    </div>

    <!-- Anomaly Detail -->
    <div style="padding:24px;border-bottom:1px solid #30363d;">
      <div style="font-size:11px;color:#8b949e;text-transform:uppercase;letter-spacing:0.5px;margin-bottom:12px;">Anomaly Detected</div>
      <div style="background:#161b22;border-left:3px solid ${color};padding:12px 16px;border-radius:0 6px 6px 0;">
        <div style="color:#e6edf3;font-size:14px;">${alert.detail}</div>
      </div>
    </div>

    <!-- Sign-in Details -->
    <div style="padding:24px;border-bottom:1px solid #30363d;">
      <div style="font-size:11px;color:#8b949e;text-transform:uppercase;letter-spacing:0.5px;margin-bottom:12px;">Sign-in Details</div>
      <table style="width:100%;border-collapse:collapse;">
        ${buildDetailRow('Time', new Date(alert.signInTime).toLocaleString())}
        ${buildDetailRow('IP Address', alert.ipAddress || 'Unknown')}
        ${buildDetailRow('Location', [alert.city, alert.country].filter(Boolean).join(', ') || 'Unknown')}
        ${buildDetailRow('Device', alert.deviceName ? `${alert.deviceName} (${alert.deviceOs || 'Unknown OS'})` : 'Unknown')}
        ${buildDetailRow('Application', alert.appName || 'Unknown')}
      </table>
    </div>

    <!-- Actions Taken -->
    <div style="padding:24px;border-bottom:1px solid #30363d;background:#161b22;">
      <div style="font-size:11px;color:#8b949e;text-transform:uppercase;letter-spacing:0.5px;margin-bottom:8px;">Automatic Actions Triggered</div>
      ${['critical', 'high'].includes(alert.severity)
        ? `<div style="color:#3fb950;font-size:13px;">✓ User sessions revoked — MFA will be required on next sign-in</div>
           <div style="color:#3fb950;font-size:13px;margin-top:4px;">✓ Security notification sent to user</div>`
        : `<div style="color:#8b949e;font-size:13px;">• Logged for review (no automatic action for ${alert.severity} severity)</div>`
      }
    </div>

    <!-- Footer -->
    <div style="padding:16px 24px;text-align:center;">
      <div style="font-size:12px;color:#8b949e;">
        Modern Endpoint — Privileged Identity Monitor<br>
        Alert ID: ${alert.id}
      </div>
    </div>
  </div>
</body>
</html>`;
}

function buildDetailRow(label, value) {
  return `
    <tr>
      <td style="padding:6px 0;color:#8b949e;font-size:12px;width:100px;">${label}</td>
      <td style="padding:6px 0;color:#e6edf3;font-size:13px;">${value}</td>
    </tr>`;
}

function buildUserNoticeHtml(user, alert) {
  return `
<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"></head>
<body style="margin:0;padding:0;background:#0d1117;font-family:'Segoe UI',Arial,sans-serif;">
  <div style="max-width:600px;margin:0 auto;background:#0d1117;border:1px solid #30363d;border-radius:8px;overflow:hidden;">
    
    <div style="background:#FF3B3B;padding:20px 24px;">
      <div style="font-size:22px;font-weight:700;color:#fff;">🔒 Security Action Required</div>
      <div style="color:rgba(255,255,255,0.85);margin-top:4px;font-size:14px;">Your account requires immediate verification</div>
    </div>

    <div style="padding:24px;">
      <p style="color:#e6edf3;font-size:15px;margin:0 0 16px;">Hello <strong>${user.displayName}</strong>,</p>
      <p style="color:#8b949e;font-size:14px;margin:0 0 16px;">
        Our security system detected unusual activity on your privileged account. As a precaution, 
        your active sessions have been terminated.
      </p>
      <div style="background:#161b22;border:1px solid #f5a623;border-radius:6px;padding:16px;margin-bottom:16px;">
        <div style="color:#f5a623;font-weight:600;margin-bottom:8px;">Detected: ${alert.anomalyLabel}</div>
        <div style="color:#8b949e;font-size:13px;">${alert.detail}</div>
      </div>
      <p style="color:#8b949e;font-size:14px;margin:0 0 16px;">
        When you next sign in, you will be required to complete multi-factor authentication.
        If this was not you, contact your IT administrator immediately.
      </p>
      <p style="color:#8b949e;font-size:12px;margin:0;">
        This is an automated security notification from Modern Endpoint — Privileged Identity Monitor.
      </p>
    </div>
  </div>
</body>
</html>`;
}

async function sendAdminAlert(alert) {
  const adminEmail = process.env.ALERT_ADMIN_EMAIL;
  if (!adminEmail) {
    console.warn('[Email] ALERT_ADMIN_EMAIL not configured');
    return;
  }

  await graphService.sendAlertEmail({
    to: adminEmail,
    subject: `[${alert.severity.toUpperCase()}] Privileged User Alert — ${alert.anomalyLabel} — ${alert.userPrincipalName}`,
    body: buildAdminAlertHtml(alert)
  });
}

async function sendUserSecurityNotice(user, alert) {
  const userEmail = user.mail || user.userPrincipalName;
  if (!userEmail) return;

  await graphService.sendAlertEmail({
    to: userEmail,
    subject: '🔒 Security Alert: Unusual Activity Detected on Your Account',
    body: buildUserNoticeHtml(user, alert)
  });
}

module.exports = { sendAdminAlert, sendUserSecurityNotice };
