const express = require('express');
const router = express.Router();
const emailService = require('../services/emailService');

const isMock = () => process.env.MOCK_MODE === 'true';

// GET /api/mock/status
router.get('/status', (req, res) => {
  res.json({
    mockMode: isMock(),
    message: isMock()
      ? '✅ MOCK_MODE is ON — using simulated data'
      : '⚠️ MOCK_MODE is OFF — using live Graph API'
  });
});

// POST /api/mock/test-mail
// Send a real test email to verify email configuration
router.post('/test-mail', async (req, res) => {
  const { to } = req.body;
  const adminEmail = to || process.env.ALERT_ADMIN_EMAIL;

  if (!adminEmail) {
    return res.status(400).json({
      success: false,
      error: 'No recipient — set ALERT_ADMIN_EMAIL in env or pass { "to": "email@domain.com" } in request body'
    });
  }

  const testAlert = {
    id: 'test-mail-' + Date.now(),
    userId: 'test-user',
    userDisplayName: 'Test User',
    userPrincipalName: 'test@yourtenant.com',
    roles: ['Global Administrator'],
    signInId: 'test-signin',
    signInTime: new Date().toISOString(),
    ipAddress: '1.2.3.4',
    country: 'Test Country',
    city: 'Test City',
    deviceName: 'Test Device',
    deviceOs: 'Windows 11',
    appName: 'Microsoft Azure Portal',
    anomalyType: 'TEST',
    anomalyLabel: '🧪 Test Alert — Email Configuration Check',
    severity: 'medium',
    detail: 'This is a test email to verify that alert notifications are working correctly.',
    status: 'open',
    detectedAt: new Date().toISOString(),
    actionsTriggered: []
  };

  console.log('[Test Mail] Sending test email to:', adminEmail);

  try {
    await emailService.sendAdminAlert(testAlert);
    console.log('[Test Mail] ✅ Success');
    res.json({
      success: true,
      message: 'Test email sent to ' + adminEmail,
      sentAt: new Date().toISOString(),
      recipient: adminEmail,
      sender: process.env.ALERT_SENDER_EMAIL || 'not configured'
    });
  } catch (err) {
    console.error('[Test Mail] ❌ Failed:', err.message);
    res.status(500).json({
      success: false,
      error: err.message,
      hint: checkEmailConfig()
    });
  }
});

// POST /api/mock/trigger-alert
router.post('/trigger-alert', async (req, res) => {
  const { scenario = 'impossible_travel', sendEmail = true } = req.body;

  const scenarios = {
    impossible_travel: {
      id: 'mock-triggered-' + Date.now(),
      userId: 'mock-user-001',
      userDisplayName: 'Alex Johnson',
      userPrincipalName: 'alex.johnson@contoso.com',
      roles: ['Global Administrator'],
      signInId: 'signin-test-' + Date.now(),
      signInTime: new Date().toISOString(),
      ipAddress: '103.21.244.0',
      country: 'Japan',
      city: 'Tokyo',
      deviceName: 'Unknown Device',
      deviceOs: 'Windows 10',
      appName: 'Azure Portal',
      anomalyType: 'IMPOSSIBLE_TRAVEL',
      anomalyLabel: 'Impossible Travel',
      severity: 'critical',
      detail: '9,200 km in 0.7 hours — physically impossible (Tel Aviv → Tokyo)',
      status: 'open',
      detectedAt: new Date().toISOString(),
      actionsTriggered: []
    },
    new_country: {
      id: 'mock-triggered-' + Date.now(),
      userId: 'mock-user-002',
      userDisplayName: 'Sarah Mitchell',
      userPrincipalName: 'sarah.mitchell@contoso.com',
      roles: ['Intune Administrator'],
      signInId: 'signin-test-' + Date.now(),
      signInTime: new Date().toISOString(),
      ipAddress: '185.220.101.45',
      country: 'North Korea',
      city: 'Pyongyang',
      deviceName: 'SARAH-WORKSTATION',
      deviceOs: 'macOS',
      appName: 'Microsoft Intune Admin Center',
      anomalyType: 'NEW_COUNTRY',
      anomalyLabel: 'New Country Detected',
      severity: 'high',
      detail: 'Sign-in from new country: North Korea',
      status: 'open',
      detectedAt: new Date().toISOString(),
      actionsTriggered: []
    },
    unknown_device: {
      id: 'mock-triggered-' + Date.now(),
      userId: 'mock-user-004',
      userDisplayName: 'Emma Torres',
      userPrincipalName: 'emma.torres@contoso.com',
      roles: ['Intune Administrator'],
      signInId: 'signin-test-' + Date.now(),
      signInTime: new Date().toISOString(),
      ipAddress: '198.51.100.99',
      country: 'China',
      city: 'Beijing',
      deviceName: null,
      deviceOs: 'Android',
      appName: 'Microsoft Intune',
      anomalyType: 'UNKNOWN_DEVICE',
      anomalyLabel: 'Unrecognized Device',
      severity: 'medium',
      detail: 'Unrecognized Android device — never seen before',
      status: 'open',
      detectedAt: new Date().toISOString(),
      actionsTriggered: []
    },
    off_hours: {
      id: 'mock-triggered-' + Date.now(),
      userId: 'mock-user-005',
      userDisplayName: 'Daniel Carter',
      userPrincipalName: 'daniel.carter@contoso.com',
      roles: ['Security Administrator'],
      signInId: 'signin-test-' + Date.now(),
      signInTime: new Date(Date.now() - 2 * 3600000).toISOString(),
      ipAddress: '91.108.4.200',
      country: 'Germany',
      city: 'Berlin',
      deviceName: 'DANIEL-LAPTOP',
      deviceOs: 'Windows 11',
      appName: 'Microsoft Entra ID',
      anomalyType: 'OFF_HOURS',
      anomalyLabel: 'Off-Hours Sign-in',
      severity: 'low',
      detail: 'Sign-in at 03:14 UTC — outside configured work hours (06:00–22:00)',
      status: 'open',
      detectedAt: new Date().toISOString(),
      actionsTriggered: []
    },
    failed_mfa: {
      id: 'mock-triggered-' + Date.now(),
      userId: 'mock-user-006',
      userDisplayName: 'Olivia Chen',
      userPrincipalName: 'olivia.chen@contoso.com',
      roles: ['Exchange Administrator'],
      signInId: 'signin-test-' + Date.now(),
      signInTime: new Date().toISOString(),
      ipAddress: '45.155.205.233',
      country: 'Russia',
      city: 'Moscow',
      deviceName: null,
      deviceOs: 'Linux',
      appName: 'Exchange Admin Center',
      anomalyType: 'FAILED_MFA',
      anomalyLabel: 'MFA Failure',
      severity: 'high',
      detail: 'MFA challenge failed (error 500121) from Russia — high-risk country',
      status: 'open',
      detectedAt: new Date().toISOString(),
      actionsTriggered: []
    },
    high_risk: {
      id: 'mock-triggered-' + Date.now(),
      userId: 'mock-user-007',
      userDisplayName: 'Marcus Webb',
      userPrincipalName: 'marcus.webb@contoso.com',
      roles: ['Global Administrator', 'Privileged Role Administrator'],
      signInId: 'signin-test-' + Date.now(),
      signInTime: new Date().toISOString(),
      ipAddress: '185.220.101.180',
      country: 'Iran',
      city: 'Tehran',
      deviceName: null,
      deviceOs: 'Unknown',
      appName: 'Azure Portal',
      anomalyType: 'HIGH_RISK',
      anomalyLabel: 'High Risk (Entra ID)',
      severity: 'critical',
      detail: 'Microsoft Entra ID flagged this sign-in as high risk (leaked credentials / anonymous proxy)',
      status: 'open',
      detectedAt: new Date().toISOString(),
      actionsTriggered: []
    },
    lateral_movement: {
      id: 'mock-triggered-' + Date.now(),
      userId: 'mock-user-008',
      userDisplayName: 'Ryan Blackwood',
      userPrincipalName: 'ryan.blackwood@contoso.com',
      roles: ['SharePoint Administrator'],
      signInId: null,
      signInTime: new Date().toISOString(),
      ipAddress: null,
      country: null,
      city: null,
      deviceName: null,
      deviceOs: null,
      appName: 'Microsoft Entra ID',
      anomalyType: 'LATERAL_MOVEMENT',
      anomalyLabel: 'Lateral Movement Detected',
      severity: 'critical',
      detail: '3 role/group/permission change(s): Add member to role → Global Administrator | Add app role assignment → Microsoft Graph | Add delegated permission grant → Mail.ReadWrite',
      source: 'audit_log',
      status: 'open',
      detectedAt: new Date().toISOString(),
      actionsTriggered: []
    },
    unusual_deletion: {
      id: 'mock-triggered-' + Date.now(),
      userId: 'mock-user-009',
      userDisplayName: 'Jessica Park',
      userPrincipalName: 'jessica.park@contoso.com',
      roles: ['User Administrator'],
      signInId: null,
      signInTime: new Date().toISOString(),
      ipAddress: null,
      country: null,
      city: null,
      deviceName: null,
      deviceOs: null,
      appName: 'Microsoft Entra ID',
      anomalyType: 'UNUSUAL_DELETION',
      anomalyLabel: 'Unusual Deletion Activity',
      severity: 'high',
      detail: '17 deletion(s) — avg 1.2/day. Targets: User Account: john.doe, Group: Finance-Team, Application: Corp-VPN',
      source: 'audit_log',
      status: 'open',
      detectedAt: new Date().toISOString(),
      actionsTriggered: []
    },
    unusual_rule_creation: {
      id: 'mock-triggered-' + Date.now(),
      userId: 'mock-user-010',
      userDisplayName: 'Nathan Brooks',
      userPrincipalName: 'nathan.brooks@contoso.com',
      roles: ['Conditional Access Administrator'],
      signInId: null,
      signInTime: new Date().toISOString(),
      ipAddress: null,
      country: null,
      city: null,
      deviceName: null,
      deviceOs: null,
      appName: 'Microsoft Entra ID',
      anomalyType: 'UNUSUAL_RULE_CREATION',
      anomalyLabel: 'Suspicious Policy/Rule Creation',
      severity: 'high',
      detail: '4 policy/rule creation(s) outside normal pattern: Add conditional access policy, Add named location, Add authentication strength, Set cross-tenant access policy',
      source: 'audit_log',
      status: 'open',
      detectedAt: new Date().toISOString(),
      actionsTriggered: []
    },
    high_velocity: {
      id: 'mock-triggered-' + Date.now(),
      userId: 'mock-user-011',
      userDisplayName: 'Sophie Lambert',
      userPrincipalName: 'sophie.lambert@contoso.com',
      roles: ['Global Administrator'],
      signInId: 'signin-test-' + Date.now(),
      signInTime: new Date().toISOString(),
      ipAddress: '5.188.206.14',
      country: 'Ukraine',
      city: 'Kyiv',
      deviceName: null,
      deviceOs: 'Windows',
      appName: 'Microsoft 365 Admin Center',
      anomalyType: 'HIGH_VELOCITY',
      anomalyLabel: 'Unusual Sign-in Frequency',
      severity: 'medium',
      detail: '12 sign-ins in the last 10 minutes — credential stuffing or automated attack pattern',
      status: 'open',
      detectedAt: new Date().toISOString(),
      actionsTriggered: []
    }
  };

  const alert = scenarios[scenario] || scenarios.impossible_travel;

  console.log('\n========================================');
  console.log('[MOCK TRIGGER] Alert generated:');
  console.log('  User:     ' + alert.userDisplayName + ' (' + alert.userPrincipalName + ')');
  console.log('  Anomaly:  ' + alert.anomalyLabel);
  console.log('  Severity: ' + alert.severity.toUpperCase());
  console.log('  Detail:   ' + alert.detail);
  console.log('========================================\n');

  const result = { alert, emailSent: false, emailError: null };

  if (sendEmail) {
    const adminEmail = process.env.ALERT_ADMIN_EMAIL;
    if (!adminEmail) {
      result.emailError = 'ALERT_ADMIN_EMAIL not configured';
    } else {
      try {
        await emailService.sendAdminAlert(alert);
        result.emailSent = true;
        console.log('[MOCK] ✅ Alert email sent to ' + adminEmail);
      } catch (err) {
        result.emailError = err.message;
        console.error('[MOCK] ❌ Email failed:', err.message);
      }
    }
  }

  res.json(result);
});

// GET /api/auth/debug — TEMPORARY
router.get('/status', (req, res) => {
  res.json({ mockMode: isMock() });
});

function checkEmailConfig() {
  const issues = [];
  if (!process.env.ALERT_SENDER_EMAIL) issues.push('ALERT_SENDER_EMAIL is not set');
  if (!process.env.ALERT_ADMIN_EMAIL)  issues.push('ALERT_ADMIN_EMAIL is not set');
  if (!process.env.CLIENT_ID)          issues.push('CLIENT_ID is not set (needed for Mail.Send)');
  if (!process.env.CLIENT_SECRET)      issues.push('CLIENT_SECRET is not set');
  if (!process.env.TENANT_ID)          issues.push('TENANT_ID is not set');
  return issues.length > 0 ? 'Config issues: ' + issues.join(', ') : 'Config looks OK — check Graph API permissions (Mail.Send)';
}

module.exports = router;

// POST /api/mock/test-telegram
router.post('/test-telegram', async (req, res) => {
  const telegramService = require('../services/telegramService');

  if (!process.env.TELEGRAM_BOT_TOKEN || !process.env.TELEGRAM_CHAT_ID) {
    return res.status(400).json({
      success: false,
      error:   'Telegram not configured',
      hint:    'Set TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID in environment variables'
    });
  }

  try {
    // Send a realistic mock alert with action buttons
    const mockAlert = {
      id:               'test-' + Date.now(),
      tenantId:         'test-tenant',
      userId:           'test-user',
      userDisplayName:  'Test Admin User',
      userPrincipalName:'admin@yourtenant.com',
      roles:            ['Global Administrator'],
      anomalyLabel:     '🧪 Test Alert — Bot Configuration Check',
      severity:         'high',
      detail:           'This is a test alert to verify Telegram integration is working.',
      ipAddress:        '1.2.3.4',
      country:          'Test Country',
      city:             'Test City',
      deviceName:       'Test Device',
      deviceOs:         'Windows 11',
      appName:          'Azure Portal',
      signInTime:       new Date().toISOString(),
      detectedAt:       new Date().toISOString(),
      actionsTriggered: []
    };

    await telegramService.sendAlertWithPlaybook(mockAlert);

    res.json({
      success:  true,
      message:  'Test alert sent to Telegram! Check your bot for the message with action buttons.',
      chatId:   process.env.TELEGRAM_CHAT_ID,
      sentAt:   new Date().toISOString()
    });

    console.log('[Test Telegram] ✅ Test alert sent');
  } catch (err) {
    console.error('[Test Telegram] ❌ Failed:', err.message);
    res.status(500).json({
      success: false,
      error:   err.message,
      hint:    'Check TELEGRAM_BOT_TOKEN is valid and TELEGRAM_CHAT_ID is correct'
    });
  }
});
