const graphService    = require('./graphService');
const alertsStore     = require('./alertsStore');
const emailService    = require('./emailService');
const settingsService = require('./settingsService');
const behavioralEngine = require('./behavioralEngine');
const siemService = require('./siemService');
const incidentStore = require('./incidentStore');

// ─── Application Risk Weights ─────────────────────────────────────────────
// Sign-in to high-privilege portals = more dangerous than Outlook
const APP_RISK_WEIGHT = {
  // Critical admin surfaces — weight 3x
  'Microsoft Azure':                    3,
  'Azure Portal':                       3,
  'Microsoft Azure Management':         3,
  'Microsoft Intune':                   3,
  'Microsoft Intune Enrollment':        3,
  'Intune Company Portal':              3,
  'Microsoft 365 Admin Center':         3,
  'Microsoft Entra ID':                 3,
  'Azure Active Directory':             3,
  'Microsoft Graph':                    3,
  'Microsoft Graph Explorer':           3,
  'Privileged Identity Management':     3,
  'Azure AD Privileged Identity Mgmt':  3,
  // High admin surfaces — weight 2x
  'Exchange Admin Center':              2,
  'Security and Compliance Center':     2,
  'Microsoft Defender':                 2,
  'Microsoft Defender for Endpoint':    2,
  'Microsoft Defender for Cloud':       2,
  'SharePoint Online':                  2,
  'Microsoft Purview':                  2,
  'Microsoft Teams Admin Center':       2,
  'Power Platform Admin Center':        2,
  // Standard M365 apps — weight 1x (default)
  'Microsoft Teams':                    1,
  'Outlook':                            1,
  'OneDrive':                           1,
  'SharePoint':                         1,
  'Office 365':                         1,
};

function getAppRiskWeight(appDisplayName) {
  if (!appDisplayName) return 1;
  // Exact match first
  if (APP_RISK_WEIGHT[appDisplayName] !== undefined) return APP_RISK_WEIGHT[appDisplayName];
  // Partial match
  for (const [key, weight] of Object.entries(APP_RISK_WEIGHT)) {
    if (appDisplayName.toLowerCase().includes(key.toLowerCase())) return weight;
  }
  return 1;
}


const ANOMALY = {
  NEW_IP:            'NEW_IP',
  NEW_COUNTRY:       'NEW_COUNTRY',
  UNKNOWN_DEVICE:    'UNKNOWN_DEVICE',
  IMPOSSIBLE_TRAVEL: 'IMPOSSIBLE_TRAVEL',
  OFF_HOURS:         'OFF_HOURS',
  FAILED_MFA:        'FAILED_MFA',
  HIGH_RISK:         'HIGH_RISK'
};

const ANOMALY_LABELS = {
  NEW_IP:            'New IP Address',
  NEW_COUNTRY:       'New Country Detected',
  UNKNOWN_DEVICE:    'Unrecognized Device',
  IMPOSSIBLE_TRAVEL: 'Impossible Travel',
  OFF_HOURS:         'Off-Hours Sign-in',
  FAILED_MFA:        'MFA Failure',
  HIGH_RISK:         'High Risk Sign-in'
};

function toRuntimeBaseline(profile) {
  return {
    knownIPs: new Set(profile.knownIPs || []),
    knownCountries: new Set(profile.knownCountries || []),
    knownDevices: new Set(profile.knownDevices || []),
    recentSignIns: profile.recentSignIns || [],
    lastUpdated: profile.lastUpdated || null
  };
}

function getBaseline(tenantId, userId) {
  return toRuntimeBaseline(incidentStore.getBaselineProfile(tenantId, userId));
}

function updateBaseline(tenantId, userId, signIn, options = {}) {
  incidentStore.updateBaselineProfile(tenantId, userId, signIn, options);
}

function haversineKm(lat1, lon1, lat2, lon2) {
  const R = 6371, dLat = (lat2-lat1)*Math.PI/180, dLon = (lon2-lon1)*Math.PI/180;
  const a = Math.sin(dLat/2)**2 + Math.cos(lat1*Math.PI/180)*Math.cos(lat2*Math.PI/180)*Math.sin(dLon/2)**2;
  return R * 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1-a));
}

function isOffHours(dateStr) {
  const hour = new Date(dateStr).getUTCHours();
  return hour < 6 || hour > 22;
}

function detectAnomalies(tenantId, userId, signIn, baseline, settings) {
  const anomalies = [];
  const isSuccess = signIn.status && signIn.status.errorCode === 0;
  const ip        = signIn.ipAddress;
  const country   = signIn.location && signIn.location.countryOrRegion;
  const deviceId  = signIn.deviceDetail && signIn.deviceDetail.deviceId;
  const deviceName = signIn.deviceDetail && signIn.deviceDetail.displayName;

  // Skip whitelisted sign-ins entirely
  if (settingsService.isWhitelisted(settings, signIn, null)) return [];

  if (ip && baseline.knownIPs.size > 0 && !baseline.knownIPs.has(ip) &&
      settingsService.isRuleEnabled(settings, 'NEW_IP')) {
    anomalies.push({ type: ANOMALY.NEW_IP, detail: 'Sign-in from new IP: ' + ip });
  }

  if (country && baseline.knownCountries.size > 0 && !baseline.knownCountries.has(country) &&
      settingsService.isRuleEnabled(settings, 'NEW_COUNTRY')) {
    anomalies.push({ type: ANOMALY.NEW_COUNTRY, detail: 'Sign-in from new country: ' + country });
  }

  if (deviceId && baseline.knownDevices.size > 0 && !baseline.knownDevices.has(deviceId) &&
      settingsService.isRuleEnabled(settings, 'UNKNOWN_DEVICE')) {
    anomalies.push({ type: ANOMALY.UNKNOWN_DEVICE, detail: 'Unrecognized device: ' + (deviceName || deviceId) });
  }

  const lat = signIn.location && signIn.location.geoCoordinates ? signIn.location.geoCoordinates.latitude  : null;
  const lon = signIn.location && signIn.location.geoCoordinates ? signIn.location.geoCoordinates.longitude : null;
  const t   = new Date(signIn.createdDateTime).getTime();

  if (lat && lon && isSuccess && settingsService.isRuleEnabled(settings, 'IMPOSSIBLE_TRAVEL')) {
    for (const prev of baseline.recentSignIns.slice(-5)) {
      if (!prev.lat || !prev.lon) continue;
      const hrs  = Math.abs(t - new Date(prev.time).getTime()) / 3600000;
      if (hrs < 0.5) continue;
      const dist = haversineKm(prev.lat, prev.lon, lat, lon);
      if (dist > hrs * 900 && dist > 500) {
        anomalies.push({ type: ANOMALY.IMPOSSIBLE_TRAVEL, detail: Math.round(dist) + ' km in ' + hrs.toFixed(1) + ' hours — physically impossible' });
        break;
      }
    }
  }

  if (isOffHours(signIn.createdDateTime) && isSuccess &&
      settingsService.isRuleEnabled(settings, 'OFF_HOURS')) {
    anomalies.push({ type: ANOMALY.OFF_HOURS, detail: 'Sign-in at ' + new Date(signIn.createdDateTime).toUTCString() });
  }

  if (['high', 'medium'].includes(signIn.riskLevelAggregated) &&
      settingsService.isRuleEnabled(settings, 'HIGH_RISK')) {
    anomalies.push({ type: ANOMALY.HIGH_RISK, detail: 'Entra ID risk level: ' + signIn.riskLevelAggregated });
  }

  return anomalies;
}

async function scanUser(tenantId, user, signIns, settings) {
  const baseline   = getBaseline(tenantId, user.id);
  const newAlerts  = [];
  const sorted     = [...signIns].sort((a,b) => new Date(a.createdDateTime) - new Date(b.createdDateTime));

  for (const signIn of sorted) {
    // ── Behavioral scoring (replaces static threshold detection) ──
    const scoring   = behavioralEngine.scoreSignIn(signIn, baseline, settings);
    if (scoring.isClean) {
      updateBaseline(tenantId, user.id, signIn);
      continue;
    }
    // Convert scoring factors to anomalies format
    const anomalies = scoring.factors.map(f => ({
      type:   f.type,
      detail: f.detail,
      score:  f.score
    }));

    for (const anomaly of anomalies) {
      const severity = settingsService.getEffectiveSeverity(settings, anomaly.type);
      const alert = {
        id:                `${tenantId}-${user.id}-${signIn.id}-${anomaly.type}`,
        tenantId,
        userId:            user.id,
        userDisplayName:   user.displayName,
        userPrincipalName: user.userPrincipalName,
        roles:             user.roles,
        signInId:          signIn.id,
        signInTime:        signIn.createdDateTime,
        ipAddress:         signIn.ipAddress,
        country:           signIn.location && signIn.location.countryOrRegion,
        city:              signIn.location && signIn.location.city,
        deviceName:        signIn.deviceDetail && signIn.deviceDetail.displayName,
        deviceOs:          signIn.deviceDetail && signIn.deviceDetail.operatingSystem,
        appName:           signIn.appDisplayName,
        anomalyType:       anomaly.type,
        anomalyLabel:      behavioralEngine.ANOMALY_LABELS[anomaly.type] || anomaly.type,
        severity:          scoring.severity || severity,
        riskScore:         scoring.score,
        appTier:           scoring.appTier,
        riskFactors:       scoring.factors,
        detail:            anomaly.detail,
        status:            'open',
        detectedAt:        new Date().toISOString(),
        actionsTriggered:  []
      };

      if (!alertsStore.exists(alert.id)) {
        // Also check Azure Tables to prevent duplicates after restart
        const tableStorage = require('./tableStorage');
        let existsInAzure = false;
        try {
          const existing = await tableStorage.getAlerts(tenantId, {});
          existsInAzure = existing.some(a => a.id === alert.id);
        } catch (e) { /* ignore — proceed with add */ }

        if (!existsInAzure) {
          alertsStore.add(alert);
          const baselineProfile = incidentStore.getBaselineProfile(tenantId, user.id);
          incidentStore.recordIncident(tenantId, alert, {
            baseline: baselineProfile,
            entraRiskContext: { riskScore: scoring.score, appTier: scoring.appTier, factors: scoring.factors },
            geoContext: { city: alert.city || null, country: alert.country || null, ipAddress: alert.ipAddress || null },
            deviceContext: { name: alert.deviceName || null, os: alert.deviceOs || null },
            recommendedAction: alert.severity === 'critical' ? 'revoke' : alert.severity === 'high' ? 'triage' : 'monitor',
            updateDetail: alert.detail
          });
          newAlerts.push(alert);
          if (settings.siem) {
            siemService.forwardAlert(alert, settings.siem).catch(e => console.error('[SIEM] forward error:', e.message));
          }
        }
      }
    } // end for anomaly
    updateBaseline(tenantId, user.id, signIn, { anomalies, severity: scoring.severity, alertId: newAlerts[newAlerts.length - 1]?.id || null });
  }
  return newAlerts;
}

async function runFullScan(tenantId) {
  if (!tenantId) { console.warn('[Anomaly] No tenantId — skipping'); return []; }

  const settings   = settingsService.getSettings(tenantId);
  const users      = await graphService.getPrivilegedUsers(tenantId);
  const allAlerts  = [];

  for (const user of users) {
    // Skip whitelisted users
    if (settings.whitelist.users && settings.whitelist.users.includes(user.userPrincipalName)) continue;

    try {
      const signIns   = await graphService.getUserSignIns(tenantId, user.id, 48);
      const newAlerts = await scanUser(tenantId, user, signIns, settings);
      allAlerts.push(...newAlerts);

      if (newAlerts.length > 0) {
        await triggerActions(tenantId, newAlerts, user, settings);
      }
    } catch (err) {
      console.error('[Anomaly] Error scanning', user.userPrincipalName, ':', err.message);
    }
  }

  console.log('[Anomaly] Scan complete for', tenantId, '— new alerts:', allAlerts.length);
  return allAlerts;
}

async function triggerActions(tenantId, alerts, user, settings) {
  const adminEmails = settingsService.getAdminEmails(settings);
  const notifyCfg   = settings.notifications || {};
  const telegramCfg = settings.notifications || {};

  // ── Notification matrix ───────────────────────────────────────────────
  // critical → Telegram (immediate) + email (immediate)
  // high     → email (immediate)
  // medium   → email only if configured
  // low      → digest only (no immediate notifications)
  const emailSeverities   = notifyCfg.emailOnSeverity   || ['critical', 'high', 'medium'];
  const telegramSeverities = notifyCfg.telegramOnSeverity || ['critical', 'high'];

  const telegramToken  = telegramCfg.telegramBotToken || process.env.TELEGRAM_BOT_TOKEN;
  const telegramChatId = telegramCfg.telegramChatId   || process.env.TELEGRAM_CHAT_ID;

  for (const alert of alerts) {
    const actions     = settings.autoActions?.[alert.severity] || {};
    const shouldEmail    = emailSeverities.includes(alert.severity) && adminEmails.length > 0;
    const shouldTelegram = telegramSeverities.includes(alert.severity) && telegramToken && telegramChatId;

    // ── Immediate Telegram (critical/high) ────────────────────────────
    if (shouldTelegram) {
      try {
        const telegramService = require('./telegramService');
        const emoji = alert.severity === 'critical' ? '🚨' : '⚠️';
        await telegramService.sendMessageWithToken(telegramToken, telegramChatId,
          `${emoji} *${alert.severity.toUpperCase()} Alert*\n\n` +
          `*User:* ${escMd(alert.userDisplayName)}\n` +
          `*UPN:* \`${escMd(alert.userPrincipalName)}\`\n` +
          `*Threat:* ${escMd(alert.anomalyLabel)}\n` +
          `*Detail:* ${escMd(alert.detail)}\n` +
          `*App:* ${escMd(alert.appName || 'Unknown')}\n` +
          `*Location:* ${escMd([alert.city, alert.country].filter(Boolean).join(', ') || 'Unknown')}\n` +
          `*IP:* \`${escMd(alert.ipAddress || 'N/A')}\`\n` +
          `*Detected:* ${new Date(alert.detectedAt).toLocaleString('en-GB')}`
        );
        alertsStore.addAction(alert.id, 'telegram_sent');
      } catch (err) {
        console.error('[Actions] Telegram failed:', err.message);
      }
    }

    // ── Email (critical/high/medium) ──────────────────────────────────
    if (shouldEmail) {
      for (const email of adminEmails) {
        try {
          await emailService.sendAdminAlert(alert, tenantId, email);
          alertsStore.addAction(alert.id, 'admin_email_sent:' + email);
        } catch (err) {
          console.error('[Actions] Email to', email, 'failed:', err.message);
        }
      }
    }

    // ── Revoke sessions ───────────────────────────────────────────────
    if (actions.revokeSession) {
      try {
        await graphService.revokeUserSessions(tenantId, user.id);
        alertsStore.addAction(alert.id, 'sessions_revoked');
        if (notifyCfg.userNotify && (user.mail || user.userPrincipalName)) {
          await emailService.sendUserSecurityNotice(user, alert, tenantId);
          alertsStore.addAction(alert.id, 'user_notified');
        }
      } catch (err) {
        console.error('[Actions] Revoke failed:', err.message);
      }
    }

    // ── Disable user ──────────────────────────────────────────────────
    if (actions.disableUser) {
      try {
        await graphService.disableUser(tenantId, user.id);
        alertsStore.addAction(alert.id, 'user_disabled');
        console.log('[Actions] User disabled:', user.userPrincipalName);
      } catch (err) {
        console.error('[Actions] Disable user failed:', err.message);
      }
    }
  }
}

function escMd(str) {
  if (!str) return '';
  return String(str).replace(/[_*[\]()~`>#+=|{}.!\\-]/g, '\\$&');
}


// ─── Upgrade severity based on app risk ───────────────────────────────────
function upgradeSeverityByApp(baseSeverity, appDisplayName) {
  const weight = getAppRiskWeight(appDisplayName);
  if (weight < 2) return baseSeverity; // Standard apps — no upgrade

  // High/critical apps — bump up one level
  const LEVELS = ['low', 'medium', 'high', 'critical'];
  const idx = LEVELS.indexOf(baseSeverity);
  if (idx < 0) return baseSeverity;

  if (weight >= 3) {
    // Critical admin portals — bump up two levels
    return LEVELS[Math.min(idx + 2, LEVELS.length - 1)];
  }
  // High admin portals — bump up one level
  return LEVELS[Math.min(idx + 1, LEVELS.length - 1)];
}

module.exports = { runFullScan, scanUser, ANOMALY, ANOMALY_LABELS };
