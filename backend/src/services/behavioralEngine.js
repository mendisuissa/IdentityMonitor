// behavioralEngine.js — Behavioral Baseline + Smart Risk Scoring
// Replaces simple "new IP = medium" with context-aware scoring
//
// Score components (0-100):
//   Anomaly base score × App weight × Context multipliers = Final Risk Score
//   Risk Score → Severity: <25=low, 25-50=medium, 50-75=high, 75+=critical

// ─── Country Risk Categories ──────────────────────────────────────────────
const COUNTRY_RISK = {
  // Tier 3 — Nation-state threat actors, common source of attacks
  HIGH_RISK: new Set([
    'Russia', 'China', 'North Korea', 'Iran', 'Belarus',
    'Syria', 'Venezuela', 'Cuba', 'Myanmar'
  ]),
  // Tier 2 — Elevated risk, less common for legitimate admin work
  MEDIUM_RISK: new Set([
    'Ukraine', 'Romania', 'Brazil', 'Nigeria', 'Vietnam',
    'Indonesia', 'Pakistan', 'Bangladesh', 'Ghana'
  ])
};

// ─── Application Risk Tiers ───────────────────────────────────────────────
const APP_TIERS = {
  CRITICAL: [ // Admin portals — highest risk if compromised
    'azure portal', 'microsoft azure', 'microsoft intune',
    'microsoft entra', 'azure active directory', 'microsoft 365 admin',
    'privileged identity management', 'microsoft graph',
    'security and compliance', 'microsoft defender for cloud'
  ],
  HIGH: [     // Admin-adjacent — elevated risk
    'exchange admin', 'sharepoint admin', 'teams admin',
    'power platform admin', 'microsoft defender', 'microsoft purview'
  ],
  MEDIUM: [   // Standard M365 apps
    'sharepoint', 'teams', 'yammer', 'power apps', 'power bi'
  ]
  // LOW = everything else (Outlook, OneDrive, etc.)
};

function getAppTier(appName) {
  if (!appName) return 'LOW';
  const lower = appName.toLowerCase();
  if (APP_TIERS.CRITICAL.some(a => lower.includes(a))) return 'CRITICAL';
  if (APP_TIERS.HIGH.some(a => lower.includes(a)))     return 'HIGH';
  if (APP_TIERS.MEDIUM.some(a => lower.includes(a)))   return 'MEDIUM';
  return 'LOW';
}

function getCountryRisk(country) {
  if (!country) return 'LOW';
  if (COUNTRY_RISK.HIGH_RISK.has(country))   return 'HIGH';
  if (COUNTRY_RISK.MEDIUM_RISK.has(country)) return 'MEDIUM';
  return 'LOW';
}

// ─── Haversine distance ───────────────────────────────────────────────────
function haversineKm(lat1, lon1, lat2, lon2) {
  const R = 6371;
  const dLat = (lat2 - lat1) * Math.PI / 180;
  const dLon = (lon2 - lon1) * Math.PI / 180;
  const a = Math.sin(dLat/2)**2 +
    Math.cos(lat1*Math.PI/180) * Math.cos(lat2*Math.PI/180) * Math.sin(dLon/2)**2;
  return R * 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1-a));
}

// ─── Core Behavioral Scoring Engine ──────────────────────────────────────
function scoreSignIn(signIn, baseline, settings) {
  const factors = [];
  let baseScore  = 0;
  const appTier  = getAppTier(signIn.appDisplayName);
  const countryRisk = getCountryRisk(signIn.location?.countryOrRegion);

  // ── Factor 1: New IP ──────────────────────────────────────────────────
  const ip = signIn.ipAddress;
  if (ip && baseline.knownIPs?.length > 0 && !baseline.knownIPs.includes(ip)) {
    let ipScore = 15;
    // Boost if high-risk country
    if (countryRisk === 'HIGH')   ipScore += 20;
    if (countryRisk === 'MEDIUM') ipScore += 10;
    baseScore += ipScore;
    factors.push({ type: 'NEW_IP', score: ipScore, detail: 'New IP: ' + ip + (countryRisk !== 'LOW' ? ' (' + countryRisk + ' risk country)' : '') });
  }

  // ── Factor 2: New Country ─────────────────────────────────────────────
  const country = signIn.location?.countryOrRegion;
  if (country && baseline.knownCountries?.length > 0 && !baseline.knownCountries.includes(country)) {
    let countryScore = 20;
    if (countryRisk === 'HIGH')   countryScore += 35;  // Russia/China/NK = automatic high
    if (countryRisk === 'MEDIUM') countryScore += 15;
    baseScore += countryScore;
    factors.push({ type: 'NEW_COUNTRY', score: countryScore, detail: 'New country: ' + country + ' (risk: ' + countryRisk + ')' });
  }

  // ── Factor 3: Unknown Device ──────────────────────────────────────────
  const deviceId   = signIn.deviceDetail?.deviceId;
  const deviceName = signIn.deviceDetail?.displayName;
  if (deviceId && baseline.knownDevices?.length > 0 && !baseline.knownDevices.includes(deviceId)) {
    const deviceScore = 15;
    baseScore += deviceScore;
    factors.push({ type: 'UNKNOWN_DEVICE', score: deviceScore, detail: 'Unknown device: ' + (deviceName || deviceId) });
  }

  // ── Factor 4: Impossible Travel ───────────────────────────────────────
  const lat = signIn.location?.geoCoordinates?.latitude;
  const lon = signIn.location?.geoCoordinates?.longitude;
  const ts  = new Date(signIn.createdDateTime).getTime();

  if (lat && lon && signIn.status?.errorCode === 0) {
    for (const prev of (baseline.recentSignIns || []).slice(-5)) {
      if (!prev.lat || !prev.lon) continue;
      const hrs  = Math.abs(ts - new Date(prev.time).getTime()) / 3600000;
      if (hrs < 0.1) continue;
      const km   = haversineKm(prev.lat, prev.lon, lat, lon);
      const maxKm = hrs * 900;
      if (km > maxKm && km > 300) {
        const travelScore = 55 + Math.min(20, Math.round((km - 300) / 500));
        baseScore += travelScore;
        factors.push({ type: 'IMPOSSIBLE_TRAVEL', score: travelScore, detail: Math.round(km) + ' km in ' + hrs.toFixed(1) + 'h — physically impossible' });
        break;
      }
    }
  }

  // ── Factor 5: Off-Hours ───────────────────────────────────────────────
  const wh = settings?.workHours;
  if (wh) {
    const settingsService = require('./settingsService');
    if (settingsService.isOffHours(settings, signIn.createdDateTime)) {
      const offScore = 10;
      baseScore += offScore;
      factors.push({ type: 'OFF_HOURS', score: offScore, detail: 'Sign-in outside work hours' });
    }
  }

  // ── Factor 6: High Entra Risk ─────────────────────────────────────────
  if (signIn.riskLevelAggregated === 'high') {
    baseScore += 40;
    factors.push({ type: 'HIGH_RISK', score: 40, detail: 'Entra ID risk: high' });
  } else if (signIn.riskLevelAggregated === 'medium') {
    baseScore += 20;
    factors.push({ type: 'HIGH_RISK', score: 20, detail: 'Entra ID risk: medium' });
  }

  // ── Factor 7: Sign-in velocity (many sign-ins in short time) ─────────
  const recentSignIns = (baseline.recentSignIns || []).filter(s =>
    ts - new Date(s.time).getTime() < 10 * 60 * 1000  // last 10 min
  );
  if (recentSignIns.length >= 8) {  // Raised from 4 → 8 to reduce false positives
    const velScore = 15;
    baseScore += velScore;
    factors.push({ type: 'HIGH_VELOCITY', score: velScore, detail: recentSignIns.length + ' sign-ins in last 10 minutes' });
  }

  // ── Factor 8: Failed MFA ──────────────────────────────────────────────
  if (signIn.status?.errorCode === 500121 || signIn.status?.errorCode === 50074) {
    baseScore += 25;
    factors.push({ type: 'FAILED_MFA', score: 25, detail: 'MFA challenge failed' });
  }

  // ── App Weight Multiplier ─────────────────────────────────────────────
  const APP_MULTIPLIER = { CRITICAL: 2.0, HIGH: 1.5, MEDIUM: 1.2, LOW: 1.0 };
  const multiplier = APP_MULTIPLIER[appTier];
  const finalScore = Math.min(100, Math.round(baseScore * multiplier));

  // ── Map to Severity ───────────────────────────────────────────────────
  let severity;
  if      (finalScore >= 75) severity = 'critical';
  else if (finalScore >= 50) severity = 'high';
  else if (finalScore >= 25) severity = 'medium';
  else if (finalScore > 0)   severity = 'low';
  else                        severity = null; // clean

  // ── Override: respect user's custom severity settings ─────────────────
  // (If admin set NEW_COUNTRY to 'critical', respect that)
  if (factors.length === 1 && settings?.detectionRules) {
    const rule = settings.detectionRules[factors[0].type];
    if (rule && rule.severity) {
      const LEVELS = ['low','medium','high','critical'];
      const customIdx = LEVELS.indexOf(rule.severity);
      const calcIdx   = LEVELS.indexOf(severity);
      severity = LEVELS[Math.max(customIdx, calcIdx)];
    }
  }

  return {
    score:       finalScore,
    severity,
    factors,
    appTier,
    countryRisk,
    multiplier,
    isClean:     finalScore === 0 || factors.length === 0
  };
}

// ─── Get primary anomaly type from factors ────────────────────────────────
function getPrimaryAnomaly(factors) {
  if (!factors || factors.length === 0) return null;
  return factors.sort((a, b) => b.score - a.score)[0];
}

// ─── Build human-readable explanation ────────────────────────────────────
function buildExplanation(result, appName) {
  const { factors, score, appTier, countryRisk, multiplier } = result;
  if (factors.length === 0) return 'Normal sign-in behavior';

  const parts = factors.map(f => f.detail);
  let explanation = parts.join(' + ');

  if (appTier !== 'LOW') {
    explanation += ` · High-risk application: ${appName} (${appTier.toLowerCase()} tier, ×${multiplier} weight)`;
  }

  explanation += ` · Risk score: ${score}/100`;
  return explanation;
}

// ─── ANOMALY type constants (for compatibility) ───────────────────────────
const ANOMALY_LABELS = {
  NEW_IP:            'New IP Address',
  NEW_COUNTRY:       'New Country Detected',
  UNKNOWN_DEVICE:    'Unrecognized Device',
  IMPOSSIBLE_TRAVEL: 'Impossible Travel',
  OFF_HOURS:         'Off-Hours Sign-in',
  FAILED_MFA:        'MFA Failure',
  HIGH_RISK:         'High Risk (Entra ID)',
  HIGH_VELOCITY:     'Unusual Sign-in Frequency'
};

module.exports = {
  scoreSignIn,
  getPrimaryAnomaly,
  buildExplanation,
  getAppTier,
  getCountryRisk,
  ANOMALY_LABELS
};
