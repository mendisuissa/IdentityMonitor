const alertsStore = require('./alertsStore');
const workflowStore = require('./workflowStore');
const incidentStore = require('./incidentStore');
const settingsService = require('./settingsService');

const severityWeight = { critical: 35, high: 22, medium: 12, low: 6 };

function ageDecayFactor(detectedAt) {
  if (!detectedAt) return 1;
  const ageHours = (Date.now() - new Date(detectedAt).getTime()) / 36e5;
  if (ageHours < 24)  return 1.0;   // fresh — full weight
  if (ageHours < 72)  return 0.8;   // 1-3 days
  if (ageHours < 168) return 0.5;   // 3-7 days
  if (ageHours < 720) return 0.25;  // 1 month
  return 0.1;                        // old — minimal weight
}

function calcUserScore(alerts, baseline = {}) {
  const openAlerts = alerts.filter(a => a.status === 'open');
  const dismissed  = alerts.filter(a => a.status === 'dismissed').length;
  const resolutionHistory  = baseline.resolutionHistory  || [];
  const priorAnomalyHistory = baseline.anomalyHistory    || baseline.priorAnomalyHistory || [];

  // Geo variance: unique countries seen in last 30 days
  const recentSignIns = (baseline.recentSignIns || []).filter(s => {
    const ageMs = Date.now() - new Date(s.time || 0).getTime();
    return ageMs < 30 * 24 * 36e5;
  });
  const geoVariance    = new Set(recentSignIns.map(s => s.country).filter(Boolean)).size;
  const deviceVariance = new Set(recentSignIns.map(s => s.deviceId || s.deviceName).filter(Boolean)).size;

  let score = 8;

  // Open alerts with age decay
  for (const alert of openAlerts) {
    const weight = severityWeight[alert.severity] || 8;
    const decay  = ageDecayFactor(alert.detectedAt);
    score += Math.round(weight * decay);
  }

  // Anomaly history (last 30 days only, with decay)
  const recentAnomalies = priorAnomalyHistory.filter(a => {
    const ageMs = Date.now() - new Date(a.time || 0).getTime();
    return ageMs < 30 * 24 * 36e5;
  });
  score += Math.min(15, recentAnomalies.length * 2);

  // Geo variance penalty (>2 countries = suspicious)
  score += Math.min(10, Math.max(0, geoVariance - 2) * 3);

  // Device novelty (>3 devices = suspicious)
  score += Math.min(8, Math.max(0, deviceVariance - 3) * 2);

  // Resolution history reduces score (analyst handling builds trust)
  score -= Math.min(12, resolutionHistory.length * 2);
  score -= Math.min(6,  dismissed * 1);

  return Math.max(0, Math.min(100, Math.round(score)));
}

function classify(score) {
  if (score >= 80) return 'critical';
  if (score >= 55) return 'high';
  if (score >= 30) return 'medium';
  if (score > 0) return 'low';
  return 'clean';
}

function hoursBetween(a, b) {
  const ms = new Date(b).getTime() - new Date(a).getTime();
  return ms > 0 ? ms / 36e5 : null;
}

function getRiskPosture(tenantId) {
  const alerts = alertsStore.getAll(tenantId);
  const settings = settingsService.getSettings(tenantId);
  const userIds = Array.from(new Set(alerts.map(a => a.userId)));
  const users = userIds.map(userId => {
    const userAlerts = alerts.filter(a => a.userId === userId);
    const latest = userAlerts[0] || {};
    const baseline = incidentStore.getBaselineProfile(tenantId, userId);
    const score = calcUserScore(userAlerts, baseline);
    return {
      userId,
      displayName: latest.userDisplayName || userId,
      userPrincipalName: latest.userPrincipalName || '',
      roles: latest.roles || [],
      score,
      level: classify(score),
      openAlerts: userAlerts.filter(a => a.status === 'open').length,
      criticalOpen: userAlerts.filter(a => a.status === 'open' && a.severity === 'critical').length,
      recentAnomalies: (baseline.priorAnomalyHistory || []).slice(-3).reverse(),
      baseline: {
        knownCountries: baseline.knownCountries || [],
        knownDevices: baseline.knownDevices || [],
        knownIPs: baseline.knownIPs || []
      }
    };
  }).sort((a,b) => b.score - a.score).slice(0, 20);

  const closed = alerts.filter(a => a.status !== 'open');
  const mttrHours = closed.map(alert => hoursBetween(alert.detectedAt, alert.resolvedAt)).filter(v => v !== null);
  const workflowCases = workflowStore.getCases(tenantId);
  const acknowledged = workflowCases.map(c => {
    const timestamps = [];
    if (c.updatedAt) timestamps.push(c.updatedAt);
    (c.comments || []).forEach(comment => timestamps.push(comment.createdAt));
    (c.approvalHistory || []).forEach(item => timestamps.push(item.timestamp));
    if (!timestamps.length) return null;
    timestamps.sort();
    return hoursBetween(c.detectedAt, timestamps[0]);
  }).filter(v => v !== null);

  const dayMap = {};
  alerts.forEach(alert => {
    const day = String(alert.detectedAt).slice(0, 10);
    dayMap[day] = dayMap[day] || { day, alerts: 0, autoContained: 0, dismissed: 0, resolved: 0 };
    dayMap[day].alerts += 1;
    if ((alert.actionsTriggered || []).some(a => String(a.action).includes('revoke'))) dayMap[day].autoContained += 1;
    if (alert.status === 'dismissed') dayMap[day].dismissed += 1;
    if (alert.status === 'resolved') dayMap[day].resolved += 1;
  });

  const allScores = users.map(u => u.score);
  const averageRiskScore = allScores.length ? Math.round(allScores.reduce((a,b)=>a+b,0)/allScores.length) : 0;

  return {
    summary: {
      monitoredPrivilegedAccounts: users.length,
      alertsBySeverity: {
        critical: alerts.filter(a => a.severity === 'critical').length,
        high: alerts.filter(a => a.severity === 'high').length,
        medium: alerts.filter(a => a.severity === 'medium').length,
        low: alerts.filter(a => a.severity === 'low').length
      },
      autoContainedIncidents: alerts.filter(a => (a.actionsTriggered || []).some(x => String(x.action).includes('revoke'))).length,
      falsePositiveTrend: alerts.filter(a => a.status === 'dismissed').length,
      mttaHours: acknowledged.length ? Number((acknowledged.reduce((a,b)=>a+b,0)/acknowledged.length).toFixed(1)) : null,
      mttrHours: mttrHours.length ? Number((mttrHours.reduce((a,b)=>a+b,0)/mttrHours.length).toFixed(1)) : null,
      averageRiskScore,
      retention: settings.retentionPolicy || {}
    },
    mostRiskyAdmins: users.slice(0, 8),
    trend: Object.values(dayMap).sort((a,b)=>a.day.localeCompare(b.day)).slice(-30),
    topAnomalyCategories: Object.entries(alerts.reduce((acc, alert) => {
      acc[alert.anomalyLabel || alert.anomalyType] = (acc[alert.anomalyLabel || alert.anomalyType] || 0) + 1;
      return acc;
    }, {})).sort((a,b)=>b[1]-a[1]).slice(0,6).map(([name,count]) => ({ name, count }))
  };
}

module.exports = { getRiskPosture, calcUserScore, classify };
