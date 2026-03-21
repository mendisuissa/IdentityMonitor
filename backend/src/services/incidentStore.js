// incidentStore.js — baselines + incidents persisted to Azure Table Storage
// Table: incidents  — PartitionKey=tenantId, RowKey=alertId
// Table: baselines  — already exists in tableStorage.js (reused here)
const { TableClient } = require('@azure/data-tables');
const tableStorage = require('./tableStorage');

const INCIDENT_TABLE = 'incidents';
let _incClient = null;

function getIncidentClient() {
  if (_incClient) return _incClient;
  const connStr = process.env.AZURE_STORAGE_CONNECTION_STRING;
  if (!connStr) throw new Error('AZURE_STORAGE_CONNECTION_STRING not configured');
  _incClient = TableClient.fromConnectionString(connStr, INCIDENT_TABLE);
  return _incClient;
}

async function ensureTable() {
  try { await getIncidentClient().createTable(); console.log('[IncidentStore] Table ready: incidents'); }
  catch (err) { if (err.statusCode !== 409) console.warn('[IncidentStore] Table init:', err.message); }
}
ensureTable().catch(() => {});

function tryParse(v, fallback) { try { return typeof v === 'string' ? JSON.parse(v) : (v ?? fallback); } catch { return fallback; } }

// ─── BASELINE (delegates to existing tableStorage) ────────────────────────
function getBaselineProfile(tenantId, userId) {
  // Sync wrapper — returns empty baseline, fires async fetch
  _fetchBaselineAsync(tenantId, userId).catch(() => {});
  return _baselineCache.get(`${tenantId}:${userId}`) || _emptyBaseline(userId);
}

function _emptyBaseline(userId) {
  return { userId, knownIPs: [], knownCountries: [], knownDevices: [], recentSignIns: [], anomalyHistory: [], resolutionHistory: [], stats: { totalSignIns: 0, offHoursCount: 0, riskEvents: 0, lastSeenAt: null }, lastUpdated: null };
}

const _baselineCache = new Map();

async function _fetchBaselineAsync(tenantId, userId) {
  const k = `${tenantId}:${userId}`;
  if (_baselineCache.has(k)) return _baselineCache.get(k);
  try {
    const raw = await tableStorage.getBaseline(tenantId, userId);
    const profile = { userId, knownIPs: raw.knownIPs || [], knownCountries: raw.knownCountries || [], knownDevices: raw.knownDevices || [], recentSignIns: raw.recentSignIns || [], anomalyHistory: [], resolutionHistory: [], stats: { totalSignIns: 0, offHoursCount: 0, riskEvents: 0, lastSeenAt: null }, lastUpdated: raw.lastUpdated || null };
    _baselineCache.set(k, profile);
    return profile;
  } catch { return _emptyBaseline(userId); }
}

function updateBaselineProfile(tenantId, userId, signIn, options = {}) {
  const k = `${tenantId}:${userId}`;
  const profile = _baselineCache.get(k) || _emptyBaseline(userId);

  const knownIPs      = new Set(profile.knownIPs);
  const knownCountries = new Set(profile.knownCountries);
  const knownDevices  = new Set(profile.knownDevices);

  if (signIn.ipAddress) knownIPs.add(signIn.ipAddress);
  if (signIn.location?.countryOrRegion) knownCountries.add(signIn.location.countryOrRegion);
  const devId = signIn.deviceDetail?.deviceId || signIn.deviceDetail?.displayName;
  if (devId) knownDevices.add(devId);

  const recentSignIns = [...profile.recentSignIns, {
    id: signIn.id, time: signIn.createdDateTime, ip: signIn.ipAddress || null,
    appName: signIn.appDisplayName || 'Unknown',
    city: signIn.location?.city || null, country: signIn.location?.countryOrRegion || null,
    riskLevel: signIn.riskLevelAggregated || 'none',
    lat: signIn.location?.geoCoordinates?.latitude ?? null, lon: signIn.location?.geoCoordinates?.longitude ?? null,
    deviceId: signIn.deviceDetail?.deviceId || null, deviceName: signIn.deviceDetail?.displayName || null,
    deviceOs: signIn.deviceDetail?.operatingSystem || null,
    status: signIn.status?.errorCode === 0 ? 'success' : 'failed'
  }].slice(-40);

  const anomalyHistory = [...profile.anomalyHistory];
  if (Array.isArray(options.anomalies) && options.anomalies.length) {
    anomalyHistory.push(...options.anomalies.map(a => ({ time: signIn.createdDateTime, type: a.type, severity: options.severity || 'medium', alertId: options.alertId || null, detail: a.detail || '' })));
  }

  const isOffHoursFlag = (() => { const h = new Date(signIn.createdDateTime).getUTCHours(); return h < 6 || h > 22; })();

  const next = {
    ...profile,
    knownIPs: Array.from(knownIPs), knownCountries: Array.from(knownCountries), knownDevices: Array.from(knownDevices),
    recentSignIns, anomalyHistory: anomalyHistory.slice(-80),
    stats: { totalSignIns: (profile.stats?.totalSignIns || 0) + 1, offHoursCount: (profile.stats?.offHoursCount || 0) + (isOffHoursFlag ? 1 : 0), riskEvents: (profile.stats?.riskEvents || 0) + (['medium','high','critical'].includes(signIn.riskLevelAggregated) ? 1 : 0), lastSeenAt: signIn.createdDateTime },
    lastUpdated: new Date().toISOString()
  };
  _baselineCache.set(k, next);

  // Persist to tableStorage baselines table
  tableStorage.saveBaseline(tenantId, userId, next).catch(err => console.error('[IncidentStore] saveBaseline error:', err.message));
  return next;
}

// ─── INCIDENTS ────────────────────────────────────────────────────────────
const _incidentCache = new Map();

async function _getIncidentAsync(tenantId, alertId) {
  const k = `${tenantId}:${alertId}`;
  if (_incidentCache.has(k)) return _incidentCache.get(k);
  try {
    const rowKey = alertId.replace(/[^a-zA-Z0-9_-]/g, '_');
    const entity = await getIncidentClient().getEntity(tenantId, rowKey);
    const incident = {
      alertId: entity.alertId || alertId,
      userId: entity.userId, userDisplayName: entity.userDisplayName, userPrincipalName: entity.userPrincipalName,
      severity: entity.severity, anomalyType: entity.anomalyType, anomalyLabel: entity.anomalyLabel,
      summary: entity.summary, appName: entity.appName || 'Unknown', signInTime: entity.signInTime,
      createdAt: entity.createdAt, updatedAt: entity.updatedAt,
      signInSnapshot: tryParse(entity.signInSnapshot, {}),
      evidence: tryParse(entity.evidence, {}),
      updates: tryParse(entity.updates, []),
      resolutionState: entity.resolutionState, resolutionActor: entity.resolutionActor, resolutionAt: entity.resolutionAt
    };
    _incidentCache.set(k, incident);
    return incident;
  } catch { return null; }
}

function getIncident(tenantId, alertId) {
  const k = `${tenantId}:${alertId}`;
  if (_incidentCache.has(k)) return _incidentCache.get(k);
  _getIncidentAsync(tenantId, alertId).catch(() => {});
  return null;
}

function recordIncident(tenantId, alert, extras = {}) {
  const k = `${tenantId}:${alert.id}`;
  const existing = _incidentCache.get(k) || { createdAt: new Date().toISOString(), updates: [] };
  const incident = {
    ...existing, alertId: alert.id, userId: alert.userId,
    userDisplayName: alert.userDisplayName, userPrincipalName: alert.userPrincipalName,
    severity: alert.severity, anomalyType: alert.anomalyType, anomalyLabel: alert.anomalyLabel,
    summary: alert.detail, appName: alert.appName || existing.appName || 'Unknown', signInTime: alert.signInTime,
    signInSnapshot: { ipAddress: alert.ipAddress || null, country: alert.country || null, city: alert.city || null, deviceName: alert.deviceName || null, deviceOs: alert.deviceOs || null, appName: alert.appName || null, riskScore: alert.riskScore ?? null, appTier: alert.appTier || null, riskFactors: alert.riskFactors || [] },
    evidence: { knownIndicatorsAtDetection: extras.baseline ? { knownIPs: (extras.baseline.knownIPs || []).slice(-8), knownCountries: (extras.baseline.knownCountries || []).slice(-8), knownDevices: (extras.baseline.knownDevices || []).slice(-8) } : (existing.evidence?.knownIndicatorsAtDetection || {}), recommendedAction: extras.recommendedAction || existing.evidence?.recommendedAction || 'monitor', entraRiskContext: extras.entraRiskContext || existing.evidence?.entraRiskContext || null, geoContext: extras.geoContext || null, deviceContext: extras.deviceContext || null },
    updates: [...(existing.updates || []), { timestamp: new Date().toISOString(), type: extras.updateType || 'detection', detail: extras.updateDetail || alert.detail }].slice(-50),
    updatedAt: new Date().toISOString()
  };
  _incidentCache.set(k, incident);

  // Persist async
  const rowKey = alert.id.replace(/[^a-zA-Z0-9_-]/g, '_');
  getIncidentClient().upsertEntity({
    partitionKey: tenantId, rowKey,
    alertId: incident.alertId, userId: incident.userId, userDisplayName: incident.userDisplayName,
    userPrincipalName: incident.userPrincipalName, severity: incident.severity,
    anomalyType: incident.anomalyType, anomalyLabel: incident.anomalyLabel,
    summary: incident.summary, appName: incident.appName, signInTime: incident.signInTime,
    createdAt: incident.createdAt, updatedAt: incident.updatedAt,
    signInSnapshot: JSON.stringify(incident.signInSnapshot),
    evidence: JSON.stringify(incident.evidence),
    updates: JSON.stringify(incident.updates)
  }, 'Replace').catch(err => console.error('[IncidentStore] recordIncident error:', err.message));

  return incident;
}

function recordResolution(tenantId, alert, resolution) {
  const k = `${tenantId}:${alert.id}`;
  const entry = { alertId: alert.id, userId: alert.userId, severity: alert.severity, action: resolution.action, actor: resolution.actor || 'system', note: resolution.note || '', timestamp: new Date().toISOString() };

  // Update baseline resolution history
  const bk = `${tenantId}:${alert.userId}`;
  const profile = _baselineCache.get(bk) || _emptyBaseline(alert.userId);
  profile.resolutionHistory = [entry, ...(profile.resolutionHistory || [])].slice(0, 40);
  _baselineCache.set(bk, profile);
  tableStorage.saveBaseline(tenantId, alert.userId, profile).catch(() => {});

  // Update incident
  const existing = _incidentCache.get(k) || {};
  const updated = { ...existing, resolutionState: resolution.action, resolutionActor: entry.actor, resolutionAt: entry.timestamp, updatedAt: entry.timestamp, updates: [...(existing.updates || []), { timestamp: entry.timestamp, type: 'resolution', detail: `${entry.actor} set case to ${resolution.action}` }].slice(-50) };
  _incidentCache.set(k, updated);
  if (updated.alertId) {
    const rowKey = alert.id.replace(/[^a-zA-Z0-9_-]/g, '_');
    getIncidentClient().upsertEntity({ partitionKey: tenantId, rowKey, ...updated, signInSnapshot: JSON.stringify(updated.signInSnapshot || {}), evidence: JSON.stringify(updated.evidence || {}), updates: JSON.stringify(updated.updates || []) }, 'Replace').catch(() => {});
  }
  return entry;
}

function recommendedActionForSeverity(severity) {
  if (severity === 'critical') return 'revoke sessions and require approval for disable';
  if (severity === 'high')     return 'escalate to responder and validate geo/device context';
  if (severity === 'medium')   return 'triage with related sign-ins and analyst note';
  return 'monitor and keep baseline current';
}

function buildInvestigation(tenantId, alert, workflow) {
  if (!alert) return null;
  const profile = getBaselineProfile(tenantId, alert.userId);
  const incident = getIncident(tenantId, alert.id) || {};
  const alertTime = new Date(alert.signInTime || alert.detectedAt).getTime();
  const windowMs  = 2 * 3600 * 1000; // ±2 hours

  // Related: same sign-in window (±2h), same IP, or same country — excluding the triggering sign-in
  const relatedSignIns = (profile.recentSignIns || [])
    .filter(item => item.id !== alert.signInId)
    .map(item => {
      const itemTime = new Date(item.time || 0).getTime();
      const timeDiff = Math.abs(itemTime - alertTime);
      const sameWindow  = timeDiff <= windowMs;
      const sameIp      = item.ip && item.ip === alert.ipAddress;
      const sameCountry = item.country && item.country === alert.country;
      return { ...item, correlation: { sameWindow, sameIp, sameCountry, score: (sameIp ? 3 : 0) + (sameCountry ? 2 : 0) + (sameWindow ? 1 : 0) } };
    })
    .filter(item => item.correlation.score > 0 || (profile.recentSignIns || []).indexOf(item) < 5)
    .sort((a, b) => b.correlation.score - a.correlation.score)
    .slice(0, 10);
  const timeline = [
    { type: 'detected', title: 'Incident detected', subtitle: alert.anomalyLabel, detail: alert.detail, time: alert.detectedAt },
    { type: 'signin', title: 'Suspicious sign-in', subtitle: alert.signInTime, detail: `${alert.city || 'Unknown city'}, ${alert.country || 'Unknown country'} · ${alert.ipAddress || 'No IP'}`, time: alert.signInTime },
    ...((incident.updates || []).map(u => ({ type: u.type, title: u.type === 'resolution' ? 'Resolution update' : 'Evidence update', subtitle: u.timestamp, detail: u.detail, time: u.timestamp })))
  ].sort((a, b) => new Date(b.time) - new Date(a.time));

  return {
    summary: { alertId: alert.id, severity: alert.severity, anomalyLabel: alert.anomalyLabel, status: alert.status, userDisplayName: alert.userDisplayName, userPrincipalName: alert.userPrincipalName, roles: alert.roles || [], appName: alert.appName || 'Unknown', recommendedAction: workflow?.requestedAction || incident?.evidence?.recommendedAction || recommendedActionForSeverity(alert.severity) },
    anomalyFactors: alert.riskFactors || [],
    signInTimeline: timeline,
    relatedSignIns,
    geoContext: { current: { city: alert.city || null, country: alert.country || null, ipAddress: alert.ipAddress || null }, knownCountries: profile.knownCountries || [], geoVariance: new Set((profile.recentSignIns || []).map(i => i.country).filter(Boolean)).size },
    deviceContext: { current: { name: alert.deviceName || null, os: alert.deviceOs || null }, knownDevices: profile.knownDevices || [], novelty: alert.deviceName && !(profile.knownDevices || []).includes(alert.deviceName) ? 'new' : 'known_or_unknown' },
    entraRiskContext: { score: alert.riskScore || null, appTier: alert.appTier || null, riskEventsSeen: profile.stats?.riskEvents || 0, recentAnomalies: (profile.anomalyHistory || []).slice(-6).reverse() },
    recommendedAction: { primary: workflow?.requestedAction || recommendedActionForSeverity(alert.severity), rationale: alert.severity === 'critical' ? 'Critical privileged anomaly with high business impact potential.' : alert.severity === 'high' ? 'High-confidence privileged anomaly that needs owner validation.' : 'Use analyst review and baseline context before stronger response.' },
    analystNotes: workflow?.comments || [],
    resolutionState: { status: workflow?.caseStatus || (alert.status === 'open' ? 'open' : 'closed'), approvalStatus: workflow?.approvalStatus || 'pending', resolvedBy: alert.resolvedBy || incident?.resolutionActor || null, resolvedAt: alert.resolvedAt || incident?.resolutionAt || null, suppressReason: workflow?.suppressReason || '' },
    baselineProfile: { knownIPs: profile.knownIPs || [], knownCountries: profile.knownCountries || [], knownDevices: profile.knownDevices || [], totalSignIns: profile.stats?.totalSignIns || 0, offHoursCount: profile.stats?.offHoursCount || 0, priorAnomalyHistory: (profile.anomalyHistory || []).slice(-10).reverse(), resolutionHistory: (profile.resolutionHistory || []).slice(0, 6) },
    evidence: incident.evidence || {}
  };
}

module.exports = { getBaselineProfile, updateBaselineProfile, recordIncident, recordResolution, getIncident, buildInvestigation };
