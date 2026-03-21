// settingsService.js — per-tenant settings persisted to Azure Table Storage
const tableStorage = require('./tableStorage');

const _cache = new Map();
const CACHE_TTL = 60 * 1000;

function _cacheGet(tenantId) {
  const entry = _cache.get(tenantId);
  if (!entry) return null;
  if (Date.now() > entry.expiresAt) { _cache.delete(tenantId); return null; }
  return entry.data;
}
function _cacheSet(tenantId, data) { _cache.set(tenantId, { data, expiresAt: Date.now() + CACHE_TTL }); }

function defaultSettings(tenantId) {
  const trialEnd = new Date(Date.now() + 14 * 24 * 60 * 60 * 1000).toISOString();
  return {
    tenantId, createdAt: new Date().toISOString(), updatedAt: new Date().toISOString(),
    billing: { plan: 'trial', trialStarted: new Date().toISOString(), trialEndsAt: trialEnd, pricePerMonth: 10, currency: 'USD', tenantCount: 1 },
    admins: [],
    notifications: { adminEmails: [], userNotify: true, emailOnSeverity: ['critical', 'high', 'medium'], telegramBotToken: process.env.TELEGRAM_BOT_TOKEN || '', telegramChatId: process.env.TELEGRAM_CHAT_ID || '', telegramOnSeverity: ['critical', 'high'] },
    detectionRules: { NEW_IP: { enabled: true, severity: 'medium' }, NEW_COUNTRY: { enabled: true, severity: 'high' }, UNKNOWN_DEVICE: { enabled: true, severity: 'medium' }, IMPOSSIBLE_TRAVEL: { enabled: true, severity: 'critical' }, OFF_HOURS: { enabled: false, severity: 'low' }, FAILED_MFA: { enabled: true, severity: 'high' }, HIGH_RISK: { enabled: true, severity: 'critical' } },
    workHours: { timezone: 'Asia/Jerusalem', startHour: 7, endHour: 20, workDays: [0,1,2,3,4], slaMode: 'business_hours', criticalRuns24x7: true, quietHoursEnabled: false, quietStartHour: 22, quietEndHour: 6 },
    businessHours: { timezone: 'Asia/Jerusalem', startHour: 7, endHour: 20, workDays: [0,1,2,3,4], slaMode: 'business_hours', criticalRuns24x7: true, quietHoursEnabled: false, quietStartHour: 22, quietEndHour: 6 },
    autoActions: { critical: { revokeSession: true, disableUser: false, telegramPlaybook: true }, high: { revokeSession: true, disableUser: false, telegramPlaybook: true }, medium: { revokeSession: false, disableUser: false, telegramPlaybook: false }, low: { revokeSession: false, disableUser: false, telegramPlaybook: false } },
    whitelist: { ips: [], countries: [], devices: [], users: [] },
    monitoredRoles: ['Global Administrator', 'Intune Administrator', 'Cloud Device Administrator', 'Privileged Role Administrator'],
    policyPack: 'balanced',
    escalation: { enabled: true, criticalMinutes: 30, highMinutes: 120, notifyRoles: ['owner', 'admin', 'msp_operator'] },
    approvalPolicies: { critical: ['responder', 'admin', 'owner'], high: ['responder', 'admin'], medium: ['analyst'], low: ['analyst'] },
    assignmentRules: { enabled: true, severityOwners: { critical: '', high: '', medium: '', low: '' }, defaultOwner: '' },
    runbooks: { critical: ['Validate sign-in context and correlated alerts', 'Trigger session revoke if user risk remains elevated', 'Escalate to tenant owner for emergency approval'], high: ['Review sign-in evidence and confirm device posture', 'Notify owner and responder lane'], medium: ['Review anomaly details', 'Add comment and assign analyst'], low: ['Monitor only'] },
    orchestrationPolicies: { allowCrossTenantSweep: true, allowBulkNotify: true, requireApprovalForDisable: true, maxTenantsPerRun: 10 },
    responsePolicies: { critical: { slaMinutes: 30, autoContain: true, requireApproval: true, notifyRoles: ['owner', 'admin', 'responder'], allowedActions: ['monitor', 'revoke', 'disable'] }, high: { slaMinutes: 120, autoContain: false, requireApproval: true, notifyRoles: ['owner', 'admin'], allowedActions: ['monitor', 'revoke'] }, medium: { slaMinutes: 240, autoContain: false, requireApproval: false, notifyRoles: ['analyst'], allowedActions: ['monitor'] }, low: { slaMinutes: 480, autoContain: false, requireApproval: false, notifyRoles: ['analyst'], allowedActions: ['monitor'] } },
    suppressionRules: [],
    responseExceptions: { rolesRequireApproval: ['Global Administrator', 'Privileged Role Administrator'], blockedActionsByRole: { 'Break Glass Account': ['disable'], 'Emergency Access': ['disable'] } },
    retentionPolicy: { incidentDays: 180, auditDays: 365, reportDays: 365, includeDismissedInTrend: true }
  };
}

function _migrate(data, tenantId) {
  const def = defaultSettings(tenantId);
  ['billing','admins','workHours','businessHours','policyPack','escalation','approvalPolicies','assignmentRules','runbooks','orchestrationPolicies','responsePolicies','suppressionRules','responseExceptions','retentionPolicy'].forEach(k => { if (!data[k]) data[k] = def[k]; });
  if (data.workHours && !data.businessHours) data.businessHours = data.workHours;
  return data;
}

async function _fetchAndCache(tenantId) {
  try {
    const raw = await tableStorage.getTenantSettings(tenantId);
    if (raw && Object.keys(raw).length > 2) {
      const data = _migrate({ ...raw, tenantId }, tenantId);
      _cacheSet(tenantId, data);
      return data;
    }
  } catch (err) { console.warn('[Settings] Azure fetch failed:', err.message); }
  const def = defaultSettings(tenantId);
  _cacheSet(tenantId, def);
  return def;
}

function getSettings(tenantId) {
  const cached = _cacheGet(tenantId);
  if (cached) return cached;
  _fetchAndCache(tenantId).catch(() => {});
  return defaultSettings(tenantId);
}

async function getSettingsAsync(tenantId) {
  const cached = _cacheGet(tenantId);
  if (cached) return cached;
  return _fetchAndCache(tenantId);
}

function saveSettings(tenantId, updates) {
  const current = _cacheGet(tenantId) || defaultSettings(tenantId);
  const merged = deepMerge(current, updates);
  if (merged.workHours && !merged.businessHours) merged.businessHours = merged.workHours;
  merged.tenantId = tenantId; merged.updatedAt = new Date().toISOString();
  _cacheSet(tenantId, merged);
  tableStorage.saveTenantSettings(tenantId, merged).catch(err => console.error('[Settings] save error:', err.message));
  return merged;
}

async function saveSettingsAsync(tenantId, updates) {
  const current = await getSettingsAsync(tenantId);
  const merged = deepMerge(current, updates);
  if (merged.workHours && !merged.businessHours) merged.businessHours = merged.workHours;
  merged.tenantId = tenantId; merged.updatedAt = new Date().toISOString();
  await tableStorage.saveTenantSettings(tenantId, merged);
  _cacheSet(tenantId, merged);
  return merged;
}

function getTrialStatus(tenantId) {
  const s = getSettings(tenantId);
  const billing = s.billing || {};
  const now = Date.now();
  if (billing.plan === 'active')    return { status: 'active',    daysLeft: null };
  if (billing.plan === 'cancelled') return { status: 'cancelled', daysLeft: 0 };
  const trialEnd = new Date(billing.trialEndsAt || 0).getTime();
  const daysLeft = Math.max(0, Math.ceil((trialEnd - now) / (24 * 60 * 60 * 1000)));
  if (billing.plan === 'trial' && daysLeft > 0) return { status: 'trial', daysLeft };
  return { status: 'expired', daysLeft: 0 };
}

function isTrialOrActive(tenantId) { const { status } = getTrialStatus(tenantId); return status === 'trial' || status === 'active'; }
function addAdmin(tenantId, admin) { const s = getSettings(tenantId); if (!s.admins) s.admins = []; if (!s.admins.find(a => a.email === admin.email)) s.admins.push({ ...admin, addedAt: new Date().toISOString() }); return saveSettings(tenantId, { admins: s.admins }); }
function removeAdmin(tenantId, email) { const s = getSettings(tenantId); s.admins = (s.admins || []).filter(a => a.email !== email); return saveSettings(tenantId, { admins: s.admins }); }
function getAdmins(tenantId) { return getSettings(tenantId).admins || []; }

function isOffHours(settings, dateStr) {
  const wh = settings.workHours; if (!wh) return false;
  try {
    const d = new Date(dateStr);
    const localHour = new Date(d.toLocaleString('en-US', { timeZone: wh.timezone })).getHours();
    const localDay  = new Date(d.toLocaleString('en-US', { timeZone: wh.timezone })).getDay();
    return !(wh.workDays || [0,1,2,3,4]).includes(localDay) || !(localHour >= (wh.startHour || 7) && localHour < (wh.endHour || 20));
  } catch (e) { return false; }
}

function isWhitelisted(settings, signIn) {
  const wl = settings.whitelist || {};
  if (wl.users    && wl.users.includes(signIn.userPrincipalName)) return true;
  if (wl.ips      && signIn.ipAddress && wl.ips.includes(signIn.ipAddress)) return true;
  const country = signIn.location?.countryOrRegion;
  if (wl.countries && country && wl.countries.includes(country)) return true;
  const deviceName = signIn.deviceDetail?.displayName;
  const deviceId   = signIn.deviceDetail?.deviceId;
  if (wl.devices && ((deviceName && wl.devices.includes(deviceName)) || (deviceId && wl.devices.includes(deviceId)))) return true;
  return false;
}

function isRuleEnabled(settings, anomalyType) { return settings.detectionRules?.[anomalyType]?.enabled !== false; }
function getEffectiveSeverity(settings, anomalyType) { return settings.detectionRules?.[anomalyType]?.severity || 'medium'; }

function getAdminEmails(settings) {
  const emails = [...(settings.notifications?.adminEmails || [])];
  for (const admin of (settings.admins || [])) {
    if (['owner', 'admin'].includes(admin.role) && admin.email && !emails.includes(admin.email)) emails.push(admin.email);
  }
  return emails;
}

function deepMerge(target, source) {
  const result = Object.assign({}, target);
  for (const key of Object.keys(source)) {
    if (source[key] && typeof source[key] === 'object' && !Array.isArray(source[key])) result[key] = deepMerge(target[key] || {}, source[key]);
    else result[key] = source[key];
  }
  return result;
}

module.exports = { getSettings, getSettingsAsync, saveSettings, saveSettingsAsync, getTrialStatus, isTrialOrActive, addAdmin, removeAdmin, getAdmins, isWhitelisted, isRuleEnabled, getEffectiveSeverity, getAdminEmails, isOffHours, defaultSettings };
