// incidentService.js — Incident timeline + notes + owner + evidence

const fs   = require('fs');
const path = require('path');

const DIR = process.env.NODE_ENV === 'production'
  ? '/home/incidents' : path.join(__dirname, '../../../incidents');
if (!fs.existsSync(DIR)) fs.mkdirSync(DIR, { recursive: true });

const EVENTS = {
  ALERT_CREATED:      { label: 'Alert detected',              icon: '🚨', color: '#ff3b3b' },
  EMAIL_SENT:         { label: 'Alert email sent',            icon: '📧', color: '#4a90d9' },
  TELEGRAM_SENT:      { label: 'Telegram alert sent',         icon: '🤖', color: '#4a90d9' },
  SESSION_REVOKED:    { label: 'Sessions revoked',            icon: '🔒', color: '#f5a623' },
  USER_DISABLED:      { label: 'Account disabled',            icon: '🚫', color: '#ff3b3b' },
  MFA_REQUIRED:       { label: 'MFA re-challenge triggered',  icon: '🔐', color: '#f5a623' },
  ALERT_RESOLVED:     { label: 'Marked as resolved',          icon: '✅', color: '#2ecc71' },
  ALERT_DISMISSED:    { label: 'Dismissed as false positive', icon: '👁',  color: '#8ba3cc' },
  NOTE_ADDED:         { label: 'Investigation note added',    icon: '📝', color: '#8ba3cc' },
  WHITELIST_ADDED:    { label: 'Added to whitelist',          icon: '✓',  color: '#2ecc71' },
  OWNER_ASSIGNED:     { label: 'Assigned to investigator',    icon: '👤', color: '#4a90d9' },
  APPROVAL_REQUESTED: { label: 'Action approval requested',   icon: '⏳', color: '#f5a623' },
  APPROVAL_GRANTED:   { label: 'Action approved',             icon: '✅', color: '#2ecc71' },
  APPROVAL_DENIED:    { label: 'Action denied',               icon: '❌', color: '#ff3b3b' },
  EVIDENCE_EXPORTED:  { label: 'Evidence pack exported',      icon: '📄', color: '#8ba3cc' },
  AUTO_REVOKE:        { label: 'Auto-revoked (15min timeout)', icon: '🤖', color: '#ff6b35' },
  PLAYBOOK_RUN:       { label: 'Playbook executed',           icon: '▶️', color: '#4a90d9' },
  BASELINE_UPDATED:   { label: 'Baseline updated',            icon: '📊', color: '#2ecc71' }
};

function filePath(tenantId, alertId) {
  return path.join(DIR, tenantId + '_' + alertId.replace(/[^a-zA-Z0-9_-]/g, '_') + '.jsonl');
}

function addEvent(tenantId, alertId, type, details, actor) {
  details = details || {};
  actor   = actor   || 'system';
  const ev = {
    timestamp: new Date().toISOString(),
    tenantId, alertId, type,
    label: EVENTS[type] ? EVENTS[type].label : type,
    icon:  EVENTS[type] ? EVENTS[type].icon  : '•',
    color: EVENTS[type] ? EVENTS[type].color : '#8ba3cc',
    actor, details
  };
  try { fs.appendFileSync(filePath(tenantId, alertId), JSON.stringify(ev) + '\n'); }
  catch (e) { console.error('[Incident]', e.message); }
  return ev;
}

function getTimeline(tenantId, alertId) {
  const fp = filePath(tenantId, alertId);
  if (!fs.existsSync(fp)) return [];
  try {
    return fs.readFileSync(fp, 'utf8').split('\n')
      .filter(Boolean).map(l => JSON.parse(l));
  } catch (e) { return []; }
}

module.exports = { addEvent, getTimeline, EVENTS };
