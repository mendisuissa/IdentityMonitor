// approvalService.js — Two-admin approval flow for destructive actions
// Critical actions (disable account) require second admin via Telegram

const fs   = require('fs');
const path = require('path');

const DIR = process.env.NODE_ENV === 'production'
  ? '/home/approvals' : path.join(__dirname, '../../../approvals');
if (!fs.existsSync(DIR)) fs.mkdirSync(DIR, { recursive: true });

const STATUS = { PENDING: 'pending', APPROVED: 'approved', DENIED: 'denied', EXPIRED: 'expired' };

const ACTIONS_REQUIRING_APPROVAL = {
  DISABLE_USER:      { label: 'Disable Account',     risk: 'critical', timeoutMin: 30 },
  BULK_REVOKE:       { label: 'Revoke All Sessions',  risk: 'high',     timeoutMin: 15 },
  WHITELIST_COUNTRY: { label: 'Whitelist Country',    risk: 'high',     timeoutMin: 60 }
};

function createApproval(tenantId, alertId, action, requestedBy, details) {
  const id = 'appr-' + Date.now();
  const expiresAt = new Date(Date.now() + (ACTIONS_REQUIRING_APPROVAL[action]?.timeoutMin || 30) * 60 * 1000).toISOString();
  const approval = { id, tenantId, alertId, action, requestedBy, details, status: STATUS.PENDING, createdAt: new Date().toISOString(), expiresAt, approvedBy: null, deniedBy: null };
  fs.writeFileSync(path.join(DIR, id + '.json'), JSON.stringify(approval, null, 2));
  return approval;
}

function getApproval(id) {
  const fp = path.join(DIR, id + '.json');
  if (!fs.existsSync(fp)) return null;
  try { return JSON.parse(fs.readFileSync(fp, 'utf8')); } catch (e) { return null; }
}

function resolveApproval(id, decision, resolvedBy) {
  const ap = getApproval(id);
  if (!ap) return null;
  if (new Date(ap.expiresAt) < new Date()) { ap.status = STATUS.EXPIRED; }
  else { ap.status = decision === 'approve' ? STATUS.APPROVED : STATUS.DENIED; }
  ap.approvedBy = decision === 'approve' ? resolvedBy : null;
  ap.deniedBy   = decision === 'deny'    ? resolvedBy : null;
  ap.resolvedAt = new Date().toISOString();
  fs.writeFileSync(path.join(DIR, id + '.json'), JSON.stringify(ap, null, 2));
  return ap;
}

function getPendingApprovals(tenantId) {
  try {
    return fs.readdirSync(DIR)
      .filter(f => f.endsWith('.json'))
      .map(f => { try { return JSON.parse(fs.readFileSync(path.join(DIR, f), 'utf8')); } catch { return null; } })
      .filter(a => a && a.tenantId === tenantId && a.status === STATUS.PENDING && new Date(a.expiresAt) > new Date());
  } catch { return []; }
}

module.exports = { createApproval, getApproval, resolveApproval, getPendingApprovals, STATUS, ACTIONS_REQUIRING_APPROVAL };
