'use strict';
const crypto = require('node:crypto');

const NOT_APPROVED = (reason) => Object.freeze({ status: 'NOT_APPROVED', reason });
const explicitDecisions = new WeakSet();

// Replaceable human-auth interface. Only a webhook authenticated with the
// independent webhook secret may feed CVE callbacks into this broker. Missing
// configuration denies; the bot token or caller-provided boolean is not proof.
function createApprovalBroker({ fetchImpl = (...args) => fetch(...args), now = Date.now,
  config = () => ({ token: process.env.TELEGRAM_BOT_TOKEN, chatId: process.env.TELEGRAM_CHAT_ID,
    webhookSecret: process.env.TELEGRAM_WEBHOOK_SECRET,
    approvers: (process.env.TELEGRAM_APPROVER_USER_IDS || '').split(',').map(s => s.trim()).filter(Boolean) }) } = {}) {
  const pending = new Map();
  return {
    async request(tenantId, cveId, plan, timeoutMs) {
      let cfg, fingerprint;
      try { cfg = structuredClone(config()); fingerprint = planHash(plan); } catch (_) { return NOT_APPROVED('CONFIGURATION_OR_PLAN_INVALID'); }
      if (!cfg || !cfg.token || !cfg.chatId || !cfg.webhookSecret || !Array.isArray(cfg.approvers) || !cfg.approvers.length || !cfg.approvers.every(id => typeof id === 'string' && id.trim())) return NOT_APPROVED('CONFIGURATION_MISSING');
      if (!Number.isFinite(timeoutMs) || timeoutMs <= 0 || timeoutMs > 15 * 60_000) return NOT_APPROVED('INVALID_TIMEOUT');
      const requestId = crypto.randomBytes(16).toString('hex');
      const expiresAt = now() + timeoutMs;
      let resultResolve;
      const result = new Promise(resolve => { resultResolve = resolve; });
      const controller = new AbortController();
      const record = { tenantId, cveId, requestId, expiresAt, planHash: fingerprint, cfg, messageId: null,
        finish(decision) { clearTimeout(record.timer); pending.delete(requestId); controller.abort(); resultResolve(decision); } };
      record.timer = setTimeout(() => record.finish(NOT_APPROVED('TIMEOUT')), timeoutMs);
      pending.set(requestId, record);
      // The response timer covers transport, JSON parsing AND human response.
      // A hanging notification never prevents NOT_APPROVED from resolving.
      Promise.resolve().then(async () => {
        const response = await fetchImpl('https://api.telegram.org/bot' + cfg.token + '/sendMessage', {
          method: 'POST', signal: controller.signal, headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ chat_id: cfg.chatId,
            text: `Review remediation ${cveId} for tenant ${tenantId}. Plan fingerprint: ${record.planHash}. P0 execution remains held; this records a decision only.`,
            reply_markup: { inline_keyboard: [[{ text: 'Approve this plan', callback_data: `approve_cve:${requestId}` }, { text: 'Reject', callback_data: `skip_cve:${requestId}` }]] } })
        });
        if (!pending.has(requestId)) return;
        if (!response || response.ok !== true) return record.finish(NOT_APPROVED('TRANSPORT_FAILED'));
        const data = await response.json();
        if (!pending.has(requestId)) return;
        if (data?.ok !== true || !Number.isSafeInteger(data?.result?.message_id) || String(data?.result?.chat?.id) !== String(cfg.chatId)) return record.finish(NOT_APPROVED('MALFORMED_RESPONSE'));
        record.messageId = data.result.message_id;
      }).catch(() => { if (pending.has(requestId)) record.finish(NOT_APPROVED('TRANSPORT_FAILED')); });
      return result;
    },
    callback(query) {
      const match = /^(approve_cve|skip_cve):([a-f0-9]{32})$/.exec(query?.data || '');
      if (!match) return false;
      const record = pending.get(match[2]);
      if (!record) return false;
      if (record.expiresAt <= now()) { record.finish(NOT_APPROVED('EXPIRED')); return false; }
      if (!record.messageId || query?.from?.is_bot !== false || !record.cfg.approvers.includes(String(query?.from?.id)) || String(query?.message?.chat?.id) !== String(record.cfg.chatId) || query?.message?.message_id !== record.messageId) return false;
      if (match[1] === 'skip_cve') { record.finish(NOT_APPROVED('REJECTED')); return true; }
      const decision = Object.freeze({ status: 'APPROVED_EXPLICITLY', requestId: record.requestId,
        tenantId: record.tenantId, planHash: record.planHash, approver: String(query.from.id), expiresAt: record.expiresAt });
      explicitDecisions.add(decision);
      record.finish(decision);
      return true;
    },
    cancelAll() { for (const record of pending.values()) record.finish(NOT_APPROVED('CANCELLED')); }
  };
}

function canonical(value) {
  if (value === null || typeof value === 'string' || typeof value === 'boolean') return JSON.stringify(value);
  if (typeof value === 'number' && Number.isFinite(value)) return JSON.stringify(value);
  if (Array.isArray(value)) return '[' + value.map(canonical).join(',') + ']';
  if (value && Object.getPrototypeOf(value) === Object.prototype) return '{' + Object.keys(value).filter(k => value[k] !== undefined).sort().map(k => JSON.stringify(k)+':'+canonical(value[k])).join(',') + '}';
  throw new Error('P0_INVALID_REMEDIATION_PLAN');
}
function planHash(plan) { return crypto.createHash('sha256').update(canonical(plan)).digest('hex'); }
function isExplicit(decision) { return !!decision && explicitDecisions.has(decision) && decision.status === 'APPROVED_EXPLICITLY' && decision.expiresAt > Date.now(); }

function assertExecutionHeld() {
  // Transport authentication is necessary but not yet sufficient for execution:
  // current executors resolve mutable package/device targets after approval.
  // Do NOT add an env bypass. Frozen-target execution is a release prerequisite.
  const error = new Error('P0_REMEDIATION_HELD: independently authenticated approval of the final execution plan is required');
  error.code = 'P0_REMEDIATION_HELD'; error.status = 423; throw error;
}

function authenticateWebhook(req) {
  const expected = process.env.TELEGRAM_WEBHOOK_SECRET;
  const supplied = req.headers?.['x-telegram-bot-api-secret-token'];
  if (!expected || typeof supplied !== 'string') return false;
  const a = Buffer.from(expected), b = Buffer.from(supplied);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

module.exports = { createApprovalBroker, NOT_APPROVED, isExplicit, planHash, assertExecutionHeld, authenticateWebhook };
