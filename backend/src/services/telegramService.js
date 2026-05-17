// telegramService.js — Telegram Bot for interactive security playbooks
// Admin receives alert → sees buttons: ✅ Approve / ❌ Block / 👁 Investigate
// No action within 15min on critical = auto-block

const TELEGRAM_BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN;
const TELEGRAM_CHAT_ID   = process.env.TELEGRAM_CHAT_ID;

// Pending actions waiting for admin approval: alertId → { resolve, timeout }
const pendingActions = new Map();

// Pending CVE remediations waiting for Telegram Approve/Skip: shortKey → { resolve, timer, messageId, tenantId, cveId }
const pendingCveApprovals = new Map();

function shortId() {
  return Math.random().toString(36).slice(2, 10); // 8-char random key — fits Telegram 64-byte callback_data limit
}

// ─── Send alert with inline keyboard ────────────────────────────────────
// Accepts optional token/chatId overrides so settings-based credentials work
async function sendAlertWithPlaybook(alert, tokenOverride, chatIdOverride) {
  const token  = tokenOverride  || TELEGRAM_BOT_TOKEN;
  const chatId = chatIdOverride || TELEGRAM_CHAT_ID;
  if (!token || !chatId) {
    console.warn('[Telegram] Bot not configured — skipping Telegram notification');
    return null;
  }

  const severityEmoji = {
    critical: '🚨', high: '⚠️', medium: '🔶', low: 'ℹ️'
  }[alert.severity] || '⚠️';

  const text = [
    `${severityEmoji} *PRIVILEGED IDENTITY ALERT*`,
    ``,
    `*Severity:* ${alert.severity.toUpperCase()}`,
    `*Type:* ${alert.anomalyLabel}`,
    ``,
    `*User:* ${escMd(alert.userDisplayName)}`,
    `*UPN:* \`${escMd(alert.userPrincipalName)}\``,
    `*Roles:* ${escMd((alert.roles || []).join(', '))}`,
    ``,
    `*Detail:* ${escMd(alert.detail)}`,
    ``,
    `*IP:* \`${alert.ipAddress || 'unknown'}\``,
    `*Location:* ${escMd([alert.city, alert.country].filter(Boolean).join(', ') || 'Unknown')}`,
    `*Device:* ${escMd(alert.deviceName || 'Unknown')} \\(${escMd(alert.deviceOs || '')}\\)`,
    `*App:* ${escMd(alert.appName || 'Unknown')}`,
    ``,
    `*Detected:* ${escMd(new Date(alert.detectedAt).toLocaleString('en-GB'))}`,
  ].join('\n');

  // Inline keyboard — action buttons
  const keyboard = {
    inline_keyboard: [
      [
        { text: '🔒 Revoke Sessions + Notify User', callback_data: 'revoke:' + alert.id },
        { text: '🚫 Disable Account',               callback_data: 'disable:' + alert.id }
      ],
      [
        { text: '✅ False Positive — Dismiss',       callback_data: 'dismiss:' + alert.id },
        { text: '👁 Investigate Later',               callback_data: 'investigate:' + alert.id }
      ]
    ]
  };

  try {
    const res = await fetch(
      'https://api.telegram.org/bot' + token + '/sendMessage',
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          chat_id:    chatId,
          text,
          parse_mode: 'MarkdownV2',
          reply_markup: keyboard
        })
      }
    );

    const data = await res.json();
    if (!data.ok) throw new Error(data.description);

    console.log('[Telegram] ✅ Alert sent, message_id:', data.result.message_id);

    // For critical alerts — auto-revoke if no action within 15 min
    if (alert.severity === 'critical') {
      scheduleAutoRevoke(alert, data.result.message_id, token, chatId);
    }

    return data.result.message_id;
  } catch (err) {
    console.error('[Telegram] ❌ Send failed:', err.message);
    return null;
  }
}

// ─── Update message after action taken ───────────────────────────────────
async function updateMessageAfterAction(messageId, tokenOrAction, chatIdOrUndefined, actionText) {
  // Supports both old call signature (messageId, actionText) and
  // new call signature (messageId, token, chatId, actionText)
  let token, chatId, text;
  if (actionText !== undefined) {
    token = tokenOrAction || TELEGRAM_BOT_TOKEN;
    chatId = chatIdOrUndefined || TELEGRAM_CHAT_ID;
    text = actionText;
  } else {
    token = TELEGRAM_BOT_TOKEN;
    chatId = TELEGRAM_CHAT_ID;
    text = tokenOrAction; // old signature: second arg was actionText
  }
  if (!token || !chatId) return;
  try {
    await fetch(
      'https://api.telegram.org/bot' + token + '/editMessageReplyMarkup',
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          chat_id:      chatId,
          message_id:   messageId,
          reply_markup: { inline_keyboard: [] }  // Remove buttons
        })
      }
    );
    await sendMessageWithToken(token, chatId, '✅ Action taken: ' + text);
  } catch (err) {
    console.error('[Telegram] updateMessage error:', err.message);
  }
}

// ─── Send simple text message ────────────────────────────────────────────
async function sendMessage(text) {
  if (!TELEGRAM_BOT_TOKEN || !TELEGRAM_CHAT_ID) return;
  try {
    await fetch(
      'https://api.telegram.org/bot' + TELEGRAM_BOT_TOKEN + '/sendMessage',
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          chat_id: TELEGRAM_CHAT_ID,
          text,
          parse_mode: 'Markdown'
        })
      }
    );
  } catch (err) {
    console.error('[Telegram] sendMessage error:', err.message);
  }
}

// ─── Auto-revoke for critical alerts if no action ─────────────────────────
function scheduleAutoRevoke(alert, messageId, token, chatId) {
  const _token  = token  || TELEGRAM_BOT_TOKEN;
  const _chatId = chatId || TELEGRAM_CHAT_ID;
  const TIMEOUT_MS = 15 * 60 * 1000; // 15 minutes

  const timer = setTimeout(async () => {
    if (pendingActions.has(alert.id)) {
      pendingActions.delete(alert.id);
      console.log('[Telegram] ⏰ Auto-revoking sessions for', alert.userPrincipalName, '(no admin action in 15min)');

      try {
        const graphService = require('./graphService');
        await graphService.revokeUserSessions(alert.tenantId, alert.userId);
        await updateMessageAfterAction(messageId, _token, _chatId,
          '🤖 AUTO-REVOKED (no admin action within 15 minutes)\nUser: ' + alert.userDisplayName
        );
      } catch (err) {
        console.error('[Telegram] Auto-revoke failed:', err.message);
      }
    }
  }, TIMEOUT_MS);

  pendingActions.set(alert.id, { timer, messageId, alert });

  // Warn at 10 min
  setTimeout(() => {
    if (pendingActions.has(alert.id)) {
      sendMessageWithToken(_token, _chatId,
        '⏰ *Reminder:* Critical alert for *' + alert.userDisplayName + '*\\. No action yet — auto\\-revoke in 5 minutes\\.'
      );
    }
  }, 10 * 60 * 1000);
}

// ─── Cancel pending auto-revoke ───────────────────────────────────────────
function cancelAutoRevoke(alertId) {
  const pending = pendingActions.get(alertId);
  if (pending) {
    clearTimeout(pending.timer);
    pendingActions.delete(alertId);
  }
}

// ─── Handle callback query from Telegram button press ────────────────────
async function handleCallbackQuery(callbackQuery) {
  const { id, data, message } = callbackQuery;
  const parts    = (data || '').split(':');
  const action   = parts[0];
  const payload  = parts.slice(1).join(':'); // everything after first colon

  // Answer the callback (removes loading state on button)
  await answerCallbackQuery(id);

  console.log('[Telegram] Button pressed:', action, 'payload:', payload);

  // ── CVE approval callbacks ──────────────────────────────────────────────
  if (action === 'approve_cve' || action === 'skip_cve') {
    const key = payload;
    const pending = pendingCveApprovals.get(key);
    if (!pending) {
      await sendMessage('⚠️ This approval request has already expired or been handled.');
      return;
    }
    clearTimeout(pending.timer);
    pendingCveApprovals.delete(key);

    const decision = action === 'approve_cve' ? 'approved' : 'skipped';
    const icon     = decision === 'approved' ? '✅' : '⏭';
    const label    = decision === 'approved' ? 'Approved — remediating now' : 'Skipped — deferred to next run';

    // Remove buttons from original message
    if (message?.message_id) {
      try {
        await fetch('https://api.telegram.org/bot' + TELEGRAM_BOT_TOKEN + '/editMessageReplyMarkup', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            chat_id:    TELEGRAM_CHAT_ID,
            message_id: message.message_id,
            reply_markup: { inline_keyboard: [] }
          })
        });
      } catch (_) {}
    }
    await sendMessage(`${icon} *CVE Approval*: ${pending.cveId} — ${label}`);
    pending.resolve(decision);
    return;
  }

  // ── Alert action callbacks (existing) ────────────────────────────────
  const alertId = payload;
  cancelAutoRevoke(alertId);

  const pending = pendingActions.get(alertId);
  const alert = pending ? pending.alert : null;

  try {
    switch (action) {
      case 'revoke':
        if (alert) {
          const graphService = require('./graphService');
          await graphService.revokeUserSessions(alert.tenantId, alert.userId);
          await updateMessageAfterAction(message.message_id,
            'Sessions revoked for ' + alert.userDisplayName + ' — user will be prompted for MFA'
          );
        }
        break;

      case 'disable':
        if (alert) {
          const graphService = require('./graphService');
          await graphService.disableUser(alert.tenantId, alert.userId);
          await updateMessageAfterAction(message.message_id,
            'Account DISABLED for ' + alert.userDisplayName
          );
        }
        break;

      case 'dismiss':
        await updateMessageAfterAction(message.message_id,
          'Alert dismissed as false positive'
        );
        break;

      case 'investigate':
        await updateMessageAfterAction(message.message_id,
          'Marked for investigation — alert remains open in dashboard'
        );
        break;
    }
  } catch (err) {
    console.error('[Telegram] Callback action failed:', err.message);
    await sendMessage('❌ Action failed: ' + err.message);
  }
}

async function answerCallbackQuery(callbackQueryId) {
  try {
    await fetch(
      'https://api.telegram.org/bot' + TELEGRAM_BOT_TOKEN + '/answerCallbackQuery',
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ callback_query_id: callbackQueryId })
      }
    );
  } catch (err) { /* ignore */ }
}

// ─── Send new-CVE discovery alert ────────────────────────────────────────
async function sendNewCveAlert(tenantId, newCves) {
  const token  = TELEGRAM_BOT_TOKEN;
  const chatId = TELEGRAM_CHAT_ID;
  if (!token || !chatId || !newCves.length) return;

  const sev = (v) => ({ critical: 0, high: 1, medium: 2, low: 3 })[String(v || '').toLowerCase()] ?? 4;
  const sorted = [...newCves].sort((a, b) => sev(a.severity) - sev(b.severity));

  const SEV_EMOJI = { critical: '🔴', high: '🟠', medium: '🟡', low: '🔵' };
  const shortTenant = String(tenantId || '').substring(0, 8);

  let msg = `🆕 *New CVEs Detected* — tenant \`${escMd(shortTenant)}…\`\n`;
  msg += `\n${sorted.length} new vulnerabilit${sorted.length === 1 ? 'y' : 'ies'} since last scan:\n\n`;
  for (const v of sorted.slice(0, 10)) {
    const icon = SEV_EMOJI[String(v.severity || '').toLowerCase()] || '⚪';
    const cve  = escMd(v.cveId || v.id || '?');
    const prod = escMd(v.displayProductName || v.productName || '?');
    const sevLabel = escMd(String(v.severity || '').toUpperCase());
    msg += `${icon} *${cve}* · ${sevLabel} · ${prod}\n`;
  }
  if (sorted.length > 10) msg += `_…and ${sorted.length - 10} more_\n`;
  msg += `\n📊 Open *IdentityMonitor* → Remediation to act`;

  try {
    await fetch('https://api.telegram.org/bot' + token + '/sendMessage', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ chat_id: chatId, text: msg, parse_mode: 'MarkdownV2' })
    });
  } catch (err) {
    console.error('[Telegram] sendNewCveAlert error:', err.message);
  }
}

// ─── Request CVE remediation approval (Critical CVEs) ────────────────────
/**
 * Sends a Telegram message with [✅ Approve] [⏭ Skip] buttons for a critical CVE.
 * Returns a Promise that resolves to 'approved' or 'skipped'.
 * Auto-resolves to 'skipped' after timeoutMs (default 5 min).
 */
async function requestCveApproval(tenantId, cveId, cveData, timeoutMs = 5 * 60 * 1000) {
  const token  = TELEGRAM_BOT_TOKEN;
  const chatId = TELEGRAM_CHAT_ID;
  if (!token || !chatId) return 'approved'; // no bot → proceed automatically

  const key     = shortId();
  const prod    = escMd(cveData.displayProductName || cveData.productName || '?');
  const cveSafe = escMd(cveId);
  const sevSafe = escMd(String(cveData.severity || '').toUpperCase());

  const text = [
    `🚨 *Auto\\-Remediation Approval Required*`,
    ``,
    `A *Critical* CVE is queued for automatic remediation\\.`,
    ``,
    `🔴 *${cveSafe}* · ${sevSafe}`,
    `📦 Product: ${prod}`,
    `🏢 Tenant: \`${escMd(String(tenantId).substring(0, 8))}…\``,
    ``,
    `Approve to deploy via Intune WinGet / Windows Update, or Skip to defer\\.`,
    `⏱ Auto\\-skip in ${Math.round(timeoutMs / 60000)} minutes if no response\\.`,
  ].join('\n');

  const keyboard = {
    inline_keyboard: [[
      { text: '✅ Approve — Remediate Now', callback_data: `approve_cve:${key}` },
      { text: '⏭ Skip — Defer',            callback_data: `skip_cve:${key}`    },
    ]]
  };

  let messageId = null;
  try {
    const res = await fetch('https://api.telegram.org/bot' + token + '/sendMessage', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ chat_id: chatId, text, parse_mode: 'MarkdownV2', reply_markup: keyboard })
    });
    const data = await res.json();
    if (data.ok) messageId = data.result.message_id;
  } catch (err) {
    console.error('[Telegram] requestCveApproval send error:', err.message);
    return 'approved'; // can't send → proceed
  }

  return new Promise((resolve) => {
    const timer = setTimeout(async () => {
      if (!pendingCveApprovals.has(key)) return;
      pendingCveApprovals.delete(key);
      // Remove buttons on timeout
      if (messageId) {
        try {
          await fetch('https://api.telegram.org/bot' + token + '/editMessageReplyMarkup', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ chat_id: chatId, message_id: messageId, reply_markup: { inline_keyboard: [] } })
          });
          await sendMessageWithToken(token, chatId, `⏭ *Auto\\-skip*: No response in ${Math.round(timeoutMs / 60000)} min — ${cveId} deferred to next run\\.`);
        } catch (_) {}
      }
      resolve('skipped');
    }, timeoutMs);

    pendingCveApprovals.set(key, { resolve, timer, messageId, tenantId, cveId });
  });
}

// ─── Send test message ────────────────────────────────────────────────────
async function sendTestMessage() {
  return sendMessage(
    '🤖 *Privileged Identity Monitor*\n\n' +
    '✅ Telegram integration is working\\!\n' +
    'You will receive security alerts with action buttons here\\.'
  );
}

// ─── Escape MarkdownV2 special chars ─────────────────────────────────────
function escMd(str) {
  if (!str) return '';
  return String(str).replace(/[_*[\]()~`>#+=|{}.!\\-]/g, '\\$&');
}


async function sendMessageWithToken(botToken, chatId, text) {
  if (!botToken || !chatId) return;
  try {
    await fetch(`https://api.telegram.org/bot${botToken}/sendMessage`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ chat_id: chatId, text, parse_mode: "Markdown" })
    });
  } catch (err) {
    console.error("[Telegram] sendMessageWithToken error:", err.message);
  }
}

module.exports = {
  sendAlertWithPlaybook,
  sendMessage,
  sendMessageWithToken,
  sendTestMessage,
  handleCallbackQuery,
  cancelAutoRevoke,
  updateMessageAfterAction,
  sendNewCveAlert,
  requestCveApproval,
};
