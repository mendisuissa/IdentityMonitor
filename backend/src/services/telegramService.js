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

// ─── Send simple text message (MarkdownV2) ───────────────────────────────
// Accepts optional token/chatId overrides so settings-stored credentials work.
async function sendMessage(text, tokenOverride, chatIdOverride) {
  const token  = tokenOverride  || TELEGRAM_BOT_TOKEN;
  const chatId = chatIdOverride || TELEGRAM_CHAT_ID;
  if (!token || !chatId) {
    console.warn('[Telegram] sendMessage skipped — bot token or chat ID not configured');
    return;
  }
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
        })
      }
    );
    const data = await res.json();
    if (!data.ok) {
      console.error('[Telegram] sendMessage API error:', data.description, '| text preview:', text.slice(0, 120));
    } else {
      console.log('[Telegram] ✅ Message sent, message_id:', data.result.message_id);
    }
  } catch (err) {
    console.error('[Telegram] sendMessage error:', err.message);
  }
}

// ─── Send for a specific tenant (uses settings-based credentials with env fallback) ───
async function sendMessageForTenant(tenantId, text) {
  try {
    const settingsService = require('./settingsService');
    const s = await settingsService.getSettingsAsync(tenantId).catch(() => ({}));
    const token  = s?.notifications?.telegramBotToken  || TELEGRAM_BOT_TOKEN;
    const chatId = s?.notifications?.telegramChatId    || TELEGRAM_CHAT_ID;
    return sendMessage(text, token, chatId);
  } catch (_) {
    return sendMessage(text); // fallback to env vars
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
      await sendMessage('⚠️ This approval request has already expired or been handled\\.');
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
    await sendMessage(`${icon} *CVE Approval*: ${escMd(pending.cveId)} — ${escMd(label)}`);
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

// ─── Handle incoming text messages from the bot admin ────────────────────
/**
 * Called when the admin types a message (not a button press) to the bot.
 * Supports:
 *   /help | עזרה          — list of commands
 *   /alerts | התראות      — open alerts summary
 *   /last | ריצה אחרונה   — last remediation run results
 *   /failed | למה failed  — failures detail from last run
 *   CVE-YYYY-NNNNN        — details for a specific CVE
 *   /status               — system health summary
 */
async function handleTextMessage(msg) {
  const chatId = String(msg.chat?.id || '');
  const text   = (msg.text || '').trim();
  const lower  = text.toLowerCase();

  if (!chatId) return;

  // Find which tenant owns this chatId
  const tenantId = await findTenantByChatId(chatId);

  // Strip bot username suffix — Telegram sends "/cmd@BotName" in groups
  // e.g. "/help@IdentityMBot" → "/help"
  const cleanText  = text.replace(/@\S+$/, '').trim();
  const cleanLower = cleanText.toLowerCase();

  // ── /help ─────────────────────────────────────────────────────────────
  if (cleanLower.startsWith('/help') || cleanLower === 'עזרה' || cleanLower === 'help') {
    return replyTo(chatId,
      '🤖 *IdentityMonitor Bot Commands*\n\n' +
      '`/alerts` \\— open security alerts summary\n' +
      '`/failed` \\— CVEs that failed in the last remediation run\n' +
      '`/last` \\— full results of the last remediation run\n' +
      '`/status` \\— system health overview\n' +
      '`CVE\\-YYYY\\-NNNNN` \\— details for a specific CVE\n\n' +
      '_Type naturally too: "למה failed?" or "show alerts"_'
    );
  }

  // ── /alerts | show alerts | התראות ────────────────────────────────────
  if (cleanLower.startsWith('/alerts') || cleanLower.includes('alert') || cleanLower.includes('התראות') || cleanLower.includes('alerts')) {
    return handleAlertsQuery(chatId, tenantId);
  }

  // ── /failed | למה | why | כישלונות ────────────────────────────────────
  if (cleanLower.startsWith('/failed') || cleanLower.includes('failed') || cleanLower.includes('למה') || cleanLower.includes('why') || cleanLower.includes('כישלון') || cleanLower.includes('fail')) {
    return handleFailedQuery(chatId, tenantId);
  }

  // ── /last | ריצה | last run ────────────────────────────────────────────
  if (cleanLower.startsWith('/last') || cleanLower.includes('last run') || cleanLower.includes('ריצה') || cleanLower.includes('last') || cleanLower.includes('remediat')) {
    return handleLastRunQuery(chatId, tenantId);
  }

  // ── /status ────────────────────────────────────────────────────────────
  if (cleanLower.startsWith('/status') || cleanLower === 'status' || cleanLower === 'סטטוס' || cleanLower.includes('status')) {
    return handleStatusQuery(chatId, tenantId);
  }

  // ── CVE lookup ─────────────────────────────────────────────────────────
  const cveMatch = cleanText.toUpperCase().match(/CVE-\d{4}-\d+/);
  if (cveMatch) {
    return handleCveQuery(chatId, tenantId, cveMatch[0]);
  }

  // ── Unknown — show mini-help ───────────────────────────────────────────
  return replyTo(chatId,
    '🤔 לא הבנתי\\.\n\n' +
    'נסה:\n' +
    '• `/help` \\— רשימת פקודות\n' +
    '• `/failed` \\— למה כישלונות?\n' +
    '• `/last` \\— ריצה אחרונה\n' +
    '• `/alerts` \\— התראות פתוחות'
  );
}

// ── Query helpers ─────────────────────────────────────────────────────────

async function handleAlertsQuery(chatId, tenantId) {
  try {
    const alertsStore = require('./alertsStore');
    if (tenantId) await alertsStore.loadFromAzure(tenantId);
    const alerts = alertsStore.getAll(tenantId).filter(a => a.status === 'open');

    if (alerts.length === 0) {
      return replyTo(chatId, '✅ *No open alerts* — all clear\\!');
    }

    const bySev = { critical: 0, high: 0, medium: 0, low: 0 };
    for (const a of alerts) bySev[a.severity] = (bySev[a.severity] || 0) + 1;

    const recent = alerts
      .sort((a, b) => new Date(b.detectedAt) - new Date(a.detectedAt))
      .slice(0, 5);

    let msg = `🚨 *Open Alerts: ${alerts.length}*\n\n`;
    if (bySev.critical) msg += `🔴 Critical: ${bySev.critical}\n`;
    if (bySev.high)     msg += `🟠 High: ${bySev.high}\n`;
    if (bySev.medium)   msg += `🟡 Medium: ${bySev.medium}\n`;
    if (bySev.low)      msg += `🔵 Low: ${bySev.low}\n`;
    msg += '\n*Recent:*\n';
    for (const a of recent) {
      const icon = { critical: '🔴', high: '🟠', medium: '🟡', low: '🔵' }[a.severity] || '⚪';
      msg += `${icon} ${escMd(a.anomalyLabel || a.anomalyType)} — ${escMd(a.userDisplayName)}\n`;
    }
    if (alerts.length > 5) msg += `_…and ${alerts.length - 5} more_`;

    return replyTo(chatId, msg);
  } catch (err) {
    return replyTo(chatId, `❌ Could not fetch alerts: ${escMd(err.message)}`);
  }
}

async function handleFailedQuery(chatId, tenantId) {
  try {
    const histStore = require('./remediationHistoryStore');
    const history   = await histStore.getRemediationHistory(tenantId || 'default', { limit: 200 });

    if (history.length === 0) {
      return replyTo(chatId, 'ℹ️ No remediation history found\\.');
    }

    // Group history into runs (items within 10 min of each other = same run)
    const runs   = groupIntoRuns(history);
    // Pick the most recent run with >1 item, or just the latest if all are single
    const lastRun = runs.find(r => r.length > 1) || runs[0];
    const failed  = lastRun.filter(r => r.status === 'failed');

    if (failed.length === 0) {
      const success = lastRun.filter(r => r.status === 'success').length;
      return replyTo(chatId,
        `✅ *No failures* in the last run\\!\n` +
        `Run time: ${escMd(new Date(lastRun[0].executedAt).toLocaleString('en-GB'))}\n` +
        `${success} succeeded, 0 failed`
      );
    }

    let msg = `❌ *${failed.length} failure${failed.length !== 1 ? 's' : ''} in last run*\n`;
    msg += `🕐 ${escMd(new Date(lastRun[0].executedAt).toLocaleString('en-GB'))}\n\n`;

    for (const f of failed) {
      msg += `🔴 *${escMd(f.cveId)}* · ${escMd(f.productName || f.category)}\n`;
      if (f.message) msg += `   └ ${escMd(f.message)}\n`;
      const errDetail = f.result?.error?.message || f.result?.errorMessage || f.result?.statusText;
      if (errDetail) msg += `   └ ⚠️ ${escMd(String(errDetail).slice(0, 120))}\n`;
      msg += '\n';
    }

    return replyTo(chatId, msg);
  } catch (err) {
    return replyTo(chatId, `❌ Error: ${escMd(err.message)}`);
  }
}

async function handleLastRunQuery(chatId, tenantId) {
  try {
    const histStore = require('./remediationHistoryStore');
    const history   = await histStore.getRemediationHistory(tenantId || 'default', { limit: 200 });

    if (history.length === 0) {
      return replyTo(chatId, 'ℹ️ No remediation runs found\\.');
    }

    // Group into runs and pick the most recent substantial run
    const runs    = groupIntoRuns(history);
    const lastRun = runs.find(r => r.length > 1) || runs[0];

    const success = lastRun.filter(r => r.status === 'success').length;
    const failed  = lastRun.filter(r => r.status === 'failed').length;
    const skipped = lastRun.filter(r => r.status === 'skipped').length;
    const runTime = new Date(lastRun[lastRun.length - 1].executedAt); // earliest item = run start

    let msg = `🤖 *Last Auto\\-Remediation Run*\n`;
    msg += `🕐 ${escMd(runTime.toLocaleString('en-GB'))}\n`;
    msg += `📦 ${lastRun.length} items processed\n\n`;
    msg += `✅ Success: ${success}   ❌ Failed: ${failed}   ⏭ Skipped: ${skipped}\n\n`;

    const failedItems = lastRun.filter(r => r.status === 'failed');
    if (failedItems.length > 0) {
      msg += `*Failures:*\n`;
      for (const f of failedItems) {
        msg += `❌ ${escMd(f.cveId)} · ${escMd(f.productName || '')}\n`;
        if (f.message) msg += `   _${escMd(f.message.slice(0, 100))}_\n`;
      }
      msg += '\nType `/failed` for full error details\\.';
    }

    return replyTo(chatId, msg);
  } catch (err) {
    return replyTo(chatId, `❌ Error: ${escMd(err.message)}`);
  }
}

// ── Group flat history (newest-first) into run batches ───────────────────────
// Items within 10 minutes of each other are considered the same run.
function groupIntoRuns(history, gapMinutes = 10) {
  if (!history.length) return [];
  const runs = [];
  let current = [history[0]];
  for (let i = 1; i < history.length; i++) {
    const prevMs = new Date(history[i - 1].executedAt).getTime();
    const currMs = new Date(history[i].executedAt).getTime();
    const gap    = (prevMs - currMs) / 60000; // positive because newest-first
    if (gap > gapMinutes) {
      runs.push(current);
      current = [history[i]];
    } else {
      current.push(history[i]);
    }
  }
  runs.push(current);
  return runs; // runs[0] = most recent
}

async function handleStatusQuery(chatId, tenantId) {
  try {
    const alertsStore = require('./alertsStore');
    const histStore   = require('./remediationHistoryStore');

    if (tenantId) await alertsStore.loadFromAzure(tenantId).catch(() => {});
    const openAlerts = alertsStore.getAll(tenantId).filter(a => a.status === 'open');
    const critical   = openAlerts.filter(a => a.severity === 'critical').length;
    const high       = openAlerts.filter(a => a.severity === 'high').length;

    const stats = await histStore.getRemediationStats(tenantId || 'default');

    let msg = `📊 *IdentityMonitor Status*\n\n`;
    msg += `🚨 Open Alerts: *${openAlerts.length}*`;
    if (critical || high) msg += ` \\(${critical} critical, ${high} high\\)`;
    msg += '\n';

    if (stats.lastRunAt) {
      msg += `🤖 Last Remediation: ${escMd(new Date(stats.lastRunAt).toLocaleString('en-GB'))}\n`;
      msg += `   ✅ ${stats.byStatus?.success || 0}  ❌ ${stats.byStatus?.failed || 0}  ⏭ ${stats.byStatus?.skipped || 0}\n`;
    } else {
      msg += `🤖 No remediation runs yet\n`;
    }

    return replyTo(chatId, msg);
  } catch (err) {
    return replyTo(chatId, `❌ Error: ${escMd(err.message)}`);
  }
}

async function handleCveQuery(chatId, tenantId, cveId) {
  try {
    const histStore = require('./remediationHistoryStore');
    const history   = await histStore.getRemediationHistory(tenantId || 'default', { limit: 500 });
    const records   = history.filter(r => r.cveId.toUpperCase() === cveId.toUpperCase());

    if (records.length === 0) {
      return replyTo(chatId, `ℹ️ No remediation history found for *${escMd(cveId)}*\\.`);
    }

    const latest = records[0];
    const icon   = latest.status === 'success' ? '✅' : latest.status === 'failed' ? '❌' : '⏭';
    let msg = `${icon} *${escMd(cveId)}*\n\n`;
    msg += `📦 Product: ${escMd(latest.productName || latest.category || 'unknown')}\n`;
    msg += `🔴 Severity: ${escMd((latest.severity || '').toUpperCase())}\n`;
    msg += `📋 Status: ${escMd(latest.status)}\n`;
    msg += `🕐 Last attempt: ${escMd(new Date(latest.executedAt).toLocaleString('en-GB'))}\n`;
    if (latest.message) msg += `📝 Message: ${escMd(latest.message)}\n`;

    const errDetail = latest.result?.error?.message || latest.result?.errorMessage;
    if (errDetail) msg += `⚠️ Error: ${escMd(String(errDetail).slice(0, 200))}\n`;

    msg += `\n_Total attempts: ${records.length}_`;
    const successes = records.filter(r => r.status === 'success').length;
    if (successes > 0) msg += ` \\(${successes} succeeded\\)`;

    return replyTo(chatId, msg);
  } catch (err) {
    return replyTo(chatId, `❌ Error: ${escMd(err.message)}`);
  }
}

// ── Find tenant by Telegram chatId ───────────────────────────────────────────
// Strategy (in order):
//  1. Pull tenantId from alerts already in memory (works for single-tenant setups)
//  2. Scan settings for all known tenants matching this chatId
async function findTenantByChatId(chatId) {
  // Strategy 1 — pull tenantId from alerts already loaded in memory
  try {
    const alertsStore = require('./alertsStore');
    const allAlerts   = typeof alertsStore.getAllRaw === 'function'
      ? alertsStore.getAllRaw()
      : alertsStore.getAll(null);
    if (Array.isArray(allAlerts) && allAlerts.length > 0 && allAlerts[0].tenantId) {
      const tid = allAlerts[0].tenantId;
      // Confirm this tenant's chatId matches (or no chatId configured)
      try {
        const s = require('./settingsService').getSettings(tid);
        const cfgChatId = s?.notifications?.telegramChatId || process.env.TELEGRAM_CHAT_ID;
        if (!cfgChatId || String(cfgChatId) === chatId) return tid;
      } catch (_) {
        return tid; // can't verify settings — trust alert tenantId
      }
    }
  } catch (_) {}

  // Strategy 2 — scan settings for all known tenants
  try {
    const settingsService = require('./settingsService');
    const knownTenants = typeof settingsService.listKnownTenants === 'function'
      ? settingsService.listKnownTenants()
      : [];
    for (const tid of knownTenants) {
      const s = settingsService.getSettings(tid);
      if (s?.notifications?.telegramChatId && String(s.notifications.telegramChatId) === chatId) {
        return tid;
      }
    }
  } catch (_) {}

  return null;
}

// ── Helper: send plain reply ──────────────────────────────────────────────────
async function replyTo(chatId, text) {
  try {
    await fetch(
      `https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage`,
      {
        method:  'POST',
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify({
          chat_id:    chatId,
          text,
          parse_mode: 'MarkdownV2',
        })
      }
    );
  } catch (err) {
    console.error('[Telegram] replyTo error:', err.message);
  }
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
  sendMessageForTenant,
  sendMessageWithToken,
  sendTestMessage,
  handleCallbackQuery,
  handleTextMessage,
  cancelAutoRevoke,
  updateMessageAfterAction,
  sendNewCveAlert,
  requestCveApproval,
};
