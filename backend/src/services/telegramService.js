// telegramService.js — Telegram Bot for interactive security playbooks
// Admin receives alert → sees buttons: ✅ Approve / ❌ Block / 👁 Investigate
// No action within 15min on critical = auto-block

const TELEGRAM_BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN;
const TELEGRAM_CHAT_ID   = process.env.TELEGRAM_CHAT_ID;

// Pending actions waiting for admin approval: alertId → { resolve, timeout }
const pendingActions = new Map();

// ─── Send alert with inline keyboard ────────────────────────────────────
async function sendAlertWithPlaybook(alert) {
  if (!TELEGRAM_BOT_TOKEN || !TELEGRAM_CHAT_ID) {
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
      'https://api.telegram.org/bot' + TELEGRAM_BOT_TOKEN + '/sendMessage',
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          chat_id:    TELEGRAM_CHAT_ID,
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
      scheduleAutoRevoke(alert, data.result.message_id);
    }

    return data.result.message_id;
  } catch (err) {
    console.error('[Telegram] ❌ Send failed:', err.message);
    return null;
  }
}

// ─── Update message after action taken ───────────────────────────────────
async function updateMessageAfterAction(messageId, actionText) {
  if (!TELEGRAM_BOT_TOKEN || !TELEGRAM_CHAT_ID) return;
  try {
    await fetch(
      'https://api.telegram.org/bot' + TELEGRAM_BOT_TOKEN + '/editMessageReplyMarkup',
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          chat_id:      TELEGRAM_CHAT_ID,
          message_id:   messageId,
          reply_markup: { inline_keyboard: [] }  // Remove buttons
        })
      }
    );

    await sendMessage('✅ Action taken: ' + actionText);
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
function scheduleAutoRevoke(alert, messageId) {
  const TIMEOUT_MS = 15 * 60 * 1000; // 15 minutes

  const timer = setTimeout(async () => {
    if (pendingActions.has(alert.id)) {
      pendingActions.delete(alert.id);
      console.log('[Telegram] ⏰ Auto-revoking sessions for', alert.userPrincipalName, '(no admin action in 15min)');

      try {
        const graphService = require('./graphService');
        await graphService.revokeUserSessions(alert.tenantId, alert.userId);
        await updateMessageAfterAction(messageId,
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
      sendMessage('⏰ *Reminder:* Critical alert for *' + alert.userDisplayName + '* has no action yet\\. Auto\\-revoke in 5 minutes\\.');
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
  const [action, alertId] = (data || '').split(':');

  // Answer the callback (removes loading state on button)
  await answerCallbackQuery(id);

  console.log('[Telegram] Button pressed:', action, 'for alert:', alertId);

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
  updateMessageAfterAction
};
