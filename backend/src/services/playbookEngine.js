// playbookEngine.js — Conditional automated response engine
// Playbooks: { id, name, enabled, conditionOperator('AND'/'OR'), conditions[], actions[], cooldownMinutes }
// Condition: { field: 'severity'|'riskLevel'|'country'|'hour'|'anomalyType', operator: 'gte'|'eq'|'in'|'notIn'|'between'|'notBetween', value }
// Action: { type: 'revokeSessions'|'disableUser'|'sendTelegram'|'createCase'|'notifyAdmin' }

const LEVELS = ['low', 'medium', 'high', 'critical'];

// Per-user cooldown map: `${playbookId}:${userId}` → lastTriggeredMs
const _cooldowns = new Map();

// ─── Evaluate a single condition against an alert ─────────────────────────
function evaluateCondition(condition, alert) {
  const { field, operator, value } = condition;

  switch (field) {
    case 'severity': {
      const alertIdx = LEVELS.indexOf(alert.severity);
      const condIdx  = LEVELS.indexOf(value);
      if (alertIdx < 0 || condIdx < 0) return false;
      if (operator === 'gte') return alertIdx >= condIdx;
      if (operator === 'eq')  return alertIdx === condIdx;
      return false;
    }

    case 'riskLevel': {
      const riskVal  = alert.riskLevel || alert.riskLevelAggregated || alert.severity;
      const alertIdx = LEVELS.indexOf(riskVal);
      const condIdx  = LEVELS.indexOf(value);
      if (alertIdx < 0 || condIdx < 0) return false;
      if (operator === 'gte') return alertIdx >= condIdx;
      if (operator === 'eq')  return alertIdx === condIdx;
      return false;
    }

    case 'country': {
      const alertCountry = alert.country || '';
      const arr = Array.isArray(value) ? value : [value];
      if (operator === 'in')    return arr.some(c => String(c).toLowerCase() === String(alertCountry).toLowerCase());
      if (operator === 'notIn') return !arr.some(c => String(c).toLowerCase() === String(alertCountry).toLowerCase());
      return false;
    }

    case 'hour': {
      const detectedAt = alert.detectedAt || alert.signInTime;
      if (!detectedAt) return false;
      const hour = new Date(detectedAt).getUTCHours();
      const range = Array.isArray(value) ? value : [value, value];
      const [start, end] = range;
      const inRange = start <= end
        ? (hour >= start && hour <= end)
        : (hour >= start || hour <= end); // wraps midnight
      if (operator === 'between')    return inRange;
      if (operator === 'notBetween') return !inRange;
      return false;
    }

    case 'anomalyType': {
      const alertType  = alert.anomalyType  || '';
      const alertLabel = alert.anomalyLabel || '';
      const arr = Array.isArray(value) ? value : [value];
      if (operator === 'eq')  return arr.some(v => v === alertType || v === alertLabel);
      if (operator === 'in')  return arr.some(v => v === alertType || v === alertLabel);
      return false;
    }

    default:
      return false;
  }
}

// ─── Evaluate all conditions for a playbook ───────────────────────────────
function evaluatePlaybook(playbook, alert) {
  const conditions = playbook.conditions || [];
  if (conditions.length === 0) return false;

  const op = (playbook.conditionOperator || 'AND').toUpperCase();
  if (op === 'OR') {
    return conditions.some(c => evaluateCondition(c, alert));
  }
  // Default: AND
  return conditions.every(c => evaluateCondition(c, alert));
}

// ─── Execute actions for a triggered playbook ─────────────────────────────
async function executePlaybookActions(playbook, alert, tenantId) {
  const results = [];
  const actions = playbook.actions || [];

  for (const action of actions) {
    const type = action.type;

    try {
      switch (type) {
        case 'revokeSessions': {
          try {
            await require('./graphService').revokeUserSessions(tenantId, alert.userId);
            results.push({ action: type, status: 'ok' });
          } catch (err) {
            results.push({ action: type, status: 'error', error: err.message });
          }
          break;
        }

        case 'disableUser': {
          try {
            await require('./graphService').disableUser(tenantId, alert.userId);
            results.push({ action: type, status: 'ok' });
          } catch (err) {
            results.push({ action: type, status: 'error', error: err.message });
          }
          break;
        }

        case 'sendTelegram': {
          try {
            const telegramService = require('./telegramService');
            const escMd = (str) => String(str || '').replace(/[_*[\]()~`>#+=|{}.!\\-]/g, '\\$&');
            const severityEmoji = { critical: '🚨', high: '⚠️', medium: '🔶', low: 'ℹ️' }[alert.severity] || '⚠️';
            const message =
              `${severityEmoji} *Playbook Triggered: ${escMd(playbook.name)}*\n\n` +
              `*User:* ${escMd(alert.userDisplayName || alert.userId)}\n` +
              `*UPN:* \`${escMd(alert.userPrincipalName || '')}\`\n` +
              `*Anomaly:* ${escMd(alert.anomalyLabel || alert.anomalyType)}\n` +
              `*Severity:* ${escMd(alert.severity)}\n` +
              `*Country:* ${escMd(alert.country || 'Unknown')}\n` +
              `*Detected:* ${escMd(new Date(alert.detectedAt || Date.now()).toLocaleString('en-GB'))}`;

            // Use per-tenant token if available, fall back to env vars
            const settingsService = require('./settingsService');
            const settings = settingsService.getSettings(tenantId);
            const botToken = (settings.notifications && settings.notifications.telegramBotToken) || process.env.TELEGRAM_BOT_TOKEN;
            const chatId   = (settings.notifications && settings.notifications.telegramChatId)   || process.env.TELEGRAM_CHAT_ID;

            if (botToken && chatId) {
              await telegramService.sendMessageWithToken(botToken, chatId, message);
            } else {
              await telegramService.sendMessage && telegramService.sendMessage(message);
            }
            results.push({ action: type, status: 'ok' });
          } catch (err) {
            results.push({ action: type, status: 'error', error: err.message });
          }
          break;
        }

        case 'createCase': {
          try {
            const workflowStore = require('./workflowStore');
            const caseData = {
              caseStatus:      'triage',
              requestedAction: action.requestedAction || 'revoke',
              owner:           action.owner || 'auto-playbook',
              note:            'Auto-created by playbook: ' + playbook.name
            };
            if (typeof workflowStore.createOrUpdateCase === 'function') {
              await workflowStore.createOrUpdateCase(tenantId, alert.id, caseData);
            } else if (typeof workflowStore.upsertCase === 'function') {
              await workflowStore.upsertCase(tenantId, alert.id, caseData);
            } else {
              // Fall back to patchAlertWorkflowAsync
              await workflowStore.patchAlertWorkflowAsync(tenantId, alert.id, caseData, 'auto-playbook');
            }
            results.push({ action: type, status: 'ok' });
          } catch (err) {
            results.push({ action: type, status: 'error', error: err.message });
          }
          break;
        }

        case 'notifyAdmin': {
          try {
            await require('./emailService').sendAdminAlert(alert);
            results.push({ action: type, status: 'ok' });
          } catch (err) {
            results.push({ action: type, status: 'error', error: err.message });
          }
          break;
        }

        default:
          results.push({ action: type, status: 'error', error: 'Unknown action type: ' + type });
      }
    } catch (outerErr) {
      results.push({ action: type, status: 'error', error: outerErr.message });
    }
  }

  return results;
}

// ─── Run all enabled playbooks for a given alert ──────────────────────────
async function runPlaybooksForAlert(tenantId, alert) {
  const settingsService = require('./settingsService');
  const settings = settingsService.getSettings(tenantId);
  const playbooks = (settings.playbooks || []).filter(p => p.enabled !== false);

  const triggered = [];

  for (const playbook of playbooks) {
    if (!evaluatePlaybook(playbook, alert)) continue;

    // Check per-user cooldown
    const cooldownMs = (playbook.cooldownMinutes || 0) * 60 * 1000;
    const cooldownKey = `${playbook.id}:${alert.userId}`;
    const lastTriggered = _cooldowns.get(cooldownKey) || 0;

    if (cooldownMs > 0 && Date.now() - lastTriggered < cooldownMs) {
      console.log(`[Playbooks] Skipping "${playbook.name}" for ${alert.userId} — still in cooldown`);
      continue;
    }

    _cooldowns.set(cooldownKey, Date.now());

    console.log(`[Playbooks] Triggering "${playbook.name}" for alert ${alert.id}`);
    const actionResults = await executePlaybookActions(playbook, alert, tenantId);

    triggered.push({
      playbookId:   playbook.id,
      playbookName: playbook.name,
      alertId:      alert.id,
      actions:      actionResults
    });
  }

  return triggered;
}

module.exports = {
  LEVELS,
  evaluateCondition,
  evaluatePlaybook,
  executePlaybookActions,
  runPlaybooksForAlert
};
