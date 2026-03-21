const settingsService = require('./settingsService');

function fieldValue(alert, field) {
  const flat = {
    severity: alert.severity,
    anomalyType: alert.anomalyType,
    anomalyLabel: alert.anomalyLabel,
    userPrincipalName: alert.userPrincipalName,
    userDisplayName: alert.userDisplayName,
    country: alert.country,
    appName: alert.appName,
    deviceName: alert.deviceName,
    appTier: alert.appTier
  };
  return flat[field];
}

function matchesRule(alert, rule = {}) {
  const value = fieldValue(alert, rule.field);
  if (!rule.enabled || !rule.field) return false;
  if (rule.operator === 'equals') return String(value || '').toLowerCase() === String(rule.value || '').toLowerCase();
  if (rule.operator === 'contains') return String(value || '').toLowerCase().includes(String(rule.value || '').toLowerCase());
  if (rule.operator === 'in') return String(rule.value || '').split(',').map(v => v.trim().toLowerCase()).includes(String(value || '').toLowerCase());
  return false;
}

function roleBlocksAction(alert, action, responseExceptions = {}) {
  const blocked = responseExceptions.blockedActionsByRole || {};
  return (alert.roles || []).filter(role => (blocked[role] || []).includes(action));
}

function buildPolicyDecision(tenantId, alert) {
  const settings = settingsService.getSettings(tenantId);
  const responsePolicies = settings.responsePolicies || {};
  const severityPolicy = responsePolicies[alert.severity] || responsePolicies.medium || {};
  const suppressionRule = (settings.suppressionRules || []).find(rule => matchesRule(alert, rule)) || null;
  const forcedApprovalRoles = settings.responseExceptions?.rolesRequireApproval || [];
  const requiresApproval = !!severityPolicy.requireApproval || (alert.roles || []).some(role => forcedApprovalRoles.includes(role));
  const blockedActions = {};
  for (const action of ['monitor', 'revoke', 'disable']) {
    const blockedByRoles = roleBlocksAction(alert, action, settings.responseExceptions || {});
    if (blockedByRoles.length) blockedActions[action] = blockedByRoles;
  }
  const allowedActions = (severityPolicy.allowedActions || ['monitor']).filter(action => !blockedActions[action]);
  const recommendedAction = suppressionRule
    ? 'suppress'
    : severityPolicy.autoContain && allowedActions.includes('revoke')
    ? 'revoke'
    : allowedActions[0] || 'monitor';

  return {
    suppressed: !!suppressionRule,
    suppressionRule,
    requiresApproval,
    notifyRoles: severityPolicy.notifyRoles || [],
    allowedActions,
    blockedActions,
    autoContain: !!severityPolicy.autoContain && !suppressionRule,
    slaMinutes: severityPolicy.slaMinutes || 240,
    recommendedAction,
    rationale: suppressionRule
      ? `Suppressed by rule: ${suppressionRule.name || suppressionRule.reason || suppressionRule.id}`
      : requiresApproval
      ? 'Approval required based on severity policy or privileged role exception.'
      : 'Action allowed directly by current response policy.'
  };
}

function normalizeAlert(sample = {}) {
  return {
    severity: sample.severity || 'medium',
    anomalyType: sample.anomalyType || 'UNKNOWN',
    anomalyLabel: sample.anomalyLabel || sample.anomalyType || 'Custom scenario',
    userPrincipalName: sample.userPrincipalName || 'unknown@example.com',
    userDisplayName: sample.userDisplayName || 'Unknown user',
    country: sample.country || '',
    appName: sample.appName || '',
    deviceName: sample.deviceName || '',
    appTier: sample.appTier || '',
    roles: Array.isArray(sample.roles) ? sample.roles : String(sample.roles || '').split(',').map(v => v.trim()).filter(Boolean)
  };
}

function simulateDecision(tenantId, sample = {}) {
  return buildPolicyDecision(tenantId, normalizeAlert(sample));
}

function getExecutionCheck(tenantId, alert, action = 'monitor', workflow = {}) {
  const normalized = normalizeAlert(alert);
  const decision = buildPolicyDecision(tenantId, normalized);
  if (decision.suppressed) {
    return { canExecute: false, state: 'suppressed', reason: decision.rationale, decision };
  }
  if (!decision.allowedActions.includes(action)) {
    return { canExecute: false, state: 'blocked', reason: `Action ${action} is not allowed by policy for ${normalized.severity}.`, decision };
  }
  if (decision.blockedActions?.[action]?.length) {
    return { canExecute: false, state: 'blocked', reason: `Blocked for roles: ${decision.blockedActions[action].join(', ')}`, decision };
  }
  if (decision.requiresApproval && workflow?.approvalStatus !== 'approved') {
    return { canExecute: false, state: 'awaiting_approval', reason: 'Action requires approval before execution.', decision };
  }
  return { canExecute: true, state: 'ready', reason: 'Action is allowed and can be executed now.', decision };
}

module.exports = { buildPolicyDecision, simulateDecision, getExecutionCheck };
