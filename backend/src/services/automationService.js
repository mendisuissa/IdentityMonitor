const alertsStore = require('./alertsStore');
const workflowStore = require('./workflowStore');
const settingsService = require('./settingsService');
const auditLog = require('./auditLog');
const tenantRegistry = require('./tenantRegistry');
const notificationCenter = require('./notificationCenterService');
const policyEngine = require('./policyEngineService');

function severityMinutes(settings, severity) {
  const policy = settings.responsePolicies?.[severity];
  if (policy?.slaMinutes) return policy.slaMinutes;
  const esc = settings.escalation || {};
  if (severity === 'critical') return esc.criticalMinutes || 30;
  if (severity === 'high') return esc.highMinutes || 120;
  if (severity === 'medium') return Math.max(240, esc.highMinutes || 120);
  return Math.max(480, (esc.highMinutes || 120) * 2);
}

function buildApprovalPlan(alert, settings = {}) {
  const decision = policyEngine.buildPolicyDecision(alert.tenantId, alert);
  if (!decision.requiresApproval) return [];
  const configured = settings.approvalPolicies?.[alert.severity] || settings.approvalPolicies?.medium || ['analyst'];
  return configured.map((role, index) => ({ step: index + 1, role, status: 'pending' }));
}

function resolveOwner(alert, settings = {}) {
  const rules = settings.assignmentRules || {};
  if (rules.enabled === false) return '';
  return rules.severityOwners?.[alert.severity] || rules.defaultOwner || '';
}

function ensureWorkflowDefaults(tenantId, alert) {
  const settings = settingsService.getSettings(tenantId);
  const wf = workflowStore.getAlertWorkflow(tenantId, alert.id);
  const patch = {};
  if (!wf.dueAt) patch.dueAt = new Date(new Date(alert.detectedAt).getTime() + severityMinutes(settings, alert.severity) * 60000).toISOString();
  if (!Array.isArray(wf.approvalSteps) || wf.approvalSteps.length === 0) patch.approvalSteps = buildApprovalPlan(alert, settings);
  if (!wf.owner) patch.owner = resolveOwner(alert, settings);
  if (!wf.approvalHistory) patch.approvalHistory = [];
  if (!wf.mentions) patch.mentions = [];
  if (!wf.notifications) patch.notifications = [];
  if (!wf.automationActions) patch.automationActions = [];
  if (!wf.runbookSteps) patch.runbookSteps = settings.runbooks?.[alert.severity] || [];
  if (Object.keys(patch).length) return workflowStore.patchAlertWorkflow(tenantId, alert.id, patch, 'system');
  return wf;
}

function appendAction(list, action) {
  const actions = Array.isArray(list) ? list : [];
  if (actions.some(a => a.type === action.type && a.key === action.key)) return actions;
  return [...actions, action];
}

function enqueueUnique(tenantId, type, uniqueKey, payload) {
  const existing = notificationCenter.list(tenantId, { limit: 300 }).find(n => n.type === type && n.uniqueKey === uniqueKey);
  if (existing) return existing;
  return notificationCenter.enqueue(tenantId, { type, uniqueKey, ...payload });
}

function evaluateTenant(tenantId) {
  const alerts = alertsStore.getOpen(tenantId);
  const settings = settingsService.getSettings(tenantId);
  const now = Date.now();
  const summary = {
    tenantId,
    openAlerts: alerts.length,
    overdueCases: 0,
    escalatedCases: 0,
    pendingApprovals: 0,
    automationActions: 0,
    notificationsQueued: 0
  };

  for (const alert of alerts) {
    let wf = ensureWorkflowDefaults(tenantId, alert);
    const patch = {};
    const policyDecision = policyEngine.buildPolicyDecision(tenantId, alert);
    const dueTs = wf.dueAt ? new Date(wf.dueAt).getTime() : null;
    const isBreached = !!dueTs && dueTs < now && wf.caseStatus !== 'closed';
    const nextStep = (wf.approvalSteps || []).find(s => s.status === 'pending');

    if (policyDecision.suppressed) {
      patch.caseStatus = 'closed';
      patch.suppressReason = policyDecision.suppressionRule?.reason || 'Suppressed by policy';
      patch.approvalStatus = 'approved';
      patch.notifications = appendAction(wf.notifications, {
        type: 'suppression',
        key: `suppress-${alert.id}`,
        severity: alert.severity,
        sentAt: new Date().toISOString(),
        channel: 'workflow',
        target: 'policy-engine'
      });
    }

    if (nextStep) {
      summary.pendingApprovals += 1;
      enqueueUnique(tenantId, 'approval', `approval-${alert.id}-${nextStep.step}`, {
        severity: alert.severity,
        target: nextStep.role,
        title: `Approval required · ${alert.anomalyLabel}`,
        detail: `Step ${nextStep.step} is waiting for ${nextStep.role}`,
        metadata: { alertId: alert.id, step: nextStep.step, role: nextStep.role }
      });
    }

    if (isBreached) {
      summary.overdueCases += 1;
      const nextLevel = Math.max(1, (wf.escalationLevel || 0) + 1);
      patch.slaBreachedAt = wf.slaBreachedAt || new Date().toISOString();
      patch.escalationLevel = Math.min(nextLevel, 3);
      patch.caseStatus = wf.caseStatus === 'closed' ? 'closed' : 'triage';
      patch.isOverdue = true;
      patch.notifications = appendAction(wf.notifications, {
        type: 'sla-breach',
        key: `sla-${alert.id}-${Math.min(nextLevel, 3)}`,
        severity: alert.severity,
        sentAt: new Date().toISOString(),
        channel: 'workflow',
        target: (settings.escalation?.notifyRoles || []).join(',')
      });
      patch.automationActions = appendAction(wf.automationActions, {
        type: 'escalation',
        key: `esc-${alert.id}-${Math.min(nextLevel, 3)}`,
        createdAt: new Date().toISOString(),
        detail: `Escalated to level ${Math.min(nextLevel, 3)} after SLA breach`
      });
      enqueueUnique(tenantId, 'sla-breach', `sla-${alert.id}-${Math.min(nextLevel, 3)}`, {
        severity: alert.severity,
        target: (settings.escalation?.notifyRoles || []).join(','),
        title: `SLA breached · ${alert.anomalyLabel}`,
        detail: `Escalation level ${Math.min(nextLevel, 3)} triggered for ${alert.userPrincipalName}`,
        metadata: { alertId: alert.id, level: Math.min(nextLevel, 3) }
      });
      summary.escalatedCases += 1;
    }

    if (isBreached && ['critical', 'high'].includes(alert.severity)) {
      const autoType = alert.severity === 'critical' ? 'auto-revoke-session' : 'auto-notify-owner';
      const desiredAction = alert.severity === 'critical' ? 'revoke' : 'monitor';
      const executionCheck = policyEngine.getExecutionCheck(tenantId, alert, desiredAction, wf);
      const detail = executionCheck.canExecute
        ? (alert.severity === 'critical' ? 'Automatic revoke playbook queued due to critical SLA breach' : 'Owner notification queued due to high severity SLA breach')
        : `Automation held: ${executionCheck.reason}`;
      patch.automationActions = appendAction(patch.automationActions || wf.automationActions, {
        type: executionCheck.canExecute ? autoType : 'approval-hold',
        key: `auto-${alert.id}-${executionCheck.canExecute ? autoType : 'approval-hold'}`,
        createdAt: new Date().toISOString(),
        detail,
        state: executionCheck.state
      });
      enqueueUnique(tenantId, executionCheck.canExecute ? 'automation' : 'approval-hold', `auto-${alert.id}-${executionCheck.canExecute ? autoType : 'approval-hold'}`, {
        severity: alert.severity,
        target: wf.owner || 'queue',
        title: executionCheck.canExecute ? `Automation queued - ${autoType}` : 'Automation held pending approval',
        detail: executionCheck.canExecute ? (alert.severity === 'critical' ? 'Automatic revoke session playbook staged' : 'Owner notification staged') : executionCheck.reason,
        metadata: { alertId: alert.id, automationType: autoType, executionState: executionCheck.state }
      });
    }

    if (Object.keys(patch).length) {
      wf = workflowStore.patchAlertWorkflow(tenantId, alert.id, patch, 'system');
      auditLog.log(tenantId, 'automation.sweep', { alertId: alert.id, severity: alert.severity, escalated: !!isBreached }, 'system');
    }

    summary.automationActions += (wf.automationActions || []).length;
    summary.notificationsQueued += (wf.notifications || []).length;
  }

  return summary;
}

function runAutomationSweep(targetTenantId) {
  if (targetTenantId) return [evaluateTenant(targetTenantId)];
  return tenantRegistry.getAllTenantIds().map(evaluateTenant);
}

function getMultiTenantOps(currentTenantId) {
  const tenantIds = Array.from(new Set([currentTenantId, ...tenantRegistry.getAllTenantIds()].filter(Boolean)));
  const tenants = tenantIds.map(tenantId => {
    const settings = settingsService.getSettings(tenantId);
    const workflow = workflowStore.getWorkflowStats(tenantId);
    const audit = auditLog.getStats(tenantId);
    const alerts = alertsStore.getStats(tenantId);
    const notifications = notificationCenter.stats(tenantId);
    return {
      tenantId,
      tenantName: settings.branding?.tenantName || tenantId,
      policyPack: settings.policyPack || 'balanced',
      openAlerts: alerts.open,
      criticalOpen: alerts.critical,
      overdueCases: workflow.overdue,
      pendingApproval: workflow.pendingApproval,
      notificationBacklog: notifications.unread,
      coverageRoles: (settings.monitoredRoles || []).length,
      lastActivity: audit.lastActivity,
      healthScore: Math.max(40, 100 - (workflow.overdue * 10) - (alerts.critical * 8) - (notifications.unread * 2))
    };
  }).sort((a,b) => (b.openAlerts + b.overdueCases) - (a.openAlerts + a.overdueCases));

  return {
    tenantCount: tenants.length,
    tenants,
    summary: {
      totalOpenAlerts: tenants.reduce((a,t)=>a+t.openAlerts,0),
      totalOverdueCases: tenants.reduce((a,t)=>a+t.overdueCases,0),
      totalPendingApprovals: tenants.reduce((a,t)=>a+t.pendingApproval,0),
      totalNotificationBacklog: tenants.reduce((a,t)=>a+t.notificationBacklog,0),
      lowestHealthTenant: tenants.slice().sort((a,b)=>a.healthScore-b.healthScore)[0] || null
    }
  };
}

module.exports = { runAutomationSweep, getMultiTenantOps, ensureWorkflowDefaults, buildApprovalPlan, resolveOwner };
