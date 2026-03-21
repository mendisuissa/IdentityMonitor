function buildCommonResult({ tenantId, finding, classification, plan, options = {} }) {
  const affectedDevices = Array.isArray(options.targetDeviceIds) && options.targetDeviceIds.length
    ? options.targetDeviceIds
    : Array.isArray(finding?.affectedMachines)
      ? finding.affectedMachines
      : [];

  return {
    tenantId,
    classification,
    findingRef: finding?.cveId || finding?.id || finding?.productName || 'unknown-finding',
    affectedDevices,
    generatedAt: new Date().toISOString(),
    plan,
  };
}

function planNativeRemediation({ tenantId, finding = {}, classification, options = {} }) {
  const updateType = options.updateType || 'security';
  const rebootBehavior = options.rebootBehavior || 'ifRequired';
  const common = buildCommonResult({ tenantId, finding, classification, plan: null, options });

  if (classification.type === 'windows-update') {
    return {
      ...common,
      plan: {
        executor: 'native',
        executionMode: 'native-live',
        status: 'live deploy',
        remediationType: 'windows-update',
        supported: true,
        autoRemediate: true,
        actions: ['update-now'],
        updateType,
        rebootBehavior,
        executionPath: ['IdentityMonitor', 'Native Windows Update executor', 'Target device(s)'],
        note: 'Windows Update native executor skeleton is active. Requests are accepted and returned as native-live for orchestration validation.',
      },
    };
  }

  if (classification.type === 'intune-policy') {
    return {
      ...common,
      plan: {
        executor: 'native',
        executionMode: 'native-queued',
        status: 'manual review required',
        remediationType: 'intune-policy',
        supported: true,
        autoRemediate: false,
        actions: ['queue-policy-sync', 'guided-remediation'],
        executionPath: ['IdentityMonitor', 'Native Intune policy executor', 'Queued / guided operator step'],
        note: 'Intune policy executor is currently a native queued skeleton. Graph execution can be wired later without changing the API contract.',
      },
    };
  }

  if (classification.type === 'script') {
    return {
      ...common,
      plan: {
        executor: 'native',
        executionMode: 'native-queued',
        status: 'manual review required',
        remediationType: 'script',
        supported: true,
        autoRemediate: false,
        actions: ['queue-script', 'guided-remediation'],
        executionPath: ['IdentityMonitor', 'Native script / proactive remediation executor', 'Queued / guided operator step'],
        note: 'Script / Proactive Remediation executor is exposed as a native queued skeleton for now.',
      },
    };
  }

  return {
    ...common,
    plan: {
      executor: 'manual',
      executionMode: 'guided-manual',
      status: 'manual review required',
      remediationType: 'manual',
      supported: true,
      autoRemediate: false,
      actions: ['review-guidance'],
      executionPath: ['IdentityMonitor', 'Guided manual remediation'],
      note: 'No live executor is available for this finding. Follow guided manual remediation.',
    },
  };
}

function executeNativeRemediation({ tenantId, finding = {}, classification, plan = {}, options = {} }) {
  const common = buildCommonResult({ tenantId, finding, classification, plan, options });

  if (classification.type === 'windows-update') {
    return {
      ...common,
      result: {
        executor: 'native',
        status: 'live deploy',
        remediationType: 'windows-update',
        outcome: 'queued',
        message: `Windows Update action queued as ${plan.updateType || options.updateType || 'security'} update with reboot behavior ${plan.rebootBehavior || options.rebootBehavior || 'ifRequired'}.`,
        executionPath: plan.executionPath || ['IdentityMonitor', 'Native Windows Update executor', 'Target device(s)'],
      },
    };
  }

  if (classification.type === 'intune-policy') {
    return {
      ...common,
      result: {
        executor: 'native',
        status: 'manual review required',
        remediationType: 'intune-policy',
        outcome: 'native-queued',
        message: 'Intune policy remediation has been queued in native skeleton mode. Graph enforcement can be added later.',
        executionPath: plan.executionPath || ['IdentityMonitor', 'Native Intune policy executor', 'Queued / guided operator step'],
      },
    };
  }

  if (classification.type === 'script') {
    return {
      ...common,
      result: {
        executor: 'native',
        status: 'manual review required',
        remediationType: 'script',
        outcome: 'native-queued',
        message: 'Script / Proactive Remediation task has been queued in native skeleton mode.',
        executionPath: plan.executionPath || ['IdentityMonitor', 'Native script / proactive remediation executor', 'Queued / guided operator step'],
      },
    };
  }

  return {
    ...common,
    result: {
      executor: 'manual',
      status: 'manual review required',
      remediationType: 'manual',
      outcome: 'guided',
      message: 'Guided manual remediation is required for this finding.',
      executionPath: plan.executionPath || ['IdentityMonitor', 'Guided manual remediation'],
    },
  };
}

module.exports = {
  planNativeRemediation,
  executeNativeRemediation,
};
