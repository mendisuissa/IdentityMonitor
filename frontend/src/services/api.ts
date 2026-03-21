// API_BASE_URL is intentionally empty string.
// apiFetch always prepends /api/ — setting VITE_API_BASE_URL=/api causes /api/api/... double prefix.
const API_BASE_URL = '';

type ApiOptions = RequestInit & {
  headers?: Record<string, string>;
};

function toQuery(params?: Record<string, unknown>) {
  if (!params) return '';
  const sp = new URLSearchParams();

  Object.entries(params).forEach(([key, value]) => {
    if (value === undefined || value === null || value === '') return;
    sp.set(key, String(value));
  });

  return sp.toString();
}

export async function apiFetch<T = any>(path: string, options: ApiOptions = {}): Promise<T> {
  const normalizedPath = path.startsWith('/') ? path : `/${path}`;
  const apiPath = normalizedPath.startsWith('/api/')
    ? normalizedPath
    : `/api${normalizedPath}`;

  const url = `${API_BASE_URL}${apiPath}`;

  const res = await fetch(url, {
    credentials: 'include',
    ...options,
    headers: {
      'Content-Type': 'application/json',
      ...(options.headers || {}),
    },
  });

  if (!res.ok) {
    const contentType = res.headers.get('content-type') || '';
    if (contentType.includes('application/json')) {
      const payload = await res.json().catch(() => null);
      const err: any = new Error(
        payload?.error || payload?.message || `Request failed: ${res.status}`
      );
      if (payload && typeof payload === 'object') {
        Object.assign(err, payload);
      }
      throw err;
    }

    const text = await res.text().catch(() => '');
    throw new Error(text || `Request failed: ${res.status}`);
  }

  const contentType = res.headers.get('content-type') || '';
  if (contentType.includes('application/json')) {
    return res.json();
  }

  return (await res.text()) as T;
}

export const api = {
  getAccess: () => apiFetch<any>('/auth/access'),

  getUsers: () => apiFetch<any>('/users'),

  getUserSignIns: (userId: string) =>
    apiFetch<any>(`/users/${userId}/signins`),

  revokeUserSessions: (userId: string) =>
    apiFetch<any>(`/users/${userId}/revoke`, {
      method: 'POST',
    }),

  triggerScan: () =>
    apiFetch<any>('/alerts/scan', {
      method: 'POST',
    }),

  getAlerts: (params?: {
    status?: string;
    severity?: string;
    q?: string;
    owner?: string;
    limit?: number;
  }) => {
    const q = toQuery(params);
    return apiFetch<any>(`/alerts${q ? `?${q}` : ''}`);
  },

  getAlertStats: () => apiFetch<any>('/alerts/stats'),

  getAlertById: (id: string) =>
    apiFetch<any>(`/alerts/${id}`),

  getAlertInvestigation: (id: string) =>
    apiFetch<any>(`/alerts/${id}/investigation`),

  updateAlertWorkflow: (id: string, body: Record<string, unknown>) =>
    apiFetch<any>(`/alerts/${id}/workflow`, {
      method: 'PATCH',
      body: JSON.stringify(body),
    }),

  patchWorkflow: (id: string, patch: any) =>
    apiFetch<any>(`/alerts/${id}/workflow`, {
      method: 'PATCH',
      body: JSON.stringify(patch),
    }),

  updateAlertPlaybook: (id: string, body: Record<string, unknown>) =>
    apiFetch<any>(`/alerts/${id}/playbook`, {
      method: 'PATCH',
      body: JSON.stringify(body),
    }),

  decidePlaybook: (
    id: string,
    approvalStatus: 'approved' | 'rejected',
    requestedAction: string,
    comment?: string
  ) =>
    apiFetch<any>(`/alerts/${id}/playbook`, {
      method: 'PATCH',
      body: JSON.stringify({ approvalStatus, requestedAction, comment }),
    }),

  approveAlertAction: (id: string, requestedAction = 'revoke') =>
    apiFetch<any>(`/alerts/${id}/playbook`, {
      method: 'PATCH',
      body: JSON.stringify({
        approvalStatus: 'approved',
        requestedAction,
      }),
    }),

  rejectAlertAction: (id: string) =>
    apiFetch<any>(`/alerts/${id}/playbook`, {
      method: 'PATCH',
      body: JSON.stringify({
        approvalStatus: 'rejected',
        requestedAction: 'monitor',
      }),
    }),

  assignAlertOwner: (id: string, owner: string) =>
    apiFetch<any>(`/alerts/${id}/workflow`, {
      method: 'PATCH',
      body: JSON.stringify({ owner }),
    }),

  resolveAlert: (id: string, actor = 'admin') =>
    apiFetch<any>(`/alerts/${id}/resolve`, {
      method: 'PATCH',
      body: JSON.stringify({ actor }),
    }),

  dismissAlert: (id: string) =>
    apiFetch<any>(`/alerts/${id}/dismiss`, {
      method: 'PATCH',
    }),

  refreshAlerts: () =>
    apiFetch<any>('/alerts/refresh', {
      method: 'POST',
    }),

  getNotificationInbox: (params?: { status?: string; limit?: number; dedupe?: boolean }) => {
    const q = toQuery(params);
    return apiFetch<any>(`/settings/notifications/inbox${q ? `?${q}` : ''}`);
  },

  ackNotification: (id: string) =>
    apiFetch<any>(`/settings/notifications/${id}/ack`, {
      method: 'POST',
    }),

  getCases: (params?: {
    status?: string;
    caseStatus?: string;
    approvalStatus?: string;
    owner?: string;
    severity?: string;
    q?: string;
    limit?: number;
  }) => {
    const q = toQuery(params);
    return apiFetch<any>(`/alerts/cases${q ? `?${q}` : ''}`);
  },

  getCaseById: (id: string) =>
    apiFetch<any>(`/alerts/cases/${id}`),

  createCase: (body: any) =>
    apiFetch<any>('/alerts/cases', {
      method: 'POST',
      body: JSON.stringify(body),
    }),

  updateCase: (id: string, body: any) =>
    apiFetch<any>(`/alerts/cases/${id}`, {
      method: 'PATCH',
      body: JSON.stringify(body),
    }),

  bulkCases: (body: { alertIds: string[]; action: string; owner?: string; comment?: string }) =>
    apiFetch<any>('/alerts/bulk', {
      method: 'POST',
      body: JSON.stringify(body),
    }),

  getComments: (entityType: string, entityId: string) =>
    apiFetch<any>(`/alerts/${entityId}/comments`),

  addComment: (arg1: string, arg2: string, arg3?: any) => {
    if (arg3 !== undefined) {
      return apiFetch<any>(`/alerts/${arg2}/comments`, {
        method: 'POST',
        body: JSON.stringify(arg3),
      });
    }
    return apiFetch<any>(`/alerts/${arg1}/comments`, {
      method: 'POST',
      body: JSON.stringify({ message: arg2 }),
    });
  },

  getAudit: (params?: { limit?: number; action?: string; actor?: string; since?: string; tenantId?: string }) => {
    const q = toQuery(params);
    return apiFetch<any>(`/audit${q ? `?${q}` : ''}`);
  },

  getAuditLog: (params?: { q?: string; limit?: number; tenantId?: string }) => {
    const q = toQuery(params);
    return apiFetch<any>(`/audit${q ? `?${q}` : ''}`);
  },

  exportAuditUrl: (params?: { action?: string; actor?: string; since?: string }) => {
    const q = toQuery(params);
    return `${API_BASE_URL}/api/audit/export${q ? `?${q}` : ''}`;
  },

  runAutomationSweep: () =>
    apiFetch<any>('/alerts/automation/run', {
      method: 'POST',
    }),

  getResponsePolicies: () =>
    apiFetch<any>('/settings/response-policies'),

  saveResponsePolicies: (body: any) =>
    apiFetch<any>('/settings/response-policies', {
      method: 'PUT',
      body: JSON.stringify(body),
    }),

  getSuppressionRules: () =>
    apiFetch<any>('/settings/suppression-rules'),

  saveSuppressionRules: (body: any) =>
    apiFetch<any>('/settings/suppression-rules', {
      method: 'PUT',
      body: JSON.stringify(body),
    }),

  getResponseExceptions: () =>
    apiFetch<any>('/settings/response-exceptions'),

  saveResponseExceptions: (body: any) =>
    apiFetch<any>('/settings/response-exceptions', {
      method: 'PUT',
      body: JSON.stringify(body),
    }),

  getRetentionPolicy: () =>
    apiFetch<any>('/settings/retention-policy'),

  saveRetentionPolicy: (body: any) =>
    apiFetch<any>('/settings/retention-policy', {
      method: 'PUT',
      body: JSON.stringify(body),
    }),

  getRetentionPreview: () =>
    apiFetch<any>('/settings/retention-preview'),

  getBusinessHours: () =>
    apiFetch<any>('/settings/business-hours'),

  saveBusinessHours: (body: any) =>
    apiFetch<any>('/settings/business-hours', {
      method: 'PUT',
      body: JSON.stringify(body),
    }),

  simulatePolicy: (body: any) =>
    apiFetch<any>('/settings/policy-simulator', {
      method: 'POST',
      body: JSON.stringify(body),
    }),

  getAdmins: () =>
    apiFetch<any>('/settings/admins'),

  addAdmin: (body: any) =>
    apiFetch<any>('/settings/admins', {
      method: 'POST',
      body: JSON.stringify(body),
    }),

  removeAdmin: (id: string) =>
    apiFetch<any>(`/settings/admins/${id}`, {
      method: 'DELETE',
    }),

  getWhitelist: () =>
    apiFetch<any>('/settings/whitelist'),

  saveWhitelist: (body: any) =>
    apiFetch<any>('/settings/whitelist', {
      method: 'PUT',
      body: JSON.stringify(body),
    }),

  getDetectionRules: () =>
    apiFetch<any>('/settings/detection'),

  saveDetectionRules: (body: any) =>
    apiFetch<any>('/settings/detection', {
      method: 'PUT',
      body: JSON.stringify(body),
    }),

  getAutoActions: () =>
    apiFetch<any>('/settings/auto-actions'),

  saveAutoActions: (body: any) =>
    apiFetch<any>('/settings/auto-actions', {
      method: 'PUT',
      body: JSON.stringify(body),
    }),

  getPlanAndTrial: () =>
    apiFetch<any>('/settings/plan-trial'),

  savePlanAndTrial: (body: any) =>
    apiFetch<any>('/settings/plan-trial', {
      method: 'PUT',
      body: JSON.stringify(body),
    }),

  getTelegramSettings: () =>
    apiFetch<any>('/settings/telegram'),

  saveTelegramSettings: (body: any) =>
    apiFetch<any>('/settings/telegram', {
      method: 'PUT',
      body: JSON.stringify(body),
    }),

  testTelegramDelivery: (body: any) =>
    apiFetch<any>('/settings/telegram/test', {
      method: 'POST',
      body: JSON.stringify(body),
    }),

  getSiemSettings: () =>
    apiFetch<any>('/settings/siem'),

  saveSiemSettings: (body: any) =>
    apiFetch<any>('/settings/siem', {
      method: 'POST',
      body: JSON.stringify(body),
    }),

  testSiemLogAnalytics: (body: { workspaceId: string; sharedKey: string }) =>
    apiFetch<any>('/settings/siem/test-log-analytics', {
      method: 'POST',
      body: JSON.stringify(body),
    }),

  saveAssignmentRules: (body: any) =>
    apiFetch<any>('/settings/assignment-rules', {
      method: 'PUT',
      body: JSON.stringify(body),
    }),

  saveApprovalPolicies: (body: any) =>
    apiFetch<any>('/settings/approval-policies', {
      method: 'PUT',
      body: JSON.stringify(body),
    }),

  saveRunbooks: (body: any) =>
    apiFetch<any>('/settings/runbooks', {
      method: 'PUT',
      body: JSON.stringify(body),
    }),

  getTenantHealth: () =>
    apiFetch<any>('/tenant/health'),

  getOpsDashboard: () =>
    apiFetch<any>('/tenant/ops-dashboard'),

  getRolesMatrix: () =>
    apiFetch<any>('/tenant/roles-matrix'),

  getPolicyPack: () =>
    apiFetch<any>('/settings/policy-pack'),

  setPolicyPack: (body: any) =>
    apiFetch<any>('/settings/policy-pack', {
      method: 'PUT',
      body: JSON.stringify(body),
    }),

  getOrchestration: () =>
    apiFetch<any>('/settings/ops/orchestration'),

  getOrchestrationPolicies: () =>
    apiFetch<any>('/settings/ops/orchestration/policies'),

  saveOrchestrationPolicies: (body: any) =>
    apiFetch<any>('/settings/ops/orchestration/policies', {
      method: 'PUT',
      body: JSON.stringify(body),
    }),

  orchestrateTenants: (body: {
    action: string;
    tenantIds?: string[];
    comment?: string;
    policy?: string;
  }) =>
    apiFetch<any>('/tenant/orchestrate', {
      method: 'POST',
      body: JSON.stringify(body),
    }),

  getDefenderVulnerabilities: (top = 50) =>
    apiFetch<any>(`/defender/vulnerabilities?top=${top}`),

  getDefenderVulnerabilityMachines: (cveId: string, top = 100) =>
    apiFetch<any>(`/defender/vulnerabilities/${encodeURIComponent(cveId)}/machines?top=${top}`),

  getDefenderTenantConfig: () =>
    apiFetch<any>('/defender/tenant/config'),

  getRiskPosture: () =>
    apiFetch<any>('/reports/risk-posture'),

  getExecutiveSnapshot: () =>
    apiFetch<any>('/reports/executive-snapshot'),

  executiveExportUrl: (format: 'csv' | 'json' = 'csv') =>
    `${API_BASE_URL}/api/reports/executive/export?format=${format}`,

  planRemediation: (body: {
    tenantId?: string;
    finding: any;
    options?: {
      updateType?: 'security' | 'feature';
      rebootBehavior?: 'ifRequired' | 'force' | 'defer';
      targetDeviceIds?: string[];
    };
  }) =>
    apiFetch<any>('/remediation/plan', {
      method: 'POST',
      body: JSON.stringify(body),
    }),

  executeRemediation: (body: {
    tenantId?: string;
    approvalId?: string;
    devices?: string[];
    finding: any;
    plan: any;
    options?: {
      updateType?: 'security' | 'feature';
      rebootBehavior?: 'ifRequired' | 'force' | 'defer';
      targetDeviceIds?: string[];
    };
  }) =>
    apiFetch<any>('/remediation/execute', {
      method: 'POST',
      body: JSON.stringify(body),
    }),
};

export default api;