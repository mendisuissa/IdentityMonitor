import { apiFetch } from './api';

export const multiTenantRemediationApiAdditions = {
  getDefenderVulnerabilities: (tenantId: string, top = 50) =>
    apiFetch(`/defender/vulnerabilities?top=${top}`, {
      headers: {
        'x-tenant-id': tenantId
      }
    }),

  getDefenderTenantConfig: (tenantId: string) =>
    apiFetch('/defender/tenant/config', {
      headers: {
        'x-tenant-id': tenantId
      }
    })
};
