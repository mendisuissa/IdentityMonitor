const { TableClient } = require('@azure/data-tables');

const connectionString = process.env.AZURE_STORAGE_CONNECTION_STRING;
const tableName = process.env.AZURE_STORAGE_TENANT_TABLE || 'TenantIntegrations';

function getTableClient() {
  if (!connectionString) {
    throw new Error('AZURE_STORAGE_CONNECTION_STRING is not configured.');
  }

  return TableClient.fromConnectionString(connectionString, tableName);
}

async function ensureTenantTable() {
  const client = getTableClient();
  await client.createTable().catch(() => {});
  return client;
}

async function getTenantIntegration(tenantId) {
  if (!tenantId) {
    throw new Error('Missing tenant id for integration lookup.');
  }

  const client = await ensureTenantTable();

  try {
    const entity = await client.getEntity('TENANT', tenantId);

    const sharedClientId = process.env.DEFENDER_SHARED_CLIENT_ID || process.env.CLIENT_ID || null;
    const sharedClientSecret = process.env.DEFENDER_SHARED_CLIENT_SECRET || process.env.CLIENT_SECRET || null;
    const configuredClientId = entity.defenderClientId || sharedClientId;
    const configuredClientSecret = entity.defenderClientSecret || sharedClientSecret;

    return {
      tenantId: entity.tenantId || tenantId,
      tenantName: entity.tenantName || null,
      defenderTenantId: entity.defenderTenantId || tenantId,
      defenderClientId: configuredClientId,
      defenderClientSecret: configuredClientSecret,
      defenderEnabled: String(entity.defenderEnabled || 'true').toLowerCase() === 'true',
      webappBaseUrl: entity.webappBaseUrl || null,
      sharedToken: entity.sharedToken || null,
      status: entity.status || 'unknown',
      lastValidatedAt: entity.lastValidatedAt || null,
      authMode: entity.defenderClientId ? 'per-tenant-app' : (configuredClientId ? 'shared-multi-tenant-app' : 'unconfigured')
    };
  } catch (error) {
    if (error.statusCode === 404) {
      return null;
    }
    throw error;
  }
}

async function upsertTenantIntegration(integration) {
  if (!integration?.tenantId) {
    throw new Error('tenantId is required for upsertTenantIntegration.');
  }

  const client = await ensureTenantTable();

  const existing = await getTenantIntegration(integration.tenantId).catch(() => null);

  const entity = {
    partitionKey: 'TENANT',
    rowKey: integration.tenantId,
    tenantId: integration.tenantId,
    tenantName: integration.tenantName || existing?.tenantName || '',
    defenderTenantId: integration.defenderTenantId || existing?.defenderTenantId || integration.tenantId,
    defenderClientId: integration.defenderClientId || existing?.defenderClientId || '',
    defenderClientSecret: integration.defenderClientSecret || existing?.defenderClientSecret || '',
    defenderEnabled: String(integration.defenderEnabled ?? existing?.defenderEnabled ?? true),
    webappBaseUrl: integration.webappBaseUrl || existing?.webappBaseUrl || '',
    sharedToken: integration.sharedToken || existing?.sharedToken || '',
    status: integration.status || existing?.status || 'configured',
    lastValidatedAt: integration.lastValidatedAt || existing?.lastValidatedAt || ''
  };

  await client.upsertEntity(entity, 'Replace');
  return entity;
}

module.exports = {
  getTenantIntegration,
  upsertTenantIntegration
};
