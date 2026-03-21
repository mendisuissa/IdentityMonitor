const { BlobServiceClient } = require('@azure/storage-blob');

const connectionString = process.env.AZURE_STORAGE_CONNECTION_STRING;
const containerName = process.env.AZURE_STORAGE_ALERTS_CONTAINER || 'tenant-alerts';

function getContainerClient() {
  if (!connectionString) {
    throw new Error('AZURE_STORAGE_CONNECTION_STRING is not configured.');
  }

  const serviceClient = BlobServiceClient.fromConnectionString(connectionString);
  return serviceClient.getContainerClient(containerName);
}

async function writeTenantSnapshot(tenantId, area, payload) {
  if (!tenantId) return;

  const containerClient = getContainerClient();
  await containerClient.createIfNotExists();

  const now = new Date();
  const date = now.toISOString().slice(0, 10);
  const timestamp = now.toISOString().replace(/[:.]/g, '-');
  const blobName = `tenants/${tenantId}/${area}/${date}/${timestamp}.json`;
  const blobClient = containerClient.getBlockBlobClient(blobName);

  const body = JSON.stringify(payload, null, 2);
  await blobClient.upload(body, Buffer.byteLength(body), {
    blobHTTPHeaders: { blobContentType: 'application/json' }
  });

  return blobName;
}

module.exports = {
  writeTenantSnapshot
};
