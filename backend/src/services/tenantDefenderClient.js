
const { getTenantIntegration } = require('./tenantIntegrationStore');
const { writeTenantSnapshot } = require('./tenantBlobSnapshotStore');

const tokenCache = new Map();
const DEFENDER_SCOPE = 'https://api.securitycenter.microsoft.com/.default';
const DEFENDER_API_BASE = 'https://api.security.microsoft.com';

function getCacheKey(config) {
  return `${config.defenderTenantId}:${config.defenderClientId}`;
}

function resolveEffectiveConfig(tenantId, integration = {}) {
  const sharedClientId = process.env.DEFENDER_SHARED_CLIENT_ID || process.env.DEFENDER_CLIENT_ID || '';
  const sharedClientSecret = process.env.DEFENDER_SHARED_CLIENT_SECRET || process.env.DEFENDER_CLIENT_SECRET || '';

  const tenantClientId = integration.defenderClientId || '';
  const tenantClientSecret = integration.defenderClientSecret || '';
  const tenantDefenderTenantId = integration.defenderTenantId || '';

  const usingSharedCredentials = !(tenantClientId && tenantClientSecret);

  return {
    ...integration,
    defenderEnabled: integration.defenderEnabled !== false,
    defenderTenantId: tenantDefenderTenantId || tenantId,
    defenderClientId: usingSharedCredentials ? sharedClientId : tenantClientId,
    defenderClientSecret: usingSharedCredentials ? sharedClientSecret : tenantClientSecret,
    usingSharedCredentials,
  };
}

async function getAccessToken(config) {
  const cacheKey = getCacheKey(config);
  const now = Date.now();
  const cached = tokenCache.get(cacheKey);

  if (cached && cached.expiresAt - 60000 > now) {
    return cached.accessToken;
  }

  console.log('DEFENDER EFFECTIVE CONFIG', {
    tenantId: config.defenderTenantId,
    clientId: config.defenderClientId,
    hasSecret: !!config.defenderClientSecret,
    usingSharedCredentials: !!config.usingSharedCredentials,
    scope: DEFENDER_SCOPE,
  });

  const body = new URLSearchParams({
    client_id: config.defenderClientId,
    client_secret: config.defenderClientSecret,
    grant_type: 'client_credentials',
    scope: DEFENDER_SCOPE,
  });

  const response = await fetch(
    `https://login.microsoftonline.com/${config.defenderTenantId}/oauth2/v2.0/token`,
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body,
    }
  );

  const data = await response.json().catch(() => ({}));

  if (!response.ok) {
    const error = new Error(data.error_description || 'Failed to acquire Defender token.');
    error.status = response.status;
    error.details = data;
    throw error;
  }

  tokenCache.set(cacheKey, {
    accessToken: data.access_token,
    expiresAt: Date.now() + Number(data.expires_in || 3600) * 1000,
  });

  return data.access_token;
}

async function defenderGet(config, path) {
  const cacheKey = getCacheKey(config);
  let token = await getAccessToken(config);

  let response = await fetch(`${DEFENDER_API_BASE}${path}`, {
    method: 'GET',
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: 'application/json',
    },
  });

  let data = await response.json().catch(() => ({}));

  const missingRoles =
    response.status === 403 &&
    String(data?.error?.message || '').includes('Missing application roles');

  if (missingRoles) {
    tokenCache.delete(cacheKey);
    token = await getAccessToken(config);

    response = await fetch(`${DEFENDER_API_BASE}${path}`, {
      method: 'GET',
      headers: {
        Authorization: `Bearer ${token}`,
        Accept: 'application/json',
      },
    });

    data = await response.json().catch(() => ({}));
  }

  if (!response.ok) {
    const apiMessage = data?.error?.message || `Defender API failed: ${response.status}`;
    const error = new Error(apiMessage);
    error.status = response.status;
    error.details = data;
    throw error;
  }

  return data;
}

function normalizeSeverity(value) {
  return value || 'unknown';
}

function normalizeText(value) {
  if (!value) return null;
  const text = String(value).trim();
  return text || null;
}

function guessProductFromText(text) {
  const raw = normalizeText(text);
  if (!raw) return null;
  const patterns = [
    /vulnerability exists in\s+(.+?)\s+version/i,
    /exists in\s+(.+?)\s+versions?/i,
    /upgrade\s+(.+?)\s+to\s+/i,
    /apply\s+the\s+latest\s+patches?\s+for\s+(.+?)(?:\.|$)/i,
    /affected product:?\s+(.+?)(?:\.|$)/i,
  ];
  for (const pattern of patterns) {
    const m = raw.match(pattern);
    if (m && m[1]) {
      const candidate = m[1].replace(/[\[\]()]/g, '').trim();
      if (candidate && !candidate.toUpperCase().startsWith('CVE-') && !candidate.toUpperCase().startsWith('TVM-')) {
        return candidate;
      }
    }
  }
  return null;
}

function normalizeVulnerability(raw) {
  const cveId = normalizeText(raw.cveId || raw.id || null);
  const productName =
    normalizeText(raw.productName) ||
    guessProductFromText(raw.description) ||
    (cveId && cveId.toUpperCase().startsWith('CVE-') ? null : normalizeText(raw.name));
  const publisher = normalizeText(raw.vendor || raw.publisher || null);
  return {
    id: normalizeText(raw.id || cveId),
    cveId,
    name: normalizeText(raw.name || cveId),
    productName,
    publisher,
    description: normalizeText(raw.description) || '',
    severity: normalizeSeverity(raw.severity || raw.severityName),
    cvss: raw.cvssV3 || raw.cvssScore || null,
    publishedOn: raw.publishedOn || null,
    updatedOn: raw.updatedOn || null,
    exploitabilityLevel: raw.exploitabilityLevel || null,
    category: 'application',
    affectedMachineCount: Number(raw.affectedMachineCount || 0),
    affectedMachines: Array.isArray(raw.affectedMachines) ? raw.affectedMachines : [],
    recommendation: normalizeText(raw.recommendation) || null,
  };
}

function normalizeRecommendation(raw) {
  return {
    id: normalizeText(raw.id),
    name: normalizeText(raw.name),
    recommendationName: normalizeText(raw.recommendationName || raw.name),
    productName: normalizeText(raw.productName || raw.softwareName),
    publisher: normalizeText(raw.productVendor || raw.publisher || raw.vendor),
    description: normalizeText(raw.description || raw.remediationAction || raw.securityRecommendation),
    category: normalizeText(raw.category),
    fixingKbId: normalizeText(raw.fixingKbId),
  };
}

function mergeEnrichment(vuln, recMap, softwareMap) {
  const cveKey = (vuln.cveId || '').toUpperCase();
  const rec = recMap.get(cveKey);
  const software = softwareMap.get(cveKey);
  const productName =
    software?.productName ||
    vuln.productName ||
    rec?.productName ||
    guessProductFromText(vuln.description) ||
    'Unknown product';
  const publisher =
    software?.publisher ||
    vuln.publisher ||
    rec?.publisher ||
    'Not provided by Defender payload';
  const affectedMachines = software?.affectedMachines || vuln.affectedMachines || [];
  const affectedMachineCount =
    software?.affectedMachineCount ?? vuln.affectedMachineCount ?? affectedMachines.length ?? 0;
  return {
    ...vuln,
    productName,
    publisher,
    relatedProducts: Array.isArray(software?.relatedProducts) ? software.relatedProducts : [],
    recommendation:
      vuln.recommendation ||
      rec?.description ||
      `Apply the vendor-provided update or mitigation path for the affected product.`,
    affectedMachines,
    affectedMachineCount,
    inferenceSource: software?.productName ? 'machinesVulnerabilities' : (vuln.productName ? 'vulnerability-payload' : null),
  };
}

function prettifyProductName(value) {
  const raw = normalizeText(value);
  if (!raw) return null;
  return raw
    .replace(/_/g, ' ')
    .replace(/chromium based/gi, 'Chromium-based')
    .replace(/webview2/gi, 'WebView2')
    .replace(/mac os/gi, 'Mac OS')
    .replace(/[a-z]/g, (m) => m.toUpperCase());
}

async function listSoftwareVulnerabilitiesByMachine(config, top = 5000) {
  const data = await defenderGet(config, `/api/vulnerabilities/machinesVulnerabilities?$top=${top}`);
  return Array.isArray(data?.value) ? data.value : [];
}

function buildSoftwareIndex(rows) {
  const map = new Map();
  for (const row of rows) {
    const cveKey = String(row?.cveId || row?.CveId || '').toUpperCase();
    if (!cveKey) continue;

    const machineName = normalizeText(
      row?.computerDnsName || row?.deviceName || row?.machineName || row?.DeviceName || row?.MachineName
    );
    const machineId = normalizeText(row?.machineId || row?.deviceId || row?.MachineId || machineName);
    const productName = prettifyProductName(row?.productName || row?.softwareName || row?.SoftwareName);
    const publisher = normalizeText(row?.productVendor || row?.softwareVendor || row?.SoftwareVendor);

    const existing = map.get(cveKey) || {
      productName: null,
      publisher: null,
      affectedMachines: [],
      affectedMachineCount: 0,
      relatedProducts: [],
      machineIds: new Set(),
      productFrequency: new Map(),
      publisherFrequency: new Map(),
    };

    if (machineId && !existing.machineIds.has(machineId)) {
      existing.machineIds.add(machineId);
      if (machineName && !existing.affectedMachines.includes(machineName)) {
        existing.affectedMachines.push(machineName);
      }
    }

    if (productName) {
      existing.productFrequency.set(productName, (existing.productFrequency.get(productName) || 0) + 1);
      if (!existing.relatedProducts.includes(productName)) {
        existing.relatedProducts.push(productName);
      }
    }

    if (publisher) {
      existing.publisherFrequency.set(publisher, (existing.publisherFrequency.get(publisher) || 0) + 1);
    }

    const topProduct = [...existing.productFrequency.entries()].sort((a, b) => b[1] - a[1])[0]?.[0] || null;
    const topPublisher = [...existing.publisherFrequency.entries()].sort((a, b) => b[1] - a[1])[0]?.[0] || null;

    existing.productName = topProduct;
    existing.publisher = topPublisher;
    existing.affectedMachineCount = existing.machineIds.size;
    map.set(cveKey, existing);
  }

  for (const value of map.values()) {
    delete value.machineIds;
    delete value.productFrequency;
    delete value.publisherFrequency;
  }

  return map;
}

function buildRecommendationIndex(rows) {
  const map = new Map();
  for (const row of rows.map(normalizeRecommendation)) {
    const possibleKeys = [row.id, row.name, row.recommendationName]
      .map((v) => normalizeText(v))
      .filter(Boolean)
      .map((v) => String(v).toUpperCase());
    for (const key of possibleKeys) {
      if ((key.startsWith('CVE-') || key.startsWith('TVM-')) && !map.has(key)) {
        map.set(key, row);
      }
    }
  }
  return map;
}

async function getTenantConfigOrThrow(tenantId) {
  const integration = await getTenantIntegration(tenantId);
  const config = resolveEffectiveConfig(tenantId, integration || {});

  if (!integration || integration.defenderEnabled === false) {
    const error = new Error('Defender integration is not configured for this customer tenant.');
    error.status = 404;
    throw error;
  }

  if (!config.defenderClientId || !config.defenderClientSecret) {
    const error = new Error('Defender credentials are missing for this customer tenant.');
    error.status = 500;
    throw error;
  }

  return { integration, config };
}

async function listTenantVulnerabilities(tenantId, top = 100) {
  const { config } = await getTenantConfigOrThrow(tenantId);
  const [vulnData, recData, softwareRows] = await Promise.all([
    defenderGet(config, `/api/vulnerabilities?$top=${top}`),
    defenderGet(config, `/api/recommendations?$top=${Math.min(top, 200)}`).catch(() => ({ value: [] })),
    listSoftwareVulnerabilitiesByMachine(config, 5000).catch(() => []),
  ]);

  const baseItems = Array.isArray(vulnData?.value) ? vulnData.value.map(normalizeVulnerability) : [];
  const recMap = buildRecommendationIndex(Array.isArray(recData?.value) ? recData.value : []);
  const softwareMap = buildSoftwareIndex(Array.isArray(softwareRows) ? softwareRows : []);
  const items = baseItems.map((item) => mergeEnrichment(item, recMap, softwareMap));

  await writeTenantSnapshot(tenantId, 'defender/vulnerabilities', {
    count: items.length,
    items,
  }).catch(() => {});

  return items;
}

async function listTenantRecommendations(tenantId, top = 100) {
  const { config } = await getTenantConfigOrThrow(tenantId);
  const data = await defenderGet(config, `/api/recommendations?$top=${top}`);
  const items = Array.isArray(data?.value) ? data.value.map(normalizeRecommendation) : [];

  await writeTenantSnapshot(tenantId, 'defender/recommendations', {
    count: items.length,
    items,
  }).catch(() => {});

  return items;
}

async function listTenantVulnerabilityMachines(tenantId, cveId, top = 100) {
  const { config } = await getTenantConfigOrThrow(tenantId);
  const normalized = String(cveId || '').toUpperCase();
  if (!normalized.startsWith('CVE-')) {
    return { count: 0, items: [], unsupportedIdentifier: cveId };
  }

  const data = await defenderGet(
    config,
    `/api/vulnerabilities/${encodeURIComponent(normalized)}/machineReferences?$top=${top}`
  );

  const items = Array.isArray(data?.value)
    ? data.value.map((row) => ({
        id: row.id || null,
        computerDnsName: row.computerDnsName || row.deviceName || null,
        osPlatform: row.osPlatform || null,
        rbacGroupName: row.rbacGroupName || null,
      }))
    : [];

  return { count: items.length, items };
}

module.exports = {
  listTenantVulnerabilities,
  listTenantRecommendations,
  listTenantVulnerabilityMachines,
  getTenantConfigOrThrow,
};
