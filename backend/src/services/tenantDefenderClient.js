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

function normalizeDefenderUrl(pathOrUrl) {
  if (!pathOrUrl) return null;
  if (/^https?:\/\//i.test(pathOrUrl)) {
    return pathOrUrl;
  }
  return `${DEFENDER_API_BASE}${pathOrUrl}`;
}

async function defenderGet(config, pathOrUrl) {
  const cacheKey = getCacheKey(config);
  let token = await getAccessToken(config);
  const url = normalizeDefenderUrl(pathOrUrl);

  let response = await fetch(url, {
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

    response = await fetch(url, {
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


async function defenderGetAllPages(config, initialPathOrUrl, options = {}) {
  const maxPages = Number(options.maxPages || 50);
  const allItems = [];
  let nextUrl = initialPathOrUrl;
  let page = 0;

  const initialUrl = normalizeDefenderUrl(initialPathOrUrl);
  let skipMode = false;
  let pageSize = 0;
  let skip = 0;

  try {
    const u = new URL(initialUrl);
    pageSize = Number(u.searchParams.get('$top') || 0);
    skip = Number(u.searchParams.get('$skip') || 0);
    if (pageSize > 0 && /\/api\/(vulnerabilities|recommendations)(\?|$)/i.test(u.pathname)) {
      skipMode = true;
    }
  } catch (_) {}

  while (nextUrl && page < maxPages) {
    page += 1;
    const data = await defenderGet(config, nextUrl);
    const items = Array.isArray(data?.value) ? data.value : [];
    allItems.push(...items);

    const rawNext = data?.['@odata.nextLink'] || data?.odataNextLink || null;
    if (rawNext) {
      nextUrl = rawNext;
      continue;
    }

    if (skipMode && pageSize > 0 && items.length === pageSize) {
      skip += pageSize;
      try {
        const u = new URL(initialUrl);
        u.searchParams.set('$top', String(pageSize));
        u.searchParams.set('$skip', String(skip));
        nextUrl = `${u.pathname}${u.search}`;
      } catch (_) {
        nextUrl = null;
      }
      continue;
    }

    nextUrl = null;
  }

  return allItems;
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

function inferCategory(raw = {}, productName = null) {
  const text = [
    raw?.name,
    raw?.description,
    raw?.vendor,
    raw?.publisher,
    productName,
    raw?.category,
    raw?.vulnerabilityCategory,
    raw?.recommendation,
  ]
    .filter(Boolean)
    .map((v) => String(v).toLowerCase())
    .join(' ');

  const windowsHints = [
    'windows update', 'security update', 'feature update', 'quality update', 'kb', 'cumulative update',
    'windows component', 'operating system', 'windows server', 'windows 10', 'windows 11', 'monthly rollup',
    'servicing stack', 'microsoft windows'
  ];
  const intuneHints = ['intune', 'configuration profile', 'compliance policy', 'device policy', 'settings catalog'];
  const scriptHints = ['script', 'powershell', 'remediation script', 'proactive remediation', 'detection script'];
  const identityHints = ['identity', 'conditional access', 'entra', 'azure ad', 'authentication', 'mfa'];

  if (windowsHints.some((hint) => text.includes(hint))) return 'windows-update';
  if (intuneHints.some((hint) => text.includes(hint))) return 'intune-policy';
  if (scriptHints.some((hint) => text.includes(hint))) return 'script';
  if (identityHints.some((hint) => text.includes(hint))) return 'identity';
  return 'application';
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
    publicExploit: raw.publicExploit === true,
    exploitVerified: raw.exploitVerified === true,
    exploitInKit: raw.exploitInKit === true,
    status: normalizeText(raw.status) || null,
    epss: raw.epss ?? null,
    category: inferCategory(raw, productName),
    affectedMachineCount: Number(raw.exposedMachines || raw.affectedMachineCount || 0),
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
  const products = Array.isArray(software?.products) ? software.products : [];
  const primaryProduct = products[0] || null;
  const productName =
    vuln.productName ||
    primaryProduct?.productName ||
    software?.productName ||
    rec?.productName ||
    guessProductFromText(vuln.description) ||
    'Unknown product';
  const publisher =
    vuln.publisher ||
    primaryProduct?.publisher ||
    software?.publisher ||
    rec?.publisher ||
    'Not provided by Defender payload';
  const affectedMachines = Array.isArray(software?.affectedMachines)
    ? software.affectedMachines.map((x) => x.name)
    : (vuln.affectedMachines || []);
  const affectedMachineCount =
    software?.affectedMachineCount || vuln.affectedMachineCount || affectedMachines.length || 0;
  return {
    ...vuln,
    productName,
    publisher,
    productNames: products.map((x) => x.productName).filter(Boolean),
    relatedProducts: products.map((x) => ({
      productName: x.productName,
      publisher: x.publisher || null,
      productVersion: x.productVersion || null,
    })),
    recommendation:
      vuln.recommendation ||
      rec?.description ||
      `Apply the vendor-provided update or mitigation path for the affected product.`,
    affectedMachines,
    affectedMachineCount,
  };
}

async function listSoftwareVulnerabilitiesByMachine(config) {
  return defenderGetAllPages(config, '/api/vulnerabilities/machinesVulnerabilities?$top=200', { maxPages: 25 });
}

function buildSoftwareIndex(rows) {
  const map = new Map();
  for (const row of rows) {
    const cveKey = String(row?.cveId || row?.CveId || '').toUpperCase();
    if (!cveKey) continue;
    const existing = map.get(cveKey) || {
      productName: null,
      publisher: null,
      affectedMachines: [],
      affectedMachineCount: 0,
      products: [],
    };
    const productName = normalizeText(row?.productName || row?.SoftwareName);
    const publisher = normalizeText(row?.productVendor || row?.SoftwareVendor);
    const machineName = normalizeText(row?.computerDnsName || row?.deviceName || row?.DeviceName || row?.machineName);
    const machineId = normalizeText(row?.machineId || row?.MachineId);
    const productVersion = normalizeText(row?.productVersion || row?.SoftwareVersion);

    if (productName) {
      const key = `${(publisher || '').toLowerCase()}|${productName.toLowerCase()}|${(productVersion || '').toLowerCase()}`;
      if (!existing.products.some((x) => x.key === key)) {
        existing.products.push({
          key,
          productName,
          publisher,
          productVersion,
        });
      }
    }

    const machineKey = machineId || machineName;
    if (machineKey && !existing.affectedMachines.some((x) => x.key === machineKey)) {
      existing.affectedMachines.push({ key: machineKey, name: machineName || machineId || 'Unknown device' });
    }

    if (!existing.productName && productName) existing.productName = productName;
    if (!existing.publisher && publisher) existing.publisher = publisher;
    existing.affectedMachineCount = existing.affectedMachines.length;
    map.set(cveKey, existing);
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


async function fetchAllVulnerabilities(config, requestedTop = 0) {
  const pageSize = requestedTop > 0 ? Math.min(requestedTop, 200) : 200;
  return defenderGetAllPages(config, `/api/vulnerabilities?$top=${pageSize}&$skip=0`, { maxPages: 100 });
}

async function fetchAllRecommendations(config, requestedTop = 0) {
  const pageSize = requestedTop > 0 ? Math.min(requestedTop, 200) : 200;
  return defenderGetAllPages(config, `/api/recommendations?$top=${pageSize}&$skip=0`, { maxPages: 50 });
}

async function listTenantVulnerabilities(tenantId, top = 0) {
  const { config } = await getTenantConfigOrThrow(tenantId);

  const requestedTop = Number(top) > 0 ? Number(top) : 0;

  const [vulnRows, recRows] = await Promise.all([
    fetchAllVulnerabilities(config, requestedTop),
    fetchAllRecommendations(config, 0).catch(() => []),
  ]);

  const baseItems = Array.isArray(vulnRows) ? vulnRows.map(normalizeVulnerability) : [];
  const recMap = buildRecommendationIndex(Array.isArray(recRows) ? recRows : []);
  const items = baseItems.map((item) => mergeEnrichment(item, recMap, new Map()));

  const finalItems = requestedTop > 0 ? items.slice(0, requestedTop) : items;

  await writeTenantSnapshot(tenantId, 'defender/vulnerabilities', {
    count: finalItems.length,
    items: finalItems,
  }).catch(() => {});

  return finalItems;
}
async function listTenantRecommendations(tenantId, top = 0) {
  const { config } = await getTenantConfigOrThrow(tenantId);

  const requestedTop = Number(top) > 0 ? Number(top) : 0;
  const items = await fetchAllRecommendations(config, requestedTop);

  const normalized = Array.isArray(items) ? items.map(normalizeRecommendation) : [];
  const finalItems = requestedTop > 0 ? normalized.slice(0, requestedTop) : normalized;

  await writeTenantSnapshot(tenantId, 'defender/recommendations', {
    count: finalItems.length,
    items: finalItems,
  }).catch(() => {});

  return finalItems;
}

async function listTenantVulnerabilityMachines(tenantId, cveId, top = 100) {
  const { config } = await getTenantConfigOrThrow(tenantId);
  const normalized = String(cveId || '').toUpperCase();
  if (!normalized.startsWith('CVE-')) {
    return { count: 0, items: [], unsupportedIdentifier: cveId };
  }

  const requestedTop = Number(top) > 0 ? Number(top) : 0;
  const pageSize = requestedTop > 0 ? Math.min(requestedTop, 200) : 200;

  const rows = await defenderGetAllPages(
    config,
    `/api/vulnerabilities/${encodeURIComponent(normalized)}/machineReferences?$top=${pageSize}`,
    { maxPages: 50 }
  );

  const items = Array.isArray(rows)
    ? rows.map((row) => ({
        id: row.id || null,
        computerDnsName: row.computerDnsName || row.deviceName || null,
        osPlatform: row.osPlatform || null,
        rbacGroupName: row.rbacGroupName || null,
      }))
    : [];

  const finalItems = requestedTop > 0 ? items.slice(0, requestedTop) : items;
  return { count: finalItems.length, items: finalItems };
}

module.exports = {
  listTenantVulnerabilities,
  listTenantRecommendations,
  listTenantVulnerabilityMachines,
  getTenantConfigOrThrow,
};
