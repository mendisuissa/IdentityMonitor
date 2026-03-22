const DEFAULT_BASE_URL = 'http://localhost:4000';

function normalizeBaseUrl(raw) {
  return String(raw || DEFAULT_BASE_URL).replace(/\/$/, '');
}

function getWebappConfig() {
  const baseUrl = normalizeBaseUrl(
    process.env.WEBAPP_REMEDIATION_BASE_URL ||
    process.env.WEBAPP_BASE_URL ||
    DEFAULT_BASE_URL
  );

  const token = String(
    process.env.WEBAPP_REMEDIATION_TOKEN ||
    process.env.REMEDIATION_SHARED_TOKEN ||
    ''
  ).trim();

  return {
    baseUrl,
    token,
    tokenConfigured: !!token
  };
}

function buildHeaders(extraHeaders = {}) {
  const { token } = getWebappConfig();
  const headers = {
    Accept: 'application/json',
    ...extraHeaders
  };

  if (token) {
    headers.Authorization = `Bearer ${token}`;
  }

  return headers;
}

async function requestJson(method, path, payload) {
  const { baseUrl } = getWebappConfig();
  const isBodyMethod = method !== 'GET' && method !== 'HEAD';
  const response = await fetch(`${baseUrl}${path}`, {
    method,
    headers: buildHeaders(isBodyMethod ? { 'Content-Type': 'application/json' } : {}),
    body: isBodyMethod ? JSON.stringify(payload || {}) : undefined
  });

  const data = await response.json().catch(() => ({}));

  if (!response.ok) {
    const externalMessage = data?.details?.message || data?.message || data?.error || `Request failed: ${response.status}`;
    const error = new Error(externalMessage);
    error.status = response.status;
    error.details = data;
    throw error;
  }

  return data;
}

function buildHints(finding = {}) {
  return {
    id: finding.id || finding.cveId || finding.name || null,
    cveId: finding.cveId || null,
    productName: finding.productName || finding.softwareName || finding.name || null,
    publisher: finding.publisher || null,
    recommendation: finding.recommendation || null,
    description: finding.description || null,
    category: finding.category || null,
    severity: finding.severity || null,
    relatedProducts: Array.isArray(finding.relatedProducts) ? finding.relatedProducts : [],
    productNames: Array.isArray(finding.productNames) ? finding.productNames : []
  };
}

async function getExternalHealth() {
  try {
    const health = await requestJson('GET', '/api/remediation/health');
    return {
      ok: true,
      service: health?.service || 'webapp-remediation-executor',
      sharedTokenConfigured: !!health?.sharedTokenConfigured,
      sharedTokenAccepted: !!health?.sharedTokenAccepted,
      baseUrl: getWebappConfig().baseUrl
    };
  } catch (error) {
    return {
      ok: false,
      baseUrl: getWebappConfig().baseUrl,
      tokenConfigured: getWebappConfig().tokenConfigured,
      status: error.status || 500,
      error: error.message,
      details: error.details || null
    };
  }
}

async function resolveApplicationRemediation(finding) {
  return requestJson('POST', '/api/remediation/resolve', { finding: buildHints(finding) });
}

async function executeApplicationRemediation(payload) {
  const { finding = {}, ...rest } = payload || {};
  return requestJson('POST', '/api/remediation/execute', { ...rest, finding: buildHints(finding) });
}

module.exports = {
  getExternalHealth,
  getWebappConfig,
  resolveApplicationRemediation,
  executeApplicationRemediation
};
