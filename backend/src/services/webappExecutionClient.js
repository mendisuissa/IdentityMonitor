const WEBAPP_BASE_URL = process.env.WEBAPP_BASE_URL || 'http://localhost:4000';
const SHARED_TOKEN = process.env.REMEDIATION_SHARED_TOKEN || '';

async function postJson(path, payload, includeAuth = false) {
  const headers = { 'Content-Type': 'application/json' };

  if (includeAuth && SHARED_TOKEN) {
    headers.Authorization = `Bearer ${SHARED_TOKEN}`;
  }

  const response = await fetch(`${WEBAPP_BASE_URL}${path}`, {
    method: 'POST',
    headers,
    body: JSON.stringify(payload || {})
  });

  const data = await response.json().catch(() => ({}));

  if (!response.ok) {
    const externalMessage = data?.details?.message || data?.error || `Request failed: ${response.status}`;
    const error = new Error(externalMessage);
    error.status = response.status;
    error.details = data;
    throw error;
  }

  return data;
}

function buildHints(finding = {}) {
  return {
    cveId: finding.cveId || null,
    productName: finding.productName || finding.softwareName || finding.name || null,
    publisher: finding.publisher || null,
    recommendation: finding.recommendation || null,
    description: finding.description || null,
    category: finding.category || null,
    severity: finding.severity || null
  };
}

async function resolveApplicationRemediation(finding) {
  return postJson('/api/remediation/resolve', { finding: buildHints(finding) }, true);
}

async function executeApplicationRemediation(payload) {
  const { finding = {}, ...rest } = payload || {};
  return postJson('/api/remediation/execute', { ...rest, finding: buildHints(finding) }, true);
}

module.exports = {
  resolveApplicationRemediation,
  executeApplicationRemediation
};
