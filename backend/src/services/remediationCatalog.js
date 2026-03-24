function normalizeText(value) {
  return String(value || '').trim();
}

function firstNonEmpty(...values) {
  for (const value of values) {
    const text = normalizeText(value);
    if (text) return text;
  }
  return '';
}

function inferProductFromDescription(description = '') {
  const text = String(description || '');
  const lower = text.toLowerCase();
  const patterns = [
    /windows telephony service/i,
    /windows kernel/i,
    /windows update/i,
    /hyper-v/i,
    /remote desktop services?/i,
    /remote desktop protocol/i,
    /server message block/i,
    /windows smb/i,
    /rpc runtime/i,
    /windows rpc/i,
    /microsoft edge/i,
    /edge chromium/i,
    /microsoft office/i,
    /windows defender/i,
  ];
  for (const pattern of patterns) {
    const match = text.match(pattern);
    if (match?.[0]) return match[0];
  }
  if (lower.includes('windows') && lower.includes('service')) return 'Windows platform service';
  if (lower.includes('windows') && lower.includes('component')) return 'Windows platform component';
  if (lower.includes('windows')) return 'Microsoft Windows component';
  return '';
}

function inferPublisher({ publisher = '', description = '', classification = null } = {}) {
  const explicit = normalizeText(publisher);
  if (explicit) return explicit;
  const lower = String(description || '').toLowerCase();
  if ((classification && ['windows-update', 'platform'].includes(classification.type)) || lower.includes('windows') || lower.includes('microsoft')) {
    return 'Microsoft';
  }
  return 'Not provided by Defender payload';
}

function classifyFinding(finding = {}) {
  const category = String(finding.category || '').toLowerCase();
  const productName = String(finding.productName || finding.softwareName || finding.name || '').toLowerCase();
  const publisher = String(finding.publisher || '').toLowerCase();
  const description = String(finding.description || '').toLowerCase();
  const recommendation = String(finding.recommendation || '').toLowerCase();

  const text = [category, productName, publisher, description, recommendation].join(' ');

  const windowsUpdateHints = [
    'windows update', 'security update', 'feature update', 'quality update', 'kb', 'cumulative update',
    'windows component', 'operating system', 'windows server', 'windows 10', 'windows 11', 'monthly rollup',
    'telephony service', 'kernel', 'rpc', 'smb', 'hyper-v', 'privilege escalation'
  ];
  const intuneHints = ['intune', 'configuration profile', 'compliance policy', 'device policy', 'settings catalog'];
  const scriptHints = ['script', 'powershell', 'remediation script', 'proactive remediation', 'detection script'];
  const identityHints = ['identity', 'conditional access', 'entra', 'azure ad', 'authentication', 'mfa'];
  const appHints = ['chrome', 'chromium', 'firefox', 'edge', 'webview', '7-zip', '7zip', 'notepad++', 'acrobat', 'office', 'vlc', 'java', 'browser', 'runtime', 'mongodb', 'openssl'];

  if (windowsUpdateHints.some((hint) => text.includes(hint)) || category === 'windows-update') {
    return { type: 'windows-update', family: 'platform' };
  }

  if (intuneHints.some((hint) => text.includes(hint)) || category === 'intune-policy') {
    return { type: 'intune-policy', family: 'configuration' };
  }

  if (scriptHints.some((hint) => text.includes(hint)) || category === 'script') {
    return { type: 'script', family: 'configuration' };
  }

  if (identityHints.some((hint) => text.includes(hint)) || category === 'identity') {
    return { type: 'identity', family: 'identity' };
  }

  if (category === 'application' || appHints.some((hint) => text.includes(hint))) {
    return { type: 'application', family: 'software' };
  }

  if (category.includes('configuration') || category.includes('config')) {
    return { type: 'configuration', family: 'configuration' };
  }

  return { type: 'manual', family: 'manual' };
}

function buildDisplayCategoryLabel(finding = {}, classification = null) {
  if (classification?.type === 'windows-update') return 'windows-update';
  if (classification?.family === 'platform') return 'platform';
  const category = normalizeText(finding.category).toLowerCase();
  if (category) return category;
  return classification?.family || classification?.type || 'unknown';
}

function enrichFinding(finding = {}) {
  const classification = classifyFinding(finding);
  const description = normalizeText(finding.description);
  const explicitProduct = firstNonEmpty(finding.productName, finding.softwareName);
  const inferredProduct = inferProductFromDescription(description);
  const displayProductName = explicitProduct && !/^CVE-/i.test(explicitProduct) && !/^TVM-/i.test(explicitProduct)
    ? explicitProduct
    : firstNonEmpty(inferredProduct,
      classification.type === 'windows-update' ? 'Windows platform component' : '',
      classification.family === 'software' ? 'Software exposure' : '',
      'Unknown product');
  const displayPublisher = inferPublisher({ publisher: finding.publisher, description, classification });
  const displayCategoryLabel = buildDisplayCategoryLabel(finding, classification);
  const inferenceSource = explicitProduct && !/^CVE-/i.test(explicitProduct) && !/^TVM-/i.test(explicitProduct)
    ? 'defender-payload'
    : (inferredProduct ? 'description-enrichment' : 'classification-fallback');

  return {
    ...finding,
    classification,
    displayProductName,
    displayPublisher,
    displayCategoryLabel,
    inferredProductName: inferredProduct || null,
    inferenceSource,
  };
}

module.exports = {
  classifyFinding,
  enrichFinding,
};
