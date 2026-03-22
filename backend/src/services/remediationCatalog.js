function textContainsAny(text, hints = []) {
  return hints.some((hint) => text.includes(hint));
}

function classifyFinding(finding = {}) {
  const category = String(finding.category || '').toLowerCase();
  const productName = String(finding.productName || finding.softwareName || finding.name || '').toLowerCase();
  const publisher = String(finding.publisher || '').toLowerCase();
  const description = String(finding.description || '').toLowerCase();
  const recommendation = String(finding.recommendation || '').toLowerCase();

  const text = [category, productName, publisher, description, recommendation].join(' ');

  const windowsUpdateHints = [
    'windows update', 'security update', 'feature update', 'quality update', 'cumulative update',
    'servicing stack', 'monthly rollup', 'microsoft windows', 'windows server', 'operating system',
    'kb', 'patch tuesday'
  ];
  const intuneHints = [
    'intune', 'configuration profile', 'compliance policy', 'device policy', 'endpoint security policy',
    'attack surface reduction', 'asr rule', 'device configuration'
  ];
  const scriptHints = [
    'script', 'powershell', 'remediation script', 'proactive remediation', 'shell script', 'detection script'
  ];
  const appHints = [
    'chrome', 'firefox', 'edge', 'webview', '7-zip', '7zip', 'notepad++', 'acrobat', 'office', 'vlc',
    'java', 'python', 'node.js', 'mongodb', 'webex', 'zoom', 'teams', 'adobe'
  ];

  if (textContainsAny(text, intuneHints)) {
    return { type: 'intune-policy', family: 'configuration' };
  }

  if (textContainsAny(text, scriptHints)) {
    return { type: 'script', family: 'configuration' };
  }

  if (
    textContainsAny(text, windowsUpdateHints) ||
    category.includes('windows') ||
    category.includes('os') ||
    productName.startsWith('windows ') ||
    productName.includes('windows server') ||
    /^kb\d+/i.test(productName)
  ) {
    return { type: 'windows-update', family: 'platform' };
  }

  if (
    category.includes('application') ||
    textContainsAny(text, appHints) ||
    (publisher && publisher !== 'microsoft windows' && !productName.includes('windows'))
  ) {
    return { type: 'application', family: 'software' };
  }

  if (category.includes('identity')) {
    return { type: 'identity', family: 'identity' };
  }

  if (category.includes('configuration') || category.includes('config')) {
    return { type: 'configuration', family: 'configuration' };
  }

  return { type: 'manual', family: 'manual' };
}

module.exports = {
  classifyFinding
};
