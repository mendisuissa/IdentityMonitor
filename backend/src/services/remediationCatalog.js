function normalizeText(value) {
  return String(value || '').toLowerCase();
}

function textHasAny(text, hints = []) {
  return hints.some((hint) => text.includes(hint));
}

function classifyFinding(finding = {}) {
  const category = normalizeText(finding.category);
  const productName = normalizeText(finding.productName || finding.softwareName || finding.name);
  const publisher = normalizeText(finding.publisher);
  const description = normalizeText(finding.description);
  const recommendation = normalizeText(finding.recommendation);

  const text = [category, productName, publisher, description, recommendation].join(' ');

  const windowsUpdateHints = [
    'windows update', 'security update', 'feature update', 'quality update', 'kb', 'cumulative update',
    'windows component', 'operating system', 'windows server', 'windows 10', 'windows 11', 'monthly rollup',
    'windows telephony service', 'telephony service', 'win32k', 'kernel', 'rpc', 'rdp', 'smb', 'hyper-v',
    'print spooler', 'lsass', 'remote desktop', 'privilege escalation', 'elevation of privilege',
    'microsoft windows', 'windows service', 'server service'
  ];
  const intuneHints = ['intune', 'configuration profile', 'compliance policy', 'device policy', 'settings catalog'];
  const scriptHints = ['script', 'powershell', 'remediation script', 'proactive remediation', 'detection script'];
  const identityHints = ['identity', 'conditional access', 'entra', 'azure ad', 'authentication', 'mfa'];
  const appHints = ['chrome', 'chromium', 'firefox', 'edge', 'webview', '7-zip', '7zip', 'notepad++', 'acrobat', 'office', 'vlc', 'java', 'browser', 'runtime', 'mongodb', 'openssl'];

  if (textHasAny(text, windowsUpdateHints) || category === 'windows-update' || category === 'platform' || category === 'windows') {
    return { type: 'windows-update', family: 'platform' };
  }

  if (textHasAny(text, intuneHints) || category === 'intune-policy') {
    return { type: 'intune-policy', family: 'configuration' };
  }

  if (textHasAny(text, scriptHints) || category === 'script') {
    return { type: 'script', family: 'configuration' };
  }

  if (category === 'application' || textHasAny(text, appHints)) {
    return { type: 'application', family: 'software' };
  }

  if (textHasAny(text, identityHints) || category === 'identity') {
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
