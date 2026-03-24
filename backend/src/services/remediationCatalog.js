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
    'windows telephony service', 'telephony service', 'privilege escalation', 'kernel', 'rpc', 'smb', 'hyper-v'
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

module.exports = {
  classifyFinding
};
