function classifyFinding(finding = {}) {
  const category = String(finding.category || '').toLowerCase();
  const productName = String(finding.productName || finding.softwareName || finding.name || '').toLowerCase();
  const publisher = String(finding.publisher || '').toLowerCase();
  const description = String(finding.description || '').toLowerCase();
  const recommendation = String(finding.recommendation || '').toLowerCase();

  const text = [category, productName, publisher, description, recommendation].join(' ');

  const appHints = ['chrome', 'firefox', 'edge', 'webview2', '7-zip', '7zip', 'notepad++', 'acrobat', 'office', 'vlc', 'java'];
  const windowsUpdateHints = ['windows update', 'security update', 'feature update', 'quality update', 'kb', 'cumulative update', 'windows component', 'operating system', 'patch tuesday', 'os build'];
  const intuneHints = ['intune', 'configuration profile', 'compliance policy', 'device policy', 'attack surface reduction policy', 'endpoint security policy'];
  const scriptHints = ['script', 'powershell', 'remediation script', 'proactive remediation', 'detection script', 'remediation package'];

  if (windowsUpdateHints.some((hint) => text.includes(hint)) || category.includes('windows') || productName.includes('windows')) {
    return { type: 'windows-update', family: 'platform' };
  }

  if (intuneHints.some((hint) => text.includes(hint))) {
    return { type: 'intune-policy', family: 'configuration' };
  }

  if (scriptHints.some((hint) => text.includes(hint))) {
    return { type: 'script', family: 'configuration' };
  }

  if (category.includes('application') || appHints.some((hint) => text.includes(hint)) || (publisher && !text.includes('microsoft windows'))) {
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
