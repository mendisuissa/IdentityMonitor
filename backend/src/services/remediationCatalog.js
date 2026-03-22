function classifyFinding(finding = {}) {
  const category = String(finding.category || '').toLowerCase();
  const productName = String(finding.productName || finding.softwareName || finding.name || '').toLowerCase();
  const publisher = String(finding.publisher || '').toLowerCase();
  const description = String(finding.description || '').toLowerCase();

  const text = [category, productName, publisher, description].join(' ');

  const appHints = ['chrome', 'firefox', 'edge', '7-zip', '7zip', 'notepad++', 'acrobat', 'office', 'vlc', 'java', 'webview', 'runtime', 'driver'];
  const windowsUpdateHints = ['windows update', 'security update', 'feature update', 'quality update', 'kb', 'cumulative update', 'servicing stack', 'windows component', 'operating system', 'microsoft windows', 'windows server'];
  const intuneHints = ['intune', 'configuration profile', 'compliance policy', 'device policy', 'settings catalog'];
  const scriptHints = ['script', 'powershell', 'remediation script', 'proactive remediation', 'shell script', 'bash'];

  if (windowsUpdateHints.some((hint) => text.includes(hint)) || category.includes('windows-update') || category == 'windows' || productName.includes('microsoft windows')) {
    return { type: 'windows-update', family: 'platform' };
  }

  if (intuneHints.some((hint) => text.includes(hint)) || category.includes('intune-policy')) {
    return { type: 'intune-policy', family: 'configuration' };
  }

  if (scriptHints.some((hint) => text.includes(hint)) || category.includes('script')) {
    return { type: 'script', family: 'configuration' };
  }

  if (category.includes('identity')) {
    return { type: 'identity', family: 'identity' };
  }

  if (category.includes('configuration') || category.includes('config')) {
    return { type: 'configuration', family: 'configuration' };
  }

  if (category.includes('application') || appHints.some((hint) => text.includes(hint))) {
    return { type: 'application', family: 'software' };
  }

  if (publisher && !windowsUpdateHints.some((hint) => text.includes(hint))) {
    return { type: 'application', family: 'software' };
  }

  return { type: 'manual', family: 'manual' };
}

module.exports = {
  classifyFinding
};
