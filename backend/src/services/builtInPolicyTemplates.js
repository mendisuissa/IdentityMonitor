const BUILT_IN_POLICY_TEMPLATES = [
  {
    id: 'edge-security-baseline',
    name: 'Microsoft Edge hardening baseline',
    targetRef: 'Edge Security Baseline',
    description: 'Assign a tenant Edge security baseline or equivalent browser hardening policy.',
    category: 'browser',
    keywords: ['edge', 'browser', 'chromium'],
    findingTypes: ['application'],
  },
  {
    id: 'chrome-enterprise-hardening',
    name: 'Google Chrome enterprise hardening',
    targetRef: 'Chrome Enterprise Baseline',
    description: 'Assign a tenant Chrome hardening policy for secure browser settings.',
    category: 'browser',
    keywords: ['chrome', 'browser', 'google chrome', 'webrtc'],
    findingTypes: ['application'],
  },
  {
    id: 'windows-update-ring',
    name: 'Windows Update expedited deployment',
    targetRef: 'Windows Update Ring - Security',
    description: 'Assign an Intune update ring / expedite policy to the target group.',
    category: 'windows-update',
    keywords: ['windows', 'update', 'telephony', 'kernel', 'rpc', 'smb'],
    findingTypes: ['windows-update'],
  },
  {
    id: 'defender-antivirus-hardening',
    name: 'Microsoft Defender Antivirus hardening',
    targetRef: 'Defender Antivirus Hardening',
    description: 'Assign a Defender AV policy with stronger protection and signature settings.',
    category: 'defender',
    keywords: ['defender', 'antivirus', 'malware', 'signature'],
    findingTypes: ['script', 'intune-policy'],
  },
  {
    id: 'attack-surface-reduction',
    name: 'Attack Surface Reduction baseline',
    targetRef: 'ASR Baseline',
    description: 'Assign a tenant ASR rules baseline to reduce exploit surface.',
    category: 'defender',
    keywords: ['asr', 'office', 'script', 'macro', 'exploit'],
    findingTypes: ['intune-policy', 'script'],
  },
  {
    id: 'firewall-hardening',
    name: 'Windows Firewall hardening baseline',
    targetRef: 'Firewall Hardening Baseline',
    description: 'Assign a firewall profile baseline to the target group.',
    category: 'network',
    keywords: ['firewall', 'network', 'adjacent network'],
    findingTypes: ['intune-policy'],
  },
  {
    id: 'smartscreen-browser-protection',
    name: 'SmartScreen & browser protection baseline',
    targetRef: 'SmartScreen Browser Protection',
    description: 'Assign browser protection settings through Intune.',
    category: 'browser',
    keywords: ['browser', 'smartscreen', 'edge', 'chrome', 'web'],
    findingTypes: ['application', 'intune-policy'],
  },
  {
    id: 'bitlocker-device-protection',
    name: 'BitLocker device protection baseline',
    targetRef: 'BitLocker Device Protection',
    description: 'Assign disk protection and recovery key escrow settings.',
    category: 'device-protection',
    keywords: ['bitlocker', 'device protection', 'encryption'],
    findingTypes: ['intune-policy'],
  },
  {
    id: 'windows-laps-baseline',
    name: 'Windows LAPS baseline',
    targetRef: 'Windows LAPS Baseline',
    description: 'Assign a local administrator password solution policy.',
    category: 'identity',
    keywords: ['laps', 'local admin', 'administrator'],
    findingTypes: ['identity', 'intune-policy'],
  },
  {
    id: 'avd-session-host-hardening',
    name: 'AVD session host hardening',
    targetRef: 'AVD Session Host Hardening',
    description: 'Assign hardened settings for Azure Virtual Desktop session hosts.',
    category: 'avd',
    keywords: ['avd', 'session host', 'remote desktop', 'rdp'],
    findingTypes: ['intune-policy'],
  },
];

function normalize(text) {
  return String(text || '').trim().toLowerCase();
}

function scorePolicyTemplate(template, finding = {}) {
  const haystack = [
    finding.displayProductName,
    finding.productName,
    finding.softwareName,
    finding.name,
    finding.description,
    finding.category,
    finding.classification?.type,
    finding.classification?.family,
  ].filter(Boolean).join(' ').toLowerCase();
  let score = 0;
  if ((template.findingTypes || []).includes(finding.classification?.type)) score += 8;
  for (const keyword of template.keywords || []) {
    if (haystack.includes(normalize(keyword))) score += 3;
  }
  return score;
}

function getRecommendedPolicyTemplates(finding = {}) {
  return BUILT_IN_POLICY_TEMPLATES
    .map((item) => ({ ...item, score: scorePolicyTemplate(item, finding) }))
    .filter((item) => item.score > 0)
    .sort((a, b) => b.score - a.score)
    .slice(0, 4);
}

module.exports = {
  BUILT_IN_POLICY_TEMPLATES,
  getRecommendedPolicyTemplates,
};
