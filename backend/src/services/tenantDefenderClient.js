const { getTenantIntegration } = require('./tenantIntegrationStore');
const { writeTenantSnapshot } = require('./tenantBlobSnapshotStore');

const tokenCache = new Map();
const DEFENDER_SCOPE = 'https://api.securitycenter.microsoft.com/.default';
const DEFENDER_API_BASE = 'https://api.security.microsoft.com';

const vulnerabilityCache = new Map();
const VULNERABILITY_CACHE_TTL_MS = Number(process.env.DEFENDER_VULNERABILITY_CACHE_TTL_MS || 5 * 60 * 1000);
const VULNERABILITY_CACHE_MAX_TOP = Number(process.env.DEFENDER_VULNERABILITY_CACHE_MAX_TOP || 1000);

function getVulnerabilityCacheKey(tenantId) {
  return String(tenantId || '').trim().toLowerCase();
}

function readVulnerabilityCache(tenantId) {
  const key = getVulnerabilityCacheKey(tenantId);
  const entry = vulnerabilityCache.get(key);
  if (!entry) return null;
  if (entry.expiresAt <= Date.now()) return null;
  return entry;
}

function writeVulnerabilityCache(tenantId, items) {
  const key = getVulnerabilityCacheKey(tenantId);
  const normalized = Array.isArray(items) ? items : [];
  vulnerabilityCache.set(key, {
    items: normalized,
    expiresAt: Date.now() + VULNERABILITY_CACHE_TTL_MS,
    refreshedAt: new Date().toISOString(),
  });
  return normalized;
}

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

const DEFENDER_REQUEST_TIMEOUT_MS = Number(process.env.DEFENDER_REQUEST_TIMEOUT_MS || 25000);

function fetchWithTimeout(url, options = {}) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), DEFENDER_REQUEST_TIMEOUT_MS);
  return fetch(url, { ...options, signal: controller.signal })
    .finally(() => clearTimeout(timer));
}

async function defenderGet(config, pathOrUrl) {
  const cacheKey = getCacheKey(config);
  let token = await getAccessToken(config);
  const url = normalizeDefenderUrl(pathOrUrl);

  let response = await fetchWithTimeout(url, {
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

    response = await fetchWithTimeout(url, {
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

  while (nextUrl && page < maxPages) {
    page += 1;
    const data = await defenderGet(config, nextUrl);
    const items = Array.isArray(data?.value) ? data.value : [];
    allItems.push(...items);
    nextUrl = data?.['@odata.nextLink'] || data?.odataNextLink || null;
  }

  return allItems;
}

async function fetchDefenderCollectionWithSkip(config, collectionPath, options = {}) {
  const maxPages = Number(options.maxPages || 50);
  const pageSize = Math.max(1, Math.min(Number(options.pageSize || 200), Number(options.maxPageSize || 8000) || 8000));
  const requestedTop = Number(options.top || 0);

  let page = 0;
  let skip = 0;
  const rows = [];

  while (page < maxPages) {
    page += 1;
    const remaining = requestedTop > 0 ? requestedTop - rows.length : pageSize;
    if (requestedTop > 0 && remaining <= 0) break;

    const currentTop = requestedTop > 0 ? Math.min(pageSize, remaining) : pageSize;
    const separator = collectionPath.includes('?') ? '&' : '?';
    const path = `${collectionPath}${separator}$top=${currentTop}&$skip=${skip}`;
    const data = await defenderGet(config, path);
    const items = Array.isArray(data?.value) ? data.value : [];
    rows.push(...items);

    if (items.length < currentTop) break;
    skip += items.length;
  }

  return rows;
}

function normalizeSeverity(value) {
  return value || 'unknown';
}

function normalizeText(value) {
  if (!value) return null;
  const text = String(value).trim();
  return text || null;
}

// Static knowledge base: canonical product name → WinGet package ID
const PRODUCT_WINGET_MAP = {
  'google chrome': 'Google.Chrome',
  'chrome': 'Google.Chrome',
  'chromium': 'Google.Chrome',
  'mozilla firefox': 'Mozilla.Firefox',
  'firefox': 'Mozilla.Firefox',
  'microsoft edge': 'Microsoft.Edge',
  'edge': 'Microsoft.Edge',
  '7-zip': '7zip.7zip',
  '7zip': '7zip.7zip',
  'vlc': 'VideoLAN.VLC',
  'vlc media player': 'VideoLAN.VLC',
  'zoom': 'Zoom.Zoom',
  'zoom client': 'Zoom.Zoom',
  'microsoft teams': 'Microsoft.Teams',
  'teams': 'Microsoft.Teams',
  'adobe acrobat reader': 'Adobe.Acrobat.Reader.64-bit',
  'acrobat reader': 'Adobe.Acrobat.Reader.64-bit',
  'acrobat': 'Adobe.Acrobat.Reader.64-bit',
  'notepad++': 'Notepad++.Notepad++',
  'winrar': 'RARLab.WinRAR',
  'java': 'Oracle.JavaRuntimeEnvironment',
  'java runtime': 'Oracle.JavaRuntimeEnvironment',
  'jre': 'Oracle.JavaRuntimeEnvironment',
  'python': 'Python.Python.3',
  'node.js': 'OpenJS.NodeJS',
  'nodejs': 'OpenJS.NodeJS',
  'git': 'Git.Git',
  'visual studio code': 'Microsoft.VisualStudioCode',
  'vscode': 'Microsoft.VisualStudioCode',
  'vs code': 'Microsoft.VisualStudioCode',
  'slack': 'SlackTechnologies.Slack',
  'dropbox': 'Dropbox.Dropbox',
  'skype': 'Microsoft.Skype',
  'putty': 'PuTTY.PuTTY',
  'wireshark': 'WiresharkFoundation.Wireshark',
  'opera': 'Opera.Opera',
  'brave': 'Brave.Brave',
  'tor browser': 'TorProject.TorBrowser',
  'signal': 'OpenWhisperSystems.Signal',
  'telegram': 'Telegram.TelegramDesktop',
  'discord': 'Discord.Discord',
  'libreoffice': 'TheDocumentFoundation.LibreOffice',
  'openoffice': 'Apache.OpenOffice',
  'inkscape': 'Inkscape.Inkscape',
  'gimp': 'GIMP.GIMP',
  'obs': 'OBSProject.OBSStudio',
  'obs studio': 'OBSProject.OBSStudio',
  'audacity': 'Audacity.Audacity',
  'handbrake': 'HandBrake.HandBrake',
  'filezilla': 'TimKosse.FileZilla.Client',
  'curl': 'cURL.cURL',
  'openssh': 'Microsoft.OpenSSH.Beta',
  'winscp': 'WinSCP.WinSCP',
  'winpcap': 'WinPcap.WinPcap',
  'npcap': 'Npcap.Npcap',
  'microsoft office': 'Microsoft.Office',
  'office': 'Microsoft.Office',
  'word': 'Microsoft.Office',
  'excel': 'Microsoft.Office',
  'outlook': 'Microsoft.Office',
  'powershell': 'Microsoft.PowerShell',
  'dotnet': 'Microsoft.DotNet.Runtime.8',
  '.net': 'Microsoft.DotNet.Runtime.8',
  'visual c++': 'Microsoft.VCRedist.2015+.x64',
  'vcredist': 'Microsoft.VCRedist.2015+.x64',
  '1password': 'AgileBits.1Password',
  'lastpass': 'LastPass.LastPass',
  'bitwarden': 'Bitwarden.Bitwarden',
  'keepass': 'DominikReichl.KeePass',
  'tresorit': 'Tresorit.Tresorit',
  'malwarebytes': 'Malwarebytes.Malwarebytes',
  'ccleaner': 'Piriform.CCleaner',
  'cpu-z': 'CPUID.CPU-Z',
  'hwinfo': 'REALiX.HWiNFO',
  'speccy': 'Piriform.Speccy',
  'greenshot': 'Greenshot.Greenshot',
  'paint.net': 'dotPDN.PaintDotNet',
  'irfanview': 'IrfanSkiljan.IrfanView',
  'kdenlive': 'KDE.Kdenlive',
  'krita': 'KDE.Krita',
  'blender': 'BlenderFoundation.Blender',
  'unity hub': 'Unity.UnityHub',
  'github desktop': 'GitHub.GitHubDesktop',
  'sourcetree': 'Atlassian.Sourcetree',
  'fork': 'Fork.Fork',
  'postman': 'Postman.Postman',
  'insomnia': 'Insomnia.Insomnia',
  'docker': 'Docker.DockerDesktop',
  'virtualbox': 'Oracle.VirtualBox',
  'vmware workstation': 'VMware.WorkstationPro',
  'vagrant': 'HashiCorp.Vagrant',
  'terraform': 'HashiCorp.Terraform',
  'kubectl': 'Kubernetes.kubectl',
  'helm': 'Helm.Helm',
  'nodejs': 'OpenJS.NodeJS',
  'rust': 'Rustlang.Rust.Msvc',
  'go': 'GoLang.Go',
  'ruby': 'RubyInstallerTeam.Ruby',
  'php': 'PHP.PHP',
  'mysql': 'Oracle.MySQL',
  'postgresql': 'PostgreSQL.PostgreSQL',
  'redis': 'Redis.Redis',
  'mongodb': 'MongoDB.Server',
  'elasticsearch': 'Elastic.Elasticsearch',
  'apache': 'Apache.ApacheHTTPServer',
  'nginx': 'Nginx.Nginx',
  'tomcat': 'Apache.Tomcat',
  'open vpn': 'OpenVPNTechnologies.OpenVPN',
  'openvpn': 'OpenVPNTechnologies.OpenVPN',
};

// Direct product name patterns in CVE text (ordered by specificity)
const CVE_TEXT_PATTERNS = [
  // "in Google Chrome versions prior to"
  /\bin\s+(?:the\s+\w+(?:\s+\w+)?\s+(?:feature|component|module|functionality)\s+of\s+)?([A-Z][A-Za-z0-9 .+#-]{2,40}?)\s+versions?\s+(?:prior|before|earlier|below|up to)/i,
  // "affects Google Chrome before"
  /\baffects?\s+([A-Z][A-Za-z0-9 .+#-]{2,40}?)\s+(?:versions?\s+)?(?:prior|before|earlier|below)/i,
  // "Google Chrome 148.x is vulnerable"
  /\b([A-Z][A-Za-z0-9 .+#-]{2,40}?)\s+\d+[\d.]+\s+is\s+(?:vulnerable|affected)/i,
  // "vulnerability in Google Chrome"
  /\bvulnerability\s+in\s+(?:the\s+)?([A-Z][A-Za-z0-9 .+#-]{2,40?}?)(?:\s+application|\s+browser|\s+client|\s+software|\s+plugin|\s+extension)?(?:\s+versions?)?(?:\.|,|\s+(?:prior|before|earlier|allows?|could|may|when|that|which))/i,
  // "upgrade Google Chrome to"
  /\bupgrade\s+([A-Z][A-Za-z0-9 .+#-]{2,40}?)\s+to/i,
  // "update Google Chrome to the latest"
  /\bupdate\s+([A-Z][A-Za-z0-9 .+#-]{2,40}?)\s+to\s+the\s+latest/i,
  // "patching Google Chrome"
  /\bpatch(?:ing)?\s+([A-Z][A-Za-z0-9 .+#-]{2,40}?)(?:\s+to|\s+via|\.|,)/i,
  // fallback: "exists in X version"
  /\bexists?\s+in\s+([A-Z][A-Za-z0-9 .+#-]{2,40}?)\s+versions?/i,
  // fallback: "apply patches for X"
  /\bapply\s+(?:the\s+)?latest\s+patches?\s+(?:for|to)\s+([A-Z][A-Za-z0-9 .+#-]{2,40?})(?:\s+and|\.|,|$)/i,
];

function guessProductFromText(text) {
  const raw = normalizeText(text);
  if (!raw) return null;

  for (const pattern of CVE_TEXT_PATTERNS) {
    const m = raw.match(pattern);
    if (m && m[1]) {
      const candidate = m[1]
        .replace(/[\[\]()]/g, '')
        .replace(/\s+/g, ' ')
        .trim();
      if (
        candidate.length >= 2 &&
        !candidate.toUpperCase().startsWith('CVE-') &&
        !candidate.toUpperCase().startsWith('TVM-') &&
        !/^(the|a|an|this|that|its|their|remote|local|all|any|multiple)$/i.test(candidate)
      ) {
        return candidate;
      }
    }
  }
  return null;
}

// Resolve a product name (from Defender or guessed) to its canonical WinGet ID.
// Returns { wingetId, canonicalName } or null if unknown.
function resolveProductToWinget(productName, publisher) {
  if (!productName) return null;
  const key = productName.toLowerCase().trim();
  const pubKey = (publisher || '').toLowerCase().trim();

  // Direct lookup
  if (PRODUCT_WINGET_MAP[key]) {
    return { wingetId: PRODUCT_WINGET_MAP[key], canonicalName: productName };
  }

  // Try partial match (product name contains known key)
  for (const [known, wingetId] of Object.entries(PRODUCT_WINGET_MAP)) {
    if (key.includes(known) || known.includes(key)) {
      return { wingetId, canonicalName: productName };
    }
  }

  // Publisher-based hint
  if (pubKey.includes('google') && (key.includes('chrome') || key.includes('chromium'))) {
    return { wingetId: 'Google.Chrome', canonicalName: 'Google Chrome' };
  }
  if (pubKey.includes('mozilla') && key.includes('firefox')) {
    return { wingetId: 'Mozilla.Firefox', canonicalName: 'Mozilla Firefox' };
  }
  if (pubKey.includes('microsoft') && key.includes('edge')) {
    return { wingetId: 'Microsoft.Edge', canonicalName: 'Microsoft Edge' };
  }

  return null;
}

function inferCategory(raw) {
  // ── Step 0: Non-Windows platform → unsupported-platform ──────────────────
  // Detect Linux, macOS, iOS, Android CVEs before any other check.
  // These cannot be remediated via Intune WinGet — flag them explicitly
  // so the UI shows a clear "not supported on this platform" message.
  const _product0 = String(raw?.productName || raw?.name || '').replace(/_/g, ' ').toLowerCase();
  const _publisher0 = String(raw?.vendor || raw?.publisher || '').replace(/_/g, ' ').toLowerCase();

  const LINUX_PUBLISHERS = ['canonical', 'debian', 'red hat', 'redhat', 'suse', 'novell', 'centos', 'fedora project', 'alpine linux'];
  const APPLE_PUBLISHERS = ['apple inc', 'apple'];

  if (LINUX_PUBLISHERS.some((p) => _publisher0.includes(p))) return 'unsupported-platform';
  if (APPLE_PUBLISHERS.some((p) => _publisher0 === p || _publisher0.startsWith(p + ' '))) return 'unsupported-platform';

  const NON_WINDOWS_PRODUCT_PATTERNS = [
    // Linux distros / packages
    /\bubuntu\b/, /\bdebian\b/, /\brhel\b/, /\bcentos\b/, /\bfedora\b/,
    /\balpine linux\b/, /\bopensuse\b/, /\barch linux\b/,
    /\blinux kernel\b/, /\bglibc\b/, /\bmusl\b/,
    // macOS
    /\bmacos\b/, /\bos x\b/, /\bxcode\b/,
    // iOS / iPadOS
    /\bon ios\b/, /\bfor ios\b/, /\bios\b.*\bapp\b/, /\biphone\b/, /\bipad\b/, /\bipados\b/,
    // Android
    /\bandroid\b/,
  ];

  if (NON_WINDOWS_PRODUCT_PATTERNS.some((p) => p.test(_product0))) return 'unsupported-platform';

  // ── Core rule ─────────────────────────────────────────────────────────────
  // 'windows-update' is decided EXCLUSIVELY from the product name + publisher.
  // The description/recommendation is NEVER used for this decision because
  // Defender's AI descriptions often say "Microsoft Edge also ships this fix"
  // for third-party CVEs (Chrome, OpenSSL, etc.), which would cause false
  // windows-update classifications for every such CVE.
  //
  // Only the description/recommendation is used for the secondary categories
  // (script, intune-policy, identity).
  // ─────────────────────────────────────────────────────────────────────────

  const productName = String(raw?.productName || raw?.name || '')
    .replace(/_/g, ' ')  // snake_case → spaces (Defender normalisation)
    .toLowerCase()
    .trim();

  const publisherName = String(raw?.vendor || raw?.publisher || '')
    .replace(/_/g, ' ')
    .toLowerCase()
    .trim();

  // ── 1. Is the publisher clearly NOT Microsoft? → application immediately ──
  // e.g. Google, Mozilla, Canonical, OpenSSL Project, Oracle, Apache…
  const NON_MICROSOFT_PUBLISHERS = [
    'google', 'mozilla', 'canonical', 'ubuntu', 'debian', 'redhat', 'red hat',
    'openssl', 'oracle', 'apache', 'nginx', 'elastic', 'mongodb', 'postgresql',
    'videolan', 'zoom', 'slack', 'discord', 'dropbox', 'signal', 'telegram',
    'bitwarden', 'keepass', 'malwarebytes', 'iobit', 'avast', 'avira', 'kaspersky',
    'notepad++', 'rarlab', 'winrar', '7-zip', 'putty', 'wireshark', 'hashicorp',
    'docker', 'vmware', 'virtualbox', 'jetbrains', 'atlassian', 'github',
    'python', 'nodejs', 'openjs', 'rust', 'golang', 'php',
  ];
  if (NON_MICROSOFT_PUBLISHERS.some((p) => publisherName.includes(p))) {
    return 'application';
  }

  // ── 2. Is the PRODUCT NAME a Microsoft Windows OS / built-in component? ──
  // These always go through Windows Update, not WinGet.
  const WINDOWS_UPDATE_PRODUCT_PATTERNS = [
    /^windows\b/,                        // "Windows 10", "Windows Server 2025", "windows_server_2025"
    /\bwindows (10|11|server|rt)\b/,
    /^microsoft windows\b/,
    /\bdwm core library\b/,              // DWM (Desktop Window Manager)
    /\bwin32k\b/,
    /\bntfs\b/,
    /\bhyper-v\b/,
    /\bremote desktop\b/,
    /\bnet logon\b/,
    /\bkernel\b.*\bwindows\b/,
    /\bwindows\b.*\bkernel\b/,
    /\bcryptographic services\b/,
    /\bwindows defender\b/,
    /\bsecurity support provider\b/,
    /\bprint spooler\b/,
    /\btask scheduler\b/,
    /\bcomponent object model\b/,
    /\bwmi\b/,
    /\bdns server\b.*\bwindows\b/,
    /^microsoft edge\b/,                 // Edge — managed via Windows Update
    /\bmsedge\b/,
    /^microsoft office\b/,
    /^microsoft (word|excel|outlook|powerpoint|access|publisher|onenote|visio|project)\b/,
    /^microsoft \.net\b/,
    /^\.net framework\b/,
    /\bdotnet framework\b/,
    /^visual c\+\+/,
    /\bvcredist\b/,
  ];

  if (WINDOWS_UPDATE_PRODUCT_PATTERNS.some((p) => p.test(productName))) {
    return 'windows-update';
  }

  // Publisher "microsoft" + product sounds like a Windows component (not a third-party app)
  if (publisherName === 'microsoft' || publisherName.startsWith('microsoft ')) {
    // Check for known Microsoft non-Windows products that go via WinGet
    const MICROSOFT_WINGET_PRODUCTS = [
      'visual studio code', 'vscode', 'teams', 'skype', 'powertoys',
      'winget', 'terminal', 'powershell',
    ];
    const isWingetProduct = MICROSOFT_WINGET_PRODUCTS.some((p) => productName.includes(p));
    if (!isWingetProduct && productName) {
      // Generic Microsoft product with no specific override → assume Windows Update
      return 'windows-update';
    }
  }

  // ── 3. Description/recommendation — secondary signals only ───────────────
  // Used for script, intune-policy, identity — NOT for windows-update.
  const descText = [raw?.description, raw?.recommendation, raw?.name]
    .filter(Boolean)
    .join(' ')
    .toLowerCase();

  if (/(intune|configuration profile|compliance policy|endpoint manager|mobile device management)/i.test(descText)) {
    return 'intune-policy';
  }
  if (/(powershell script|remediation script|proactive remediation|device health script)/i.test(descText)) {
    return 'script';
  }
  if (/(identity|credential theft|privilege escalation|entra id|azure ad|active directory|mfa bypass)/i.test(descText)) {
    return 'identity';
  }

  // ── 4. Default → third-party application ─────────────────────────────────
  return 'application';
}

function normalizeVulnerability(raw) {
  const cveId = normalizeText(raw.cveId || raw.id || null);
  // Defender returns snake_case product names (e.g. "windows_server_2025") — convert to display-friendly form
  const rawProductName =
    normalizeText(raw.productName) ||
    guessProductFromText(raw.description) ||
    (cveId && cveId.toUpperCase().startsWith('CVE-') ? null : normalizeText(raw.name));
  const productName = rawProductName ? rawProductName.replace(/_/g, ' ') : rawProductName;
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
    category: inferCategory(raw),
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
  return fetchDefenderCollectionWithSkip(config, '/api/vulnerabilities/machinesVulnerabilities', {
    pageSize: 200,
    maxPageSize: 200,
    maxPages: 25,
  });
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

async function listTenantVulnerabilities(tenantId, top = 0, options = {}) {
  const requestedTop = Number(top) > 0 ? Number(top) : 0;
  const forceRefresh = options?.forceRefresh === true;
  const cacheEntry = !forceRefresh ? readVulnerabilityCache(tenantId) : null;

  if (cacheEntry) {
    const items = requestedTop > 0 ? cacheEntry.items.slice(0, requestedTop) : cacheEntry.items;
    return items;
  }

  const { config } = await getTenantConfigOrThrow(tenantId);
  const fetchTop = requestedTop > 0
    ? Math.max(requestedTop, Math.min(VULNERABILITY_CACHE_MAX_TOP, 250))
    : VULNERABILITY_CACHE_MAX_TOP;

  // Step 1: get CVE IDs + machine counts that actually affect this org's devices
  const machineVulnRows = await fetchDefenderCollectionWithSkip(
    config,
    '/api/vulnerabilities/machinesVulnerabilities',
    { pageSize: 200, maxPageSize: 8000, maxPages: 25, top: fetchTop }
  ).catch(() => []);

  // Build: cveId → { machineCount, productName, publisher }
  const orgCveMap = new Map();
  for (const row of (Array.isArray(machineVulnRows) ? machineVulnRows : [])) {
    const cveId = String(row?.cveId || row?.CveId || '').toUpperCase();
    if (!cveId) continue;
    if (!orgCveMap.has(cveId)) {
      orgCveMap.set(cveId, {
        machineIds: new Set(),
        productName: row.productName || row.softwareName || null,
        publisher: row.softwareVendor || row.softwareVendorId || row.publisher || null,
      });
    }
    const e = orgCveMap.get(cveId);
    if (row.machineId || row.deviceId) e.machineIds.add(row.machineId || row.deviceId);
  }

  // Step 2: fetch full CVE details from /api/vulnerabilities (has CVSS, description, etc.)
  const vulnRows = await fetchDefenderCollectionWithSkip(config, '/api/vulnerabilities', {
    pageSize: 200, maxPageSize: 8000, maxPages: 25, top: fetchTop,
  }).catch(() => []);

  // Step 3: merge — if we got org CVEs, filter global list to only those;
  // inject accurate machine count from machinesVulnerabilities
  let items;
  if (orgCveMap.size > 0 && Array.isArray(vulnRows) && vulnRows.length > 0) {
    items = vulnRows
      .filter(r => {
        const id = String(r?.cveId || r?.id || '').toUpperCase();
        return orgCveMap.has(id);
      })
      .map(r => {
        const id = String(r?.cveId || r?.id || '').toUpperCase();
        const orgData = orgCveMap.get(id) || {};
        return normalizeVulnerability({
          ...r,
          exposedMachines: orgData.machineIds?.size || 1,
          publisher: r.vendor || r.publisher || orgData.publisher || null,
        });
      });

    // Include org CVEs that weren't in /api/vulnerabilities (rare edge case)
    const coveredIds = new Set(items.map(i => i.cveId));
    for (const [cveId, orgData] of orgCveMap) {
      if (!coveredIds.has(cveId)) {
        items.push(normalizeVulnerability({
          cveId,
          id: cveId,
          exposedMachines: orgData.machineIds?.size || 1,
          productName: orgData.productName,
          publisher: orgData.publisher,
        }));
      }
    }
  } else if (orgCveMap.size > 0) {
    // No /api/vulnerabilities data — use machinesVulnerabilities data only
    items = Array.from(orgCveMap.entries()).map(([cveId, d]) =>
      normalizeVulnerability({
        cveId, id: cveId,
        exposedMachines: d.machineIds?.size || 1,
        productName: d.productName,
        publisher: d.publisher,
      })
    );
  } else {
    // machinesVulnerabilities empty — show all global CVEs as fallback
    items = Array.isArray(vulnRows) ? vulnRows.map(normalizeVulnerability) : [];
  }

  writeVulnerabilityCache(tenantId, items);

  await writeTenantSnapshot(tenantId, 'defender/vulnerabilities', {
    count: items.length,
    items,
    refreshedAt: new Date().toISOString(),
  }).catch(() => {});

  return requestedTop > 0 ? items.slice(0, requestedTop) : items;
}

async function listTenantRecommendations(tenantId, top = 0) {
  const { config } = await getTenantConfigOrThrow(tenantId);
  const requestedTop = Number(top) > 0 ? Number(top) : 0;

  const items = await fetchDefenderCollectionWithSkip(config, '/api/recommendations', {
    pageSize: 200,
    maxPageSize: 10000,
    maxPages: 10,
    top: requestedTop,
  });

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

  const rows = await fetchDefenderCollectionWithSkip(
    config,
    `/api/vulnerabilities/${encodeURIComponent(normalized)}/machineReferences`,
    { pageSize: 100, maxPageSize: 200, maxPages: 20, top }
  );

  const items = Array.isArray(rows)
    ? rows.map((row) => ({
        id: row.id || null,
        computerDnsName: row.computerDnsName || row.deviceName || null,
        osPlatform: row.osPlatform || null,
        rbacGroupName: row.rbacGroupName || null,
      }))
    : [];

  return { count: items.length, items };
}

/**
 * Fetch a single CVE directly from Defender by ID.
 * Used when the CVE is not in the cached vulnerability list (e.g. low-exposure CVEs).
 */
async function getTenantVulnerabilityByCveId(tenantId, cveId) {
  const normalized = String(cveId || '').toUpperCase().trim();
  if (!normalized.startsWith('CVE-')) return null;

  // Check cache first
  const cacheEntry = readVulnerabilityCache(tenantId);
  if (cacheEntry) {
    const found = cacheEntry.items.find((item) =>
      String(item.cveId || item.id || '').toUpperCase() === normalized
    );
    if (found) return found;
  }

  // Fetch directly from Defender
  const { config } = await getTenantConfigOrThrow(tenantId);
  const data = await defenderGet(config, `/api/vulnerabilities/${encodeURIComponent(normalized)}`).catch(() => null);
  if (!data) return null;

  return normalizeVulnerability(data);
}

/**
 * Returns a fully-enriched finding for a single CVE:
 * - Full CVE object from Defender (more fields than the list endpoint)
 * - Affected machines from /machineReferences
 * - Software (productName + publisher) from /machinesVulnerabilities filtered by cveId
 * Used by the remediation panel before calling /plan so the webapp gets complete data.
 */
async function enrichTenantVulnerability(tenantId, cveId) {
  const normalized = String(cveId || '').toUpperCase().trim();
  if (!normalized.startsWith('CVE-')) return null;

  const { config } = await getTenantConfigOrThrow(tenantId);

  // 1. Full CVE object
  const rawCve = await defenderGet(config, `/api/vulnerabilities/${encodeURIComponent(normalized)}`).catch(() => null);
  const base = rawCve ? normalizeVulnerability(rawCve) : { cveId: normalized, id: normalized, name: normalized };

  // 2. Machine references (affected devices)
  const machineRows = await fetchDefenderCollectionWithSkip(
    config,
    `/api/vulnerabilities/${encodeURIComponent(normalized)}/machineReferences`,
    { pageSize: 100, maxPageSize: 200, maxPages: 10, top: 200 }
  ).catch(() => []);

  const affectedMachines = Array.isArray(machineRows)
    ? machineRows.map(r => r.computerDnsName || r.deviceName || r.id || 'Unknown').filter(Boolean)
    : [];

  // 3. Software index — fetch machine-vulnerability rows filtered to this CVE
  //    Defender allows $filter on machinesVulnerabilities
  const swRows = await fetchDefenderCollectionWithSkip(
    config,
    `/api/vulnerabilities/machinesVulnerabilities?$filter=cveId+eq+'${encodeURIComponent(normalized)}'`,
    { pageSize: 200, maxPageSize: 200, maxPages: 10 }
  ).catch(() => []);

  const softwareMap = buildSoftwareIndex(swRows);
  const software = softwareMap.get(normalized) || null;

  const productName =
    base.productName ||
    software?.productName ||
    software?.products?.[0]?.productName ||
    guessProductFromText(base.description) ||
    guessProductFromText(base.name) ||
    null;

  const publisher =
    base.publisher ||
    software?.publisher ||
    software?.products?.[0]?.publisher ||
    null;

  const relatedProducts = Array.isArray(software?.products)
    ? software.products.map(p => ({ productName: p.productName, publisher: p.publisher || null, productVersion: p.productVersion || null }))
    : [];

  // Resolve to a known WinGet package ID for accurate automated remediation
  const wingetResolution = resolveProductToWinget(productName, publisher);
  const resolvedProductName = wingetResolution?.canonicalName || productName;
  const suggestedWingetId = wingetResolution?.wingetId || null;

  // Extract fix version from description (e.g. "prior to 148.0.7778.96")
  const fixVersionMatch = (base.description || '').match(
    /(?:prior to|before|earlier than|below|update to|upgrade to)\s+([\d][.\d]+\d)/i
  );
  const fixVersion = fixVersionMatch?.[1] || null;

  return {
    ...base,
    productName: resolvedProductName || productName,
    publisher,
    affectedMachines: affectedMachines.length ? affectedMachines : (software?.affectedMachines?.map(m => m.name) || []),
    affectedMachineCount: affectedMachines.length || software?.affectedMachineCount || base.affectedMachineCount || 0,
    relatedProducts,
    productNames: relatedProducts.map(p => p.productName).filter(Boolean),
    suggestedWingetId,
    fixVersion,
    remediationConfidence: suggestedWingetId ? 'high' : (productName ? 'medium' : 'low'),
  };
}

module.exports = {
  listTenantVulnerabilities,
  listTenantRecommendations,
  listTenantVulnerabilityMachines,
  getTenantVulnerabilityByCveId,
  enrichTenantVulnerability,
  getTenantConfigOrThrow,
  readVulnerabilityCache,
};
