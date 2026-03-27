import React, { useEffect, useMemo, useState } from 'react';
import { api } from '../services/api';

type RelatedProduct = {
  productName?: string;
  publisher?: string;
  productVersion?: string;
};

type Finding = {
  id?: string;
  cveId?: string;
  productName?: string;
  productNames?: string[];
  relatedProducts?: RelatedProduct[];
  name?: string;
  softwareName?: string;
  publisher?: string;
  category?: string;
  severity?: string;
  status?: string;
  recommendation?: string;
  description?: string;
  cvss?: number | null;
  publishedOn?: string | null;
  updatedOn?: string | null;
  affectedMachineCount?: number;
  affectedMachines?: string[];
  inferenceSource?: string | null;
  epss?: number | null;
  publicExploit?: boolean;
  exploitVerified?: boolean;
  exploitInKit?: boolean;
  displayProductName?: string;
  displayPublisher?: string;
  displayCategoryLabel?: string;
  classification?: { type?: string; family?: string };
};

type DetailTab = 'details' | 'devices' | 'plan';

type Props = { tenantId?: string; tenantName?: string };

function getFriendlyErrorMessage(error: any) {
  const raw = error?.message || error?.error || error?.details?.error?.message || '';
  const normalized = String(raw).toLowerCase();
  if (normalized.includes('no tvm license')) return 'Live Defender vulnerability data is not available for this tenant.';
  if (normalized.includes('unauthorized')) return 'The Defender integration is connected, but this tenant is not authorized.';
  if (normalized.includes('failed to fetch')) return 'The app could not reach the Defender integration service.';
  return raw || 'Failed to load Defender vulnerabilities.';
}

function getDisplayProduct(finding: Finding) {
  return finding.displayProductName || finding.productName || finding.softwareName || finding.name || 'Unknown product';
}

function getDisplayPublisher(finding: Finding) {
  return finding.displayPublisher || finding.publisher || 'Not provided by Defender payload';
}

function getDisplayCategory(finding: Finding) {
  return finding.displayCategoryLabel || finding.classification?.type || finding.category || 'unknown';
}

function normalizeProblemLabel(finding: Finding) {
  const product = getDisplayProduct(finding);
  const severity = finding.severity || 'Unknown severity';
  return `${product} exposure • ${severity}`;
}

function isCveId(value?: string | null) {
  return !!value && /^CVE-/i.test(value);
}

function severityClass(value?: string | null) {
  const normalized = String(value || '').toLowerCase();
  if (normalized === 'critical') return 'critical';
  if (normalized === 'high') return 'high';
  if (normalized === 'medium') return 'medium';
  if (normalized === 'low') return 'low';
  return 'neutral';
}

function formatDate(value?: string | null) {
  if (!value) return 'Not available';
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return String(value);
  return d.toLocaleString();
}

function formatEpss(value?: number | null) {
  if (value === null || value === undefined) return 'Not available';
  if (value === 0) return '0';
  if (value < 0.01) return value.toFixed(5);
  return value.toFixed(3);
}

function getPlanBadge(planResult: any) {
  const card = planResult?.plan?.statusCard;
  if (!card) return null;
  return {
    label: card.label || card.code || 'status',
    tone: card.tone || 'neutral',
    message: card.message || '',
  };
}

function getAffectedDeviceCount(finding: Finding, affectedMachines: string[]) {
  if (affectedMachines.length) return affectedMachines.length;
  return finding.affectedMachineCount ?? 0;
}

function toCsvLines(input: string) {
  return input.split(/[\n,;]+/).map((s) => s.trim()).filter(Boolean);
}

type BuiltInScriptOption = {
  id: string;
  label: string;
  value: string;
  tags?: string[];
};

const BUILT_IN_SCRIPT_OPTIONS: BuiltInScriptOption[] = [
  { id: 'edge-update', label: 'Update Microsoft Edge', value: 'Update Microsoft Edge', tags: ['edge', 'browser', 'update'] },
  { id: 'chrome-update', label: 'Update Google Chrome', value: 'Update Google Chrome', tags: ['chrome', 'browser', 'update'] },
  { id: 'edge-restart', label: 'Restart Microsoft Edge', value: 'Restart Microsoft Edge', tags: ['edge', 'browser', 'restart'] },
  { id: 'edge-cache', label: 'Clear Edge cache', value: 'Clear Edge cache', tags: ['edge', 'browser', 'cache'] },
  { id: 'wu-reset', label: 'Reset Windows Update components', value: 'Reset Windows Update components', tags: ['windows', 'update', 'wu'] },
  { id: 'wu-scan', label: 'Trigger Windows Update scan', value: 'Trigger Windows Update scan', tags: ['windows', 'update', 'scan'] },
  { id: 'wu-services', label: 'Repair Windows Update services', value: 'Repair Windows Update services', tags: ['windows', 'update', 'services'] },
  { id: 'intune-sync', label: 'Force Intune device sync', value: 'Force Intune device sync', tags: ['intune', 'sync', 'mdm'] },
  { id: 'mdm-repair', label: 'Repair MDM enrollment tasks', value: 'Repair MDM enrollment tasks', tags: ['intune', 'mdm', 'enrollment'] },
  { id: 'teams-cache', label: 'Clear Teams cache', value: 'Clear Teams cache', tags: ['teams', 'cache'] },
  { id: 'office-c2r', label: 'Repair Office Click-to-Run', value: 'Repair Office Click-to-Run', tags: ['office', 'click-to-run'] },
  { id: 'defender-refresh', label: 'Refresh Defender signatures', value: 'Refresh Defender signatures', tags: ['defender', 'signatures'] },
];

function getRecommendedBuiltInScripts(finding: Finding | null) {
  if (!finding) return BUILT_IN_SCRIPT_OPTIONS.slice(0, 4);
  const hay = `${getDisplayProduct(finding)} ${finding.description || ''} ${getDisplayCategory(finding)}`.toLowerCase();
  const hits = BUILT_IN_SCRIPT_OPTIONS.filter((item) =>
    (item.tags || []).some((tag) => hay.includes(tag))
  );
  return hits.length ? hits.slice(0, 4) : BUILT_IN_SCRIPT_OPTIONS.slice(0, 4);
}

export default function RemediationPage({ tenantId, tenantName }: Props) {

  const componentStyles = `
    .remediation-shell{
      color:var(--text-primary);
      display:flex;
      flex-direction:column;
      gap:16px;
    }
    .remediation-shell *{ box-sizing:border-box; }
    .remediation-hero,
    .remediation-banner,
    .remediation-filters,
    .remediation-list-card,
    .remediation-detail-card,
    .remediation-stat-card,
    .card-block{
      background:var(--navy-900);
      border:1px solid var(--navy-border);
      border-radius:18px;
      box-shadow:0 4px 24px rgba(0,0,0,.22);
    }
    .remediation-hero{
      display:flex;
      justify-content:space-between;
      gap:20px;
      padding:22px 20px;
      align-items:flex-start;
    }
    .remediation-breadcrumb{
      color:var(--text-accent);
      font-size:12px;
      font-weight:700;
      margin-bottom:8px;
    }
    .remediation-hero h1{
      margin:0 0 8px;
      font-size:22px;
      line-height:1.15;
      color:var(--text-primary);
    }
    .remediation-hero p{
      margin:0 0 14px;
      color:var(--text-secondary);
      max-width:760px;
      line-height:1.55;
    }
    .remediation-tenant-line{
      display:flex;
      flex-wrap:wrap;
      gap:16px;
      color:var(--text-secondary);
      font-size:13px;
    }
    .remediation-hero-actions{ display:flex; align-items:flex-start; }
    .btn{
      border:none;
      border-radius:12px;
      padding:10px 16px;
      font-weight:700;
      cursor:pointer;
      transition:.18s ease;
    }
    .btn:hover{ transform:translateY(-1px); }
    .btn:disabled{ opacity:.55; cursor:not-allowed; transform:none; }
    .btn-primary{
      background:var(--amber-500);
      color:#111827;
    }
    .btn-secondary{
      background:var(--navy-700);
      color:var(--text-primary);
      border:1px solid var(--navy-border-light);
    }
    .remediation-stats-grid{
      display:grid;
      grid-template-columns:repeat(4,minmax(0,1fr));
      gap:14px;
    }
    .remediation-stat-card{
      padding:16px 18px;
      min-height:84px;
      display:flex;
      flex-direction:column;
      justify-content:space-between;
    }
    .remediation-stat-card span{
      color:var(--text-secondary);
      font-size:13px;
    }
    .remediation-stat-card strong{
      font-size:20px;
      color:var(--text-primary);
    }
    .remediation-banner{
      padding:16px 18px;
    }
    .remediation-banner.warning{ border-color:rgba(245,158,11,.35); }
    .remediation-banner.success{ border-color:rgba(16,185,129,.35); }
    .remediation-banner.danger{ border-color:rgba(239,68,68,.35); }
    .remediation-banner-actions{ margin-top:12px; }
    .remediation-banner details{ margin-top:10px; }
    .remediation-banner pre,
    .detail-summary-block pre{
      white-space:pre-wrap;
      word-break:break-word;
      max-height:320px;
      overflow:auto;
      background:var(--navy-950);
      padding:12px;
      border-radius:12px;
      border:1px solid var(--navy-border);
      color:var(--text-primary);
      font-size:12px;
    }
    .remediation-filters{
      padding:16px;
      display:flex;
      flex-direction:column;
      gap:14px;
    }
    .filters-headline{
      display:flex;
      justify-content:space-between;
      align-items:flex-start;
      gap:16px;
    }
    .filters-headline h3{
      margin:0 0 4px;
      color:var(--text-primary);
      font-size:18px;
    }
    .filters-headline p{
      margin:0;
      color:var(--text-secondary);
    }
    .filters-inline{
      display:flex;
      flex-wrap:wrap;
      gap:16px;
    }
    .filters-inline label{
      display:flex;
      align-items:center;
      gap:8px;
      color:var(--text-primary);
      font-size:14px;
    }
    .filters-grid{
      display:grid;
      grid-template-columns:repeat(3,minmax(0,1fr));
      gap:12px;
    }
    .filters-grid input,
    .filters-grid select,
    .plan-form-grid input,
    .plan-form-grid select,
    .plan-form-grid textarea{
      width:100%;
      background:var(--navy-800);
      color:var(--text-primary);
      border:1px solid var(--navy-border-light);
      border-radius:10px;
      padding:11px 12px;
      outline:none;
    }
    .filters-grid select option,
    .plan-form-grid select option{
      background:var(--navy-900);
      color:var(--text-primary);
    }
    .filters-grid input::placeholder,
    .plan-form-grid input::placeholder,
    .plan-form-grid textarea::placeholder{
      color:var(--text-muted);
    }
    .remediation-layout{
      display:grid;
      grid-template-columns:300px minmax(0,1fr);
      gap:16px;
      align-items:start;
    }
    .remediation-list-card{
      padding:16px;
      position:sticky;
      top:16px;
      min-height:560px;
    }
    .list-card-header h3{
      margin:0 0 6px;
      color:var(--text-primary);
    }
    .list-card-header p{
      margin:0;
      color:var(--text-secondary);
      font-size:13px;
    }
    .finding-list{
      display:flex;
      flex-direction:column;
      gap:12px;
      margin-top:14px;
      max-height:920px;
      overflow:auto;
      padding-right:4px;
    }
    .finding-card{
      width:100%;
      text-align:left;
      padding:14px;
      background:var(--navy-800);
      border:1px solid var(--navy-border);
      border-radius:16px;
      color:var(--text-primary);
      cursor:pointer;
      transition:.18s ease;
    }
    .finding-card:hover{
      border-color:var(--navy-border-light);
      transform:translateY(-1px);
    }
    .finding-card.active{
      border-color:var(--indigo);
      box-shadow:0 0 0 1px var(--indigo-glow) inset;
      background:var(--navy-700);
    }
    .finding-card-topline,
    .finding-card-footer{
      display:flex;
      justify-content:space-between;
      gap:10px;
      align-items:center;
    }
    .finding-card-cve{
      font-size:13px;
      font-weight:700;
      color:var(--text-primary);
    }
    .finding-card-title{
      margin:10px 0 8px;
      font-size:15px;
      line-height:1.3;
      color:var(--text-primary);
      font-weight:800;
    }
    .finding-card-meta,
    .finding-card-footer{
      color:var(--text-secondary);
      font-size:12px;
      line-height:1.45;
    }
    .severity-pill,
    .status-badge{
      display:inline-flex;
      align-items:center;
      justify-content:center;
      min-height:24px;
      padding:4px 9px;
      border-radius:999px;
      font-size:11px;
      font-weight:800;
      text-transform:uppercase;
      letter-spacing:.03em;
    }
    .severity-pill.high,
    .status-badge.warning{
      background:rgba(249,115,22,.15);
      color:#ffb366;
      border:1px solid rgba(249,115,22,.26);
    }
    .severity-pill.critical{
      background:var(--red-glow);
      color:#ff8ca0;
      border:1px solid rgba(239,68,68,.28);
    }
    .severity-pill.medium{
      background:rgba(59,130,246,.15);
      color:#8ec4ff;
      border:1px solid rgba(59,130,246,.24);
    }
    .severity-pill.low,
    .severity-pill.neutral,
    .status-badge.neutral{
      background:rgba(148,163,184,.14);
      color:var(--text-secondary);
      border:1px solid rgba(148,163,184,.22);
    }
    .status-badge.success{
      background:rgba(16,185,129,.15);
      color:#83f0a5;
      border:1px solid rgba(16,185,129,.22);
    }
    .status-badge.danger{
      background:var(--red-glow);
      color:#ff91a4;
      border:1px solid rgba(239,68,68,.28);
    }
    .remediation-detail-card{
      padding:18px;
      min-height:720px;
    }
    .detail-header{
      display:flex;
      justify-content:space-between;
      gap:16px;
      align-items:flex-start;
    }
    .detail-header h2{
      margin:0 0 8px;
      font-size:22px;
      color:var(--text-primary);
    }
    .detail-status-line{
      color:var(--text-primary);
      display:flex;
      align-items:center;
      gap:8px;
      font-size:14px;
    }
    .detail-status-dot{
      width:9px;
      height:9px;
      border-radius:999px;
      background:var(--red-critical);
      display:inline-block;
    }
    .detail-header-actions,
    .detail-tab-strip{
      display:flex;
      gap:8px;
      flex-wrap:wrap;
    }
    .chip-button,
    .detail-tab-strip button{
      border-radius:999px;
      border:1px solid var(--navy-border-light);
      background:var(--navy-800);
      color:var(--text-secondary);
      padding:8px 12px;
      cursor:pointer;
      font-weight:700;
    }
    .chip-button.active,
    .detail-tab-strip button.active{
      background:var(--navy-600);
      border-color:var(--indigo);
      color:var(--text-primary);
    }
    .detail-tab-strip{
      margin-top:14px;
      padding-bottom:12px;
      border-bottom:1px solid var(--navy-border);
    }
    .detail-banner{
      margin-top:16px;
      padding:12px 14px;
      border-radius:12px;
      background:var(--navy-800);
      color:var(--text-primary);
      border:1px solid var(--navy-border);
    }
    .detail-banner.slim{ margin-top:0; }
    .detail-banner.subtle-error{
      background:rgba(127,29,29,.2);
      color:#ffd0d0;
      border-color:rgba(239,68,68,.18);
    }
    .detail-section{ margin-top:16px; }
    .card-block{ padding:18px; }
    .detail-grid{
      display:grid;
      grid-template-columns:repeat(2,minmax(0,1fr));
      gap:16px 20px;
    }
    .detail-grid.compact{ margin-top:14px; }
    .detail-grid > div{
      display:flex;
      flex-direction:column;
      gap:6px;
      min-width:0;
    }
    .detail-grid span,
    .plan-form-grid label span{
      color:var(--text-secondary);
      font-size:12px;
    }
    .detail-grid strong{
      color:var(--text-primary);
      line-height:1.45;
      word-break:break-word;
    }
    .detail-summary-block{
      margin-top:18px;
      padding:14px;
      border-radius:14px;
      background:var(--navy-800);
      border:1px solid var(--navy-border);
    }
    .detail-summary-block.compact{ margin-top:16px; }
    .detail-summary-block h4,
    .detail-related-products h4{
      margin:0 0 8px;
      color:var(--text-primary);
    }
    .detail-summary-block p,
    .detail-related-products li{
      margin:0;
      color:var(--text-primary);
      line-height:1.6;
    }
    .detail-related-products{
      margin-top:18px;
    }
    .detail-related-grid{
      display:grid;
      grid-template-columns:repeat(2,minmax(0,1fr));
      gap:12px;
    }
    .detail-related-card,
    .device-list-item{
      padding:12px 14px;
      border-radius:12px;
      background:var(--navy-800);
      border:1px solid var(--navy-border);
      color:var(--text-primary);
    }
    .device-list{
      display:flex;
      flex-direction:column;
      gap:10px;
      margin-top:8px;
    }
    .device-list-item{
      display:flex;
      justify-content:space-between;
      gap:12px;
      align-items:center;
    }
    .muted{ color:var(--text-secondary); }
    .plan-header-row,
    .section-headline,
    .section-headline.inline,
    .plan-actions-row{
      display:flex;
      justify-content:space-between;
      gap:12px;
      align-items:flex-start;
    }
    .plan-header-row h3,
    .section-headline h3{
      margin:0;
      color:var(--text-primary);
      font-size:17px;
    }
    .plan-header-row p,
    .section-headline span{
      margin:6px 0 0;
      color:var(--text-secondary);
    }
    .plan-execution-path{ margin-top:18px; }
    .plan-form-grid{
      margin-top:18px;
      display:grid;
      grid-template-columns:repeat(2,minmax(0,1fr));
      gap:14px;
    }
    .plan-form-grid label{
      display:flex;
      flex-direction:column;
      gap:8px;
    }
    .plan-form-grid .span-2{ grid-column:span 2; }
    .plan-actions-row{ margin-top:18px; }
    .finding-empty{
      display:flex;
      align-items:center;
      justify-content:center;
      text-align:center;
      min-height:120px;
      color:var(--text-secondary);
      border:1px dashed var(--navy-border-light);
      border-radius:14px;
      background:var(--navy-800);
      padding:16px;
    }
    .success-block{ border-color:rgba(16,185,129,.22); }
    @media (max-width: 1100px){
      .remediation-layout{ grid-template-columns:1fr; }
      .remediation-list-card{ position:static; min-height:unset; }
      .remediation-stats-grid,
      .filters-grid,
      .detail-grid,
      .detail-related-grid,
      .plan-form-grid{
        grid-template-columns:1fr 1fr;
      }
    }
    @media (max-width: 760px){
      .remediation-hero,
      .filters-headline,
      .detail-header,
      .plan-header-row,
      .section-headline,
      .plan-actions-row{
        flex-direction:column;
      }
      .remediation-stats-grid,
      .filters-grid,
      .detail-grid,
      .detail-related-grid,
      .plan-form-grid{
        grid-template-columns:1fr;
      }
      .plan-form-grid .span-2{ grid-column:span 1; }
      .device-list-item,
      .finding-card-topline,
      .finding-card-footer{
        flex-direction:column;
        align-items:flex-start;
      }
    }
  `;

  const [findings, setFindings] = useState<Finding[]>([]);
  const [selectedIndex, setSelectedIndex] = useState(0);
  const [loadingFindings, setLoadingFindings] = useState(true);
  const [planning, setPlanning] = useState(false);
  const [executing, setExecuting] = useState(false);
  const [planResult, setPlanResult] = useState<any>(null);
  const [execResult, setExecResult] = useState<any>(null);
  const [error, setError] = useState('');
  const [technicalError, setTechnicalError] = useState('');
  const [tenantConfig, setTenantConfig] = useState<any>(null);
  const [needsAdminConsent, setNeedsAdminConsent] = useState(false);
  const [adminConsentUrl, setAdminConsentUrl] = useState('');
  const [consentBanner, setConsentBanner] = useState('');
  const [search, setSearch] = useState('');
  const [filterCve, setFilterCve] = useState('');
  const [filterProduct, setFilterProduct] = useState('');
  const [filterPublisher, setFilterPublisher] = useState('');
  const [filterCategory, setFilterCategory] = useState('');
  const [filterSeverity, setFilterSeverity] = useState('');
  const [remediationRequiredOnly, setRemediationRequiredOnly] = useState(true);
  const [exposedDevicesOnly, setExposedDevicesOnly] = useState(true);
  const [machinesLoading, setMachinesLoading] = useState(false);
  const [affectedMachines, setAffectedMachines] = useState<string[]>([]);
  const [affectedMachinesError, setAffectedMachinesError] = useState('');
  const [activeTab, setActiveTab] = useState<DetailTab>('details');
  const [updateType, setUpdateType] = useState<'security' | 'feature'>('security');
  const [rebootBehavior, setRebootBehavior] = useState<'ifRequired' | 'force' | 'defer'>('ifRequired');
  const [deviceIdsText, setDeviceIdsText] = useState('');
  const [policyTarget, setPolicyTarget] = useState('');
  const [scriptName, setScriptName] = useState('');
  const [scriptMode, setScriptMode] = useState<'recommended' | 'builtin' | 'custom'>('recommended');
  const [selectedBuiltInScript, setSelectedBuiltInScript] = useState('');
  const [executionNotes, setExecutionNotes] = useState('');

  useEffect(() => {
    let mounted = true;
    async function loadFindings() {
      setLoadingFindings(true);
      setError('');
      setTechnicalError('');
      setNeedsAdminConsent(false);
      setAdminConsentUrl('');
      try {
        const [config, result] = await Promise.all([
          api.getDefenderTenantConfig(),
          api.getDefenderVulnerabilities(250)
        ]);
        if (!mounted) return;
        const items = Array.isArray(result?.items) ? result.items : [];
        setTenantConfig(config || null);
        setNeedsAdminConsent(!!config?.needsAdminConsent);
        setAdminConsentUrl(config?.adminConsentUrl || '');
        setFindings(items);
        setSelectedIndex(0);
      } catch (err: any) {
        if (!mounted) return;
        setError(getFriendlyErrorMessage(err));
        setTechnicalError(err?.details ? JSON.stringify(err.details, null, 2) : (err?.message || ''));
        setTenantConfig(null);
        setFindings([]);
        setNeedsAdminConsent(!!err?.needsAdminConsent);
        setAdminConsentUrl(err?.adminConsentUrl || '');
      } finally {
        if (mounted) setLoadingFindings(false);
      }
    }
    loadFindings();
    return () => { mounted = false; };
  }, [tenantId]);

  const filteredFindings = useMemo(() => {
    return findings.filter((f) => {
      const cve = (f.cveId || f.id || '').toLowerCase();
      const product = getDisplayProduct(f).toLowerCase();
      const publisher = getDisplayPublisher(f).toLowerCase();
      const category = getDisplayCategory(f).toLowerCase();
      const severity = (f.severity || '').toLowerCase();
      const status = (f.status || '').toLowerCase();
      const haystack = `${cve} ${product} ${publisher} ${category} ${severity} ${status} ${f.description || ''}`.toLowerCase();
      if (search && !haystack.includes(search.toLowerCase())) return false;
      if (filterCve && !cve.includes(filterCve.toLowerCase())) return false;
      if (filterProduct && !product.includes(filterProduct.toLowerCase())) return false;
      if (filterPublisher && !publisher.includes(filterPublisher.toLowerCase())) return false;
      if (filterCategory && !category.includes(filterCategory.toLowerCase())) return false;
      if (filterSeverity && severity !== filterSeverity.toLowerCase()) return false;
      if (remediationRequiredOnly && String(f.status || '').toLowerCase() !== 'remediationrequired') return false;
      if (exposedDevicesOnly && (f.affectedMachineCount ?? 0) <= 0) return false;
      return true;
    });
  }, [findings, search, filterCve, filterProduct, filterPublisher, filterCategory, filterSeverity, remediationRequiredOnly, exposedDevicesOnly]);

  useEffect(() => {
    setSelectedIndex(0);
  }, [search, filterCve, filterProduct, filterPublisher, filterCategory, filterSeverity, remediationRequiredOnly, exposedDevicesOnly]);

  const selectedFinding = useMemo(() => filteredFindings[selectedIndex] || null, [filteredFindings, selectedIndex]);
  const selectedExecutor = planResult?.plan?.executor || null;
  const isWindowsExecutor = selectedExecutor === 'native-windows-update';
  const isIntuneExecutor = selectedExecutor === 'native-intune-policy';
  const isScriptExecutor = selectedExecutor === 'native-script';
  const planBadge = getPlanBadge(planResult);
  const primaryProducts = Array.isArray(selectedFinding?.relatedProducts) ? selectedFinding!.relatedProducts!.slice(0, 6) : [];
  const recommendedBuiltInScripts = useMemo(() => getRecommendedBuiltInScripts(selectedFinding), [selectedFinding]);

  useEffect(() => {
    setPlanResult(null);
    setExecResult(null);
    setActiveTab('details');
    setAffectedMachines([]);
    setAffectedMachinesError('');
    setScriptMode('recommended');
    setSelectedBuiltInScript('');
    setScriptName('');
  }, [selectedFinding?.id, selectedFinding?.cveId]);

  useEffect(() => {
    let mounted = true;
    async function loadMachines() {
      setAffectedMachines([]);
      setAffectedMachinesError('');
      if (!selectedFinding || activeTab !== 'devices') return;
      const cve = selectedFinding.cveId || selectedFinding.id || '';
      if (!isCveId(cve)) {
        setAffectedMachinesError('Device drill-down is available only for CVE findings.');
        return;
      }
      setMachinesLoading(true);
      try {
        const result = await api.getDefenderVulnerabilityMachines(cve, 100);
        if (!mounted) return;
        const items = Array.isArray(result?.items) ? result.items : [];
        const names = items.map((x: any) => x.deviceName || x.computerDnsName || x.machineName || x.name).filter(Boolean);
        setAffectedMachines(names);
        if (!names.length) setAffectedMachinesError('No affected device names were returned for this finding.');
      } catch (err: any) {
        if (!mounted) return;
        setAffectedMachinesError(err?.message || 'Affected device drill-down is not available for this finding.');
      } finally {
        if (mounted) setMachinesLoading(false);
      }
    }
    loadMachines();
    return () => { mounted = false; };
  }, [selectedFinding?.id, selectedFinding?.cveId, activeTab]);

  useEffect(() => {
    if (!planResult?.plan || !selectedFinding) return;
    setPlanResult((current: any) => {
      if (!current?.plan) return current;
      const inferredDeviceNames = affectedMachines.length ? affectedMachines : (current.plan.inferredDeviceNames || []);
      return {
        ...current,
        finding: {
          ...current.finding,
          ...selectedFinding,
          affectedMachines: affectedMachines.length ? affectedMachines : (current.finding?.affectedMachines || selectedFinding.affectedMachines || []),
        },
        plan: {
          ...current.plan,
          targetHint: getDisplayProduct(selectedFinding),
          inferredDeviceNames,
        },
      };
    });
  }, [affectedMachines, selectedFinding]);

  useEffect(() => {
    const lower = String(selectedFinding?.classification?.type || '').toLowerCase();
    const shouldPrefetch = lower === 'script' || lower === 'windows-update';
    if (!selectedFinding || !shouldPrefetch || affectedMachines.length || machinesLoading) return;
    const cve = selectedFinding.cveId || selectedFinding.id || '';
    if (!isCveId(cve)) return;
    let cancelled = false;
    (async () => {
      try {
        setMachinesLoading(true);
        const result = await api.getDefenderVulnerabilityMachines(cve, 100);
        if (cancelled) return;
        const items = Array.isArray(result?.items) ? result.items : [];
        const names = items.map((x: any) => x.deviceName || x.computerDnsName || x.machineName || x.name).filter(Boolean);
        setAffectedMachines(names);
        if (!names.length) setAffectedMachinesError('No affected device names were returned for this finding.');
      } catch (err: any) {
        if (!cancelled) setAffectedMachinesError(err?.message || 'Affected device drill-down is not available for this finding.');
      } finally {
        if (!cancelled) setMachinesLoading(false);
      }
    })();
    return () => { cancelled = true; };
  }, [selectedFinding?.id, selectedFinding?.cveId, selectedFinding?.classification?.type]);

  function getEffectiveScriptName() {
    if (scriptMode === 'custom') return scriptName.trim();
    if (selectedBuiltInScript.trim()) return selectedBuiltInScript.trim();
    return recommendedBuiltInScripts[0]?.value || scriptName.trim();
  }

  async function ensureAffectedMachinesLoaded() {
    if (!selectedFinding) return affectedMachines;
    if (affectedMachines.length) return affectedMachines;
    const cve = selectedFinding.cveId || selectedFinding.id || '';
    if (!isCveId(cve)) return affectedMachines;
    try {
      setMachinesLoading(true);
      const result = await api.getDefenderVulnerabilityMachines(cve, 100);
      const items = Array.isArray(result?.items) ? result.items : [];
      const names = items.map((x: any) => x.deviceName || x.computerDnsName || x.machineName || x.name).filter(Boolean);
      setAffectedMachines(names);
      if (!names.length) setAffectedMachinesError('No affected device names were returned for this finding.');
      return names;
    } catch (err: any) {
      setAffectedMachinesError(err?.message || 'Affected device drill-down is not available for this finding.');
      return [];
    } finally {
      setMachinesLoading(false);
    }
  }

  useEffect(() => {
    if (scriptMode === 'custom') return;
    if (selectedBuiltInScript) return;
    const fallback = (scriptMode === 'recommended' ? recommendedBuiltInScripts[0] : BUILT_IN_SCRIPT_OPTIONS[0])?.value || '';
    if (fallback) setSelectedBuiltInScript(fallback);
  }, [scriptMode, recommendedBuiltInScripts, selectedBuiltInScript]);

  async function handlePlan() {
    if (!selectedFinding) return;
    setPlanning(true);
    setError('');
    setTechnicalError('');
    setExecResult(null);
    try {
      const classificationType = String(selectedFinding.classification?.type || '').toLowerCase();
      const names = (classificationType === 'script' || classificationType === 'windows-update')
        ? await ensureAffectedMachinesLoaded()
        : affectedMachines;
      const result = await api.planRemediation({
        tenantId,
        finding: {
          ...selectedFinding,
          affectedMachines: names.length ? names : (selectedFinding.affectedMachines || []),
        },
        options: {
          updateType,
          rebootBehavior,
          policyTarget,
          scriptName: getEffectiveScriptName(),
          affectedDeviceNames: names,
        },
      });
      setPlanResult(result);
      setActiveTab('plan');
    } catch (err: any) {
      setError(err?.message || 'Planning failed.');
      setTechnicalError(err?.details ? JSON.stringify(err.details, null, 2) : '');
    } finally {
      setPlanning(false);
    }
  }

  async function handleExecute() {
    if (!selectedFinding || !planResult?.plan) return;
    const deviceIds = toCsvLines(deviceIdsText);
    let resolvedNames = affectedMachines.length ? affectedMachines : (planResult?.plan?.inferredDeviceNames || []);
    if (!deviceIds.length && !resolvedNames.length) {
      resolvedNames = await ensureAffectedMachinesLoaded();
    }
    if (!deviceIds.length && !resolvedNames.length) {
      setError('No target devices were resolved yet. Open Exposed devices or enter Microsoft Entra device IDs manually before executing remediation.');
      setTechnicalError('');
      return;
    }
    setExecuting(true);
    setError('');
    setTechnicalError('');
    try {
      const result = await api.executeRemediation({
        tenantId,
        approvalId: 'apr-ui-001',
        devices: deviceIds,
        finding: {
          ...selectedFinding,
          affectedMachines: resolvedNames,
        },
        plan: planResult.plan,
        options: {
          updateType,
          rebootBehavior,
          deviceIds,
          targetDeviceIds: deviceIds,
          affectedDeviceNames: resolvedNames,
          policyTarget,
          scriptName: getEffectiveScriptName(),
          notes: executionNotes,
        },
      });
      setExecResult(result);
      setActiveTab('plan');
    } catch (err: any) {
      setError(err?.message || 'Execution failed.');
      setTechnicalError(err?.details ? JSON.stringify(err.details, null, 2) : '');
    } finally {
      setExecuting(false);
    }
  }

  const clearFilters = () => {
    setSearch('');
    setFilterCve('');
    setFilterProduct('');
    setFilterPublisher('');
    setFilterCategory('');
    setFilterSeverity('');
    setRemediationRequiredOnly(true);
    setExposedDevicesOnly(true);
  };

  const totalFindings = findings.length;
  const shownFindings = filteredFindings.length;
  const exposedCount = findings.filter((f) => (f.affectedMachineCount ?? 0) > 0).length;
  const remediationRequiredCount = findings.filter((f) => String(f.status || '').toLowerCase() === 'remediationrequired').length;
  const highOrCriticalCount = findings.filter((f) => ['high', 'critical'].includes(String(f.severity || '').toLowerCase())).length;

  return (
    <>
      <style>{componentStyles}</style>
      <div className="remediation-shell">
      <section className="remediation-hero">
        <div>
          <div className="remediation-breadcrumb">Defender-informed remediation workspace</div>
          <h1>Vulnerability Remediation</h1>
          <p>Plan and execute remediation paths for software and platform exposure with a product view that is closer to Defender.</p>
          <div className="remediation-tenant-line">
            <div>Active tenant: <strong>{tenantName || tenantId || 'Current connected tenant'}</strong></div>
            {tenantConfig ? <div>Defender: <strong>{tenantConfig.defenderEnabled ? 'Enabled' : 'Disabled'}</strong></div> : null}
            <div>Showing: <strong>{shownFindings} of {totalFindings}</strong></div>
          </div>
        </div>
      </section>

      <section className="remediation-stats-grid">
        <div className="remediation-stat-card"><span>Findings in scope</span><strong>{shownFindings}</strong></div>
        <div className="remediation-stat-card"><span>Remediation required</span><strong>{remediationRequiredCount}</strong></div>
        <div className="remediation-stat-card"><span>Exposed devices</span><strong>{exposedCount}</strong></div>
        <div className="remediation-stat-card"><span>High / Critical</span><strong>{highOrCriticalCount}</strong></div>
      </section>

      {needsAdminConsent && (
        <section className="remediation-banner warning">
          <div>
            <strong>Defender access needs admin consent.</strong>
            <div>This customer tenant must complete Defender admin consent before the app can read live vulnerability data.</div>
          </div>
          <div className="remediation-banner-actions">
            {adminConsentUrl ? <a className="btn btn-primary" href={adminConsentUrl}>Grant Defender admin consent</a> : null}
          </div>
        </section>
      )}

      {!!consentBanner && !needsAdminConsent && (
        <section className="remediation-banner success">
          <div>{consentBanner}</div>
        </section>
      )}

      {error && (
        <section className="remediation-banner danger">
          <div>
            <strong>Unable to load remediation data</strong>
            <div>{error}</div>
            {technicalError ? <details><summary>Technical details</summary><pre>{technicalError}</pre></details> : null}
          </div>
        </section>
      )}

      <section className="remediation-filters">
        <div className="filters-headline">
          <div>
            <h3>Refine the Defender view</h3>
            <p>Keep the fast filters, but stay in the cleaner tabbed layout.</p>
          </div>
          <button className="btn btn-secondary" onClick={clearFilters}>Clear filters</button>
        </div>
        <div className="filters-inline toggles">
          <label><input type="checkbox" checked={remediationRequiredOnly} onChange={(e) => setRemediationRequiredOnly(e.target.checked)} /> Remediation required only</label>
          <label><input type="checkbox" checked={exposedDevicesOnly} onChange={(e) => setExposedDevicesOnly(e.target.checked)} /> Exposed devices only</label>
        </div>
        <div className="filters-grid">
          <input value={search} onChange={(e) => setSearch(e.target.value)} placeholder="Search vulnerabilities" />
          <input value={filterCve} onChange={(e) => setFilterCve(e.target.value)} placeholder="CVE-2026-25188" />
          <input value={filterProduct} onChange={(e) => setFilterProduct(e.target.value)} placeholder="Filter by product" />
          <input value={filterPublisher} onChange={(e) => setFilterPublisher(e.target.value)} placeholder="Filter by publisher" />
          <input value={filterCategory} onChange={(e) => setFilterCategory(e.target.value)} placeholder="Filter by category" />
          <select value={filterSeverity} onChange={(e) => setFilterSeverity(e.target.value)}>
            <option value="">All severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>
        </div>
      </section>

      <section className="remediation-layout">
        <aside className="remediation-list-card">
          <div className="list-card-header">
            <div>
              <h3>Vulnerability list</h3>
              <p>{loadingFindings ? 'Loading findings…' : `${shownFindings} item${shownFindings === 1 ? '' : 's'} currently match your filters`}</p>
            </div>
          </div>
          <div className="finding-list">
            {loadingFindings ? <div className="finding-empty">Loading Defender vulnerability data…</div> : null}
            {!loadingFindings && !filteredFindings.length ? <div className="finding-empty">No vulnerabilities match the current filters.</div> : null}
            {!loadingFindings && filteredFindings.map((finding, index) => {
              const active = index === selectedIndex;
              const count = getAffectedDeviceCount(finding, active ? affectedMachines : []);
              return (
                <button key={finding.id || finding.cveId || index} className={`finding-card ${active ? 'active' : ''}`} onClick={() => setSelectedIndex(index)}>
                  <div className="finding-card-topline">
                    <div className="finding-card-cve">{finding.cveId || finding.id || 'Vulnerability'}</div>
                    <span className={`severity-pill ${severityClass(finding.severity)}`}>{finding.severity || 'Unknown'}</span>
                  </div>
                  <div className="finding-card-title">{getDisplayProduct(finding)}</div>
                  <div className="finding-card-meta">{getDisplayPublisher(finding)} &nbsp; {getDisplayCategory(finding)}</div>
                  <div className="finding-card-footer">
                    <span>{finding.status || 'Unknown status'}</span>
                    <span>{count} exposed device{count === 1 ? '' : 's'}</span>
                  </div>
                </button>
              );
            })}
          </div>
        </aside>

        <article className="remediation-detail-card">
          {!selectedFinding ? <div className="finding-empty">Choose a vulnerability to review details.</div> : (
            <>
              <div className="detail-header">
                <div>
                  <h2>{selectedFinding.cveId || selectedFinding.id || 'Selected vulnerability'}</h2>
                  <div className="detail-status-line"><span className="detail-status-dot" /> {selectedFinding.status || 'Remediation required'}</div>
                </div>
                <div className="detail-header-actions">
                  <button className={`chip-button ${activeTab === 'details' ? 'active' : ''}`} onClick={() => setActiveTab('details')}>Vulnerability details</button>
                  <button className={`chip-button ${activeTab === 'devices' ? 'active' : ''}`} onClick={() => setActiveTab('devices')}>Exposed devices</button>
                  <button className={`chip-button ${activeTab === 'plan' ? 'active' : ''}`} onClick={() => setActiveTab('plan')}>Remediation plan</button>
                </div>
              </div>

              <div className="detail-tab-strip">
                <button className={activeTab === 'details' ? 'active' : ''} onClick={() => setActiveTab('details')}>Vulnerability details</button>
                <button className={activeTab === 'devices' ? 'active' : ''} onClick={() => setActiveTab('devices')}>Exposed devices</button>
                <button className={activeTab === 'plan' ? 'active' : ''} onClick={() => setActiveTab('plan')}>Remediation plan</button>
              </div>

              <div className="detail-banner">The vulnerability data shown here is sourced from your connected Defender tenant and mapped into a remediation workflow.</div>

              {activeTab === 'details' && (
                <section className="detail-section card-block">
                  <div className="detail-grid">
                    <div><span>Vulnerability name</span><strong>{selectedFinding.cveId || selectedFinding.id || 'Not available'}</strong></div>
                    <div><span>Affected product</span><strong>{getDisplayProduct(selectedFinding)}</strong></div>
                    <div><span>Publisher</span><strong>{getDisplayPublisher(selectedFinding)}</strong></div>
                    <div><span>Severity</span><strong>{selectedFinding.severity || 'Not available'}</strong></div>
                    <div><span>CVSS</span><strong>{selectedFinding.cvss ?? 'Not available'}</strong></div>
                    <div><span>Status</span><strong>{selectedFinding.status || 'Not available'}</strong></div>
                    <div><span>Published on</span><strong>{formatDate(selectedFinding.publishedOn)}</strong></div>
                    <div><span>Updated on</span><strong>{formatDate(selectedFinding.updatedOn)}</strong></div>
                    <div><span>Category</span><strong>{getDisplayCategory(selectedFinding)}</strong></div>
                    <div><span>EPSS</span><strong>{formatEpss(selectedFinding.epss)}</strong></div>
                    <div><span>Public exploit</span><strong>{selectedFinding.publicExploit ? 'Yes' : 'No'}</strong></div>
                    <div><span>Exploit verified</span><strong>{selectedFinding.exploitVerified ? 'Yes' : 'No'}</strong></div>
                  </div>
                  <div className="detail-summary-block">
                    <h4>Description</h4>
                    <p>{selectedFinding.description || 'No description was provided by Defender.'}</p>
                  </div>
                  {primaryProducts.length > 0 ? (
                    <div className="detail-related-products">
                      <h4>Related products</h4>
                      <div className="detail-related-grid">
                        {primaryProducts.map((item, idx) => (
                          <div key={`${item.productName || 'product'}-${idx}`} className="detail-related-card">
                            {item.productName || 'Unknown product'}{item.productVersion ? ` ${item.productVersion}` : ''} · {item.publisher || 'unknown publisher'}
                          </div>
                        ))}
                      </div>
                    </div>
                  ) : null}
                </section>
              )}

              {activeTab === 'devices' && (
                <section className="detail-section card-block">
                  <div className="section-headline">
                    <h3>Exposed devices</h3>
                    <span>{getAffectedDeviceCount(selectedFinding, affectedMachines)} item{getAffectedDeviceCount(selectedFinding, affectedMachines) === 1 ? '' : 's'}</span>
                  </div>
                  {machinesLoading ? <div className="finding-empty">Loading affected devices…</div> : null}
                  {!machinesLoading && affectedMachinesError ? <div className="detail-banner subtle-error">{affectedMachinesError}</div> : null}
                  {!machinesLoading && !affectedMachinesError && !affectedMachines.length ? <div className="finding-empty">No affected devices were returned for this vulnerability.</div> : null}
                  {!machinesLoading && !!affectedMachines.length ? (
                    <div className="device-list">
                      {affectedMachines.map((name) => (
                        <div key={name} className="device-list-item">
                          <span>{name}</span>
                          <span className="muted">Update available</span>
                        </div>
                      ))}
                    </div>
                  ) : null}
                  <div style={{ marginTop: 20, display: 'flex', justifyContent: 'flex-end' }}>
                    <button
                      className="btn btn-primary"
                      onClick={() => { handlePlan(); setActiveTab('plan'); }}
                      disabled={planning || needsAdminConsent}
                    >
                      {planning ? 'Planning…' : 'Plan remediation →'}
                    </button>
                  </div>
                </section>
              )}

              {activeTab === 'plan' && (
                <section className="detail-section card-block">
                  <div className="plan-header-row">
                    <div>
                      <h3>Plan details</h3>
                      <p>{normalizeProblemLabel(selectedFinding)}</p>
                    </div>
                    {planBadge ? <span className={`status-badge ${planBadge.tone}`}>{planBadge.label}</span> : null}
                  </div>

                  {planResult?.plan ? (
                    <>
                      <div className="detail-summary-block compact">
                        <p>{planResult.plan.message || 'Review and execute the recommended remediation path for this finding.'}</p>
                      </div>

                      <div className="detail-grid">
                        <div><span>Affected product</span><strong>{getDisplayProduct(selectedFinding)}</strong></div>
                        <div><span>Publisher</span><strong>{getDisplayPublisher(selectedFinding)}</strong></div>
                        <div><span>Affected devices</span><strong>{affectedMachines.length ? affectedMachines.join(', ') : ((planResult.plan.inferredDeviceNames || []).join(', ') || affectedMachinesError || 'Not available')}</strong></div>
                        <div><span>Executor</span><strong>{planResult.plan.executor || 'Not planned yet'}</strong></div>
                        <div><span>Execution mode</span><strong>{planResult.plan.executionMode || 'Not planned yet'}</strong></div>
                      </div>

                      <div className="plan-execution-path">
                        <div className="section-headline inline">
                          <h3>Execution path</h3>
                          {planBadge ? <span className={`status-badge ${planBadge.tone}`}>{planBadge.label}</span> : null}
                        </div>
                        <div className="detail-banner slim">{planBadge?.message || 'Plan remediation to calculate route'}</div>
                        <div className="detail-grid compact">
                          <div><span>Route</span><strong>{planResult.plan.executionPath?.route || 'Plan remediation to calculate route'}</strong></div>
                          <div><span>Classification</span><strong>{planResult.plan.executionPath?.classification || selectedFinding.classification?.type || 'unknown'}</strong></div>
                          <div><span>Family</span><strong>{planResult.plan.executionPath?.family || selectedFinding.classification?.family || 'unknown'}</strong></div>
                          {planResult.plan.executor === 'webapp' ? <div><span>External state</span><strong>{planResult.plan.external?.connected ? 'Connected' : 'Not connected'}</strong></div> : null}
                        </div>
                      </div>

                      {isWindowsExecutor && (
                        <div className="plan-form-grid">
                          <label>
                            <span>Windows Update options</span>
                            <select value={updateType} onChange={(e) => setUpdateType(e.target.value as 'security' | 'feature')}>
                              <option value="security">Security update</option>
                              <option value="feature">Feature update</option>
                            </select>
                          </label>
                          <label>
                            <span>Reboot behavior</span>
                            <select value={rebootBehavior} onChange={(e) => setRebootBehavior(e.target.value as 'ifRequired' | 'force' | 'defer')}>
                              <option value="ifRequired">Reboot if required</option>
                              <option value="force">Force reboot</option>
                              <option value="defer">Defer reboot</option>
                            </select>
                          </label>
                          <label className="span-2">
                            <span>Microsoft Entra device IDs (optional), comma or new line separated</span>
                            <textarea rows={3} value={deviceIdsText} onChange={(e) => setDeviceIdsText(e.target.value)} placeholder="6ca3d4cf-0a77-f70a-1df1-b0fc447442eb" />
                          </label>
                        </div>
                      )}

                      {isIntuneExecutor && (
                        <div className="plan-form-grid">
                          <label className="span-2">
                            <span>Policy target</span>
                            <input value={policyTarget} onChange={(e) => setPolicyTarget(e.target.value)} placeholder="Policy ID or exact policy name | Entra group object ID" />
                          </label>
                        </div>
                      )}

                      {isScriptExecutor && (
                        <>
                          <div className="plan-form-grid">
                            <label>
                              <span>Script source</span>
                              <select value={scriptMode} onChange={(e) => setScriptMode(e.target.value as 'recommended' | 'builtin' | 'custom')}>
                                <option value="recommended">Recommended built-ins</option>
                                <option value="builtin">All built-in remediations</option>
                                <option value="custom">Custom policy ID / display name</option>
                              </select>
                            </label>
                            <label>
                              <span>Resolved target devices</span>
                              <input value={affectedMachines.length ? `${affectedMachines.length} device(s) ready` : (machinesLoading ? 'Resolving devices…' : 'Will resolve from Exposed devices')} readOnly />
                            </label>
                            {scriptMode !== 'custom' ? (
                              <label className="span-2">
                                <span>{scriptMode === 'recommended' ? 'Recommended built-in remediation' : 'Built-in remediation catalog'}</span>
                                <select value={selectedBuiltInScript} onChange={(e) => setSelectedBuiltInScript(e.target.value)}>
                                  {(scriptMode === 'recommended' ? recommendedBuiltInScripts : BUILT_IN_SCRIPT_OPTIONS).map((item) => (
                                    <option key={item.id} value={item.value}>{item.label}</option>
                                  ))}
                                </select>
                              </label>
                            ) : (
                              <label className="span-2">
                                <span>Script policy ID or display name</span>
                                <input value={scriptName} onChange={(e) => setScriptName(e.target.value)} placeholder="Device health script policy ID or exact display name" />
                              </label>
                            )}
                          </div>
                          <div className="detail-summary-block compact">
                            <p>{scriptMode === 'custom' ? 'Enter an existing Intune device health script policy ID or exact display name.' : `The remediation run will use: ${getEffectiveScriptName() || 'Select a remediation script.'}`}</p>
                          </div>
                        </>
                      )}

                      <div className="plan-form-grid">
                        <label className="span-2">
                          <span>Execution notes</span>
                          <textarea rows={3} value={executionNotes} onChange={(e) => setExecutionNotes(e.target.value)} placeholder="Optional notes for the remediation run" />
                        </label>
                      </div>

                      <div className="plan-actions-row">
                        <button className="btn btn-secondary" onClick={handlePlan} disabled={planning}>{planning ? 'Refreshing…' : 'Refresh plan'}</button>
                        <button className="btn btn-primary" onClick={handleExecute} disabled={executing}>{executing ? 'Executing…' : 'Execute remediation'}</button>
                      </div>

                      {Array.isArray(planResult.plan.manualSteps) && planResult.plan.manualSteps.length ? (
                        <div className="detail-related-products">
                          <h4>Operator guidance</h4>
                          <ul>
                            {planResult.plan.manualSteps.map((step: string, idx: number) => <li key={idx}>{step}</li>)}
                          </ul>
                        </div>
                      ) : null}
                    </>
                  ) : (
                    <div className="finding-empty">Plan remediation to calculate the route and execution mode for this finding.</div>
                  )}

                  {execResult ? (
                    <div className="detail-summary-block compact success-block">
                      <h4>Execution result</h4>
                      <pre>{JSON.stringify(execResult, null, 2)}</pre>
                    </div>
                  ) : null}
                </section>
              )}
            </>
          )}
        </article>
      </section>
    </div>
    </>
  );
}
