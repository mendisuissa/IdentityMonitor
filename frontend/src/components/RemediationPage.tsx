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

export default function RemediationPage({ tenantId, tenantName }: Props) {

  const componentStyles = `
    .remediation-shell{
      color:#e8eefc;
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
      background:linear-gradient(180deg, rgba(12,31,72,.96) 0%, rgba(6,19,50,.96) 100%);
      border:1px solid rgba(88,130,255,.22);
      border-radius:18px;
      box-shadow:0 10px 32px rgba(0,0,0,.28);
    }
    .remediation-hero{
      display:flex;
      justify-content:space-between;
      gap:20px;
      padding:22px 20px;
      align-items:flex-start;
    }
    .remediation-breadcrumb{
      color:#8fb6ff;
      font-size:12px;
      font-weight:700;
      margin-bottom:8px;
    }
    .remediation-hero h1{
      margin:0 0 8px;
      font-size:22px;
      line-height:1.15;
      color:#fff;
    }
    .remediation-hero p{
      margin:0 0 14px;
      color:#bdd2ff;
      max-width:760px;
      line-height:1.55;
    }
    .remediation-tenant-line{
      display:flex;
      flex-wrap:wrap;
      gap:16px;
      color:#a8c0ef;
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
      background:#ffb527;
      color:#111827;
    }
    .btn-secondary{
      background:rgba(22,45,92,.9);
      color:#d7e4ff;
      border:1px solid rgba(109,151,255,.25);
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
      color:#a9c0ef;
      font-size:13px;
    }
    .remediation-stat-card strong{
      font-size:20px;
      color:#fff;
    }
    .remediation-banner{
      padding:16px 18px;
    }
    .remediation-banner.warning{ border-color:rgba(255,183,77,.35); }
    .remediation-banner.success{ border-color:rgba(52,211,153,.35); }
    .remediation-banner.danger{ border-color:rgba(248,113,113,.35); }
    .remediation-banner-actions{ margin-top:12px; }
    .remediation-banner details{ margin-top:10px; }
    .remediation-banner pre,
    .detail-summary-block pre{
      white-space:pre-wrap;
      word-break:break-word;
      max-height:320px;
      overflow:auto;
      background:rgba(2,10,31,.5);
      padding:12px;
      border-radius:12px;
      border:1px solid rgba(109,151,255,.16);
      color:#d5e3ff;
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
      color:#fff;
      font-size:18px;
    }
    .filters-headline p{
      margin:0;
      color:#aac3f2;
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
      color:#e4ecff;
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
      background:#071a45;
      color:#eff5ff;
      border:1px solid rgba(110,153,255,.22);
      border-radius:10px;
      padding:11px 12px;
      outline:none;
    }
    .filters-grid input::placeholder,
    .plan-form-grid input::placeholder,
    .plan-form-grid textarea::placeholder{
      color:#7f9acb;
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
      color:#fff;
    }
    .list-card-header p{
      margin:0;
      color:#a8c0ef;
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
      background:rgba(11,35,82,.82);
      border:1px solid rgba(93,136,242,.22);
      border-radius:16px;
      color:#eff4ff;
      cursor:pointer;
      transition:.18s ease;
    }
    .finding-card:hover{
      border-color:rgba(123,165,255,.45);
      transform:translateY(-1px);
    }
    .finding-card.active{
      border-color:#6ca2ff;
      box-shadow:0 0 0 1px rgba(108,162,255,.24) inset;
      background:rgba(15,45,104,.96);
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
      color:#fff;
    }
    .finding-card-title{
      margin:10px 0 8px;
      font-size:15px;
      line-height:1.3;
      color:#fff;
      font-weight:800;
    }
    .finding-card-meta,
    .finding-card-footer{
      color:#a7c1f0;
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
      background:rgba(251,146,60,.15);
      color:#ffb366;
      border:1px solid rgba(251,146,60,.26);
    }
    .severity-pill.critical{
      background:rgba(244,63,94,.16);
      color:#ff8ca0;
      border:1px solid rgba(244,63,94,.28);
    }
    .severity-pill.medium{
      background:rgba(96,165,250,.15);
      color:#8ec4ff;
      border:1px solid rgba(96,165,250,.24);
    }
    .severity-pill.low,
    .severity-pill.neutral,
    .status-badge.neutral{
      background:rgba(148,163,184,.14);
      color:#d3deef;
      border:1px solid rgba(148,163,184,.22);
    }
    .status-badge.success{
      background:rgba(34,197,94,.15);
      color:#83f0a5;
      border:1px solid rgba(34,197,94,.22);
    }
    .status-badge.danger{
      background:rgba(244,63,94,.16);
      color:#ff91a4;
      border:1px solid rgba(244,63,94,.28);
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
      color:#fff;
    }
    .detail-status-line{
      color:#f4f7ff;
      display:flex;
      align-items:center;
      gap:8px;
      font-size:14px;
    }
    .detail-status-dot{
      width:9px;
      height:9px;
      border-radius:999px;
      background:#f43f5e;
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
      border:1px solid rgba(109,151,255,.22);
      background:rgba(7,26,69,.72);
      color:#d7e4ff;
      padding:8px 12px;
      cursor:pointer;
      font-weight:700;
    }
    .chip-button.active,
    .detail-tab-strip button.active{
      background:rgba(14,49,111,.95);
      border-color:#6ca2ff;
      color:#fff;
    }
    .detail-tab-strip{
      margin-top:14px;
      padding-bottom:12px;
      border-bottom:1px solid rgba(112,147,230,.18);
    }
    .detail-banner{
      margin-top:16px;
      padding:12px 14px;
      border-radius:12px;
      background:rgba(255,255,255,.04);
      color:#dce8ff;
      border:1px solid rgba(109,151,255,.12);
    }
    .detail-banner.slim{ margin-top:0; }
    .detail-banner.subtle-error{
      background:rgba(127,29,29,.2);
      color:#ffd0d0;
      border-color:rgba(248,113,113,.18);
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
      color:#8fb0ea;
      font-size:12px;
    }
    .detail-grid strong{
      color:#fff;
      line-height:1.45;
      word-break:break-word;
    }
    .detail-summary-block{
      margin-top:18px;
      padding:14px;
      border-radius:14px;
      background:rgba(255,255,255,.035);
      border:1px solid rgba(109,151,255,.12);
    }
    .detail-summary-block.compact{ margin-top:16px; }
    .detail-summary-block h4,
    .detail-related-products h4{
      margin:0 0 8px;
      color:#fff;
    }
    .detail-summary-block p,
    .detail-related-products li{
      margin:0;
      color:#dbe8ff;
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
      background:rgba(255,255,255,.035);
      border:1px solid rgba(109,151,255,.12);
      color:#e8efff;
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
    .muted{ color:#8fb0ea; }
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
      color:#fff;
      font-size:17px;
    }
    .plan-header-row p,
    .section-headline span{
      margin:6px 0 0;
      color:#a8c0ef;
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
      color:#a9c0ef;
      border:1px dashed rgba(109,151,255,.18);
      border-radius:14px;
      background:rgba(255,255,255,.025);
      padding:16px;
    }
    .success-block{ border-color:rgba(34,197,94,.22); }
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
  const [executionNotes, setExecutionNotes] = useState('');
  const [cacheInfo, setCacheInfo] = useState<{ cached?: boolean; cacheRefreshedAt?: string | null } | null>(null);

  async function loadFindings(options?: { refresh?: boolean }) {
    setLoadingFindings(true);
    setError('');
    setTechnicalError('');
    setNeedsAdminConsent(false);
    setAdminConsentUrl('');
    try {
      const [config, result] = await Promise.all([
        api.getDefenderTenantConfig(),
        api.getDefenderVulnerabilities(250, { refresh: options?.refresh })
      ]);
      const items = Array.isArray(result?.items) ? result.items : [];
      setTenantConfig(config || null);
      setNeedsAdminConsent(!!config?.needsAdminConsent);
      setAdminConsentUrl(config?.adminConsentUrl || '');
      setFindings(items);
      setCacheInfo({ cached: !!result?.cached, cacheRefreshedAt: result?.cacheRefreshedAt || null });
      setSelectedIndex(0);
    } catch (err: any) {
      setError(getFriendlyErrorMessage(err));
      setTechnicalError(err?.details ? JSON.stringify(err.details, null, 2) : (err?.message || ''));
      setTenantConfig(null);
      setFindings([]);
      setCacheInfo(null);
      setNeedsAdminConsent(!!err?.needsAdminConsent);
      setAdminConsentUrl(err?.adminConsentUrl || '');
    } finally {
      setLoadingFindings(false);
    }
  }

  useEffect(() => {
    let mounted = true;
    (async () => {
      if (!mounted) return;
      await loadFindings();
    })();
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

  useEffect(() => {
    setPlanResult(null);
    setExecResult(null);
    setActiveTab('details');
    setAffectedMachines([]);
    setAffectedMachinesError('');
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

  async function handlePlan() {
    if (!selectedFinding) return;
    setPlanning(true);
    setError('');
    setTechnicalError('');
    setExecResult(null);
    try {
      const result = await api.planRemediation({
        tenantId,
        finding: {
          ...selectedFinding,
          affectedMachines: affectedMachines.length ? affectedMachines : (selectedFinding.affectedMachines || []),
        },
        options: {
          updateType,
          rebootBehavior,
          policyTarget,
          scriptName,
          affectedDeviceNames: affectedMachines,
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
    const resolvedNames = affectedMachines.length ? affectedMachines : (planResult?.plan?.inferredDeviceNames || []);
    if (!deviceIds.length && !resolvedNames.length) {
      setError('Load Exposed devices first or enter Microsoft Entra device IDs manually before running Windows Update.');
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
          scriptName,
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
        <div className="remediation-hero-actions">
          <button className="btn btn-primary" onClick={handlePlan} disabled={planning || !selectedFinding || needsAdminConsent}>
            {planning ? 'Planning…' : 'Plan remediation'}
          </button>
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
            {cacheInfo?.cacheRefreshedAt ? (
              <p style={{ marginTop: 8, opacity: 0.8 }}>
                {cacheInfo.cached ? 'Cached Defender snapshot' : 'Fresh Defender fetch'} • {new Date(cacheInfo.cacheRefreshedAt).toLocaleTimeString()}
              </p>
            ) : null}
          </div>
          <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
            <button className="btn btn-secondary" onClick={() => loadFindings({ refresh: true })} disabled={loadingFindings}>
              {loadingFindings ? 'Refreshing…' : 'Refresh Defender'}
            </button>
            <button className="btn btn-secondary" onClick={clearFilters}>Clear filters</button>
          </div>
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
                        <div className="plan-form-grid">
                          <label className="span-2">
                            <span>Script policy ID or display name</span>
                            <input value={scriptName} onChange={(e) => setScriptName(e.target.value)} placeholder="Device health script policy ID or exact display name" />
                          </label>
                        </div>
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
