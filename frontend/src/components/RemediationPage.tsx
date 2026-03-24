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
                            <input value={policyTarget} onChange={(e) => setPolicyTarget(e.target.value)} placeholder="Name of the Intune policy or profile to update" />
                          </label>
                        </div>
                      )}

                      {isScriptExecutor && (
                        <div className="plan-form-grid">
                          <label className="span-2">
                            <span>Script / remediation package</span>
                            <input value={scriptName} onChange={(e) => setScriptName(e.target.value)} placeholder="Name of the remediation script or proactive remediation package" />
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
  );
}
