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
  recommendation?: string;
  description?: string;
  cvss?: number | null;
  publishedOn?: string | null;
  updatedOn?: string | null;
  affectedMachineCount?: number;
  affectedMachines?: string[];
  inferenceSource?: string | null;
  status?: string;
  epss?: number | null;
  publicExploit?: boolean;
  exploitVerified?: boolean;
  exploitInKit?: boolean;
};

type DetailTab = 'details' | 'devices' | 'plan';

function getFriendlyErrorMessage(error: any) {
  const raw = error?.message || error?.error || error?.details?.error?.message || '';
  const normalized = String(raw).toLowerCase();
  if (normalized.includes('no tvm license')) return 'Live Defender vulnerability data is not available for this tenant.';
  if (normalized.includes('unauthorized')) return 'The Defender integration is connected, but this tenant is not authorized.';
  if (normalized.includes('failed to fetch')) return 'The app could not reach the Defender integration service.';
  return raw || 'Failed to load Defender vulnerabilities.';
}

function getDisplayProduct(finding: Finding) {
  const value = finding.productName || finding.softwareName || finding.name || '';
  if (!value || /^CVE-/i.test(value) || /^TVM-/i.test(value)) {
    return 'Unknown product';
  }
  return value;
}

function getDisplayPublisher(finding: Finding) {
  return finding.publisher || 'Not provided by Defender payload';
}

function isCveId(value?: string | null) {
  return !!value && /^CVE-/i.test(value);
}

function normalizeProblemLabel(finding: Finding) {
  const product = getDisplayProduct(finding);
  const severity = finding.severity || 'Unknown severity';
  return `${product} exposure • ${severity}`;
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

function getPrimaryRelatedProducts(finding: Finding) {
  const items = Array.isArray(finding.relatedProducts) ? finding.relatedProducts : [];
  return items.slice(0, 6);
}

type Props = { tenantId?: string; tenantName?: string };

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
  const [machinesLoading, setMachinesLoading] = useState(false);
  const [affectedMachines, setAffectedMachines] = useState<string[]>([]);
  const [affectedMachinesError, setAffectedMachinesError] = useState('');
  const [activeTab, setActiveTab] = useState<DetailTab>('details');

  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const consent = params.get('consent');
    const message = params.get('message');
    if (consent === 'granted') {
      setConsentBanner('Organization access approved. Reloading live Defender data for this tenant.');
      params.delete('consent');
      params.delete('message');
      const newUrl = `${window.location.pathname}${params.toString() ? `?${params.toString()}` : ''}`;
      window.history.replaceState({}, '', newUrl);
    } else if (consent === 'error') {
      setConsentBanner(message || 'Admin consent was not completed.');
    }
  }, []);

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
          api.getDefenderVulnerabilities(100)
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
      const category = (f.category || '').toLowerCase();
      const severity = (f.severity || '').toLowerCase();
      const haystack = `${cve} ${product} ${publisher} ${category} ${severity} ${f.description || ''}`.toLowerCase();
      if (search && !haystack.includes(search.toLowerCase())) return false;
      if (filterCve && !cve.includes(filterCve.toLowerCase())) return false;
      if (filterProduct && !product.includes(filterProduct.toLowerCase())) return false;
      if (filterPublisher && !publisher.includes(filterPublisher.toLowerCase())) return false;
      if (filterCategory && !category.includes(filterCategory.toLowerCase())) return false;
      if (filterSeverity && severity !== filterSeverity.toLowerCase()) return false;
      return true;
    });
  }, [findings, search, filterCve, filterProduct, filterPublisher, filterCategory, filterSeverity]);

  useEffect(() => {
    setSelectedIndex(0);
  }, [search, filterCve, filterProduct, filterPublisher, filterCategory, filterSeverity]);

  const selectedFinding = useMemo(() => filteredFindings[selectedIndex] || null, [filteredFindings, selectedIndex]);

  useEffect(() => {
    setPlanResult(null);
    setExecResult(null);
    setActiveTab('details');
  }, [selectedFinding?.id, selectedFinding?.cveId]);

  useEffect(() => {
    let mounted = true;
    async function loadMachines() {
      setAffectedMachines([]);
      setAffectedMachinesError('');
      if (!selectedFinding) return;
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
        const names = items
          .map((x: any) => x.deviceName || x.computerDnsName || x.machineName || x.name)
          .filter(Boolean);
        setAffectedMachines(names);
        if (!names.length) {
          setAffectedMachinesError('No affected device names were returned for this finding.');
        }
      } catch (err: any) {
        if (!mounted) return;
        setAffectedMachinesError(err?.message || 'Affected device drill-down is not available for this finding.');
      } finally {
        if (mounted) setMachinesLoading(false);
      }
    }
    loadMachines();
    return () => { mounted = false; };
  }, [selectedFinding]);

  async function handlePlan() {
    if (!selectedFinding) return;
    setPlanning(true);
    setError('');
    setTechnicalError('');
    setExecResult(null);
    try {
      const result = await api.planRemediation({ tenantId, finding: selectedFinding });
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
    setExecuting(true);
    setError('');
    setTechnicalError('');
    try {
      const result = await api.executeRemediation({
        tenantId,
        approvalId: 'apr-ui-001',
        devices: [],
        finding: selectedFinding,
        plan: planResult.plan
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
  };

  const metrics = useMemo(() => {
    const visible = filteredFindings.length;
    const remediationRequired = filteredFindings.filter((x) => String(x.status || '').toLowerCase() === 'remediationrequired').length;
    const totalDevices = filteredFindings.reduce((sum, x) => sum + (x.affectedMachineCount || 0), 0);
    const exploitable = filteredFindings.filter((x) => x.publicExploit || x.exploitVerified || x.exploitInKit).length;
    return { visible, remediationRequired, totalDevices, exploitable };
  }, [filteredFindings]);

  const planBadge = getPlanBadge(planResult);
  const primaryProducts = selectedFinding ? getPrimaryRelatedProducts(selectedFinding) : [];

  return (
    <div className="remediation-shell">
      <section className="remediation-hero">
        <div>
          <div className="remediation-breadcrumb">Exposure / Vulnerability Remediation</div>
          <h1>Vulnerability remediation</h1>
          <p>Review exposed software, inspect impacted devices, and plan the right remediation path from one Defender-style workspace.</p>
          <div className="remediation-tenant-line">
            Active tenant <strong>{tenantName || tenantId || 'Current connected tenant'}</strong>
            {tenantConfig ? <span>Defender {tenantConfig.defenderEnabled ? 'enabled' : 'disabled'}</span> : null}
          </div>
        </div>
        <div className="remediation-hero-actions">
          <button className="btn btn-primary" onClick={handlePlan} disabled={planning || !selectedFinding || needsAdminConsent}>
            {planning ? 'Planning…' : 'Plan remediation'}
          </button>
          <button className="btn btn-ghost" onClick={handleExecute} disabled={executing || !planResult?.plan || needsAdminConsent}>
            {executing ? 'Executing…' : 'Execute remediation'}
          </button>
        </div>
      </section>

      <section className="remediation-kpi-strip">
        <div className="rem-kpi rem-kpi-blue">
          <span>Visible vulnerabilities</span>
          <strong>{metrics.visible}</strong>
        </div>
        <div className="rem-kpi rem-kpi-red">
          <span>Remediation required</span>
          <strong>{metrics.remediationRequired}</strong>
        </div>
        <div className="rem-kpi rem-kpi-purple">
          <span>Exposed devices</span>
          <strong>{metrics.totalDevices}</strong>
        </div>
        <div className="rem-kpi rem-kpi-amber">
          <span>Exploit signals</span>
          <strong>{metrics.exploitable}</strong>
        </div>
      </section>

      {consentBanner ? <div className="remediation-callout info">{consentBanner}</div> : null}
      {needsAdminConsent ? (
        <div className="remediation-callout info">
          <div className="callout-title">Organization approval required</div>
          <div>An Entra admin from this customer tenant needs to approve Defender application access once before live vulnerabilities can be loaded.</div>
          <div style={{ marginTop: 12 }}><a className="btn btn-primary" href={adminConsentUrl || '/api/auth/admin-consent'}>Approve organization access</a></div>
        </div>
      ) : null}
      {error ? (
        <div className="remediation-callout danger">
          <div>{error}</div>
          {technicalError ? <details style={{ marginTop: 10 }}><summary>Technical details</summary><pre className="json-box">{technicalError}</pre></details> : null}
        </div>
      ) : null}

      <section className="remediation-toolbar-card">
        <div className="remediation-toolbar-top">
          <div className="toolbar-title">Filters</div>
          <button className="btn btn-ghost btn-sm" onClick={clearFilters}>Clear filters</button>
        </div>
        <div className="remediation-toolbar-grid">
          <input className="rem-input" value={search} onChange={(e) => setSearch(e.target.value)} placeholder="Search vulnerabilities" />
          <input className="rem-input" value={filterCve} onChange={(e) => setFilterCve(e.target.value)} placeholder="Filter by CVE" />
          <input className="rem-input" value={filterProduct} onChange={(e) => setFilterProduct(e.target.value)} placeholder="Filter by product" />
          <input className="rem-input" value={filterPublisher} onChange={(e) => setFilterPublisher(e.target.value)} placeholder="Filter by publisher" />
          <input className="rem-input" value={filterCategory} onChange={(e) => setFilterCategory(e.target.value)} placeholder="Filter by category" />
          <select className="rem-input" value={filterSeverity} onChange={(e) => setFilterSeverity(e.target.value)}>
            <option value="">All severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>
        </div>
      </section>

      <div className="remediation-workspace">
        <section className="rem-list-card">
          <div className="rem-list-header">
            <div>
              <div className="toolbar-title">Vulnerabilities</div>
              <div className="toolbar-subtitle">Select an item to open its Defender-style detail blade.</div>
            </div>
            <div className="toolbar-meta">{loadingFindings ? 'Loading…' : `${filteredFindings.length} items`}</div>
          </div>

          {loadingFindings ? <div className="rem-empty-state">Loading Defender vulnerabilities…</div> : filteredFindings.length === 0 ? (
            <div className="rem-empty-state">No Defender vulnerabilities found for this tenant.</div>
          ) : (
            <div className="rem-list-scroll">
              {filteredFindings.map((finding, index) => {
                const isSelected = index === selectedIndex;
                const product = getDisplayProduct(finding);
                const cve = finding.cveId || finding.id || '-';
                return (
                  <button
                    key={`${finding.cveId || finding.id || 'finding'}-${index}`}
                    type="button"
                    className={`rem-list-item ${isSelected ? 'active' : ''}`}
                    onClick={() => { setSelectedIndex(index); setPlanResult(null); setExecResult(null); }}
                  >
                    <div className="rem-list-item-top">
                      <div className="rem-list-cve">{cve}</div>
                      <div className={`severity-badge ${severityClass(finding.severity)}`}>{finding.severity || 'Unknown'}</div>
                    </div>
                    <div className="rem-list-product">{product}</div>
                    <div className="rem-list-meta">
                      <span>{getDisplayPublisher(finding)}</span>
                      <span>{finding.category || 'application'}</span>
                      <span>{finding.affectedMachineCount ?? 0} device{(finding.affectedMachineCount ?? 0) === 1 ? '' : 's'}</span>
                    </div>
                  </button>
                );
              })}
            </div>
          )}
        </section>

        <section className="rem-detail-blade">
          {selectedFinding ? (
            <>
              <div className="rem-blade-header">
                <div>
                  <div className="rem-blade-title">{selectedFinding.cveId || selectedFinding.id || 'Selected vulnerability'}</div>
                  <div className="rem-blade-status-row">
                    <span className={`status-dot ${String(selectedFinding.status || '').toLowerCase() === 'remediationrequired' ? 'critical' : 'low'}`} />
                    <span>{selectedFinding.status === 'RemediationRequired' ? 'Remediation required' : (selectedFinding.status || 'Status unavailable')}</span>
                  </div>
                </div>
                <div className="rem-blade-actions">
                  <button className="btn btn-ghost btn-sm" onClick={() => setActiveTab('details')}>Open details</button>
                  <button className="btn btn-ghost btn-sm" onClick={() => setActiveTab('devices')}>Exposed devices</button>
                  <button className="btn btn-ghost btn-sm" onClick={() => setActiveTab('plan')}>Plan & execute</button>
                </div>
              </div>

              <div className="rem-tabs">
                <button className={`rem-tab ${activeTab === 'details' ? 'active' : ''}`} onClick={() => setActiveTab('details')}>Vulnerability details</button>
                <button className={`rem-tab ${activeTab === 'devices' ? 'active' : ''}`} onClick={() => setActiveTab('devices')}>Exposed devices</button>
                <button className={`rem-tab ${activeTab === 'plan' ? 'active' : ''}`} onClick={() => setActiveTab('plan')}>Remediation plan</button>
              </div>

              <div className="rem-legal-note">The vulnerability data shown here is sourced from your connected Defender tenant and mapped into a remediation workflow.</div>

              {activeTab === 'details' ? (
                <div className="rem-tab-grid">
                  <div className="rem-surface">
                    <div className="rem-section-title">Vulnerability description</div>
                    <div className="rem-ai-label">Generated by AI / Defender metadata</div>
                    <div className="rem-description">{selectedFinding.description || 'No description available.'}</div>

                    <div className="rem-section-title" style={{ marginTop: 24 }}>Threat insights</div>
                    <div className="rem-insights-grid">
                      <div className="rem-insight-box"><span>Public exploit</span><strong>{selectedFinding.publicExploit ? 'Yes' : 'No'}</strong></div>
                      <div className="rem-insight-box"><span>Verified</span><strong>{selectedFinding.exploitVerified ? 'Yes' : 'No'}</strong></div>
                      <div className="rem-insight-box"><span>Exploit kits</span><strong>{selectedFinding.exploitInKit ? 'Yes' : 'No'}</strong></div>
                      <div className="rem-insight-box"><span>EPSS</span><strong>{formatEpss(selectedFinding.epss)}</strong></div>
                    </div>
                  </div>

                  <div className="rem-surface rem-surface-side">
                    <div className="rem-section-title">Vulnerability details</div>
                    <div className="rem-details-list">
                      <div><span>Vulnerability name</span><strong>{selectedFinding.cveId || selectedFinding.id || '-'}</strong></div>
                      <div><span>Affected product</span><strong>{getDisplayProduct(selectedFinding)}</strong></div>
                      <div><span>Publisher</span><strong>{getDisplayPublisher(selectedFinding)}</strong></div>
                      <div><span>Severity</span><strong>{selectedFinding.severity || 'Unknown'}</strong></div>
                      <div><span>CVSS</span><strong>{selectedFinding.cvss ?? 'Not available'}</strong></div>
                      <div><span>Status</span><strong>{selectedFinding.status || 'Unknown'}</strong></div>
                      <div><span>Published on</span><strong>{formatDate(selectedFinding.publishedOn)}</strong></div>
                      <div><span>Updated on</span><strong>{formatDate(selectedFinding.updatedOn)}</strong></div>
                    </div>
                  </div>
                </div>
              ) : null}

              {activeTab === 'devices' ? (
                <div className="rem-surface">
                  <div className="rem-devices-header">
                    <div className="rem-section-title">Exposed devices</div>
                    <div className="toolbar-meta">{getAffectedDeviceCount(selectedFinding, affectedMachines)} item{getAffectedDeviceCount(selectedFinding, affectedMachines) === 1 ? '' : 's'}</div>
                  </div>
                  {machinesLoading ? <div className="rem-empty-state">Loading affected devices…</div> : affectedMachines.length ? (
                    <div className="rem-device-list">
                      {affectedMachines.map((name) => (
                        <div key={name} className="rem-device-row">
                          <strong>{name}</strong>
                          <span>Update available</span>
                        </div>
                      ))}
                    </div>
                  ) : <div className="rem-empty-state">{affectedMachinesError || 'No affected device names were returned for this finding.'}</div>}
                </div>
              ) : null}

              {activeTab === 'plan' ? (
                <div className="rem-plan-stack">
                  <div className="rem-surface">
                    <div className="rem-section-title">Plan details</div>
                    <div className="rem-plan-summary">{normalizeProblemLabel(selectedFinding)}</div>
                    <div className="rem-plan-description">{selectedFinding.recommendation || 'Apply the vendor-provided update or mitigation path for the affected product.'}</div>

                    <div className="rem-details-list" style={{ marginTop: 18 }}>
                      <div><span>Affected product</span><strong>{getDisplayProduct(selectedFinding)}</strong></div>
                      <div><span>Publisher</span><strong>{getDisplayPublisher(selectedFinding)}</strong></div>
                      <div><span>Affected devices</span><strong>{affectedMachines.length ? affectedMachines.join(', ') : (affectedMachinesError || 'Not available')}</strong></div>
                      <div><span>Executor</span><strong>{planResult?.plan?.executor || 'Not planned yet'}</strong></div>
                      <div><span>Execution mode</span><strong>{planResult?.plan?.executionMode || 'Not planned yet'}</strong></div>
                    </div>

                    {primaryProducts.length ? (
                      <>
                        <div className="rem-section-title" style={{ marginTop: 22 }}>Related products</div>
                        <div className="rem-chip-wrap">
                          {primaryProducts.map((item, idx) => (
                            <div key={`${item.productName || 'product'}-${idx}`} className="rem-chip">
                              {item.productName || 'Unknown product'}{item.productVersion ? ` ${item.productVersion}` : ''} · {item.publisher || 'unknown publisher'}
                            </div>
                          ))}
                        </div>
                      </>
                    ) : null}
                  </div>

                  <div className="rem-surface">
                    <div className="rem-plan-header-row">
                      <div className="rem-section-title">Execution path</div>
                      {planBadge ? <div className={`rem-status-pill ${planBadge.tone}`}>{planBadge.label}</div> : null}
                    </div>
                    {planBadge?.message ? <div className="rem-plan-banner">{planBadge.message}</div> : null}
                    <div className="rem-details-list">
                      <div><span>Route</span><strong>{planResult?.plan?.executionPath?.route || 'Plan remediation to calculate route'}</strong></div>
                      <div><span>Classification</span><strong>{planResult?.classification?.type || selectedFinding.category || '-'}</strong></div>
                      <div><span>Family</span><strong>{planResult?.classification?.family || 'software'}</strong></div>
                      <div><span>External state</span><strong>{planResult?.plan?.external?.connected ? 'Connected' : 'Not connected'}</strong></div>
                    </div>

                    <div className="rem-plan-actions">
                      <button className="btn btn-primary" onClick={handlePlan} disabled={planning || needsAdminConsent}>{planning ? 'Planning…' : 'Refresh plan'}</button>
                      <button className="btn btn-ghost" onClick={handleExecute} disabled={executing || !planResult?.plan || needsAdminConsent}>{executing ? 'Executing…' : 'Execute remediation'}</button>
                    </div>

                    <details className="rem-raw-json">
                      <summary>Raw plan</summary>
                      <pre className="json-box">{JSON.stringify(planResult || { message: 'Run planning to generate a remediation path.' }, null, 2)}</pre>
                    </details>

                    {execResult ? (
                      <details className="rem-raw-json" open>
                        <summary>Execution result</summary>
                        <pre className="json-box">{JSON.stringify(execResult, null, 2)}</pre>
                      </details>
                    ) : null}
                  </div>
                </div>
              ) : null}
            </>
          ) : <div className="rem-empty-state">No finding selected.</div>}
        </section>
      </div>
    </div>
  );
}
