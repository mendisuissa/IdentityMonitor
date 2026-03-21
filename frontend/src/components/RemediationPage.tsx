import React, { useEffect, useMemo, useState } from 'react';
import { api } from '../services/api';

type Finding = {
  id?: string;
  cveId?: string;
  productName?: string;
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
};

type PlanOptions = {
  updateType: 'security' | 'feature';
  rebootBehavior: 'ifRequired' | 'force' | 'defer';
};

const badgeStyles: Record<string, React.CSSProperties> = {
  'live deploy': { background: '#052e16', color: '#bbf7d0', border: '1px solid #166534' },
  'bundle created': { background: '#172554', color: '#bfdbfe', border: '1px solid #1d4ed8' },
  'manual review required': { background: '#3f2a0d', color: '#fde68a', border: '1px solid #92400e' },
  'external not connected': { background: '#3f0f1a', color: '#fecdd3', border: '1px solid #be123c' },
};

function StatusBadge({ value }: { value?: string | null }) {
  const label = value || 'manual review required';
  return (
    <span style={{
      display: 'inline-flex',
      alignItems: 'center',
      gap: 6,
      padding: '4px 10px',
      borderRadius: 999,
      fontSize: 12,
      fontWeight: 600,
      textTransform: 'uppercase',
      letterSpacing: 0.4,
      ...(badgeStyles[label] || badgeStyles['manual review required'])
    }}>
      {label}
    </span>
  );
}

function getFriendlyErrorMessage(error: any) {
  const raw = error?.message || error?.error || error?.details?.error?.message || '';
  const normalized = String(raw).toLowerCase();
  if (normalized.includes('no tvm license')) return 'Live Defender vulnerability data is not available for this tenant.';
  if (normalized.includes('unauthorized')) return 'The Defender integration is connected, but this tenant is not authorized.';
  if (normalized.includes('failed to fetch')) return 'The app could not reach the Defender integration service.';
  return raw || 'Failed to load Defender vulnerabilities.';
}

function normalizeProblemLabel(finding: Finding) {
  const product = getDisplayProduct(finding);
  const severity = finding.severity || 'Unknown severity';
  return `${product} exposure • ${severity}`;
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

function getDownloadUrl(execResult: any) {
  return execResult?.result?.downloadUrl || execResult?.result?.bundleUrl || execResult?.result?.artifact?.downloadUrl || '';
}

function getExecutionPath(planResult: any, execResult: any) {
  const path = execResult?.result?.executionPath || planResult?.plan?.executionPath || [];
  return Array.isArray(path) ? path : [];
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
  const [planOptions, setPlanOptions] = useState<PlanOptions>({ updateType: 'security', rebootBehavior: 'ifRequired' });

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
      const result = await api.planRemediation({ tenantId, finding: selectedFinding, options: planOptions });
      setPlanResult(result);
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
        devices: affectedMachines,
        finding: selectedFinding,
        plan: planResult.plan,
        options: planOptions,
      });
      setExecResult(result);
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

  const classificationType = planResult?.classification?.type || null;
  const isApplicationPlan = classificationType === 'application';
  const showNativeControls = classificationType && classificationType !== 'application';
  const executionPath = getExecutionPath(planResult, execResult);
  const downloadUrl = getDownloadUrl(execResult);
  const currentStatus = execResult?.result?.status || planResult?.plan?.status || null;

  return (
    <div className="page-shell">
      <section className="panel">
        <div className="panel-header">
          <div>
            <h2>Vulnerability Remediation</h2>
            <p>Plan and execute remediation paths for software and platform exposure.</p>
            <div className="text-muted" style={{ fontSize: 12, marginTop: 8 }}>
              Active tenant: <strong>{tenantName || tenantId || 'Current connected tenant'}</strong>
              {tenantConfig ? ` · Defender ${tenantConfig.defenderEnabled ? 'enabled' : 'disabled'}` : ''}
            </div>
          </div>
          <button className="btn btn-primary" onClick={handlePlan} disabled={planning || !selectedFinding || needsAdminConsent}>
            {planning ? 'Planning...' : 'Plan Remediation'}
          </button>
        </div>

        {consentBanner ? <div className="detail-card" style={{ marginBottom: 16 }}>{consentBanner}</div> : null}
        {needsAdminConsent ? (
          <div className="detail-card" style={{ marginBottom: 16, borderColor: '#1d4ed8' }}>
            <div style={{ fontWeight: 600, marginBottom: 8 }}>Organization approval required</div>
            <div>An Entra admin from this customer tenant needs to approve Defender application access once before live vulnerabilities can be loaded.</div>
            <div style={{ marginTop: 12 }}><a className="btn btn-primary" href={adminConsentUrl || '/api/auth/admin-consent'}>Approve organization access</a></div>
          </div>
        ) : null}

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, minmax(0, 1fr))', gap: 10, marginBottom: 16 }}>
          <input value={search} onChange={(e) => setSearch(e.target.value)} placeholder="Search vulnerabilities" />
          <input value={filterCve} onChange={(e) => setFilterCve(e.target.value)} placeholder="Filter by CVE" />
          <input value={filterProduct} onChange={(e) => setFilterProduct(e.target.value)} placeholder="Filter by Product" />
          <input value={filterPublisher} onChange={(e) => setFilterPublisher(e.target.value)} placeholder="Filter by Publisher" />
          <input value={filterCategory} onChange={(e) => setFilterCategory(e.target.value)} placeholder="Filter by Category" />
          <select value={filterSeverity} onChange={(e) => setFilterSeverity(e.target.value)}>
            <option value="">All severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>
        </div>
        <div style={{ marginBottom: 16 }}><button className="btn btn-secondary" onClick={clearFilters}>Clear filters</button></div>

        {loadingFindings ? <div className="detail-card">Loading Defender vulnerabilities...</div> : filteredFindings.length === 0 ? (
          <div className="detail-card"><div>No Defender vulnerabilities found for this tenant.</div>{error ? <div style={{ marginTop: 10 }}>{error}</div> : null}</div>
        ) : (
          <div className="table-wrap">
            <table className="data-table">
              <thead><tr><th>CVE</th><th>Product</th><th>Publisher</th><th>Category</th><th>Severity</th><th>Affected devices</th></tr></thead>
              <tbody>
                {filteredFindings.map((finding, index) => (
                  <tr key={`${finding.cveId || finding.id || 'finding'}-${index}`} className={index === selectedIndex ? 'selected-row' : ''} onClick={() => { setSelectedIndex(index); setPlanResult(null); setExecResult(null); }} style={{ cursor: 'pointer' }}>
                    <td>{finding.cveId || finding.id || '-'}</td>
                    <td>{getDisplayProduct(finding)}</td>
                    <td>{getDisplayPublisher(finding)}</td>
                    <td>{finding.category || '-'}</td>
                    <td>{finding.severity || '-'}</td>
                    <td>{finding.affectedMachineCount ?? 0}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      <section className="panel">
        <div className="panel-header"><div><h2>Plan Details</h2><p>See exactly what product is affected, which executor will run, and what path will be used.</p></div></div>
        <div className="stack">
          {error ? (
            <div className="detail-card" style={{ borderColor: '#7f1d1d' }}>
              <div>{error}</div>
              {technicalError ? <details style={{ marginTop: 10, opacity: 0.75 }}><summary>Technical details</summary><div style={{ marginTop: 8, whiteSpace: 'pre-wrap', wordBreak: 'break-word' }}>{technicalError}</div></details> : null}
            </div>
          ) : null}

          {selectedFinding ? (
            <div className="detail-card">
              <div className="label">Problem summary</div>
              <div className="value">{normalizeProblemLabel(selectedFinding)}</div>
              <div className="muted">{selectedFinding.description || 'No description available'}</div>

              <div className="label" style={{ marginTop: 12 }}>Affected product</div>
              <div className="value">{getDisplayProduct(selectedFinding)}</div>

              <div className="label" style={{ marginTop: 12 }}>Publisher</div>
              <div className="value">{getDisplayPublisher(selectedFinding)}</div>

              <div className="label" style={{ marginTop: 12 }}>Severity</div>
              <div className="value">{selectedFinding.severity || '-'}</div>

              <div className="label" style={{ marginTop: 12 }}>CVSS</div>
              <div className="value">{selectedFinding.cvss ?? '-'}</div>

              <div className="label" style={{ marginTop: 12 }}>Recommended action</div>
              <div className="value">{selectedFinding.recommendation || 'Apply the vendor-provided update or mitigation path for the affected product.'}</div>

              <div className="label" style={{ marginTop: 12 }}>Affected devices</div>
              {machinesLoading ? <div className="value">Loading affected devices...</div> : affectedMachines.length ? (
                <ul style={{ margin: 0, paddingLeft: 18 }}>
                  {affectedMachines.map((name) => <li key={name}>{name}</li>)}
                </ul>
              ) : <div className="value">{affectedMachinesError || 'No affected device names were returned for this finding.'}</div>}
            </div>
          ) : <div className="detail-card">No finding selected.</div>}

          {showNativeControls ? (
            <div className="detail-card">
              <div className="label">Native execution options</div>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, minmax(0, 1fr))', gap: 12, marginTop: 10 }}>
                <label>
                  <div className="label">Update type</div>
                  <select value={planOptions.updateType} onChange={(e) => setPlanOptions((current) => ({ ...current, updateType: e.target.value as 'security' | 'feature' }))}>
                    <option value="security">Security</option>
                    <option value="feature">Feature</option>
                  </select>
                </label>
                <label>
                  <div className="label">Reboot behavior</div>
                  <select value={planOptions.rebootBehavior} onChange={(e) => setPlanOptions((current) => ({ ...current, rebootBehavior: e.target.value as 'ifRequired' | 'force' | 'defer' }))}>
                    <option value="ifRequired">If required</option>
                    <option value="force">Force reboot</option>
                    <option value="defer">Defer reboot</option>
                  </select>
                </label>
              </div>
              <div className="muted" style={{ marginTop: 10 }}>These controls apply only to native execution paths. Application findings stay on the external Webapp path.</div>
            </div>
          ) : planResult?.classification?.type === 'application' ? (
            <div className="detail-card">
              <div className="label">External application path</div>
              <div className="value">This finding is classified as an application issue and will stay on the Webapp remediation executor. Native update options are intentionally hidden.</div>
            </div>
          ) : null}

          {planResult ? (
            <div className="detail-card">
              <div style={{ display: 'flex', justifyContent: 'space-between', gap: 12, alignItems: 'center', flexWrap: 'wrap' }}>
                <div>
                  <div className="label">Executor</div><div className="value">{planResult.plan?.executor || 'n/a'}</div>
                </div>
                <StatusBadge value={planResult.plan?.status} />
              </div>
              <div className="label" style={{ marginTop: 12 }}>Execution mode</div><div className="value">{planResult.plan?.executionMode || 'n/a'}</div>
              <div className="label" style={{ marginTop: 12 }}>Classification</div><div className="value">{planResult.classification?.type || 'n/a'}</div>
              <div className="label" style={{ marginTop: 12 }}>Execution path</div>
              <div className="value">{(planResult.plan?.executionPath || []).join(' → ') || 'n/a'}</div>
              {planResult.plan?.message ? <><div className="label" style={{ marginTop: 12 }}>Planner message</div><div className="value">{planResult.plan.message}</div></> : null}
              {planResult.plan?.note ? <><div className="label" style={{ marginTop: 12 }}>Planner note</div><div className="value">{planResult.plan.note}</div></> : null}
              {planResult.plan?.checkedSources?.length ? <><div className="label" style={{ marginTop: 12 }}>Checked sources</div><div className="value">{planResult.plan.checkedSources.join(', ')}</div></> : null}
              <div className="label" style={{ marginTop: 12 }}>Raw plan</div><pre className="json-box">{JSON.stringify(planResult, null, 2)}</pre>
            </div>
          ) : <div className="detail-card">Run planning to generate a remediation path.</div>}

          <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
            <button className="btn btn-secondary" onClick={handleExecute} disabled={executing || !planResult?.plan || needsAdminConsent}>
              {executing ? 'Executing...' : (planResult?.classification?.type === 'windows-update' ? 'Update now' : 'Execute Remediation')}
            </button>
            {currentStatus === 'bundle created' && downloadUrl ? (
              <a className="btn btn-primary" href={downloadUrl} target="_blank" rel="noreferrer">Download remediation bundle</a>
            ) : null}
          </div>

          {execResult ? (
            <div className="detail-card">
              <div style={{ display: 'flex', justifyContent: 'space-between', gap: 12, alignItems: 'center', flexWrap: 'wrap' }}>
                <div>
                  <div className="label">External remediation result</div>
                  <div className="value">{execResult.result?.message || execResult.result?.outcome || 'Execution completed.'}</div>
                </div>
                <StatusBadge value={execResult.result?.status} />
              </div>
              <div className="label" style={{ marginTop: 12 }}>Execution path</div>
              <div className="value">{executionPath.join(' → ') || 'n/a'}</div>
              {downloadUrl ? <><div className="label" style={{ marginTop: 12 }}>Bundle</div><div className="value">Bundle artifact is available for download.</div></> : null}
              <div className="label" style={{ marginTop: 12 }}>Raw execution result</div><pre className="json-box">{JSON.stringify(execResult, null, 2)}</pre>
            </div>
          ) : null}
        </div>
      </section>
    </div>
  );
}
