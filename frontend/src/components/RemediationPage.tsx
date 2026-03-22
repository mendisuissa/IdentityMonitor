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
  status?: string | null;
};

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

function isRemediationRequired(finding: Finding) {
  return String(finding.status || '').toLowerCase() === 'remediationrequired';
}

function hasExposedDevices(finding: Finding) {
  return Number(finding.affectedMachineCount || 0) > 0;
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
  const [showRemediationRequiredOnly, setShowRemediationRequiredOnly] = useState(true);
  const [showExposedDevicesOnly, setShowExposedDevicesOnly] = useState(true);
  const [machinesLoading, setMachinesLoading] = useState(false);
  const [affectedMachines, setAffectedMachines] = useState<string[]>([]);
  const [affectedMachinesError, setAffectedMachinesError] = useState('');

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

  const remediationRequiredCount = useMemo(() => findings.filter(isRemediationRequired).length, [findings]);
  const exposedDevicesCount = useMemo(() => findings.filter(hasExposedDevices).length, [findings]);

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
      if (showRemediationRequiredOnly && !isRemediationRequired(f)) return false;
      if (showExposedDevicesOnly && !hasExposedDevices(f)) return false;
      return true;
    });
  }, [findings, search, filterCve, filterProduct, filterPublisher, filterCategory, filterSeverity, showRemediationRequiredOnly, showExposedDevicesOnly]);

  useEffect(() => {
    setSelectedIndex(0);
  }, [search, filterCve, filterProduct, filterPublisher, filterCategory, filterSeverity, showRemediationRequiredOnly, showExposedDevicesOnly]);

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
      const result = await api.planRemediation({ tenantId, finding: selectedFinding });
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
        devices: [],
        finding: selectedFinding,
        plan: planResult.plan
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
    setShowRemediationRequiredOnly(true);
    setShowExposedDevicesOnly(true);
  };

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

        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 10, marginBottom: 14 }}>
          <button className={`btn ${showRemediationRequiredOnly ? 'btn-primary' : 'btn-secondary'}`} onClick={() => setShowRemediationRequiredOnly((v) => !v)} type="button">
            {showRemediationRequiredOnly ? '✓ ' : ''}Remediation required only ({remediationRequiredCount})
          </button>
          <button className={`btn ${showExposedDevicesOnly ? 'btn-primary' : 'btn-secondary'}`} onClick={() => setShowExposedDevicesOnly((v) => !v)} type="button">
            {showExposedDevicesOnly ? '✓ ' : ''}Exposed devices only ({exposedDevicesCount})
          </button>
          <div className="text-muted" style={{ fontSize: 12, alignSelf: 'center' }}>
            Showing {filteredFindings.length} of {findings.length} findings
          </div>
        </div>

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
          <div className="detail-card"><div>No Defender vulnerabilities match the current filters.</div><div style={{ marginTop: 8, opacity: 0.75 }}>Try disabling 'Remediation required only' or 'Exposed devices only'.</div>{error ? <div style={{ marginTop: 10 }}>{error}</div> : null}</div>
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
                    <td><div style={{ display: 'flex', alignItems: 'center', gap: 8 }}><span>{finding.severity || '-'}</span>{isRemediationRequired(finding) ? <span style={{ fontSize: 11, padding: '2px 8px', borderRadius: 999, border: '1px solid #1d4ed8', color: '#93c5fd' }}>Remediation required</span> : null}</div></td>
                    <td style={{ fontWeight: hasExposedDevices(finding) ? 700 : 400, color: hasExposedDevices(finding) ? '#f8fafc' : undefined }}>{finding.affectedMachineCount ?? 0}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      <section className="panel">
        <div className="panel-header"><div><h2>Plan Details</h2><p>See exactly what product is affected and where it exists.</p></div></div>
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

              <div className="label" style={{ marginTop: 12 }}>Defender status</div>
              <div className="value">{selectedFinding.status || 'Unknown'}</div>

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

          {planResult ? (
            <div className="detail-card">
              <div className="label">Executor</div><div className="value">{planResult.plan?.executor || 'n/a'}</div>
              <div className="label" style={{ marginTop: 12 }}>Execution mode</div><div className="value">{planResult.plan?.executionMode || 'n/a'}</div>
              <div className="label" style={{ marginTop: 12 }}>Raw plan</div><pre className="json-box">{JSON.stringify(planResult, null, 2)}</pre>
            </div>
          ) : <div className="detail-card">Run planning to generate a remediation path.</div>}

          <button className="btn btn-secondary" onClick={handleExecute} disabled={executing || !planResult?.plan || needsAdminConsent}>
            {executing ? 'Executing...' : 'Execute Remediation'}
          </button>
          {execResult ? <div className="detail-card"><div className="label">Execution result</div><pre className="json-box">{JSON.stringify(execResult, null, 2)}</pre></div> : null}
        </div>
      </section>
    </div>
  );
}
