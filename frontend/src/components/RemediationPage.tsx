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

function mapRebootBehavior(value: string) {
  if (value === 'force') return 'force-reboot';
  if (value === 'defer') return 'defer-reboot';
  return 'reboot-if-required';
}

function getStatusBadgeStyle(code?: string) {
  if (code === 'live-deploy' || code === 'native-queued') return { background: 'rgba(34,197,94,0.15)', border: '1px solid rgba(34,197,94,0.45)', color: '#86efac' };
  if (code === 'bundle-created') return { background: 'rgba(59,130,246,0.15)', border: '1px solid rgba(59,130,246,0.45)', color: '#93c5fd' };
  if (code === 'external-not-connected') return { background: 'rgba(239,68,68,0.15)', border: '1px solid rgba(239,68,68,0.45)', color: '#fca5a5' };
  return { background: 'rgba(245,158,11,0.15)', border: '1px solid rgba(245,158,11,0.45)', color: '#fcd34d' };
}

function getBundleInfo(execResult: any) {
  const result = execResult?.result || execResult || {};
  const delivery = result?.delivery || {};
  return delivery?.bundle || result?.bundle || null;
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
  const [updateType, setUpdateType] = useState<'security' | 'feature'>('security');
  const [rebootBehavior, setRebootBehavior] = useState<'ifRequired' | 'force' | 'defer'>('ifRequired');
  const [targetDeviceIds, setTargetDeviceIds] = useState('');

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
  const classificationType = planResult?.classification?.type || '';
  const planStatus = planResult?.plan?.statusCard || null;
  const executionPath = planResult?.plan?.executionPath || null;
  const bundleInfo = getBundleInfo(execResult);

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
      const result = await api.planRemediation({
        tenantId,
        finding: selectedFinding,
        options: {
          updateType,
          rebootBehavior,
          targetDeviceIds: targetDeviceIds.split(/[\n,;]+/).map((x) => x.trim()).filter(Boolean)
        }
      });
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
        options: {
          updateType,
          rebootBehavior,
          targetDeviceIds: targetDeviceIds.split(/[\n,;]+/).map((x) => x.trim()).filter(Boolean)
        }
      });
      setExecResult(result);
    } catch (err: any) {
      setError(err?.message || 'Execution failed.');
      setTechnicalError(err?.details ? JSON.stringify(err.details, null, 2) : '');
    } finally {
      setExecuting(false);
    }
  }

  function handleDownloadBundle() {
    const bundle = bundleInfo;
    if (!bundle) return;

    if (bundle.downloadUrl) {
      window.open(bundle.downloadUrl, '_blank', 'noopener,noreferrer');
      return;
    }

    if (bundle.base64) {
      const mimeType = bundle.mimeType || 'application/zip';
      const fileName = bundle.fileName || 'remediation-bundle.zip';
      const binary = atob(bundle.base64);
      const bytes = new Uint8Array(binary.length);
      for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
      const blob = new Blob([bytes], { type: mimeType });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = fileName;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
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
        <div className="panel-header"><div><h2>Plan Details</h2><p>See exactly which executor will run, and what path will be used.</p></div></div>
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

          {classificationType === 'windows-update' ? (
            <div className="detail-card">
              <div className="label">Windows Update options</div>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, minmax(0, 1fr))', gap: 10, marginTop: 10 }}>
                <div>
                  <div className="label">Update now</div>
                  <div className="muted">This native executor creates a WUfB deployment immediately after planning and execution.</div>
                </div>
                <div>
                  <div className="label">Update type</div>
                  <select value={updateType} onChange={(e) => setUpdateType(e.target.value as 'security' | 'feature')}>
                    <option value="security">Security</option>
                    <option value="feature">Feature</option>
                  </select>
                </div>
                <div>
                  <div className="label">Reboot behavior</div>
                  <select value={rebootBehavior} onChange={(e) => setRebootBehavior(e.target.value as 'ifRequired' | 'force' | 'defer')}>
                    <option value="ifRequired">Reboot if required</option>
                    <option value="force">Force reboot</option>
                    <option value="defer">Defer reboot</option>
                  </select>
                </div>
                <div>
                  <div className="label">Target device IDs</div>
                  <textarea value={targetDeviceIds} onChange={(e) => setTargetDeviceIds(e.target.value)} rows={5} placeholder="Paste Microsoft Entra device IDs, one per line or comma-separated" />
                </div>
              </div>
            </div>
          ) : null}

          {planResult ? (
            <div className="detail-card">
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 12, flexWrap: 'wrap' }}>
                <div>
                  <div className="label">Executor</div>
                  <div className="value">{planResult.plan?.executor || 'n/a'}</div>
                </div>
                {planStatus ? (
                  <span style={{ ...getStatusBadgeStyle(planStatus.code), borderRadius: 999, padding: '6px 10px', fontSize: 12, fontWeight: 700, textTransform: 'uppercase', letterSpacing: 0.3 }}>{planStatus.label}</span>
                ) : null}
              </div>
              <div className="label" style={{ marginTop: 12 }}>Execution mode</div>
              <div className="value">{planResult.plan?.executionMode || 'n/a'}</div>
              {executionPath ? (
                <>
                  <div className="label" style={{ marginTop: 12 }}>Execution path</div>
                  <div className="value">{executionPath.route}</div>
                </>
              ) : null}
              {planStatus?.message ? (
                <>
                  <div className="label" style={{ marginTop: 12 }}>Plan status</div>
                  <div className="value">{planStatus.message}</div>
                </>
              ) : null}
              {planResult?.warning ? (
                <div className="detail-card" style={{ marginTop: 12, borderColor: '#7f1d1d' }}>{planResult.warning}</div>
              ) : null}
              <div className="label" style={{ marginTop: 12 }}>Raw plan</div>
              <pre className="json-box">{JSON.stringify(planResult, null, 2)}</pre>
            </div>
          ) : <div className="detail-card">Run planning to generate a remediation path.</div>}

          <button className="btn btn-secondary" onClick={handleExecute} disabled={executing || !planResult?.plan || needsAdminConsent}>
            {executing ? 'Executing...' : 'Execute Remediation'}
          </button>

          {execResult ? (
            <div className="detail-card">
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 12, flexWrap: 'wrap' }}>
                <div>
                  <div className="label">Execution result</div>
                  <div className="value">{execResult?.result?.message || execResult?.result?.status || 'Completed'}</div>
                </div>
                {execResult?.result?.statusCard ? (
                  <span style={{ ...getStatusBadgeStyle(execResult.result.statusCard.code), borderRadius: 999, padding: '6px 10px', fontSize: 12, fontWeight: 700, textTransform: 'uppercase', letterSpacing: 0.3 }}>{execResult.result.statusCard.label}</span>
                ) : null}
              </div>

              {(execResult?.forwardedTo === 'webapp' || planResult?.plan?.executor === 'webapp') ? (
                <div className="detail-card" style={{ marginTop: 12 }}>
                  <div className="label">External remediation result</div>
                  <div className="value">{execResult?.result?.message || 'Application remediation was handled through the external Webapp service.'}</div>
                  {bundleInfo ? (
                    <div style={{ marginTop: 12 }}>
                      <button className="btn btn-primary" onClick={handleDownloadBundle}>Download remediation bundle</button>
                    </div>
                  ) : null}
                </div>
              ) : null}

              <pre className="json-box">{JSON.stringify(execResult, null, 2)}</pre>
            </div>
          ) : null}
        </div>
      </section>
    </div>
  );
}
