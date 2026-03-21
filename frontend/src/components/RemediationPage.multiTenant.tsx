import React, { useEffect, useMemo, useState } from 'react';
import { multiTenantRemediationApiAdditions } from '../services/remediationApi.multiTenant';

type Finding = {
  id?: string;
  cveId?: string;
  productName?: string;
  name?: string;
  softwareName?: string;
  publisher?: string;
  category?: string;
  severity?: string;
  description?: string;
  cvss?: number | null;
};

type Props = {
  tenantId: string;
};

export default function RemediationPageMultiTenant({ tenantId }: Props) {
  const [findings, setFindings] = useState<Finding[]>([]);
  const [selectedIndex, setSelectedIndex] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  useEffect(() => {
    let mounted = true;

    async function load() {
      setLoading(true);
      setError('');

      try {
      const result = await multiTenantRemediationApiAdditions.getDefenderVulnerabilities(tenantId, 50);
        if (!mounted) return;
        setFindings(Array.isArray(result?.items) ? result.items : []);
      } catch (err: any) {
        if (!mounted) return;
        setError(err.message || 'Failed to load Defender vulnerabilities for this tenant.');
        setFindings([]);
      } finally {
        if (mounted) setLoading(false);
      }
    }

    if (tenantId) {
      load();
    }

    return () => {
      mounted = false;
    };
  }, [tenantId]);

  const selectedFinding = useMemo(() => findings[selectedIndex] || null, [findings, selectedIndex]);

  return (
    <div className="page-shell">
      <section className="panel">
        <div className="panel-header">
          <div>
            <h2>Vulnerability Remediation</h2>
            <p>Live Defender vulnerability data for the selected customer tenant.</p>
          </div>
        </div>

        {loading ? <div className="detail-card">Loading customer vulnerabilities...</div> : null}
        {!loading && error ? <div className="detail-card">{error}</div> : null}
        {!loading && !error && findings.length === 0 ? (
          <div className="detail-card">No Defender vulnerabilities were returned for this tenant.</div>
        ) : null}

        {!loading && !error && findings.length > 0 ? (
          <div className="table-wrap">
            <table className="data-table">
              <thead>
                <tr>
                  <th>CVE</th>
                  <th>Product</th>
                  <th>Publisher</th>
                  <th>Category</th>
                  <th>Severity</th>
                </tr>
              </thead>
              <tbody>
                {findings.map((finding, index) => (
                  <tr
                    key={`${finding.cveId || finding.id || 'finding'}-${index}`}
                    className={index === selectedIndex ? 'selected-row' : ''}
                    onClick={() => setSelectedIndex(index)}
                    style={{ cursor: 'pointer' }}
                  >
                    <td>{finding.cveId || finding.id || '-'}</td>
                    <td>{finding.productName || finding.softwareName || finding.name || '-'}</td>
                    <td>{finding.publisher || '-'}</td>
                    <td>{finding.category || '-'}</td>
                    <td>{finding.severity || '-'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : null}
      </section>

      <section className="panel">
        <div className="panel-header">
          <div>
            <h2>Selected Finding</h2>
            <p>Current row details for customer tenant {tenantId}.</p>
          </div>
        </div>

        <div className="stack">
          {selectedFinding ? (
            <div className="detail-card">
              <div className="label">CVE</div>
              <div className="value">{selectedFinding.cveId || selectedFinding.id || '-'}</div>
              <div className="muted">{selectedFinding.productName || selectedFinding.name || '-'}</div>
            </div>
          ) : (
            <div className="detail-card">No finding selected.</div>
          )}
        </div>
      </section>
    </div>
  );
}
