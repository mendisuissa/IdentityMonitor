import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { apiFetch } from '../services/api';

// ─── Types ─────────────────────────────────────────────────────────────────

interface BillingStatus {
  plan: 'trial' | 'pro' | 'msp' | 'expired' | string;
  status: 'trial' | 'active' | 'canceled' | 'expired' | string;
  daysLeft?: number | null;
  renewalDate?: string | null;
  trialEndsAt?: string | null;
}

interface AlertStats {
  total?: number;
  totalOpen?: number;
  open?: number;
}

interface PortalResponse {
  url: string;
}

// ─── Plan feature definitions ──────────────────────────────────────────────

interface PlanFeature {
  text: string;
  pro: boolean;
  msp: boolean;
}

const PLAN_FEATURES: PlanFeature[] = [
  { text: '1 Microsoft 365 tenant', pro: true, msp: false },
  { text: 'Up to 10 Microsoft 365 tenants', pro: false, msp: true },
  { text: 'Real-time anomaly detection', pro: true, msp: true },
  { text: 'Telegram alerts with action buttons', pro: true, msp: true },
  { text: 'Email notifications', pro: true, msp: true },
  { text: 'Conditional Access management', pro: true, msp: true },
  { text: '180-day alert retention', pro: true, msp: true },
  { text: 'Audit Center', pro: true, msp: true },
  { text: 'MSP Fleet Dashboard', pro: false, msp: true },
  { text: 'Cross-tenant security sweep', pro: false, msp: true },
  { text: 'Bulk notifications', pro: false, msp: true },
  { text: 'Priority support', pro: false, msp: true },
  { text: 'Super Admin view', pro: false, msp: true },
];

// ─── Helpers ───────────────────────────────────────────────────────────────

function planLabel(status: BillingStatus): string {
  const p = status.plan?.toLowerCase();
  if (p === 'msp') return 'MSP';
  if (p === 'pro') return 'Pro';
  if (status.status === 'trial') return 'Trial';
  return 'Trial';
}

function planColor(status: BillingStatus): string {
  const p = status.plan?.toLowerCase();
  if (p === 'msp') return '#9B8AFB';
  if (p === 'pro') return '#E8784A';
  return '#F5A623';
}

function isTrial(status: BillingStatus): boolean {
  return status.status === 'trial' || (!status.plan || status.plan === 'trial');
}

function isActive(status: BillingStatus): boolean {
  return status.status === 'active';
}

function featureIncluded(feature: PlanFeature, status: BillingStatus): boolean {
  const p = status.plan?.toLowerCase();
  if (p === 'msp') return feature.msp;
  if (p === 'pro') return feature.pro;
  // trial gets pro features
  return feature.pro;
}

function formatDate(dateStr: string | null | undefined): string {
  if (!dateStr) return '—';
  try {
    return new Date(dateStr).toLocaleDateString(undefined, {
      year: 'numeric',
      month: 'long',
      day: 'numeric',
    });
  } catch {
    return dateStr;
  }
}

// ─── Sub-components ────────────────────────────────────────────────────────

function PlanBadge({ status }: { status: BillingStatus }) {
  const label = planLabel(status);
  const color = planColor(status);
  return (
    <span
      style={{
        display: 'inline-block',
        padding: '4px 14px',
        borderRadius: 99,
        fontSize: 11,
        fontWeight: 700,
        textTransform: 'uppercase',
        letterSpacing: 0.6,
        background: `${color}1F`,
        color,
        border: `1px solid ${color}40`,
      }}
    >
      {label}
    </span>
  );
}

// ─── Main Component ────────────────────────────────────────────────────────

export default function BillingPage() {
  const navigate = useNavigate();

  const [billingStatus, setBillingStatus] = useState<BillingStatus | null>(null);
  const [alertStats, setAlertStats] = useState<AlertStats | null>(null);
  const [loadingStatus, setLoadingStatus] = useState(true);
  const [portalLoading, setPortalLoading] = useState(false);
  const [error, setError] = useState('');

  useEffect(() => {
    let mounted = true;

    const fetchData = async () => {
      setLoadingStatus(true);
      setError('');
      try {
        const [status, stats] = await Promise.all([
          apiFetch<BillingStatus>('/billing/status'),
          apiFetch<AlertStats>('/alerts/stats').catch(() => null),
        ]);
        if (mounted) {
          setBillingStatus(status);
          setAlertStats(stats);
        }
      } catch (err: any) {
        if (mounted) {
          setError(err?.message || 'Failed to load billing information.');
        }
      } finally {
        if (mounted) setLoadingStatus(false);
      }
    };

    fetchData();
    return () => { mounted = false; };
  }, []);

  const handleManageSubscription = async () => {
    setPortalLoading(true);
    setError('');
    try {
      const res = await apiFetch<PortalResponse>('/billing/portal');
      if (res?.url) {
        window.location.href = res.url;
      } else {
        setError('Could not open billing portal. Please try again.');
      }
    } catch (err: any) {
      setError(err?.message || 'Failed to open billing portal.');
    } finally {
      setPortalLoading(false);
    }
  };

  const alertCount = alertStats?.total ?? alertStats?.totalOpen ?? alertStats?.open ?? 0;
  const scansEstimate = '~720/day';

  // ── Loading ──
  if (loadingStatus) {
    return (
      <div className="loading-state">
        <div className="loading-spinner" />
        <div className="loading-text">Loading billing information…</div>
      </div>
    );
  }

  // ── Fallback: treat as trial if nothing returned ──
  const status: BillingStatus = billingStatus ?? { plan: 'trial', status: 'trial' };

  return (
    <div>
      {/* ── Page Header ── */}
      <div className="page-header">
        <div>
          <div className="page-title">Billing &amp; Plan</div>
          <div className="page-subtitle">Manage your subscription and usage</div>
        </div>
      </div>

      {/* ── Global error ── */}
      {error && (
        <div
          style={{
            marginBottom: 20,
            background: 'rgba(255,68,85,0.08)',
            border: '1px solid rgba(255,68,85,0.25)',
            borderRadius: 10,
            padding: '12px 16px',
            color: 'var(--red-critical)',
            fontSize: 13,
          }}
        >
          {error}
        </div>
      )}

      <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>

        {/* ── Section 1: Current Plan ── */}
        <div className="card">
          <div className="card-header">
            <div className="card-title">
              <span
                style={{
                  width: 7,
                  height: 7,
                  borderRadius: '50%',
                  background: '#E8784A',
                  boxShadow: '0 0 10px rgba(232,120,74,0.55)',
                  display: 'inline-block',
                  flexShrink: 0,
                }}
              />
              Current Plan
            </div>
            <PlanBadge status={status} />
          </div>

          <div style={{ paddingTop: 20, display: 'flex', flexDirection: 'column', gap: 16 }}>
            <div
              style={{
                display: 'flex',
                flexWrap: 'wrap',
                gap: 24,
                alignItems: 'flex-start',
              }}
            >
              {/* Plan info */}
              <div style={{ flex: '1 1 220px' }}>
                <div
                  style={{
                    fontSize: 32,
                    fontWeight: 800,
                    letterSpacing: -0.5,
                    color: planColor(status),
                    marginBottom: 4,
                  }}
                >
                  {planLabel(status)}
                </div>

                {isTrial(status) && (
                  <div style={{ fontSize: 13, color: 'var(--text-secondary)' }}>
                    {typeof status.daysLeft === 'number' ? (
                      <>
                        <span
                          style={{
                            fontWeight: 600,
                            color:
                              status.daysLeft <= 7
                                ? 'var(--red-critical)'
                                : 'var(--amber-500)',
                          }}
                        >
                          {status.daysLeft} day{status.daysLeft !== 1 ? 's' : ''} left
                        </span>{' '}
                        in your free trial
                      </>
                    ) : (
                      'Free trial active'
                    )}
                    {status.trialEndsAt && (
                      <div style={{ marginTop: 4, color: 'var(--text-muted)', fontSize: 12 }}>
                        Ends {formatDate(status.trialEndsAt)}
                      </div>
                    )}
                  </div>
                )}

                {isActive(status) && (
                  <div style={{ fontSize: 13, color: 'var(--text-secondary)' }}>
                    Active subscription
                    {status.renewalDate && (
                      <div style={{ marginTop: 4, color: 'var(--text-muted)', fontSize: 12 }}>
                        Renews {formatDate(status.renewalDate)}
                      </div>
                    )}
                  </div>
                )}

                {!isTrial(status) && !isActive(status) && (
                  <div
                    style={{
                      fontSize: 13,
                      color: 'var(--red-critical)',
                      fontWeight: 600,
                    }}
                  >
                    Subscription inactive
                  </div>
                )}
              </div>

              {/* CTA */}
              <div
                style={{
                  display: 'flex',
                  flexDirection: 'column',
                  gap: 10,
                  justifyContent: 'flex-start',
                  paddingTop: 4,
                }}
              >
                {isTrial(status) ? (
                  <button
                    className="btn btn-primary"
                    onClick={() => navigate('/pricing')}
                  >
                    Upgrade now
                  </button>
                ) : (
                  <button
                    className="btn btn-primary"
                    onClick={handleManageSubscription}
                    disabled={portalLoading}
                  >
                    {portalLoading ? (
                      <span style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                        <span className="spin">⟳</span> Opening…
                      </span>
                    ) : (
                      'Manage subscription'
                    )}
                  </button>
                )}

                {isTrial(status) && (
                  <div style={{ fontSize: 11, color: 'var(--text-muted)', textAlign: 'center' }}>
                    No credit card required
                  </div>
                )}
              </div>
            </div>
          </div>
        </div>

        {/* ── Section 2: Plan Features ── */}
        <div className="card">
          <div className="card-header">
            <div className="card-title">
              <span
                style={{
                  width: 7,
                  height: 7,
                  borderRadius: '50%',
                  background: '#E8784A',
                  boxShadow: '0 0 10px rgba(232,120,74,0.55)',
                  display: 'inline-block',
                  flexShrink: 0,
                }}
              />
              Plan Features
            </div>
          </div>

          <div style={{ paddingTop: 16 }}>
            <table className="data-table" style={{ tableLayout: 'fixed' }}>
              <thead>
                <tr>
                  <th style={{ width: '70%' }}>Feature</th>
                  <th style={{ width: '30%', textAlign: 'center' }}>Included</th>
                </tr>
              </thead>
              <tbody>
                {PLAN_FEATURES.map((feature) => {
                  const included = featureIncluded(feature, status);
                  return (
                    <tr key={feature.text} style={{ opacity: included ? 1 : 0.38 }}>
                      <td style={{ color: included ? 'var(--text-primary)' : 'var(--text-muted)' }}>
                        {feature.text}
                      </td>
                      <td style={{ textAlign: 'center' }}>
                        {included ? (
                          <span
                            style={{
                              display: 'inline-flex',
                              alignItems: 'center',
                              justifyContent: 'center',
                              width: 20,
                              height: 20,
                              borderRadius: '50%',
                              background: 'rgba(0,201,139,0.12)',
                              border: '1px solid rgba(0,201,139,0.30)',
                              color: 'var(--green-clean)',
                              fontSize: 11,
                              fontWeight: 700,
                            }}
                          >
                            ✓
                          </span>
                        ) : (
                          <span
                            style={{
                              display: 'inline-flex',
                              alignItems: 'center',
                              justifyContent: 'center',
                              width: 20,
                              height: 20,
                              borderRadius: '50%',
                              background: 'rgba(255,255,255,0.04)',
                              border: '1px solid rgba(255,255,255,0.08)',
                              color: 'var(--text-muted)',
                              fontSize: 12,
                            }}
                          >
                            –
                          </span>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>

            {isTrial(status) && (
              <div
                style={{
                  marginTop: 14,
                  padding: '10px 14px',
                  background: 'rgba(232,120,74,0.06)',
                  border: '1px solid rgba(232,120,74,0.18)',
                  borderRadius: 8,
                  fontSize: 12,
                  color: 'var(--text-secondary)',
                }}
              >
                All features are available during your trial.{' '}
                <button
                  className="btn btn-ghost btn-sm"
                  onClick={() => navigate('/pricing')}
                  style={{ fontSize: 12, padding: '2px 10px' }}
                >
                  View plans →
                </button>
              </div>
            )}
          </div>
        </div>

        {/* ── Section 3: Usage This Month ── */}
        <div className="card">
          <div className="card-header">
            <div className="card-title">
              <span
                style={{
                  width: 7,
                  height: 7,
                  borderRadius: '50%',
                  background: '#E8784A',
                  boxShadow: '0 0 10px rgba(232,120,74,0.55)',
                  display: 'inline-block',
                  flexShrink: 0,
                }}
              />
              Usage This Month
            </div>
            <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>Estimated</span>
          </div>

          <div
            style={{
              paddingTop: 20,
              display: 'grid',
              gridTemplateColumns: 'repeat(auto-fit, minmax(160px, 1fr))',
              gap: 16,
            }}
          >
            {/* Alerts detected */}
            <div
              style={{
                background: 'rgba(255,255,255,0.03)',
                border: '1px solid rgba(255,255,255,0.07)',
                borderRadius: 12,
                padding: '16px 18px',
              }}
            >
              <div
                style={{
                  fontSize: 11,
                  fontWeight: 600,
                  textTransform: 'uppercase',
                  letterSpacing: 0.7,
                  color: 'var(--text-muted)',
                  marginBottom: 8,
                }}
              >
                Alerts detected
              </div>
              <div
                style={{
                  fontSize: 28,
                  fontWeight: 800,
                  letterSpacing: -0.5,
                  color: alertCount > 0 ? 'var(--orange-high)' : 'var(--green-clean)',
                  lineHeight: 1,
                  marginBottom: 4,
                }}
              >
                {alertCount}
              </div>
              <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>total alerts</div>
            </div>

            {/* Tenants monitored */}
            <div
              style={{
                background: 'rgba(255,255,255,0.03)',
                border: '1px solid rgba(255,255,255,0.07)',
                borderRadius: 12,
                padding: '16px 18px',
              }}
            >
              <div
                style={{
                  fontSize: 11,
                  fontWeight: 600,
                  textTransform: 'uppercase',
                  letterSpacing: 0.7,
                  color: 'var(--text-muted)',
                  marginBottom: 8,
                }}
              >
                Tenants monitored
              </div>
              <div
                style={{
                  fontSize: 28,
                  fontWeight: 800,
                  letterSpacing: -0.5,
                  color: 'var(--text-primary)',
                  lineHeight: 1,
                  marginBottom: 4,
                }}
              >
                {status.plan?.toLowerCase() === 'msp' ? '—' : '1'}
              </div>
              <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>
                {status.plan?.toLowerCase() === 'msp' ? 'see MSP Fleet' : 'M365 tenant'}
              </div>
            </div>

            {/* Scans run */}
            <div
              style={{
                background: 'rgba(255,255,255,0.03)',
                border: '1px solid rgba(255,255,255,0.07)',
                borderRadius: 12,
                padding: '16px 18px',
              }}
            >
              <div
                style={{
                  fontSize: 11,
                  fontWeight: 600,
                  textTransform: 'uppercase',
                  letterSpacing: 0.7,
                  color: 'var(--text-muted)',
                  marginBottom: 8,
                }}
              >
                Scans run
              </div>
              <div
                style={{
                  fontSize: 28,
                  fontWeight: 800,
                  letterSpacing: -0.5,
                  color: 'var(--text-primary)',
                  lineHeight: 1,
                  marginBottom: 4,
                }}
              >
                {scansEstimate}
              </div>
              <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>automated scans</div>
            </div>
          </div>
        </div>

      </div>
    </div>
  );
}
