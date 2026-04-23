import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { apiFetch } from '../services/api';

// ─── Types ─────────────────────────────────────────────────────────────────

interface BillingStatus {
  plan: 'free' | 'active' | 'cancelled' | string;
  daysLeft?: number | null;
  renewalDate?: string | null;
  trialEndsAt?: string | null;
  activatedAt?: string | null;
  cancelledAt?: string | null;
  gumroadUrl?: string | null;
  gumroadSubscriptionId?: string | null;
}

const GUMROAD_URL = 'https://moderne.gumroad.com/l/azxxv';

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

// pro = included in Free tier, msp = included in Pro (paid) tier
const PLAN_FEATURES: PlanFeature[] = [
  { text: 'Sign-in anomaly detection (60s cycle)', pro: true,  msp: true  },
  { text: 'Alert dashboard & history',             pro: true,  msp: true  },
  { text: 'User risk overview',                    pro: true,  msp: true  },
  { text: 'Manual investigation tools',            pro: true,  msp: true  },
  { text: 'Telegram alerts with action buttons',   pro: false, msp: true  },
  { text: 'Email notifications (multi-admin)',      pro: false, msp: true  },
  { text: 'Automated session revoke',              pro: false, msp: true  },
  { text: 'Automated user disable',                pro: false, msp: true  },
  { text: 'Conditional Access management',         pro: false, msp: true  },
  { text: 'PIM privilege monitoring',              pro: false, msp: true  },
  { text: 'Audit Center (365-day retention)',      pro: false, msp: true  },
  { text: 'Reports & exports',                     pro: false, msp: true  },
];

// ─── Helpers ───────────────────────────────────────────────────────────────

function planLabel(status: BillingStatus): string {
  if (status.plan === 'active') return 'Pro';
  if (status.plan === 'cancelled') return 'Cancelled';
  return 'Free';
}

function planColor(status: BillingStatus): string {
  if (status.plan === 'active') return '#E8784A';
  if (status.plan === 'cancelled') return '#FF4455';
  return '#888';
}

function isPremium(status: BillingStatus): boolean {
  return status.plan === 'active';
}

function featureIncluded(feature: PlanFeature, status: BillingStatus): boolean {
  if (isPremium(status)) return feature.pro || feature.msp;
  // Free tier: only free features (pro=true means it was a pro-only feature → show as locked for free)
  return false; // we'll override per-feature below
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

  const handleManageSubscription = () => {
    window.open(billingStatus?.gumroadUrl || 'https://moderne.gumroad.com/l/azxxv', '_blank');
  };

  const handleUpgrade = async () => {
    try {
      const res = await apiFetch<{ url: string }>('/billing/checkout').catch(() => null);
      window.location.href = res?.url || 'https://moderne.gumroad.com/l/azxxv';
    } catch {
      window.location.href = 'https://moderne.gumroad.com/l/azxxv';
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

  const status: BillingStatus = billingStatus ?? { plan: 'free' };

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

                {!isPremium(status) && (
                  <div style={{ fontSize: 13, color: 'var(--text-secondary)' }}>
                    Free tier — detection active, notifications locked
                  </div>
                )}

                {isPremium(status) && (
                  <div style={{ fontSize: 13, color: 'var(--text-secondary)' }}>
                    Active subscription
                    {status.activatedAt && (
                      <div style={{ marginTop: 4, color: 'var(--text-muted)', fontSize: 12 }}>
                        Active since {formatDate(status.activatedAt)}
                      </div>
                    )}
                  </div>
                )}

                {status.plan === 'cancelled' && (
                  <div
                    style={{ fontSize: 13, color: 'var(--red-critical)', fontWeight: 600 }}
                  >
                    Subscription cancelled — premium features frozen
                  </div>
                )}
              </div>

              {/* CTA */}
              <div style={{ display: 'flex', flexDirection: 'column', gap: 10, justifyContent: 'flex-start', paddingTop: 4 }}>
                {isPremium(status) ? (
                  <>
                    <button className="btn btn-primary" onClick={handleManageSubscription}>
                      Manage on Gumroad ↗
                    </button>
                    <div style={{ fontSize: 11, color: 'var(--text-muted)', textAlign: 'center' }}>
                      Cancel anytime from your Gumroad dashboard
                    </div>
                  </>
                ) : (
                  <>
                    <button className="btn btn-primary" onClick={handleUpgrade}>
                      Upgrade to Pro — $15/mo →
                    </button>
                    <div style={{ fontSize: 11, color: 'var(--text-muted)', textAlign: 'center' }}>
                      Unlock Telegram alerts, email &amp; auto-remediation
                    </div>
                  </>
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
                  // pro=true → included in free tier; msp=true → included in premium
                  const freeIncluded    = feature.pro;
                  const premiumIncluded = feature.msp;
                  const included = isPremium(status) ? premiumIncluded : freeIncluded;
                  return (
                    <tr key={feature.text} style={{ opacity: included ? 1 : 0.38 }}>
                      <td style={{ color: included ? 'var(--text-primary)' : 'var(--text-muted)' }}>
                        {!freeIncluded && !isPremium(status) && (
                          <span style={{ fontSize: 10, color: '#E8784A', fontWeight: 700, marginRight: 6 }}>PRO</span>
                        )}
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

            {!isPremium(status) && (
              <div
                style={{
                  marginTop: 14, padding: '10px 14px',
                  background: 'rgba(232,120,74,0.06)', border: '1px solid rgba(232,120,74,0.18)',
                  borderRadius: 8, fontSize: 12, color: 'var(--text-secondary)',
                }}
              >
                🔒 <strong style={{ color: '#E8784A' }}>Pro</strong> features are locked on the Free tier.{' '}
                <button
                  className="btn btn-ghost btn-sm"
                  onClick={() => navigate('/pricing')}
                  style={{ fontSize: 12, padding: '2px 10px' }}
                >
                  Upgrade for $15/mo →
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
