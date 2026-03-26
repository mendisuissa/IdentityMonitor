import React, { useState, useEffect } from 'react';
import { api } from './services/api';
import { BrowserRouter, Routes, Route, NavLink, useNavigate } from 'react-router-dom';
import Dashboard from './components/Dashboard';
import UsersPage from './components/UsersPage';
import AlertsPage from './components/AlertsPage';
import SignInsPage from './components/SignInsPage';
import MockPanel from './components/MockPanel';
import LoginPage from './components/LoginPage';
import LiveIndicator from './components/LiveIndicator';
import ReportsPage from './components/ReportsPage';
import PimPage from './components/PimPage';
import MspDashboard from './components/MspDashboard';
import SettingsPage from './components/SettingsPage';
import AuditCenterPage from './components/AuditCenterPage';
import CaseBoardPage from './components/CaseBoardPage';
import TenantOpsPage from './components/TenantOpsPage';
import RemediationPage from './components/RemediationPage';
import './styles.css';

interface TenantUser {
  userName: string;
  userEmail: string;
  tenantId: string;
  tenantName: string;
}

function NotificationDrawer({ open, items, onClose, onAck, onApprove, onReject, onAssign }: {
  open: boolean;
  items: any[];
  onClose: () => void;
  onAck: (id: string) => void;
  onApprove: (id: string) => void;
  onReject: (id: string) => void;
  onAssign: (id: string) => void;
}) {
  if (!open) return null;
  return (
    <div style={{ position: 'fixed', top: 60, right: 16, width: 420, maxWidth: '92vw', maxHeight: '72vh', overflowY: 'auto', background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 14, padding: 16, boxShadow: '0 24px 48px rgba(0,0,0,0.4)', zIndex: 400 }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 12 }}>
        <div>
          <div style={{ fontWeight: 700, fontSize: 14 }}>Notification Center</div>
          <div style={{ fontSize: 12, color: 'var(--text-muted)', marginTop: 2 }}>Live security alerts & approvals</div>
        </div>
        <div style={{ display: 'flex', gap: 8 }}>
          {items.filter(i => i.status !== 'acked').length > 0 && (
            <button className="btn btn-ghost btn-sm" onClick={() => items.filter(i => i.status !== 'acked').forEach(i => onAck(i.id))} style={{ fontSize: 11 }}>
              Mark all read
            </button>
          )}
          <button className="btn btn-ghost btn-sm" onClick={onClose}>✕</button>
        </div>
      </div>
      {!items.length && <div style={{ color: 'var(--text-muted)', padding: '18px 4px', fontSize: 13 }}>No active notifications.</div>}
      <div style={{ display: 'grid', gap: 8 }}>
        {items.map((item) => {
          const approval = item.type === 'approval';
          return (
            <div key={item.id} className="card" style={{ padding: 12 }}>
              <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: 12 }}>
                <div>
                  <div style={{ fontWeight: 600, fontSize: 13 }}>{item.displayTitle || item.title}</div>
                  {item.displaySubtitle && <div style={{ color: 'var(--text-muted)', fontSize: 12, marginTop: 2 }}>{item.displaySubtitle}</div>}
                </div>
                <span className="role-tag">{item.kindLabel || item.type}</span>
              </div>
              {item.displayDetail && <div style={{ fontSize: 13, marginTop: 8 }}>{item.displayDetail}</div>}
              {!!item.duplicateCount && item.duplicateCount > 1 && <div style={{ color: 'var(--text-muted)', fontSize: 11, marginTop: 6 }}>{item.duplicateCount} similar notifications grouped.</div>}
              <div style={{ color: 'var(--text-muted)', fontSize: 11, marginTop: 6 }}>{new Date(item.createdAt).toLocaleString()}</div>
              <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginTop: 10 }}>
                {item.metadata?.alertId && <a className="btn btn-ghost btn-sm" href="/alerts">Open incident</a>}
                {item.metadata?.caseId && <a className="btn btn-ghost btn-sm" href="/cases">Open case</a>}
                {approval && <button className="btn btn-ghost btn-sm" onClick={() => onAssign(item.metadata?.alertId || '')}>Assign to me</button>}
                {approval && <button className="btn btn-primary btn-sm" onClick={() => onApprove(item.metadata?.alertId || '')}>Approve</button>}
                {approval && <button className="btn btn-ghost btn-sm" onClick={() => onReject(item.metadata?.alertId || '')}>Reject</button>}
                <button className="btn btn-ghost btn-sm" onClick={() => onAck(item.id)}>Acknowledge</button>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

function Sidebar({ user, scanLoading, onScan, newAlertCount, mockMode, inbox, onAckNotification, onApproveNotification, onRejectNotification, onAssignNotification }: {
  user: TenantUser | null;
  scanLoading: boolean;
  onScan: () => void;
  newAlertCount: number;
  mockMode: boolean;
  inbox: any[];
  onAckNotification: (id: string) => void;
  onApproveNotification: (alertId: string) => void;
  onRejectNotification: (alertId: string) => void;
  onAssignNotification: (alertId: string) => void;
}) {
  const [drawerOpen, setDrawerOpen] = useState(false);
  const unread = inbox.filter(i => i.status !== 'acked').length;

  return (
    <>
      <aside className="sidebar">
        {/* Logo */}
        <div className="sidebar-logo">
          <div className="logo-icon">🛡️</div>
          <div>
            <div className="logo-text">IdentityMonitor</div>
            <div className="logo-sub">Security Operations</div>
          </div>
        </div>

        {/* Nav sections */}
        <div style={{ flex: 1, overflowY: 'auto', paddingBottom: 8 }}>
          <div className="nav-section">
            <div className="nav-label">Overview</div>
            <NavLink to="/" end className={({ isActive }) => isActive ? 'nav-item active' : 'nav-item'}>
              <span>⊞</span> Dashboard
            </NavLink>
            <NavLink to="/alerts" className={({ isActive }) => isActive ? 'nav-item active' : 'nav-item'}>
              <span>⚡</span> Alerts
              {newAlertCount > 0 && <span className="nav-badge">{newAlertCount}</span>}
            </NavLink>
            <NavLink to="/cases" className={({ isActive }) => isActive ? 'nav-item active' : 'nav-item'}>
              <span>📋</span> Case Board
            </NavLink>
            <NavLink to="/users" className={({ isActive }) => isActive ? 'nav-item active' : 'nav-item'}>
              <span>👥</span> Exposure
            </NavLink>
          </div>

          <div className="nav-section">
            <div className="nav-label">Security</div>
            <NavLink to="/signins" className={({ isActive }) => isActive ? 'nav-item active' : 'nav-item'}>
              <span>🔍</span> Sign-in Activity
            </NavLink>
            <NavLink to="/remediation" className={({ isActive }) => isActive ? 'nav-item active' : 'nav-item'}>
              <span>🛠️</span> Remediation
            </NavLink>
            <NavLink to="/reports" className={({ isActive }) => isActive ? 'nav-item active' : 'nav-item'}>
              <span>📊</span> Reports
            </NavLink>
            <NavLink to="/audit" className={({ isActive }) => isActive ? 'nav-item active' : 'nav-item'}>
              <span>📜</span> Audit Center
            </NavLink>
            <NavLink to="/pim" className={({ isActive }) => isActive ? 'nav-item active' : 'nav-item'}>
              <span>🔑</span> PIM Analysis
            </NavLink>
          </div>

          <div className="nav-section">
            <div className="nav-label">Management</div>
            <NavLink to="/ops" className={({ isActive }) => isActive ? 'nav-item active' : 'nav-item'}>
              <span>🏢</span> Tenant Ops
            </NavLink>
            <NavLink to="/msp" className={({ isActive }) => isActive ? 'nav-item active' : 'nav-item'}>
              <span>🌐</span> MSP Fleet
            </NavLink>
            <NavLink to="/settings" className={({ isActive }) => isActive ? 'nav-item active' : 'nav-item'}>
              <span>⚙️</span> Settings
            </NavLink>
          </div>
        </div>

        {/* Footer */}
        <div className="sidebar-footer">
          <div style={{ display: 'flex', gap: 8, marginBottom: 12 }}>
            {!mockMode && (
              <button className="btn btn-primary btn-sm" onClick={onScan} disabled={scanLoading} style={{ flex: 1, justifyContent: 'center', fontSize: 12 }}>
                {scanLoading ? <><span className="spin">⟳</span> Scanning...</> : '⟳ Run Scan'}
              </button>
            )}
            <button
              className="btn btn-ghost btn-sm"
              onClick={() => setDrawerOpen(v => !v)}
              style={{ position: 'relative', flexShrink: 0 }}
            >
              🔔
              {unread > 0 && (
                <span className="nav-badge" style={{ position: 'absolute', top: -4, right: -4, minWidth: 16, padding: '0 4px', fontSize: 9 }}>
                  {unread}
                </span>
              )}
            </button>
          </div>

          {user ? (
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <div className="sidebar-avatar">
                {(user.userName || user.userEmail || '?').charAt(0).toUpperCase()}
              </div>
              <div style={{ flex: 1, minWidth: 0 }}>
                <div style={{ fontSize: 12, fontWeight: 600, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{user.userName}</div>
                <div style={{ fontSize: 10, color: 'var(--text-muted)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{user.userEmail}</div>
              </div>
              <a href="/api/auth/logout" className="btn btn-ghost btn-sm" style={{ fontSize: 11, flexShrink: 0 }}>↩</a>
            </div>
          ) : (
            <div style={{ fontSize: 12, color: 'var(--text-muted)' }}>
              {mockMode ? '🟡 Mock Mode' : 'Not signed in'}
            </div>
          )}
        </div>
      </aside>

      <NotificationDrawer
        open={drawerOpen}
        items={inbox}
        onClose={() => setDrawerOpen(false)}
        onAck={onAckNotification}
        onApprove={onApproveNotification}
        onReject={onRejectNotification}
        onAssign={onAssignNotification}
      />
    </>
  );
}

function AppShell() {
  const [user, setUser] = useState<TenantUser | null>(null);
  const [authLoading, setAuthLoading] = useState(true);
  const [scanLoading, setScanLoading] = useState(false);
  const [openAlerts, setOpenAlerts] = useState(0);
  const [scanResult, setScanResult] = useState<string | null>(null);
  const [mockMode, setMockMode] = useState(false);
  const [showMockPanel, setShowMockPanel] = useState(false);
  const [inbox, setInbox] = useState<any[]>([]);
  const navigate = useNavigate();

  useEffect(() => {
    fetch('/api/health', { credentials: 'include' })
      .then(r => r.json())
      .then(d => {
        setMockMode(d.mockMode === true);
        if (d.mockMode === true) { setAuthLoading(false); return; }
        return fetch('/api/auth/status', { credentials: 'include' })
          .then(r => r.json())
          .then(d => { if (d.authenticated && d.tenant) setUser(d.tenant as TenantUser); });
      })
      .catch(err => console.error('[App] health/auth check failed:', err))
      .finally(() => setAuthLoading(false));
  }, []);

  useEffect(() => {
    api.getNotificationInbox({ limit: 12, dedupe: true }).then((res: any) => setInbox(res.items || [])).catch(() => {});
    api.getAlertStats().then((stats: any) => setOpenAlerts(stats.open || stats.active || stats.totalOpen || 0)).catch(() => {});
  }, []);

  const handleScan = async () => {
    setScanLoading(true);
    setScanResult(null);
    try {
      const { api } = await import('./services/api');
      const result = await api.triggerScan();
      setScanResult(`Scan complete — ${result.newAlerts} new alert${result.newAlerts !== 1 ? 's' : ''} detected`);
      setOpenAlerts(p => p + result.newAlerts);
    } catch {
      setScanResult('Scan failed — check backend connection');
    } finally {
      setScanLoading(false);
      setTimeout(() => setScanResult(null), 5000);
    }
  };

  if (authLoading) return (
    <div className="loading-state" style={{ minHeight: '100vh' }}>
      <div className="loading-spinner" />
      <div className="loading-text">Loading...</div>
    </div>
  );

  if (!mockMode && !user) return <LoginPage onLogin={() => {}} />;

  return (
    <div className="app">
      <Sidebar
        user={user}
        scanLoading={scanLoading}
        onScan={handleScan}
        newAlertCount={openAlerts}
        mockMode={mockMode}
        inbox={inbox}
        onAckNotification={(id) => api.ackNotification(id).then(() => api.getNotificationInbox({ limit: 12, dedupe: true }).then((res: any) => setInbox(res.items || [])))}
        onApproveNotification={(alertId) => api.approveAlertAction(alertId).then(() => api.getNotificationInbox({ limit: 12, dedupe: true }).then((res: any) => setInbox(res.items || [])))}
        onRejectNotification={(alertId) => api.rejectAlertAction(alertId).then(() => api.getNotificationInbox({ limit: 12, dedupe: true }).then((res: any) => setInbox(res.items || [])))}
        onAssignNotification={(alertId) => user && api.assignAlertOwner(alertId, user.userEmail).then(() => api.getNotificationInbox({ limit: 12, dedupe: true }).then((res: any) => setInbox(res.items || [])))}
      />

      <div style={{ flex: 1, marginLeft: 220, display: 'flex', flexDirection: 'column', minHeight: '100vh' }}>
        {mockMode && (
          <div className="mock-banner">
            <span>🟡 MOCK MODE — Simulated data active</span>
            <button className="mock-trigger-btn" onClick={() => setShowMockPanel(p => !p)}>
              {showMockPanel ? '✕ Close' : '⚡ Trigger Test Alert'}
            </button>
          </div>
        )}
        {showMockPanel && mockMode && (
          <MockPanel onAlertTriggered={() => setOpenAlerts(p => p + 1)} />
        )}
        {scanResult && (
          <div className={`scan-toast ${scanResult.includes('failed') ? 'toast-error' : 'toast-success'}`}>
            {scanResult}
          </div>
        )}
        <main className="main-content">
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/users" element={<UsersPage />} />
            <Route path="/alerts" element={<AlertsPage />} />
            <Route path="/signins" element={<SignInsPage />} />
            <Route path="/reports" element={<ReportsPage />} />
            <Route path="/pim" element={<PimPage />} />
            <Route path="/msp" element={<MspDashboard />} />
            <Route path="/cases" element={<CaseBoardPage />} />
            <Route path="/audit" element={<AuditCenterPage />} />
            <Route path="/ops" element={<TenantOpsPage />} />
            <Route path="/login" element={<LoginPage onLogin={() => navigate('/')} />} />
            <Route path="/settings" element={<SettingsPage />} />
            <Route path="/remediation" element={<RemediationPage />} />
          </Routes>
        </main>
      </div>
    </div>
  );
}

export default function App() {
  return (
    <BrowserRouter>
      <AppShell />
    </BrowserRouter>
  );
}
