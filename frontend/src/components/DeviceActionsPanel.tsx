import React, { useEffect, useState } from 'react';
import { api } from '../services/api';

interface DeviceAction {
  id: string;
  type: 'wipe' | 'reset' | 'delete';
  deviceName: string;
  userDisplayName: string;
  userPrincipalName: string;
  initiatedBy: string;
  timestamp: string;
  severity: 'critical' | 'high' | 'medium';
  status: 'completed' | 'in_progress' | 'pending';
  os?: string;
  _isMock?: boolean;
}

function timeAgo(ts: string) {
  const diff = Date.now() - new Date(ts).getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  return `${Math.floor(hrs / 24)}d ago`;
}

const TYPE_LABELS: Record<string, string> = { wipe: 'WIPE', reset: 'RESET', delete: 'DELETE' };
const STATUS_LABELS: Record<string, string> = { completed: '✓ Done', in_progress: '⟳ Running', pending: '⏳ Pending' };

export default function DeviceActionsPanel() {
  const [actions, setActions] = useState<DeviceAction[]>([]);
  const [loading, setLoading] = useState(true);
  const [dismissed, setDismissed] = useState<Set<string>>(new Set());
  const [expanded, setExpanded] = useState(true);

  useEffect(() => {
    api.getDeviceActions()
      .then(data => setActions(Array.isArray(data) ? data : []))
      .catch(() => setActions([]))
      .finally(() => setLoading(false));
  }, []);

  const handleAck = async (id: string) => {
    try {
      await api.acknowledgeDeviceAction(id);
      setDismissed(prev => new Set([...prev, id]));
    } catch {}
  };

  const visible = actions.filter(a => !dismissed.has(a.id)).filter(a => a._isMock !== true);

  return (
    <div>
      <div className="page-header" style={{ marginBottom: 24 }}>
        <div>
          <div className="page-title">Device Actions</div>
          <div className="page-subtitle">Wipe, delete, and reset events across managed devices</div>
        </div>
      </div>

      {loading && (
        <div style={{ color: 'var(--text-muted)', fontSize: 13, padding: '24px 0' }}>
          Loading device actions…
        </div>
      )}

      {!loading && visible.length === 0 && (
        <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', minHeight: 320, gap: 12, color: 'var(--text-secondary)' }}>
          <i className="ti ti-device-desktop-check" style={{ fontSize: 48, opacity: 0.2 }} />
          <div style={{ fontWeight: 700, fontSize: 15, color: 'var(--text-primary)', opacity: 0.5 }}>No destructive device actions</div>
          <div style={{ fontSize: 13, opacity: 0.5 }}>Wipe, delete, and reset events from Intune will appear here.</div>
        </div>
      )}

      {!loading && visible.length > 0 && (
        <div className="device-actions-panel" style={{ marginBottom: 24 }}>
          <div className="device-actions-header">
            <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
              <span style={{ fontSize: 18 }}>⚠️</span>
              <div>
                <span style={{ fontWeight: 700, fontSize: 14, color: '#ef4444' }}>
                  Destructive Device Actions Detected
                </span>
                <div style={{ fontSize: 12, color: 'var(--text-muted)', marginTop: 2 }}>
                  {visible.length} event{visible.length !== 1 ? 's' : ''} — Wipe / Delete / Reset
                </div>
              </div>
            </div>
            <button className="btn btn-ghost btn-sm" onClick={() => setExpanded(v => !v)} style={{ fontSize: 11 }}>
              {expanded ? '▲ Collapse' : '▼ Expand'}
            </button>
          </div>

          {expanded && (
            <div>
              {visible.map(action => (
                <div key={action.id} className="device-action-row">
                  <span className={`device-action-type-badge ${action.type}`}>
                    {TYPE_LABELS[action.type]}
                  </span>
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
                      <span style={{ fontWeight: 600, fontSize: 13 }}>{action.deviceName}</span>
                      {action.os && (
                        <span style={{ fontSize: 11, color: 'var(--text-muted)', padding: '1px 6px', background: 'rgba(255,255,255,0.05)', borderRadius: 99 }}>
                          {action.os}
                        </span>
                      )}
                      <span style={{
                        fontSize: 11, fontWeight: 600, padding: '1px 7px', borderRadius: 99,
                        background: action.status === 'in_progress' ? 'rgba(249,115,22,0.1)' : 'rgba(255,255,255,0.05)',
                        color: action.status === 'in_progress' ? '#f97316' : 'var(--text-muted)',
                      }}>
                        {STATUS_LABELS[action.status]}
                      </span>
                    </div>
                    <div style={{ fontSize: 12, color: 'var(--text-secondary)', marginTop: 3 }}>
                      User: <strong>{action.userDisplayName}</strong>
                      {' · '}Initiated by:{' '}
                      <span style={{ color: action.initiatedBy !== action.userPrincipalName ? '#f97316' : 'var(--text-secondary)' }}>
                        {action.initiatedBy}
                      </span>
                    </div>
                  </div>
                  <div style={{ textAlign: 'right', flexShrink: 0 }}>
                    <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 6 }}>
                      {timeAgo(action.timestamp)}
                    </div>
                    <button className="btn btn-ghost btn-sm" onClick={() => handleAck(action.id)} style={{ fontSize: 11 }}>
                      Acknowledge
                    </button>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
