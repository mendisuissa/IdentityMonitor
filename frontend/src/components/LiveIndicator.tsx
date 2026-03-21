import React, { useEffect, useState } from 'react';
import { connectWS, onWS, getWSState } from '../services/wsClient';

interface Props {
  onNewAlert?: (alert: any) => void;
}

export default function LiveIndicator({ onNewAlert }: Props) {
  const [status, setStatus] = useState<'connected'|'disconnected'|'connecting'>('connecting');
  const [lastEvent, setLastEvent] = useState<string | null>(null);
  const [pulse, setPulse] = useState(false);

  useEffect(() => {
    connectWS();

    const unsubs = [
      onWS('connected',      () => setStatus('connected')),
      onWS('disconnected',   () => setStatus('disconnected')),
      onWS('new_alert',      (data) => {
        setPulse(true);
        setTimeout(() => setPulse(false), 2000);
        setLastEvent('New alert: ' + data.alert?.anomalyLabel);
        onNewAlert?.(data.alert);
      }),
      onWS('scan_complete',  (data) => {
        if (data.newAlertCount > 0) {
          setLastEvent(data.newAlertCount + ' new alerts detected');
          setPulse(true);
          setTimeout(() => setPulse(false), 2000);
        }
      }),
    ];

    return () => unsubs.forEach(u => u());
  }, []);

  const color = status === 'connected' ? '#2ecc71' : status === 'connecting' ? '#f5a623' : '#ff3b3b';
  const label = status === 'connected' ? 'LIVE' : status === 'connecting' ? 'CONNECTING' : 'OFFLINE';

  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 6 }} title={lastEvent || label}>
      <div style={{
        width: 8, height: 8, borderRadius: '50%',
        background: color,
        boxShadow: pulse ? '0 0 0 4px ' + color + '40' : '0 0 6px ' + color,
        transition: 'box-shadow 0.3s ease',
        animation: status === 'connected' ? 'livePulse 2s infinite' : 'none'
      }} />
      <span style={{
        fontFamily: 'var(--font-mono)',
        fontSize: 10,
        fontWeight: 700,
        color,
        letterSpacing: '0.5px'
      }}>{label}</span>

      <style>{`
        @keyframes livePulse {
          0%, 100% { box-shadow: 0 0 4px ${color}; }
          50% { box-shadow: 0 0 10px ${color}60; }
        }
      `}</style>
    </div>
  );
}
