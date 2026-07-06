import React, { useEffect, useState } from 'react';
import { apiFetch } from '../services/api';

type CaTab = 'policies' | 'quickactions' | 'locations';

interface CaPolicy {
  id: string;
  displayName: string;
  state: string;
  createdDateTime?: string;
  modifiedDateTime?: string;
  conditions?: any;
  grantControls?: any;
  sessionControls?: any;
}

interface NamedLocation {
  id: string;
  displayName: string;
  '@odata.type'?: string;
  ipRanges?: Array<{ cidrAddress: string }>;
  countriesAndRegions?: string[];
  isTrusted?: boolean;
}

interface QuickActionResult {
  ok: boolean;
  message: string;
}

function StateBadge({ state }: { state: string }) {
  if (state === 'enabled') {
    return (
      <span
        className="severity-badge"
        style={{ background: 'var(--green-clean)', color: '#fff', fontSize: 11 }}
      >
        Enabled
      </span>
    );
  }
  if (state === 'enabledForReportingButNotEnforced') {
    return (
      <span
        className="severity-badge"
        style={{ background: 'var(--amber-400)', color: '#000', fontSize: 11 }}
      >
        Report only
      </span>
    );
  }
  return (
    <span
      className="severity-badge"
      style={{ background: 'var(--red-critical)', color: '#fff', fontSize: 11 }}
    >
      Disabled
    </span>
  );
}

function ConditionsSummary({ conditions }: { conditions?: any }) {
  if (!conditions) return <span style={{ color: 'var(--text-muted)', fontSize: 12 }}>—</span>;
  const parts: string[] = [];
  if (conditions.users?.includeUsers?.length) parts.push(`Users: ${conditions.users.includeUsers.slice(0, 2).join(', ')}${conditions.users.includeUsers.length > 2 ? '…' : ''}`);
  if (conditions.users?.includeGroups?.length) parts.push(`${conditions.users.includeGroups.length} group(s)`);
  if (conditions.applications?.includeApplications?.length) {
    const apps = conditions.applications.includeApplications;
    parts.push(apps[0] === 'All' ? 'All apps' : `${apps.length} app(s)`);
  }
  if (conditions.locations?.includeLocations?.length) parts.push('Location filter');
  if (conditions.platforms?.includePlatforms?.length) parts.push(`Platforms: ${conditions.platforms.includePlatforms.join(', ')}`);
  return (
    <span style={{ fontSize: 12, color: 'var(--text-secondary)' }}>
      {parts.length ? parts.join(' · ') : 'No conditions'}
    </span>
  );
}

// ─── Lookup tables ────────────────────────────────────────────────────────────
const KNOWN_APPS: Record<string, string> = {
  All: 'All Cloud Apps', None: 'No Applications', Office365: 'Microsoft 365',
  '00000003-0000-0000-c000-000000000000': 'Microsoft Graph',
  '00000002-0000-0ff1-ce00-000000000000': 'Exchange Online',
  '00000003-0000-0ff1-ce00-000000000000': 'SharePoint Online',
  '00000004-0000-0ff1-ce00-000000000000': 'Skype for Business',
  '0000000a-0000-0000-c000-000000000000': 'Microsoft Intune',
  'c44b4083-3bb0-49c1-b47d-974e53cbdf3c': 'Azure Portal',
  '1fec8e78-bce4-4aaf-ab1b-5451cc387264': 'Microsoft Teams',
  'd3590ed6-52b3-4102-aeff-aad2292ab01c': 'Microsoft Office',
  '4345a7b9-9a63-4910-a426-35363201d503': 'Office (Web)',
  '57fb890c-0dab-4253-a5e0-7188c88b2bb4': 'SharePoint (Web)',
};
const KNOWN_ROLES: Record<string, string> = {
  '62e90394-69f5-4237-9190-012177145e10': 'Global Administrator',
  '194ae4cb-b126-40b2-bd5b-6091b380977d': 'Security Administrator',
  'b1be1c3e-b65d-4f19-8427-f6fa0d97feb9': 'Conditional Access Administrator',
  '88d8e3e3-8f55-4a1e-953a-9b9898b8876b': 'Global Reader',
  'e8611ab8-c189-46e8-94e1-60213ab1f814': 'Privileged Role Administrator',
  '3a2c62db-5318-420d-8d74-23affee5d9d5': 'Intune Administrator',
  '9f06204d-73c1-4d4c-880a-6edb90606fd8': 'Device Administrator',
};
const PLATFORM_META: Record<string, { icon: string; label: string }> = {
  windows: { icon: '🪟', label: 'Windows' },
  iOS: { icon: '📱', label: 'iOS' },
  android: { icon: '🤖', label: 'Android' },
  macOS: { icon: '🍎', label: 'macOS' },
  linux: { icon: '🐧', label: 'Linux' },
  windowsPhone: { icon: '📵', label: 'Windows Phone' },
  all: { icon: '🌐', label: 'All Platforms' },
};
const CLIENT_APP_LABELS: Record<string, string> = {
  browser: '🌐 Browser',
  mobileAppsAndDesktopClients: '📱 Mobile & Desktop',
  exchangeActiveSync: '📧 Exchange ActiveSync',
  other: '⚡ Other Clients',
};
const CONTROL_META: Record<string, { icon: string; label: string; color: string }> = {
  mfa:                 { icon: '🔐', label: 'Require MFA',              color: 'var(--indigo)' },
  compliantDevice:     { icon: '✅', label: 'Compliant Device',          color: 'var(--green-clean)' },
  domainJoinedDevice:  { icon: '🏢', label: 'Hybrid Azure AD Join',      color: 'var(--blue-low)' },
  approvedApplication: { icon: '📋', label: 'Approved App',              color: 'var(--blue-low)' },
  compliantApplication:{ icon: '📋', label: 'Compliant App',             color: 'var(--green-clean)' },
  block:               { icon: '🚫', label: 'Block Access',              color: 'var(--red-critical)' },
  passwordChange:      { icon: '🔑', label: 'Password Change Required',  color: 'var(--yellow-medium)' },
};
const RISK_COLOR: Record<string, string> = {
  none: 'var(--text-muted)', low: 'var(--blue-low)', medium: 'var(--yellow-medium)', high: 'var(--orange-high)',
};

// ─── Sub-components ───────────────────────────────────────────────────────────
function DrawerSection({ icon, title, children }: { icon: string; title: string; children: React.ReactNode }) {
  return (
    <div style={{ marginBottom: 18 }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 7, marginBottom: 8 }}>
        <span style={{ fontSize: 14 }}>{icon}</span>
        <span style={{ fontSize: 11, fontWeight: 700, color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: '0.7px' }}>{title}</span>
      </div>
      <div style={{ background: 'rgba(255,255,255,0.03)', borderRadius: 12, padding: '14px 16px', border: '1px solid var(--navy-border)', display: 'flex', flexDirection: 'column', gap: 12 }}>
        {children}
      </div>
    </div>
  );
}

function DrawerField({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div>
      <div style={{ fontSize: 11, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.4px', marginBottom: 6 }}>{label}</div>
      {children}
    </div>
  );
}

function UserTag({ id }: { id: string }) {
  if (id === 'All') return <span style={{ display: 'inline-flex', alignItems: 'center', gap: 5, padding: '4px 12px', borderRadius: 999, background: 'rgba(232,120,74,0.12)', border: '1px solid rgba(232,120,74,0.3)', color: 'var(--indigo)', fontSize: 12, fontWeight: 700 }}>👥 All Users</span>;
  if (id === 'GuestsOrExternalUsers') return <span className="role-tag" style={{ fontSize: 12 }}>🌍 Guests & External</span>;
  if (id.match(/^[0-9a-f-]{36}$/i)) return <span className="role-tag" style={{ fontSize: 11, fontFamily: 'var(--font-mono)', opacity: 0.8 }} title={id}>{id.substring(0, 8)}…</span>;
  return <span className="role-tag" style={{ fontSize: 12 }}>{id}</span>;
}

function RoleTag({ id }: { id: string }) {
  const name = KNOWN_ROLES[id];
  if (name) return <span className="role-tag" style={{ fontSize: 12 }}>🎭 {name}</span>;
  return <span className="role-tag" style={{ fontSize: 11, fontFamily: 'var(--font-mono)', opacity: 0.8 }} title={id}>{id.substring(0, 8)}…</span>;
}

function AppTag({ id }: { id: string }) {
  const name = KNOWN_APPS[id];
  if (name) return <span className="role-tag" style={{ fontSize: 12 }}>🔷 {name}</span>;
  if (id.match(/^[0-9a-f-]{36}$/i)) return <span className="role-tag" style={{ fontSize: 11, fontFamily: 'var(--font-mono)', opacity: 0.8 }} title={id}>{id.substring(0, 8)}…</span>;
  return <span className="role-tag" style={{ fontSize: 12 }}>{id}</span>;
}

function PlatformChip({ p }: { p: string }) {
  const meta = PLATFORM_META[p] || PLATFORM_META[p.toLowerCase()] || { icon: '💻', label: p };
  return (
    <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6, padding: '5px 12px', borderRadius: 8, background: 'rgba(255,255,255,0.05)', border: '1px solid var(--navy-border)', fontSize: 13 }}>
      {meta.icon} <span style={{ color: 'var(--text-primary)', fontWeight: 600 }}>{meta.label}</span>
    </span>
  );
}

function ControlChip({ ctrl }: { ctrl: string }) {
  const meta = CONTROL_META[ctrl] || { icon: '⚡', label: ctrl, color: 'var(--text-secondary)' };
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '10px 14px', borderRadius: 10, background: 'rgba(255,255,255,0.04)', border: '1px solid var(--navy-border)' }}>
      <span style={{ fontSize: 20 }}>{meta.icon}</span>
      <span style={{ fontSize: 14, fontWeight: 600, color: meta.color }}>{meta.label}</span>
    </div>
  );
}

function RiskBadge({ level }: { level: string }) {
  return (
    <span style={{ display: 'inline-flex', alignItems: 'center', gap: 4, padding: '3px 10px', borderRadius: 6, background: 'rgba(255,255,255,0.05)', border: `1px solid ${RISK_COLOR[level] || 'var(--navy-border)'}`, color: RISK_COLOR[level] || 'var(--text-secondary)', fontSize: 12, fontWeight: 700, textTransform: 'capitalize' }}>
      {level}
    </span>
  );
}

function formatSignInFreq(sif: any): string {
  if (!sif?.isEnabled) return 'Disabled';
  if (sif.frequencyInterval === 'everyTime') return 'Every sign-in';
  if (sif.value && sif.type) return `Every ${sif.value} ${sif.type}`;
  return 'Enabled';
}

function PolicyDetailDrawer({
  policy, onClose, onToggle, toggling,
  onDeleteClick, onDeleteConfirm, onDeleteCancel, deleteConfirm, deleting,
}: {
  policy: CaPolicy; onClose: () => void;
  onToggle: (p: CaPolicy) => void; toggling: boolean;
  onDeleteClick: () => void; onDeleteConfirm: () => void; onDeleteCancel: () => void;
  deleteConfirm: boolean; deleting: boolean;
}) {
  const c = policy.conditions || {};
  const gc = policy.grantControls || {};
  const sc = policy.sessionControls || {};

  React.useEffect(() => {
    const handler = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose(); };
    document.addEventListener('keydown', handler);
    return () => document.removeEventListener('keydown', handler);
  }, [onClose]);

  const stateColor = policy.state === 'enabled' ? 'var(--green-clean)'
    : policy.state === 'enabledForReportingButNotEnforced' ? 'var(--yellow-medium)'
    : 'var(--red-critical)';

  const sif = sc.signInFrequency;
  const pb  = sc.persistentBrowser;
  const cas = sc.cloudAppSecurity;
  const aer = sc.applicationEnforcedRestrictions;

  const hasUsers = c.users?.includeUsers?.length || c.users?.excludeUsers?.length || c.users?.includeGroups?.length || c.users?.excludeGroups?.length || c.users?.includeRoles?.length || c.users?.excludeRoles?.length;
  const hasApps  = c.applications?.includeApplications?.length || c.applications?.excludeApplications?.length;
  const hasDeviceNet = c.platforms?.includePlatforms?.length || c.platforms?.excludePlatforms?.length || c.clientAppTypes?.length || c.locations?.includeLocations?.length || c.locations?.excludeLocations?.length;
  const hasRisk  = c.signInRiskLevels?.length || c.userRiskLevels?.length;
  const hasGrant = gc.builtInControls?.length || gc.customAuthenticationFactors?.length || gc.termsOfUse?.length;
  const hasSession = (sif?.isEnabled) || (pb?.isEnabled) || (cas?.isEnabled) || (aer?.isEnabled);

  return (
    <>
      <div onClick={onClose} style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.55)', zIndex: 199, backdropFilter: 'blur(2px)' }} />
      <div style={{
        position: 'fixed', top: 0, right: 0, height: '100vh', width: 'min(600px, 100vw)',
        background: 'var(--navy-900)', borderLeft: `3px solid ${stateColor}`,
        boxShadow: '-20px 0 60px rgba(0,0,0,0.5)', zIndex: 200,
        overflowY: 'auto', display: 'flex', flexDirection: 'column',
      }}>
        {/* Sticky header */}
        <div style={{ padding: '20px 24px', borderBottom: '1px solid var(--navy-border)', position: 'sticky', top: 0, background: 'var(--navy-900)', zIndex: 1 }}>
          <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: 12 }}>
            <div style={{ flex: 1, minWidth: 0 }}>
              <div style={{ fontSize: 16, fontWeight: 700, lineHeight: 1.3, wordBreak: 'break-word' }}>{policy.displayName}</div>
              <div style={{ fontSize: 10, color: 'var(--text-muted)', marginTop: 4, fontFamily: 'var(--font-mono)', wordBreak: 'break-all' }}>{policy.id}</div>
            </div>
            <button className="btn btn-ghost btn-sm" onClick={onClose} style={{ flexShrink: 0, fontSize: 16 }}>✕</button>
          </div>
          <div style={{ marginTop: 12, display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
            <StateBadge state={policy.state} />
            <button className="btn btn-ghost btn-sm" disabled={toggling} onClick={() => onToggle(policy)}>
              {toggling ? '…' : policy.state === 'enabled' ? 'Disable' : 'Enable'}
            </button>
            {deleteConfirm ? (
              <>
                <button className="btn btn-danger btn-sm" disabled={deleting} onClick={onDeleteConfirm}>{deleting ? '…' : 'Confirm delete'}</button>
                <button className="btn btn-ghost btn-sm" onClick={onDeleteCancel}>Cancel</button>
              </>
            ) : (
              <button className="btn btn-danger btn-sm" onClick={onDeleteClick}>Delete</button>
            )}
          </div>
        </div>

        {/* Body */}
        <div style={{ padding: '20px 24px', flex: 1 }}>
          {/* Dates */}
          <div style={{ display: 'flex', gap: 28, marginBottom: 20, fontSize: 13, color: 'var(--text-secondary)' }}>
            {policy.createdDateTime && <div><div style={{ fontSize: 10, color: 'var(--text-muted)', marginBottom: 2 }}>Created</div>{new Date(policy.createdDateTime).toLocaleString()}</div>}
            {policy.modifiedDateTime && <div><div style={{ fontSize: 10, color: 'var(--text-muted)', marginBottom: 2 }}>Last modified</div>{new Date(policy.modifiedDateTime).toLocaleString()}</div>}
          </div>

          {/* Users & Groups */}
          {hasUsers ? (
            <DrawerSection icon="👥" title="Users & Groups">
              {c.users?.includeUsers?.length > 0 && (
                <DrawerField label="Include Users">
                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                    {c.users.includeUsers.map((id: string, i: number) => <UserTag key={i} id={id} />)}
                  </div>
                </DrawerField>
              )}
              {c.users?.excludeUsers?.length > 0 && (
                <DrawerField label="Exclude Users">
                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                    {c.users.excludeUsers.map((id: string, i: number) => <UserTag key={i} id={id} />)}
                  </div>
                </DrawerField>
              )}
              {c.users?.includeGroups?.length > 0 && (
                <DrawerField label="Include Groups">
                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                    {c.users.includeGroups.map((id: string, i: number) => <UserTag key={i} id={id} />)}
                  </div>
                </DrawerField>
              )}
              {c.users?.excludeGroups?.length > 0 && (
                <DrawerField label="Exclude Groups">
                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                    {c.users.excludeGroups.map((id: string, i: number) => <UserTag key={i} id={id} />)}
                  </div>
                </DrawerField>
              )}
              {c.users?.includeRoles?.length > 0 && (
                <DrawerField label="Include Roles">
                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                    {c.users.includeRoles.map((id: string, i: number) => <RoleTag key={i} id={id} />)}
                  </div>
                </DrawerField>
              )}
              {c.users?.excludeRoles?.length > 0 && (
                <DrawerField label="Exclude Roles">
                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                    {c.users.excludeRoles.map((id: string, i: number) => <RoleTag key={i} id={id} />)}
                  </div>
                </DrawerField>
              )}
            </DrawerSection>
          ) : null}

          {/* Applications */}
          {hasApps ? (
            <DrawerSection icon="📱" title="Applications">
              {c.applications?.includeApplications?.length > 0 && (
                <DrawerField label="Include">
                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                    {c.applications.includeApplications.map((id: string, i: number) => <AppTag key={i} id={id} />)}
                  </div>
                </DrawerField>
              )}
              {c.applications?.excludeApplications?.length > 0 && (
                <DrawerField label="Exclude">
                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                    {c.applications.excludeApplications.map((id: string, i: number) => <AppTag key={i} id={id} />)}
                  </div>
                </DrawerField>
              )}
            </DrawerSection>
          ) : null}

          {/* Device & Network */}
          {hasDeviceNet ? (
            <DrawerSection icon="🖥️" title="Device & Network">
              {c.platforms?.includePlatforms?.length > 0 && (
                <DrawerField label="Include Platforms">
                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                    {c.platforms.includePlatforms.map((p: string, i: number) => <PlatformChip key={i} p={p} />)}
                  </div>
                </DrawerField>
              )}
              {c.platforms?.excludePlatforms?.length > 0 && (
                <DrawerField label="Exclude Platforms">
                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                    {c.platforms.excludePlatforms.map((p: string, i: number) => <PlatformChip key={i} p={p} />)}
                  </div>
                </DrawerField>
              )}
              {c.clientAppTypes?.length > 0 && (
                <DrawerField label="Client App Types">
                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                    {c.clientAppTypes.map((t: string, i: number) => (
                      <span key={i} className="role-tag" style={{ fontSize: 12 }}>{CLIENT_APP_LABELS[t] || t}</span>
                    ))}
                  </div>
                </DrawerField>
              )}
              {(c.locations?.includeLocations?.length > 0 || c.locations?.excludeLocations?.length > 0) && (
                <DrawerField label="Locations">
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                    {c.locations?.includeLocations?.length > 0 && (
                      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6, alignItems: 'center' }}>
                        <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>Include:</span>
                        {c.locations.includeLocations.map((l: string, i: number) => <span key={i} className="role-tag" style={{ fontSize: 12 }}>📍 {l}</span>)}
                      </div>
                    )}
                    {c.locations?.excludeLocations?.length > 0 && (
                      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6, alignItems: 'center' }}>
                        <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>Exclude:</span>
                        {c.locations.excludeLocations.map((l: string, i: number) => <span key={i} className="role-tag" style={{ fontSize: 12 }}>📍 {l}</span>)}
                      </div>
                    )}
                  </div>
                </DrawerField>
              )}
            </DrawerSection>
          ) : null}

          {/* Risk Levels */}
          {hasRisk ? (
            <DrawerSection icon="⚠️" title="Risk Levels">
              {c.signInRiskLevels?.length > 0 && (
                <DrawerField label="Sign-in Risk">
                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                    {c.signInRiskLevels.map((r: string, i: number) => <RiskBadge key={i} level={r} />)}
                  </div>
                </DrawerField>
              )}
              {c.userRiskLevels?.length > 0 && (
                <DrawerField label="User Risk">
                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                    {c.userRiskLevels.map((r: string, i: number) => <RiskBadge key={i} level={r} />)}
                  </div>
                </DrawerField>
              )}
            </DrawerSection>
          ) : null}

          {/* Grant Controls */}
          {hasGrant ? (
            <DrawerSection icon="🔐" title="Access Controls — Grant">
              {gc.operator && (
                <DrawerField label="Require controls">
                  <span style={{ display: 'inline-flex', padding: '3px 10px', borderRadius: 6, background: 'rgba(155,138,251,0.15)', border: '1px solid rgba(155,138,251,0.3)', color: '#C4BBFF', fontSize: 12, fontWeight: 700 }}>
                    {gc.operator === 'AND' ? 'ALL of the following' : 'ONE of the following'}
                  </span>
                </DrawerField>
              )}
              {gc.builtInControls?.length > 0 && (
                <DrawerField label="Controls">
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                    {gc.builtInControls.map((ctrl: string, i: number) => <ControlChip key={i} ctrl={ctrl} />)}
                  </div>
                </DrawerField>
              )}
              {gc.termsOfUse?.length > 0 && (
                <DrawerField label="Terms of Use">
                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                    {gc.termsOfUse.map((t: string, i: number) => <span key={i} className="role-tag" style={{ fontSize: 12 }}>📜 {t}</span>)}
                  </div>
                </DrawerField>
              )}
            </DrawerSection>
          ) : null}

          {/* Session Controls */}
          {hasSession ? (
            <DrawerSection icon="⏱️" title="Session Controls">
              {sif?.isEnabled && (
                <div style={{ display: 'flex', alignItems: 'center', gap: 12, padding: '10px 14px', borderRadius: 10, background: 'rgba(255,255,255,0.04)', border: '1px solid var(--navy-border)' }}>
                  <span style={{ fontSize: 20 }}>🔄</span>
                  <div>
                    <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>Sign-in Frequency</div>
                    <div style={{ fontSize: 14, fontWeight: 600, color: 'var(--text-primary)' }}>{formatSignInFreq(sif)}</div>
                    {sif.authenticationType && <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 2 }}>{sif.authenticationType}</div>}
                  </div>
                </div>
              )}
              {pb?.isEnabled && (
                <div style={{ display: 'flex', alignItems: 'center', gap: 12, padding: '10px 14px', borderRadius: 10, background: 'rgba(255,255,255,0.04)', border: '1px solid var(--navy-border)' }}>
                  <span style={{ fontSize: 20 }}>🖥️</span>
                  <div>
                    <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>Persistent Browser Session</div>
                    <div style={{ fontSize: 14, fontWeight: 600, color: pb.mode === 'always' ? 'var(--green-clean)' : 'var(--red-critical)' }}>
                      {pb.mode === 'always' ? 'Always persist' : 'Never persist'}
                    </div>
                  </div>
                </div>
              )}
              {cas?.isEnabled && (
                <div style={{ display: 'flex', alignItems: 'center', gap: 12, padding: '10px 14px', borderRadius: 10, background: 'rgba(255,255,255,0.04)', border: '1px solid var(--navy-border)' }}>
                  <span style={{ fontSize: 20 }}>☁️</span>
                  <div>
                    <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>Cloud App Security</div>
                    <div style={{ fontSize: 14, fontWeight: 600, color: 'var(--text-primary)' }}>{cas.cloudAppSecuritySessionControlType || 'Enabled'}</div>
                  </div>
                </div>
              )}
              {aer?.isEnabled && (
                <div style={{ display: 'flex', alignItems: 'center', gap: 12, padding: '10px 14px', borderRadius: 10, background: 'rgba(255,255,255,0.04)', border: '1px solid var(--navy-border)' }}>
                  <span style={{ fontSize: 20 }}>📋</span>
                  <div>
                    <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>App-Enforced Restrictions</div>
                    <div style={{ fontSize: 14, fontWeight: 600, color: 'var(--text-primary)' }}>Enabled</div>
                  </div>
                </div>
              )}
            </DrawerSection>
          ) : null}

          {/* Raw JSON */}
          <details>
            <summary style={{ cursor: 'pointer', color: '#F5A462', fontSize: 13, userSelect: 'none', outline: 'none', padding: '4px 0' }}>Raw JSON</summary>
            <pre style={{ marginTop: 10, background: 'rgba(7,9,15,0.95)', border: '1px solid var(--navy-border)', borderRadius: 10, padding: '12px 14px', fontSize: 11, color: 'var(--text-secondary)', overflow: 'auto', whiteSpace: 'pre-wrap', wordBreak: 'break-word', fontFamily: 'var(--font-mono)', lineHeight: 1.6 }}>
              {JSON.stringify(policy, null, 2)}
            </pre>
          </details>
        </div>
      </div>
    </>
  );
}

export default function ConditionalAccessPage() {
  const [tab, setTab] = useState<CaTab>('policies');
  const [dismissedBanner, setDismissedBanner] = useState(false);
  const [permissionError, setPermissionError] = useState(false);

  // Policies tab
  const [policies, setPolicies] = useState<CaPolicy[]>([]);
  const [policiesLoading, setPoliciesLoading] = useState(false);
  const [policiesError, setPoliciesError] = useState('');
  const [togglingId, setTogglingId] = useState<string | null>(null);
  const [deletingId, setDeletingId] = useState<string | null>(null);
  const [deleteConfirmId, setDeleteConfirmId] = useState<string | null>(null);
  const [selectedPolicy, setSelectedPolicy] = useState<CaPolicy | null>(null);

  // Locations tab
  const [locations, setLocations] = useState<NamedLocation[]>([]);
  const [locationsLoading, setLocationsLoading] = useState(false);
  const [locationsError, setLocationsError] = useState('');

  // Quick actions
  const [blockIp, setBlockIp] = useState({ ip: '', locationName: '' });
  const [blockIpResult, setBlockIpResult] = useState<QuickActionResult | null>(null);
  const [blockIpBusy, setBlockIpBusy] = useState(false);

  const [mfaUser, setMfaUser] = useState({ userId: '', policyName: '' });
  const [mfaResult, setMfaResult] = useState<QuickActionResult | null>(null);
  const [mfaBusy, setMfaBusy] = useState(false);

  const [blockUser, setBlockUser] = useState({ userId: '', policyName: '' });
  const [blockUserResult, setBlockUserResult] = useState<QuickActionResult | null>(null);
  const [blockUserBusy, setBlockUserBusy] = useState(false);

  const handle403 = (err: any) => {
    if (err?.status === 403 || String(err?.message).includes('403') || String(err?.message).toLowerCase().includes('permission')) {
      setPermissionError(true);
    }
  };

  const loadPolicies = async () => {
    setPoliciesLoading(true);
    setPoliciesError('');
    try {
      const data = await apiFetch<any>('/identity/ca-policies');
      setPolicies(Array.isArray(data) ? data : (data?.value || []));
    } catch (err: any) {
      handle403(err);
      setPoliciesError(err?.message || 'Failed to load policies');
    } finally {
      setPoliciesLoading(false);
    }
  };

  const loadLocations = async () => {
    setLocationsLoading(true);
    setLocationsError('');
    try {
      const data = await apiFetch<any>('/identity/named-locations');
      setLocations(Array.isArray(data) ? data : (data?.value || []));
    } catch (err: any) {
      handle403(err);
      setLocationsError(err?.message || 'Failed to load named locations');
    } finally {
      setLocationsLoading(false);
    }
  };

  useEffect(() => {
    if (tab === 'policies') loadPolicies();
    if (tab === 'locations') loadLocations();
  }, [tab]);

  const togglePolicy = async (policy: CaPolicy) => {
    const newState = policy.state === 'enabled' ? 'disabled' : 'enabled';
    setTogglingId(policy.id);
    try {
      await apiFetch(`/identity/ca-policies/${policy.id}`, {
        method: 'PATCH',
        body: JSON.stringify({ state: newState }),
      });
      setPolicies(prev => prev.map(p => p.id === policy.id ? { ...p, state: newState } : p));
    } catch (err: any) {
      handle403(err);
    } finally {
      setTogglingId(null);
    }
  };

  const deletePolicy = async (id: string) => {
    setDeletingId(id);
    setDeleteConfirmId(null);
    try {
      await apiFetch(`/identity/ca-policies/${id}`, { method: 'DELETE' });
      setPolicies(prev => prev.filter(p => p.id !== id));
    } catch (err: any) {
      handle403(err);
    } finally {
      setDeletingId(null);
    }
  };

  const submitBlockIp = async () => {
    if (!blockIp.ip.trim()) return;
    setBlockIpBusy(true);
    setBlockIpResult(null);
    try {
      const res = await apiFetch<any>('/identity/block-ip', {
        method: 'POST',
        body: JSON.stringify({
          ipAddress: blockIp.ip.trim(),
          locationName: blockIp.locationName.trim() || 'IdentityMonitor-Blocked-IPs',
        }),
      });
      setBlockIpResult({ ok: true, message: res?.message || 'IP blocked successfully.' });
    } catch (err: any) {
      handle403(err);
      setBlockIpResult({ ok: false, message: err?.message || 'Failed to block IP.' });
    } finally {
      setBlockIpBusy(false);
    }
  };

  const submitMfa = async () => {
    if (!mfaUser.userId.trim()) return;
    setMfaBusy(true);
    setMfaResult(null);
    try {
      const res = await apiFetch<any>('/identity/require-mfa', {
        method: 'POST',
        body: JSON.stringify({
          userId: mfaUser.userId.trim(),
          policyName: mfaUser.policyName.trim() || undefined,
        }),
      });
      setMfaResult({ ok: true, message: res?.message || 'MFA policy applied successfully.' });
    } catch (err: any) {
      handle403(err);
      setMfaResult({ ok: false, message: err?.message || 'Failed to apply MFA policy.' });
    } finally {
      setMfaBusy(false);
    }
  };

  const submitBlockUser = async () => {
    if (!blockUser.userId.trim()) return;
    setBlockUserBusy(true);
    setBlockUserResult(null);
    try {
      const res = await apiFetch<any>('/identity/block-user', {
        method: 'POST',
        body: JSON.stringify({
          userId: blockUser.userId.trim(),
          policyName: blockUser.policyName.trim() || undefined,
        }),
      });
      setBlockUserResult({ ok: true, message: res?.message || 'User blocked successfully.' });
    } catch (err: any) {
      handle403(err);
      setBlockUserResult({ ok: false, message: err?.message || 'Failed to block user.' });
    } finally {
      setBlockUserBusy(false);
    }
  };

  const tabs: Array<{ id: CaTab; label: string; icon: string }> = [
    { id: 'policies', label: 'Policies', icon: 'ti-shield-lock' },
    { id: 'quickactions', label: 'Quick Actions', icon: 'ti-bolt' },
    { id: 'locations', label: 'Named Locations', icon: 'ti-map-pin' },
  ];

  return (
    <div>
      <div className="page-header">
        <div>
          <div className="page-title">Conditional Access</div>
          <div className="page-subtitle">Manage CA policies, block IPs, enforce MFA, and view named locations</div>
        </div>
      </div>

      {/* Permission warning banner */}
      {!dismissedBanner && (
        <div
          style={{
            background: 'rgba(245,166,35,0.12)',
            border: '1px solid var(--amber-400)',
            borderRadius: 8,
            padding: '10px 16px',
            marginBottom: 16,
            display: 'flex',
            alignItems: 'flex-start',
            gap: 12,
          }}
        >
          <span style={{ fontSize: 16 }}>ℹ️</span>
          <div style={{ flex: 1, fontSize: 13, color: 'var(--text-secondary)' }}>
            Conditional Access policies require{' '}
            <strong>Policy.ReadWrite.ConditionalAccess</strong> permission. If you see errors, go
            to Settings → re-grant admin consent.
          </div>
          <button
            className="btn btn-ghost btn-sm"
            onClick={() => setDismissedBanner(true)}
            style={{ flexShrink: 0 }}
          >
            ×
          </button>
        </div>
      )}

      {/* 403 permission error banner */}
      {permissionError && (
        <div
          style={{
            background: 'rgba(255,59,59,0.12)',
            border: '1px solid var(--red-critical)',
            borderRadius: 8,
            padding: '10px 16px',
            marginBottom: 16,
            fontSize: 13,
            color: 'var(--text-secondary)',
          }}
        >
          <strong>Missing permission:</strong> Policy.ReadWrite.ConditionalAccess — Re-grant
          admin consent to enable CA management.{' '}
          <a
            href="/api/auth/admin-consent?returnTo=/identity"
            style={{ color: 'var(--amber-400)', textDecoration: 'underline' }}
          >
            Re-grant admin consent
          </a>
        </div>
      )}

      {/* Tab bar */}
      <div
        style={{
          display: 'flex',
          gap: 6,
          marginBottom: 18,
          borderBottom: '1px solid var(--navy-border)',
          overflowX: 'auto',
          paddingBottom: 2,
        }}
      >
        {tabs.map(t => (
          <button
            key={t.id}
            onClick={() => setTab(t.id)}
            className={`btn btn-sm ${tab === t.id ? 'btn-primary' : 'btn-ghost'}`}
            style={{ whiteSpace: 'nowrap', display: 'flex', alignItems: 'center', gap: 5 }}
          >
            <i className={`ti ${t.icon}`} style={{ fontSize: 13 }}></i>{t.label}
          </button>
        ))}
      </div>

      {/* ── Policies tab ── */}
      {tab === 'policies' && (
        <div className="card">
          <div className="card-header">
            <div className="card-title">Conditional Access Policies</div>
            <button className="btn btn-ghost btn-sm" onClick={loadPolicies}>
              Refresh
            </button>
          </div>

          {policiesLoading && (
            <div className="loading-state">
              <div className="loading-spinner" />
            </div>
          )}

          {!policiesLoading && policiesError && (
            <div style={{ color: 'var(--red-critical)', fontSize: 13, padding: '12px 0' }}>
              {policiesError}
            </div>
          )}

          {!policiesLoading && !policiesError && policies.length === 0 && (
            <div className="empty-state">
              <div>No conditional access policies found.</div>
            </div>
          )}

          {!policiesLoading && policies.length > 0 && (
            <div style={{ overflowX: 'auto' }}>
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Policy Name</th>
                    <th>State</th>
                    <th>Conditions</th>
                    <th>Created / Modified</th>
                    <th style={{ width: 160 }}>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {policies.map(policy => (
                    <tr
                      key={policy.id}
                      onClick={() => { setSelectedPolicy(policy); setDeleteConfirmId(null); }}
                      style={{ cursor: 'pointer' }}
                    >
                      <td>
                        <span style={{ fontWeight: 600 }}>{policy.displayName}</span>
                        <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 2 }}>
                          {policy.id}
                        </div>
                      </td>
                      <td>
                        <StateBadge state={policy.state} />
                      </td>
                      <td>
                        <ConditionsSummary conditions={policy.conditions} />
                      </td>
                      <td style={{ fontSize: 12, color: 'var(--text-muted)' }}>
                        {policy.createdDateTime
                          ? new Date(policy.createdDateTime).toLocaleDateString()
                          : '—'}
                        {policy.modifiedDateTime && (
                          <div>
                            Mod: {new Date(policy.modifiedDateTime).toLocaleDateString()}
                          </div>
                        )}
                      </td>
                      <td onClick={e => e.stopPropagation()}>
                        <div style={{ display: 'flex', gap: 6 }}>
                          <button
                            className="btn btn-ghost btn-sm"
                            disabled={togglingId === policy.id}
                            onClick={() => togglePolicy(policy)}
                          >
                            {togglingId === policy.id
                              ? '…'
                              : policy.state === 'enabled'
                              ? 'Disable'
                              : 'Enable'}
                          </button>
                          {deleteConfirmId === policy.id ? (
                            <>
                              <button
                                className="btn btn-danger btn-sm"
                                disabled={deletingId === policy.id}
                                onClick={() => deletePolicy(policy.id)}
                              >
                                {deletingId === policy.id ? '…' : 'Confirm'}
                              </button>
                              <button
                                className="btn btn-ghost btn-sm"
                                onClick={() => setDeleteConfirmId(null)}
                              >
                                Cancel
                              </button>
                            </>
                          ) : (
                            <button
                              className="btn btn-danger btn-sm"
                              onClick={() => setDeleteConfirmId(policy.id)}
                            >
                              Delete
                            </button>
                          )}
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {/* ── Quick Actions tab ── */}
      {tab === 'quickactions' && (
        <div style={{ display: 'grid', gap: 16 }}>

          {/* Card 1: Block IP */}
          <div className="card">
            <div className="card-header">
              <div className="card-title">🚫 Block IP Address</div>
            </div>
            <div style={{ display: 'grid', gap: 10, maxWidth: 480 }}>
              <div>
                <label style={{ fontSize: 12, color: 'var(--text-muted)', display: 'block', marginBottom: 4 }}>
                  IP Address *
                </label>
                <input
                  className="input"
                  placeholder="e.g. 1.2.3.4 or 1.2.3.0/24"
                  value={blockIp.ip}
                  onChange={e => setBlockIp(prev => ({ ...prev, ip: e.target.value }))}
                />
              </div>
              <div>
                <label style={{ fontSize: 12, color: 'var(--text-muted)', display: 'block', marginBottom: 4 }}>
                  Named Location (optional, defaults to "IdentityMonitor-Blocked-IPs")
                </label>
                <input
                  className="input"
                  placeholder="IdentityMonitor-Blocked-IPs"
                  value={blockIp.locationName}
                  onChange={e => setBlockIp(prev => ({ ...prev, locationName: e.target.value }))}
                />
              </div>
              <div>
                <button
                  className="btn btn-primary"
                  disabled={blockIpBusy || !blockIp.ip.trim()}
                  onClick={submitBlockIp}
                >
                  {blockIpBusy ? 'Blocking…' : 'Block IP'}
                </button>
              </div>
              {blockIpResult && (
                <div
                  style={{
                    padding: '8px 12px',
                    borderRadius: 6,
                    fontSize: 13,
                    background: blockIpResult.ok ? 'rgba(46,204,113,0.12)' : 'rgba(255,59,59,0.12)',
                    border: `1px solid ${blockIpResult.ok ? 'var(--green-clean)' : 'var(--red-critical)'}`,
                    color: blockIpResult.ok ? 'var(--green-clean)' : 'var(--red-critical)',
                  }}
                >
                  {blockIpResult.message}
                </div>
              )}
            </div>
          </div>

          {/* Card 2: Require MFA */}
          <div className="card">
            <div className="card-header">
              <div className="card-title">🔐 Require MFA for User</div>
            </div>
            <div style={{ display: 'grid', gap: 10, maxWidth: 480 }}>
              <div>
                <label style={{ fontSize: 12, color: 'var(--text-muted)', display: 'block', marginBottom: 4 }}>
                  User ID (objectId or UPN) *
                </label>
                <input
                  className="input"
                  placeholder="user@company.com or object-id"
                  value={mfaUser.userId}
                  onChange={e => setMfaUser(prev => ({ ...prev, userId: e.target.value }))}
                />
              </div>
              <div>
                <label style={{ fontSize: 12, color: 'var(--text-muted)', display: 'block', marginBottom: 4 }}>
                  Policy Name (optional)
                </label>
                <input
                  className="input"
                  placeholder="e.g. Require-MFA-TargetedUser"
                  value={mfaUser.policyName}
                  onChange={e => setMfaUser(prev => ({ ...prev, policyName: e.target.value }))}
                />
              </div>
              <div>
                <button
                  className="btn btn-primary"
                  disabled={mfaBusy || !mfaUser.userId.trim()}
                  onClick={submitMfa}
                >
                  {mfaBusy ? 'Applying…' : 'Require MFA'}
                </button>
              </div>
              {mfaResult && (
                <div
                  style={{
                    padding: '8px 12px',
                    borderRadius: 6,
                    fontSize: 13,
                    background: mfaResult.ok ? 'rgba(46,204,113,0.12)' : 'rgba(255,59,59,0.12)',
                    border: `1px solid ${mfaResult.ok ? 'var(--green-clean)' : 'var(--red-critical)'}`,
                    color: mfaResult.ok ? 'var(--green-clean)' : 'var(--red-critical)',
                  }}
                >
                  {mfaResult.message}
                </div>
              )}
            </div>
          </div>

          {/* Card 3: Emergency Block User */}
          <div className="card" style={{ borderColor: 'var(--red-critical)' }}>
            <div className="card-header">
              <div className="card-title">🔒 Emergency Block User</div>
            </div>
            <div
              style={{
                padding: '8px 12px',
                marginBottom: 14,
                borderRadius: 6,
                background: 'rgba(255,59,59,0.10)',
                border: '1px solid var(--red-critical)',
                fontSize: 13,
                color: 'var(--red-critical)',
              }}
            >
              This blocks ALL sign-ins for the specified user immediately.
            </div>
            <div style={{ display: 'grid', gap: 10, maxWidth: 480 }}>
              <div>
                <label style={{ fontSize: 12, color: 'var(--text-muted)', display: 'block', marginBottom: 4 }}>
                  User ID (objectId or UPN) *
                </label>
                <input
                  className="input"
                  placeholder="user@company.com or object-id"
                  value={blockUser.userId}
                  onChange={e => setBlockUser(prev => ({ ...prev, userId: e.target.value }))}
                />
              </div>
              <div>
                <label style={{ fontSize: 12, color: 'var(--text-muted)', display: 'block', marginBottom: 4 }}>
                  Policy Name (optional)
                </label>
                <input
                  className="input"
                  placeholder="e.g. Emergency-Block-User"
                  value={blockUser.policyName}
                  onChange={e => setBlockUser(prev => ({ ...prev, policyName: e.target.value }))}
                />
              </div>
              <div>
                <button
                  className="btn btn-danger"
                  disabled={blockUserBusy || !blockUser.userId.trim()}
                  onClick={submitBlockUser}
                >
                  {blockUserBusy ? 'Blocking…' : 'Emergency Block'}
                </button>
              </div>
              {blockUserResult && (
                <div
                  style={{
                    padding: '8px 12px',
                    borderRadius: 6,
                    fontSize: 13,
                    background: blockUserResult.ok ? 'rgba(46,204,113,0.12)' : 'rgba(255,59,59,0.12)',
                    border: `1px solid ${blockUserResult.ok ? 'var(--green-clean)' : 'var(--red-critical)'}`,
                    color: blockUserResult.ok ? 'var(--green-clean)' : 'var(--red-critical)',
                  }}
                >
                  {blockUserResult.message}
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Policy detail drawer */}
      {selectedPolicy && (
        <PolicyDetailDrawer
          policy={selectedPolicy}
          onClose={() => { setSelectedPolicy(null); setDeleteConfirmId(null); }}
          onToggle={p => { togglePolicy(p); setSelectedPolicy(prev => prev ? { ...prev, state: prev.state === 'enabled' ? 'disabled' : 'enabled' } : null); }}
          toggling={togglingId === selectedPolicy.id}
          onDeleteClick={() => setDeleteConfirmId(selectedPolicy.id)}
          onDeleteConfirm={() => { deletePolicy(selectedPolicy.id); setSelectedPolicy(null); }}
          onDeleteCancel={() => setDeleteConfirmId(null)}
          deleteConfirm={deleteConfirmId === selectedPolicy.id}
          deleting={deletingId === selectedPolicy.id}
        />
      )}

      {/* ── Named Locations tab ── */}
      {tab === 'locations' && (
        <div className="card">
          <div className="card-header">
            <div className="card-title">Named Locations</div>
            <button className="btn btn-ghost btn-sm" onClick={loadLocations}>
              Refresh
            </button>
          </div>

          {locationsLoading && (
            <div className="loading-state">
              <div className="loading-spinner" />
            </div>
          )}

          {!locationsLoading && locationsError && (
            <div style={{ color: 'var(--red-critical)', fontSize: 13, padding: '12px 0' }}>
              {locationsError}
            </div>
          )}

          {!locationsLoading && !locationsError && locations.length === 0 && (
            <div className="empty-state">
              <div>No named locations found.</div>
            </div>
          )}

          {!locationsLoading && locations.length > 0 && (
            <div style={{ display: 'grid', gap: 12 }}>
              {locations.map(loc => {
                const isIp =
                  loc['@odata.type'] === '#microsoft.graph.ipNamedLocation' ||
                  Array.isArray(loc.ipRanges);
                const isCountry =
                  loc['@odata.type'] === '#microsoft.graph.countryNamedLocation' ||
                  Array.isArray(loc.countriesAndRegions);

                return (
                  <div
                    key={loc.id}
                    style={{
                      padding: '12px 14px',
                      borderRadius: 8,
                      border: '1px solid var(--navy-border)',
                      background: 'var(--navy-800)',
                    }}
                  >
                    <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 8 }}>
                      <span style={{ fontSize: 16 }}>{isIp ? '🌐' : '🗺️'}</span>
                      <span style={{ fontWeight: 600 }}>{loc.displayName}</span>
                      {loc.isTrusted && (
                        <span
                          className="severity-badge"
                          style={{ background: 'var(--green-clean)', color: '#fff', fontSize: 10 }}
                        >
                          Trusted
                        </span>
                      )}
                    </div>

                    {isIp && loc.ipRanges && loc.ipRanges.length > 0 && (
                      <div>
                        <div
                          style={{
                            fontSize: 11,
                            color: 'var(--text-muted)',
                            textTransform: 'uppercase',
                            letterSpacing: '0.5px',
                            marginBottom: 6,
                          }}
                        >
                          IP Ranges ({loc.ipRanges.length})
                        </div>
                        <pre
                          style={{
                            fontFamily: 'var(--font-mono)',
                            fontSize: 12,
                            background: 'rgba(0,0,0,0.25)',
                            padding: '8px 10px',
                            borderRadius: 6,
                            margin: 0,
                            overflowX: 'auto',
                            color: 'var(--text-secondary)',
                          }}
                        >
                          {loc.ipRanges.map(r => r.cidrAddress).join('\n')}
                        </pre>
                      </div>
                    )}

                    {isCountry && loc.countriesAndRegions && loc.countriesAndRegions.length > 0 && (
                      <div>
                        <div
                          style={{
                            fontSize: 11,
                            color: 'var(--text-muted)',
                            textTransform: 'uppercase',
                            letterSpacing: '0.5px',
                            marginBottom: 6,
                          }}
                        >
                          Countries ({loc.countriesAndRegions.length})
                        </div>
                        <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
                          {loc.countriesAndRegions.map(cc => (
                            <span
                              key={cc}
                              className="role-tag"
                              style={{ fontSize: 12 }}
                            >
                              {cc}
                            </span>
                          ))}
                        </div>
                      </div>
                    )}

                    {!isIp && !isCountry && (
                      <div style={{ fontSize: 12, color: 'var(--text-muted)' }}>
                        {loc['@odata.type'] || 'Unknown location type'}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
