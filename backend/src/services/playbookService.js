// playbookService.js — Smart playbooks per anomaly type
// Each anomaly gets a tailored response plan

const PLAYBOOKS = {

  IMPOSSIBLE_TRAVEL: {
    name: 'Impossible Travel Response',
    severity: 'critical',
    steps: [
      { order: 1, action: 'REVOKE_SESSIONS',    label: 'Revoke all active sessions',         auto: true,  description: 'Immediately terminate all sessions to force re-authentication' },
      { order: 2, action: 'NOTIFY_USER',         label: 'Notify the affected admin',           auto: true,  description: 'Send security alert email to the admin account' },
      { order: 3, action: 'TELEGRAM_ALERT',      label: 'Send Telegram playbook alert',        auto: true,  description: 'Alert security team with approve/deny buttons' },
      { order: 4, action: 'REQUIRE_MFA',         label: 'Force MFA on next sign-in',           auto: false, description: 'Conditional access will prompt MFA on re-authentication' },
      { order: 5, action: 'INVESTIGATE',         label: 'Investigate sign-in logs',            auto: false, description: 'Review full sign-in history for this user in the last 7 days' },
      { order: 6, action: 'CONSIDER_DISABLE',    label: 'Consider temporary account disable',  auto: false, description: 'If investigation confirms breach, disable the account', requiresApproval: true }
    ],
    blastRadius: 'An attacker with Global Admin access can read all data, add new admins, disable MFA, and exfiltrate the entire tenant.',
    whyItMatters: 'Impossible travel indicates credential theft or VPN/proxy usage. Either way, immediate action is required.'
  },

  NEW_COUNTRY: {
    name: 'New Country Sign-in Response',
    severity: 'high',
    steps: [
      { order: 1, action: 'TELEGRAM_ALERT',  label: 'Alert security team',              auto: true,  description: 'Notify with country details and approve/deny buttons' },
      { order: 2, action: 'NOTIFY_USER',     label: 'Notify admin — confirm legitimacy', auto: true,  description: 'Ask the admin if they are traveling' },
      { order: 3, action: 'REVOKE_SESSIONS', label: 'Revoke sessions if unconfirmed',   auto: false, description: 'Revoke only if admin cannot confirm the sign-in' },
      { order: 4, action: 'WHITELIST',       label: 'Add to country whitelist if OK',   auto: false, description: 'If admin confirms travel, whitelist the country' }
    ],
    blastRadius: 'Unknown country sign-ins may indicate account sharing, credential theft, or compromised device.',
    whyItMatters: 'First-time country access is one of the strongest indicators of credential compromise.'
  },

  UNKNOWN_DEVICE: {
    name: 'Unknown Device Response',
    severity: 'medium',
    steps: [
      { order: 1, action: 'LOG_EVENT',       label: 'Log and monitor',                  auto: true,  description: 'Record device details for baseline comparison' },
      { order: 2, action: 'NOTIFY_USER',     label: 'Notify admin — confirm device',    auto: true,  description: 'Ask admin to confirm they used this device' },
      { order: 3, action: 'TELEGRAM_ALERT',  label: 'Alert security team',              auto: false, description: 'Only if device cannot be confirmed' },
      { order: 4, action: 'REVOKE_SESSIONS', label: 'Revoke sessions if unconfirmed',   auto: false, description: 'Only if admin denies using this device' }
    ],
    blastRadius: 'Unmanaged devices may lack security controls and could be compromised.',
    whyItMatters: 'Privileged access from unmanaged devices bypasses endpoint security policies.'
  },

  HIGH_RISK: {
    name: 'High Entra Risk Response',
    severity: 'critical',
    steps: [
      { order: 1, action: 'REVOKE_SESSIONS', label: 'Revoke all sessions immediately',  auto: true,  description: 'Entra has detected high-risk signals — act immediately' },
      { order: 2, action: 'TELEGRAM_ALERT',  label: 'Emergency alert to security team', auto: true,  description: 'High-priority Telegram alert with full context' },
      { order: 3, action: 'NOTIFY_USER',     label: 'Notify affected admin',            auto: true,  description: 'Alert admin to change password and check activity' },
      { order: 4, action: 'INVESTIGATE',     label: 'Review Entra risk details',        auto: false, description: 'Check Entra Identity Protection for specific risk signals' },
      { order: 5, action: 'CONSIDER_DISABLE', label: 'Disable account pending investigation', auto: false, description: 'Disable until risk is remediated', requiresApproval: true }
    ],
    blastRadius: 'Microsoft has flagged this sign-in as high risk — potential active attack in progress.',
    whyItMatters: 'Entra risk scores incorporate real-time threat intelligence including leaked credential databases.'
  },

  HIGH_VELOCITY: {
    name: 'Sign-in Velocity Response',
    severity: 'high',
    steps: [
      { order: 1, action: 'LOG_EVENT',       label: 'Log velocity event',               auto: true,  description: 'Multiple sign-ins may indicate automated attack' },
      { order: 2, action: 'TELEGRAM_ALERT',  label: 'Alert security team',              auto: true,  description: 'Notify with velocity count and IP details' },
      { order: 3, action: 'REVOKE_SESSIONS', label: 'Revoke if confirmed attack',       auto: false, description: 'Revoke if IPs look like credential stuffing' }
    ],
    blastRadius: 'Credential stuffing or password spray attacks target admin accounts.',
    whyItMatters: '4+ sign-ins in 10 minutes is a strong indicator of automated attack tools.'
  }
};

function getPlaybook(anomalyType) {
  return PLAYBOOKS[anomalyType] || PLAYBOOKS['NEW_COUNTRY'];
}

function getAllPlaybooks() { return PLAYBOOKS; }

module.exports = { getPlaybook, getAllPlaybooks, PLAYBOOKS };
