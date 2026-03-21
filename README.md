# Privileged Identity Monitor
### Modern Endpoint — Security Operations

Real-time anomaly detection and alerting for privileged Entra ID accounts (Global Admin, Intune Admin).

---

## What It Does

- **Monitors** all users with Global Admin, Intune Admin, Cloud Device Admin, or Privileged Role Admin roles
- **Detects** behavioral anomalies: new IP, new country, unknown device, impossible travel, off-hours sign-ins, high Entra risk score
- **Alerts** via email (Graph API Send Mail) to the security admin
- **Responds** automatically: revokes sessions (forces MFA re-auth) on critical/high severity
- **Notifies** the affected user directly
- **Scans** automatically every 15 minutes via cron job

---

## Architecture

```
Azure App Service
├── Node.js/Express Backend
│   ├── GET  /api/users              — privileged users + risk level
│   ├── GET  /api/users/:id/signins  — sign-in history
│   ├── POST /api/users/:id/revoke   — revoke sessions (force MFA)
│   ├── GET  /api/alerts             — all anomaly alerts
│   ├── GET  /api/alerts/stats       — summary counts
│   ├── POST /api/alerts/scan        — manual scan trigger
│   └── GET  /api/signins            — all privileged sign-ins
└── React Frontend (served from /public)
    ├── Dashboard    — stats, recent alerts, at-risk users
    ├── Users        — full privileged user list + revoke action
    ├── Alerts       — alert management with expand/resolve/dismiss
    └── Sign-in Logs — raw authentication events
```

---

## Entra ID App Registration Setup

### 1. Create App Registration

1. Go to **Entra Admin Center** → App registrations → New registration
2. Name: `Privileged Identity Monitor`
3. Supported account type: Single tenant
4. No redirect URI needed (service principal)

### 2. API Permissions (Application, not Delegated)

| Permission | Type | Purpose |
|---|---|---|
| `AuditLog.Read.All` | Application | Read sign-in logs |
| `Directory.Read.All` | Application | List directory roles & members |
| `Mail.Send` | Application | Send alert emails |
| `User.Read.All` | Application | Read user details |
| `RoleManagement.Read.Directory` | Application | Read role assignments |
| `UserAuthenticationMethod.ReadWrite.All` | Application | MFA enforcement (optional) |

> Click **Grant admin consent** for all permissions.

### 3. Create Client Secret

App registration → Certificates & secrets → New client secret → Copy value immediately.

---

## Local Development

### Backend

```bash
cd backend
cp .env.example .env
# Fill in TENANT_ID, CLIENT_ID, CLIENT_SECRET, ALERT_SENDER_EMAIL, ALERT_ADMIN_EMAIL
npm install
npm run dev
```

### Frontend

```bash
cd frontend
npm install
npm run dev
# Opens at http://localhost:5173
# Proxies /api to http://localhost:3001
```

---

## Azure Deployment

### Required GitHub Secrets

| Secret | Value |
|---|---|
| `AZURE_APP_NAME` | Your Azure App Service name |
| `AZURE_PUBLISH_PROFILE` | Download from App Service → Get publish profile |

### Azure App Service Configuration (Application Settings)

Set these in **Configuration → Application settings**:

```
TENANT_ID          = your-tenant-id
CLIENT_ID          = your-client-id
CLIENT_SECRET      = your-client-secret
ALERT_SENDER_EMAIL = alerts@yourdomain.com
ALERT_ADMIN_EMAIL  = secops@yourdomain.com
NODE_ENV           = production
SESSION_SECRET     = (generate a random 32+ char string)
```

### Deploy

Push to `main` branch — GitHub Actions handles the rest.

---

## Anomaly Detection Logic

| Anomaly | Severity | Trigger |
|---|---|---|
| New IP Address | Medium | IP not seen in user's last 30 sign-ins |
| New Country | High | Country not in user's history |
| Unknown Device | Medium | Device ID not in user's known devices |
| Impossible Travel | Critical | Physical distance vs time exceeds ~900 km/h |
| Off-Hours Sign-in | Low | Sign-in between 22:00–06:00 UTC |
| High Risk (Entra) | Critical | Entra ID risk level = high |
| Medium Risk (Entra) | High | Entra ID risk level = medium |

### Automatic Response by Severity

| Severity | Admin Email | Revoke Sessions | User Notification |
|---|---|---|---|
| Critical | ✓ | ✓ | ✓ |
| High | ✓ | ✓ | ✓ |
| Medium | ✓ | ✗ | ✗ |
| Low | ✓ | ✗ | ✗ |

---

## Notes

- Baseline is built in-memory and resets on app restart. For production persistence, replace `alertsStore.js` with Azure Table Storage or CosmosDB.
- The cron scan runs every 15 minutes and checks the last 48 hours of sign-in data.
- Sign-in logs require an Entra ID P1 or P2 license.
- `Mail.Send` requires the sender mailbox (`ALERT_SENDER_EMAIL`) to exist in the tenant.
