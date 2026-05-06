# IdentityMonitor — Security & Privacy Architecture

**Document version:** 1.0  
**Date:** 2026-05-05  
**Scope:** Backend (Node.js/Express on Azure App Service) + Frontend (React SPA)

---

## 1. Data Architecture & Tenant Isolation

IdentityMonitor is a **multi-tenant SaaS** platform. Every piece of data is scoped to a `tenantId` derived from the authenticated Microsoft Entra session.

### Storage Layout (Azure Table Storage)

| Table | PartitionKey | RowKey | Contains |
|-------|-------------|--------|----------|
| `alerts` | `tenantId` | `alertId` | Security alerts, anomaly details |
| `baselines` | `tenantId` | `userId` | Behavioral baselines per user |
| `tenants` (profile rows) | `profile` | `tenantId` | Tenant name, contact email, last-seen |
| `tenants` (settings rows) | `settings` | `tenantId` | All configuration |
| `webhooks` | `tenantId` | `subscriptionId` | Graph webhook subscriptions |
| `incidents` | `tenantId` | `incidentId` | Incident records |
| `workflows` | `tenantId` | `workflowId` | Workflow/approval state |
| `TenantIntegrations` | `TENANT` | `tenantId` | Defender credentials, shared tokens |

**Isolation guarantee:** All queries include a `PartitionKey eq '<tenantId>'` filter. No query ever returns rows from a different partition. There is no cross-tenant JOIN or shared row.

### Session Isolation

Each HTTP session stores `req.session.tenant.tenantId`. All route handlers call `req.session?.tenant?.tenantId` to determine the acting tenant. A session cannot reference another tenant's `tenantId` unless the user authenticates with that tenant's credentials.

Sessions are stored on the filesystem (`/home/sessions` in production) with:
- 24-hour TTL (`SESSION_TTL_SEC = 86400`)
- `httpOnly: true` cookies (not accessible to JavaScript)
- `secure: true` in production (HTTPS only)
- `sameSite: 'lax'` (CSRF mitigation)
- `rolling: true` (extended on every authenticated request)

---

## 2. Encryption at Rest

### Secret Fields

The following fields are encrypted with **AES-256-GCM** before being written to Azure Table Storage, and decrypted on read:

| Field | Location |
|-------|----------|
| `defenderClientSecret` | `TenantIntegrations` table |
| `sharedToken` | `TenantIntegrations` table |
| `telegramBotToken` | `tenants/settings` table |

**Cipher:** AES-256-GCM  
**Key derivation:** If `ENCRYPTION_KEY` is a 64-hex-character string it is used directly as 32 raw bytes. Otherwise it is derived with `scrypt(key, 'identitymonitor-salt-v1', 32)`.  
**Format:** `enc:v1:<iv_hex>:<auth_tag_hex>:<ciphertext_hex>`  
**IV:** 16 bytes, cryptographically random per encryption.  
**Auth tag:** 16 bytes (GCM integrity check — tampered ciphertext is rejected at decrypt time).

**Backward compatibility:** The `decrypt()` function returns plaintext as-is if the value does not carry the `enc:v1:` prefix. Legacy plaintext values are re-encrypted the next time they are written.

### Environment Variables Required

| Variable | Purpose |
|----------|---------|
| `ENCRYPTION_KEY` | 64-char hex string (256-bit key) — generate with `openssl rand -hex 32` |
| `SESSION_SECRET` | Random string for Express session signing |
| `AZURE_STORAGE_CONNECTION_STRING` | Azure Storage access |

---

## 3. Encryption in Transit

- All production traffic uses **HTTPS** enforced by Azure App Service.
- The Express session cookie is set to `secure: true` in production — browsers will not send it over plain HTTP.
- Calls to the Microsoft Graph API and Defender APIs use the Azure SDK / `node-fetch` over TLS 1.2+.
- Telegram Bot API calls use HTTPS.

---

## 4. Authentication & Authorization

### Authentication Flow

1. User clicks "Sign in" → redirected to `login.microsoftonline.com` (Microsoft Entra OAuth2 / MSAL).
2. Entra issues tokens; the backend exchanges the auth code for an access token.
3. The backend writes `req.session.tenant` with `{ tenantId, userEmail, role, ... }`.
4. All subsequent API calls carry the session cookie — no tokens are stored client-side.

### Role-Based Access Control

Access to every API endpoint is gated by `requirePermission(permission)` middleware (see `accessControl.js`). The role matrix defines which roles have which permissions:

| Role | Can do |
|------|--------|
| `owner` | All actions including GDPR erasure, billing, admin management |
| `admin` | Settings, whitelist, detection rules, policy, response |
| `responder` | Alerts, incidents, remediation actions |
| `analyst` | Read-only: alerts, audit, reports |
| `msp_operator` | Multi-tenant sweep, orchestration |

Roles are stored in the session on login; the access control check runs server-side on every request.

### Microsoft App Registration (Defender Integration)

- The app supports **per-tenant app registration** or a **shared multi-tenant app**.
- `defenderClientSecret` is encrypted at rest (AES-256-GCM) and never returned to the frontend.
- Client credentials are exchanged for short-lived access tokens using the Microsoft Identity platform; tokens are not persisted.

---

## 5. PII Handling

### Data Collected

| Data type | Where stored | Retention |
|-----------|-------------|-----------|
| User Principal Names (UPNs) | Alert records (Azure Table Storage) | Configurable (default 180 days) |
| IP addresses | Alert records | Configurable (default 180 days) |
| Device names / IDs | Alert records, baselines | Configurable (default 180 days) |
| Sign-in timestamps | Alert records, baselines | Configurable (default 180 days) |
| Admin email addresses | Settings table | Until manually removed |
| Tenant contact email | Tenant profile | Until erasure |

### PII in Logs

Console log output does **not** contain UPNs, email addresses, or IP addresses. Where user-specific context is needed in a log line, only the opaque `userId` (a GUID from Entra) is used. This prevents PII from appearing in Azure App Service log streams.

---

## 6. Data Retention

Retention periods are configurable per tenant in **Settings → Retention Policy**:

| Category | Default | Configurable |
|----------|---------|-------------|
| Incidents / Alerts | 180 days | Yes |
| Audit logs | 365 days | Yes |
| Reports | 365 days | Yes |

**Enforcement:** A background cron job runs every night at 02:00 UTC and deletes alert rows whose `detectedAt` timestamp is older than the configured `incidentDays` cutoff. This runs automatically for every active tenant.

---

## 7. GDPR Compliance

### Lawful Basis

IdentityMonitor processes personal data (UPNs, IP addresses, sign-in events) under the **legitimate interest** of the data controller (the customer organisation) to protect against identity-based threats, and under **contract** (the SaaS service agreement).

### Data Subject Rights

| Right | Implementation |
|-------|---------------|
| Right of access | Tenant admins can export all alert and audit data from the UI |
| Right to rectification | Alert records can be updated/dismissed |
| Right to erasure | `DELETE /api/settings/tenant-data` — permanently deletes all Azure Table Storage data for the tenant (alerts, baselines, settings, integrations, webhooks, incidents, workflows, tenant profile). Only the `owner` role may trigger this. |
| Right to restriction | Tenant can disable all detection rules and stop data collection |
| Data portability | Audit log CSV export available at Settings → Audit → Export |

### Sub-processors

| Sub-processor | Purpose | Location |
|--------------|---------|----------|
| Microsoft Azure | Table Storage, App Service hosting | EU regions configurable |
| Microsoft Graph / Entra | Authentication, sign-in log access | Microsoft DPA |
| Telegram (optional) | Alert notifications | User-configurable; disable if not needed |
| SendGrid / email provider | Admin email alerts | User-configurable |

### Data Processing Agreement

Customers must execute a DPA with Anthropic/the operator before deploying in production for EU data subjects. Azure has a pre-signed DPA available through the Microsoft Products and Services Agreement.

---

## 8. Audit Logging

Every write action (settings change, whitelist update, alert resolution, admin added/removed, GDPR erasure) is written to the in-memory + Azure-backed audit log with:

- `timestamp` (ISO 8601)
- `action` (e.g. `settings.updated`, `gdpr.erasure_completed`)
- `actor` (user email from session)
- `details` (structured JSON, no raw PII beyond what is intrinsic to the action)

Audit logs are retained for the configured `auditDays` (default 365 days) and can be exported as CSV by users with the `audit.export` permission.

---

## 9. Secrets Management

### Required Secrets (Azure App Service → Configuration → Application Settings)

```
ENCRYPTION_KEY=<64-char hex>           # generate: openssl rand -hex 32
SESSION_SECRET=<random string>          # generate: openssl rand -base64 32
AZURE_STORAGE_CONNECTION_STRING=<...>
CLIENT_ID=<Entra app client id>
CLIENT_SECRET=<Entra app client secret>
TENANT_ID=<your Entra tenant id>
REDIRECT_URI=https://<your-domain>/api/auth/callback
```

### Optional Secrets

```
TELEGRAM_BOT_TOKEN=<...>              # default Telegram bot (overridden per tenant)
TELEGRAM_CHAT_ID=<...>
DEFENDER_SHARED_CLIENT_ID=<...>       # shared Defender app (if not per-tenant)
DEFENDER_SHARED_CLIENT_SECRET=<...>
BILLING_DISABLED=true                 # for self-hosted / dev environments
```

**Never commit secrets to source control.** Use `.env` for local development (gitignored) and Azure App Service Application Settings for production.

---

## 10. Vulnerability & Dependency Management

- Dependencies are managed with `npm`. Run `npm audit` regularly and apply patches promptly.
- The GitHub Actions CI pipeline (`deploy.yml`) builds from source on every push to `main`.
- No third-party scripts are loaded from CDNs in the frontend — all dependencies are bundled at build time via Vite.

---

## 11. Incident Response

If you suspect a security incident (data breach, unauthorised access):

1. Rotate `ENCRYPTION_KEY` and `SESSION_SECRET` immediately in Azure App Service settings — this invalidates all active sessions and re-keying will re-encrypt secrets on next write.
2. Revoke the Entra app registration client secret and issue a new one.
3. Review the audit log at `Settings → Audit` for suspicious actions.
4. If data exfiltration is suspected, invoke the GDPR erasure endpoint (`DELETE /api/settings/tenant-data`) for affected tenants, or delete the Azure Storage tables directly.
5. Notify affected data subjects within 72 hours as required by GDPR Article 33.

---

## 12. Security Contact

To report a security vulnerability, email: **mendi20018@gmail.com**

Please do not disclose security vulnerabilities in public GitHub issues.
