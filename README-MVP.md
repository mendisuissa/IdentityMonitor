# Remediation MVP Pack (Fixed)

This pack wires **IdentityMonitor** to **Webapp** for application vulnerability remediation.

## What this MVP does

- `IdentityMonitor` resolves a vulnerability finding into a remediation plan.
- If the finding maps to an application supported by the catalog, it routes execution to `Webapp`.
- `Webapp` accepts the request and returns a queued remediation job response.

## Included files

### IdentityMonitor
- `backend/src/routes/remediation.js`
- `backend/src/services/remediationCatalog.js`
- `backend/src/services/webappExecutionClient.js`

### Webapp
- `apps/api/src/routes/remediation.ts`

## IdentityMonitor wiring

In your backend entry file, add:

```js
const remediationRouter = require('./routes/remediation');
app.use('/api/remediation', remediationRouter);
```

And set environment variables:

```env
WEBAPP_REMEDIATION_URL=https://app.modernendpoint.tech
WEBAPP_REMEDIATION_TOKEN=your-shared-token
```

## Webapp wiring

In your API router bootstrap, mount the new remediation route:

```ts
import remediationRouter from './routes/remediation';
app.use('/api/remediation', remediationRouter);
```

And set:

```env
REMEDIATION_SHARED_TOKEN=your-shared-token
```

## Example test payload

POST to `IdentityMonitor /api/remediation/execute`

```json
{
  "tenantId": "tenant-demo",
  "approvalId": "apr_001",
  "devices": ["device-a", "device-b"],
  "finding": {
    "cveId": "CVE-2026-12345",
    "productName": "Google Chrome",
    "recommendation": "Update Google Chrome to the latest version"
  }
}
```

## Notes

- This is intentionally a **safe MVP stub**.
- The Webapp route currently returns a queued job response and does not yet build or assign the actual Intune remediation package.
- The catalog currently includes Chrome, Edge, and 7-Zip to show the pattern.
