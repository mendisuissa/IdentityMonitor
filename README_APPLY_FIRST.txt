Apply these files on top of the current IdentityMonitor repo.

Files included:
- backend/src/services/tenantDefenderClient.js
- frontend/src/components/RemediationPage.tsx

What this fixes:
- switches Defender software enrichment to the official machinesVulnerabilities API path
- maps productName / productVendor / machineName fields correctly
- aggregates affected machines by unique machineId
- keeps related products per CVE so a CVE affecting Edge/Chrome/WebView2 no longer shows as Unknown product
- improves remediation product display in the UI

Validation performed:
- node --check backend/src/services/tenantDefenderClient.js
- frontend npm run build
