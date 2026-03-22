Delta purpose:
- Fix Defender field mapping for vulnerability remediation.
- Use the official Defender endpoint for per-machine/per-software enrichment.
- Populate affected device count from exposedMachines on /api/vulnerabilities.
- Preserve multiple affected products per CVE and show them in the UI.

Files included:
- backend/src/services/tenantDefenderClient.js
- frontend/src/components/RemediationPage.tsx

Key fixes:
1) tenantDefenderClient.js
   - changed software enrichment source from:
     /api/machines/SoftwareVulnerabilitiesByMachine
     to:
     /api/vulnerabilities/machinesVulnerabilities
   - maps affectedMachineCount from raw.exposedMachines when returned by /api/vulnerabilities
   - keeps relatedProducts[] and productNames[] per CVE
   - de-duplicates machines by machineId/device name

2) RemediationPage.tsx
   - product column now shows primary product plus (+N more)
   - plan details now show Related products when Defender reports multiple products

Validation performed:
- node --check backend/src/services/tenantDefenderClient.js

Important note:
- I did not claim a full frontend build here because the uploaded zip does not include installed dependencies.
