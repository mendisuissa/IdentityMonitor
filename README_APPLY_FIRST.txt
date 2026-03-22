IdentityMonitor remediation delta

Included files:
- backend/src/routes/remediation.js
- backend/src/services/nativeRemediationExecutor.js
- frontend/src/components/RemediationPage.tsx
- frontend/src/services/api.ts

What this delta adds:
1) Full remediation execution matrix
   - application -> webapp external remediation
   - windows-update -> native execute via Graph Windows Updates
   - intune-policy -> native guided queued execution
   - script -> native guided queued execution
   - manual -> guided manual

2) Windows Update execution
   - Supports update type: security / feature
   - Supports reboot behavior: ifRequired / force / defer
   - Requires Microsoft Entra device IDs
   - Creates deployment + assigns audience via Graph beta

3) Intune / Script execution
   - Queued guided execution result with taskId / queuedAt / summary
   - Keeps current product UX clean without pretending live Graph mutation exists yet

4) Remediation health in UI
   - Frontend now calls GET /api/remediation/health
   - Shows external remediation connector state and Retry connection button

5) Quick filters preserved
   - Remediation required only
   - Exposed devices only

6) UI cleanup
   - Keeps the current look from your latest ZIP
   - Technical JSON moved into collapsible Technical details
   - Execution result shows message first, then raw details

Validation performed:
- node --check backend/src/routes/remediation.js
- node --check backend/src/services/nativeRemediationExecutor.js
- frontend npm run build -> passed

Important env for native Windows Update execute:
- CLIENT_ID
- CLIENT_SECRET
- App registration with Microsoft Graph Windows Updates permissions
- Valid Entra device IDs in the execute form

Important env for external application remediation:
- WEBAPP_REMEDIATION_BASE_URL
- WEBAPP_REMEDIATION_TOKEN
