Apply this delta on top of your current UI baseline.

Files included:
- backend/src/services/remediationCatalog.js
- backend/src/services/nativeRemediationExecutor.js
- backend/src/routes/remediation.js

What it does:
- Preserves the current tabbed Remediation UI (no frontend files changed)
- Improves classification for windows-update / intune-policy / script before generic application matching
- Enables Windows Update live execution through Graph beta deployment flow
- Keeps Intune Policy and Script as native queued execution with taskId / queuedAt / summary
- Extends /api/remediation/health to include external connector status

Important for Windows Update live execution:
- CLIENT_ID and CLIENT_SECRET must be configured
- App registration needs Graph permissions for Windows Update deployment
- Use Microsoft Entra device IDs when executing Windows Update
