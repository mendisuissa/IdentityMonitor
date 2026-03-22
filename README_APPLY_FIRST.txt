Apply these files over your current IdentityMonitor project.

Files included:
- backend/src/services/tenantDefenderClient.js
- backend/src/services/remediationCatalog.js

What this fixes:
- Stops forcing every Defender vulnerability into category=application
- Improves classification order so windows-update / intune-policy / script are matched before application
- Preserves the current UI
