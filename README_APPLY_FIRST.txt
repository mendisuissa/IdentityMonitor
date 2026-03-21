IdentityMonitor delta

Files included:
- backend/src/routes/remediation.js
- backend/src/services/nativeRemediationExecutor.js
- frontend/src/components/RemediationPage.tsx

What this delta adds:
- External remediation / bundle UX
- Result card + status badges
- Execution path rendering
- Classification matrix routing
- Native executor skeletons for Windows Update / Intune Policy / Script
- Windows Update options: update type + reboot behavior

Validation completed:
- frontend npm run build: passed
- backend node --check: passed

Apply by copying these files over the matching paths in your repo.
