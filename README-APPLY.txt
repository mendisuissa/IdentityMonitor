IdentityMonitor - Windows Update direct execution delta

Files included:
- backend/src/services/remediationCatalog.js
- backend/src/services/nativeRemediationExecutor.js
- frontend/src/components/RemediationPage.tsx
- frontend/src/services/api.ts

What changed:
1. Better classifier for Windows/platform CVEs (including Windows Telephony Service / privilege escalation style findings).
2. Windows Update execution can now use exposed device names from Defender directly, so the UI no longer requires Entra device IDs for the common case.
3. The remediation UI now passes affected device names into plan/execute requests.
4. External state is shown only for the Webapp executor, so Windows Update findings no longer look like an external connectivity problem.
5. Windows Update input text now clearly states that device IDs are optional.

Validation notes:
- Backend syntax was checked with node -c for the modified backend files.
- Frontend full build is currently blocked by an existing missing dependency in this repo: date-fns.
- No new dependency was added by this delta.
