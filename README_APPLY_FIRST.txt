Apply this delta on top of your latest ZIP baseline.

Included:
- frontend/src/components/RemediationPage.tsx

What this delta does:
- Restores the cleaner Defender-style tabbed remediation UI
- Keeps the quick filters:
  - Remediation required only
  - Exposed devices only
- Keeps the current planning / execute wiring
- Keeps Windows Update / Intune / Script controls inside the Plan tab
- Moves raw JSON under collapsed Technical details

What it does NOT change:
- backend routes
- token flow
- defender mapping
- external connector logic
