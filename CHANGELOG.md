# API client merge fix

This delta restores API client methods that were added in earlier deltas but were accidentally overwritten by a later delta.

## Fixes
- Restores `getRiskPosture`
- Restores `executiveExportUrl`
- Restores response policy methods
- Restores suppression / retention / business-hours methods
- Restores `simulatePolicy`
- Restores `getRetentionPreview`
- Keeps Phase 14A notification action methods (`approveAlertAction`, `rejectAlertAction`, `assignAlertOwner`)
