# Architecture Next Step

## Current split

- **IdentityMonitor** = detection, decisioning, approval, orchestration
- **Webapp** = application remediation executor

## Why this matters

Not every vulnerability is an application vulnerability. To cover all vulnerability types, IdentityMonitor should own a generic executor model.

## Recommended executor model

### 1. App executor
Use `Webapp` for:
- winget upgrades
- Intune Win32 app replacement
- application uninstall/reinstall

### 2. OS patch executor
Use a dedicated executor for:
- Windows Update / quality update remediation
- patch ring assignment
- expedited updates where supported

### 3. Configuration executor
Use a config executor for:
- registry changes
- policy changes
- attack surface reduction settings
- hardening baselines

### 4. Script executor
Use a script engine for:
- deterministic PowerShell/bash remediation
- health checks
- post-remediation validation

### 5. Manual/ticket executor
Use this for:
- unsupported findings
- risky changes
- server-side/manual fixes
- cases requiring CAB approval

## Suggested v2 objects

### Vulnerability finding
- `id`
- `tenantId`
- `category`
- `source`
- `cveId`
- `productName`
- `severity`
- `affectedDevices`
- `recommendation`

### Remediation plan
- `executor`
- `strategy`
- `requiresApproval`
- `validationMode`
- `rollbackSupported`

### Execution record
- `jobId`
- `executor`
- `status`
- `startedAt`
- `completedAt`
- `resultsByDevice`

## Best next implementation step

Build an `executorRegistry` inside IdentityMonitor:
- `webappExecutor`
- `osPatchExecutor`
- `configExecutor`
- `scriptExecutor`
- `manualExecutor`

Then route each finding by category and plan type instead of sending everything to Webapp.
