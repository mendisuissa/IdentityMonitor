param(
  [string]$Source = ".",
  [string]$Target = "C:\temp\phase3\New"
)

Copy-Item -Path (Join-Path $Source "backend") -Destination $Target -Recurse -Force
Copy-Item -Path (Join-Path $Source "frontend") -Destination $Target -Recurse -Force
Copy-Item -Path (Join-Path $Source "CHANGELOG.md") -Destination $Target -Force
Copy-Item -Path (Join-Path $Source "APPLY-STEPS.md") -Destination $Target -Force
Write-Host "Phase 14B delta copied to $Target"
