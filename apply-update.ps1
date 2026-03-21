param(
  [Parameter(Mandatory=$true)]
  [string]$ProjectRoot
)

$DeltaRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
Write-Host "Applying Phase 14A delta from $DeltaRoot to $ProjectRoot"

Copy-Item -Path (Join-Path $DeltaRoot 'backend') -Destination $ProjectRoot -Recurse -Force
Copy-Item -Path (Join-Path $DeltaRoot 'frontend') -Destination $ProjectRoot -Recurse -Force

Write-Host "Delta copied."
Write-Host "Next:"
Write-Host "  cd $ProjectRoot/frontend && npm install && npm run build"
Write-Host "  cd $ProjectRoot/backend && npm install && npm start"
