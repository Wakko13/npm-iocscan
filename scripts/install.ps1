<#
.SYNOPSIS
Installer for npm-iocscan

.DESCRIPTION
Installs npm-iocscan script to a location accessible from PowerShell profile.

Usage:
  ./install.ps1
  ./install.ps1 -Destination "C:\Tools"
  ./install.ps1 -AddToProfile
#>

param(
    [string]$Destination = "$env:APPDATA\npm-iocscan",
    [switch]$AddToProfile
)

Write-Host "npm-iocscan Installer" -ForegroundColor Cyan
Write-Host ""

# Create destination directory
if (-not (Test-Path $Destination)) {
    New-Item -ItemType Directory -Path $Destination -Force | Out-Null
    Write-Host "✓ Created directory: $Destination" -ForegroundColor Green
}
else {
    Write-Host "ℹ Directory exists: $Destination" -ForegroundColor Gray
}

# Copy main script
$scriptSource = Join-Path $PSScriptRoot "npm-iocscan.ps1"
$scriptDest = Join-Path $Destination "npm-iocscan.ps1"

if (Test-Path $scriptSource) {
    Copy-Item -Path $scriptSource -Destination $scriptDest -Force
    Write-Host "✓ Installed: $scriptDest" -ForegroundColor Green
}
else {
    Write-Host "✗ Error: npm-iocscan.ps1 not found in script root" -ForegroundColor Red
    exit 1
}

# Copy documentation
$docs = @("README.md", "LICENSE")
$docsPath = Join-Path $PSScriptRoot "docs"

foreach ($doc in $docs) {
    $docSource = Join-Path $PSScriptRoot $doc
    if (Test-Path $docSource) {
        Copy-Item -Path $docSource -Destination (Join-Path $Destination $doc) -Force
        Write-Host "✓ Copied: $doc" -ForegroundColor Green
    }
}

# Add to PowerShell profile (optional)
if ($AddToProfile) {
    $profilePath = $PROFILE
    if (-not (Test-Path $profilePath)) {
        New-Item -ItemType File -Path $profilePath -Force | Out-Null
        Write-Host "✓ Created PowerShell profile: $profilePath" -ForegroundColor Green
    }
    
    $profileEntry = @"
# npm-iocscan – supply chain security scanner
function npm-iocscan {
    & "$scriptDest" @args
}
"@
    
    if ((Get-Content $profilePath -Raw) -notmatch "npm-iocscan") {
        Add-Content -Path $profilePath -Value "`n$profileEntry"
        Write-Host "✓ Added npm-iocscan to PowerShell profile" -ForegroundColor Green
        Write-Host "  Reload your terminal or run: . `$PROFILE" -ForegroundColor Gray
    }
}

Write-Host ""
Write-Host "Installation complete!" -ForegroundColor Green
Write-Host ""
Write-Host "Quick start:" -ForegroundColor Cyan
Write-Host "  npm-iocscan -Path ." -ForegroundColor Gray
Write-Host "  npm-iocscan -Path . -ScanTransitive" -ForegroundColor Gray
Write-Host ""
Write-Host "Documentation:" -ForegroundColor Cyan
Write-Host "  Get-Help $scriptDest -Full" -ForegroundColor Gray
Write-Host "  $Destination\README.md" -ForegroundColor Gray
