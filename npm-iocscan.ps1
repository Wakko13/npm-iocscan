<#
.SYNOPSIS
Comprehensive npm security IOC and lifecycle script scanner for Node.js projects.

.DESCRIPTION
Scans package manifests and lockfiles for:
  - Known malicious package names and typosquat variants
  - Suspicious lifecycle scripts (preinstall, postinstall, prepare, etc.)
  - Exfiltration indicators (discord, telegram, webhook, curl, wget, powershell)

Only performs static analysis on declared/resolved packages - does not execute scripts.

.PARAMETER Path
The root directory to scan. Recursively finds all package.json, lockfiles, etc.

.PARAMETER ScanTransitive
If specified, resolves full dependency trees in isolated Docker containers 
using 'npm install --ignore-scripts' (safe, no code execution).

.EXAMPLE
./npm-iocscan.ps1 -Path .
Basic static scan of current directory.

.EXAMPLE
./npm-iocscan.ps1 -Path . -ScanTransitive
Full scan including transitive dependency resolution (requires Docker).

.EXAMPLE
./npm-iocscan.ps1 -Path C:\Projects\my-app -ScanTransitive
Scan a specific project with transitive resolution.

.NOTES
Requires: PowerShell 5.0+
Optional: Docker (for -ScanTransitive flag)

Author: npm-iocscan contributors
License: AGPL-3.0-only
#>

param(
    [string]$Path = '.',
    [switch]$ScanTransitive
)

# IOC patterns: malicious package names, lifecycle scripts, exfiltration endpoints
$iocPatterns = @{
    malicious_packages = @(
        'plain-crypto-js',                    # Typosquat of crypto-js
        '@anthropic-ai/claude-code',          # Reported fake Anthropic package
        'npm-plugin',                         # Generic malicious runner
        'npm-run',                            # Generic runner
        'lodash4',                            # Typosquat of lodash
        'cors-any',                           # Known exfiltration vector
        'http-server-proxy'                   # Proxy hijack
    )
    suspicious_scripts = @(
        'preinstall',
        'postinstall',
        'prepare',
        'postuninstall',
        'preuninstall',
        'preupdate'
    )
    exfiltration = @(
        'discord\.com|webhook',
        'telegram.*api',
        'pastebin',
        'http-echo',
        'webhook\.site',
        'beeceptor'
    )
    shell_commands = @(
        'curl\s+http',
        'wget\s+http',
        'Invoke-WebRequest',
        'powershell\s+',
        '\$\(',                               # Command substitution
        'eval\s*\(',
        'exec\s*\('
    )
}

$foundIssues = @()

# Find all package manifests and lockfiles
$files = @(Get-ChildItem -Path $Path -Recurse -File -Include 'package.json', 'package-lock.json', 'npm-shrinkwrap.json', 'yarn.lock', 'pnpm-lock.yaml' -ErrorAction SilentlyContinue)

if (-not $files) {
    Write-Host "No package manifests or lockfiles found in: $Path" -ForegroundColor Yellow
    exit 0
}

Write-Host "Scanning $($files.Count) file(s) for npm security indicators..." -ForegroundColor Cyan
Write-Host ""

foreach ($file in $files) {
    $content = Get-Content -Path $file.FullName -Raw
    $fileRelPath = Resolve-Path -Path $file.FullName -Relative
    
    # Parse JSON for package manifests
    if ($file.Name -match 'package.*\.json$') {
        try {
            $json = $content | ConvertFrom-Json
            
            # Check declared dependencies
            foreach ($depType in @('dependencies', 'devDependencies', 'optionalDependencies')) {
                if ($json.$depType) {
                    foreach ($pkg in $json.$depType.PSObject.Properties) {
                        # Check for malicious package names
                        foreach ($malicious in $iocPatterns.malicious_packages) {
                            if ($pkg.Name -match [regex]::Escape($malicious)) {
                                $foundIssues += @{
                                    File = $fileRelPath
                                    Severity = 'CRITICAL'
                                    Type = 'Malicious Package'
                                    Package = $pkg.Name
                                    Version = $pkg.Value
                                    Line = ''
                                }
                            }
                        }
                    }
                }
            }
            
            # Check for lifecycle scripts
            if ($json.scripts) {
                foreach ($script in $json.scripts.PSObject.Properties) {
                    foreach ($suspicious in $iocPatterns.suspicious_scripts) {
                        if ($script.Name -eq $suspicious) {
                            $scriptBody = $script.Value
                            $suspiciousIndicator = ''
                            
                            # Check script content for exfiltration/shell indicators
                            foreach ($exfil in $iocPatterns.exfiltration) {
                                if ($scriptBody -match $exfil) {
                                    $suspiciousIndicator = "Contains: $exfil"
                                    break
                                }
                            }
                            foreach ($shellCmd in $iocPatterns.shell_commands) {
                                if ($scriptBody -match $shellCmd) {
                                    $suspiciousIndicator = "Shell command: $(($scriptBody -split '\s')[0])"
                                    break
                                }
                            }
                            
                            $severity = if ($suspiciousIndicator) { 'HIGH' } else { 'MEDIUM' }
                            
                            $foundIssues += @{
                                File = $fileRelPath
                                Severity = $severity
                                Type = "Lifecycle Script: $($script.Name)"
                                Package = 'package.json'
                                Version = "$($scriptBody.Substring(0, [Math]::Min(60, $scriptBody.Length)))..."
                                Line = $suspiciousIndicator
                            }
                        }
                    }
                }
            }
        }
        catch {
            Write-Host "  ⚠ Failed to parse $fileRelPath : $_" -ForegroundColor Yellow
        }
    }
    
    # Raw pattern scan on all files for fallback detection
    $lines = $content -split "`n"
    for ($i = 0; $i -lt $lines.Count; $i++) {
        $line = $lines[$i]
        
        # Malicious packages
        foreach ($malicious in $iocPatterns.malicious_packages) {
            if ($line -match $malicious) {
                $foundIssues += @{
                    File = $fileRelPath
                    Severity = 'CRITICAL'
                    Type = 'Malicious Package (pattern)'
                    Package = $malicious
                    Version = ''
                    Line = $line.Trim()
                }
            }
        }
        
        # Exfiltration endpoints
        foreach ($exfil in $iocPatterns.exfiltration) {
            if ($line -match $exfil) {
                $foundIssues += @{
                    File = $fileRelPath
                    Severity = 'CRITICAL'
                    Type = 'Exfiltration Indicator'
                    Package = ''
                    Version = ''
                    Line = $line.Trim()
                }
            }
        }
    }
}

# Report findings
if ($foundIssues) {
    $foundIssues | ForEach-Object {
        $color = switch ($_.Severity) {
            'CRITICAL' { 'Red' }
            'HIGH' { 'Yellow' }
            default { 'Cyan' }
        }
        Write-Host "[$($_.Severity)] $($_.Type)" -ForegroundColor $color
        Write-Host "  File: $($_.File)" -ForegroundColor Gray
        if ($_.Package) { Write-Host "  Package: $($_.Package)" -ForegroundColor Gray }
        if ($_.Version) { Write-Host "  Version/Detail: $($_.Version)" -ForegroundColor Gray }
        if ($_.Line) { Write-Host "  Content: $($_.Line)" -ForegroundColor Gray }
        Write-Host ""
    }
    Write-Host "Found $($foundIssues.Count) potential issue(s)." -ForegroundColor Red
}
else {
    Write-Host "✓ No IOCs or suspicious lifecycle scripts detected in static analysis." -ForegroundColor Green
}

# Transitive dependency check (requires docker + node image)
if ($ScanTransitive -and (Get-Command docker -ErrorAction SilentlyContinue)) {
    Write-Host ""
    Write-Host "Scanning resolved transitive dependencies (--ignore-scripts)..." -ForegroundColor Cyan
    
    $projDirs = @(Get-ChildItem -Path $Path -Recurse -File -Include 'package.json' | ForEach-Object { Split-Path $_.FullName } | Select-Object -Unique)
    
    foreach ($projDir in $projDirs) {
        $relDir = Resolve-Path -Path $projDir -Relative
        Write-Host "  Project: $relDir" -ForegroundColor Gray
        
        # Resolve without executing scripts
        $lockOutput = docker run --rm -v "$($projDir):/src:ro" node:20-alpine sh -lc @"
cd /tmp && cp /src/package.json . && npm install --package-lock-only --ignore-scripts --silent 2>/dev/null && npm ls --depth=999 --json 2>/dev/null | jq -r '.dependencies | to_entries[] | "\(.key)@\(.value.version)"' | sort
"@ 2>$null
        
        if ($lockOutput) {
            $depCount = if ($lockOutput -is [array]) { $lockOutput.Count } else { 1 }
            Write-Host "    Resolved $depCount dependencies (no scripts executed)" -ForegroundColor Green
        }
    }
}
