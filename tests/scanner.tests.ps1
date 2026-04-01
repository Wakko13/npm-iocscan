<#
.SYNOPSIS
Pester tests for npm-iocscan security scanner

.DESCRIPTION
Validates detection accuracy against known fixtures:
- Clean manifests should produce no IOCs
- Malicious packages should be detected
- Suspicious lifecycle scripts should be flagged
- Exfiltration patterns should be caught

Run with: Invoke-Pester ./scanner.tests.ps1 -Verbose
#>

function New-TestProjectFromFixture {
    param(
        [Parameter(Mandatory = $true)]
        [string]$FixtureName
    )

    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ([System.Guid]::NewGuid().ToString())
    New-Item -ItemType Directory -Path $tempRoot -Force | Out-Null

    $source = Join-Path $PSScriptRoot "fixtures\$FixtureName"
    $target = Join-Path $tempRoot 'package.json'
    Copy-Item -Path $source -Destination $target -Force

    return $tempRoot
}

function Invoke-ScannerOutput {
    param(
        [string]$TargetPath
    )

    if ($TargetPath) {
        return (& $scriptPath -Path $TargetPath *>&1 | Out-String)
    }

    return (& $scriptPath *>&1 | Out-String)
}

function Assert-Contains {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Actual,
        [Parameter(Mandatory = $true)]
        [string]$Expected
    )

    if ($Actual -notmatch [regex]::Escape($Expected)) {
        throw "Expected output to contain '$Expected' but got: $Actual"
    }
}

function Assert-DoesNotThrow {
    param(
        [Parameter(Mandatory = $true)]
        [scriptblock]$Action
    )

    try {
        & $Action | Out-Null
    }
    catch {
        throw "Expected command not to throw, but it threw: $($_.Exception.Message)"
    }
}

Describe "npm-iocscan Scanner" {
    
    $scriptPath = "${PSScriptRoot}\..\npm-iocscan.ps1"
    
    Context "Clean Package Detection" {
        It "should pass clean package.json with no IOCs" {
            $projectRoot = New-TestProjectFromFixture -FixtureName 'clean.package.json'
            try {
                $output = Invoke-ScannerOutput -TargetPath $projectRoot
                Assert-Contains -Actual $output -Expected 'No IOCs or suspicious lifecycle scripts'
            }
            finally {
                Remove-Item -Path $projectRoot -Recurse -Force -ErrorAction SilentlyContinue
            }
        }
    }
    
    Context "Malicious Package Detection" {
        It "should detect plain-crypto-js typosquat" {
            $projectRoot = New-TestProjectFromFixture -FixtureName 'malicious.package.json'
            try {
                $output = Invoke-ScannerOutput -TargetPath $projectRoot
                Assert-Contains -Actual $output -Expected 'CRITICAL'
                Assert-Contains -Actual $output -Expected 'plain-crypto-js'
            }
            finally {
                Remove-Item -Path $projectRoot -Recurse -Force -ErrorAction SilentlyContinue
            }
        }
    }
    
    Context "Lifecycle Script Detection" {
        It "should flag postinstall scripts with curl" {
            $projectRoot = New-TestProjectFromFixture -FixtureName 'lifecycle-hook.package.json'
            try {
                $output = Invoke-ScannerOutput -TargetPath $projectRoot
                Assert-Contains -Actual $output -Expected 'Lifecycle Script: postinstall'
            }
            finally {
                Remove-Item -Path $projectRoot -Recurse -Force -ErrorAction SilentlyContinue
            }
        }
        
        It "should detect shell commands in prepare scripts" {
            $projectRoot = New-TestProjectFromFixture -FixtureName 'webhook-exfil.package.json'
            try {
                $output = Invoke-ScannerOutput -TargetPath $projectRoot
                Assert-Contains -Actual $output -Expected 'Lifecycle Script: prepare'
            }
            finally {
                Remove-Item -Path $projectRoot -Recurse -Force -ErrorAction SilentlyContinue
            }
        }
    }
    
    Context "Exfiltration Detection" {
        It "should flag discord.com webhook URLs" {
            $projectRoot = New-TestProjectFromFixture -FixtureName 'webhook-exfil.package.json'
            try {
                $output = Invoke-ScannerOutput -TargetPath $projectRoot
                Assert-Contains -Actual $output -Expected 'discord.com'
            }
            finally {
                Remove-Item -Path $projectRoot -Recurse -Force -ErrorAction SilentlyContinue
            }
        }
    }
    
    Context "Parameter Validation" {
        It "should handle missing -Path parameter when run from a project root" {
            $projectRoot = New-TestProjectFromFixture -FixtureName 'clean.package.json'
            Push-Location $projectRoot
            try {
                Assert-DoesNotThrow -Action { Invoke-ScannerOutput }
            }
            finally {
                Pop-Location
                Remove-Item -Path $projectRoot -Recurse -Force -ErrorAction SilentlyContinue
            }
        }
        
        It "should accept a valid project directory path" {
            $projectRoot = New-TestProjectFromFixture -FixtureName 'clean.package.json'
            try {
                Assert-DoesNotThrow -Action { Invoke-ScannerOutput -TargetPath $projectRoot }
            }
            finally {
                Remove-Item -Path $projectRoot -Recurse -Force -ErrorAction SilentlyContinue
            }
        }
    }
}
