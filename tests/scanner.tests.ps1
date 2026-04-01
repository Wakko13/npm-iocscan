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

Describe "npm-iocscan Scanner" {
    
    $scriptPath = "${PSScriptRoot}\..\npm-iocscan.ps1"
    $fixturesPath = "${PSScriptRoot}\fixtures"
    
    Context "Clean Package Detection" {
        It "should pass clean package.json with no IOCs" {
            $output = & $scriptPath -Path $fixturesPath | Out-String
            $output | Should -Match "No IOCs or suspicious lifecycle scripts"
        }
    }
    
    Context "Malicious Package Detection" {
        It "should detect plain-crypto-js typosquat" {
            $output = & $scriptPath -Path "${fixturesPath}\malicious.package.json" | Out-String
            $output | Should -Match "CRITICAL"
            $output | Should -Match "plain-crypto-js"
        }
    }
    
    Context "Lifecycle Script Detection" {
        It "should flag postinstall scripts with curl" {
            $output = & $scriptPath -Path "${fixturesPath}\lifecycle-hook.package.json" | Out-String
            $output | Should -Match "Lifecycle Script: postinstall"
        }
        
        It "should detect shell commands in prepare scripts" {
            $output = & $scriptPath -Path "${fixturesPath}\webhook-exfil.package.json" | Out-String
            $output | Should -Match "prepare"
        }
    }
    
    Context "Exfiltration Detection" {
        It "should flag discord.com webhook URLs" {
            $output = & $scriptPath -Path "${fixturesPath}\webhook-exfil.package.json" | Out-String
            $output | Should -Match "discord.com"
        }
    }
    
    Context "Parameter Validation" {
        It "should handle missing -Path parameter (default to current dir)" {
            { & $scriptPath } | Should -Not -Throw
        }
        
        It "should accept -Path parameter" {
            { & $scriptPath -Path $fixturesPath } | Should -Not -Throw
        }
    }
}
