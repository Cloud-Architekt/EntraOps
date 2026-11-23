#Requires -Modules Pester

BeforeAll {
    $script:TestRepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
    . "$script:TestRepositoryRoot/EntraOps/Public/Core/Install-EntraOpsRequiredModule.ps1"
    . "$script:TestRepositoryRoot/EntraOps/Private/Get-EntraOpsModuleRequirement.ps1"

    # Install-PSResource may be missing on the test host; the tests mock it
    if (-not (Get-Command -Name Install-PSResource -ErrorAction SilentlyContinue)) {
        function Install-PSResource { param($Name, $Version, $Scope, [switch]$TrustRepository) }
    }

    function New-TestModuleInfo {
        param([string]$Name, [string]$Version)
        [pscustomobject]@{ Name = $Name; Version = [version]$Version }
    }
}

Describe 'Install-EntraOpsRequiredModule' {
    BeforeEach {
        Mock Install-PSResource {}
        Mock Write-Warning {}
    }

    It 'uses a loaded module without scanning the module paths' {
        Mock Get-Module { New-TestModuleInfo -Name 'Az.Accounts' -Version '5.5.4' } -ParameterFilter { -not $ListAvailable }
        Mock Get-Module { throw 'module paths must not be scanned' } -ParameterFilter { $ListAvailable }

        Install-EntraOpsRequiredModule -ModuleName 'Az.Accounts' -MinimalVersion '2.19.0' | Should -Be 'Module Az.Accounts (v5.5.4) is available.'
        Should -Invoke Install-PSResource -Times 0 -Exactly
    }

    It 'installs exactly the required version when only other versions are available' {
        Mock Get-Module { } -ParameterFilter { -not $ListAvailable }
        Mock Get-Module { New-TestModuleInfo -Name 'SentinelEnrichment' -Version '0.2.1'; New-TestModuleInfo -Name 'SentinelEnrichment' -Version '0.3.0' } -ParameterFilter { $ListAvailable }

        Install-EntraOpsRequiredModule -ModuleName 'SentinelEnrichment' -RequiredVersion '0.2.2'

        Should -Invoke Install-PSResource -Times 1 -Exactly -ParameterFilter { $Name -eq 'SentinelEnrichment' -and $Version -eq '[0.2.2]' }
    }

    It 'does not install when the required version is already available' {
        Mock Get-Module { } -ParameterFilter { -not $ListAvailable }
        Mock Get-Module { New-TestModuleInfo -Name 'SentinelEnrichment' -Version '0.2.2'; New-TestModuleInfo -Name 'SentinelEnrichment' -Version '0.3.0' } -ParameterFilter { $ListAvailable }

        Install-EntraOpsRequiredModule -ModuleName 'SentinelEnrichment' -RequiredVersion '0.2.2' | Should -Be 'Module SentinelEnrichment (v0.2.2) is available.'
        Should -Invoke Install-PSResource -Times 0 -Exactly
    }

    It 'installs the latest version when only an older one than the minimal version is available' {
        Mock Get-Module { } -ParameterFilter { -not $ListAvailable }
        Mock Get-Module { New-TestModuleInfo -Name 'Az.Resources' -Version '6.0.0' } -ParameterFilter { $ListAvailable }

        Install-EntraOpsRequiredModule -ModuleName 'Az.Resources' -MinimalVersion '6.16.2'

        Should -Invoke Install-PSResource -Times 1 -Exactly -ParameterFilter { $Name -eq 'Az.Resources' -and [string]::IsNullOrEmpty($Version) }
    }

    It 'uses the EntraOps version requirement without a version and imports exactly the pinned version' {
        Mock Get-Module { } -ParameterFilter { -not $ListAvailable }
        Mock Get-Module { New-TestModuleInfo -Name 'SentinelEnrichment' -Version '0.3.0' } -ParameterFilter { $ListAvailable }
        Mock Import-Module {}

        Install-EntraOpsRequiredModule -ModuleName 'SentinelEnrichment' -Import

        Should -Invoke Install-PSResource -Times 1 -Exactly -ParameterFilter { $Name -eq 'SentinelEnrichment' -and $Version -eq '[0.2.2]' }
        Should -Invoke Import-Module -Times 1 -Exactly -ParameterFilter { $Name -eq 'SentinelEnrichment' -and $RequiredVersion -eq '0.2.2' -and $Global }
    }
}
