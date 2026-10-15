#Requires -Modules Pester

BeforeAll {
    $script:TestRepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
    # Stub for runners without Az.Accounts; the mocks below replace it
    function global:Get-AzAccessToken {
        [CmdletBinding()]
        param([string]$ResourceTypeName, [string]$ResourceUrl, [string]$TenantId, [switch]$AsSecureString)
        throw 'Get-AzAccessToken must be mocked'
    }
    Import-Module (Join-Path $script:TestRepositoryRoot 'EntraOps') -Force
    $script:Session = & (Get-Module EntraOps) { $__EntraOpsSession }
}

AfterAll {
    $script:Session.ArmTokenCache.Clear()
    Remove-Item -LiteralPath 'Function:\Get-AzAccessToken' -ErrorAction SilentlyContinue
}

Describe 'ARM access token acquisition' {
    BeforeEach {
        $script:Session.ArmTokenCache.Clear()
        Mock Get-AzAccessToken -ModuleName EntraOps {
            [pscustomobject]@{ Token = (ConvertTo-SecureString 'arm-token' -AsPlainText -Force); ExpiresOn = [DateTimeOffset]::UtcNow.AddHours(1) }
        }
        Mock Invoke-RestMethod -ModuleName EntraOps { [pscustomobject]@{ data = @([pscustomobject]@{ id = 'r1' }); value = @([pscustomobject]@{ id = 's1' }) } }
    }

    It 'requests the Resource Graph token by resource type' {
        Invoke-EntraOpsAzGraphQuery -KqlQuery 'Resources | take 1' | Out-Null

        Should -Invoke Get-AzAccessToken -ModuleName EntraOps -Times 1 -Exactly -ParameterFilter { $ResourceTypeName -eq 'Arm' -and [string]::IsNullOrEmpty($ResourceUrl) }
    }

    It 'requests the ARM token by resource type' {
        Invoke-EntraOpsAzQuery -Method GET -Uri '/subscriptions' -DisableCache | Out-Null

        Should -Invoke Get-AzAccessToken -ModuleName EntraOps -ParameterFilter { $ResourceTypeName -eq 'Arm' -and [string]::IsNullOrEmpty($ResourceUrl) }
        Should -Invoke Get-AzAccessToken -ModuleName EntraOps -Times 0 -Exactly -ParameterFilter { -not [string]::IsNullOrEmpty($ResourceUrl) }
    }

    It 'requests the ARM token of an explicit tenant by resource type' {
        Invoke-EntraOpsAzQuery -Method GET -Uri '/subscriptions' -TenantId '11111111-1111-1111-1111-111111111111' -DisableCache | Out-Null

        Should -Invoke Get-AzAccessToken -ModuleName EntraOps -ParameterFilter { $ResourceTypeName -eq 'Arm' -and $TenantId -eq '11111111-1111-1111-1111-111111111111' }
    }
}
