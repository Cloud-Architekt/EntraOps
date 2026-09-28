#Requires -Modules Pester

BeforeDiscovery {
    $script:TestRepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
}

BeforeAll {
    $script:TestRepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
    function Get-AzContext { throw "Get-AzContext must be mocked" }
    function Set-AzContext { param($SubscriptionId, $Context) throw "Set-AzContext must be mocked" }
    . "$script:TestRepositoryRoot/EntraOps/Public/PrivilegedAccess/Get-EntraOpsPrivilegedEAMResourceAppsFirstParty.ps1"
}

Describe "Get-EntraOpsPrivilegedEAMResourceAppsFirstParty Azure context isolation" {
    BeforeEach {
        $script:OriginalContext = [pscustomobject]@{ Name = "original"; Tenant = [pscustomobject]@{ Id = "tenant" } }
        Mock Get-AzContext { $script:OriginalContext }
        Mock Set-AzContext {}
    }

    It "restores the original context when a source query fails" {
        Mock Invoke-RestMethod { throw "simulated source query failure" }

        {
            Get-EntraOpsPrivilegedEAMResourceAppsFirstParty -TenantId "tenant" `
                -SentinelWorkspaceId "workspace" -SentinelWorkspaceSubscriptionId "target"
        } | Should -Throw "*simulated source query failure*"

        Should -Invoke Set-AzContext -Times 1 -Exactly -ParameterFilter { $SubscriptionId -eq "target" }
        Should -Invoke Set-AzContext -Times 1 -Exactly -ParameterFilter { $Context -eq $script:OriginalContext }
    }
}
