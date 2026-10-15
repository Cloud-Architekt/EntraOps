#Requires -Modules Pester

BeforeDiscovery {
    $script:TestRepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
}

BeforeAll {
    $script:TestRepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
    function Get-AzContext { throw "Get-AzContext must be mocked" }
    function Set-AzContext { param($SubscriptionId, $Context) throw "Set-AzContext must be mocked" }
    function Push-EntraOpsLogsIngestionAPI {
        param($TableName, $JsonContent, $DataCollectionRuleName, $DataCollectionResourceGroupName, $DataCollectionRuleSubscriptionId)
        throw "Push-EntraOpsLogsIngestionAPI must be mocked"
    }
    . "$script:TestRepositoryRoot/EntraOps/Public/PrivilegedAccess/Save-EntraOpsPrivilegedEAMInsightsCustomTable.ps1"
}

Describe "Save-EntraOpsPrivilegedEAMInsightsCustomTable Azure context isolation" {
    BeforeEach {
        $script:OriginalContext = [pscustomobject]@{ Name = "original" }
        Mock Get-AzContext { $script:OriginalContext }
        Mock Set-AzContext {}
    }

    It "restores the original context when classification file discovery fails" {
        Mock Test-Path { throw "simulated file discovery failure" }

        {
            Save-EntraOpsPrivilegedEAMInsightsCustomTable -ImportPath "/classification" `
                -DataCollectionRuleName "dcr" -DataCollectionResourceGroupName "rg" `
                -DataCollectionRuleSubscriptionId "target" -TenantId "tenant" `
                -PrincipalTypeFilter "user" -RbacSystems "Azure"
        } | Should -Throw "*simulated file discovery failure*"

        Should -Invoke Set-AzContext -Times 1 -Exactly -ParameterFilter { $SubscriptionId -eq "target" }
        Should -Invoke Set-AzContext -Times 1 -Exactly -ParameterFilter { $Context -eq $script:OriginalContext }
    }

    It "forwards a single classification record as a JSON array" {
        $ObjectTypePath = Join-Path $TestDrive "Azure/user"
        New-Item -ItemType Directory -Path $ObjectTypePath -Force | Out-Null
        @{ ObjectId = "11111111-1111-1111-1111-111111111111" } |
            ConvertTo-Json |
            Set-Content -LiteralPath (Join-Path $ObjectTypePath "record.json")

        $script:CapturedJson = $null
        Mock Push-EntraOpsLogsIngestionAPI { $script:CapturedJson = $JsonContent }

        Save-EntraOpsPrivilegedEAMInsightsCustomTable -ImportPath $TestDrive `
            -DataCollectionRuleName "dcr" -DataCollectionResourceGroupName "rg" `
            -DataCollectionRuleSubscriptionId "target" -TenantId "tenant" `
            -PrincipalTypeFilter "user" -RbacSystems "Azure"

        Should -Invoke Push-EntraOpsLogsIngestionAPI -Times 1 -Exactly
        $script:CapturedJson.TrimStart() | Should -Match '^\['
        @($script:CapturedJson | ConvertFrom-Json).Count | Should -Be 1
    }

    It "does not reuse files when a later object-type directory is missing" {
        $ObjectTypePath = Join-Path $TestDrive "Azure/user"
        New-Item -ItemType Directory -Path $ObjectTypePath -Force | Out-Null
        @{ ObjectId = "22222222-2222-2222-2222-222222222222" } |
            ConvertTo-Json |
            Set-Content -LiteralPath (Join-Path $ObjectTypePath "record.json")
        Mock Push-EntraOpsLogsIngestionAPI {}

        Save-EntraOpsPrivilegedEAMInsightsCustomTable -ImportPath $TestDrive `
            -DataCollectionRuleName "dcr" -DataCollectionResourceGroupName "rg" `
            -DataCollectionRuleSubscriptionId "target" -TenantId "tenant" `
            -PrincipalTypeFilter @("user", "group") -RbacSystems "Azure"

        Should -Invoke Push-EntraOpsLogsIngestionAPI -Times 1 -Exactly
    }
}
