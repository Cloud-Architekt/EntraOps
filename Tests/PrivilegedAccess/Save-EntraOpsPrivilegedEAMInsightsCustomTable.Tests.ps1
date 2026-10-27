#Requires -Modules Pester

BeforeDiscovery {
    $script:TestRepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
}

BeforeAll {
    $script:TestRepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
    function Get-AzContext { throw "Get-AzContext must be mocked" }
    function Set-AzContext { param($SubscriptionId, $Context) throw "Set-AzContext must be mocked" }
    function Push-EntraOpsLogsIngestionAPI {
        param($TableName, $JsonContent, $DataCollectionRuleName, $DataCollectionResourceGroupName, $DataCollectionRuleSubscriptionId, $TimeGenerated)
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
        Mock Push-EntraOpsLogsIngestionAPI { $script:CapturedJson = $JsonContent } -ParameterFilter { $JsonContent -notmatch 'EntraOpsIngestionRun' }
        Mock Push-EntraOpsLogsIngestionAPI {} -ParameterFilter { $JsonContent -match 'EntraOpsIngestionRun' }

        Save-EntraOpsPrivilegedEAMInsightsCustomTable -ImportPath $TestDrive `
            -DataCollectionRuleName "dcr" -DataCollectionResourceGroupName "rg" `
            -DataCollectionRuleSubscriptionId "target" -TenantId "tenant" `
            -PrincipalTypeFilter "user" -RbacSystems "Azure"

        Should -Invoke Push-EntraOpsLogsIngestionAPI -Times 1 -Exactly -ParameterFilter { $JsonContent -notmatch 'EntraOpsIngestionRun' }
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

        Should -Invoke Push-EntraOpsLogsIngestionAPI -Times 1 -Exactly -ParameterFilter { $JsonContent -notmatch 'EntraOpsIngestionRun' }
    }

    It "stamps every batch of one run with the same TimeGenerated" {
        # The parser selects the latest ingestion by TimeGenerated, so all records of a run must share it.
        foreach ($System in "Azure", "EntraID") {
            $ObjectTypePath = Join-Path $TestDrive "$System/user"
            New-Item -ItemType Directory -Path $ObjectTypePath -Force | Out-Null
            @{ ObjectId = [guid]::NewGuid().ToString() } | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $ObjectTypePath "record.json")
        }
        $script:CapturedTimes = [System.Collections.Generic.List[object]]::new()
        Mock Push-EntraOpsLogsIngestionAPI { $script:CapturedTimes.Add($TimeGenerated) }

        Save-EntraOpsPrivilegedEAMInsightsCustomTable -ImportPath $TestDrive `
            -DataCollectionRuleName "dcr" -DataCollectionResourceGroupName "rg" `
            -DataCollectionRuleSubscriptionId "target" -TenantId "tenant" `
            -RbacSystems "Azure", "EntraID"

        # Two data batches plus one completion marker per RBAC system, all with the run timestamp
        $script:CapturedTimes.Count | Should -Be 4
        $script:CapturedTimes[0] | Should -Not -BeNullOrEmpty
        @($script:CapturedTimes | Sort-Object -Unique).Count | Should -Be 1
    }

    It "writes a completion marker per collected RBAC system after its records" {
        foreach ($System in "Azure", "EntraID") {
            $ObjectTypePath = Join-Path $TestDrive "$System/user"
            New-Item -ItemType Directory -Path $ObjectTypePath -Force | Out-Null
            @{ ObjectId = [guid]::NewGuid().ToString(); RoleSystem = $System } | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $ObjectTypePath "record.json")
        }
        $script:Calls = [System.Collections.Generic.List[object]]::new()
        Mock Push-EntraOpsLogsIngestionAPI { $script:Calls.Add(@($JsonContent | ConvertFrom-Json)[0]) }

        # Defender has no export folder: it was not collected and gets no marker.
        Save-EntraOpsPrivilegedEAMInsightsCustomTable -ImportPath $TestDrive `
            -DataCollectionRuleName "dcr" -DataCollectionResourceGroupName "rg" `
            -DataCollectionRuleSubscriptionId "target" -TenantId "tenant" `
            -RbacSystems "Azure", "EntraID", "Defender"

        @($script:Calls | ForEach-Object { "$($_.ObjectType)/$($_.RoleSystem)" }) |
            Should -Be @('/Azure', 'EntraOpsIngestionRun/Azure', '/EntraID', 'EntraOpsIngestionRun/EntraID')
    }

    It "writes no completion marker when a batch of the RBAC system fails" {
        $ObjectTypePath = Join-Path $TestDrive "Azure/user"
        New-Item -ItemType Directory -Path $ObjectTypePath -Force | Out-Null
        @{ ObjectId = [guid]::NewGuid().ToString() } | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $ObjectTypePath "record.json")
        Mock Push-EntraOpsLogsIngestionAPI { throw "simulated ingestion failure" } -ParameterFilter { $JsonContent -notmatch 'EntraOpsIngestionRun' }
        Mock Push-EntraOpsLogsIngestionAPI {} -ParameterFilter { $JsonContent -match 'EntraOpsIngestionRun' }

        { Save-EntraOpsPrivilegedEAMInsightsCustomTable -ImportPath $TestDrive `
                -DataCollectionRuleName "dcr" -DataCollectionResourceGroupName "rg" `
                -DataCollectionRuleSubscriptionId "target" -TenantId "tenant" `
                -RbacSystems "Azure" } | Should -Throw "*simulated ingestion failure*"

        Should -Invoke Push-EntraOpsLogsIngestionAPI -Times 0 -Exactly -ParameterFilter { $JsonContent -match 'EntraOpsIngestionRun' }
    }

    It "writes no completion marker for a run limited to some object types" {
        $ObjectTypePath = Join-Path $TestDrive "Azure/user"
        New-Item -ItemType Directory -Path $ObjectTypePath -Force | Out-Null
        @{ ObjectId = [guid]::NewGuid().ToString() } | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $ObjectTypePath "record.json")
        Mock Push-EntraOpsLogsIngestionAPI {}

        # The parser would otherwise return only users of the RBAC system and hide its groups and service principals
        Save-EntraOpsPrivilegedEAMInsightsCustomTable -ImportPath $TestDrive `
            -DataCollectionRuleName "dcr" -DataCollectionResourceGroupName "rg" `
            -DataCollectionRuleSubscriptionId "target" -TenantId "tenant" `
            -PrincipalTypeFilter "user" -RbacSystems "Azure" -WarningVariable FilterWarnings -WarningAction SilentlyContinue

        Should -Invoke Push-EntraOpsLogsIngestionAPI -Times 1 -Exactly -ParameterFilter { $JsonContent -notmatch 'EntraOpsIngestionRun' }
        Should -Invoke Push-EntraOpsLogsIngestionAPI -Times 0 -Exactly -ParameterFilter { $JsonContent -match 'EntraOpsIngestionRun' }
        "$FilterWarnings" | Should -Match 'No completion marker'
    }
}
