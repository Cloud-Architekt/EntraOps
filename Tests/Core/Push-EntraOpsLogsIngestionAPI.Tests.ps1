#Requires -Modules Pester

BeforeDiscovery {
    $script:TestRepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
}

BeforeAll {
    $script:TestRepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
    function Get-AzContext { throw "Get-AzContext must be mocked" }
    function Set-AzContext { param($SubscriptionId, $Context) throw "Set-AzContext must be mocked" }
    function Get-AzAccessToken { param($ResourceUrl, [switch]$AsSecureString) throw "Get-AzAccessToken must be mocked" }
    function Invoke-AzRestMethod { param($Method, $Uri) throw "Invoke-AzRestMethod must be mocked" }
    function Invoke-RestMethod { param($Uri, $Method, $Body, $Headers, [switch]$Verbose) throw "Invoke-RestMethod must be mocked" }
    . "$script:TestRepositoryRoot/EntraOps/Public/Core/Push-EntraOpsLogsIngestionAPI.ps1"
}

Describe "Push-EntraOpsLogsIngestionAPI Azure context isolation" {
    BeforeEach {
        $script:OriginalContext = [pscustomobject]@{ Name = "original" }
        Mock Get-AzContext { $script:OriginalContext }
        Mock Set-AzContext {}
        Mock Get-AzAccessToken {
            [pscustomobject]@{ Token = ConvertTo-SecureString "token" -AsPlainText -Force }
        }
    }

    It "does not access Azure in sample-data mode" {
        $Result = Push-EntraOpsLogsIngestionAPI -JsonContent '{"value":1}' -DataCollectionRuleName "dcr" -DataCollectionRuleSubscriptionId "target" -SampleDataOnly $true

        $Result.TrimStart() | Should -Match '^\['
        @($Result | ConvertFrom-Json).Count | Should -Be 1
        Should -Invoke Get-AzContext -Times 0 -Exactly
        Should -Invoke Set-AzContext -Times 0 -Exactly
        Should -Invoke Get-AzAccessToken -Times 0 -Exactly
    }

    It "restores the original context when ARM lookup fails" {
        Mock Invoke-AzRestMethod { throw "simulated ARM failure" }

        { Push-EntraOpsLogsIngestionAPI -JsonContent '{"value":1}' -DataCollectionRuleName "dcr" -DataCollectionRuleSubscriptionId "target" } |
            Should -Throw "*simulated ARM failure*"

        Should -Invoke Set-AzContext -Times 1 -Exactly -ParameterFilter { $SubscriptionId -eq "target" }
        Should -Invoke Set-AzContext -Times 1 -Exactly -ParameterFilter { $Context -eq $script:OriginalContext }
    }

    It "restores the original context after successful ingestion" {
        Mock Invoke-AzRestMethod {
            if ($Uri -like "*dataCollectionRules/*") {
                return [pscustomobject]@{ Content = '{"properties":{"dataflows":[{"outputStream":"Custom-PrivilegedEAM_CL"}],"dataCollectionEndpointId":"/subscriptions/target/resourceGroups/rg/providers/Microsoft.Insights/dataCollectionEndpoints/dce","immutableId":"dcr-id"}}' }
            }
            return [pscustomobject]@{ Content = '{"properties":{"logsIngestion":{"endpoint":"https://example.invalid"}}}' }
        }
        Mock Invoke-RestMethod {}

        { Push-EntraOpsLogsIngestionAPI -JsonContent '{"value":1}' -DataCollectionRuleName "dcr" -DataCollectionResourceGroupName "rg" -DataCollectionRuleSubscriptionId "target" } |
            Should -Not -Throw

        Should -Invoke Invoke-RestMethod -Times 1 -Exactly
        Should -Invoke Set-AzContext -Times 1 -Exactly -ParameterFilter { $SubscriptionId -eq "target" }
        Should -Invoke Set-AzContext -Times 1 -Exactly -ParameterFilter { $Context -eq $script:OriginalContext }
    }

    It "sends the request body as a flat JSON array of records" {
        Mock Invoke-AzRestMethod {
            if ($Uri -like "*dataCollectionRules/*") {
                return [pscustomobject]@{ Content = '{"properties":{"dataflows":[{"outputStream":"Custom-PrivilegedEAM_CL"}],"dataCollectionEndpointId":"/subscriptions/target/resourceGroups/rg/providers/Microsoft.Insights/dataCollectionEndpoints/dce","immutableId":"dcr-id"}}' }
            }
            return [pscustomobject]@{ Content = '{"properties":{"logsIngestion":{"endpoint":"https://example.invalid"}}}' }
        }
        $script:CapturedBody = $null
        Mock Invoke-RestMethod { $script:CapturedBody = $Body }

        Push-EntraOpsLogsIngestionAPI -JsonContent '[{"value":1},{"value":2}]' -DataCollectionRuleName "dcr" -DataCollectionResourceGroupName "rg" -DataCollectionRuleSubscriptionId "target"

        Should -Invoke Invoke-RestMethod -Times 1 -Exactly
        $script:CapturedBody | Should -Not -BeNullOrEmpty
        # Must be a flat array of record objects ([{...},{...}]), not a nested array ([[{...}]])
        # as produced by ConvertTo-Json -InputObject <collection> -AsArray.
        $script:CapturedBody | Should -Not -Match '^\s*\[\s*\['
        $Parsed = @($script:CapturedBody | ConvertFrom-Json -Depth 10)
        $Parsed.Count | Should -Be 2
        $Parsed[0].value | Should -Be 1
        $Parsed[1].value | Should -Be 2
        $Parsed[0].TimeGenerated | Should -Not -BeNullOrEmpty
    }

    It "fails before sending a single record larger than the request limit" {
        Mock Invoke-AzRestMethod {
            if ($Uri -like "*dataCollectionRules/*") {
                return [pscustomobject]@{ Content = '{"properties":{"dataflows":[{"outputStream":"Custom-PrivilegedEAM_CL"}],"dataCollectionEndpointId":"/subscriptions/target/resourceGroups/rg/providers/Microsoft.Insights/dataCollectionEndpoints/dce","immutableId":"dcr-id"}}' }
            }
            return [pscustomobject]@{ Content = '{"properties":{"logsIngestion":{"endpoint":"https://example.invalid"}}}' }
        }
        Mock Invoke-RestMethod {}
        $OversizedJson = @{ value = ('x' * 1000000) } | ConvertTo-Json -Compress

        {
            Push-EntraOpsLogsIngestionAPI -JsonContent $OversizedJson -DataCollectionRuleName "dcr" `
                -DataCollectionResourceGroupName "rg" -DataCollectionRuleSubscriptionId "target"
        } | Should -Throw "*Single record exceeds the 1 MB Logs Ingestion API request limit*"

        Should -Invoke Invoke-RestMethod -Times 0 -Exactly
        Should -Invoke Set-AzContext -Times 1 -Exactly -ParameterFilter { $Context -eq $script:OriginalContext }
    }

    It "recursively splits a payload whose serialized body exceeds the request limit" {
        Mock Invoke-AzRestMethod {
            if ($Uri -like "*dataCollectionRules/*") {
                return [pscustomobject]@{ Content = '{"properties":{"dataflows":[{"outputStream":"Custom-PrivilegedEAM_CL"}],"dataCollectionEndpointId":"/subscriptions/target/resourceGroups/rg/providers/Microsoft.Insights/dataCollectionEndpoints/dce","immutableId":"dcr-id"}}' }
            }
            return [pscustomobject]@{ Content = '{"properties":{"logsIngestion":{"endpoint":"https://example.invalid"}}}' }
        }
        $script:CapturedBodies = [System.Collections.Generic.List[string]]::new()
        Mock Invoke-RestMethod { $script:CapturedBodies.Add([string]$Body) }
        $Json = @(
            @{ id = 1; value = ('x' * 600000) }
            @{ id = 2; value = ('y' * 600000) }
        ) | ConvertTo-Json -Depth 10 -AsArray -Compress

        Push-EntraOpsLogsIngestionAPI -JsonContent $Json -DataCollectionRuleName "dcr" `
            -DataCollectionResourceGroupName "rg" -DataCollectionRuleSubscriptionId "target"

        Should -Invoke Invoke-RestMethod -Times 2 -Exactly
        $script:CapturedBodies | Should -HaveCount 2
        foreach ($CapturedBody in $script:CapturedBodies) {
            $CapturedBody.TrimStart() | Should -Match '^\['
            @($CapturedBody | ConvertFrom-Json).Count | Should -Be 1
            [System.Text.Encoding]::UTF8.GetByteCount($CapturedBody) | Should -BeLessOrEqual 1000000
        }
    }
}
