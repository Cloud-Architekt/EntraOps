#Requires -Modules Pester

BeforeAll {
    $script:TestRepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
    . "$script:TestRepositoryRoot/EntraOps/Private/Test-EntraOpsPathWithinRoot.ps1"
    . "$script:TestRepositoryRoot/EntraOps/Public/PrivilegedAccess/Save-EntraOpsPrivilegedEAMWatchLists.ps1"
    . "$script:TestRepositoryRoot/EntraOps/Private/Get-EntraOpsDeploymentIdentity.ps1"
    . "$script:TestRepositoryRoot/EntraOps/Private/Publish-EntraOpsSentinelWatchlist.ps1"
    . "$script:TestRepositoryRoot/EntraOps/Private/Test-EntraOpsSentinelWatchlistDeployment.ps1"

    # Stubs for commands of Az.Accounts and SentinelEnrichment, which the tests mock
    function Invoke-AzRestMethod { param($Method, $Uri, $Payload) throw 'Invoke-AzRestMethod must be mocked' }
    function New-GkSeAzSentinelWatchlist { param($WatchListFilePath, $DisplayName, $WatchListDescription, $itemsSearchKey, $SubscriptionId, $ResourceGroupName, $WorkspaceName, $DefaultDuration, [switch]$ReplaceExistingWatchlist) throw 'New-GkSeAzSentinelWatchlist must be mocked' }
    function Install-EntraOpsRequiredModule { param($ModuleName, [switch]$Import) }

    function New-TestRestResponse {
        param([int]$StatusCode = 200, [object]$Content)
        [pscustomobject]@{ StatusCode = $StatusCode; Content = ($Content | ConvertTo-Json -Depth 10) }
    }

    $script:DeploymentVariables = 'GITHUB_REPOSITORY', 'GITHUB_WORKFLOW', 'BUILD_REPOSITORY_NAME', 'SYSTEM_TEAMPROJECT'
    function Set-TestDeploymentEnvironment {
        param([hashtable]$Values = @{})
        foreach ($Name in $script:DeploymentVariables) {
            if ($Values.ContainsKey($Name)) { Set-Item -Path "Env:$Name" -Value $Values[$Name] } else { Remove-Item -Path "Env:$Name" -ErrorAction SilentlyContinue }
        }
    }
    $script:SavedDeploymentEnvironment = @{}
    foreach ($Name in $script:DeploymentVariables) { $script:SavedDeploymentEnvironment[$Name] = [System.Environment]::GetEnvironmentVariable($Name) }

    function New-TestRoleAssignment {
        param(
            [string]$RoleAssignmentId,
            [string]$ScopeId = '/',
            [string]$RoleDefinitionId,
            [string]$RoleDefinitionName = 'Role',
            [string]$TransitiveByObjectId,
            [object[]]$Classification = @([pscustomobject]@{ AdminTierLevel = '0'; AdminTierLevelName = 'ControlPlane'; Service = 'Service' })
        )
        [pscustomobject]@{
            RoleAssignmentId      = $RoleAssignmentId
            RoleAssignmentScopeId = $ScopeId
            RoleDefinitionId      = $RoleDefinitionId
            RoleDefinitionName    = $RoleDefinitionName
            TransitiveByObjectId  = $TransitiveByObjectId
            Classification        = $Classification
        }
    }

    function Save-TestRbacSystem {
        param([string]$Root, [string]$RbacSystem, [object[]]$Objects)
        $Folder = Join-Path $Root $RbacSystem
        New-Item -ItemType Directory -Path $Folder -Force | Out-Null
        ConvertTo-Json -InputObject @($Objects) -Depth 10 | Set-Content -LiteralPath (Join-Path $Folder "$RbacSystem.json")
    }
}

Describe 'Save-EntraOpsPrivilegedEAMWatchLists watchlist keys' {
    BeforeAll {
        $Global:EntraOpsBaseFolder = $TestDrive
        $script:ImportPath = Join-Path $TestDrive 'PrivilegedEAM'
        $script:ExportPath = Join-Path $TestDrive 'Export'
        New-Item -ItemType Directory -Path $script:ExportPath -Force | Out-Null

        # Group-transitive assignment: the same RoleAssignmentId reaches two members.
        $AzureObjects = foreach ($MemberId in '11111111-0000-0000-0000-000000000001', '11111111-0000-0000-0000-000000000002') {
            [pscustomobject]@{
                ObjectId        = $MemberId
                ObjectType      = 'user'
                RoleAssignments = @(New-TestRoleAssignment -RoleAssignmentId 'shared-assignment' -ScopeId '/subscriptions/1' -RoleDefinitionId 'owner' -TransitiveByObjectId 'group-1')
            }
        }
        # ResourceApps delegated grant: one RoleAssignmentId across scopes, one permission unresolved (no RoleDefinitionId).
        $ResourceAppsObjects = @([pscustomobject]@{
                ObjectId        = '22222222-0000-0000-0000-000000000001'
                ObjectType      = 'serviceprincipal'
                RoleAssignments = @(
                    (New-TestRoleAssignment -RoleAssignmentId 'grant-1' -ScopeId 'resource-a' -RoleDefinitionId 'perm-1'),
                    (New-TestRoleAssignment -RoleAssignmentId 'grant-1' -ScopeId 'resource-b' -RoleDefinitionId 'perm-1'),
                    (New-TestRoleAssignment -RoleAssignmentId 'grant-1' -ScopeId 'resource-b' -RoleDefinitionName 'Unresolved.One'),
                    (New-TestRoleAssignment -RoleAssignmentId 'grant-1' -ScopeId 'resource-b' -RoleDefinitionName 'Unresolved.Two')
                )
            })
        # The same RoleAssignmentId in another RBAC system must not collide with the Azure one.
        $EntraIdObjects = @([pscustomobject]@{
                ObjectId        = '33333333-0000-0000-0000-000000000001'
                ObjectType      = 'user'
                RoleAssignments = @(New-TestRoleAssignment -RoleAssignmentId 'shared-assignment' -ScopeId '/subscriptions/1' -RoleDefinitionId 'owner')
            })

        Save-TestRbacSystem -Root $script:ImportPath -RbacSystem 'Azure' -Objects $AzureObjects
        Save-TestRbacSystem -Root $script:ImportPath -RbacSystem 'ResourceApps' -Objects $ResourceAppsObjects
        Save-TestRbacSystem -Root $script:ImportPath -RbacSystem 'EntraID' -Objects $EntraIdObjects

        Save-EntraOpsPrivilegedEAMWatchLists -ImportPath $script:ImportPath -ExportFolder $script:ExportPath `
            -RbacSystems 'Azure', 'EntraID', 'ResourceApps' -SkipUploadSaveLocal $true | Out-Null

        $script:RoleAssignmentRows = @(Import-Csv (Join-Path $script:ExportPath 'EntraOps_RoleAssignments.csv'))
        $script:ClassificationRows = @(Import-Csv (Join-Path $script:ExportPath 'EntraOps_RoleClassifications.csv'))
    }

    AfterAll {
        Remove-Variable -Name EntraOpsBaseFolder -Scope Global -ErrorAction SilentlyContinue
    }

    It 'writes one role assignment row with a unique key per principal and assignment' {
        $script:RoleAssignmentRows.Count | Should -Be 7
        @($script:RoleAssignmentRows.UniqueId | Sort-Object -Unique).Count | Should -Be 7
        $script:RoleAssignmentRows.UniqueId | Should -Not -Match '_$'
    }

    It 'keeps a classification row for every assignment the parser joins' {
        $ClassificationKeys = @($script:ClassificationRows | ForEach-Object { "$($_.RoleAssignmentId)|$($_.RoleAssignmentScopeId)|$($_.RoleSystem)|$($_.RoleDefinitionId)" })
        foreach ($Row in $script:RoleAssignmentRows) {
            "$($Row.RoleAssignmentId)|$($Row.RoleAssignmentScopeId)|$($Row.RoleSystem)|$($Row.RoleDefinitionId)" | Should -BeIn $ClassificationKeys
        }
    }

    It 'deduplicates classification rows shared by several principals of the same assignment' {
        @($script:ClassificationRows | Where-Object { $_.RoleSystem -eq 'Azure' }).Count | Should -Be 1
        @($script:ClassificationRows.UniqueId | Sort-Object -Unique).Count | Should -Be $script:ClassificationRows.Count
    }
}

Describe 'Get-EntraOpsDeploymentIdentity' {
    AfterAll {
        foreach ($Name in $script:DeploymentVariables) {
            if ($null -eq $script:SavedDeploymentEnvironment[$Name]) { Remove-Item -Path "Env:$Name" -ErrorAction SilentlyContinue } else { Set-Item -Path "Env:$Name" -Value $script:SavedDeploymentEnvironment[$Name] }
        }
    }

    It 'names the GitHub repository and workflow' {
        Set-TestDeploymentEnvironment @{ GITHUB_REPOSITORY = 'contoso/EntraOps'; GITHUB_WORKFLOW = 'Push-EntraOpsPrivilegedEAM' }
        Get-EntraOpsDeploymentIdentity | Should -Be 'GitHub contoso/EntraOps (Push-EntraOpsPrivilegedEAM)'
    }

    It 'names the Azure DevOps project and repository' {
        Set-TestDeploymentEnvironment @{ SYSTEM_TEAMPROJECT = 'Identity'; BUILD_REPOSITORY_NAME = 'EntraOps' }
        Get-EntraOpsDeploymentIdentity | Should -Be 'Azure DevOps Identity/EntraOps'
    }

    It 'falls back to the machine name' {
        Set-TestDeploymentEnvironment
        Get-EntraOpsDeploymentIdentity | Should -Be "Machine $([System.Environment]::MachineName)"
    }
}

Describe 'Publish-EntraOpsSentinelWatchlist' {
    BeforeAll {
        $Global:TenantNameContext = 'contoso.onmicrosoft.com'
    }

    AfterAll {
        Remove-Variable -Name TenantNameContext -Scope Global -ErrorAction SilentlyContinue
        foreach ($Name in $script:DeploymentVariables) {
            if ($null -eq $script:SavedDeploymentEnvironment[$Name]) { Remove-Item -Path "Env:$Name" -ErrorAction SilentlyContinue } else { Set-Item -Path "Env:$Name" -Value $script:SavedDeploymentEnvironment[$Name] }
        }
    }

    BeforeEach {
        Set-TestDeploymentEnvironment @{ GITHUB_REPOSITORY = 'contoso/EntraOps'; GITHUB_WORKFLOW = 'Push-EntraOpsPrivilegedEAM' }
        $script:CsvPath = Join-Path $TestDrive 'EntraOps_Principals.csv'
        'UniqueId,ObjectId' | Set-Content -LiteralPath $script:CsvPath
        'a-EntraID,a' | Add-Content -LiteralPath $script:CsvPath
        $script:PublishParameters = @{
            SubscriptionId    = 'sub'
            ResourceGroupName = 'rg'
            WorkspaceName     = 'ws'
            WatchListName     = 'EntraOps_Principals'
            WatchListFilePath = $script:CsvPath
            SearchKey         = 'UniqueId'
            ExpectedItemCount = 1
        }
        Mock New-GkSeAzSentinelWatchlist {
            # SentinelEnrichment leaves the block files of a split upload next to the CSV
            'block' | Set-Content -LiteralPath ($WatchListFilePath.Replace('.csv', '_1.csv'))
        }
    }

    It 'warns with both deployments when another deployment wrote the watchlist last' {
        $script:WatchListReads = 0
        Mock Invoke-AzRestMethod {
            if ($Uri -match '/watchlistItems') { return New-TestRestResponse -Content @{ value = @(@{ id = '1' }) } }
            $script:WatchListReads++
            New-TestRestResponse -Content @{ properties = @{ description = 'EntraOps | Tenant: contoso.onmicrosoft.com | Deployment: Azure DevOps Identity/EntraOps' } }
        }

        $Result = Publish-EntraOpsSentinelWatchlist @script:PublishParameters -WarningVariable Warnings -WarningAction SilentlyContinue 6>$null

        $Result.Issue | Should -BeNullOrEmpty
        @($Warnings | Where-Object { "$_" -match "last written by 'Azure DevOps Identity/EntraOps'" -and "$_" -match "replaced by 'GitHub contoso/EntraOps \(Push-EntraOpsPrivilegedEAM\)'" }).Count | Should -Be 1
        Should -Invoke New-GkSeAzSentinelWatchlist -Times 1 -Exactly -ParameterFilter {
            $WatchListDescription -eq 'EntraOps | Tenant: contoso.onmicrosoft.com | Deployment: GitHub contoso/EntraOps (Push-EntraOpsPrivilegedEAM)' -and $ReplaceExistingWatchlist
        }
        Test-Path -LiteralPath (Join-Path $TestDrive 'EntraOps_Principals_1.csv') | Should -BeFalse
    }

    It 'does not warn when the same deployment wrote the watchlist last' {
        Mock Invoke-AzRestMethod {
            if ($Uri -match '/watchlistItems') { return New-TestRestResponse -Content @{ value = @(@{ id = '1' }) } }
            New-TestRestResponse -Content @{ properties = @{ description = 'EntraOps | Tenant: contoso.onmicrosoft.com | Deployment: GitHub contoso/EntraOps (Push-EntraOpsPrivilegedEAM)' } }
        }

        $null = Publish-EntraOpsSentinelWatchlist @script:PublishParameters -WarningVariable Warnings -WarningAction SilentlyContinue 6>$null

        @($Warnings | Where-Object { "$_" -match 'last written by' }).Count | Should -Be 0
    }

    It 'reports a watchlist that is missing after the upload' {
        Mock Invoke-AzRestMethod { [pscustomobject]@{ StatusCode = 404; Content = '{}' } }

        $Result = Publish-EntraOpsSentinelWatchlist @script:PublishParameters -WarningVariable Warnings -WarningAction SilentlyContinue 6>$null

        $Result.Issue | Should -Be 'Missing'
        @($Warnings | Where-Object { "$_" -match 'does not exist after the upload' }).Count | Should -Be 1
    }
}

Describe 'Test-EntraOpsSentinelWatchlistDeployment' {
    It 'reports an empty watchlist after the retries' {
        Mock Invoke-AzRestMethod {
            if ($Uri -match '/watchlistItems') { return New-TestRestResponse -Content @{ value = @() } }
            New-TestRestResponse -Content @{ properties = @{} }
        }

        $Result = Test-EntraOpsSentinelWatchlistDeployment -SubscriptionId 'sub' -ResourceGroupName 'rg' -WorkspaceName 'ws' -WatchListName 'EntraOps_Principals' -ExpectedItemCount 5 -EmptyRetryCount 2 -EmptyRetryDelaySeconds 0

        $Result.Exists | Should -BeTrue
        $Result.Issue | Should -Be 'Empty'
        Should -Invoke Invoke-AzRestMethod -Times 3 -Exactly -ParameterFilter { $Uri -match '/watchlistItems' }
    }

    It 'does not report items for a page without an item list' {
        foreach ($Content in '{}', '{"value":null}') {
            Mock Invoke-AzRestMethod {
                if ($Uri -match '/watchlistItems') { return [pscustomobject]@{ StatusCode = 200; Content = $Content } }
                New-TestRestResponse -Content @{ properties = @{} }
            }

            $Result = Test-EntraOpsSentinelWatchlistDeployment -SubscriptionId 'sub' -ResourceGroupName 'rg' -WorkspaceName 'ws' -WatchListName 'EntraOps_Principals' -ExpectedItemCount 5 -WarningVariable Warnings -WarningAction SilentlyContinue

            $Result.ItemCount | Should -Be -1
            $Result.Issue | Should -BeNullOrEmpty
            @($Warnings | Where-Object { "$_" -match 'returned no item list' }).Count | Should -Be 1
        }
    }

    It 'reads only the first page of a watchlist that was not split' {
        $SmallCsv = Join-Path $TestDrive 'small.csv'
        'UniqueId' | Set-Content -LiteralPath $SmallCsv
        Mock Invoke-AzRestMethod {
            if ($Uri -match '/watchlistItems') { return New-TestRestResponse -Content @{ value = @(@{ id = '1' }); nextLink = 'https://management.azure.com/next' } }
            New-TestRestResponse -Content @{ properties = @{} }
        }

        $Result = Test-EntraOpsSentinelWatchlistDeployment -SubscriptionId 'sub' -ResourceGroupName 'rg' -WorkspaceName 'ws' -WatchListName 'EntraOps_Principals' -ExpectedItemCount 500 -WatchListFilePath $SmallCsv

        $Result.Issue | Should -BeNullOrEmpty
        $Result.Counted | Should -BeFalse
        Should -Invoke Invoke-AzRestMethod -Times 1 -Exactly -ParameterFilter { $Uri -match '/watchlistItems' }
    }
}

Describe 'Save-EntraOpsPrivilegedEAMWatchLists upload result' {
    BeforeAll {
        $Global:EntraOpsBaseFolder = $TestDrive
        $script:UploadImportPath = Join-Path $TestDrive 'UploadEAM'
        Save-TestRbacSystem -Root $script:UploadImportPath -RbacSystem 'EntraID' -Objects @([pscustomobject]@{
                ObjectId        = '44444444-0000-0000-0000-000000000001'
                ObjectType      = 'user'
                RoleAssignments = @(New-TestRoleAssignment -RoleAssignmentId 'assignment-1' -RoleDefinitionId 'role-1')
            })
    }

    AfterAll {
        Remove-Variable -Name EntraOpsBaseFolder -Scope Global -ErrorAction SilentlyContinue
    }

    It 'uploads every watchlist and reports the missing ones together at the end' {
        Mock Publish-EntraOpsSentinelWatchlist {
            [pscustomobject]@{ WatchListName = $WatchListName; Issue = if ($WatchListName -eq 'EntraOps_RoleAssignments') { 'Missing' } else { $null } }
        }

        Save-EntraOpsPrivilegedEAMWatchLists -ImportPath $script:UploadImportPath -ExportFolder (Join-Path $TestDrive 'UploadExport') -RbacSystems 'EntraID' `
            -SentinelSubscriptionId 'sub' -SentinelResourceGroupName 'rg' -SentinelWorkspaceName 'ws' -ErrorVariable UploadErrors -ErrorAction SilentlyContinue | Out-Null

        Should -Invoke Publish-EntraOpsSentinelWatchlist -Times 3 -Exactly
        @($UploadErrors).Count | Should -Be 1
        "$($UploadErrors[0])" | Should -Match '1 watchlist\(s\) missing or empty after the upload: EntraOps_RoleAssignments \(Missing\)'
    }

    It 'stops with an -ErrorAction Stop of the caller' {
        Mock Publish-EntraOpsSentinelWatchlist { [pscustomobject]@{ WatchListName = $WatchListName; Issue = 'Missing' } }

        { Save-EntraOpsPrivilegedEAMWatchLists -ImportPath $script:UploadImportPath -ExportFolder (Join-Path $TestDrive 'UploadExport') -RbacSystems 'EntraID' `
                -SentinelSubscriptionId 'sub' -SentinelResourceGroupName 'rg' -SentinelWorkspaceName 'ws' -ErrorAction Stop } | Should -Throw '*3 watchlist(s) missing or empty after the upload*'
    }
}
