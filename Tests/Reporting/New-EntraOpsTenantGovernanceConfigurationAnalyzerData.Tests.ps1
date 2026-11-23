#Requires -Modules Pester

BeforeAll {
    $RepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
    Import-Module (Join-Path $RepositoryRoot 'EntraOps') -Force

    function Save-HistoryTestCommit {
        param([string]$Date, [string]$Message)

        & git -C $Root add --all
        if ($LASTEXITCODE -ne 0) { throw 'Could not stage the snapshot fixture.' }
        $PreviousAuthorDate = $env:GIT_AUTHOR_DATE
        $PreviousCommitterDate = $env:GIT_COMMITTER_DATE
        try {
            $env:GIT_AUTHOR_DATE = $Date
            $env:GIT_COMMITTER_DATE = $Date
            & git -C $Root -c user.name=EntraOps -c user.email=fixture@example.com -c commit.gpgsign=false commit --quiet -m $Message
            if ($LASTEXITCODE -ne 0) { throw "Could not commit snapshot fixture '$Message'." }
        } finally {
            $env:GIT_AUTHOR_DATE = $PreviousAuthorDate
            $env:GIT_COMMITTER_DATE = $PreviousCommitterDate
        }
    }

    function Publish-HistoryTestSnapshot {
        param([string]$Date, [string]$Id, [string]$Value)

        @{
            resourceType = 'microsoft.entra.test'
            properties   = @{ Id = 'fixture-resource'; displayName = $Value }
        } | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $Snapshots 'microsoft.entra.test/resource.json')
        @{
            SnapshotId                  = $Id
            SnapshotJobStatus           = 'succeeded'
            IsComplete                  = $true
            CapturedDateTime            = $Date
            PublishedResourceTypes      = @('microsoft.entra.test')
            PublishedResourceTypeCounts = @{ 'microsoft.entra.test' = 1 }
        } | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $Snapshots '.SnapshotManifest.json')
        Remove-Item -LiteralPath (Join-Path $Snapshots '.PendingSnapshotJob.json') -Force -ErrorAction SilentlyContinue
        Save-HistoryTestCommit -Date $Date -Message "Complete $Id"
    }

    function Save-HistoryTestBookkeeping {
        param([string]$Date, [string]$Name, [string]$Id)

        @{ SnapshotJobId = $Id; LastCheckedDateTime = $Date } | ConvertTo-Json |
            Set-Content -LiteralPath (Join-Path $Snapshots $Name)
        Save-HistoryTestCommit -Date $Date -Message "Bookkeeping $Id $Name"
    }
}

Describe 'Configuration Analyzer snapshot history' -Skip:(-not (Get-Command git -ErrorAction SilentlyContinue)) {
    BeforeEach {
        $script:Root = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
        $script:Snapshots = Join-Path $Root 'TenantGovernance/Snapshots'
        $script:AppRoot = Join-Path $Root 'Reports/ConfigurationAnalyzer'
        New-Item -ItemType Directory -Path (Join-Path $Snapshots 'microsoft.entra.test'), $AppRoot -Force | Out-Null
        & git -C $Root init --quiet
        if ($LASTEXITCODE -ne 0) { throw 'Could not initialize snapshot history fixture.' }
    }

    It 'keeps completed captures and excludes pending and failed attempts with interval <Interval>' -ForEach @(
        @{ Interval = 'P1W' }
        @{ Interval = 'None' }
    ) {
        Publish-HistoryTestSnapshot -Date '2026-10-02T07:00:00Z' -Id 'week1' -Value 'unchanged'
        Save-HistoryTestBookkeeping -Date '2026-10-09T06:00:00Z' -Name '.PendingSnapshotJob.json' -Id 'week2'
        Save-HistoryTestBookkeeping -Date '2026-10-09T06:30:00Z' -Name '.PendingSnapshotJob.json' -Id 'week2'
        # This successful capture changes only its manifest: the resources are unchanged.
        Publish-HistoryTestSnapshot -Date '2026-10-09T07:00:00Z' -Id 'week2' -Value 'unchanged'
        Save-HistoryTestBookkeeping -Date '2026-10-16T06:00:00Z' -Name '.PendingSnapshotJob.json' -Id 'week3'
        Publish-HistoryTestSnapshot -Date '2026-10-16T07:00:00Z' -Id 'week3' -Value 'updated'
        Save-HistoryTestBookkeeping -Date '2026-10-23T06:00:00Z' -Name '.PendingSnapshotJob.json' -Id 'week4'
        Save-HistoryTestBookkeeping -Date '2026-10-23T06:30:00Z' -Name '.LastAttemptManifest.json' -Id 'week4-failed'

        $Payload = New-EntraOpsTenantGovernanceConfigurationAnalyzerData -RepoRoot $Root -AppRoot $AppRoot `
            -SnapshotInterval $Interval -ResolveGroupMembersForPrivilegedAssets $false -AllowStaleSnapshot `
            -SkipWorkingTree -PassThru -WarningAction SilentlyContinue 6>$null

        @($Payload.snapshots.subject) | Should -Be @('Complete week1', 'Complete week2', 'Complete week3')
        @($Payload.snapshots | ForEach-Object { $Payload.blobs[$_.resources[0].h].properties.displayName }) |
            Should -Be @('unchanged', 'unchanged', 'updated')
    }
}

Describe 'Configuration Analyzer without git history' {
    BeforeEach {
        # A folder outside any git working copy (TestDrive is not a git repository).
        $script:Root = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
        $script:Snapshots = Join-Path $Root 'TenantGovernance/Snapshots'
        $script:AppRoot = Join-Path $Root 'Reports/ConfigurationAnalyzer'
        New-Item -ItemType Directory -Path (Join-Path $Snapshots 'microsoft.entra.test'), $AppRoot -Force | Out-Null
        @{ resourceType = 'microsoft.entra.test'; properties = @{ Id = 'fixture-resource'; displayName = 'current' } } | ConvertTo-Json |
            Set-Content -LiteralPath (Join-Path $Snapshots 'microsoft.entra.test/resource.json')
        @{ SnapshotId = 'local'; SnapshotJobStatus = 'succeeded'; IsComplete = $true; CapturedDateTime = (Get-Date).ToUniversalTime().AddHours(-1).ToString('o')
            PublishedResourceTypes = @('microsoft.entra.test'); PublishedResourceTypeCounts = @{ 'microsoft.entra.test' = 1 }
        } | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $Snapshots '.SnapshotManifest.json')
    }

    It 'uses the current snapshot folder as one snapshot with content (<Source>)' -ForEach @(
        @{ Source = 'Auto' }
        @{ Source = 'Folder' }
    ) {
        $Payload = New-EntraOpsTenantGovernanceConfigurationAnalyzerData -RepoRoot $Root -AppRoot $AppRoot -HistorySource $Source `
            -ResolveGroupMembersForPrivilegedAssets $false -PassThru -WarningVariable Warnings -WarningAction SilentlyContinue -InformationVariable Information 6>$null

        $Payload.historySource | Should -Be 'folder'
        @($Payload.snapshots).Count | Should -Be 1
        $Payload.snapshots[0].commitSha | Should -Be '(snapshot folder)'
        $Payload.snapshots[0].hasDetail | Should -BeTrue
        $Payload.snapshotFolder | Should -Be 'TenantGovernance/Snapshots'
        $Payload.blobs[$Payload.snapshots[0].resources[0].h].properties.displayName | Should -Be 'current'
        # The fallback is a notice, not a warning.
        @($Warnings | Where-Object { "$_" -like '*history*' }).Count | Should -Be 0
        @($Information | Where-Object { "$_" -like 'History source:*no history and drift*' }).Count | Should -Be 1
    }

    It 'names the resource types with export errors of a partial snapshot instead of an empty stale list' {
        @{ SnapshotId = 'partial'; SnapshotJobStatus = 'partiallySuccessful'; IsComplete = $false; CapturedDateTime = (Get-Date).ToUniversalTime().AddHours(-1).ToString('o')
            PublishedResourceTypes = @('microsoft.entra.test'); PublishedResourceTypeCounts = @{ 'microsoft.entra.test' = 1 }
            StaleResourceTypes = @(); PublishedWithErrorsResourceTypes = @('microsoft.entra.conditionalaccesspolicy')
            ResourceTypeStates = @(@{ ResourceType = 'microsoft.entra.test'; State = 'PublishedWithErrors' })
        } | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $Snapshots '.SnapshotManifest.json')

        $null = New-EntraOpsTenantGovernanceConfigurationAnalyzerData -RepoRoot $Root -AppRoot $AppRoot -AllowPartialSnapshot `
            -ResolveGroupMembersForPrivilegedAssets $false -PassThru -WarningVariable Warnings -WarningAction SilentlyContinue 6>$null

        $PartialWarning = @($Warnings | Where-Object { "$_" -like '*partial Tenant Governance snapshot*' })
        $PartialWarning.Count | Should -Be 1
        "$($PartialWarning[0])" | Should -BeLike '*per-resource export errors*microsoft.entra.conditionalaccesspolicy*'
        "$($PartialWarning[0])" | Should -Not -BeLike '*Stale resource types: .*'
    }

    It 'uses a snapshot folder outside the git working copy like Folder (Auto), and fails with -HistorySource Git' -Skip:(-not (Get-Command git -ErrorAction SilentlyContinue)) {
        # The working folder is a git working copy, the snapshot folder (-ImportPath) is somewhere else.
        $Repo = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
        $RepoAppRoot = Join-Path $Repo 'Reports/ConfigurationAnalyzer'
        New-Item -ItemType Directory -Path $RepoAppRoot -Force | Out-Null
        & git -C $Repo init --quiet

        $Payload = New-EntraOpsTenantGovernanceConfigurationAnalyzerData -RepoRoot $Repo -AppRoot $RepoAppRoot -ImportPath $Snapshots `
            -ResolveGroupMembersForPrivilegedAssets $false -PassThru -WarningAction SilentlyContinue 6>$null

        $Payload.historySource | Should -Be 'folder'
        @($Payload.snapshots).Count | Should -Be 1
        { New-EntraOpsTenantGovernanceConfigurationAnalyzerData -RepoRoot $Repo -AppRoot $RepoAppRoot -ImportPath $Snapshots -HistorySource Git -ResolveGroupMembersForPrivilegedAssets $false 6>$null } |
            Should -Throw '*is not inside the git working copy*'
    }

    It 'fails with -HistorySource Git outside a git working copy' {
        { New-EntraOpsTenantGovernanceConfigurationAnalyzerData -RepoRoot $Root -AppRoot $AppRoot -HistorySource Git -ResolveGroupMembersForPrivilegedAssets $false 6>$null } |
            Should -Throw '*not inside a git working copy*'
    }

    It 'hashes the files like git' -Skip:(-not (Get-Command git -ErrorAction SilentlyContinue)) {
        $File = Join-Path $Snapshots 'microsoft.entra.test/resource.json'
        # --no-filters: the hash covers the raw bytes, also with core.autocrlf (Windows runners write CRLF).
        & (Get-Module EntraOps) { param($Path) Get-EntraOpsGitBlobHash -LiteralPath $Path } $File | Should -Be (& git hash-object --no-filters -- $File)
    }
}

Describe 'Configuration Analyzer group resolution' {
    It 'resolves the groups that Conditional Access policies exclude, not only the included ones' {
        $Root = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
        $Snapshots = Join-Path $Root 'TenantGovernance/Snapshots'
        $PolicyFolder = Join-Path $Snapshots 'microsoft.entra.conditionalaccesspolicy'
        $AppRoot = Join-Path $Root 'Reports/ConfigurationAnalyzer'
        New-Item -ItemType Directory -Path $PolicyFolder, $AppRoot, (Join-Path $Root 'PrivilegedEAM/EntraID') -Force | Out-Null
        $IncludedId = '11111111-1111-1111-1111-111111111111'
        $ExcludedId = '22222222-2222-2222-2222-222222222222'
        @{ resourceType = 'microsoft.entra.conditionalaccesspolicy'; properties = @{ Id = 'ca1'; DisplayName = 'Require MFA'; State = 'enabled'; IncludeGroups = @($IncludedId); ExcludeGroups = @($ExcludedId) } } |
            ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $PolicyFolder 'ca1.json')
        @{
            SnapshotId = 'snapshot-1'; SnapshotJobStatus = 'succeeded'; IsComplete = $true; CapturedDateTime = (Get-Date).ToUniversalTime().ToString('o')
            PublishedResourceTypes = @('microsoft.entra.conditionalaccesspolicy'); PublishedResourceTypeCounts = @{ 'microsoft.entra.conditionalaccesspolicy' = 1 }
        } | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $Snapshots '.SnapshotManifest.json')
        @([ordered]@{ ObjectId = 'cp-user'; ObjectType = 'user'; ObjectDisplayName = 'CP Admin'; ObjectAdminTierLevel = '0'; ObjectAdminTierLevelName = 'ControlPlane'; RoleSystem = 'EntraID'; RoleAssignments = @() }) |
            ConvertTo-Json -Depth 5 -AsArray | Set-Content -LiteralPath (Join-Path $Root 'PrivilegedEAM/EntraID/EntraID.json')

        Mock -ModuleName EntraOps Invoke-EntraOpsMsGraphQuery { [pscustomobject]@{ Id = ($Uri -split '/groups/')[1].Split('?')[0]; DisplayName = 'Group' } }
        Mock -ModuleName EntraOps Get-EntraOpsPrivilegedTransitiveGroupMember { [pscustomobject]@{ Id = 'cp-user'; DisplayName = 'CP Admin' } }

        $Payload = New-EntraOpsTenantGovernanceConfigurationAnalyzerData -RepoRoot $Root -AppRoot $AppRoot -HistorySource Folder `
            -ResolveGroupMembersForPrivilegedAssets $true -PassThru -WarningAction SilentlyContinue 6>$null

        @($Payload.resolvedGroupTiers.Keys | Sort-Object) | Should -Be @($IncludedId, $ExcludedId)
        $Payload.resolvedGroupTiers[$ExcludedId].tierName | Should -Be 'ControlPlane'
    }

    It 'resolves a PIM approver group whose name contains an @' {
        $Root = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
        $Snapshots = Join-Path $Root 'TenantGovernance/Snapshots'
        $SettingFolder = Join-Path $Snapshots 'microsoft.entra.rolesetting'
        $AppRoot = Join-Path $Root 'Reports/ConfigurationAnalyzer'
        New-Item -ItemType Directory -Path $SettingFolder, $AppRoot, (Join-Path $Root 'PrivilegedEAM/EntraID') -Force | Out-Null
        @{ resourceType = 'microsoft.entra.rolesetting'; properties = @{ Id = 'role1'; DisplayName = 'Global Administrator'; ActivateApprover = @('Approvers@HQ', 'AdeleV@contoso.com') } } |
            ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $SettingFolder 'role1.json')
        @{
            SnapshotId = 'snapshot-1'; SnapshotJobStatus = 'succeeded'; IsComplete = $true; CapturedDateTime = (Get-Date).ToUniversalTime().ToString('o')
            PublishedResourceTypes = @('microsoft.entra.rolesetting'); PublishedResourceTypeCounts = @{ 'microsoft.entra.rolesetting' = 1 }
        } | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $Snapshots '.SnapshotManifest.json')
        @([ordered]@{ ObjectId = 'cp-user'; ObjectType = 'user'; ObjectDisplayName = 'CP Admin'; ObjectAdminTierLevel = '0'; ObjectAdminTierLevelName = 'ControlPlane'; RoleSystem = 'EntraID'; RoleAssignments = @() }) |
            ConvertTo-Json -Depth 5 -AsArray | Set-Content -LiteralPath (Join-Path $Root 'PrivilegedEAM/EntraID/EntraID.json')
        # The group is found by its display name; the user principal name matches no group.
        Mock -ModuleName EntraOps Invoke-EntraOpsMsGraphQuery { if ($Uri -like "*Approvers@HQ*" -or $Uri -like "*Approvers%40HQ*") { [pscustomobject]@{ Id = '11111111-1111-1111-1111-111111111111'; DisplayName = 'Approvers@HQ' } } }
        Mock -ModuleName EntraOps Get-EntraOpsPrivilegedTransitiveGroupMember { [pscustomobject]@{ Id = 'cp-user'; DisplayName = 'CP Admin' } }

        $Payload = New-EntraOpsTenantGovernanceConfigurationAnalyzerData -RepoRoot $Root -AppRoot $AppRoot -HistorySource Folder `
            -ResolveGroupMembersForPrivilegedAssets $true -PassThru -WarningAction SilentlyContinue 6>$null

        @($Payload.resolvedGroupTiers.Keys) | Should -Be @('11111111-1111-1111-1111-111111111111')
        $Payload.resolvedGroupTiers['11111111-1111-1111-1111-111111111111'].displayName | Should -Be 'Approvers@HQ'
    }

    It 'skips a deleted access package assignment policy with one summarised warning' {
        $Root = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
        $Snapshots = Join-Path $Root 'TenantGovernance/Snapshots'
        $Type = 'microsoft.entra.entitlementmanagementaccesspackageassignmentpolicy'
        $PolicyFolder = Join-Path $Snapshots $Type
        $AppRoot = Join-Path $Root 'Reports/ConfigurationAnalyzer'
        New-Item -ItemType Directory -Path $PolicyFolder, $AppRoot, (Join-Path $Root 'PrivilegedEAM/EntraID') -Force | Out-Null
        $GroupId = '11111111-1111-1111-1111-111111111111'
        foreach ($PolicyId in 'policy-1', 'deleted-policy') {
            @{ resourceType = $Type; properties = @{ Id = $PolicyId; DisplayName = $PolicyId } } | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $PolicyFolder "$PolicyId.json")
        }
        @{
            SnapshotId = 'snapshot-1'; SnapshotJobStatus = 'succeeded'; IsComplete = $true; CapturedDateTime = (Get-Date).ToUniversalTime().ToString('o')
            PublishedResourceTypes = @($Type); PublishedResourceTypeCounts = @{ $Type = 2 }
        } | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $Snapshots '.SnapshotManifest.json')
        @([ordered]@{ ObjectId = 'cp-user'; ObjectType = 'user'; ObjectDisplayName = 'CP Admin'; ObjectAdminTierLevel = '0'; ObjectAdminTierLevelName = 'ControlPlane'; RoleSystem = 'EntraID'; RoleAssignments = @() }) |
            ConvertTo-Json -Depth 5 -AsArray | Set-Content -LiteralPath (Join-Path $Root 'PrivilegedEAM/EntraID/EntraID.json')
        Mock -ModuleName EntraOps Invoke-EntraOpsMsGraphQuery {
            if ($Uri -like '*/accessPackageAssignmentPolicies/deleted-policy') {
                # Same shape as the error Invoke-EntraOpsMsGraphQuery -ThrowOnFailure throws for a 404
                $Exception = [System.InvalidOperationException]::new("Microsoft Graph query '$Uri' failed: NotFound")
                $Exception.Data['StatusCode'] = 404
                throw $Exception
            }
            if ($Uri -like '*/accessPackageAssignmentPolicies/policy-1') {
                return [pscustomobject]@{ requestorSettings = [pscustomobject]@{ allowedRequestors = @([pscustomobject]@{ '@odata.type' = '#microsoft.graph.groupMembers'; id = '11111111-1111-1111-1111-111111111111' }) } }
            }
            [pscustomobject]@{ Id = '11111111-1111-1111-1111-111111111111'; DisplayName = 'Requestors' }
        }
        Mock -ModuleName EntraOps Get-EntraOpsPrivilegedTransitiveGroupMember { [pscustomobject]@{ Id = 'cp-user'; DisplayName = 'CP Admin' } }

        $Payload = New-EntraOpsTenantGovernanceConfigurationAnalyzerData -RepoRoot $Root -AppRoot $AppRoot -HistorySource Folder `
            -ResolveGroupMembersForPrivilegedAssets $true -PassThru -WarningVariable Warnings -WarningAction SilentlyContinue 6>$null

        @($Payload.resolvedGroupTiers.Keys) | Should -Be @($GroupId)
        $PolicyWarnings = @($Warnings | Where-Object { "$_" -match 'deleted-policy' })
        $PolicyWarnings.Count | Should -Be 1
        "$($PolicyWarnings[0])" | Should -Match 'NotFound'
        "$($PolicyWarnings[0])" | Should -Not -Match 'Could not resolve'
    }

    It 'looks up only the access package assignment policies of the latest snapshot, not those left in the git history' -Skip:(-not (Get-Command git -ErrorAction SilentlyContinue)) {
        $Root = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
        $Snapshots = Join-Path $Root 'TenantGovernance/Snapshots'
        $Type = 'microsoft.entra.entitlementmanagementaccesspackageassignmentpolicy'
        $PolicyFolder = Join-Path $Snapshots $Type
        $AppRoot = Join-Path $Root 'Reports/ConfigurationAnalyzer'
        New-Item -ItemType Directory -Path $PolicyFolder, $AppRoot, (Join-Path $Root 'PrivilegedEAM/EntraID') -Force | Out-Null
        & git -C $Root init --quiet
        @([ordered]@{ ObjectId = 'cp-user'; ObjectType = 'user'; ObjectDisplayName = 'CP Admin'; ObjectAdminTierLevel = '0'; ObjectAdminTierLevelName = 'ControlPlane'; RoleSystem = 'EntraID'; RoleAssignments = @() }) |
            ConvertTo-Json -Depth 5 -AsArray | Set-Content -LiteralPath (Join-Path $Root 'PrivilegedEAM/EntraID/EntraID.json')
        foreach ($Capture in @(
                @{ Date = '2026-10-02T07:00:00Z'; Id = 'week1'; Policies = @('policy-1', 'removed-policy') }
                @{ Date = '2026-10-09T07:00:00Z'; Id = 'week2'; Policies = @('policy-1') }
            )) {
            Get-ChildItem -LiteralPath $PolicyFolder -File | Remove-Item -Force
            foreach ($PolicyId in $Capture.Policies) {
                @{ resourceType = $Type; properties = @{ Id = $PolicyId; DisplayName = $PolicyId } } | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $PolicyFolder "$PolicyId.json")
            }
            @{
                SnapshotId = $Capture.Id; SnapshotJobStatus = 'succeeded'; IsComplete = $true; CapturedDateTime = $Capture.Date
                PublishedResourceTypes = @($Type); PublishedResourceTypeCounts = @{ $Type = $Capture.Policies.Count }
            } | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $Snapshots '.SnapshotManifest.json')
            Save-HistoryTestCommit -Date $Capture.Date -Message "Complete $($Capture.Id)"
        }
        Mock -ModuleName EntraOps Invoke-EntraOpsMsGraphQuery { [pscustomobject]@{ requestorSettings = [pscustomobject]@{ allowedRequestors = @() } } }
        Mock -ModuleName EntraOps Get-EntraOpsPrivilegedTransitiveGroupMember { }

        $Payload = New-EntraOpsTenantGovernanceConfigurationAnalyzerData -RepoRoot $Root -AppRoot $AppRoot -HistorySource Git -SnapshotInterval None `
            -SkipWorkingTree -AllowStaleSnapshot -ResolveGroupMembersForPrivilegedAssets $true -PassThru -WarningVariable Warnings -WarningAction SilentlyContinue 6>$null

        @($Payload.snapshots).Count | Should -Be 2
        Should -Invoke -ModuleName EntraOps Invoke-EntraOpsMsGraphQuery -Times 1 -Exactly -ParameterFilter { $Uri -like '*/accessPackageAssignmentPolicies/policy-1' }
        Should -Invoke -ModuleName EntraOps Invoke-EntraOpsMsGraphQuery -Times 0 -ParameterFilter { $Uri -like '*/accessPackageAssignmentPolicies/removed-policy' }
        @($Warnings | Where-Object { "$_" -match 'removed-policy' }).Count | Should -Be 0
    }

    It 'does not resolve groups with a connection to another tenant than the one of the snapshot' {
        $Root = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
        $Snapshots = Join-Path $Root 'TenantGovernance/Snapshots'
        $PolicyFolder = Join-Path $Snapshots 'microsoft.entra.conditionalaccesspolicy'
        $AppRoot = Join-Path $Root 'Reports/ConfigurationAnalyzer'
        New-Item -ItemType Directory -Path $PolicyFolder, $AppRoot, (Join-Path $Root 'PrivilegedEAM/EntraID') -Force | Out-Null
        @{ resourceType = 'microsoft.entra.conditionalaccesspolicy'; properties = @{ Id = 'ca1'; DisplayName = 'Require MFA'; State = 'enabled'; ExcludeGroups = @('Break Glass') } } |
            ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $PolicyFolder 'ca1.json')
        @{
            TenantId = '00000000-0000-0000-0000-000000000001'; TenantName = 'contoso.onmicrosoft.com'
            SnapshotId = 'snapshot-1'; SnapshotJobStatus = 'succeeded'; IsComplete = $true; CapturedDateTime = (Get-Date).ToUniversalTime().ToString('o')
            PublishedResourceTypes = @('microsoft.entra.conditionalaccesspolicy'); PublishedResourceTypeCounts = @{ 'microsoft.entra.conditionalaccesspolicy' = 1 }
        } | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $Snapshots '.SnapshotManifest.json')
        @([ordered]@{ ObjectId = 'cp-user'; ObjectType = 'user'; ObjectDisplayName = 'CP Admin'; ObjectAdminTierLevel = '0'; ObjectAdminTierLevelName = 'ControlPlane'; RoleSystem = 'EntraID'; RoleAssignments = @() }) |
            ConvertTo-Json -Depth 5 -AsArray | Set-Content -LiteralPath (Join-Path $Root 'PrivilegedEAM/EntraID/EntraID.json')
        # A group of the same name in the connected (other) tenant.
        Mock -ModuleName EntraOps Invoke-EntraOpsMsGraphQuery { [pscustomobject]@{ Id = '22222222-2222-2222-2222-222222222222'; DisplayName = 'Break Glass' } }
        Mock -ModuleName EntraOps Get-EntraOpsPrivilegedTransitiveGroupMember { [pscustomobject]@{ Id = 'cp-user'; DisplayName = 'CP Admin' } }

        $PreviousTenantIdContext = $Global:TenantIdContext
        try {
            $Global:TenantIdContext = '00000000-0000-0000-0000-000000000002'
            $Payload = New-EntraOpsTenantGovernanceConfigurationAnalyzerData -RepoRoot $Root -AppRoot $AppRoot -HistorySource Folder `
                -ResolveGroupMembersForPrivilegedAssets $true -PassThru -WarningVariable Warnings -WarningAction SilentlyContinue 6>$null
        } finally {
            $Global:TenantIdContext = $PreviousTenantIdContext
        }

        @($Payload.resolvedGroupTiers.Keys).Count | Should -Be 0
        Should -Invoke -ModuleName EntraOps Invoke-EntraOpsMsGraphQuery -Times 0
        ($Warnings -join ' ') | Should -Match 'snapshot belongs to tenant 00000000-0000-0000-0000-000000000001, but the connection is to tenant 00000000-0000-0000-0000-000000000002'
    }
}
