#Requires -Modules Pester

Describe 'Privilege History without git history' {
    BeforeAll {
        $RepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
        Import-Module (Join-Path $RepositoryRoot 'EntraOps') -Force -WarningAction SilentlyContinue
    }

    BeforeEach {
        # A folder outside any git working copy (TestDrive is not a git repository).
        $script:Root = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
        $script:AppRoot = Join-Path $Root 'Reports/PrivilegeHistory'
        New-Item -ItemType Directory -Path (Join-Path $Root 'PrivilegedEAM/EntraID'), $AppRoot -Force | Out-Null
        @(
            [ordered]@{
                ObjectId = '11111111-1111-1111-1111-111111111111'; ObjectType = 'user'; ObjectSubType = 'Member'; ObjectDisplayName = 'Admin A'
                ObjectAdminTierLevel = '1'; ObjectAdminTierLevelName = 'ManagementPlane'
                RoleAssignments = @(@{ RoleAssignmentId = 'ra1'; RoleDefinitionName = 'Global Administrator'; RoleAssignmentScopeId = '/'; Classification = @(@{ AdminTierLevelName = 'ControlPlane'; Service = 'Global' }) })
            }
        ) | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath (Join-Path $Root 'PrivilegedEAM/EntraID/EntraID.json')
    }

    It 'compares an unclassified object as User Access for tier breaches' {
        @(
            [ordered]@{
                ObjectId = '22222222-2222-2222-2222-222222222222'; ObjectType = 'serviceprincipal'; ObjectSubType = 'Application'; ObjectDisplayName = 'Client'
                ObjectAdminTierLevel = 'Unclassified'; ObjectAdminTierLevelName = 'Unclassified'
                RoleAssignments = @(
                    # A User Access role of an unclassified object is no breach; a Management Plane role is.
                    @{ RoleAssignmentId = 'ra-ua'; RoleDefinitionName = 'User.Read'; RoleAssignmentScopeId = '/'; Classification = @(@{ AdminTierLevelName = 'UserAccess'; Service = 'Default' }) }
                    @{ RoleAssignmentId = 'ra-mp'; RoleDefinitionName = 'AuditLog.Read.All'; RoleAssignmentScopeId = '/'; Classification = @(@{ AdminTierLevelName = 'ManagementPlane'; Service = 'Security' }) }
                )
            }
        ) | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath (Join-Path $Root 'PrivilegedEAM/EntraID/EntraID.json')
        $Payload = @(New-EntraOpsPrivilegedEamPrivilegeHistoryData -RepoRoot $Root -AppRoot $AppRoot -HistorySource Folder -PassThru -WarningAction SilentlyContinue 6>$null | Where-Object { $_ -is [System.Collections.IDictionary] })[0]
        $Payload.snapshots[0].totals.tierBreaches | Should -Be 1
    }

    It 'writes the role type, the resource of delegated permissions and the Microsoft first-party flags for the drift rules' {
        New-Item -ItemType Directory -Path (Join-Path $Root 'PrivilegedEAM/ResourceApps') -Force | Out-Null
        @(
            [ordered]@{
                ObjectId = '33333333-3333-3333-3333-333333333333'; ObjectType = 'serviceprincipal'; ObjectSubType = 'Application'; ObjectDisplayName = 'Microsoft Graph Command Line Tools'
                ObjectUserPrincipalName = '14d82eec-204b-4c2f-b7e8-296a70dab67e'; OriginTenantId = 'cdc5aeea-15c5-4db6-b079-fcadd2505dc2'
                ObjectAdminTierLevel = 'Unclassified'; ObjectAdminTierLevelName = 'Unclassified'
                RoleAssignments = @(@{ RoleAssignmentId = 'g1'; RoleAssignmentInstanceId = 'g1-mail'; RoleDefinitionName = 'Mail.Read'; RoleType = 'Delegated'; RoleAssignmentScopeId = '/'; RoleAssignmentScopeName = 'Microsoft Graph'; Classification = @(@{ AdminTierLevelName = 'ManagementPlane'; Service = 'Mail' }) })
            }
        ) | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath (Join-Path $Root 'PrivilegedEAM/ResourceApps/ResourceApps.json')
        $Payload = @(New-EntraOpsPrivilegedEamPrivilegeHistoryData -RepoRoot $Root -AppRoot $AppRoot -HistorySource Folder -PassThru -WarningAction SilentlyContinue 6>$null | Where-Object { $_ -is [System.Collections.IDictionary] })[0]
        $Client = @($Payload.snapshots[0].objects | Where-Object { $_.objectId -eq '33333333-3333-3333-3333-333333333333' })[0]
        $Client.isMicrosoftFirstParty | Should -BeTrue
        $Client.isMicrosoftConsentClient | Should -BeTrue
        $Client.roleAssignments[0].roleType | Should -Be 'Delegated'
        $Client.roleAssignments[0].resourceName | Should -Be 'Microsoft Graph'
        $Admin = @($Payload.snapshots[0].objects | Where-Object { $_.objectId -eq '11111111-1111-1111-1111-111111111111' })[0]
        $Admin.isMicrosoftFirstParty | Should -BeFalse
        $Admin.roleAssignments[0].Keys | Should -Contain 'roleType'
        # The chart still counts every tier breach, the delegated permission included.
        $Payload.snapshots[0].totals.tierBreaches | Should -Be 2
    }

    It 'uses the current export as the only snapshot (<Source>)' -ForEach @(
        @{ Source = 'Auto' }
        @{ Source = 'Folder' }
    ) {
        $Information = New-EntraOpsPrivilegedEamPrivilegeHistoryData -RepoRoot $Root -AppRoot $AppRoot -HistorySource $Source -PassThru -WarningVariable Warnings -WarningAction SilentlyContinue 6>&1
        $Payload = @($Information | Where-Object { $_ -is [System.Collections.IDictionary] })[0]

        $Payload.historySource | Should -Be 'folder'
        @($Payload.snapshots).Count | Should -Be 1
        $Payload.snapshots[0].commitSha | Should -Be '(current export)'
        $Payload.snapshots[0].workingTree | Should -BeTrue
        $Payload.snapshots[0].totals.tierBreaches | Should -Be 1
        "$AppRoot/data/privilege-history-data.js" | Should -Exist
        # A working folder without git is a supported setup: an informational line, no warning.
        $Warnings | Should -BeNullOrEmpty
        ($Information | Where-Object { $_ -is [System.Management.Automation.InformationRecord] }) -join "`n" | Should -Match 'History source:\s+current export only, no trend'
    }

    It 'fails with -HistorySource Git outside a git working copy' {
        { New-EntraOpsPrivilegedEamPrivilegeHistoryData -RepoRoot $Root -AppRoot $AppRoot -HistorySource Git 6>$null } | Should -Throw '*not inside a git working copy*'
    }
}

Describe 'Privilege History from the git history' -Skip:(-not (Get-Command git -ErrorAction SilentlyContinue)) {
    BeforeAll {
        $RepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
        Import-Module (Join-Path $RepositoryRoot 'EntraOps') -Force -WarningAction SilentlyContinue

        function Save-PrivilegeHistoryTestExport {
            param([string]$TierLevelName = 'ManagementPlane')
            @(
                [ordered]@{
                    ObjectId = '11111111-1111-1111-1111-111111111111'; ObjectType = 'user'; ObjectSubType = 'Member'; ObjectDisplayName = 'Admin A'
                    ObjectAdminTierLevel = '1'; ObjectAdminTierLevelName = $TierLevelName
                    RoleAssignments = @(@{ RoleAssignmentId = 'ra1'; RoleDefinitionName = 'Global Administrator'; RoleAssignmentScopeId = '/'; Classification = @(@{ AdminTierLevelName = 'ControlPlane'; Service = 'Global' }) })
                }
            ) | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath (Join-Path $Root 'PrivilegedEAM/EntraID/EntraID.json')
        }

        function Save-PrivilegeHistoryTestCommit {
            param([string]$Date, [string]$Message)
            & git -C $Root add --all
            if ($LASTEXITCODE -ne 0) { throw 'Could not stage the export fixture.' }
            $PreviousAuthorDate = $env:GIT_AUTHOR_DATE
            $PreviousCommitterDate = $env:GIT_COMMITTER_DATE
            try {
                $env:GIT_AUTHOR_DATE = $Date
                $env:GIT_COMMITTER_DATE = $Date
                & git -C $Root -c user.name=EntraOps -c user.email=fixture@example.com -c commit.gpgsign=false commit --quiet -m $Message
                if ($LASTEXITCODE -ne 0) { throw "Could not commit the export fixture '$Message'." }
            } finally {
                $env:GIT_AUTHOR_DATE = $PreviousAuthorDate
                $env:GIT_COMMITTER_DATE = $PreviousCommitterDate
            }
        }
    }

    BeforeEach {
        $script:Root = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
        $script:AppRoot = Join-Path $Root 'Reports/PrivilegeHistory'
        New-Item -ItemType Directory -Path (Join-Path $Root 'PrivilegedEAM/EntraID'), $AppRoot -Force | Out-Null
        & git -C $Root init --quiet
        if ($LASTEXITCODE -ne 0) { throw 'Could not initialize the export history fixture.' }
    }

    It 'adds the uncommitted export as the newest snapshot' {
        Save-PrivilegeHistoryTestExport
        Save-PrivilegeHistoryTestCommit -Date '2026-10-01T07:00:00Z' -Message 'Export 1'
        Save-PrivilegeHistoryTestExport -TierLevelName 'ControlPlane'

        $Payload = New-EntraOpsPrivilegedEamPrivilegeHistoryData -RepoRoot $Root -AppRoot $AppRoot -SnapshotInterval 'None' -PassThru 6>$null

        $Payload.historySource | Should -Be 'git'
        @($Payload.snapshots).Count | Should -Be 2
        $Payload.snapshots[0].workingTree | Should -BeNullOrEmpty
        $Payload.snapshots[0].totals.tierBreaches | Should -Be 1
        $Payload.snapshots[1].commitSha | Should -Be '(working tree)'
        $Payload.snapshots[1].workingTree | Should -BeTrue
        $Payload.snapshots[1].totals.tierBreaches | Should -Be 0
        [datetimeoffset]$Payload.snapshots[1].commitDate | Should -BeGreaterThan ([datetimeoffset]$Payload.snapshots[0].commitDate)
    }

    It 'adds no snapshot for an export that matches HEAD' {
        Save-PrivilegeHistoryTestExport
        Save-PrivilegeHistoryTestCommit -Date '2026-10-01T07:00:00Z' -Message 'Export 1'

        $Payload = New-EntraOpsPrivilegedEamPrivilegeHistoryData -RepoRoot $Root -AppRoot $AppRoot -PassThru 6>$null

        @($Payload.snapshots).Count | Should -Be 1
        $Payload.snapshots[0].commitSha | Should -Not -Be '(working tree)'
    }

    It 'uses the current export like Folder when the export has no commits (Auto)' {
        Save-PrivilegeHistoryTestExport

        $Payload = New-EntraOpsPrivilegedEamPrivilegeHistoryData -RepoRoot $Root -AppRoot $AppRoot -PassThru -WarningVariable Warnings -WarningAction SilentlyContinue 6>$null

        $Payload.historySource | Should -Be 'folder'
        @($Payload.snapshots).Count | Should -Be 1
        $Payload.snapshots[0].commitSha | Should -Be '(current export)'
        $Warnings | Should -BeNullOrEmpty
    }

    It 'uses an export outside the git working copy like Folder (Auto), and fails with -HistorySource Git' {
        Save-PrivilegeHistoryTestExport
        $Outside = Join-Path $TestDrive "outside-$([guid]::NewGuid().ToString('N'))"
        Copy-Item -LiteralPath (Join-Path $Root 'PrivilegedEAM') -Destination $Outside -Recurse

        $Payload = New-EntraOpsPrivilegedEamPrivilegeHistoryData -RepoRoot $Root -AppRoot $AppRoot -ImportPath $Outside -PassThru -WarningAction SilentlyContinue 6>$null

        $Payload.historySource | Should -Be 'folder'
        @($Payload.snapshots).Count | Should -Be 1
        { New-EntraOpsPrivilegedEamPrivilegeHistoryData -RepoRoot $Root -AppRoot $AppRoot -ImportPath $Outside -HistorySource Git 6>$null } | Should -Throw '*is not inside the git working copy*'
    }

    It 'reads the uncommitted export with -HistorySource Git when the export has no commits' {
        Save-PrivilegeHistoryTestExport

        $Payload = New-EntraOpsPrivilegedEamPrivilegeHistoryData -RepoRoot $Root -AppRoot $AppRoot -HistorySource Git -PassThru -WarningVariable Warnings -WarningAction SilentlyContinue 6>$null

        $Payload.historySource | Should -Be 'git'
        @($Payload.snapshots).Count | Should -Be 1
        $Payload.snapshots[0].commitSha | Should -Be '(working tree)'
        ($Warnings -join ' ') | Should -Match 'uncommitted Privileged EAM export'
    }
}
