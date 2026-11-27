#Requires -Modules Pester

BeforeDiscovery {
    $script:NodeMissing = $null -eq (Get-Command node -ErrorAction SilentlyContinue)
}

Describe 'Privileged Assets findings' {
    BeforeAll {
        $script:TestRepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
        Import-Module (Join-Path $script:TestRepositoryRoot 'EntraOps/EntraOps.psd1') -Force -WarningAction SilentlyContinue
        $script:Harness = Join-Path $PSScriptRoot 'Get-PrivilegedAssetsReportFinding.cjs'

        function Get-TestObjectId([int]$Number) { '{0:x8}-0000-0000-0000-{1:x12}' -f $Number, $Number }

        function New-TestRoleAssignment([string]$Tier, [string]$Name = 'Role') {
            [ordered]@{ RoleDefinitionName = $Name; RoleAssignmentInstanceId = "i-$Name-$Tier"; PIMAssignmentType = 'Eligible'; RoleAssignmentScopeId = '/'; Classification = @(@{ AdminTierLevelName = $Tier; Service = "S-$Tier" }) }
        }

        function New-TestObject([int]$Number, [string]$Type, [string]$Tier, [hashtable]$Property = @{}) {
            $Object = [ordered]@{ ObjectId = (Get-TestObjectId $Number); ObjectType = $Type; ObjectSubType = 'Member'; ObjectDisplayName = "Object $Number"; ObjectTenantId = 'tenant-1'; ObjectAdminTierLevelName = $Tier; RoleAssignments = @() }
            foreach ($Key in $Property.Keys) { $Object[$Key] = $Property[$Key] }
            $Object
        }

        # One object per rule (plus related objects), so every rule fails at least once.
        function Get-TestExport([hashtable]$TierByNumber = @{}) {
            $Tier = { param($Number, $Default) if ($TierByNumber.ContainsKey($Number)) { $TierByNumber[$Number] } else { $Default } }
            @(
                New-TestObject 1 'user' (& $Tier 1 'ControlPlane') @{ RoleAssignments = @(New-TestRoleAssignment 'ControlPlane'); OwnedDevices = @((Get-TestObjectId 900), (Get-TestObjectId 901)); AssociatedPawDevice = @((Get-TestObjectId 900).ToUpper()) }
                New-TestObject 2 'user' (& $Tier 2 'ManagementPlane') @{ RoleAssignments = @(New-TestRoleAssignment 'ControlPlane'); OnPremSynchronized = $true }
                # A role-assignable group in a restricted management administrative unit ("Conflict"): protected by the group.
                New-TestObject 3 'group' (& $Tier 3 'ControlPlane') @{ ObjectSubType = 'Role-assignable'; RestrictedManagementByRMAU = $true; RoleAssignments = @(New-TestRoleAssignment 'ControlPlane'); Owners = @((Get-TestObjectId 4), (Get-TestObjectId 999)) }
                New-TestObject 11 'group' (& $Tier 11 'ManagementPlane') @{ ObjectSubType = 'Security'; RoleAssignments = @(New-TestRoleAssignment 'ManagementPlane') }
                # The service principal of a Microsoft first-party application: neither unclassified nor outside the home tenant.
                New-TestObject 12 'serviceprincipal' (& $Tier 12 '') @{ ObjectSubType = 'Application'; OriginTenantId = 'f8cdef31-a31e-4b4a-93e4-5f571e91255a'; RoleAssignments = @(New-TestRoleAssignment 'ControlPlane') }
                # The service principal of a multi-tenant application of another organization.
                New-TestObject 13 'serviceprincipal' (& $Tier 13 'ControlPlane') @{ ObjectSubType = 'Application'; OriginTenantId = 'tenant-2'; RoleAssignments = @(New-TestRoleAssignment 'ControlPlane') }
                New-TestObject 4 'user' (& $Tier 4 'UserAccess') @{ OwnedObjects = @((Get-TestObjectId 3)); RestrictedManagementByRAG = $true }
                New-TestObject 5 'serviceprincipal' (& $Tier 5 'WorkloadPlane') @{ ObjectSubType = 'agentidentity'; IdentityParent = (Get-TestObjectId 600).ToUpper(); RoleAssignments = @(New-TestRoleAssignment 'ManagementPlane') }
                New-TestObject 6 'serviceprincipal' (& $Tier 6 'UserAccess') @{ ObjectSubType = 'agentidentityblueprint'; ObjectUserPrincipalName = (Get-TestObjectId 600) }
                # A guest: the export writes the home tenant into ObjectTenantId and flags the user with OutsideOfHomeTenant.
                New-TestObject 7 'user' (& $Tier 7 '') @{ ObjectSubType = 'Guest'; OutsideOfHomeTenant = $true; RoleAssignments = @(New-TestRoleAssignment 'UserAccess') }
                New-TestObject 8 'application' (& $Tier 8 'ControlPlane') @{ RoleAssignments = @(New-TestRoleAssignment 'WorkloadPlane') }
                New-TestObject 9 'user' (& $Tier 9 'ManagementPlane') @{ ObjectSubType = 'agentuser'; Sponsors = @((Get-TestObjectId 1)); AssociatedWorkAccount = @((Get-TestObjectId 77)); RoleAssignments = @(New-TestRoleAssignment 'ManagementPlane') }
                New-TestObject 10 'user' (& $Tier 10 'Unclassified') @{ RoleAssignments = @(New-TestRoleAssignment 'Unclassified') }
            )
        }

        function New-TestDataFile([string]$Root, [object[]]$Export) {
            New-Item -ItemType Directory -Path "$Root/PrivilegedEAM/EntraID", "$Root/App" -Force | Out-Null
            ConvertTo-Json -InputObject $Export -Depth 10 | Set-Content -LiteralPath "$Root/PrivilegedEAM/EntraID/EntraID.json"
            $Payload = New-EntraOpsPrivilegedAssetsData -RepoRoot $Root -ImportPath "$Root/PrivilegedEAM" -AppRoot "$Root/App" -OutFile "$Root/App/data/privileged-assets-data.js" -ResolveRelatedObjectIds $false -PassThru -InformationAction SilentlyContinue 6> $null
            [pscustomobject]@{ Payload = $Payload; DataFile = "$Root/App/data/privileged-assets-data.js" }
        }

        function ConvertTo-FindingMap($ByObject) {
            $Map = [ordered]@{}
            # The report sorts the findings of an object by rule; compare them as a set.
            foreach ($Key in @($ByObject.Keys | Sort-Object)) { $Map[$Key] = @($ByObject[$Key] | Sort-Object) -join ',' }
            $Map
        }
    }

    It 'embeds the findings of every rule in the report data' {
        $Data = New-TestDataFile -Root (Join-Path $TestDrive 'all') -Export (Get-TestExport)

        $Data.Payload.findings.rules.key | Should -Be @(Get-EntraOpsFindingRule -Area PrivilegedAssets).Key
        foreach ($Rule in $Data.Payload.findings.rules) {
            $Rule.status | Should -Be 'Failed' -Because "the fixture has a failing object for $($Rule.key)"
            $Rule.reportSeverity | Should -BeIn @('high', 'medium', 'low', 'info')
        }
        # In catalog order: by category, then by severity.
        $Data.Payload.findings.byObject[(Get-TestObjectId 2)] | Should -Be @('tierBreach', 'hybridPrivileged', 'restrictedManagementGap', 'pawMissing', 'workAccountMissing')
        $Data.Payload.findings.byObject[(Get-TestObjectId 5)] | Should -Be @('parentLowerTier', 'sponsorMissing')
        $Data.Payload.findings.byObject.Contains((Get-TestObjectId 8)) | Should -BeFalse
        # "Conflict" is protected by the role-assignable group; the owner outside the export is Tier 2.
        $Data.Payload.findings.byObject[(Get-TestObjectId 3)] | Should -Be @('ownerLowerTier')
        # A group with Management Plane access without restricted management is reported by EO.4004 (Privileged EAM), not by restrictedManagementGap.
        $Data.Payload.findings.byObject.Contains((Get-TestObjectId 11)) | Should -BeFalse
        $Data.Payload.findings.byObject[(Get-TestObjectId 7)] | Should -Be @('unclassified', 'foreign')
        $Data.Payload.findings.byObject.Contains((Get-TestObjectId 12)) | Should -BeFalse
        $Data.Payload.findings.byObject[(Get-TestObjectId 13)] | Should -Be @('foreign')
    }

    It 'matches the What-if rules of the report' -Skip:$script:NodeMissing {
        $Data = New-TestDataFile -Root (Join-Path $TestDrive 'parity') -Export (Get-TestExport)

        $ReportFindings = node $script:Harness $Data.DataFile | ConvertFrom-Json -AsHashtable
        $LASTEXITCODE | Should -Be 0
        ConvertTo-Json (ConvertTo-FindingMap $ReportFindings) | Should -BeExactly (ConvertTo-Json (ConvertTo-FindingMap $Data.Payload.findings.byObject))
    }

    It 'counts the evaluated objects of each rule like PowerShell (applies)' -Skip:$script:NodeMissing {
        $Root = Join-Path $TestDrive 'applies'
        $Data = New-TestDataFile -Root $Root -Export (Get-TestExport)
        $Counts = node $script:Harness $Data.DataFile --applies | ConvertFrom-Json -AsHashtable
        $LASTEXITCODE | Should -Be 0
        $Results = @(Invoke-EntraOpsFindingEvaluation -Area PrivilegedAssets -ImportPath "$Root/PrivilegedEAM" -WarningAction SilentlyContinue)
        foreach ($Result in $Results) { $Counts[$Result.Key] | Should -Be $Result.EvaluatedCount -Because $Result.Key }
    }

    It 'counts only directory roles that lower administrators cannot manage as restricted management (EO.4005)' {
        # Exports of EntraOps before 1.2.0 set RestrictedManagementByAadRole for every directory role: the Entra ID roles of the
        # object decide. Helpdesk Administrators can reset Directory Readers holders; an eligible role scoped to an
        # administrative unit protects its holder.
        $Role = {
            param([string]$Name, [string]$Id, [string]$Scope = '/', [string]$Pim = 'Permanent')
            [ordered]@{ RoleDefinitionName = $Name; RoleDefinitionId = $Id; RoleAssignmentInstanceId = "i-$Name-$Scope"; RoleType = 'BuiltInRole'; PIMAssignmentType = $Pim; RoleAssignmentScopeId = $Scope; Classification = @(@{ AdminTierLevelName = 'UserAccess'; Service = 'Directory' }) }
        }
        $Export = @(
            New-TestObject 1 'user' 'ManagementPlane' @{ RestrictedManagementByAadRole = $true; RoleAssignments = @(& $Role 'Directory Readers' '88d8e3e3-8f55-4a1e-953a-9b9898b8876b') }
            New-TestObject 2 'user' 'ManagementPlane' @{ RestrictedManagementByAadRole = $true; RoleAssignments = @((& $Role 'Directory Readers' '88d8e3e3-8f55-4a1e-953a-9b9898b8876b'), (& $Role 'Global Reader' 'f2ef992c-3afb-46b9-b7cf-a126ee74c451' '/administrativeUnits/00000000-0000-0000-0000-000000000001' 'Eligible')) }
            New-TestObject 3 'user' 'ManagementPlane' @{ RestrictedManagementByAadRole = $true; RoleAssignments = @(& $Role 'User Administrator' 'FE930BE7-5E62-47DB-91AF-98C3A49A38B1') }
            # A custom role (an ID outside the list) protects its holder.
            New-TestObject 4 'user' 'ManagementPlane' @{ RestrictedManagementByAadRole = $true; RoleAssignments = @(& $Role 'Custom Role' '11111111-2222-3333-4444-555555555555') }
        )
        $Root = Join-Path $TestDrive 'restricted-role'
        $Data = New-TestDataFile -Root $Root -Export $Export

        (@($Data.Payload.objects | Where-Object objectId -eq (Get-TestObjectId 1)))[0].restrictedManagement | Should -Be 'Not applied'
        (@($Data.Payload.objects | Where-Object objectId -eq (Get-TestObjectId 2)))[0].restrictedManagement | Should -Be 'Applied'
        $Data.Payload.findings.byObject[(Get-TestObjectId 1)] | Should -Contain 'restrictedManagementGap'
        $Data.Payload.findings.byObject[(Get-TestObjectId 2)] | Should -Not -Contain 'restrictedManagementGap'
        $Data.Payload.findings.byObject[(Get-TestObjectId 3)] | Should -Contain 'restrictedManagementGap'
        $Data.Payload.findings.byObject[(Get-TestObjectId 4)] | Should -Not -Contain 'restrictedManagementGap'

        $Rule = @(Invoke-EntraOpsFindingEvaluation -Area PrivilegedAssets -ImportPath "$Root/PrivilegedEAM" -WarningAction SilentlyContinue) | Where-Object Key -eq 'restrictedManagementGap'
        $Result = @($Rule.Results | Where-Object { $_.Instance.ObjectId -eq (Get-TestObjectId 1) })[0]
        $Result.Message | Should -BeLike "*reset the password of holders of its directory role(s) 'Directory Readers'*"
        $Result.Evidence.DirectoryRoles | Should -Be @('Directory Readers')
        if (-not $script:NodeMissing) {
            $ReportFindings = node $script:Harness $Data.DataFile | ConvertFrom-Json -AsHashtable
            ConvertTo-Json (ConvertTo-FindingMap $ReportFindings) | Should -BeExactly (ConvertTo-Json (ConvertTo-FindingMap $Data.Payload.findings.byObject))
        }
    }

    It 'leaves out delegated permissions from the access of the object, in PowerShell and the What-if rules' {
        # Only a delegated Management Plane permission: the object tier (User Access) is no tier breach, and the
        # owner of a lower tier is compared with User Access. The assignment tiers still show the delegated permission.
        $Delegated = [ordered]@{ RoleDefinitionName = 'Mail.Read'; RoleAssignmentInstanceId = 'i-mail'; RoleType = 'Delegated'; PIMAssignmentType = 'Permanent'; RoleAssignmentScopeId = '/'; Classification = @(@{ AdminTierLevelName = 'ManagementPlane'; Service = 'Mail' }) }
        $Export = @(
            New-TestObject 1 'serviceprincipal' 'UserAccess' @{ ObjectSubType = 'agentidentity'; Sponsors = @((Get-TestObjectId 2)); RoleAssignments = @($Delegated); Owners = @((Get-TestObjectId 2)) }
            New-TestObject 2 'user' 'UserAccess' @{ RoleAssignments = @(New-TestRoleAssignment 'UserAccess') }
        )
        $Data = New-TestDataFile -Root (Join-Path $TestDrive 'delegated') -Export $Export
        $Object = $Data.Payload.objects | Where-Object objectId -eq (Get-TestObjectId 1)
        $Object.assignmentSummary.highestTierName | Should -Be 'ManagementPlane'
        $Object.assignmentSummary.highestAccessTierName | Should -Be 'Unclassified'
        $Object.assignments[0].roleType | Should -Be 'Delegated'
        $Data.Payload.findings.byObject.Contains((Get-TestObjectId 1)) | Should -BeFalse
        if (-not $script:NodeMissing) {
            $ReportFindings = node $script:Harness $Data.DataFile | ConvertFrom-Json -AsHashtable
            ConvertTo-Json (ConvertTo-FindingMap $ReportFindings) | Should -BeExactly (ConvertTo-Json (ConvertTo-FindingMap $Data.Payload.findings.byObject))
        }
    }

    It 'evaluates What-if tiers like a reclassified export' -Skip:$script:NodeMissing {
        # The What-if view applies the worklist tiers on top of the data; PowerShell sees them in the export.
        $Changes = @{ 1 = 'UserAccess'; 3 = 'ManagementPlane'; 4 = 'ControlPlane'; 7 = 'ControlPlane'; 10 = 'ManagementPlane' }
        $Baseline = New-TestDataFile -Root (Join-Path $TestDrive 'baseline') -Export (Get-TestExport)
        $Reclassified = New-TestDataFile -Root (Join-Path $TestDrive 'reclassified') -Export (Get-TestExport -TierByNumber $Changes)
        $Overrides = [ordered]@{}
        foreach ($Number in $Changes.Keys) { $Overrides[(Get-TestObjectId $Number)] = $Changes[$Number] }
        $OverrideFile = Join-Path $TestDrive 'overrides.json'
        $Overrides | ConvertTo-Json | Set-Content -LiteralPath $OverrideFile

        $WhatIfFindings = node $script:Harness $Baseline.DataFile $OverrideFile | ConvertFrom-Json -AsHashtable
        $LASTEXITCODE | Should -Be 0
        ConvertTo-Json (ConvertTo-FindingMap $WhatIfFindings) | Should -BeExactly (ConvertTo-Json (ConvertTo-FindingMap $Reclassified.Payload.findings.byObject))
        ConvertTo-Json (ConvertTo-FindingMap $WhatIfFindings) | Should -Not -BeExactly (ConvertTo-Json (ConvertTo-FindingMap $Baseline.Payload.findings.byObject))
    }

    It 'reports unclassified objects as unclassified only, not as a tier breach' {
        $Export = @(
            New-TestObject 1 'serviceprincipal' 'Unclassified' @{ ObjectSubType = 'Application'; RoleAssignments = @(New-TestRoleAssignment 'ControlPlane') }
            New-TestObject 2 'serviceprincipal' 'ManagementPlane' @{ ObjectSubType = 'Application'; RoleAssignments = @(New-TestRoleAssignment 'ControlPlane') }
        )
        $Data = New-TestDataFile -Root (Join-Path $TestDrive 'unclassified') -Export $Export

        $Data.Payload.findings.byObject[(Get-TestObjectId 1)] | Should -Be @('unclassified')
        $Data.Payload.findings.byObject[(Get-TestObjectId 2)] | Should -Be @('tierBreach')
        if (-not $script:NodeMissing) {
            $ReportFindings = node $script:Harness $Data.DataFile | ConvertFrom-Json -AsHashtable
            ConvertTo-Json (ConvertTo-FindingMap $ReportFindings) | Should -BeExactly (ConvertTo-Json (ConvertTo-FindingMap $Data.Payload.findings.byObject))
        }
    }

    It 'returns the Privileged Assets rules from Invoke-EntraOpsFindingEvaluation' {
        $Root = Join-Path $TestDrive 'evaluation'
        $Data = New-TestDataFile -Root $Root -Export (Get-TestExport)
        $Results = @(Invoke-EntraOpsFindingEvaluation -Area PrivilegedAssets -ImportPath "$Root/PrivilegedEAM" -WarningAction SilentlyContinue)

        $Results.Count | Should -Be 12
        $PawMissing = $Results | Where-Object Key -eq 'pawMissing'
        $PawMissing.MaesterTestId | Should -Be 'MP.EOPS.4008'
        $PawMissing.EvaluatedCount | Should -Be 2
        $PawMissing.Results.Instance.ObjectId | Should -Be (Get-TestObjectId 2)
        ($Results | Where-Object Key -eq 'ownerLowerTier').Results[0].Evidence.RelatedObjectIds | Should -Be @((Get-TestObjectId 4), (Get-TestObjectId 999))
        foreach ($Result in $Results) {
            $Result.FailedCount | Should -Be @($Data.Payload.findings.byObject.Values | Where-Object { $_ -contains $Result.Key }).Count -Because $Result.Key
        }
    }
}
