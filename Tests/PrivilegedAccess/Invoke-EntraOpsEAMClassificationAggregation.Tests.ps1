#Requires -Modules Pester

BeforeDiscovery {
    $script:TestRepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
}

BeforeAll {
    $script:TestRepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
    . "$script:TestRepositoryRoot/EntraOps/Private/Get-EntraOpsRoleAssignmentInstanceId.ps1"
    . "$script:TestRepositoryRoot/EntraOps/Private/New-EntraOpsEAMOutputObject.ps1"
    . "$script:TestRepositoryRoot/EntraOps/Private/Invoke-EntraOpsEAMClassificationAggregation.ps1"
    . "$script:TestRepositoryRoot/EntraOps/Private/Test-EntraOpsPathWithinRoot.ps1"
    . "$script:TestRepositoryRoot/EntraOps/Private/Save-EntraOpsEAMRbacSystemJson.ps1"

    function New-TestObjectDetails {
        param ([string]$ObjectId, [string]$DisplayName)
        [pscustomobject]@{
            'ObjectTenantId'                = "11111111-1111-1111-1111-111111111111"
            'ObjectType'                    = "user"
            'ObjectSubType'                 = "Member"
            'ObjectDisplayName'             = $DisplayName
            'ObjectSignInName'              = "$DisplayName@contoso.com"
            'AdminTierLevel'                = "1"
            'AdminTierLevelName'            = "ManagementPlane"
            'OnPremSynchronized'            = $false
            'AssignedAdministrativeUnits'   = $null
            'RestrictedManagementByRAG'     = $false
            'RestrictedManagementByAadRole' = $false
            'RestrictedManagementByRMAU'    = $false
            'Sponsors'                      = $null
            'Owners'                        = $null
            'OwnedObjects'                  = $null
            'OwnedDevices'                  = $null
            'IdentityParent'                = $null
            'AssociatedWorkAccount'         = $null
            'AssociatedPawDevice'           = $null
        }
    }

    function New-TestAssignment {
        param ([string]$RoleName = "Test Role", [string]$TierLevel = "1", [string]$TierLevelName = "ManagementPlane")
        [pscustomobject]@{
            'RoleDefinitionName'    = $RoleName
            'RoleAssignmentScopeId' = "/"
            'Classification'        = @([pscustomobject]@{
                    'AdminTierLevel'     = $TierLevel
                    'AdminTierLevelName' = $TierLevelName
                    'Service'            = "Test Service"
                    'TaggedBy'           = "JSONwithAction"
                })
        }
    }

    function Get-TestClassificationActionSets {
        param ([object[]]$Classification)
        $Sets = @{}
        foreach ($Entry in $Classification) {
            if ($null -eq $Entry) { continue }
            $Key = "$($Entry.AdminTierLevel)|$($Entry.AdminTierLevelName)|$($Entry.Service)"
            if (-not $Sets.ContainsKey($Key)) {
                $Sets[$Key] = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
            }
            foreach ($Action in @($Entry.MatchedActions)) {
                if (-not [string]::IsNullOrWhiteSpace($Action)) {
                    $null = $Sets[$Key].Add($Action.ToLowerInvariant())
                }
            }
        }
        return $Sets
    }

    function Assert-TestClassificationEvidence {
        param ($Object)
        $Expected = Get-TestClassificationActionSets -Classification @(
            $Object.RoleAssignments | ForEach-Object { $_.Classification }
        )
        $Actual = Get-TestClassificationActionSets -Classification @($Object.Classification)
        foreach ($Key in @(@($Expected.Keys) + @($Actual.Keys) | Sort-Object -Unique)) {
            $ExpectedActions = @($Expected[$Key] | Sort-Object) -join "`n"
            $ActualActions = @($Actual[$Key] | Sort-Object) -join "`n"
            $ActualActions | Should -BeExactly $ExpectedActions -Because "object $($Object.ObjectId) must preserve exactly the assignment actions for $Key"
        }
    }
}

Describe "New-EntraOpsEAMOutputObject tier-pair validation" {
    It "warns when a numeric tier is paired with an Unclassified name" {
        $ObjectDetails = New-TestObjectDetails -ObjectId "aaaaaaaa-0000-0000-0000-000000000001" -DisplayName "Mismatched User"
        $ObjectDetails.AdminTierLevel = "0"
        $ObjectDetails.AdminTierLevelName = "Unclassified"
        $Assignment = New-TestAssignment

        $null = New-EntraOpsEAMOutputObject `
            -ObjectId "aaaaaaaa-0000-0000-0000-000000000001" `
            -ObjectDetails $ObjectDetails `
            -Classification @($Assignment.Classification) `
            -RoleAssignments @($Assignment) `
            -RoleSystem "EntraID" `
            -WarningVariable WarningMessage

        $WarningMessage | Should -Match "Contradictory admin tier pair"
        $WarningMessage | Should -Match "canonical value: Unclassified"
    }
}

Describe "Save-EntraOpsEAMRbacSystemJson assignment deduplication" {
    It "removes exact duplicate rows but preserves a distinct nesting path" {
        $script:EntraOpsBaseFolder = $TestDrive
        $ExportFolder = Join-Path $TestDrive "EntraID"
        $Classification = @([pscustomobject]@{
                AdminTierLevel     = "0"
                AdminTierLevelName = "ControlPlane"
            })
        $Assignments = @(
            [pscustomobject]@{
                RoleAssignmentId                      = "assignment-1"
                RoleDefinitionId                      = "role-1"
                RoleDefinitionName                    = "Global Administrator"
                RoleAssignmentScopeId                 = "/"
                RoleAssignmentSubType                 = "Permanent"
                Classification                        = $Classification
                TransitiveByNestingObjectIds          = @("group-a", "group-b")
                TransitiveByNestingObjectDisplayNames = @("Group A", "Group B")
            }
            [pscustomobject]@{
                RoleAssignmentId                      = "assignment-1"
                RoleDefinitionId                      = "role-1"
                RoleDefinitionName                    = "Global Administrator"
                RoleAssignmentScopeId                 = "/"
                RoleAssignmentSubType                 = "Permanent"
                Classification                        = $Classification
                TransitiveByNestingObjectIds          = @("group-a", "group-b")
                TransitiveByNestingObjectDisplayNames = @("Group A", "Group B")
            }
            [pscustomobject]@{
                RoleAssignmentId                      = "assignment-1"
                RoleDefinitionId                      = "role-1"
                RoleDefinitionName                    = "Global Administrator"
                RoleAssignmentScopeId                 = "/"
                RoleAssignmentSubType                 = "Permanent"
                Classification                        = $Classification
                TransitiveByNestingObjectIds          = @("group-b")
                TransitiveByNestingObjectDisplayNames = @("Group B")
            }
        )
        $EamData = [pscustomobject]@{
            ObjectId          = "aaaaaaaa-0000-0000-0000-000000000001"
            ObjectType        = "user"
            ObjectDisplayName = "Guest Admin"
            RoleAssignments   = $Assignments
        }

        Save-EntraOpsEAMRbacSystemJson `
            -ExportFolder $ExportFolder `
            -RbacSystemName "EntraID" `
            -EamData $EamData `
            -AggregateFileName "EntraID.json"

        $Saved = Get-Content -LiteralPath (Join-Path $ExportFolder "EntraID.json") -Raw | ConvertFrom-Json
        @($Saved.RoleAssignments).Count | Should -Be 2
        @($Saved.RoleAssignments.RoleAssignmentInstanceId | Select-Object -Unique).Count | Should -Be 1
        @($Saved.RoleAssignments | ForEach-Object { @($_.TransitiveByNestingObjectIds).Count } | Sort-Object) | Should -Be @(1, 2)
    }

    It "writes single-entry classification collections as arrays" {
        . "$script:TestRepositoryRoot/EntraOps/Public/Validation/Test-EntraOpsGeneratedArtifacts.ps1"
        $ShapeRoot = Join-Path $TestDrive "shape"
        New-Item -ItemType Directory -Path $ShapeRoot -Force | Out-Null
        $script:EntraOpsBaseFolder = $ShapeRoot
        $ExportFolder = Join-Path $ShapeRoot "DeviceManagement"
        $SingleClassification = [pscustomobject]@{
            AdminTierLevel     = "1"
            AdminTierLevelName = "ManagementPlane"
            Service            = "Device Management"
            MatchedActions     = "Microsoft.Intune_Organization_Read"
            ScopedObjects      = [pscustomobject]@{ id = "device-1" }
        }
        $EamData = [pscustomobject]@{
            ObjectId          = "aaaaaaaa-0000-0000-0000-000000000002"
            ObjectType        = "user"
            ObjectDisplayName = "Intune Admin"
            Classification    = $SingleClassification
            RoleAssignments   = @([pscustomobject]@{
                    RoleAssignmentId      = "assignment-2"
                    RoleDefinitionId      = "role-2"
                    RoleDefinitionName    = "Intune Role"
                    RoleAssignmentScopeId = "/"
                    RoleAssignmentSubType = "Permanent"
                    Classification        = $SingleClassification
                })
        }

        Save-EntraOpsEAMRbacSystemJson -ExportFolder $ExportFolder -RbacSystemName "DeviceManagement" -EamData $EamData -AggregateFileName "DeviceManagement.json"

        $Json = Get-Content -LiteralPath (Join-Path $ExportFolder "DeviceManagement.json") -Raw
        $Saved = $Json | ConvertFrom-Json -Depth 20
        $Saved.Classification -is [array] | Should -BeTrue
        $Saved.Classification[0].MatchedActions -is [array] | Should -BeTrue
        $Saved.Classification[0].ScopedObjects -is [array] | Should -BeTrue
        $Saved.RoleAssignments[0].Classification -is [array] | Should -BeTrue
        { Test-EntraOpsGeneratedArtifacts -PrivilegedEamPath $ShapeRoot -WarningAction SilentlyContinue } | Should -Not -Throw
    }
}

Describe "Invoke-EntraOpsEAMClassificationAggregation" {
    Context "Sequential processing" {
        BeforeAll {
            $script:TestRepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
            $ResolvedId = "aaaaaaaa-0000-0000-0000-000000000001"
            $UnresolvedId = "bbbbbbbb-0000-0000-0000-000000000002"
            $UniqueObjects = @(
                [pscustomobject]@{ ObjectId = $ResolvedId; ObjectType = "user" }
                [pscustomobject]@{ ObjectId = $UnresolvedId; ObjectType = "group" }
            )
            $ObjectDetailsCache = @{
                $ResolvedId   = New-TestObjectDetails -ObjectId $ResolvedId -DisplayName "Resolved User"
                $UnresolvedId = $null
            }
            $RbacClassificationsByObject = @{
                $ResolvedId   = @(New-TestAssignment)
                $UnresolvedId = @(New-TestAssignment -RoleName "Unresolved Role")
            }
            $WarningMessages = [System.Collections.Generic.List[psobject]]::new()

            $Result = Invoke-EntraOpsEAMClassificationAggregation `
                -UniqueObjects $UniqueObjects `
                -ObjectDetailsCache $ObjectDetailsCache `
                -RbacClassificationsByObject $RbacClassificationsByObject `
                -RoleSystem "EntraID" `
                -EnableParallelProcessing $false `
                -WarningMessages $WarningMessages `
                -WarningAction SilentlyContinue
            $Result = @($Result)
        }

        It "emits one output object per unique principal (unresolved not dropped)" {
            $Result.Count | Should -Be 2
        }

        It "passes a resolved object through unchanged" {
            $Resolved = $Result | Where-Object { $_.ObjectId -eq $ResolvedId }
            $Resolved.ObjectDisplayName | Should -Be "Resolved User"
            $Resolved.ObjectType | Should -Be "user"
            $Resolved.ObjectAdminTierLevel | Should -Be "1"
            $Resolved.ObjectAdminTierLevelName | Should -Be "ManagementPlane"
            $Resolved.RoleSystem | Should -Be "EntraID"
            @($Resolved.Classification).AdminTierLevelName | Should -Be @("ManagementPlane")
            @($Resolved.Classification).TaggedBy | Should -Not -Contain "UnresolvedObject"
        }

        It "emits an unresolved object as fail-closed ControlPlane placeholder with the canonical pair" {
            $Unresolved = $Result | Where-Object { $_.ObjectId -eq $UnresolvedId }
            $Unresolved | Should -Not -BeNullOrEmpty
            $Unresolved.ObjectAdminTierLevel | Should -Be "0"
            $Unresolved.ObjectAdminTierLevelName | Should -Be "ControlPlane"
        }

        It "marks the placeholder classification with TaggedBy = UnresolvedObject" {
            $Unresolved = $Result | Where-Object { $_.ObjectId -eq $UnresolvedId }
            $Marker = @($Unresolved.Classification) | Where-Object { $_.TaggedBy -eq "UnresolvedObject" }
            $Marker | Should -Not -BeNullOrEmpty
            $Marker.AdminTierLevel | Should -Be "0"
            $Marker.AdminTierLevelName | Should -Be "ControlPlane"
        }

        It "keeps classifications derived from the assignments alongside the marker" {
            $Unresolved = $Result | Where-Object { $_.ObjectId -eq $UnresolvedId }
            @($Unresolved.Classification).AdminTierLevelName | Should -Contain "ManagementPlane"
        }

        It "fills identity fields defensively from the assignment data" {
            $Unresolved = $Result | Where-Object { $_.ObjectId -eq $UnresolvedId }
            $Unresolved.ObjectDisplayName | Should -Be $UnresolvedId
            $Unresolved.ObjectType | Should -Be "group"
            $Unresolved.ObjectSubType | Should -Be "Unresolved"
        }

        It "keeps the role assignments on the placeholder" {
            $Unresolved = $Result | Where-Object { $_.ObjectId -eq $UnresolvedId }
            @($Unresolved.RoleAssignments).RoleDefinitionName | Should -Contain "Unresolved Role"
        }

        It "adds a structured UnresolvedObject warning for the placeholder" {
            $Warning = @($WarningMessages | Where-Object { $_.Type -eq "UnresolvedObject" })
            $Warning.Count | Should -Be 1
            $Warning.Target | Should -Be $UnresolvedId
        }

        It "falls back to ObjectType 'unresolved' when the assignment carries no object type" {
            $NoTypeId = "cccccccc-0000-0000-0000-000000000003"
            $NoTypeResult = Invoke-EntraOpsEAMClassificationAggregation `
                -UniqueObjects @([pscustomobject]@{ ObjectId = $NoTypeId; ObjectType = $null }) `
                -ObjectDetailsCache @{ $NoTypeId = $null } `
                -RbacClassificationsByObject @{ $NoTypeId = @(New-TestAssignment) } `
                -RoleSystem "EntraID" `
                -EnableParallelProcessing $false `
                -WarningAction SilentlyContinue
            $NoTypeResult.ObjectType | Should -Be "unresolved"
        }
    }

    Context "Parallel processing" {
        BeforeAll {
            $script:TestRepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
            # 50+ objects trigger the parallel branch (inline output build, no module functions)
            $UnresolvedId = "bbbbbbbb-0000-0000-0000-000000000002"
            $UniqueObjects = [System.Collections.Generic.List[psobject]]::new()
            $ObjectDetailsCache = @{}
            $RbacClassificationsByObject = @{}
            for ($i = 1; $i -le 49; $i++) {
                $Id = "aaaaaaaa-0000-0000-0000-{0:d12}" -f $i
                $UniqueObjects.Add([pscustomobject]@{ ObjectId = $Id; ObjectType = "user" })
                $ObjectDetailsCache[$Id] = New-TestObjectDetails -ObjectId $Id -DisplayName "User $i"
                $RbacClassificationsByObject[$Id] = @(New-TestAssignment)
            }
            $UniqueObjects.Add([pscustomobject]@{ ObjectId = $UnresolvedId; ObjectType = "group" })
            $ObjectDetailsCache[$UnresolvedId] = $null
            $RbacClassificationsByObject[$UnresolvedId] = @(New-TestAssignment -RoleName "Unresolved Role")
            $WarningMessages = [System.Collections.Generic.List[psobject]]::new()

            $Result = Invoke-EntraOpsEAMClassificationAggregation `
                -UniqueObjects $UniqueObjects.ToArray() `
                -ObjectDetailsCache $ObjectDetailsCache `
                -RbacClassificationsByObject $RbacClassificationsByObject `
                -RoleSystem "EntraID" `
                -EnableParallelProcessing $true `
                -ParallelThrottleLimit 5 `
                -WarningMessages $WarningMessages `
                -WarningAction SilentlyContinue
            $Result = @($Result)
        }

        It "emits one output object per unique principal (unresolved not dropped)" {
            $Result.Count | Should -Be 50
        }

        It "emits the unresolved object as fail-closed ControlPlane placeholder with marker" {
            $Unresolved = $Result | Where-Object { $_.ObjectId -eq $UnresolvedId }
            $Unresolved | Should -Not -BeNullOrEmpty
            $Unresolved.ObjectAdminTierLevel | Should -Be "0"
            $Unresolved.ObjectAdminTierLevelName | Should -Be "ControlPlane"
            $Unresolved.ObjectDisplayName | Should -Be $UnresolvedId
            @($Unresolved.Classification).TaggedBy | Should -Contain "UnresolvedObject"
        }

        It "folds the parallel unresolved marker into the warning collection after the parallel block" {
            $Warning = @($WarningMessages | Where-Object { $_.Type -eq "UnresolvedObject" })
            $Warning.Count | Should -Be 1
            $Warning.Target | Should -Be $UnresolvedId
        }

        It "does not mark resolved objects" {
            $Marked = @($Result | Where-Object { @($_.Classification).TaggedBy -contains "UnresolvedObject" })
            $Marked.Count | Should -Be 1
        }
    }
}


Describe "Merge-EntraOpsEAMClassification" {
    BeforeAll {
        function New-TestClassItem {
            param ([string]$Service = "Default member", [object]$MatchedActions, [object]$ScopedObjects, [string]$TierLevel = "1", [string]$TierLevelName = "ManagementPlane")
            [pscustomobject]@{
                'AdminTierLevel'             = $TierLevel
                'AdminTierLevelName'         = $TierLevelName
                'Service'                    = $Service
                'MatchedActions'             = $MatchedActions
                'ScopedObjects'              = $ScopedObjects
                'TaggedBy'                   = "JSONwithAction"
                'TaggedByObjectIds'          = $null
                'TaggedByObjectDisplayNames' = $null
                'TaggedByRoleSystem'         = "EntraID"
            }
        }
        function New-TestAssignmentWithClass {
            param ([string]$RoleName, [object[]]$Classification)
            [pscustomobject]@{
                'RoleDefinitionName'    = $RoleName
                'RoleAssignmentScopeId' = "/"
                'Classification'        = $Classification
            }
        }
    }

    It "unions MatchedActions across assignments with the same tier/service (sorted, de-duplicated)" {
        $Assignments = @(
            New-TestAssignmentWithClass -RoleName "Role A" -Classification @(New-TestClassItem -MatchedActions @("microsoft.directory/users/password/update", "microsoft.directory/users/basic/update"))
            New-TestAssignmentWithClass -RoleName "Role B" -Classification @(New-TestClassItem -MatchedActions @("microsoft.directory/groups/members/update", "Microsoft.Directory/Users/Basic/Update"))
        )
        $Result = @(Merge-EntraOpsEAMClassification -RoleAssignments $Assignments)

        $Result.Count | Should -Be 1
        $Result[0].MatchedActions | Should -Be @(
            "microsoft.directory/groups/members/update"
            "Microsoft.Directory/Users/Basic/Update"
            "microsoft.directory/users/password/update"
        )
        $Result[0].PSObject.Properties.Name | Should -Not -Contain "TaggedBy"
    }

    It "produces the same result regardless of assignment order" {
        $A = New-TestAssignmentWithClass -RoleName "Role A" -Classification @(New-TestClassItem -Service "Default member" -MatchedActions @("b/action", "A/Action"))
        $B = New-TestAssignmentWithClass -RoleName "Role B" -Classification @(New-TestClassItem -Service "Default Member" -MatchedActions @("a/action", "c/action"))
        $Forward = Merge-EntraOpsEAMClassification -RoleAssignments @($A, $B) | ConvertTo-Json -Depth 5
        $Reverse = Merge-EntraOpsEAMClassification -RoleAssignments @($B, $A) | ConvertTo-Json -Depth 5
        $Forward | Should -BeExactly $Reverse
    }

    It "picks a deterministic service label for casing variants" {
        $A = New-TestAssignmentWithClass -RoleName "Role A" -Classification @(New-TestClassItem -Service "Default member" -MatchedActions @("x/read"))
        $B = New-TestAssignmentWithClass -RoleName "Role B" -Classification @(New-TestClassItem -Service "Default Member" -MatchedActions @("y/read"))
        foreach ($Order in @(@($A, $B), @($B, $A))) {
            $Result = @(Merge-EntraOpsEAMClassification -RoleAssignments $Order)
            $Result.Count | Should -Be 1
            $Result[0].Service | Should -BeExactly "Default Member"
            $Result[0].MatchedActions | Should -Be @("x/read", "y/read")
        }
    }

    It "keeps a single matched action as an array (also after JSON serialization)" {
        $Assignments = @(
            New-TestAssignmentWithClass -RoleName "Role A" -Classification @(New-TestClassItem -MatchedActions @("microsoft.directory/users/password/update"))
            New-TestAssignmentWithClass -RoleName "Role B" -Classification @(New-TestClassItem -MatchedActions @("microsoft.directory/users/password/update"))
        )
        $Result = @(Merge-EntraOpsEAMClassification -RoleAssignments $Assignments)

        ($Result[0].MatchedActions -is [object[]]) | Should -BeTrue
        @($Result[0].MatchedActions).Count | Should -Be 1
        ([pscustomobject]@{ Classification = $Result } | ConvertTo-Json -Depth 5 -Compress) | Should -Match '"MatchedActions":\["microsoft\.directory/users/password/update"\]'
    }

    It "keeps MatchedActions and ScopedObjects null when no assignment carries data" {
        $Assignments = @(
            New-TestAssignmentWithClass -RoleName "Role A" -Classification @(New-TestClassItem -MatchedActions $null)
            New-TestAssignmentWithClass -RoleName "Role B" -Classification @(New-TestClassItem -MatchedActions $null)
        )
        $Result = @(Merge-EntraOpsEAMClassification -RoleAssignments $Assignments)
        $Result.Count | Should -Be 1
        $Result[0].PSObject.Properties.Name | Should -Contain "MatchedActions"
        $Result[0].MatchedActions | Should -BeNullOrEmpty
        $Result[0].ScopedObjects | Should -BeNullOrEmpty
    }

    It "unions ScopedObjects by identity in a stable order" {
        $Dev1 = [pscustomobject]@{ id = "dev-2"; displayName = "Device 2" }
        $Dev2 = [pscustomobject]@{ id = "dev-1"; displayName = "Device 1" }
        $Dev2Dup = [pscustomobject]@{ id = "dev-1"; displayName = "Device 1" }
        $A = New-TestAssignmentWithClass -RoleName "Role A" -Classification @(New-TestClassItem -MatchedActions @("x/read") -ScopedObjects @($Dev1))
        $B = New-TestAssignmentWithClass -RoleName "Role B" -Classification @(New-TestClassItem -MatchedActions @("x/read") -ScopedObjects @($Dev2, $Dev2Dup))
        $Result = @(Merge-EntraOpsEAMClassification -RoleAssignments @($A, $B))
        @($Result[0].ScopedObjects).id | Should -Be @("dev-1", "dev-2")

        $Single = @(Merge-EntraOpsEAMClassification -RoleAssignments @($A))
        ($Single[0].ScopedObjects -is [object[]]) | Should -BeTrue
    }

    It "keeps distinct tier/service entries separate and sorted" {
        $Assignment = New-TestAssignmentWithClass -RoleName "Role A" -Classification @(
            New-TestClassItem -Service "Zeta" -MatchedActions @("z/read")
            New-TestClassItem -Service "Alpha" -MatchedActions @("a/read") -TierLevel "0" -TierLevelName "ControlPlane"
            New-TestClassItem -Service "Beta" -MatchedActions @("b/read")
        )
        $Result = @(Merge-EntraOpsEAMClassification -RoleAssignments @($Assignment))
        $Result.Service | Should -Be @("Alpha", "Beta", "Zeta")
    }

    It "returns an empty array when there is no classification" {
        $Result = @(Merge-EntraOpsEAMClassification -RoleAssignments @([pscustomobject]@{ RoleDefinitionName = "x"; Classification = $null }))
        $Result.Count | Should -Be 0
    }

    Context "Invoke-EntraOpsEAMClassificationAggregation uses the merged classification" {
        BeforeAll {
            $script:MergeTestAssignments = @(
                New-TestAssignmentWithClass -RoleName "Role A" -Classification @(New-TestClassItem -MatchedActions @("a/read"))
                New-TestAssignmentWithClass -RoleName "Role B" -Classification @(New-TestClassItem -Service "Default Member" -MatchedActions @("b/read", "a/read"))
            )
        }

        It "merges actions in the sequential path" {
            $Id = "dddddddd-0000-0000-0000-000000000001"
            $Result = @(Invoke-EntraOpsEAMClassificationAggregation `
                    -UniqueObjects @([pscustomobject]@{ ObjectId = $Id; ObjectType = "user" }) `
                    -ObjectDetailsCache @{ $Id = New-TestObjectDetails -ObjectId $Id -DisplayName "Merge User" } `
                    -RbacClassificationsByObject @{ $Id = $script:MergeTestAssignments } `
                    -RoleSystem "EntraID" `
                    -EnableParallelProcessing $false 6>$null)
            @($Result[0].Classification).Count | Should -Be 1
            $Result[0].Classification[0].Service | Should -BeExactly "Default Member"
            $Result[0].Classification[0].MatchedActions | Should -Be @("a/read", "b/read")
            @($Result[0].RoleAssignments).Count | Should -Be 2
        }

        It "merges actions in the parallel path" {
            $UniqueObjects = [System.Collections.Generic.List[psobject]]::new()
            $ObjectDetailsCache = @{}
            $RbacByObject = @{}
            for ($i = 1; $i -le 50; $i++) {
                $Id = "eeeeeeee-0000-0000-0000-{0:d12}" -f $i
                $UniqueObjects.Add([pscustomobject]@{ ObjectId = $Id; ObjectType = "user" })
                $ObjectDetailsCache[$Id] = New-TestObjectDetails -ObjectId $Id -DisplayName "User $i"
                $RbacByObject[$Id] = $script:MergeTestAssignments
            }
            $Result = @(Invoke-EntraOpsEAMClassificationAggregation `
                    -UniqueObjects $UniqueObjects.ToArray() `
                    -ObjectDetailsCache $ObjectDetailsCache `
                    -RbacClassificationsByObject $RbacByObject `
                    -RoleSystem "EntraID" `
                    -EnableParallelProcessing $true `
                    -ParallelThrottleLimit 5 6>$null)
            $Result.Count | Should -Be 50
            foreach ($Object in $Result) {
                @($Object.Classification).Count | Should -Be 1
                $Object.Classification[0].Service | Should -BeExactly "Default Member"
                $Object.Classification[0].MatchedActions | Should -Be @("a/read", "b/read")
            }
        }

        It "sorts assignments without changing shared classification type names (parallel: <Parallel>)" -ForEach @(
            @{ Parallel = $false }
            @{ Parallel = $true }
        ) {
            # The same classification can contribute to several principals (e.g. group inheritance).
            # Its type names must stay untouched even when several workers sort it concurrently.
            $SharedClassification = @(
                New-TestClassItem -TierLevel "1" -TierLevelName "ManagementPlane" -MatchedActions @("read")
                New-TestClassItem -TierLevel "0" -TierLevelName "ControlPlane" -MatchedActions @("write")
            )
            $OriginalTypeNames = @($SharedClassification | ForEach-Object { $_.PSObject.TypeNames -join "`n" })
            $Assignments = @(
                New-TestAssignmentWithClass -RoleName "Zeta" -Classification $SharedClassification
                New-TestAssignmentWithClass -RoleName "Alpha" -Classification $SharedClassification
                New-TestAssignmentWithClass -RoleName "Alpha" -Classification $SharedClassification
                New-TestAssignmentWithClass -RoleName "Earlier name, lower privilege" -Classification @($SharedClassification[0])
            )
            $Assignments[1].RoleAssignmentScopeId = "/z"
            $Assignments[2].RoleAssignmentScopeId = "/a"
            $UniqueObjects = @(foreach ($Index in 1..50) {
                    [pscustomobject]@{ ObjectId = "shared-$Index"; ObjectType = "user" }
                })
            $Details = @{}
            $ByObject = @{}
            foreach ($Object in $UniqueObjects) {
                $Details[$Object.ObjectId] = New-TestObjectDetails -ObjectId $Object.ObjectId -DisplayName $Object.ObjectId
                $ByObject[$Object.ObjectId] = $Assignments
            }

            $Result = @(Invoke-EntraOpsEAMClassificationAggregation `
                    -UniqueObjects $UniqueObjects -ObjectDetailsCache $Details `
                    -RbacClassificationsByObject $ByObject -RoleSystem "IdentityGovernance" `
                    -EnableParallelProcessing $Parallel -ParallelThrottleLimit 5 6>$null)

            @($SharedClassification | ForEach-Object { $_.PSObject.TypeNames -join "`n" }) | Should -Be $OriginalTypeNames
            $Result.Count | Should -Be 50
            foreach ($Object in $Result) {
                @($Object.RoleAssignments.RoleDefinitionName) | Should -Be @("Alpha", "Alpha", "Zeta", "Earlier name, lower privilege")
                @($Object.RoleAssignments.RoleAssignmentScopeId) | Should -Be @("/a", "/z", "/", "/")
                $RoundTrip = $Object | ConvertTo-Json -Depth 20 | ConvertFrom-Json
                Assert-TestClassificationEvidence -Object $RoundTrip
            }
        }

        It "preserves per-tier/service evidence for <RoleSystem> with parallel processing <Parallel>" -ForEach @(
            foreach ($RoleSystem in @('EntraID', 'Azure', 'IdentityGovernance', 'DeviceManagement', 'Defender')) {
                foreach ($Parallel in @($false, $true)) {
                    @{ RoleSystem = $RoleSystem; Parallel = $Parallel }
                }
            }
        ) {
            $Assignments = @(
                New-TestAssignmentWithClass -RoleName "Role A" -Classification @(
                    New-TestClassItem -Service "Service A" -MatchedActions @("shared/read", "first/write")
                    New-TestClassItem -Service "Service B" -MatchedActions @("shared/read")
                )
                New-TestAssignmentWithClass -RoleName "Role B" -Classification @(
                    New-TestClassItem -Service "service a" -MatchedActions @("SHARED/READ", "second/write")
                    New-TestClassItem -Service "Service A" -TierLevel "0" -TierLevelName "ControlPlane" -MatchedActions @("admin/write")
                )
            )
            $UniqueObjects = @()
            $Details = @{}
            $ByObject = @{}
            $Count = if ($Parallel) { 50 } else { 1 }
            foreach ($Index in 1..$Count) {
                $Id = "evidence-$Index"
                $UniqueObjects += [pscustomobject]@{ ObjectId = $Id; ObjectType = "user" }
                $Details[$Id] = New-TestObjectDetails -ObjectId $Id -DisplayName $Id
                $ByObject[$Id] = $Assignments
            }
            $Result = @(Invoke-EntraOpsEAMClassificationAggregation `
                    -UniqueObjects $UniqueObjects -ObjectDetailsCache $Details `
                    -RbacClassificationsByObject $ByObject -RoleSystem $RoleSystem `
                    -EnableParallelProcessing $Parallel -ParallelThrottleLimit 2 6>$null)
            $Result.Count | Should -Be $Count
            foreach ($Object in $Result) {
                @($Object.Classification).Count | Should -Be 3
                Assert-TestClassificationEvidence -Object $Object
                $RoundTrip = $Object | ConvertTo-Json -Depth 20 | ConvertFrom-Json
                Assert-TestClassificationEvidence -Object $RoundTrip
            }
        }
    }
}

Describe "Get-EntraOpsPrivilegedEAMResourceApps classification aggregation" {
    BeforeAll {
        function Resolve-EntraOpsClassificationPath { param($ClassificationFileName) }
        function Get-EntraOpsPrivilegedAppRoles { param($TenantId, $WarningMessages) }
        function Import-EntraOpsGlobalExclusions { param($Enabled) }
        function Expand-EntraOpsPrivilegedEAMJsonFile { param($FilePath) }
        function Resolve-EntraOpsAppRoleAssignmentClassification { param($AppRoleAssignments, $ClassificationDefinitions) }
        function Invoke-EntraOpsMsGraphQuery { param($Method, $Uri) }
        function Get-EntraOpsPrivilegedEntraObject { param($AadObjectId, $TenantId) }
        function Invoke-EntraOpsParallelObjectResolution { param($UniqueObjects, $TenantId, $EnableParallelProcessing, $ParallelThrottleLimit) }
        function Show-EntraOpsWarningSummary { param($WarningMessages, $IncludeObjectDetails) }
        . "$script:TestRepositoryRoot/EntraOps/Private/Set-EntraOpsEAMClassificationJustification.ps1"
        . "$script:TestRepositoryRoot/EntraOps/Public/PrivilegedAccess/Get-EntraOpsPrivilegedEAMResourceApps.ps1"

        function New-TestAppAssignment {
            param ([string]$ObjectId, [string]$Action, [string]$ScopeId = 'scope-1')
            [pscustomobject]@{
                ObjectId              = $ObjectId
                ObjectType            = 'serviceprincipal'
                RoleType              = 'Delegated'
                RoleDefinitionName    = $Action
                RoleAssignmentScopeId = 'resource-principal'
                Classification        = @([pscustomobject]@{
                        AdminTierLevel     = '2'
                        AdminTierLevelName = 'UserAccess'
                        Service            = 'Default Member'
                        MatchedActions     = @($Action)
                        ScopedObjects      = @([pscustomobject]@{ id = $ScopeId })
                    })
            }
        }
    }

    It "preserves ResourceApps evidence (direct agent assignments: <Direct>, parallel: <Parallel>, inheritance: <Kind>)" -ForEach @(
        @{ Direct = $false; Parallel = $false; Kind = 'allAllowed'; Single = $true }
        @{ Direct = $false; Parallel = $false; Kind = 'enumerated'; Single = $false }
        @{ Direct = $true; Parallel = $false; Kind = 'allAllowed'; Single = $false }
        @{ Direct = $true; Parallel = $true; Kind = 'enumerated'; Single = $false }
        @{ Direct = $false; Parallel = $true; Kind = 'allAllowed'; Single = $false }
    ) {
        $script:InheritanceKind = $Kind
        $script:AppAssignments = @(New-TestAppAssignment -ObjectId 'blueprint' -Action 'User.Read.All' -ScopeId 'scope-2')
        if (-not $Single) {
            $script:AppAssignments += New-TestAppAssignment -ObjectId 'blueprint' -Action 'Group.Read.All'
        }
        if ($Direct) {
            $script:AppAssignments += New-TestAppAssignment -ObjectId 'agent' -Action 'Application.Read.All'
        }
        if ($Parallel) {
            foreach ($Index in 1..499) {
                $script:AppAssignments += New-TestAppAssignment -ObjectId "app-$Index" -Action 'User.Read.All'
            }
        }
        Mock Resolve-EntraOpsClassificationPath { 'unused.json' }
        Mock Get-EntraOpsPrivilegedAppRoles { $script:AppAssignments }
        Mock Import-EntraOpsGlobalExclusions { @() }
        Mock Expand-EntraOpsPrivilegedEAMJsonFile { @() }
        Mock Resolve-EntraOpsAppRoleAssignmentClassification { $AppRoleAssignments }
        Mock Invoke-EntraOpsMsGraphQuery {
            if ($Uri -like '*servicePrincipals/microsoft.graph.agentIdentityBlueprintPrincipal?*') {
                return [pscustomobject]@{ id = 'blueprint'; appId = 'blueprint-app'; displayName = 'Blueprint'; appOwnerOrganizationId = 'tenant-1' }
            }
            if ($Uri -like '*/inheritablePermissions') {
                return [pscustomobject]@{
                    resourceAppId     = 'resource-app'
                    inheritableScopes = [pscustomobject]@{ kind = $script:InheritanceKind; scopes = @('User.Read.All', 'Group.Read.All') }
                }
            }
            if ($Uri -like "*appId eq 'resource-app'*") {
                return [pscustomobject]@{ id = 'resource-principal' }
            }
            if ($Uri -like "*createdByAppId*'blueprint-app'*") {
                return [pscustomobject]@{ id = 'agent' }
            }
            throw "Unexpected Graph request: $Uri"
        }
        Mock Get-EntraOpsPrivilegedEntraObject {
            $Details = New-TestObjectDetails -ObjectId $AadObjectId -DisplayName $AadObjectId
            $Details.ObjectType = 'serviceprincipal'
            $Details.ObjectSubType = 'AgentIdentity'
            return $Details
        }
        Mock Invoke-EntraOpsParallelObjectResolution {
            $Cache = @{}
            foreach ($Object in $UniqueObjects) {
                $Details = New-TestObjectDetails -ObjectId $Object.ObjectId -DisplayName $Object.ObjectId
                $Details.ObjectType = 'serviceprincipal'
                $Details.ObjectSubType = if ($Object.ObjectId -eq 'agent') { 'AgentIdentity' } else { 'Application' }
                $Cache[$Object.ObjectId] = $Details
            }
            return $Cache
        }
        Mock Show-EntraOpsWarningSummary {}

        $OriginalTypeNames = @($script:AppAssignments | ForEach-Object {
                $_.Classification | ForEach-Object { $_.PSObject.TypeNames -join "`n" }
            })
        $Result = @(Get-EntraOpsPrivilegedEamResourceApps -TenantId 'tenant-1' -EnableParallelProcessing $Parallel 6>$null)
        @($script:AppAssignments | ForEach-Object {
                $_.Classification | ForEach-Object { $_.PSObject.TypeNames -join "`n" }
            }) | Should -Be $OriginalTypeNames
        $Result.Count | Should -Be (2 + $(if ($Parallel) { 499 } else { 0 }))
        foreach ($Object in $Result) {
            Assert-TestClassificationEvidence -Object $Object
            $RoundTrip = $Object | ConvertTo-Json -Depth 20 | ConvertFrom-Json
            Assert-TestClassificationEvidence -Object $RoundTrip
        }
        $Agent = @($Result | Where-Object ObjectId -eq 'agent')
        $Agent.Count | Should -Be 1
        $ExpectedActions = @('User.Read.All')
        if (-not $Single) { $ExpectedActions += 'Group.Read.All' }
        if ($Direct) { $ExpectedActions += 'Application.Read.All' }
        @($Agent[0].Classification[0].MatchedActions | Sort-Object) | Should -Be @($ExpectedActions | Sort-Object)
        ($Agent[0].Classification[0].MatchedActions -is [array]) | Should -BeTrue
        $ExpectedScopes = if ($Single) { @('scope-2') } else { @('scope-1', 'scope-2') }
        @($Agent[0].Classification[0].ScopedObjects.id | Sort-Object) | Should -Be @($ExpectedScopes)
        @($Agent[0].RoleAssignments | Where-Object RoleAssignmentType -eq 'Inheritable').Count | Should -Be $(if ($Single) { 1 } else { 2 })
        @($Agent[0].RoleAssignments | Where-Object ObjectId -ne 'agent').Count | Should -Be 0
    }

    It "uses the shared merge helper instead of first-wins aggregation in both code paths" {
        $Path = Join-Path $script:TestRepositoryRoot "EntraOps/Public/PrivilegedAccess/Get-EntraOpsPrivilegedEAMResourceApps.ps1"
        $Ast = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$null, [ref]$null)
        $Commands = $Ast.FindAll({ param($Node) $Node -is [System.Management.Automation.Language.CommandAst] }, $true) |
        ForEach-Object { $_.GetCommandName() }
        @($Commands | Where-Object { $_ -eq "Merge-EntraOpsEAMClassification" }).Count | Should -BeGreaterOrEqual 2
        (Get-Content -Path $Path -Raw) | Should -Not -Match 'UniqueClassificationsHash'
    }
}
