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
                RoleAssignmentId                     = "assignment-1"
                RoleDefinitionId                     = "role-1"
                RoleDefinitionName                   = "Global Administrator"
                RoleAssignmentScopeId                = "/"
                RoleAssignmentSubType                = "Permanent"
                Classification                       = $Classification
                TransitiveByNestingObjectIds         = @("group-a", "group-b")
                TransitiveByNestingObjectDisplayNames = @("Group A", "Group B")
            }
            [pscustomobject]@{
                RoleAssignmentId                     = "assignment-1"
                RoleDefinitionId                     = "role-1"
                RoleDefinitionName                   = "Global Administrator"
                RoleAssignmentScopeId                = "/"
                RoleAssignmentSubType                = "Permanent"
                Classification                       = $Classification
                TransitiveByNestingObjectIds         = @("group-a", "group-b")
                TransitiveByNestingObjectDisplayNames = @("Group A", "Group B")
            }
            [pscustomobject]@{
                RoleAssignmentId                     = "assignment-1"
                RoleDefinitionId                     = "role-1"
                RoleDefinitionName                   = "Global Administrator"
                RoleAssignmentScopeId                = "/"
                RoleAssignmentSubType                = "Permanent"
                Classification                       = $Classification
                TransitiveByNestingObjectIds         = @("group-b")
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

