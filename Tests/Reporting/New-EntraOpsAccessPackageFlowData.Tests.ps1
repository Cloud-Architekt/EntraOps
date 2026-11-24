#Requires -Modules Pester

Describe 'New-EntraOpsAccessPackageFlowData' {
    BeforeAll {
        $script:TestRepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
        Import-Module (Join-Path $script:TestRepositoryRoot 'EntraOps/EntraOps.psd1') -Force -WarningAction SilentlyContinue
    }

    BeforeEach {
        $script:ControlPlaneUserId = '11111111-1111-1111-1111-111111111111'
        $script:ManagementPlaneUserId = '22222222-2222-2222-2222-222222222222'
        $script:UnprivilegedUserId = '33333333-3333-3333-3333-333333333333'
        $script:GroupId = '44444444-4444-4444-4444-444444444444'
        $script:AssignmentsResponse = @()
        $script:ScopesResponse = @()
        $script:DriftResponse = @{ group = @(); application = @() }
        $script:DriftError = $null
        $script:ExpirationResponse = $null
        $script:Root = Join-Path $TestDrive ([guid]::NewGuid())
        New-Item -ItemType Directory -Path "$script:Root/PrivilegedEAM/EntraID", "$script:Root/TenantGovernance/Snapshots", "$script:Root/App" -Force | Out-Null

        # At least two privileged objects are required: with a single object the nested-list bug
        # was masked because member enumeration still yields one valid object ID.
        @(
            [ordered]@{
                ObjectId = $script:ControlPlaneUserId; ObjectType = 'user'; ObjectSubType = 'Member'; ObjectDisplayName = 'CP Admin'
                ObjectAdminTierLevel = 'Unclassified'; ObjectAdminTierLevelName = 'Unclassified'
                RoleAssignments = @(@{ RoleAssignmentId = 'ra1'; RoleDefinitionName = 'Global Administrator'; RoleAssignmentScopeId = '/'; Classification = @(@{ AdminTierLevelName = 'ControlPlane'; Service = 'Global' }) })
            }
            [ordered]@{
                ObjectId = $script:ManagementPlaneUserId; ObjectType = 'user'; ObjectSubType = 'Member'; ObjectDisplayName = 'MP Admin'
                ObjectAdminTierLevel = 'Unclassified'; ObjectAdminTierLevelName = 'Unclassified'
                RoleAssignments = @(@{ RoleAssignmentId = 'ra2'; RoleDefinitionName = 'Groups Administrator'; RoleAssignmentScopeId = '/'; Classification = @(@{ AdminTierLevelName = 'ManagementPlane'; Service = 'Groups' }) })
            }
        ) | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath "$script:Root/PrivilegedEAM/EntraID/EntraID.json"

        @{
            resourceType = 'microsoft.entra.entitlementManagementAccessPackageAssignmentPolicy'
            properties   = @{ Id = 'policy1' }
        } | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath "$script:Root/TenantGovernance/Snapshots/policy1.json"

        Mock -ModuleName EntraOps Invoke-EntraOpsMsGraphQuery {
            switch -Wildcard ($Uri) {
                '*/accessPackageAssignmentPolicies/policy1' {
                    return [pscustomobject]@{
                        accessPackageId         = 'package1'
                        requestorSettings       = [pscustomobject]@{
                            scopeType         = 'SpecificDirectorySubjects'
                            allowedRequestors = @([pscustomobject]@{ '@odata.type' = '#microsoft.graph.groupMembers'; id = '44444444-4444-4444-4444-444444444444' })
                        }
                        requestApprovalSettings = [pscustomobject]@{ approvalStages = @() }
                    }
                }
                '*/accessPackageAssignmentPolicies/deleted-policy' {
                    # Same shape as the error Invoke-EntraOpsMsGraphQuery -ThrowOnFailure throws for a 404
                    $Exception = [System.InvalidOperationException]::new("Microsoft Graph query '$Uri' failed: Response status code does not indicate success: NotFound (Not Found).")
                    $Exception.Data['StatusCode'] = 404
                    throw $Exception
                }
                '/v1.0/identityGovernance/entitlementManagement/assignmentPolicies/policy1?*' { return [pscustomobject]@{ id = 'policy1'; expiration = $script:ExpirationResponse } }
                '*/accessPackages/package1' { return [pscustomobject]@{ displayName = 'Package 1'; catalogId = '' } }
                '*/accessPackages/package1?*' { return [pscustomobject]@{ accessPackageResourceRoleScopes = $script:ScopesResponse } }
                '*/accessPackageAssignments?*' { return $script:AssignmentsResponse }
                '*/groups/44444444-4444-4444-4444-444444444444*' { return [pscustomobject]@{ id = '44444444-4444-4444-4444-444444444444'; displayName = 'Requestor Group' } }
                '*/identityGovernance/insights/accessDriftSummary?*' {
                    if ($script:DriftError) { throw $script:DriftError }
                    $Type = if ([uri]::UnescapeDataString($Uri) -match "resource/type eq '(\w+)'") { $Matches[1] } else { '' }
                    return $script:DriftResponse[$Type]
                }
                default { throw "Unexpected Graph request in test: $Uri" }
            }
        }
        Mock -ModuleName EntraOps Get-EntraOpsIdGovScopeClassification { @() }
        Mock -ModuleName EntraOps Get-EntraOpsPrivilegedTransitiveGroupMember {
            @(
                [pscustomobject]@{ Id = '11111111-1111-1111-1111-111111111111'; DisplayName = 'CP Admin' }
                [pscustomobject]@{ Id = '22222222-2222-2222-2222-222222222222'; DisplayName = 'MP Admin' }
                [pscustomobject]@{ Id = '33333333-3333-3333-3333-333333333333'; DisplayName = 'Regular User' }
            )
        }
        Mock -ModuleName EntraOps Save-EntraOpsReportDataFile {}
    }

    It 'resolves requestor group member tiers from multiple Privileged EAM objects' {
        $Result = New-EntraOpsAccessPackageFlowData -RepoRoot $script:Root -AppRoot "$script:Root/App" -ResolveRequestorApproverTiers $true -PassThru -WarningAction SilentlyContinue

        $Group = $Result.resolvedGroupTiers[$script:GroupId]
        $Group | Should -Not -BeNullOrEmpty
        $Group.tierName | Should -Be 'ControlPlane'
        $Group.totalMembers | Should -Be 3
        $Group.privilegedMemberCount | Should -Be 2

        $MemberTiers = @{}
        foreach ($Member in $Group.members) { $MemberTiers[$Member.id] = $Member.tierName }
        $MemberTiers[$script:ControlPlaneUserId] | Should -Be 'ControlPlane'
        $MemberTiers[$script:ManagementPlaneUserId] | Should -Be 'ManagementPlane'
        $MemberTiers[$script:UnprivilegedUserId] | Should -Be 'UserAccess'
    }

    It 'keeps the expiration of the policy: from Microsoft Graph v1.0, else from the legacy policy (EO.6005)' {
        $script:ExpirationResponse = [pscustomobject]@{ type = 'afterDuration'; duration = 'PT12H'; endDateTime = $null }
        $Result = New-EntraOpsAccessPackageFlowData -RepoRoot $script:Root -AppRoot "$script:Root/App" -ResolveRequestorApproverTiers $false -PassThru -WarningAction SilentlyContinue
        $Result.policyRequestorApprovers['policy1'].expiration.type | Should -Be 'afterDuration'
        $Result.policyRequestorApprovers['policy1'].expiration.duration | Should -Be 'PT12H'

        # Without the v1.0 expiration and without a date or days on the legacy policy, the expiration stays unknown:
        # EO.6005 then falls back to the snapshot and says so.
        $script:ExpirationResponse = $null
        $Result = New-EntraOpsAccessPackageFlowData -RepoRoot $script:Root -AppRoot "$script:Root/App" -ResolveRequestorApproverTiers $false -PassThru -WarningAction SilentlyContinue
        $Result.policyRequestorApprovers['policy1'].expiration | Should -BeNullOrEmpty
    }

    It 'writes the tiers the Object Classification File declares for the target groups' {
        $Declared = '55555555-5555-5555-5555-555555555555'
        $NotDeclared = '66666666-6666-6666-6666-666666666666'
        $DeclaredAsUser = '77777777-7777-7777-7777-777777777777'
        $Scope = { param($Id, $Name) [pscustomobject]@{ accessPackageResourceRole = [pscustomobject]@{ displayName = 'Member'; originId = "Member_$Id" }; accessPackageResourceScope = [pscustomobject]@{ originId = $Id; originSystem = 'AadGroup'; displayName = $Name } } }
        $script:ScopesResponse = @((& $Scope $Declared 'Declared Group'), (& $Scope $NotDeclared 'Other Group'), (& $Scope $DeclaredAsUser 'Group Declared As User'))
        New-Item -ItemType Directory -Path "$script:Root/Classification" -Force | Out-Null
        @{ ObjectClassificationFile = @{ Enabled = $true; FilePath = './Classification/ObjectClassification.json' } } | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath "$script:Root/EntraOpsConfig.json"
        @(
            [ordered]@{ ObjectId = $Declared; ObjectType = 'group'; ObjectDisplayName = 'Declared Group'; AdminTierLevelName = 'ManagementPlane'; Justification = 'Landing zone 01' }
            # An entry for another object type does not classify the group.
            [ordered]@{ ObjectId = $DeclaredAsUser; ObjectType = 'user'; ObjectDisplayName = 'Someone'; AdminTierLevelName = 'ControlPlane'; Justification = 'Wrong type' }
        ) | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath "$script:Root/Classification/ObjectClassification.json"

        $Result = New-EntraOpsAccessPackageFlowData -RepoRoot $script:Root -AppRoot "$script:Root/App" -ResolveRequestorApproverTiers $false -PassThru -WarningAction SilentlyContinue

        @($Result.objectClassifications.Keys) | Should -Be @($Declared)
        $Result.objectClassifications[$Declared].tierName | Should -Be 'ManagementPlane'
        $Result.objectClassifications[$Declared].justification | Should -Be 'Landing zone 01'
        $Result.objectClassifications[$Declared].declaredBy | Should -Be 'Object Classification File'
        @($Result.packages['package1'].targets.originSystem | Select-Object -Unique) | Should -Be @('AadGroup')
    }

    It 'classifies target groups by the Group filters of the Alternate Tier Level Attributes before the Object Classification File' {
        $Filtered = '55555555-5555-5555-5555-555555555555'
        $FileOnly = '66666666-6666-6666-6666-666666666666'
        $Scope = { param($Id, $Name) [pscustomobject]@{ accessPackageResourceRole = [pscustomobject]@{ displayName = 'Member'; originId = "Member_$Id" }; accessPackageResourceScope = [pscustomobject]@{ originId = $Id; originSystem = 'AadGroup'; displayName = $Name } } }
        $script:ScopesResponse = @((& $Scope $Filtered 'SG-LZ01-Users'), (& $Scope $FileOnly 'Other Group'))
        New-Item -ItemType Directory -Path "$script:Root/Classification" -Force | Out-Null
        @{
            ObjectClassificationFile           = @{ Enabled = $true; FilePath = './Classification/ObjectClassification.json' }
            AlternateObjectTierLevelAttributes = @{ Group = @{ Enabled = $true; ManagementPlane = '$Object.ObjectDisplayName -like "SG-LZ*"' } }
        } | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath "$script:Root/EntraOpsConfig.json"
        @(
            [ordered]@{ ObjectId = $Filtered; ObjectType = 'group'; AdminTierLevelName = 'UserAccess'; Justification = 'From the file' }
            [ordered]@{ ObjectId = $FileOnly; ObjectType = 'group'; AdminTierLevelName = 'ControlPlane'; Justification = 'Emergency access' }
        ) | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath "$script:Root/Classification/ObjectClassification.json"
        # Get-EntraOpsPrivilegedEntraObject evaluates the filters like in Privileged EAM: here the first group matches.
        Mock -ModuleName EntraOps Get-EntraOpsPrivilegedEntraObject {
            [pscustomobject]@{ ObjectId = $AadObjectId; ObjectType = 'group'; AdminTierLevelName = $(if ($AadObjectId -eq '55555555-5555-5555-5555-555555555555') { 'ManagementPlane' } else { 'Unclassified' }) }
        }

        $Result = New-EntraOpsAccessPackageFlowData -RepoRoot $script:Root -AppRoot "$script:Root/App" -ResolveRequestorApproverTiers $false -PassThru -WarningAction SilentlyContinue

        $Result.objectClassifications[$Filtered].tierName | Should -Be 'ManagementPlane'
        $Result.objectClassifications[$Filtered].declaredBy | Should -Be 'Alternate Tier Level Attributes'
        $Result.objectClassifications[$FileOnly].tierName | Should -Be 'ControlPlane'
        $Result.objectClassifications[$FileOnly].declaredBy | Should -Be 'Object Classification File'
        # Only the filters are evaluated there (the file is read here, with its justification).
        Should -Invoke -ModuleName EntraOps Get-EntraOpsPrivilegedEntraObject -Times 2 -Exactly -ParameterFilter { $null -eq $ObjectClassificationFile -and $AlternateObjectTierLevelAttributes.Group.Enabled }
    }

    It 'does not look up the target groups when no Group filter is enabled' {
        $Id = '55555555-5555-5555-5555-555555555555'
        $script:ScopesResponse = @([pscustomobject]@{ accessPackageResourceRole = [pscustomobject]@{ displayName = 'Member'; originId = "Member_$Id" }; accessPackageResourceScope = [pscustomobject]@{ originId = $Id; originSystem = 'AadGroup'; displayName = 'Group' } })
        @{ AlternateObjectTierLevelAttributes = @{ Group = @{ Enabled = $false; ManagementPlane = '$true' } } } | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath "$script:Root/EntraOpsConfig.json"
        Mock -ModuleName EntraOps Get-EntraOpsPrivilegedEntraObject {}

        $Result = New-EntraOpsAccessPackageFlowData -RepoRoot $script:Root -AppRoot "$script:Root/App" -ResolveRequestorApproverTiers $false -PassThru -WarningAction SilentlyContinue

        $Result.objectClassifications.Count | Should -Be 0
        Should -Invoke -ModuleName EntraOps Get-EntraOpsPrivilegedEntraObject -Times 0
    }

    It 'writes no declared tiers when the Object Classification File is disabled' {
        $Id = '55555555-5555-5555-5555-555555555555'
        $script:ScopesResponse = @([pscustomobject]@{ accessPackageResourceRole = [pscustomobject]@{ displayName = 'Member'; originId = "Member_$Id" }; accessPackageResourceScope = [pscustomobject]@{ originId = $Id; originSystem = 'AadGroup'; displayName = 'Declared Group' } })
        New-Item -ItemType Directory -Path "$script:Root/Classification" -Force | Out-Null
        @{ ObjectClassificationFile = @{ Enabled = $false; FilePath = './Classification/ObjectClassification.json' } } | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath "$script:Root/EntraOpsConfig.json"
        @([ordered]@{ ObjectId = $Id; ObjectType = 'group'; AdminTierLevelName = 'ManagementPlane'; Justification = 'x' }) | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath "$script:Root/Classification/ObjectClassification.json"

        $Result = New-EntraOpsAccessPackageFlowData -RepoRoot $script:Root -AppRoot "$script:Root/App" -ResolveRequestorApproverTiers $false -PassThru -WarningAction SilentlyContinue

        $Result.objectClassifications.Count | Should -Be 0
    }

    It 'maps the beta assignment state, status and subject type' {
        $script:AssignmentsResponse = @(
            [pscustomobject]@{
                id = 'assignment1'; accessPackageId = 'package1'; assignmentPolicyId = 'policy1'
                assignmentState = 'Delivered'; assignmentStatus = 'Delivered'
                target = [pscustomobject]@{ objectId = $script:ControlPlaneUserId; displayName = 'CP Admin'; principalName = 'cp@contoso.com'; type = 'User' }
            }
            [pscustomobject]@{
                id = 'assignment2'; accessPackageId = 'package1'; assignmentPolicyId = 'policy1'
                state = 'Expired'; status = 'ExpiredNotificationTriggered'
                target = [pscustomobject]@{ objectId = $script:UnprivilegedUserId; subjectType = 'user' }
            }
        )

        $Result = New-EntraOpsAccessPackageFlowData -RepoRoot $script:Root -AppRoot "$script:Root/App" -ResolveRequestorApproverTiers $false -PassThru -WarningAction SilentlyContinue

        $Delivered = @($Result.assignments | Where-Object { $_.id -eq 'assignment1' })[0]
        $Delivered.state | Should -Be 'Delivered'
        $Delivered.status | Should -Be 'Delivered'
        $Delivered.target.subjectType | Should -Be 'User'
        $Expired = @($Result.assignments | Where-Object { $_.id -eq 'assignment2' })[0]
        $Expired.state | Should -Be 'Expired'
        $Expired.target.subjectType | Should -Be 'user'
    }

    It 'reads the access drift of the governed groups and applications' {
        $script:DriftResponse.group = @(
            [pscustomobject]@{
                id              = 'v1_summary1'
                resource        = [pscustomobject]@{ identifier = $script:GroupId; displayName = 'CP Group'; type = 'group'; catalogIdentifier = 'cat1'; catalogName = 'Tier0' }
                driftSource     = 'entra'
                driftCounts     = [pscustomobject]@{ total = 7; unauthorized = 5; missing = 2 }
                createdDateTime = '2026-10-26T03:15:42Z'
                details         = @([pscustomobject]@{
                        driftType = 'unauthorized'; assignedRole = 'Member'; expectedRole = 'None'
                        accessPackage = [pscustomobject]@{ identifier = 'package1'; displayName = 'Package 1' }
                        identities = @([pscustomobject]@{ identifier = $script:UnprivilegedUserId; principalName = 'user@contoso.com'; displayName = 'Regular User'; identityType = 'user' })
                    })
            }
        )

        $Result = New-EntraOpsAccessPackageFlowData -RepoRoot $script:Root -AppRoot "$script:Root/App" -ResolveRequestorApproverTiers $false -PassThru -WarningAction SilentlyContinue

        $Result.accessDrift.status | Should -Be 'collected'
        @($Result.accessDrift.resources).Count | Should -Be 1
        $Drift = $Result.accessDrift.resources[0]
        $Drift.resourceId | Should -Be $script:GroupId
        $Drift.catalogId | Should -Be 'cat1'
        $Drift.unauthorized | Should -Be 5
        $Drift.missing | Should -Be 2
        $Drift.details[0].accessPackageName | Should -Be 'Package 1'
        $Drift.details[0].identities[0].principalName | Should -Be 'user@contoso.com'
    }

    It 'reports the access drift as unavailable with the reason when Microsoft Graph refuses it' {
        $script:DriftError = 'Forbidden: the tenant has no Microsoft Entra ID Governance license.'

        $Result = New-EntraOpsAccessPackageFlowData -RepoRoot $script:Root -AppRoot "$script:Root/App" -ResolveRequestorApproverTiers $false -PassThru -WarningVariable Warnings -WarningAction SilentlyContinue

        $Result.accessDrift.status | Should -Be 'unavailable'
        $Result.accessDrift.reason | Should -Match 'no Microsoft Entra ID Governance license'
        @($Result.accessDrift.resources).Count | Should -Be 0
        @($Warnings | Where-Object { "$_" -like 'Access drift could not be read*' }).Count | Should -Be 1
    }

    It 'skips a deleted assignment policy with one summarised warning and unchanged data' {
        $Expected = New-EntraOpsAccessPackageFlowData -RepoRoot $script:Root -AppRoot "$script:Root/App" -ResolveRequestorApproverTiers $false -PassThru -WarningAction SilentlyContinue
        @{
            resourceType = 'microsoft.entra.entitlementManagementAccessPackageAssignmentPolicy'
            properties   = @{ Id = 'deleted-policy' }
        } | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath "$script:Root/TenantGovernance/Snapshots/deleted-policy.json"

        $Result = New-EntraOpsAccessPackageFlowData -RepoRoot $script:Root -AppRoot "$script:Root/App" -ResolveRequestorApproverTiers $false -PassThru -WarningVariable Warnings -WarningAction SilentlyContinue

        $PolicyWarnings = @($Warnings | Where-Object { "$_" -match 'deleted-policy' })
        $PolicyWarnings.Count | Should -Be 1
        "$($PolicyWarnings[0])" | Should -Match 'NotFound'
        "$($PolicyWarnings[0])" | Should -Not -Match 'Could not resolve'
        ($Result | ConvertTo-Json -Depth 20) -replace '"generatedAt":\s*"[^"]*"' | Should -Be (($Expected | ConvertTo-Json -Depth 20) -replace '"generatedAt":\s*"[^"]*"')
    }
}
