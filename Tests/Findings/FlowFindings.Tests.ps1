#Requires -Modules Pester

Describe 'PIM Request Flow and Access Package Flow findings' {
    BeforeAll {
        $script:TestRepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
        Import-Module (Join-Path $script:TestRepositoryRoot 'EntraOps/EntraOps.psd1') -Force -WarningAction SilentlyContinue

        function Get-TestId([int]$Number) { '{0:d8}-0000-0000-0000-{1:d12}' -f $Number, $Number }
        $script:Roles = @{ GlobalAdmin = (Get-TestId 101); Helpdesk = (Get-TestId 102); Custom = (Get-TestId 103); Security = (Get-TestId 105) }
        $script:Users = @{ ControlPlane = (Get-TestId 1); ManagementPlane = (Get-TestId 2); UserAccess = (Get-TestId 3); ByName = (Get-TestId 4); Unknown = (Get-TestId 99) }
        $script:Groups = @{ ControlPlane = (Get-TestId 201); ManagementPlane = (Get-TestId 202); Approvers = (Get-TestId 204); Declared = (Get-TestId 205); Unclassified = (Get-TestId 206); Unknown = (Get-TestId 299) }

        function Write-TestDataFile([string]$Path, [string]$Variable, $Data) {
            New-Item -ItemType Directory -Path (Split-Path -Parent $Path) -Force | Out-Null
            "window.$Variable = $($Data | ConvertTo-Json -Depth 20 -Compress);" | Set-Content -LiteralPath $Path
        }

        function New-TestRoleSetting([string]$RoleId, [string]$DisplayName, [hashtable]$Property = @{}) {
            $Setting = [ordered]@{
                Id = $RoleId; DisplayName = $DisplayName; ActivationReqMFA = $true; ApprovaltoActivate = $false; ActivateApprover = @()
                PermanentEligibleAssignmentisExpirationRequired = $true; PermanentActiveAssignmentisExpirationRequired = $true; AssignmentReqMFA = $true
            }
            foreach ($Key in $Property.Keys) { $Setting[$Key] = $Property[$Key] }
            $Setting
        }

        # Writes the report data of a Reports folder: Configuration Analyzer, tier map, EAM Dashboard and Access Package Flow.
        # -PimExcluded and -AccessPackageExcluded embed excluded risk flags in the Configuration Analyzer data like
        # older versions did; the rules ignore them (the exclusions are read from EntraOpsConfig.json only).
        function New-TestReportData([string]$Root, [string[]]$PimExcluded = @(), [string[]]$AccessPackageExcluded = @(), [switch]$NoDetail, [ValidateSet('collected', 'unavailable', 'missing')][string]$AccessDrift = 'collected', [switch]$AccessPackagesInOlder, [switch]$DuplicateRoleSetting, [switch]$SharedResource, [switch]$DuplicateApproverName, [switch]$RoleLessTargets, [switch]$MultiStage, [switch]$UnprivilegedApprover) {
            New-Item -ItemType Directory -Path "$Root/PimRequestFlow", "$Root/AccessPackageFlow" -Force | Out-Null
            $script:Blobs = [ordered]@{}
            $NewResource = {
                param($Type, $Name, $Properties)
                $Hash = "h$($script:Blobs.Count + 1)"
                $script:Blobs[$Hash] = [ordered]@{ resourceType = $Type; displayName = $Name; properties = $Properties }
                [ordered]@{ p = "$Type/test/$Name.json"; h = $Hash }
            }
            $Latest = @(
                & $NewResource 'microsoft.entra.rolesetting' 'Global Administrator' (New-TestRoleSetting $script:Roles.GlobalAdmin 'Global Administrator' @{ ActivationReqMFA = $false; ActivateApprover = @('cp.admin@contoso.com'); PermanentEligibleAssignmentisExpirationRequired = $false })
                & $NewResource 'microsoft.entra.rolesetting' 'Helpdesk Administrator' (New-TestRoleSetting $script:Roles.Helpdesk 'Helpdesk Administrator' @{ ApprovaltoActivate = $true; ActivateApprover = @('ua.user@contoso.com', 'Approver By Name', $(if ($UnprivilegedApprover) { 'unknown@contoso.com' } else { 'Unknown Approvers' })); AuthenticationContextRequired = $true; AuthenticationContextName = '' })
                & $NewResource 'microsoft.entra.rolesetting' 'Custom Role' (New-TestRoleSetting $script:Roles.Custom '' @{ ActivationReqMFA = $false; ApprovaltoActivate = $true; ActivateApprover = @('cp.admin@contoso.com') })
                & $NewResource 'microsoft.entra.roledefinition' 'Custom Role' ([ordered]@{ Id = $script:Roles.Custom; DisplayName = 'Custom Role'; RolePermissions = @(@{ AllowedResourceActions = @('microsoft.directory/groups/members/update') }) })
                & $NewResource 'microsoft.entra.rolesetting' 'Security Administrator' (New-TestRoleSetting $script:Roles.Security 'Security Administrator' @{ ApprovaltoActivate = $true; ActivateApprover = @('mp.admin@contoso.com') })
                & $NewResource 'microsoft.entra.entitlementmanagementaccesspackage' 'CP Access' ([ordered]@{ Id = 'pk1'; DisplayName = 'CP Access'; AccessPackageResourceRoleScopes = @(@{ AccessPackageResourceOriginId = $script:Groups.ControlPlane; AccessPackageResourceTierName = 'ManagementPlane' }) })
                & $NewResource 'microsoft.entra.entitlementmanagementaccesspackage' 'MP Access' ([ordered]@{ Id = 'pk2'; DisplayName = 'MP Access'; AccessPackageResourceRoleScopes = @() })
                & $NewResource 'microsoft.entra.entitlementmanagementaccesspackageassignmentpolicy' 'Self-service' ([ordered]@{ Id = 'pol1'; DisplayName = 'Self-service'; AccessPackageId = 'CP Access'; RequestorSettings = @{ ScopeType = 'AllExistingDirectoryMemberUsers' }; RequestApprovalSettings = @{ IsApprovalRequired = $false } })
                & $NewResource 'microsoft.entra.entitlementmanagementaccesspackageassignmentpolicy' 'Approved' ([ordered]@{ Id = 'pol2'; DisplayName = 'Approved'; AccessPackageId = 'pk2'; RequestorSettings = @{ ScopeType = 'SpecificDirectorySubjects' }; RequestApprovalSettings = @{ IsApprovalRequired = $true; ApprovalStages = @(@{ PrimaryApprovers = @(@{ odataType = '#microsoft.graph.singleUser'; Id = $script:Users.UserAccess }, @{ odataType = '#microsoft.graph.groupMembers' }) }) } })
                & $NewResource 'microsoft.entra.entitlementmanagementaccesspackageassignmentpolicy' 'Single live approver' ([ordered]@{ Id = 'pol6'; DisplayName = 'Single live approver'; AccessPackageId = 'pk2'; RequestorSettings = @{ ScopeType = 'SpecificDirectorySubjects' }; RequestApprovalSettings = @{ IsApprovalRequired = $true; ApprovalStages = @(@{ PrimaryApprovers = @(@{ odataType = '#microsoft.graph.groupMembers' }) }) } })
                & $NewResource 'microsoft.entra.entitlementmanagementaccesspackageassignmentpolicy' 'Unresolved approver' ([ordered]@{ Id = 'pol4'; DisplayName = 'Unresolved approver'; AccessPackageId = 'pk1'; RequestorSettings = @{ ScopeType = 'SpecificDirectorySubjects' }; RequestApprovalSettings = @{ IsApprovalRequired = $true; ApprovalStages = @(@{ PrimaryApprovers = @($(if ($UnprivilegedApprover) { @{ odataType = '#microsoft.graph.singleUser'; Id = 'unknown@contoso.com' } } else { @{ odataType = '#microsoft.graph.groupMembers'; Id = $script:Groups.Unknown } })) }) } })
                & $NewResource 'microsoft.entra.entitlementmanagementaccesspackageassignmentpolicy' 'User Access approver' ([ordered]@{ Id = 'pol5'; DisplayName = 'User Access approver'; AccessPackageId = 'pk1'; RequestorSettings = @{ ScopeType = 'SpecificDirectorySubjects' }; RequestApprovalSettings = @{ IsApprovalRequired = $true; ApprovalStages = @(@{ PrimaryApprovers = @($(if ($UnprivilegedApprover) { @{ odataType = '#microsoft.graph.singleUser'; Id = 'ua.user@contoso.com' } } else { @{ odataType = '#microsoft.graph.groupMembers'; Id = $script:Groups.Unknown } }), @{ odataType = '#microsoft.graph.singleUser'; Id = $script:Users.UserAccess }) }) } })
            )
            # The same role setting twice (for example two resource paths of one role): one flow id.
            if ($DuplicateRoleSetting) { $Latest += & $NewResource 'microsoft.entra.rolesetting' 'Global Administrator copy' (New-TestRoleSetting $script:Roles.GlobalAdmin 'Global Administrator' @{ ActivationReqMFA = $false }) }
            # The Control Plane group of pk1 (catalog cat2) also in pk3 of catalog cat1, which has its drift.
            if ($SharedResource) {
                $Latest = @($Latest | ForEach-Object { if ($script:Blobs[$_.h].properties.Id -eq 'pk1') { $script:Blobs[$_.h].properties.CatalogId = 'cat2' }; $_ })
                $Latest += & $NewResource 'microsoft.entra.entitlementmanagementaccesspackage' 'CP Access 2' ([ordered]@{ Id = 'pk3'; DisplayName = 'CP Access 2'; CatalogId = 'cat1'; AccessPackageResourceRoleScopes = @(@{ AccessPackageResourceOriginId = $script:Groups.ControlPlane; AccessPackageResourceTierName = 'ManagementPlane' }) })
                $Latest += & $NewResource 'microsoft.entra.entitlementmanagementaccesspackageassignmentpolicy' 'Shared' ([ordered]@{ Id = 'pol7'; DisplayName = 'Shared'; AccessPackageId = 'pk3'; RequestorSettings = @{ ScopeType = 'SpecificDirectorySubjects' }; RequestApprovalSettings = @{ IsApprovalRequired = $true } })
            }
            # pk1 (Control Plane) with two approval stages: the User Access user approves in both, the Control Plane admin in the second.
            if ($MultiStage) {
                $Latest += & $NewResource 'microsoft.entra.entitlementmanagementaccesspackageassignmentpolicy' 'Two stages' ([ordered]@{ Id = 'pol9'; DisplayName = 'Two stages'; AccessPackageId = 'pk1'; RequestorSettings = @{ ScopeType = 'SpecificDirectorySubjects' }; RequestApprovalSettings = @{ IsApprovalRequired = $true; ApprovalStages = @(
                                @{ PrimaryApprovers = @(@{ odataType = '#microsoft.graph.singleUser'; Id = $script:Users.UserAccess }) }
                                @{ PrimaryApprovers = @(@{ odataType = '#microsoft.graph.singleUser'; Id = $script:Users.UserAccess }, @{ odataType = '#microsoft.graph.singleUser'; Id = $script:Users.ControlPlane }) }
                            ) } })
            }
            # pk4 (live data) grants two groups without role assignments: one declared in the Object Classification File, one not.
            if ($RoleLessTargets) {
                $Latest += & $NewResource 'microsoft.entra.entitlementmanagementaccesspackageassignmentpolicy' 'Exclusions' ([ordered]@{ Id = 'pol8'; DisplayName = 'Exclusions'; AccessPackageId = 'pk4'; RequestorSettings = @{ ScopeType = 'AllExistingDirectoryMemberUsers' }; RequestApprovalSettings = @{ IsApprovalRequired = $false } })
            }
            $Older = @(& $NewResource 'microsoft.entra.rolesetting' 'Global Administrator' (New-TestRoleSetting $script:Roles.GlobalAdmin 'Global Administrator'))
            if ($AccessPackagesInOlder) { $Older += @($Latest | Where-Object { $_.p -like 'microsoft.entra.entitlementmanagement*' }) }
            Write-TestDataFile "$Root/ConfigurationAnalyzer/data/configuration-analyzer-data.js" 'ENTRAOPS_CONFIGANALYZER_DATA' ([ordered]@{
                    snapshots                          = @(
                        [ordered]@{ commitSha = 'aaaaaaaa'; commitDate = '2026-10-01T10:00:00.0000000+00:00'; hasDetail = (-not $NoDetail); resources = $Older }
                        [ordered]@{ commitSha = 'cccccccc'; commitDate = '2026-10-20T10:00:00.0000000+00:00'; hasDetail = (-not $NoDetail); resources = $Latest }
                    )
                    blobs                              = $script:Blobs
                    resolvedGroupTiers                 = @{ $script:Groups.ControlPlane = @{ tierName = 'ControlPlane'; displayName = 'CP Group'; members = @() } }
                    pimRequestFlowExcludedRiskFlags    = $PimExcluded
                    accessPackageFlowExcludedRiskFlags = $AccessPackageExcluded
                })
            Write-TestDataFile "$Root/ClassificationExplorer/data/tier-map.js" 'EOCE_TIER_MAP' ([ordered]@{
                    roles = @(
                        @{ sys = 'EntraID'; roleId = $script:Roles.GlobalAdmin; roleClass = 'ControlPlane' }
                        @{ sys = 'EntraID'; roleId = $script:Roles.Helpdesk; roleClass = 'UserAccess' }
                        @{ sys = 'EntraID'; roleId = $script:Roles.Security; roleClass = 'ManagementPlane' }
                    )
                    paths = @(@{ sys = 'EntraID'; roleId = ''; tier = 'ManagementPlane'; action = 'microsoft.directory/groups/members/update'; service = 'Groups' })
                })
            $EamObject = { param($Id, $Upn, $Name, $Tier, $RoleAssignments = @()) [ordered]@{ objectId = $Id; objectType = 'user'; objectUserPrincipalName = $Upn; objectDisplayName = $Name; objectAdminTierLevelName = $Tier; classification = @(); roleAssignments = $RoleAssignments } }
            Write-TestDataFile "$Root/EamDashboard/data/eam-dashboard-data.js" 'ENTRAOPS_EAM_DATA' ([ordered]@{
                    objects         = @(
                        # The current assignment of the Management Plane custom role keeps it in the scope of the role setting rules.
                        & $EamObject $script:Users.ControlPlane 'cp.admin@contoso.com' 'CP Admin' 'ControlPlane' @(@{ roleDefinitionId = $script:Roles.Custom; classification = @(@{ adminTierLevelName = 'ManagementPlane'; service = 'Groups' }) })
                        & $EamObject $script:Users.ManagementPlane 'mp.admin@contoso.com' 'MP Admin' 'ManagementPlane' @(@{ roleDefinitionId = $script:Roles.Helpdesk; classification = @(@{ adminTierLevelName = 'UserAccess' }, @{ adminTierLevelName = 'ManagementPlane'; service = 'Groups' }) })
                        & $EamObject $script:Users.UserAccess 'ua.user@contoso.com' 'UA User' 'UserAccess'
                        # The target group of pk1, classified by its own role assignments.
                        [ordered]@{ objectId = $script:Groups.ControlPlane; objectType = 'group'; objectDisplayName = 'CP Group'; objectAdminTierLevelName = 'ControlPlane'; classification = @(); roleAssignments = @() }
                        & $EamObject $script:Users.ByName '' 'Approver By Name' 'ManagementPlane'
                        # A second object with the display name of the approver: the name no longer identifies one object.
                        if ($DuplicateApproverName) { & $EamObject (Get-TestId 5) '' 'Approver By Name' 'ControlPlane' }
                    )
                    roleDefinitions = @(@{ roleDefinitionId = $script:Roles.Security; tierName = 'ControlPlane'; service = 'Security' })
                })
            Write-TestDataFile "$Root/AccessPackageFlow/data/access-package-assignments-data.js" 'ENTRAOPS_ACCESSPACKAGE_ASSIGNMENTS' ([ordered]@{
                    policyRequestorApprovers = $(
                        $LiveApprovers = @{
                            pol2 = @{ accessPackageId = 'pk2'; approvers = @(@{}, @{ Id = $script:Groups.Approvers }) }
                            pol6 = @{ accessPackageId = 'pk2'; approvers = @(@{ id = $script:Groups.Approvers; description = 'Approvers' }) }
                        }
                        # The live object ID of a single user that the snapshot names by user principal name.
                        if ($UnprivilegedApprover) { $LiveApprovers.pol4 = @{ accessPackageId = 'pk1'; approvers = @(@{ id = $script:Users.Unknown; description = 'Unknown User' }) } }
                        $LiveApprovers
                    )
                    packages                 = $(
                        $LivePackages = @{ pk2 = @{ displayName = 'MP Access'; targets = @(@{ originId = $script:Groups.ManagementPlane; tierName = 'ManagementPlane' }) } }
                        if ($RoleLessTargets) {
                            $NotClassified = "Group 'Root' is not classified in any RBAC system (Azure, EntraID, DeviceManagement)"
                            $LivePackages.pk4 = @{ displayName = 'Exclusion Access'; targets = @(
                                    @{ originId = $script:Groups.Declared; displayName = 'Declared Group'; originSystem = 'AadGroup'; tierName = 'UserAccess'; classificationReason = $NotClassified }
                                    @{ originId = $script:Groups.Unclassified; displayName = 'CA Exclusion Group'; originSystem = 'AadGroup'; tierName = 'UserAccess'; classificationReason = $NotClassified }
                                ) }
                        }
                        $LivePackages
                    )
                    objectClassifications    = $(if ($RoleLessTargets) { @{ $script:Groups.Declared = @{ tierName = 'ManagementPlane'; justification = 'Landing zone 01' } } } else { @{} })
                    # The target group of pk2 has a Control Plane member: the roll-up must not raise the tier of the target.
                    resolvedGroupTiers       = @{
                        # One regular member: an approver group without members is not compared (nobody can approve).
                        $script:Groups.Approvers       = @{ tierName = 'UserAccess'; displayName = 'Approvers'; members = @(@{ id = (Get-TestId 6); displayName = 'Regular User'; objectType = 'user' }); totalMembers = 1 }
                        $script:Groups.ManagementPlane = @{ tierName = 'ControlPlane'; displayName = 'MP Group'; members = @(@{ id = $script:Users.ControlPlane; displayName = 'CP Admin'; tierName = 'ControlPlane'; objectType = 'user' }) }
                        # A group without role assignments with a Control Plane member: the member does not classify it.
                        $script:Groups.Unclassified    = @{ tierName = 'ControlPlane'; displayName = 'CA Exclusion Group'; members = @(@{ id = $script:Users.ControlPlane; displayName = 'CP Admin'; tierName = 'ControlPlane'; objectType = 'user' }) }
                    }
                    assignments              = @(
                        @{ accessPackageId = 'pk1'; assignmentPolicyId = 'pol4'; target = @{ objectId = $script:Users.ControlPlane } }
                        @{ accessPackageId = 'pk1'; assignmentPolicyId = 'pol5'; target = @{ objectId = $script:Users.ControlPlane } }
                        @{ accessPackageId = 'pk1'; assignmentPolicyId = 'pol4'; state = 'Expired'; target = @{ objectId = $script:Users.ManagementPlane } }
                        @{ accessPackageId = 'pk1'; target = @{ objectId = $script:Users.ByName } }
                    )
                    # The Control Plane group of pk1 has drift; the drift of a group without access package is not evaluated.
                    accessDrift              = $(switch ($AccessDrift) {
                            'collected' {
                                @{ status = 'collected'; reason = ''; resources = @(
                                        @{ id = 'd1'; resourceId = $script:Groups.ControlPlane; resourceName = 'CP Group'; resourceType = 'group'; catalogId = 'cat1'; catalogName = 'Tier0 Catalog'; total = 3; unauthorized = 2; missing = 1; createdDateTime = '2026-10-26T03:15:42Z'
                                            details = @(@{ driftType = 'unauthorized'; assignedRole = 'Member'; expectedRole = 'None'; accessPackageId = 'pk1'; accessPackageName = 'CP Access'; identities = @(@{ id = $script:Users.UserAccess; principalName = 'ua.user@contoso.com'; displayName = 'UA User'; identityType = 'user' }) })
                                        }
                                        @{ id = 'd2'; resourceId = (Get-TestId 299); resourceName = 'Other Group'; resourceType = 'group'; catalogId = 'cat1'; catalogName = 'Tier0 Catalog'; total = 1; unauthorized = 1; missing = 0; createdDateTime = '2026-10-26T03:15:42Z'; details = @() }
                                    ) }
                            }
                            'unavailable' { @{ status = 'unavailable'; reason = 'Forbidden.'; resources = @() } }
                            default { $null }
                        })
                })
            $Root
        }
    }

    It 'skips the rules with a reason when the report data is missing' {
        $Results = @(Invoke-EntraOpsFindingEvaluation -Area PimRequestFlow, AccessPackageFlow -ReportPath (Join-Path $TestDrive 'missing'))

        $Results.Count | Should -Be 16
        $Results.Status | Select-Object -Unique | Should -Be 'Skipped'
        $Results[0].Reason | Should -Match 'New-EntraOpsReportingData'
    }

    It 'skips the rules with a reason when no snapshot has embedded content' {
        $Root = New-TestReportData -Root (Join-Path $TestDrive 'nodetail') -NoDetail
        $Results = @(Invoke-EntraOpsFindingEvaluation -Area PimRequestFlow -ReportPath $Root)

        $Results.Status | Select-Object -Unique | Should -Be 'Skipped'
        $Results[0].Reason | Should -Match 'no Tenant Governance snapshot'
    }

    It 'evaluates the PIM role settings of the newest snapshot like the report' {
        $Root = New-TestReportData -Root (Join-Path $TestDrive 'pim')
        $Results = @(Invoke-EntraOpsFindingEvaluation -Area PimRequestFlow -ReportPath $Root)
        $ByKey = @{}; foreach ($Result in $Results) { $ByKey[$Result.Key] = $Result }

        # Global Administrator (tier map: Control Plane) and the custom role (role action: Management Plane).
        @($ByKey.noMfaActivation.Results.Instance.DisplayName | Sort-Object) | Should -Be @('Custom Role', 'Global Administrator')
        $ByKey.noMfaActivation.Results[0].Instance.Id | Should -Match '\.activation$'
        ($ByKey.noMfaActivation.Results | Where-Object { $_.Instance.ObjectId -eq $script:Roles.Custom }).Message | Should -Be "The Management Plane role 'Custom Role' can be activated without MFA or an authentication context."
        $ByKey.permanentEligible.Results.Instance.DisplayName | Should -Be 'Global Administrator'
        $ByKey.approverNotEnforced.Results.Instance.DisplayName | Should -Be 'Global Administrator'
        # Helpdesk: assignment evidence makes it Management Plane, the User Access approver is lower; the
        # approver found by display name is not, the unknown approver is unresolved.
        $Messages = @($ByKey.approverLowerTier.Results.Message | Sort-Object { $_ -replace '^.*: ', '' })
        $Messages.Count | Should -Be 2
        # The messages name the role and its tier, and the approver with its tier.
        $Messages[0] | Should -BeLike "The Control Plane role '*' is approved by approver(s) classified at a lower tier: MP Admin (mp.admin@contoso.com), classified as Management Plane."
        $Messages[1] | Should -BeLike "The * role '*' is approved by approver(s) classified at a lower tier: UA User (ua.user@contoso.com), classified as User Access."
        $ByKey.approverUnclassified.Results.Message | Should -BeLike "1 approver(s) of the * role '*' could not be resolved against the Privileged EAM data, so their tier is not compared: '*'."
        $ByKey.authContextMissing.Results.Instance.DisplayName | Should -Be 'Helpdesk Administrator'
        $ByKey.noMfaActivation.Results[0].Evidence.SnapshotKey | Should -Be 'cccccccc|2026-10-20T10:00:00.0000000+00:00'
        $ByKey.permanentActive.Status | Should -Be 'Passed'
    }

    It 'names the approvers of a PIM role that could not be resolved in the reason of EO.1008' {
        $Root = New-TestReportData -Root (Join-Path $TestDrive 'pim-unresolved')
        $Result = Invoke-EntraOpsFindingEvaluation -Area PimRequestFlow -ReportPath $Root -ConfigFilePath (Join-Path $TestDrive 'none.json') | Where-Object Key -eq 'approverLowerTier'
        $Result.RuleId | Should -Be 'EO.1008'
        $Result.ReasonCode | Should -Be 'Note'
        $Result.Reason | Should -Be "1 approver(s) of the role 'Helpdesk Administrator' could not be resolved against the Privileged EAM data and are not evaluated: Unknown Approvers."

        # A pass with an approver that was not compared says so.
        $Passed = & (Get-Module EntraOps) {
            $Flow = [pscustomobject]@{
                id = 'r1|activation'; path = 'activation'; roleId = 'r1'; roleName = 'CP Role'; roleTier = 'ControlPlane'; p = @{ ActivationReqMFA = $true; ApprovaltoActivate = $true; ActivateApprover = @('a', 'b') }
                approvers = @([pscustomobject]@{ label = 'CP Admin'; tier = 'ControlPlane'; resolved = $true; source = 'direct' }, [pscustomobject]@{ label = 'unknown@contoso.com'; tier = 'UserAccess'; resolved = $false; source = 'default' })
                checks = $null
            }
            $Flow.checks = Get-EntraOpsPimRequestFlowFlag -Flow $Flow
            Invoke-EntraOpsFindingRuleSet -Context ([pscustomobject]@{ Area = 'PimRequestFlow'; SnapshotKey = 'k'; Flows = @($Flow) }) | Where-Object Key -eq 'approverLowerTier'
        }
        $Passed.Status | Should -Be 'Passed'
        $Passed.ReasonCode | Should -Be 'Note'
        $Passed.Reason | Should -BeLike "1 approver(s) of the role 'CP Role' could not be resolved*are not evaluated: unknown@contoso.com."
    }

    It 'compares a PIM approver named by a user principal name outside the Privileged EAM data as User Access' {
        $Root = New-TestReportData -Root (Join-Path $TestDrive 'pim-unprivileged') -UnprivilegedApprover
        $ByKey = @{}; foreach ($Result in Invoke-EntraOpsFindingEvaluation -Area PimRequestFlow -ReportPath $Root -ConfigFilePath (Join-Path $TestDrive 'none.json')) { $ByKey[$Result.Key] = $Result }

        # A user without privileged access (also a guest) can approve the role: compared, not unresolved.
        ($ByKey.approverLowerTier.Results | Where-Object { $_.Instance.ObjectId -eq $script:Roles.Helpdesk }).Message | Should -BeLike "*unknown@contoso.com, without privileged access (User Access)."
        @($ByKey.approverUnclassified.Results | Where-Object { $_.Message -like '*unknown@contoso.com*' }).Count | Should -Be 0
    }

    It 'rates an access package target by its access without delegated permissions' {
        $Root = New-TestReportData -Root (Join-Path $TestDrive 'delegated-target')
        $EamPath = "$Root/EamDashboard/data/eam-dashboard-data.js"
        $Raw = Get-Content -LiteralPath $EamPath -Raw
        $Eam = $Raw.Substring($Raw.IndexOf('=') + 1).Trim().TrimEnd(';') | ConvertFrom-Json -AsHashtable
        # A consent client with a delegated Control Plane permission only, and an application with an application permission.
        $Eam.objects += [ordered]@{ objectId = (Get-TestId 301); objectType = 'serviceprincipal'; objectDisplayName = 'Consent Client'; objectAdminTierLevelName = 'Unclassified'; classification = @(@{ adminTierLevelName = 'ControlPlane' }); roleAssignments = @(@{ roleType = 'Delegated'; classification = @(@{ adminTierLevelName = 'ControlPlane' }) }) }
        $Eam.objects += [ordered]@{ objectId = (Get-TestId 302); objectType = 'serviceprincipal'; objectDisplayName = 'Daemon'; objectAdminTierLevelName = 'Unclassified'; classification = @(); roleAssignments = @(@{ roleType = 'Application'; classification = @(@{ adminTierLevelName = 'ControlPlane' }) }, @{ roleType = 'Delegated'; classification = @(@{ adminTierLevelName = 'ManagementPlane' }) }) }
        Write-TestDataFile $EamPath 'ENTRAOPS_EAM_DATA' $Eam

        $Index = & (Get-Module EntraOps) { param($ReportPath) (Import-EntraOpsReportFindingData -ReportPath $ReportPath).ObjectTierIndex } $Root
        # The tier of the object counts its delegated permissions; the access it grants as a target does not.
        $Index[(Get-TestId 301).ToUpperInvariant()].tierName | Should -Be 'ControlPlane'
        $Index[(Get-TestId 301).ToUpperInvariant()].accessTierName | Should -Be 'UserAccess'
        $Index[(Get-TestId 302).ToUpperInvariant()].accessTierName | Should -Be 'ControlPlane'
    }

    It 'resolves access package approvers that the snapshot names by user principal name, and compares users outside the Privileged EAM data as User Access' {
        $Root = New-TestReportData -Root (Join-Path $TestDrive 'accesspackage-unprivileged') -UnprivilegedApprover
        $ByKey = @{}; foreach ($Result in Invoke-EntraOpsFindingEvaluation -Area AccessPackageFlow -ReportPath $Root -ConfigFilePath (Join-Path $TestDrive 'none.json')) { $ByKey[$Result.Key] = $Result }

        # pol4: the user principal name of the snapshot takes the live object ID; the user is not in the EAM data.
        ($ByKey.approverLowerTier.Results | Where-Object { $_.Instance.ObjectId -eq 'pol4' }).Message | Should -BeLike 'Approver(s) are classified at a lower privilege tier (User Access) than the resource being granted (Control Plane): User: Unknown User.'
        # pol5: the user principal name resolves to the classified user of the EAM data.
        ($ByKey.approverLowerTier.Results | Where-Object { $_.Instance.ObjectId -eq 'pol5' }).Message | Should -BeLike '*: User: UA User.'
        $ByKey.approverLowerTier.Reason | Should -Not -BeLike '*could not be resolved*'
    }

    It 'does not resolve a PIM approver by a display name that several objects have' {
        $Root = New-TestReportData -Root (Join-Path $TestDrive 'pim-ambiguous') -DuplicateApproverName
        $ByKey = @{}; foreach ($Result in Invoke-EntraOpsFindingEvaluation -Area PimRequestFlow -ReportPath $Root -ConfigFilePath (Join-Path $TestDrive 'none.json')) { $ByKey[$Result.Key] = $Result }

        # Neither the Management Plane nor the Control Plane object is taken: the approver is unresolved.
        $ByKey.approverUnclassified.Results.Message | Should -BeLike "2 approver(s) of the * role 'Helpdesk Administrator' could not be resolved*: 'Approver By Name (display name of several objects)', 'Unknown Approvers'."
        $ByKey.approverLowerTier.Reason | Should -BeLike "2 approver(s) of the role 'Helpdesk Administrator' could not be resolved*are not evaluated: Approver By Name (display name of several objects), Unknown Approvers."
        $Approver = @($ByKey.approverLowerTier.Results.Evidence.Approvers | Where-Object { $_.Label -like 'Approver By Name*' })[0]
        $Approver.Resolved | Should -BeFalse
        $Approver.Tier | Should -Be 'UserAccess'
    }

    It 'skips the rules for privileged PIM roles when the datasets with the role tiers are missing' {
        $Root = New-TestReportData -Root (Join-Path $TestDrive 'pim-no-tiers')
        Remove-Item -LiteralPath "$Root/ClassificationExplorer/data/tier-map.js", "$Root/EamDashboard/data/eam-dashboard-data.js"
        $ByKey = @{}; foreach ($Result in Invoke-EntraOpsFindingEvaluation -Area PimRequestFlow -ReportPath $Root -ConfigFilePath (Join-Path $TestDrive 'none.json')) { $ByKey[$Result.Key] = $Result }

        foreach ($Key in 'noMfaActivation', 'noApprovalActivation', 'approverLowerTier', 'approverUnclassified', 'permanentEligible', 'permanentActive', 'noMfaActiveAssign') {
            $ByKey[$Key].Status | Should -Be 'Skipped'
            $ByKey[$Key].ReasonCode | Should -Be 'MissingData'
            $ByKey[$Key].Reason | Should -Be 'None of the PIM role settings has a tier, because the report data has no Classification Explorer data (New-EntraOpsClassificationExplorerData) and no EAM Dashboard data (New-EntraOpsPrivilegedEamDashboardData). Generate the report data with New-EntraOpsReportingData.'
        }
        # Rules that do not depend on the role tier are evaluated.
        $ByKey.approverNotEnforced.Status | Should -Be 'Failed'
    }

    It 'excludes the risk flags excluded in the configuration' {
        $Root = New-TestReportData -Root (Join-Path $TestDrive 'excluded')
        $ConfigFile = Join-Path $TestDrive 'excluded.json'
        # Findings.ExcludedRules, and the deprecated risk-flag settings of EntraOps 1.1.0.
        @{ Findings = @{ ExcludedRules = @('AccessPackageFlow.broadRequestor') }; ConfigurationAnalyzer = @{ PimRequestFlowExcludedRiskFlags = @('noMfaActivation') } } | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $ConfigFile
        $Results = @(Invoke-EntraOpsFindingEvaluation -Area PimRequestFlow, AccessPackageFlow -ReportPath $Root -ConfigFilePath $ConfigFile -WarningVariable Warnings -WarningAction SilentlyContinue)

        ($Results | Where-Object { $_.Area -eq 'PimRequestFlow' -and $_.Key -eq 'noMfaActivation' }).Status | Should -Be 'Excluded'
        ($Results | Where-Object { $_.Area -eq 'AccessPackageFlow' -and $_.Key -eq 'broadRequestor' }).Status | Should -Be 'Excluded'
        ($Results | Where-Object { $_.Area -eq 'AccessPackageFlow' -and $_.Key -eq 'noApproval' }).Status | Should -Be 'Failed'
        @($Warnings | Where-Object { "$_" -like 'ConfigurationAnalyzer.PimRequestFlowExcludedRiskFlags is deprecated*PimRequestFlow.noMfaActivation*' }).Count | Should -Be 1
    }

    It 'ignores the excluded risk flags that older versions embedded in the Configuration Analyzer data' {
        # The data still lists the flags after they were removed from EntraOpsConfig.json.
        $Root = New-TestReportData -Root (Join-Path $TestDrive 'stale') -PimExcluded 'noMfaActivation' -AccessPackageExcluded 'broadRequestor'
        $Results = @(Invoke-EntraOpsFindingEvaluation -Area PimRequestFlow, AccessPackageFlow -ReportPath $Root -ConfigFilePath (Join-Path $TestDrive 'none.json'))
        ($Results | Where-Object { $_.Area -eq 'PimRequestFlow' -and $_.Key -eq 'noMfaActivation' }).Status | Should -Be 'Failed'
        ($Results | Where-Object { $_.Area -eq 'AccessPackageFlow' -and $_.Key -eq 'broadRequestor' }).Status | Should -Be 'Failed'

        New-EntraOpsReportFindingData -ReportPath $Root -ConfigFilePath (Join-Path $TestDrive 'none.json') 6> $null
        $Content = Get-Content -LiteralPath "$Root/PimRequestFlow/data/pim-request-flow-findings.js" -Raw
        $Pim = $Content.Substring($Content.IndexOf('=') + 1).TrimEnd().TrimEnd(';') | ConvertFrom-Json -AsHashtable -DateKind String
        @($Pim.snapshots['cccccccc|2026-10-20T10:00:00.0000000+00:00'].flags["$($script:Roles.GlobalAdmin)|activation"].id) | Should -Contain 'noMfaActivation'
    }

    It 'evaluates a flow id only once, like the report' {
        $Root = New-TestReportData -Root (Join-Path $TestDrive 'duplicate') -DuplicateRoleSetting
        $Results = @(Invoke-EntraOpsFindingEvaluation -Area PimRequestFlow -ReportPath $Root -ConfigFilePath (Join-Path $TestDrive 'none.json'))
        $NoMfa = $Results | Where-Object Key -eq 'noMfaActivation'

        # The privileged roles Global Administrator, Helpdesk, the custom role and Security Administrator; the copy of
        # Global Administrator (same flow id) is ignored.
        $NoMfa.EvaluatedCount | Should -Be 4
        $NoMfa.FailedCount | Should -Be 2
        @($NoMfa.Results.Instance.Id | Select-Object -Unique).Count | Should -Be $NoMfa.FailedCount
        $NoMfa.Results.Instance.Id | Should -Not -Match '-2$'
    }

    It 'evaluates the access package assignment policies of the newest snapshot like the report' {
        $Root = New-TestReportData -Root (Join-Path $TestDrive 'accesspackage')
        $Results = @(Invoke-EntraOpsFindingEvaluation -Area AccessPackageFlow -ReportPath $Root)
        $ByKey = @{}; foreach ($Result in $Results) { $ByKey[$Result.Key] = $Result }

        # The policy references its package by display name; the group target resolves to Control Plane.
        $ByKey.noApproval.Results.Instance.ObjectId | Should -Be 'pol1'
        $ByKey.broadRequestor.Results.Instance.ObjectId | Should -Be 'pol1'
        $ByKey.noApproval.EvaluatedCount | Should -Be 5
        # Live targets and the live group approver (matched by position) of pol2.
        ($ByKey.approverLowerTier.Results | Where-Object { $_.Instance.ObjectId -eq 'pol2' }).Message | Should -BeLike 'Approver(s) are classified at a lower privilege tier (User Access) than the resource being granted (Management Plane): *.'
        # A single live approver (lower-case id) is matched like several.
        ($ByKey.approverLowerTier.Results | Where-Object { $_.Instance.ObjectId -eq 'pol6' }).Message | Should -BeLike 'Approver(s) are classified at a lower privilege tier (User Access) than the resource being granted (Management Plane): *.'
        # Only resolved approvers are compared with the assigned principals: pol4 has only an unresolved
        # approver, pol5 also a User Access approver. The expired assignment and the assignment without
        # policy (several policies on the package) are ignored.
        $ByKey.assignedMorePrivileged.Results.Message | Should -Be "Currently assigned principal(s) have a higher privilege tier (the more privileged of their classification and their access) than this policy's approver(s) are protected for (User Access: User: UA User): CP Admin."
        $ByKey.assignedMorePrivileged.Results.Instance.DisplayName | Should -Be 'CP Access / User Access approver'
        # pol4 has no resolved approver: it is not evaluated, the reason names it.
        $ByKey.assignedMorePrivileged.EvaluatedCount | Should -Be 3
        $ByKey.assignedMorePrivileged.Reason | Should -BeLike '1 assignment policy with approval has no approver resolved against the Privileged EAM data and was not evaluated.*'
        $ByKey.approverLowerTier.Reason | Should -BeLike '1 assignment policy with approval has no approver resolved*'
        # pol5 is compared by its resolved User Access approver: the reason names the approver that was not compared.
        foreach ($Key in 'approverLowerTier', 'assignedMorePrivileged') {
            $ByKey[$Key].Reason | Should -BeLike "* 1 approver(s) of the policy 'CP Access / User Access approver' could not be resolved against the Privileged EAM data and are not evaluated: Members of group ($($script:Groups.Unknown))."
        }
    }

    It 'derives the approval tier of an access package policy from the protection tier of its approvers' {
        $Tiers = & (Get-Module EntraOps) {
            $Approver = { param($Tier, $Stage, $ProtectionTier = $null, $Resolved = $true) [pscustomobject]@{ label = "$Tier$Stage"; tier = $Tier; protectionTier = $ProtectionTier; resolved = $Resolved; stage = $Stage } }
            # A group of a Control Plane and a Management Plane member: protected like its least protected member.
            Get-EntraOpsAccessPackageFlowApprovalTier -Flow ([pscustomobject]@{ approvers = @(& $Approver 'ControlPlane' 0 'ManagementPlane') })
            # Any approver of a stage can approve: the stage is as weak as its least protected approver.
            Get-EntraOpsAccessPackageFlowApprovalTier -Flow ([pscustomobject]@{ approvers = @((& $Approver 'ControlPlane' 0), (& $Approver 'UserAccess' 0)) })
            # Every stage has to approve: the approval is as strong as its strongest stage.
            Get-EntraOpsAccessPackageFlowApprovalTier -Flow ([pscustomobject]@{ approvers = @((& $Approver 'UserAccess' 0), (& $Approver 'ControlPlane' 1)) })
            # Unresolved approvers are not compared.
            "$(Get-EntraOpsAccessPackageFlowApprovalTier -Flow ([pscustomobject]@{ approvers = @(& $Approver 'UserAccess' 0 $null $false) }))"
        }
        $Tiers | Should -Be @('ManagementPlane', 'UserAccess', 'ControlPlane', '')
    }

    It 'notes a passed access package policy that mixes resolved and unresolved approvers (EO.1009, EO.1010)' {
        $Results = & (Get-Module EntraOps) {
            $Approver = { param($Label, $Tier, $Resolved) [pscustomobject]@{ label = $Label; tier = $Tier; resolved = $Resolved; source = 'direct'; stage = 0 } }
            # The unresolved approver of the stage can approve alone, but only the Control Plane approver is compared.
            $Flow = [pscustomobject]@{
                id = 'pol1'; name = 'Mixed'; accessPackageId = 'pk1'; accessPackageName = 'CP Access'; scopeType = 'SpecificDirectorySubjects'; acceptsRequests = $true; isApprovalRequired = $true
                approvers = @((& $Approver 'User: CP Admin' 'ControlPlane' $true), (& $Approver 'User (11111111-1111-1111-1111-111111111111)' 'UserAccess' $false))
                assignedPrincipals = @([pscustomobject]@{ name = 'CP Admin'; tierName = 'ControlPlane'; resolved = $true; source = 'direct' })
                targets = @([pscustomobject]@{ tier = 'ControlPlane'; drift = $null }); checks = $null
            }
            $Flow.checks = Get-EntraOpsAccessPackageFlowFlag -Flow $Flow
            Invoke-EntraOpsFindingRuleSet -Context ([pscustomobject]@{ Area = 'AccessPackageFlow'; SnapshotKey = 'k'; Flows = @($Flow); HasAssignments = $true; AccessDrift = [pscustomobject]@{ Status = 'missing' } })
        }
        foreach ($RuleId in 'EO.1009', 'EO.1010') {
            $Result = $Results | Where-Object RuleId -eq $RuleId
            $Result.Status | Should -Be 'Passed'
            $Result.ReasonCode | Should -Be 'Note'
            $Result.Reason | Should -Be "1 approver(s) of the policy 'CP Access / Mixed' could not be resolved against the Privileged EAM data and are not evaluated: User (11111111-1111-1111-1111-111111111111)."
        }
    }

    It 'classifies an access package target group without role assignments by the Object Classification File only' {
        $Root = New-TestReportData -Root (Join-Path $TestDrive 'roleless') -RoleLessTargets
        $Context = & (Get-Module EntraOps) { param($Root) New-EntraOpsAccessPackageFlowFindingContext -ReportData (Import-EntraOpsReportFindingData -ReportPath $Root) } $Root
        $Targets = @($Context.Packages['pk4'].targets)
        # Declared: the tier and justification of the file, not the User Access default of the scope classification.
        $Targets[0].resourceName | Should -Be 'Declared Group'
        $Targets[0].tier | Should -Be 'ManagementPlane'
        $Targets[0].source | Should -Be 'objectClassification'
        $Targets[0].reason | Should -Be 'Landing zone 01'
        # Not declared: unclassified, although a Control Plane admin is a member.
        $Targets[1].resourceName | Should -Be 'CA Exclusion Group'
        $Targets[1].tier | Should -BeNullOrEmpty
        $Targets[1].source | Should -Be 'unclassified'
        # A group with a privileged scope classification and the directly classified group keep their tiers.
        $Context.Packages['pk2'].targets[0].source | Should -Be 'scopeClassification'
        $Context.Packages['pk1'].targets[0].source | Should -Be 'direct'

        $Flow = @($Context.Flows | Where-Object id -eq 'pol8')[0]
        $Flow.checks.unclassifiedTarget.Failed | Should -BeTrue
        $Flow.checks.unclassifiedTarget.Text | Should -Be 'EntraOps cannot classify the target group of this access package: CA Exclusion Group. It has no role assignment and no tier from the Alternate Tier Level Attributes or the Object Classification File, so the tier of the access the membership grants is unknown.'
        # The declared Management Plane group still makes the broad requestor scope a finding.
        $Flow.checks.broadRequestor.Text | Should -Be 'Any directory member can request a Management Plane resource (AllExistingDirectoryMemberUsers).'
        # Policies without a target group lacking role assignments are not in the scope of the check.
        @($Context.Flows | Where-Object { $_.id -ne 'pol8' -and $_.checks.unclassifiedTarget.Applies }).Count | Should -Be 0

        $Rule = @(Invoke-EntraOpsFindingEvaluation -Area AccessPackageFlow -ReportPath $Root -ConfigFilePath (Join-Path $TestDrive 'none.json') | Where-Object Key -eq 'unclassifiedTarget')[0]
        $Rule.RuleId | Should -Be 'EO.2005'
        $Rule.Status | Should -Be 'Failed'
        $Rule.EvaluatedCount | Should -Be 2
        $Rule.Results.Instance.ObjectId | Should -Be $script:Groups.Unclassified
        $Rule.Results.Message | Should -Be "'CA Exclusion Group' has no role assignment and no tier from the Alternate Tier Level Attributes or the Object Classification File: the tier of the access its membership grants is unknown. Access package(s): Exclusion Access."

        New-EntraOpsReportFindingData -ReportPath $Root -ConfigFilePath (Join-Path $TestDrive 'none.json') 6> $null
        $Content = Get-Content -LiteralPath "$Root/AccessPackageFlow/data/access-package-flow-findings.js" -Raw
        $Latest = ($Content.Substring($Content.IndexOf('=') + 1).TrimEnd().TrimEnd(';') | ConvertFrom-Json -AsHashtable -DateKind String).snapshots['cccccccc|2026-10-20T10:00:00.0000000+00:00']
        $Flag = @($Latest.flags.pol8 | Where-Object { $_.id -eq 'unclassifiedTarget' })[0]
        $Flag.severity | Should -Be 'info'
        $Flag.ruleId | Should -Be 'EO.2005'
        $Latest.packages.pk4.targets[0] | ConvertTo-Json -Compress | Should -Be '{"resourceName":"Declared Group","tier":"ManagementPlane","reason":"Landing zone 01","declaredBy":"Object Classification File","source":"objectClassification"}'
        $Latest.packages.pk4.targets[1] | ConvertTo-Json -Compress | Should -Be '{"resourceName":"CA Exclusion Group","source":"unclassified"}'
    }

    It 'accepts the unclassified target flag of a policy by an exception for the group' {
        $Root = New-TestReportData -Root (Join-Path $TestDrive 'rolelessexception') -RoleLessTargets
        $Folder = Join-Path $TestDrive 'rolelessexception-config'
        New-Item -ItemType Directory -Path $Folder -Force | Out-Null
        @{ Findings = @{ ExceptionsFilePath = './exceptions.json' } } | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath "$Folder/EntraOpsConfig.json"
        ConvertTo-Json -Depth 5 -InputObject @([ordered]@{ RuleId = 'EO.2005'; ObjectId = $script:Groups.Unclassified; State = 'Dismissed'; Justification = 'Classified with the next ServiceEM run' }) | Set-Content -LiteralPath "$Folder/exceptions.json"
        New-EntraOpsReportFindingData -ReportPath $Root -ConfigFilePath "$Folder/EntraOpsConfig.json" 6> $null

        $Content = Get-Content -LiteralPath "$Root/AccessPackageFlow/data/access-package-flow-findings.js" -Raw
        $Latest = ($Content.Substring($Content.IndexOf('=') + 1).TrimEnd().TrimEnd(';') | ConvertFrom-Json -AsHashtable -DateKind String).snapshots['cccccccc|2026-10-20T10:00:00.0000000+00:00']
        @($Latest.flags.pol8.id) | Should -Not -Contain 'unclassifiedTarget'
        @($Latest.accepted.pol8.id) | Should -Be @('unclassifiedTarget')
    }

    It 'keeps an approver in every approval stage it approves in' {
        $Root = New-TestReportData -Root (Join-Path $TestDrive 'multistage') -MultiStage
        $Context = & (Get-Module EntraOps) { param($Root) New-EntraOpsAccessPackageFlowFindingContext -ReportData (Import-EntraOpsReportFindingData -ReportPath $Root) } $Root
        $Flow = @($Context.Flows | Where-Object id -eq 'pol9')[0]
        @($Flow.approvers | ForEach-Object { "$($_.stage):$($_.label)" }) | Should -Be @('0:User: UA User', '1:User: UA User', '1:User: CP Admin')
        # Both stages are as weak as the User Access user: the approval is User Access, below the Control Plane target.
        $Flow.approvalTier | Should -Be 'UserAccess'
        $Flow.checks.approverLowerTier.Failed | Should -BeTrue
    }

    It 'does not compare the approvers of a policy whose target tier is unknown' {
        $Flow = [pscustomobject]@{
            isApprovalRequired = $true; scopeType = 'SpecificDirectorySubjects'; assignedPrincipals = @()
            approvers = @([pscustomobject]@{ label = 'User: UA User'; tier = 'UserAccess'; resolved = $true; stage = 0 })
            targets = @([pscustomobject]@{ resourceName = 'CA Exclusion Group'; tier = $null; source = 'unclassified'; originId = 'g1' })
        }
        $Checks = & (Get-Module EntraOps) { param($Flow) Get-EntraOpsAccessPackageFlowFlag -Flow $Flow } $Flow
        $Checks.approverLowerTier.Applies | Should -BeFalse
        $Checks.unclassifiedTarget.Failed | Should -BeTrue
    }

    It 'treats a group approver without member data as unresolved' {
        $ReportData = [pscustomobject]@{
            ResolvedGroupTierIndex = [System.Collections.Generic.Dictionary[string, object]]::new()
            AssignmentResolvedGroupTierIndex = [System.Collections.Generic.Dictionary[string, object]]::new()
        }
        $GroupHit = [pscustomobject]@{ objectId = 'g1'; objectType = 'group'; tierName = 'ControlPlane'; members = $null }
        & (Get-Module EntraOps) { param($ReportData, $Hit) Test-EntraOpsGroupApproverWithoutMemberData -ReportData $ReportData -Id 'g1' -Hit $Hit } $ReportData $GroupHit | Should -BeTrue
        # A member list is member data (an empty one is not: see AccessPackageFlowApproverEdgeCases.Tests.ps1).
        $ReportData.ResolvedGroupTierIndex['G1'] = [pscustomobject]@{ members = @(@{ id = 'u1' }); totalMembers = 1 }
        & (Get-Module EntraOps) { param($ReportData, $Hit) Test-EntraOpsGroupApproverWithoutMemberData -ReportData $ReportData -Id 'g1' -Hit $Hit } $ReportData $GroupHit | Should -BeFalse
    }

    It 'skips the unclassified target rule without the EAM Dashboard data' {
        $Result = & (Get-Module EntraOps) { Get-EntraOpsAccessPackageFlowUnclassifiedEvaluation -Context ([pscustomobject]@{ Flows = @(); HasEamData = $false; SnapshotKey = 'k' }) }
        $Result.SkipReason | Should -Match 'No EAM Dashboard data'
    }

    It 'evaluates the unauthorized and missing access of the privileged access package resources' {
        $Root = New-TestReportData -Root (Join-Path $TestDrive 'drift')
        $Results = @(Invoke-EntraOpsFindingEvaluation -Area AccessPackageFlow -ReportPath $Root -ConfigFilePath (Join-Path $TestDrive 'none.json'))

        # The Control Plane group of pk1 and the Management Plane group of pk2 (live data) are evaluated.
        $Unauthorized = $Results | Where-Object Key -eq 'unauthorizedAccess'
        $Unauthorized.RuleId | Should -Be 'EO.6003'
        $Unauthorized.Status | Should -Be 'Failed'
        $Unauthorized.EvaluatedCount | Should -Be 2
        $Unauthorized.Results.Instance.DisplayName | Should -Be 'CP Group'
        $Unauthorized.Results.Instance.ObjectType | Should -Be 'group'
        $Unauthorized.Results.Message | Should -Be "'CP Group' (Control Plane) has 2 member(s) or app role assignment(s) without an access package assignment as of 2026-10-26. Access package(s): CP Access."
        $Unauthorized.Results.Evidence.Examples[0].Identity | Should -Be 'ua.user@contoso.com'
        $Unauthorized.Results.Evidence.MoreExamples | Should -BeTrue

        $Missing = $Results | Where-Object Key -eq 'missingAccess'
        $Missing.RuleId | Should -Be 'EO.6004'
        $Missing.Status | Should -Be 'Failed'
        $Missing.Results.Message | Should -Be "'CP Group' (Control Plane) misses the membership or app role assignment of 1 access package assignment(s) as of 2026-10-26. Access package(s): CP Access."
        @($Missing.Results.Evidence.Examples).Count | Should -Be 0 -Because 'the only example of the drift report is unauthorized access'

        New-EntraOpsReportFindingData -ReportPath $Root -ConfigFilePath (Join-Path $TestDrive 'none.json') 6> $null
        $Content = Get-Content -LiteralPath "$Root/AccessPackageFlow/data/access-package-flow-findings.js" -Raw
        $Flags = ($Content.Substring($Content.IndexOf('=') + 1).TrimEnd().TrimEnd(';') | ConvertFrom-Json -AsHashtable -DateKind String).snapshots['cccccccc|2026-10-20T10:00:00.0000000+00:00'].flags
        foreach ($PolicyId in 'pol1', 'pol4', 'pol5') {
            $Flag = @($Flags[$PolicyId] | Where-Object { $_.id -eq 'unauthorizedAccess' })[0]
            $Flag.severity | Should -Be 'fail'
            $Flag.text | Should -Be 'Members or app role assignments without an access package assignment on a Control Plane / Management Plane resource of this access package as of 2026-10-26 - CP Group (Control Plane): 2 (Access Guardian > Access Drift).'
            $Flag = @($Flags[$PolicyId] | Where-Object { $_.id -eq 'missingAccess' })[0]
            $Flag.severity | Should -Be 'warn'
            $Flag.text | Should -Be 'Access package assignments without the membership or app role assignment on a Control Plane / Management Plane resource of this access package as of 2026-10-26 - CP Group (Control Plane): 1 (Access Guardian > Access Drift).'
        }
        @($Flags['pol2'] | Where-Object { $_.id -in 'unauthorizedAccess', 'missingAccess' }).Count | Should -Be 0
    }

    It 'keeps the drift of every catalog of a resource that access packages of several catalogs grant' {
        # pk1 (catalog cat2, without drift) is evaluated first; pk3 of catalog cat1 has the drift of the group.
        $Root = New-TestReportData -Root (Join-Path $TestDrive 'sharedresource') -SharedResource
        $Results = @(Invoke-EntraOpsFindingEvaluation -Area AccessPackageFlow -ReportPath $Root -ConfigFilePath (Join-Path $TestDrive 'none.json'))

        $Unauthorized = $Results | Where-Object Key -eq 'unauthorizedAccess'
        $Unauthorized.Status | Should -Be 'Failed'
        $Unauthorized.Results.Instance.DisplayName | Should -Be 'CP Group'
        $Unauthorized.Results.Evidence.AccessPackages | Should -Be @('CP Access', 'CP Access 2')
        $Unauthorized.Results.Evidence.Count | Should -Be 2
        $Unauthorized.Results.Evidence.Catalogs | Should -Be @('Tier0 Catalog')
    }

    It 'shows the access drift (the current state) for the newest snapshot only' {
        $Root = New-TestReportData -Root (Join-Path $TestDrive 'driftolder') -AccessPackagesInOlder
        New-EntraOpsReportFindingData -ReportPath $Root -ConfigFilePath (Join-Path $TestDrive 'none.json') 6> $null
        $Content = Get-Content -LiteralPath "$Root/AccessPackageFlow/data/access-package-flow-findings.js" -Raw
        $Snapshots = ($Content.Substring($Content.IndexOf('=') + 1).TrimEnd().TrimEnd(';') | ConvertFrom-Json -AsHashtable -DateKind String).snapshots
        @($Snapshots['aaaaaaaa|2026-10-01T10:00:00.0000000+00:00'].flags['pol1'].id) | Should -Not -Contain 'unauthorizedAccess'
        @($Snapshots['aaaaaaaa|2026-10-01T10:00:00.0000000+00:00'].flags['pol1'].id) | Should -Contain 'noApproval'
        @($Snapshots['cccccccc|2026-10-20T10:00:00.0000000+00:00'].flags['pol1'].id) | Should -Contain 'unauthorizedAccess'
    }

    It 'skips the access drift rules with the reason when the drift <Case>' -ForEach @(
        @{ Case = 'could not be read'; State = 'unavailable'; Reason = 'Access drift could not be read from Microsoft Graph*Forbidden.*' }
        @{ Case = 'was not collected'; State = 'missing'; Reason = 'The Access Package Flow data has no access drift*' }
    ) {
        $Root = New-TestReportData -Root (Join-Path $TestDrive "drift-$State") -AccessDrift $State
        $Results = @(Invoke-EntraOpsFindingEvaluation -Area AccessPackageFlow -ReportPath $Root -ConfigFilePath (Join-Path $TestDrive 'none.json'))
        foreach ($Drift in @($Results | Where-Object Key -in 'unauthorizedAccess', 'missingAccess')) {
            $Drift.Status | Should -Be 'Skipped'
            $Drift.Reason | Should -BeLike $Reason
        }
        @($Results | Where-Object Key -in 'unauthorizedAccess', 'missingAccess').Count | Should -Be 2
        ($Results | Where-Object Key -eq 'noApproval').Status | Should -Be 'Failed'
    }

    It 'writes the risk flags of every snapshot with embedded content for the reports' {
        $Root = New-TestReportData -Root (Join-Path $TestDrive 'reportdata')
        $ConfigFile = Join-Path $TestDrive 'reportdata.json'
        @{ Findings = @{ ExcludedRules = @('PimRequestFlow.approverUnclassified') } } | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $ConfigFile
        $Output = @(New-EntraOpsReportFindingData -ReportPath $Root -ConfigFilePath $ConfigFile -PassThru 6> $null)

        $Output.Area | Should -Be @('PimRequestFlow', 'AccessPackageFlow')
        $Content = Get-Content -LiteralPath "$Root/PimRequestFlow/data/pim-request-flow-findings.js" -Raw
        $Content | Should -Match '^// Auto-generated by New-EntraOpsReportFindingData'
        $Pim = $Content.Substring($Content.IndexOf('=') + 1).TrimEnd().TrimEnd(';') | ConvertFrom-Json -AsHashtable -DateKind String
        $Pim.schemaVersion | Should -Be 2
        @($Pim.snapshots.Keys) | Should -Be @('aaaaaaaa|2026-10-01T10:00:00.0000000+00:00', 'cccccccc|2026-10-20T10:00:00.0000000+00:00')
        # The older snapshot requires MFA for the Global Administrator, but no approval.
        @($Pim.snapshots['aaaaaaaa|2026-10-01T10:00:00.0000000+00:00'].flags["$($script:Roles.GlobalAdmin)|activation"].id) | Should -Be @('noApprovalActivation')
        $Latest = $Pim.snapshots['cccccccc|2026-10-20T10:00:00.0000000+00:00']
        @($Latest.flags["$($script:Roles.GlobalAdmin)|activation"].id) | Should -Be @('noMfaActivation', 'noApprovalActivation', 'approverNotEnforced')
        @($Latest.flags.Values | ForEach-Object { $_ } | Where-Object { $_.id -eq 'approverUnclassified' }).Count | Should -Be 0
        ($Pim.rules | Where-Object { $_.key -eq 'approverUnclassified' }).status | Should -Be 'Excluded'

        # The report model: role tiers (tier map, role action) and the resolved activation approvers.
        $Latest.roles[$script:Roles.GlobalAdmin].tier | Should -Be 'ControlPlane'
        $Latest.roles[$script:Roles.GlobalAdmin].approvers[0] | ConvertTo-Json -Compress | Should -Be '{"label":"CP Admin (cp.admin@contoso.com)","tier":"ControlPlane","protectionTier":"ControlPlane","resolved":true,"source":"direct"}'
        $Latest.roles[$script:Roles.Custom].tier | Should -Be 'ManagementPlane'
        $Latest.roles[$script:Roles.Custom].service | Should -Be 'Groups'
        $Latest.roles[$script:Roles.Helpdesk].approvers[2] | ConvertTo-Json -Compress | Should -Be '{"label":"Unknown Approvers","tier":"UserAccess","source":"default"}'

        $Content = Get-Content -LiteralPath "$Root/AccessPackageFlow/data/access-package-flow-findings.js" -Raw
        $Content | Should -Match 'window\.ENTRAOPS_ACCESS_PACKAGE_FLOW_FINDINGS = '
        $AccessPackage = $Content.Substring($Content.IndexOf('=') + 1).TrimEnd().TrimEnd(';') | ConvertFrom-Json -AsHashtable -DateKind String
        $Latest = $AccessPackage.snapshots['cccccccc|2026-10-20T10:00:00.0000000+00:00']
        # The scope tier of the target is lower than the classification of the group itself; the live data adds the target of pk2.
        $Latest.packages.pk1.targets[0] | ConvertTo-Json -Compress | Should -Be '{"resourceName":"CP Group","tier":"ControlPlane","source":"direct"}'
        # The Control Plane member of the pk2 group does not raise the tier the package grants.
        $Latest.packages.pk2.targets[0].tier | Should -Be 'ManagementPlane'
        $Latest.packages.pk2.targets[0].source | Should -Be 'scopeClassification'
        # The approval tier: the tier the resolved approvers are protected for; not set without a resolved approver.
        $Latest.flows.pol6.approvalTier | Should -Be 'UserAccess'
        $Latest.flows.pol4.Contains('approvalTier') | Should -BeFalse
        $Latest.flows.pol1.requestors[0] | ConvertTo-Json -Compress | Should -Be '{"scopeType":"AllExistingDirectoryMemberUsers","tier":"UserAccess","source":"broadScope"}'
        $Latest.flows.pol6.approvers[0] | ConvertTo-Json -Compress | Should -Be ('{{"label":"Members of: Approvers","tier":"UserAccess","protectionTier":"UserAccess","protectionMember":"Regular User","resolved":true,"source":"groupMembership","idSource":"live","id":"{0}","groupId":"{0}"}}' -f $script:Groups.Approvers)
        $Latest.flows.pol5.approvers[0].source | Should -Be 'default'
        $Latest.flows.pol4.assigned[0] | ConvertTo-Json -Compress | Should -Be '{"label":"CP Admin","tier":"ControlPlane","resolved":true,"source":"direct"}'
    }

    It 'does not write the risk flags of rules excluded in the Findings settings' {
        $Root = New-TestReportData -Root (Join-Path $TestDrive 'findingsettings')
        $ConfigFile = Join-Path $TestDrive 'findingsettings.json'
        @{ Findings = @{ ExcludedRules = @('EO.3007', 'AccessPackageFlow.broadRequestor') } } | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $ConfigFile
        New-EntraOpsReportFindingData -ReportPath $Root -ConfigFilePath $ConfigFile 6> $null

        $Content = Get-Content -LiteralPath "$Root/PimRequestFlow/data/pim-request-flow-findings.js" -Raw
        $Pim = $Content.Substring($Content.IndexOf('=') + 1).TrimEnd().TrimEnd(';') | ConvertFrom-Json -AsHashtable -DateKind String
        $Latest = $Pim.snapshots['cccccccc|2026-10-20T10:00:00.0000000+00:00']
        @($Latest.flags["$($script:Roles.GlobalAdmin)|activation"].id) | Should -Be @('noMfaActivation', 'approverNotEnforced')
        ($Pim.rules | Where-Object { $_.key -eq 'noApprovalActivation' }).status | Should -Be 'Excluded'

        $Content = Get-Content -LiteralPath "$Root/AccessPackageFlow/data/access-package-flow-findings.js" -Raw
        $AccessPackage = $Content.Substring($Content.IndexOf('=') + 1).TrimEnd().TrimEnd(';') | ConvertFrom-Json -AsHashtable -DateKind String
        @($AccessPackage.snapshots.Values | ForEach-Object { $_.flags.Values } | ForEach-Object { $_ } | Where-Object { $_.id -eq 'broadRequestor' }).Count | Should -Be 0
        ($AccessPackage.rules | Where-Object { $_.key -eq 'broadRequestor' }).status | Should -Be 'Excluded'
    }

    It 'applies the finding exceptions to the risk flags of the reports' {
        $Root = New-TestReportData -Root (Join-Path $TestDrive 'flowexceptions')
        $Folder = Join-Path $TestDrive 'flowexceptions-config'
        New-Item -ItemType Directory -Path $Folder -Force | Out-Null
        $Today = (Get-Date).ToUniversalTime().ToString('yyyy-MM-dd')
        $Later = (Get-Date).ToUniversalTime().AddDays(30).ToString('yyyy-MM-dd')
        @{ Findings = @{ ExceptionsFilePath = './exceptions.json' } } | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath "$Folder/EntraOpsConfig.json"
        # An object exception (the role) for EO.3006 and an instance exception (the flow) for EO.3007 of the Global Administrator.
        @(
            [ordered]@{ RuleId = 'EO.3006'; ObjectId = $script:Roles.GlobalAdmin; State = 'RiskAccepted'; Justification = 'Phishing-resistant MFA by Conditional Access'; AcceptedOn = $Today; ExpiresOn = $Later }
            [ordered]@{ RuleId = 'EO.3007'; InstanceId = "$($script:Roles.GlobalAdmin).activation"; State = 'Dismissed'; Justification = 'Emergency role' }
        ) | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath "$Folder/exceptions.json"
        New-EntraOpsReportFindingData -ReportPath $Root -ConfigFilePath "$Folder/EntraOpsConfig.json" 6> $null

        $Content = Get-Content -LiteralPath "$Root/PimRequestFlow/data/pim-request-flow-findings.js" -Raw
        $Pim = $Content.Substring($Content.IndexOf('=') + 1).TrimEnd().TrimEnd(';') | ConvertFrom-Json -AsHashtable -DateKind String
        $Pim.schemaVersion | Should -Be 2
        $Latest = $Pim.snapshots['cccccccc|2026-10-20T10:00:00.0000000+00:00']
        $FlowId = "$($script:Roles.GlobalAdmin)|activation"
        @($Latest.flags[$FlowId].id) | Should -Be @('approverNotEnforced')
        @($Latest.flags[$FlowId].ruleId) | Should -Be @('EO.3010')
        $Accepted = @($Latest.accepted[$FlowId])
        @($Accepted.id) | Should -Be @('noMfaActivation', 'noApprovalActivation')
        @($Accepted.ruleId) | Should -Be @('EO.3006', 'EO.3007')
        @($Accepted.state) | Should -Be @('RiskAccepted', 'Dismissed')
        $Accepted[0].expiresOn | Should -Be $Later
        $Accepted[0].justification | Should -Be 'Phishing-resistant MFA by Conditional Access'
        ($Pim.rules | Where-Object { $_.key -eq 'noMfaActivation' }).excluded | Should -BeFalse
        # Other roles keep their risk flags.
        @($Latest.flags.Values | ForEach-Object { $_ } | Where-Object { $_.id -eq 'noMfaActivation' }).Count | Should -BeGreaterThan 0
    }

    It 'accepts an authentication context instead of MFA on activation' {
        $Flags = & (Get-Module EntraOps) {
            param($Properties)
            Get-EntraOpsPimRequestFlowFlag -Flow ([pscustomobject]@{ path = 'activation'; roleTier = 'ControlPlane'; approvers = @(); p = $Properties })
        } @{ ActivationReqMFA = $false; ApprovaltoActivate = $false; AuthenticationContextRequired = $true; AuthenticationContextName = 'Require PAW'; AuthenticationContextId = 'c1' }
        $Flags.noMfaActivation.Failed | Should -BeFalse

        # Without a selected context the requirement has no effect: no MFA, and the context is reported as missing.
        $Flags = & (Get-Module EntraOps) {
            param($Properties)
            Get-EntraOpsPimRequestFlowFlag -Flow ([pscustomobject]@{ path = 'activation'; roleTier = 'ControlPlane'; approvers = @(); p = $Properties })
        } @{ ActivationReqMFA = $false; ApprovaltoActivate = $false; AuthenticationContextRequired = $true; AuthenticationContextName = ''; AuthenticationContextId = '' }
        $Flags.noMfaActivation.Failed | Should -BeTrue
        $Flags.authContextMissing.Failed | Should -BeTrue

        # A context known by its ID only (name not resolved by the snapshot) is configured for both checks.
        $Flags = & (Get-Module EntraOps) {
            param($Properties)
            Get-EntraOpsPimRequestFlowFlag -Flow ([pscustomobject]@{ path = 'activation'; roleTier = 'ControlPlane'; approvers = @(); p = $Properties })
        } @{ ActivationReqMFA = $false; ApprovaltoActivate = $false; AuthenticationContextRequired = $true; AuthenticationContextName = ''; AuthenticationContextId = 'c1' }
        $Flags.noMfaActivation.Failed | Should -BeFalse
        $Flags.authContextMissing.Failed | Should -BeFalse
    }

    It 'compares the approvers of privileged roles only' {
        $Evaluate = {
            param([string]$RoleTier)
            & (Get-Module EntraOps) {
                param($RoleTier)
                Get-EntraOpsPimRequestFlowFlag -Flow ([pscustomobject]@{
                        path = 'activation'; roleTier = $RoleTier; p = @{ ActivationReqMFA = $true; ApprovaltoActivate = $true; ActivateApprover = @('a', 'b') }
                        approvers = @([pscustomobject]@{ label = 'UA'; tier = 'UserAccess'; resolved = $true; source = 'direct' }, [pscustomobject]@{ label = 'Unknown'; tier = $null; resolved = $false; source = $null })
                    })
            } $RoleTier
        }
        $Flags = & $Evaluate 'ManagementPlane'
        $Flags.approverLowerTier.Failed | Should -BeTrue
        $Flags.approverUnclassified.Failed | Should -BeTrue
        # Management and Workload Plane are both Tier 1: a Workload Plane approver of a Management Plane role is no lower tier.
        $Flags = & (Get-Module EntraOps) {
            Get-EntraOpsPimRequestFlowFlag -Flow ([pscustomobject]@{
                    path = 'activation'; roleTier = 'ManagementPlane'; roleName = 'MP Role'; p = @{ ActivationReqMFA = $true; ApprovaltoActivate = $true; ActivateApprover = @('a') }
                    approvers = @([pscustomobject]@{ label = 'WP'; tier = 'WorkloadPlane'; resolved = $true; source = 'direct' })
                })
        }
        $Flags.approverLowerTier.Failed | Should -BeFalse
        # A User Access role: its approvers are not compared (every user without privileged access is unresolved).
        $Flags = & $Evaluate 'UserAccess'
        $Flags.approverLowerTier.Applies | Should -BeFalse
        $Flags.approverUnclassified.Applies | Should -BeFalse
    }

    It 'names the classification of the least protected member for a group approver, not of the group' {
        $Flags = & (Get-Module EntraOps) {
            Get-EntraOpsPimRequestFlowFlag -Flow ([pscustomobject]@{
                    path = 'activation'; roleTier = 'ControlPlane'; roleName = 'CP Role'; p = @{ ActivationReqMFA = $true; ApprovaltoActivate = $true; ActivateApprover = @('a') }
                    approvers = @([pscustomobject]@{ label = 'CP Approvers'; tier = 'ControlPlane'; protectionTier = 'UserAccess'; protectionMember = 'Regular User'; resolved = $true; source = 'direct' })
                })
        }
        $Flags.approverLowerTier.Text | Should -Be "The Control Plane role 'CP Role' is approved by approver(s) classified at a lower tier: CP Approvers (least protected member: Regular User, classified as User Access)."
    }

    It 'rates the approval of an access package by its stages: any approver of a stage, every stage' {
        $Evaluate = {
            param($Approvers)
            & (Get-Module EntraOps) {
                param($Approvers)
                Get-EntraOpsAccessPackageFlowFlag -Flow ([pscustomobject]@{
                        scopeType = 'SpecificDirectorySubjects'; acceptsRequests = $true; isApprovalRequired = $true; approvers = $Approvers
                        assignedPrincipals = @([pscustomobject]@{ name = 'CP Admin'; tierName = 'ControlPlane'; resolved = $true; source = 'direct' })
                        targets = @([pscustomobject]@{ tier = 'ManagementPlane'; drift = $null })
                    })
            } $Approvers
        }
        $Approver = { param($Tier, $Stage) [pscustomobject]@{ label = "$Tier $Stage"; tier = $Tier; resolved = $true; source = 'direct'; stage = $Stage } }
        # One stage with a Control Plane and a User Access approver: the User Access approver can approve alone.
        $Flags = & $Evaluate @((& $Approver 'ControlPlane' 0), (& $Approver 'UserAccess' 0))
        $Flags.approverLowerTier.Failed | Should -BeTrue
        $Flags.approverLowerTier.Text | Should -BeLike '*(User Access) than the resource being granted (Management Plane): UserAccess 0.'
        $Flags.assignedMorePrivileged.Failed | Should -BeTrue
        # A second stage with a Control Plane approver: both stages have to approve.
        $Flags = & $Evaluate @((& $Approver 'UserAccess' 0), (& $Approver 'ControlPlane' 1))
        $Flags.approverLowerTier.Failed | Should -BeFalse
        $Flags.assignedMorePrivileged.Failed | Should -BeFalse
        # Approvers without a stage (older data) share one stage.
        $Flags = & $Evaluate @([pscustomobject]@{ label = 'CP'; tier = 'ControlPlane'; resolved = $true; source = 'direct' }, [pscustomobject]@{ label = 'UA'; tier = 'UserAccess'; resolved = $true; source = 'direct' })
        $Flags.approverLowerTier.Failed | Should -BeTrue
    }

    It 'skips the assigned principals rule without the Access Package Flow data' {
        $Root = New-TestReportData -Root (Join-Path $TestDrive 'noassignments')
        Remove-Item -LiteralPath "$Root/AccessPackageFlow/data/access-package-assignments-data.js"
        $Result = Invoke-EntraOpsFindingEvaluation -Area AccessPackageFlow -ReportPath $Root -ConfigFilePath (Join-Path $TestDrive 'none.json') | Where-Object Key -eq 'assignedMorePrivileged'
        $Result.Status | Should -Be 'Skipped'
        $Result.Reason | Should -Match 'New-EntraOpsAccessPackageFlowData'
    }

    It 'does not report approval and requestor scope of policies that do not accept requests' {
        $Evaluate = {
            param([bool]$AcceptsRequests)
            & (Get-Module EntraOps) {
                param($AcceptsRequests)
                Get-EntraOpsAccessPackageFlowFlag -Flow ([pscustomobject]@{
                        scopeType = 'AllExistingDirectoryMemberUsers'; acceptsRequests = $AcceptsRequests; isApprovalRequired = $false
                        approvers = @(); assignedPrincipals = @(); targets = @([pscustomobject]@{ tier = 'ControlPlane'; drift = $null })
                    })
            } $AcceptsRequests
        }
        $Flags = & $Evaluate $true
        $Flags.noApproval.Failed | Should -BeTrue
        $Flags.broadRequestor.Failed | Should -BeTrue
        $Flags = & $Evaluate $false
        $Flags.noApproval.Applies | Should -BeFalse
        $Flags.broadRequestor.Applies | Should -BeFalse
    }
}
