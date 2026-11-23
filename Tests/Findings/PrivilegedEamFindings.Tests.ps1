#Requires -Modules Pester

Describe 'Privileged EAM findings' {
    BeforeAll {
        $script:TestRepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
        Import-Module (Join-Path $script:TestRepositoryRoot 'EntraOps/EntraOps.psd1') -Force -WarningAction SilentlyContinue

        function Get-TestId([int]$Number) { '{0:d8}-0000-0000-0000-{1:d12}' -f $Number, $Number }
        $script:AuProtected = Get-TestId 902
        $script:AuOpen = Get-TestId 901

        function New-TestAssignment([string]$Name, [string]$Tier, [hashtable]$Property = @{}) {
            $Assignment = [ordered]@{
                RoleAssignmentId = "ra-$Name"; RoleAssignmentInstanceId = "i-$Name"; RoleDefinitionName = $Name; RoleDefinitionId = "rd-$Name"; RoleType = 'BuiltInRole'
                RoleAssignmentType = 'Direct'; RoleAssignmentSubType = ''; PIMAssignmentType = 'Eligible'; RoleAssignmentScopeId = '/'
                Classification = $(if ($Tier) { @(@{ AdminTierLevelName = $Tier; AdminTierLevel = "$(ConvertTo-TestLevel $Tier)"; Service = "S-$Tier" }) } else { @() })
            }
            foreach ($Key in $Property.Keys) { $Assignment[$Key] = $Property[$Key] }
            $Assignment
        }
        function ConvertTo-TestLevel([string]$Tier) { @{ ControlPlane = 0; ManagementPlane = 1; UserAccess = 2 }[$Tier] }
        function New-TestObject([int]$Number, [string]$Type, [string]$SubType, [string]$Tier, [object[]]$Assignments, [hashtable]$Property = @{}) {
            $Object = [ordered]@{
                ObjectId = (Get-TestId $Number); ObjectType = $Type; ObjectSubType = $SubType; ObjectDisplayName = "Object $Number"; ObjectTenantId = 'tenant-1'
                ObjectAdminTierLevelName = $Tier; ObjectAdminTierLevel = "$(ConvertTo-TestLevel $Tier)"; RoleAssignments = $Assignments
            }
            foreach ($Key in $Property.Keys) { $Object[$Key] = $Property[$Key] }
            $Object
        }

        $script:Root = Join-Path $TestDrive 'eam'
        foreach ($System in 'EntraID', 'Azure', 'ResourceApps') { New-Item -ItemType Directory -Path "$script:Root/$System" -Force | Out-Null }
        $Write = { param($System, $Objects) ConvertTo-Json -InputObject @($Objects) -Depth 10 | Set-Content -LiteralPath "$script:Root/$System/$System.json" }
        & $Write 'EntraID' @(
            New-TestObject 1 'user' 'Member' 'ControlPlane' @(
                New-TestAssignment 'Global Administrator' 'ControlPlane' @{ PIMAssignmentType = 'Permanent' }
                # A permanent member of a group whose role assignment is permanent (standing access); a transitive
                # assignment carries the PIM assignment type of the group's assignment.
                New-TestAssignment 'Group Role A' 'ControlPlane' @{ RoleAssignmentType = 'Transitive'; RoleAssignmentSubType = 'Permanent member'; PIMAssignmentType = 'Permanent'; TransitiveByObjectId = (Get-TestId 10); TransitiveByObjectDisplayName = 'Group 10'; TransitiveByNestingObjectIds = @((Get-TestId 10)) }
                # A permanent member of a group with an eligible role assignment has to activate the role: no standing access.
                New-TestAssignment 'Group Role C' 'ControlPlane' @{ RoleAssignmentType = 'Transitive'; RoleAssignmentSubType = 'Permanent member'; PIMAssignmentType = 'Eligible'; TransitiveByObjectId = (Get-TestId 16); TransitiveByObjectDisplayName = 'Group 16'; TransitiveByNestingObjectIds = @((Get-TestId 16)) }
                # A PIM activation of an eligible assignment is no permanent assignment.
                New-TestAssignment 'Global Administrator' 'ControlPlane' @{ RoleAssignmentId = 'ra-ga-activated'; RoleAssignmentInstanceId = 'i-ga-activated'; PIMAssignmentType = 'Activated' }
                New-TestAssignment 'Custom CP' 'ControlPlane' @{ RoleType = 'CustomRole' }
            )
            New-TestObject 2 'user' 'Member' 'ControlPlane' @(
                New-TestAssignment 'Privileged Role Administrator' 'ControlPlane'
                New-TestAssignment 'Group Role B' 'ControlPlane' @{ RoleAssignmentType = 'Transitive'; RoleAssignmentSubType = 'Eligible member'; TransitiveByNestingObjectIds = @((Get-TestId 10), (Get-TestId 11)) }
                New-TestAssignment 'Custom UA' 'UserAccess' @{ RoleType = 'CustomRole' }
                New-TestAssignment 'Unknown role' $null
            )
            New-TestObject 3 'user' 'Member' 'ManagementPlane' @(New-TestAssignment 'User Administrator' 'ManagementPlane' @{ RoleAssignmentScopeId = "/administrativeUnits/$script:AuOpen" }) @{ OnPremSynchronized = $true }
            New-TestObject 4 'user' 'Member' 'ControlPlane' @(New-TestAssignment 'Security Administrator' 'ControlPlane') @{ AssignedAdministrativeUnits = @(@{ id = $script:AuOpen; displayName = 'Open AU' }) }
            # Protected by its privileged role: administrative-unit-scoped administrators cannot manage it.
            New-TestObject 15 'user' 'Member' 'ControlPlane' @(New-TestAssignment 'Billing Administrator' 'ControlPlane') @{ RestrictedManagementByAadRole = $true; AssignedAdministrativeUnits = @(@{ id = $script:AuOpen; displayName = 'Open AU' }) }
            New-TestObject 5 'user' 'Guest' 'UserAccess' @(New-TestAssignment 'Helpdesk Administrator' 'ManagementPlane' @{ PIMAssignmentType = 'Permanent'; RoleAssignmentScopeId = "/administrativeUnits/$script:AuProtected" })
            New-TestObject 6 'user' 'Member' 'ControlPlane' @(New-TestAssignment 'Exchange Administrator' 'ControlPlane') @{ RestrictedManagementByRMAU = $true; AssignedAdministrativeUnits = @(@{ id = $script:AuProtected; displayName = 'Protected AU' }) }
            New-TestObject 7 'group' 'Security' 'ManagementPlane' @(New-TestAssignment 'Groups Administrator' 'ManagementPlane' @{ PIMAssignmentType = 'Permanent' }) @{ Owners = @((Get-TestId 5)) }
            New-TestObject 8 'group' 'Role-assignable' 'ControlPlane' @(New-TestAssignment 'Authentication Administrator' 'ControlPlane' @{ PIMAssignmentType = 'Permanent' })
            # The service principal of a multi-tenant application of another organization: the export writes the home
            # tenant into ObjectTenantId and the tenant of the application into OriginTenantId.
            New-TestObject 9 'serviceprincipal' 'Application' 'ControlPlane' @(New-TestAssignment 'Application Administrator' 'ControlPlane' @{ PIMAssignmentType = 'Permanent' }) @{ OriginTenantId = 'tenant-2'; Owners = @((Get-TestId 5)) }
            New-TestObject 12 'serviceprincipal' 'AgentIdentity' 'Unclassified' @(New-TestAssignment 'Directory Writers' 'ManagementPlane' @{ PIMAssignmentType = 'Permanent' })
            New-TestObject 13 'serviceprincipal' 'AgentIdentityBlueprintPrincipal' 'Unclassified' @(New-TestAssignment 'Directory Readers' 'UserAccess' @{ PIMAssignmentType = 'Permanent' })
        )
        & $Write 'Azure' @(
            New-TestObject 1 'user' 'Member' 'ControlPlane' @(New-TestAssignment 'Owner' 'ControlPlane' @{ PIMAssignmentType = 'Permanent' })
            New-TestObject 9 'serviceprincipal' 'Application' 'ControlPlane' @(
                New-TestAssignment 'User Access Administrator' 'ControlPlane' @{ PIMAssignmentType = 'Permanent'; RoleDefinitionId = '/providers/Microsoft.Authorization/roleDefinitions/18d7d88d-d35e-4fb5-a5c3-7773c20a72d9'; RoleAssignmentScopeId = '/subscriptions/sub-1' }
                New-TestAssignment 'Role Based Access Control Administrator' 'ControlPlane' @{ PIMAssignmentType = 'Permanent'; RoleDefinitionId = '/providers/Microsoft.Authorization/roleDefinitions/f58310d9-a9f6-439a-9e8d-f62e7b41a168'; RoleAssignmentScopeId = '/subscriptions/sub-1'; RoleAssignmentCondition = '@Request[...] ForAnyOfAnyValues:GuidNotEquals {8e3af657}' }
                New-TestAssignment 'Reader' 'UserAccess' @{ RoleAssignmentScopeId = '/providers/Microsoft.Management/managementGroups/tenant-1' }
            ) @{ OriginTenantId = 'tenant-2' }
            New-TestObject 14 'serviceprincipal' 'ManagedIdentity' 'Unclassified' @(New-TestAssignment 'Contributor' 'ManagementPlane' @{ PIMAssignmentType = 'Permanent'; RoleAssignmentScopeId = '/providers/Microsoft.Management/managementGroups/tenant-1' })
        )
        & $Write 'ResourceApps' @(
            New-TestObject 9 'serviceprincipal' 'Application' 'ControlPlane' @(
                New-TestAssignment 'Directory.AccessAsUser.All' 'ControlPlane' @{ RoleType = 'Delegated'; PIMAssignmentType = 'Permanent'; RoleAssignmentScopeName = 'Microsoft Graph' }
                New-TestAssignment 'User.Read' 'UserAccess' @{ RoleType = 'Delegated'; PIMAssignmentType = 'Permanent'; RoleAssignmentScopeName = 'Microsoft Graph' }
                New-TestAssignment 'Mail.Read' 'ManagementPlane' @{ RoleType = 'Application'; PIMAssignmentType = 'Permanent' }
            ) @{ OriginTenantId = 'tenant-2' }
        )

        $script:Results = @{}
        foreach ($Result in Invoke-EntraOpsFindingEvaluation -Area PrivilegedEAM -ImportPath $script:Root -WarningAction SilentlyContinue) { $script:Results[$Result.Key] = $Result }
    }

    It 'returns all Privileged EAM rules sorted by ID' {
        @($script:Results.Values).Count | Should -Be 18
        @(Invoke-EntraOpsFindingEvaluation -Area PrivilegedEAM -ImportPath $script:Root -WarningAction SilentlyContinue).RuleId | Should -Be @(Get-EntraOpsFindingRule -Area PrivilegedEAM | Sort-Object Id).Id
    }

    It 'does not report the service principals of Microsoft first-party applications' {
        $Root = Join-Path $TestDrive 'firstparty'
        foreach ($System in 'EntraID', 'Azure') { New-Item -ItemType Directory -Path "$Root/$System" -Force | Out-Null }
        $Microsoft = @{ OriginTenantId = 'f8cdef31-a31e-4b4a-93e4-5f571e91255a' }
        $AuRole = { New-TestAssignment 'Groups Administrator' 'ManagementPlane' @{ RoleAssignmentScopeId = "/administrativeUnits/$script:AuOpen"; PIMAssignmentType = 'Permanent' } }
        ConvertTo-Json -Depth 10 -InputObject @(
            New-TestObject 20 'serviceprincipal' 'Application' 'Unclassified' @(& $AuRole) $Microsoft
            New-TestObject 21 'user' 'Member' 'ControlPlane' @(New-TestAssignment 'Security Administrator' 'ControlPlane') @{ AssignedAdministrativeUnits = @(@{ id = $script:AuOpen; displayName = 'Open AU' }) }
            New-TestObject 22 'serviceprincipal' 'Application' 'Unclassified' @(& $AuRole)
            # The same administrative unit role as 20, not first-party: reported (22 has Control Plane access in Azure).
            New-TestObject 24 'serviceprincipal' 'Application' 'Unclassified' @(& $AuRole)
        ) | Set-Content -LiteralPath "$Root/EntraID/EntraID.json"
        $RootOwner = { New-TestAssignment 'User Access Administrator' 'ControlPlane' @{ PIMAssignmentType = 'Permanent'; RoleAssignmentScopeId = '/' } }
        ConvertTo-Json -Depth 10 -InputObject @(
            # MS-PIM, recognized by its application ID in exports without OriginTenantId.
            New-TestObject 23 'serviceprincipal' 'Application' 'Unclassified' @(& $RootOwner) @{ ObjectUserPrincipalName = '01fc33a7-78ba-4d2f-a4b7-768e336e890e' }
            New-TestObject 22 'serviceprincipal' 'Application' 'Unclassified' @(& $RootOwner)
        ) | Set-Content -LiteralPath "$Root/Azure/Azure.json"

        $Results = @{}
        foreach ($Result in Invoke-EntraOpsFindingEvaluation -Area PrivilegedEAM, PrivilegedAssets -ImportPath $Root -WarningAction SilentlyContinue) { $Results[$Result.Key] = $Result }
        @($Results['auScopeLowerTier'].Results.Instance.ObjectId) | Should -Be @((Get-TestId 24))
        @($Results['azureRootScopeAssignment'].Results.Instance.ObjectId) | Should -Be @((Get-TestId 22))
        @($Results['unconstrainedRoleAssignmentDelegation'].Results.Instance.ObjectId) | Should -Be @((Get-TestId 22))
        @($Results['workloadControlPlane'].Results.Instance.ObjectId) | Should -Be @((Get-TestId 22))
        @($Results['unclassified'].Results.Instance.ObjectId | Sort-Object) | Should -Be @((Get-TestId 22), (Get-TestId 24))
        # Microsoft first-party applications are multi-tenant applications of Microsoft: not outside the home tenant.
        $Results['foreign'].Status | Should -Be 'Passed'
    }

    It 'applies the scope rules of the pre-release review (delegated groups, blueprints, first-party, consent clients, unnamed roles)' {
        $Root = Join-Path $TestDrive 'scope-rules'
        foreach ($System in 'EntraID', 'ResourceApps') { New-Item -ItemType Directory -Path "$Root/$System" -Force | Out-Null }
        $Microsoft = @{ OriginTenantId = 'f8cdef31-a31e-4b4a-93e4-5f571e91255a' }
        $Member = { param($Name, $GroupNumber) New-TestAssignment $Name 'ControlPlane' @{ RoleDefinitionId = "rd-$Name"; RoleAssignmentType = 'Transitive'; RoleAssignmentSubType = 'Permanent member'; PIMAssignmentType = 'Permanent'; TransitiveByObjectId = (Get-TestId $GroupNumber); TransitiveByObjectDisplayName = "Group $GroupNumber"; TransitiveByNestingObjectIds = @((Get-TestId $GroupNumber)) } }
        ConvertTo-Json -Depth 10 -InputObject @(
            # Group 30 holds Global Administrator as delegated access of Tenant Governance: its members are not reported by EO.3002.
            New-TestObject 30 'group' 'Role-assignable' 'ControlPlane' @(New-TestAssignment 'Global Administrator' 'ControlPlane' @{ RoleDefinitionId = 'rd-Global Administrator'; PIMAssignmentType = 'Permanent'; RoleAssignmentSubType = 'Tenant Governance Delegated Admin' })
            New-TestObject 31 'user' 'Member' 'ControlPlane' @(& $Member 'Global Administrator' 30)
            New-TestObject 32 'group' 'Role-assignable' 'ControlPlane' @(New-TestAssignment 'Privileged Role Administrator' 'ControlPlane' @{ RoleDefinitionId = 'rd-Privileged Role Administrator'; PIMAssignmentType = 'Permanent' })
            New-TestObject 33 'user' 'Member' 'ControlPlane' @(& $Member 'Privileged Role Administrator' 32)
            # A custom role assigned to a group: one principal, not the group and each member.
            New-TestObject 34 'group' 'Role-assignable' 'ControlPlane' @(New-TestAssignment 'Custom Group CP' 'ControlPlane' @{ RoleType = 'CustomRole' })
            New-TestObject 35 'user' 'Member' 'ControlPlane' @(New-TestAssignment 'Custom Group CP' 'ControlPlane' @{ RoleType = 'CustomRole'; RoleAssignmentType = 'Transitive'; TransitiveByObjectId = (Get-TestId 34) })
            # A role without a name is named by its ID.
            New-TestObject 36 'user' 'Member' 'ControlPlane' @(New-TestAssignment '' $null @{ RoleDefinitionName = ''; RoleDefinitionId = 'rd-unnamed' })
            # The tenant principal of a blueprint has no sponsors (they are kept on the blueprint); an agent identity has.
            New-TestObject 37 'serviceprincipal' 'AgentIdentityBlueprintPrincipal' 'Unclassified' @(New-TestAssignment 'Directory Readers' 'UserAccess')
            New-TestObject 38 'serviceprincipal' 'AgentIdentity' 'Unclassified' @(New-TestAssignment 'Directory Readers' 'UserAccess')
            # A Microsoft first-party service principal with owners is not reported by EO.7001.
            New-TestObject 39 'serviceprincipal' 'Application' 'ControlPlane' @(New-TestAssignment 'Application Administrator' 'ControlPlane') ($Microsoft + @{ Owners = @((Get-TestId 31)) })
        ) | Set-Content -LiteralPath "$Root/EntraID/EntraID.json"
        $Delegated = New-TestAssignment 'Directory.ReadWrite.All' 'ControlPlane' @{ RoleType = 'Delegated'; PIMAssignmentType = 'Permanent'; RoleAssignmentScopeName = 'Microsoft Graph' }
        ConvertTo-Json -Depth 10 -InputObject @(
            # Graph CLI is a Microsoft application, but its delegated permissions exist only by consent of the tenant.
            New-TestObject 40 'serviceprincipal' 'Application' 'Unclassified' @($Delegated) @{ OriginTenantId = 'cdc5aeea-15c5-4db6-b079-fcadd2505dc2'; ObjectUserPrincipalName = '14d82eec-204b-4c2f-b7e8-296a70dab67e' }
            New-TestObject 41 'serviceprincipal' 'Application' 'Unclassified' @($Delegated) $Microsoft
        ) | Set-Content -LiteralPath "$Root/ResourceApps/ResourceApps.json"

        $Results = @{}
        foreach ($Result in Invoke-EntraOpsFindingEvaluation -Area PrivilegedEAM, PrivilegedAssets -ImportPath $Root -ReportPath (Join-Path $TestDrive 'noreports') -WarningAction SilentlyContinue) { $Results[$Result.Key] = $Result }
        @($Results['permanentControlPlaneMembership'].Results.Instance.ObjectId) | Should -Be @((Get-TestId 33))
        $Custom = $Results['customRoleControlPlane'].Results | Where-Object { $_.Instance.DisplayName -eq 'Custom Group CP' }
        $Custom.Message | Should -BeLike '*is assigned to 1 principal(s).'
        $Custom.Evidence.ObjectIds | Should -Be @((Get-TestId 34))
        ($Results['unclassifiedAssignment'].Results | Where-Object { $_.Instance.ObjectId -eq (Get-TestId 36) }).Message | Should -BeLike "'unresolved role rd-unnamed' (EntraID)*"
        @($Results['sponsorMissing'].Results.Instance.ObjectId) | Should -Be @((Get-TestId 38))
        $Results['privilegedWorkloadOwner'].Status | Should -Not -Be 'Failed'
        @($Results['delegatedControlPlanePermission'].Results.Instance.ObjectId) | Should -Be @((Get-TestId 40))
        # Graph CLI is not another organization's application.
        @($Results['foreign'].Results.Instance.ObjectId) | Should -Not -Contain (Get-TestId 40)
    }

    It 'compares the access of an object without its delegated permissions, and keeps them in the role assignment rules' {
        $Root = Join-Path $TestDrive 'delegated-access'
        foreach ($System in 'EntraID', 'ResourceApps') { New-Item -ItemType Directory -Path "$Root/$System" -Force | Out-Null }
        # An agent identity whose only privileged permission is a delegated Management Plane permission, and an
        # application with a delegated Control Plane permission and owners; the sign-in scopes have no classification.
        $Mail = New-TestAssignment 'Mail.Read' 'ManagementPlane' @{ RoleType = 'Delegated'; PIMAssignmentType = 'Permanent'; RoleAssignmentScopeName = 'Microsoft Graph' }
        $Directory = New-TestAssignment 'Directory.ReadWrite.All' 'ControlPlane' @{ RoleType = 'Delegated'; PIMAssignmentType = 'Permanent'; RoleAssignmentScopeName = 'Microsoft Graph' }
        $OpenId = New-TestAssignment 'openid' $null @{ RoleType = 'Delegated'; RoleAssignmentScopeName = 'Microsoft Graph' }
        $Unknown = New-TestAssignment 'Custom.Scope' $null @{ RoleType = 'Delegated'; RoleAssignmentScopeName = 'Contoso API' }
        ConvertTo-Json -Depth 10 -InputObject @(
            New-TestObject 60 'serviceprincipal' 'AgentIdentity' 'UserAccess' @($Mail, $OpenId) @{ Sponsors = @((Get-TestId 62)); OriginTenantId = 'tenant-1' }
            New-TestObject 61 'serviceprincipal' 'Application' 'UserAccess' @($Directory, $Unknown) @{ Owners = @((Get-TestId 62)); OriginTenantId = 'tenant-2' }
        ) | Set-Content -LiteralPath "$Root/ResourceApps/ResourceApps.json"
        ConvertTo-Json -Depth 10 -InputObject @(New-TestObject 62 'user' 'Member' 'UserAccess' @(New-TestAssignment 'Directory Readers' 'UserAccess')) | Set-Content -LiteralPath "$Root/EntraID/EntraID.json"

        $Results = @{}
        foreach ($Result in Invoke-EntraOpsFindingEvaluation -Area PrivilegedEAM, PrivilegedAssets -ImportPath $Root -ReportPath (Join-Path $TestDrive 'noreports') -WarningAction SilentlyContinue) { $Results[$Result.Key] = $Result }
        foreach ($Key in 'agentPrivileged', 'foreignWorkloadControlPlane', 'workloadControlPlane', 'privilegedWorkloadOwner', 'tierBreach', 'ownerLowerTier') {
            @($Results[$Key].Results).Count | Should -Be 0 -Because "$Key compares the access without delegated permissions"
        }
        # The delegated Control Plane permission is reported as a role assignment; the sign-in scope openid is no privilege.
        @($Results['delegatedControlPlanePermission'].Results.Instance.ObjectId) | Should -Be @((Get-TestId 61))
        @($Results['unclassifiedAssignment'].Results.Evidence.RoleDefinitionName) | Should -Be @('Custom.Scope')
    }

    It 'skips EO.5001 for an export without the tenant of the applications' {
        $Root = Join-Path $TestDrive 'no-app-tenant'
        New-Item -ItemType Directory -Path "$Root/EntraID" -Force | Out-Null
        ConvertTo-Json -Depth 10 -InputObject @(New-TestObject 70 'serviceprincipal' 'Application' 'ControlPlane' @(New-TestAssignment 'Application Administrator' 'ControlPlane')) | Set-Content -LiteralPath "$Root/EntraID/EntraID.json"
        $Result = Invoke-EntraOpsFindingEvaluation -Area PrivilegedEAM -ImportPath $Root -WarningAction SilentlyContinue | Where-Object Key -eq 'foreignWorkloadControlPlane'
        $Result.Status | Should -Be 'Skipped'
        $Result.ReasonCode | Should -Be 'MissingData'
        $Result.Reason | Should -Match 'OriginTenantId'
    }

    It 'names the owners of a privileged workload identity and the tiers in its message' {
        $Root = Join-Path $TestDrive 'owner-names'
        New-Item -ItemType Directory -Path "$Root/EntraID" -Force | Out-Null
        ConvertTo-Json -Depth 10 -InputObject @(
            New-TestObject 80 'serviceprincipal' 'Application' 'ManagementPlane' @(New-TestAssignment 'Groups Administrator' 'ManagementPlane') @{ Owners = @((Get-TestId 81)); OriginTenantId = 'tenant-1' }
            New-TestObject 81 'user' 'Member' 'ManagementPlane' @(New-TestAssignment 'Groups Administrator' 'ManagementPlane')
        ) | Set-Content -LiteralPath "$Root/EntraID/EntraID.json"
        $Result = Invoke-EntraOpsFindingEvaluation -Area PrivilegedEAM -ImportPath $Root -WarningAction SilentlyContinue | Where-Object Key -eq 'privilegedWorkloadOwner'
        $Result.Results[0].Message | Should -Be "Management Plane workload identity 'Object 80' has 1 owner(s): 'Object 81'."
        $Result.Results[0].Evidence.OwnerNames | Should -Be @('Object 81')
        $Result.Results[0].Instance.AdminTierLevelName | Should -Be 'ManagementPlane'
    }

    It 'adds the application ID of an application to its evidence, which links its app registration' {
        $Root = Join-Path $TestDrive 'application-appid'
        New-Item -ItemType Directory -Path "$Root/EntraID" -Force | Out-Null
        $AppId = 'aaaaaaaa-8888-8888-8888-888888888888'
        ConvertTo-Json -Depth 10 -InputObject @(
            New-TestObject 82 'application' '' 'ManagementPlane' @(New-TestAssignment 'Groups Administrator' 'ManagementPlane') @{ Owners = @((Get-TestId 81)); ObjectUserPrincipalName = $AppId }
            New-TestObject 81 'user' 'Member' 'UserAccess' @()
        ) | Set-Content -LiteralPath "$Root/EntraID/EntraID.json"
        $Results = @{}
        foreach ($Result in Invoke-EntraOpsFindingEvaluation -Area PrivilegedEAM, PrivilegedAssets -ImportPath $Root -ReportPath (Join-Path $TestDrive 'noreports') -WarningAction SilentlyContinue) { $Results[$Result.RuleId] = $Result }
        foreach ($Id in 'EO.7001', 'EO.1004') {
            $Results[$Id].Results[0].Instance.ObjectType | Should -Be 'application' -Because $Id
            $Results[$Id].Results[0].Evidence.AppId | Should -Be $AppId -Because $Id
        }
    }

    It 'names the object tier, the higher assignment tier and the roles of a tier breach (EO.1002)' {
        $Root = Join-Path $TestDrive 'tier-breach-message'
        New-Item -ItemType Directory -Path "$Root/EntraID" -Force | Out-Null
        ConvertTo-Json -Depth 10 -InputObject @(
            New-TestObject 90 'user' 'Member' 'ManagementPlane' @((New-TestAssignment 'Global Administrator' 'ControlPlane'), (New-TestAssignment 'Groups Administrator' 'ManagementPlane'))
        ) | Set-Content -LiteralPath "$Root/EntraID/EntraID.json"
        $Result = Invoke-EntraOpsFindingEvaluation -Area PrivilegedAssets -ImportPath $Root -ReportPath (Join-Path $TestDrive 'noreports') -WarningAction SilentlyContinue | Where-Object Key -eq 'tierBreach'
        $Result.Results[0].Message | Should -Be "Management Plane object 'Object 90' (user) holds role assignments of the Control Plane: 'Global Administrator' (EntraID)."
        $Result.Results[0].Evidence.CausingRoles | Should -Be @("'Global Administrator' (EntraID)")
    }

    It 'names the related objects of a Privileged Assets finding, also those outside the export resolved by the report data' {
        $Root = Join-Path $TestDrive 'related'
        $Reports = Join-Path $TestDrive 'related-reports'
        New-Item -ItemType Directory -Path "$Root/EntraID", "$Reports/PrivilegedAssets/data" -Force | Out-Null
        $Owner = Get-TestId 51
        ConvertTo-Json -Depth 10 -InputObject @(
            New-TestObject 50 'serviceprincipal' 'Application' 'ControlPlane' @(New-TestAssignment 'Application Administrator' 'ControlPlane') @{ Owners = @($Owner) }
        ) | Set-Content -LiteralPath "$Root/EntraID/EntraID.json"
        "window.ENTRAOPS_PRIVILEGED_ASSETS_DATA = $(@{ relatedObjects = @{ $Owner = @{ objectId = $Owner; displayName = 'Regular Owner'; objectType = 'user'; source = 'Microsoft Graph' } } } | ConvertTo-Json -Depth 5 -Compress);" |
            Set-Content -LiteralPath "$Reports/PrivilegedAssets/data/privileged-assets-data.js"

        $Result = Invoke-EntraOpsFindingEvaluation -Area PrivilegedAssets -ImportPath $Root -ReportPath $Reports -WarningAction SilentlyContinue | Where-Object Key -eq 'ownerLowerTier'
        $Result.Results[0].Message | Should -BeLike "*owners of a lower tier: 'Regular Owner' (not privileged, counted as User Access)."
        $Result.Results[0].Evidence.RelatedObjectNames | Should -Be @('Regular Owner')
        # Without the report data, the owner is named by its ID.
        $Plain = Invoke-EntraOpsFindingEvaluation -Area PrivilegedAssets -ImportPath $Root -ReportPath (Join-Path $TestDrive 'noreports') -WarningAction SilentlyContinue | Where-Object Key -eq 'ownerLowerTier'
        $Plain.Results[0].Message | Should -BeLike "*owners of a lower tier: '$Owner' (not privileged, counted as User Access)."
    }

    It 'names a related object with the start of its ID when another object has the same name' {
        $Root = Join-Path $TestDrive 'samename'
        $Reports = Join-Path $TestDrive 'samename-reports'
        New-Item -ItemType Directory -Path "$Root/EntraID", "$Reports/PrivilegedAssets/data" -Force | Out-Null
        $Owner = Get-TestId 61
        ConvertTo-Json -Depth 10 -InputObject @(
            New-TestObject 60 'serviceprincipal' 'Application' 'ControlPlane' @(New-TestAssignment 'Application Administrator' 'ControlPlane') @{ Owners = @($Owner) }
            # A privileged user with the name of the owner, who is another object.
            New-TestObject 62 'user' 'Member' 'ManagementPlane' @(New-TestAssignment 'Helpdesk Administrator' 'ManagementPlane') @{ ObjectDisplayName = 'Same Name' }
        ) | Set-Content -LiteralPath "$Root/EntraID/EntraID.json"
        "window.ENTRAOPS_PRIVILEGED_ASSETS_DATA = $(@{ relatedObjects = @{ $Owner = @{ objectId = $Owner; displayName = 'Same Name'; objectType = 'user'; source = 'Microsoft Graph' } } } | ConvertTo-Json -Depth 5 -Compress);" |
            Set-Content -LiteralPath "$Reports/PrivilegedAssets/data/privileged-assets-data.js"

        $Result = Invoke-EntraOpsFindingEvaluation -Area PrivilegedAssets -ImportPath $Root -ReportPath $Reports -WarningAction SilentlyContinue | Where-Object Key -eq 'ownerLowerTier'
        $Result.Results[0].Message | Should -BeLike "*owners of a lower tier: 'Same Name ($($Owner.Substring(0, 8).ToLowerInvariant()))' (not privileged, counted as User Access)."
    }

    It 'evaluates the tier of an administrative unit role holder as the more privileged of its access and classification' {
        # Object 5 (User Access guest) holds Helpdesk Administrator (Management Plane) on the protected unit: its tier is
        # Management Plane, and the Control Plane member of the unit is protected by restricted management.
        $Result = $script:Results['auScopeLowerTier']
        $Passed = $Result.Results.Count -eq 1
        $Passed | Should -BeTrue
        $Result.Results[0].Evidence.HolderTier | Should -Be 'ManagementPlane'
    }

    It '<Key>: <Failed> of <Evaluated> instance(s) fail' -ForEach @(
        @{ Key = 'auScopeLowerTier'; Evaluated = 2; Failed = 1; Objects = @(3) }
        # PIM activations are not evaluated apart from their eligible assignments.
        @{ Key = 'unclassifiedAssignment'; Evaluated = 26; Failed = 1; Objects = @(2) }
        # The PIM activation of Global Administrator is not evaluated (its eligible assignment is).
        @{ Key = 'permanentControlPlaneAssignment'; Evaluated = 7; Failed = 2; Objects = @(1, 1) }
        # Group Role C (permanent member, eligible group assignment) is no standing access.
        @{ Key = 'permanentControlPlaneMembership'; Evaluated = 3; Failed = 1; Objects = @(1) }
        # Reader (User Access) at the tenant root management group is not in the scope of azureRootScopeAssignment.
        @{ Key = 'azureRootScopeAssignment'; Evaluated = 4; Failed = 2; Objects = @(1, 14) }
        @{ Key = 'privilegedWorkloadOwner'; Evaluated = 3; Failed = 1; Objects = @(9) }
        @{ Key = 'privilegedGroupOwner'; Evaluated = 2; Failed = 1; Objects = @(7) }
        @{ Key = 'guestPrivileged'; Evaluated = 7; Failed = 1; Objects = @(5) }
        @{ Key = 'unprotectedPrivilegedGroup'; Evaluated = 2; Failed = 1; Objects = @(7) }
        @{ Key = 'hybridManagementPlane'; Evaluated = 5; Failed = 1; Objects = @(3) }
        @{ Key = 'foreignWorkloadControlPlane'; Evaluated = 1; Failed = 1; Objects = @(9) }
        @{ Key = 'agentPrivileged'; Evaluated = 2; Failed = 1; Objects = @(12) }
        @{ Key = 'workloadControlPlane'; Evaluated = 4; Failed = 1; Objects = @(9) }
        @{ Key = 'delegatedControlPlanePermission'; Evaluated = 2; Failed = 1; Objects = @(9) }
        @{ Key = 'unconstrainedRoleAssignmentDelegation'; Evaluated = 2; Failed = 1; Objects = @(9) }
        @{ Key = 'nestedControlPlaneGroup'; Evaluated = 3; Failed = 1; Objects = @(2) }
    ) {
        $Result = $script:Results[$Key]
        $Result.EvaluatedCount | Should -Be $Evaluated
        $Result.FailedCount | Should -Be $Failed
        @($Result.Results.Instance.ObjectId | Sort-Object) | Should -Be @($Objects | ForEach-Object { Get-TestId $_ } | Sort-Object)
        $Result.Status | Should -Be 'Failed'
        foreach ($Item in $Result.Results) { $Item.Instance.Id | Should -Match '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$' }
    }

    It 'does not report the permanent Control Plane assignments of the configured emergency access accounts' {
        $Config = Join-Path $TestDrive 'emergency-access.json'
        @{ Findings = @{ EmergencyAccessAccounts = @((Get-TestId 1)) } } | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $Config
        $Result = Invoke-EntraOpsFindingEvaluation -Area PrivilegedEAM -ImportPath $script:Root -ConfigFilePath $Config -WarningAction SilentlyContinue | Where-Object Key -eq 'permanentControlPlaneAssignment'
        $Result.FailedCount | Should -Be 0
        @($Result.Results.Instance.ObjectId | Where-Object { $_ -eq (Get-TestId 1) }).Count | Should -Be 0
        $Result.Parameters.EmergencyAccessAccounts | Should -Be @((Get-TestId 1))
        $Result.ReasonCode | Should -Be 'Note'
        $Result.Reason | Should -BeLike "1 emergency access account(s) of Findings.EmergencyAccessAccounts are not reported: '*' ($(Get-TestId 1))."
    }

    It 'reports a custom role with Control Plane permissions once per role' {
        $Result = $script:Results['customRoleControlPlane']
        $Result.EvaluatedCount | Should -Be 2
        $Result.Results.Instance.DisplayName | Should -Be 'Custom CP'
        $Result.Results.Evidence.ObjectIds | Should -Be @((Get-TestId 1))
    }

    It 'explains the findings with their evidence' {
        $Scope = $script:Results['auScopeLowerTier'].Results[0]
        $Scope.Evidence.MemberObjectIds | Should -Be @((Get-TestId 4))
        $Scope.Message | Should -Match "Management Plane object 'Object 3' holds 'User Administrator' \(EntraID\) on an administrative unit with 1 more privileged member"
        $script:Results['privilegedWorkloadOwner'].Results[0].Evidence.OwnerIds | Should -Be @((Get-TestId 5))
        $script:Results['nestedControlPlaneGroup'].Results[0].Evidence.GroupIds.Count | Should -Be 2
    }

    It 'skips the rules with a reason when the export is missing' {
        $Skipped = @(Invoke-EntraOpsFindingEvaluation -Area PrivilegedEAM -ImportPath (Join-Path $TestDrive 'missing'))
        $Skipped.Status | Select-Object -Unique | Should -Be 'Skipped'
        $Skipped[0].Reason | Should -Match 'Save-EntraOpsPrivilegedEAMJson'
    }

    It 'filters by category' {
        @(Invoke-EntraOpsFindingEvaluation -Category OwnershipAndDelegation -ImportPath $script:Root -ReportPath (Join-Path $TestDrive 'noreports') -WarningAction SilentlyContinue).Key | Should -Be @('privilegedWorkloadOwner', 'privilegedGroupOwner', 'unconstrainedRoleAssignmentDelegation', 'nestedControlPlaneGroup', 'dynamicPrivilegedAdministrativeUnit')
    }
}
