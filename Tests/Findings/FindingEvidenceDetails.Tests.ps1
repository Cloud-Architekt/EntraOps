#Requires -Modules Pester

# Details of the finding results that tell instances apart or name their cause: consent type of delegated permissions
# (EO.5005), external users (EO.4010), unresolved PAW references (EO.4008), objects of the same name, and the principals
# of the Global Exclusion List in findings.json.
Describe 'Finding evidence details' {
    BeforeAll {
        $script:TestRepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
        Import-Module (Join-Path $script:TestRepositoryRoot 'EntraOps/EntraOps.psd1') -Force -WarningAction SilentlyContinue

        function Get-TestId([int]$Number) { '{0:d8}-0000-0000-0000-{1:d12}' -f $Number, $Number }
        function ConvertTo-TestGrantId([string[]]$Id) {
            $Bytes = [byte[]]@(foreach ($Item in $Id) { ([guid]$Item).ToByteArray() })
            [System.Convert]::ToBase64String($Bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
        }
        function New-TestAssignment([string]$Name, [string]$Tier, [hashtable]$Property = @{}) {
            $Assignment = [ordered]@{
                RoleAssignmentId = "ra-$Name"; RoleAssignmentInstanceId = "i-$Name"; RoleDefinitionName = $Name; RoleDefinitionId = "rd-$Name"; RoleType = 'BuiltInRole'
                RoleAssignmentType = 'Direct'; PIMAssignmentType = 'Eligible'; RoleAssignmentScopeId = '/'
                Classification = $(if ($Tier) { @(@{ AdminTierLevelName = $Tier; Service = "S-$Tier" }) } else { @() })
            }
            foreach ($Key in $Property.Keys) { $Assignment[$Key] = $Property[$Key] }
            $Assignment
        }
        function New-TestObject([int]$Number, [string]$Type, [string]$SubType, [string]$Tier, [object[]]$Assignments, [hashtable]$Property = @{}) {
            $Object = [ordered]@{
                ObjectId = (Get-TestId $Number); ObjectType = $Type; ObjectSubType = $SubType; ObjectDisplayName = "Object $Number"; ObjectTenantId = 'tenant-1'
                ObjectAdminTierLevelName = $Tier; RoleAssignments = $Assignments
            }
            foreach ($Key in $Property.Keys) { $Object[$Key] = $Property[$Key] }
            $Object
        }
        function Invoke-TestEvaluation([string]$Root, [string[]]$Area) {
            $Results = @{}
            foreach ($Result in Invoke-EntraOpsFindingEvaluation -Area $Area -ImportPath $Root -ReportPath (Join-Path $TestDrive 'noreports') -WarningAction SilentlyContinue) { $Results[$Result.Key] = $Result }
            $Results
        }
    }

    It 'reads the consent type and the user from the ID of a delegated permission grant' {
        $Client = Get-TestId 50; $Resource = Get-TestId 51; $User = Get-TestId 52
        $AllId = ConvertTo-TestGrantId $Client, $Resource
        $UserId = ConvertTo-TestGrantId $Client, $Resource, $User
        & (Get-Module EntraOps) {
            param($Client, $Resource, $User, $AllId, $UserId)
            # A grant for all users (client and resource) and the grant of one user (client, resource and user).
            $All = ConvertFrom-EntraOpsOAuth2PermissionGrantId -GrantId $AllId
            $All.ConsentType | Should -Be 'AllPrincipals'
            $All.ClientId | Should -Be $Client
            $All.ResourceId | Should -Be $Resource
            $All.PrincipalId | Should -BeNullOrEmpty
            $One = ConvertFrom-EntraOpsOAuth2PermissionGrantId -GrantId $UserId
            $One.ConsentType | Should -Be 'Principal'
            $One.PrincipalId | Should -Be $User
            ConvertFrom-EntraOpsOAuth2PermissionGrantId -GrantId 'ra-Directory.ReadWrite.All' | Should -BeNullOrEmpty
            ConvertFrom-EntraOpsOAuth2PermissionGrantId -GrantId '' | Should -BeNullOrEmpty
        } $Client $Resource $User $AllId $UserId
    }

    It 'names the consent of a delegated Control Plane permission, so two grants of one permission are told apart (EO.5005)' {
        $Root = Join-Path $TestDrive 'consent'
        foreach ($System in 'EntraID', 'ResourceApps') { New-Item -ItemType Directory -Path "$Root/$System" -Force | Out-Null }
        $Client = Get-TestId 70; $Resource = Get-TestId 71; $User = Get-TestId 72
        $Grant = @{ RoleType = 'Delegated'; PIMAssignmentType = 'Permanent'; RoleAssignmentScopeName = 'Microsoft Graph' }
        $ForAll = New-TestAssignment 'Directory.ReadWrite.All' 'ControlPlane' ($Grant + @{ RoleAssignmentId = (ConvertTo-TestGrantId $Client, $Resource); RoleAssignmentInstanceId = 'i-all' })
        $ForUser = New-TestAssignment 'Directory.ReadWrite.All' 'ControlPlane' ($Grant + @{ RoleAssignmentId = (ConvertTo-TestGrantId $Client, $Resource, $User); RoleAssignmentInstanceId = 'i-user' })
        ConvertTo-Json -Depth 10 -InputObject @(
            New-TestObject 70 'serviceprincipal' 'Application' 'UserAccess' @($ForAll, $ForUser) @{ OriginTenantId = 'tenant-1' }
        ) | Set-Content -LiteralPath "$Root/ResourceApps/ResourceApps.json"
        ConvertTo-Json -Depth 10 -InputObject @(New-TestObject 72 'user' 'Member' 'UserAccess' @(New-TestAssignment 'Directory Readers' 'UserAccess')) | Set-Content -LiteralPath "$Root/EntraID/EntraID.json"

        $Rule = (Invoke-TestEvaluation $Root 'PrivilegedEAM')['delegatedControlPlanePermission']
        $Messages = @($Rule.Results.Message | Sort-Object)
        $Messages.Count | Should -Be 2
        $Messages | Should -Contain "'Object 70' has the delegated Control Plane permission 'Directory.ReadWrite.All' of 'Microsoft Graph', consented for all users."
        $Messages | Should -Contain "'Object 70' has the delegated Control Plane permission 'Directory.ReadWrite.All' of 'Microsoft Graph', consented for the user 'Object 72' only."
        $ForUserResult = @($Rule.Results | Where-Object { $_.Evidence.ConsentType -eq 'Principal' })[0]
        $ForUserResult.Evidence.ConsentPrincipalId | Should -Be $User
    }

    It 'reports a B2B member with an #EXT# user principal name of an export without OutsideOfHomeTenant as outside the home tenant (EO.4010)' {
        $Root = Join-Path $TestDrive 'external'
        New-Item -ItemType Directory -Path "$Root/EntraID" -Force | Out-Null
        ConvertTo-Json -Depth 10 -InputObject @(
            New-TestObject 80 'user' 'Member' 'ManagementPlane' @(New-TestAssignment 'Role' 'ManagementPlane') @{ ObjectUserPrincipalName = 'AdeleV_fabrikam.com#EXT#@contoso.onmicrosoft.com' }
            New-TestObject 81 'user' 'Member' 'ManagementPlane' @(New-TestAssignment 'Role' 'ManagementPlane') @{ ObjectUserPrincipalName = 'AdeleV@contoso.com' }
        ) | Set-Content -LiteralPath "$Root/EntraID/EntraID.json"

        $Rule = (Invoke-TestEvaluation $Root 'PrivilegedAssets')['foreign']
        @($Rule.Results.Instance.ObjectId) | Should -Be @((Get-TestId 80))
        $Rule.Results[0].Message | Should -BeLike "*is a guest or external user, outside the home tenant, with the Management Plane role 'Role' (EntraID) at '/' (eligible)."
    }

    It 'reports objects of another tenant by their origin, also a synchronized member without #EXT# (EO.4010)' {
        $Root = Join-Path $TestDrive 'origin'
        New-Item -ItemType Directory -Path "$Root/EntraID" -Force | Out-Null
        $Role = { New-TestAssignment 'Role' 'ManagementPlane' }
        ConvertTo-Json -Depth 10 -InputObject @(
            # Cross-tenant synchronization: a member whose user principal name has no #EXT# and that the export doesn't flag.
            New-TestObject 100 'user' 'Member' 'ManagementPlane' @(& $Role) @{ ObjectUserPrincipalName = 'AdeleV@contoso.com'; OutsideOfHomeTenant = $false; OriginType = 'CrossTenantSync'; OriginTenantId = 'tenant-2'; OriginId = (Get-TestId 200) }
            New-TestObject 101 'user' 'Guest' 'ManagementPlane' @(& $Role) @{ OutsideOfHomeTenant = $true; OriginType = 'B2BInvitation'; OriginTenantId = 'tenant-3'; OriginId = (Get-TestId 201) }
            New-TestObject 102 'group' 'Role-assignable' 'ManagementPlane' @(& $Role) @{ ObjectTenantId = 'tenant-4'; OutsideOfHomeTenant = $true; OriginType = 'TenantGovernance'; OriginTenantId = 'tenant-4'; OriginId = (Get-TestId 102) }
            # Local objects: no finding.
            New-TestObject 103 'user' 'Member' 'ManagementPlane' @(& $Role) @{ ObjectUserPrincipalName = 'AlexW@contoso.com'; OriginType = 'Cloud'; OriginTenantId = 'tenant-1'; OriginId = (Get-TestId 103) }
            New-TestObject 104 'user' 'Member' 'ManagementPlane' @(& $Role) @{ ObjectUserPrincipalName = 'DiegoS@contoso.com'; OriginType = 'OnPremises'; OriginTenantId = 'tenant-1'; OriginId = 'S-1-5-21-1-2-3-1104' }
            New-TestObject 105 'user' 'Member' 'ManagementPlane' @(& $Role) @{ ObjectUserPrincipalName = 'LeeG@contoso.com' }
        ) | Set-Content -LiteralPath "$Root/EntraID/EntraID.json"

        $Rule = (Invoke-TestEvaluation $Root 'PrivilegedAssets')['foreign']
        @($Rule.Results.Instance.ObjectId | Sort-Object) | Should -Be @((Get-TestId 100), (Get-TestId 101), (Get-TestId 102))
        $ById = @{}; foreach ($Result in $Rule.Results) { $ById[$Result.Instance.ObjectId] = $Result }
        $ById[(Get-TestId 100)].Message | Should -BeLike '*is synchronized from tenant tenant-2 (cross-tenant synchronization), outside the home tenant, with *'
        $ById[(Get-TestId 100)].Evidence.OriginType | Should -Be 'CrossTenantSync'
        $ById[(Get-TestId 100)].Evidence.OriginId | Should -Be (Get-TestId 200)
        $ById[(Get-TestId 101)].Message | Should -BeLike '*is a guest invited from tenant tenant-3, outside the home tenant, with *'
        $ById[(Get-TestId 102)].Message | Should -BeLike '*is an object of tenant tenant-4 with access through Tenant Governance, outside the home tenant, with *'
    }

    It 'reports a Tenant Governance principal that is not found in this tenant as an object of its tenant (EO.4010, EO.4011)' {
        $Root = Join-Path $TestDrive 'tgplaceholder'
        New-Item -ItemType Directory -Path "$Root/EntraID" -Force | Out-Null
        $GlobalAdmin = { New-TestAssignment 'Global Administrator' 'ControlPlane' @{ PIMAssignmentType = 'Permanent' } }
        ConvertTo-Json -Depth 10 -InputObject @(
            # Local objects of the home tenant (tenant-1).
            New-TestObject 130 'user' 'Member' 'ControlPlane' @(& $GlobalAdmin) @{ ObjectUserPrincipalName = 'AdeleV@contoso.com'; OriginType = 'Cloud'; OriginTenantId = 'tenant-1'; OriginId = (Get-TestId 130) }
            New-TestObject 131 'user' 'Member' 'ControlPlane' @(& $GlobalAdmin) @{ ObjectUserPrincipalName = 'AlexW@contoso.com'; OriginType = 'Cloud'; OriginTenantId = 'tenant-1'; OriginId = (Get-TestId 131) }
            # The placeholder of Get-EntraOpsPrivilegedEntraObject for a principal of a governing tenant that is not found
            # here and is no remote group (no ManagingTenantId, or a principal of another governing tenant).
            New-TestObject 132 'unknown' 'unknown' 'Unclassified' @(& $GlobalAdmin) @{ ObjectDisplayName = 'Identity not found'; ObjectTenantId = 'tenant-9'; OutsideOfHomeTenant = $true; OriginType = 'TenantGovernance'; OriginTenantId = 'tenant-9'; OriginId = (Get-TestId 132) }
        ) | Set-Content -LiteralPath "$Root/EntraID/EntraID.json"

        $Results = Invoke-TestEvaluation $Root @('PrivilegedAssets', 'PrivilegedEAM')
        $Foreign = @($Results['foreign'].Results)
        @($Foreign.Instance.ObjectId | Select-Object -Unique) | Should -Be @((Get-TestId 132))
        $Foreign[0].Message | Should -BeLike "*'Identity not found' (unknown) is an object of tenant tenant-9 with access through Tenant Governance, outside the home tenant, with the Control Plane role 'Global Administrator'*"
        $ControlPlane = @($Results['foreignPrincipalControlPlane'].Results)
        @($ControlPlane.Instance.ObjectId) | Should -Be @((Get-TestId 132))
        $ControlPlane[0].Message | Should -Be "Object (unknown) 'Identity not found' is an object of tenant tenant-9 with access through Tenant Governance and has Control Plane access."
        $ControlPlane[0].Evidence.OriginType | Should -Be 'TenantGovernance'
        $ControlPlane[0].Evidence.OriginTenantId | Should -Be 'tenant-9'
    }

    It 'lists every role assignment of an object of another tenant, most privileged first, and an object with delegated permissions only once (EO.4010)' {
        $Root = Join-Path $TestDrive 'foreignassignments'
        foreach ($System in 'EntraID', 'ResourceApps') { New-Item -ItemType Directory -Path "$Root/$System" -Force | Out-Null }
        $Guest = @{ ObjectSubType = 'Guest'; OutsideOfHomeTenant = $true; OriginType = 'B2BInvitation'; OriginTenantId = 'tenant-3'; OriginId = (Get-TestId 220) }
        ConvertTo-Json -Depth 10 -InputObject @(
            New-TestObject 120 'user' 'Guest' 'ManagementPlane' @(
                New-TestAssignment 'Reader' 'UserAccess' @{ PIMAssignmentType = 'Permanent' }
                New-TestAssignment 'Global Administrator' 'ControlPlane' @{ RoleAssignmentType = 'Transitive'; TransitiveByObjectDisplayName = 'Admins' }
                New-TestAssignment 'Helpdesk Administrator' 'ManagementPlane'
            ) $Guest
            New-TestObject 121 'group' 'Role-assignable' 'ManagementPlane' @(New-TestAssignment 'Groups Administrator' 'ManagementPlane') @{ ObjectTenantId = 'tenant-4'; OutsideOfHomeTenant = $true; OriginType = 'TenantGovernance'; OriginTenantId = 'tenant-4'; OriginId = (Get-TestId 121) }
            # Local objects: evaluated, not reported.
            New-TestObject 123 'user' 'Member' 'ControlPlane' @(New-TestAssignment 'Privileged Role Administrator' 'ControlPlane') @{ OriginType = 'Cloud'; OriginTenantId = 'tenant-1'; OriginId = (Get-TestId 123) }
            New-TestObject 124 'user' 'Member' 'ManagementPlane' @(New-TestAssignment 'User Administrator' 'ManagementPlane') @{ OriginType = 'Cloud'; OriginTenantId = 'tenant-1'; OriginId = (Get-TestId 124) }
        ) | Set-Content -LiteralPath "$Root/EntraID/EntraID.json"
        # The application of another organization with a delegated permission only.
        $Delegated = New-TestAssignment 'Directory.ReadWrite.All' 'ControlPlane' @{ RoleType = 'Delegated'; PIMAssignmentType = 'Permanent'; RoleAssignmentScopeName = 'Microsoft Graph' }
        ConvertTo-Json -Depth 10 -InputObject @(
            New-TestObject 122 'serviceprincipal' 'Application' 'UserAccess' @($Delegated) @{ OriginType = 'ExternalApplication'; OriginTenantId = 'tenant-5' }
        ) | Set-Content -LiteralPath "$Root/ResourceApps/ResourceApps.json"

        $Rule = (Invoke-TestEvaluation $Root 'PrivilegedAssets')['foreign']
        $Rule.Status | Should -Be 'Failed'
        # Control Plane, then Management Plane (by object), then User Access; the object without own access last.
        @($Rule.Results | ForEach-Object { "$($_.Instance.ObjectId)|$($_.Evidence.RoleDefinitionName)" }) | Should -Be @(
            "$(Get-TestId 120)|Global Administrator"
            "$(Get-TestId 120)|Helpdesk Administrator"
            "$(Get-TestId 121)|Groups Administrator"
            "$(Get-TestId 120)|Reader"
            "$(Get-TestId 122)|"
        )
        $GlobalAdmin = $Rule.Results[0]
        $GlobalAdmin.Message | Should -Be "Management Plane object 'Object 120' (user) is a guest invited from tenant tenant-3, outside the home tenant, with the Control Plane role 'Global Administrator' (EntraID) at '/' (eligible, through 'Admins')."
        $GlobalAdmin.Detail | Should -BeLike 'Is a guest invited from tenant tenant-3, outside the home tenant, with the Control Plane role*'
        $GlobalAdmin.Evidence.Tier | Should -Be 'ControlPlane'
        $GlobalAdmin.Evidence.TransitiveBy | Should -Be 'Admins'
        $GlobalAdmin.Evidence.OriginType | Should -Be 'B2BInvitation'
        # The EAM Dashboard link of the assignment (#assignment=).
        $GlobalAdmin.Evidence.RoleAssignmentInstanceId | Should -Be 'i-Global Administrator'
        # One instance per assignment: an exception accepts one assignment of the object.
        @($Rule.Results.Instance.Id | Select-Object -Unique).Count | Should -Be 5
        $Rule.Results[4].Message | Should -Be "User Access object 'Object 122' (serviceprincipal) is the application of tenant tenant-5, outside the home tenant. It has delegated permissions only, which act within the rights of the signed-in user."
        # Evaluated: the five foreign instances and the two assignments of the local users.
        $Rule.EvaluatedCount | Should -Be 7
    }

    It 'leaves the restricted management of an object with access through Tenant Governance to its tenant (EO.4005)' {
        $Root = Join-Path $TestDrive 'governance'
        New-Item -ItemType Directory -Path "$Root/EntraID" -Force | Out-Null
        $Role = { New-TestAssignment 'Role' 'ManagementPlane' @{ RoleType = 'CustomRole' } }
        ConvertTo-Json -Depth 10 -InputObject @(
            New-TestObject 110 'user' 'Member' 'ManagementPlane' @(& $Role) @{ ObjectTenantId = 'tenant-4'; OriginType = 'TenantGovernance'; OriginTenantId = 'tenant-4'; OriginId = (Get-TestId 110) }
            New-TestObject 111 'user' 'Member' 'ManagementPlane' @(& $Role) @{ OriginType = 'Cloud'; OriginTenantId = 'tenant-1'; OriginId = (Get-TestId 111) }
            New-TestObject 112 'user' 'Member' 'ManagementPlane' @(& $Role) @{ OriginType = 'Cloud'; OriginTenantId = 'tenant-1'; OriginId = (Get-TestId 112) }
        ) | Set-Content -LiteralPath "$Root/EntraID/EntraID.json"

        $Rule = (Invoke-TestEvaluation $Root 'PrivilegedAssets')['restrictedManagementGap']
        @($Rule.Results.Instance.ObjectId | Sort-Object) | Should -Be @((Get-TestId 111), (Get-TestId 112))
    }

    It 'names a PAW reference that matches no device (EO.4008)' {
        $Root = Join-Path $TestDrive 'paw'
        New-Item -ItemType Directory -Path "$Root/EntraID" -Force | Out-Null
        ConvertTo-Json -Depth 10 -InputObject @(
            New-TestObject 90 'user' 'Member' 'ControlPlane' @(New-TestAssignment 'Role' 'ControlPlane') @{ AssociatedPawDevice = @('00000099-0000-0000-0000-000000000099'); AssociatedPawDeviceObjectId = @() }
            New-TestObject 91 'user' 'Member' 'ControlPlane' @(New-TestAssignment 'Role' 'ControlPlane') @{ AssociatedPawDevice = @(); AssociatedPawDeviceObjectId = @() }
        ) | Set-Content -LiteralPath "$Root/EntraID/EntraID.json"

        $Rule = (Invoke-TestEvaluation $Root 'PrivilegedAssets')['pawMissing']
        $Stale = @($Rule.Results | Where-Object { $_.Instance.ObjectId -eq (Get-TestId 90) })[0]
        $Stale.Message | Should -BeLike "*has no associated privileged access workstation (PAW): its PAW reference '00000099-0000-0000-0000-000000000099' matches no device."
        $Stale.Evidence.UnresolvedPawReferences | Should -Be @('00000099-0000-0000-0000-000000000099')
        @($Rule.Results | Where-Object { $_.Instance.ObjectId -eq (Get-TestId 91) })[0].Message | Should -BeLike '*has no associated privileged access workstation (PAW).'
    }

    It 'names the object of a result by its display name, also when another object has the same name' {
        $Root = Join-Path $TestDrive 'names'
        New-Item -ItemType Directory -Path "$Root/EntraID" -Force | Out-Null
        ConvertTo-Json -Depth 10 -InputObject @(
            New-TestObject 95 'serviceprincipal' 'Application' 'ManagementPlane' @(New-TestAssignment 'Role' 'ControlPlane') @{ ObjectDisplayName = 'Test'; OriginTenantId = 'tenant-1' }
            New-TestObject 96 'serviceprincipal' 'Application' 'ManagementPlane' @(New-TestAssignment 'Role' 'ControlPlane') @{ ObjectDisplayName = 'Test'; OriginTenantId = 'tenant-1' }
        ) | Set-Content -LiteralPath "$Root/EntraID/EntraID.json"

        # The reports show the ID with the result (Maester Pack: the start of the ID of objects of the same name), so
        # the message names the object as the other rules do, and its detail removes it.
        $Results = @((Invoke-TestEvaluation $Root 'PrivilegedAssets')['tierBreach'].Results)
        $Results | Should -HaveCount 2
        @($Results.Instance.ObjectId | Sort-Object) | Should -Be @((Get-TestId 95), (Get-TestId 96))
        foreach ($Result in $Results) {
            $Result.Message | Should -BeLike "Management Plane object 'Test' (serviceprincipal) holds role assignments *"
            $Result.Detail | Should -BeLike 'Holds role assignments *'
        }
    }

    It 'saves the principals of the Global Exclusion List in findings.json' {
        $Root = Join-Path $TestDrive 'exclusions'
        New-Item -ItemType Directory -Path "$Root/Classification", "$Root/Findings" -Force | Out-Null
        ConvertTo-Json -Depth 5 -InputObject @(@{ ExcludedPrincipalId = @('0000000A-0000-0000-0000-00000000000A', '0000000a-0000-0000-0000-00000000000a') }) | Set-Content -LiteralPath "$Root/Classification/Global.json"
        $Previous = $Global:EntraOpsBaseFolder
        try {
            $Global:EntraOpsBaseFolder = $Root
            @() | Save-EntraOpsFindingJson -ExportFolder "$Root/Findings" -TenantId 't' -TenantName 't' 6> $null
        } finally { $Global:EntraOpsBaseFolder = $Previous }
        $Saved = Get-Content -LiteralPath "$Root/Findings/findings.json" -Raw | ConvertFrom-Json
        $Saved.GlobalExclusions.Count | Should -Be 1
        @($Saved.GlobalExclusions.PrincipalIds) | Should -Be @('0000000a-0000-0000-0000-00000000000a')
        $Saved.GlobalExclusions.FilePath | Should -Be './Classification/Global.json'
    }
}
