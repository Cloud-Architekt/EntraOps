#Requires -Modules Pester

Describe 'Get-EntraOpsFindingDetail' {
    BeforeAll {
        $script:TestRepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
        Import-Module (Join-Path $script:TestRepositoryRoot 'EntraOps/EntraOps.psd1') -Force -WarningAction SilentlyContinue
    }

    It 'removes the subject that names the object of the result: <Message>' -ForEach @(
        @{ Message = "Management Plane object 'admThom1' reaches 10 Control Plane services through the role 'Contributor'."; DisplayName = 'admThom1'; ObjectType = 'user'; Tier = 'ManagementPlane'; Expected = "Reaches 10 Control Plane services through the role 'Contributor'." }
        @{ Message = "Management Plane object 'admAdeleV' (user) is not linked to a work account."; DisplayName = 'admAdeleV'; ObjectType = 'user'; Tier = 'ManagementPlane'; Expected = 'Is not linked to a work account.' }
        @{ Message = "Unclassified object (counted as User Access) 'App' reaches 2 Management Plane services."; DisplayName = 'App'; ObjectType = 'serviceprincipal'; Tier = 'Unclassified'; Expected = 'Reaches 2 Management Plane services.' }
        @{ Message = "Unclassified object 'Spock' (user) with Control Plane role assignments has no associated privileged access workstation (PAW)."; DisplayName = 'Spock'; ObjectType = 'user'; Tier = 'Unclassified'; Expected = 'With Control Plane role assignments, has no associated privileged access workstation (PAW).' }
        @{ Message = "The Control Plane role 'AI Administrator' can be activated without approval."; DisplayName = 'AI Administrator'; ObjectType = 'roleSetting'; Tier = 'ControlPlane'; Expected = 'Can be activated without approval.' }
        @{ Message = "User 'admBreak0-01' holds the Control Plane role 'Global Administrator' (EntraID) as a permanent assignment."; DisplayName = 'admBreak0-01'; ObjectType = 'user'; Tier = 'ControlPlane'; Expected = "Holds the Control Plane role 'Global Administrator' (EntraID) as a permanent assignment." }
        @{ Message = "'sug_AAD.CA.Exclusion.207.ALL' (Management Plane) has 2 member(s) without an access package assignment."; DisplayName = 'sug_AAD.CA.Exclusion.207.ALL'; ObjectType = 'group'; Tier = 'ManagementPlane'; Expected = 'Has 2 member(s) without an access package assignment.' }
        # Details in parentheses that the object does not show are kept.
        @{ Message = "Service principal 'Automation' (ManagedIdentity) has Control Plane access."; DisplayName = 'Automation'; ObjectType = 'serviceprincipal'; Tier = 'ControlPlane'; Expected = 'ManagedIdentity: has Control Plane access.' }
        @{ Message = "The activation of the Control Plane role 'AI Administrator' does not require an authentication context."; DisplayName = 'AI Administrator'; ObjectType = 'roleSetting'; Tier = 'ControlPlane'; Expected = 'The activation of the role does not require an authentication context.' }
        @{ Message = "Assignments of the policy 'Initial Policy' of the access package 'Pkg / A' do not expire."; DisplayName = 'Pkg / A / Initial Policy'; ObjectType = 'accessPackageAssignmentPolicy'; Tier = ''; Expected = 'Assignments of the policy do not expire.' }
        @{ Message = "Service principal 'CSOC' of the application of tenant 123 has Control Plane access."; DisplayName = 'CSOC'; ObjectType = 'serviceprincipal'; Tier = 'ControlPlane'; Expected = 'Service principal of the application of tenant 123 has Control Plane access.' }
        @{ Message = "'MDC Scopes' (Defender) of 'admBreak0-01' has no tier classification."; DisplayName = 'admBreak0-01'; ObjectType = 'user'; Tier = 'ControlPlane'; Expected = "'MDC Scopes' (Defender) has no tier classification." }
        # The tier of the access is not the tier of the object: it stays.
        @{ Message = "Management Plane workload identity 'aadops-pull-sp' has 2 owner(s)."; DisplayName = 'aadops-pull-sp'; ObjectType = 'serviceprincipal'; Tier = 'ControlPlane'; Expected = 'With Management Plane access, has 2 owner(s).' }
        @{ Message = "The policy 'Initial Policy' of the access package 'Pkg' has no access review."; DisplayName = 'Pkg / Initial Policy'; ObjectType = 'accessPackageAssignmentPolicy'; Tier = ''; Expected = 'Has no access review.' }
        @{ Message = "Custom role 'NetOps' (Azure) grants Control Plane permissions."; DisplayName = 'NetOps'; ObjectType = 'roleDefinition'; Tier = ''; Expected = 'Azure: grants Control Plane permissions.' }
    ) {
        InModuleScope EntraOps -Parameters @{ M = $Message; D = $DisplayName; O = $ObjectType; T = $Tier } { param($M, $D, $O, $T) Get-EntraOpsFindingDetail -Message $M -DisplayName $D -ObjectType $O -AdminTierLevelName $T } | Should -BeExactly $Expected
    }

    It 'keeps a message whose subject is another object, another tier, or that does not read as a sentence: <Message>' -ForEach @(
        # The role of another object.
        # The tier of the message is not the tier of the result: removing it would hide the difference.
        @{ Message = "'MDC Scopes' (Defender) of 'Other' has no tier classification."; DisplayName = 'admBreak0-01'; ObjectType = 'user'; Tier = 'ControlPlane' }
        @{ Message = 'Any directory member can request a Management Plane resource.'; DisplayName = 'Package / Policy'; ObjectType = 'accessPackageAssignmentPolicy'; Tier = '' }
    ) {
        InModuleScope EntraOps -Parameters @{ M = $Message; D = $DisplayName; O = $ObjectType; T = $Tier } { param($M, $D, $O, $T) Get-EntraOpsFindingDetail -Message $M -DisplayName $D -ObjectType $O -AdminTierLevelName $T } | Should -BeExactly $Message
    }

    It 'removes the subject of an object named with the start of its ID, as objects of the same name are' {
        InModuleScope EntraOps {
            $Id = '00000095-0000-0000-0000-000000000095'
            Get-EntraOpsFindingDetail -Message "Management Plane object 'Test (00000095)' (serviceprincipal) holds role assignments of the Control Plane: 'Role' (EntraID)." -DisplayName 'Test' -ObjectId $Id -ObjectType 'serviceprincipal' -AdminTierLevelName 'ManagementPlane' |
                Should -BeExactly "Holds role assignments of the Control Plane: 'Role' (EntraID)."
            Get-EntraOpsFindingDetail -Message "Unclassified object 'Test (00000095)' (user) with Management Plane role assignments is not protected by restricted management." -DisplayName 'Test' -ObjectId $Id -ObjectType 'user' -AdminTierLevelName 'Unclassified' |
                Should -BeExactly 'With Management Plane role assignments, is not protected by restricted management.'
            # The object of the same name with another ID is another object: the message stays.
            Get-EntraOpsFindingDetail -Message "Management Plane object 'Test (00000096)' (serviceprincipal) holds role assignments of the Control Plane." -DisplayName 'Test' -ObjectId $Id -ObjectType 'serviceprincipal' -AdminTierLevelName 'ManagementPlane' |
                Should -BeLike "Management Plane object 'Test (00000096)'*"
            # A message without the ID is read as before.
            Get-EntraOpsFindingDetail -Message "User 'Test' has no sponsor." -DisplayName 'Test' -ObjectId $Id -ObjectType 'user' -AdminTierLevelName 'UserAccess' | Should -BeExactly 'Has no sponsor.'
        }
    }

    It 'returns the message when there is no object name' {
        InModuleScope EntraOps { Get-EntraOpsFindingDetail -Message 'Tenant-wide finding.' -DisplayName '' } | Should -BeExactly 'Tenant-wide finding.'
    }
}
