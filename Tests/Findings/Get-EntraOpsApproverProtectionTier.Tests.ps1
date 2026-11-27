#Requires -Modules Pester

Describe 'Get-EntraOpsApproverProtectionTier' {
    BeforeAll {
        $script:TestRepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
        Import-Module (Join-Path $script:TestRepositoryRoot 'EntraOps/EntraOps.psd1') -Force -WarningAction SilentlyContinue

        $New = { [System.Collections.Generic.Dictionary[string, object]]::new([System.StringComparer]::Ordinal) }
        $Objects = & $New
        # A Management Plane account with Control Plane access through a tier breach.
        $Objects['BREACHED'] = [pscustomobject]@{ objectId = 'breached'; tierName = 'ControlPlane'; objectTierName = 'ManagementPlane'; members = $null }
        $Objects['UNRESOLVED-GROUP'] = [pscustomobject]@{ objectId = 'unresolved-group'; objectType = 'group'; tierName = 'ControlPlane'; objectTierName = 'Unclassified'; members = $null }
        $Objects['CP'] = [pscustomobject]@{ objectId = 'cp'; tierName = 'ControlPlane'; objectTierName = 'ControlPlane'; members = $null }
        $Groups = & $New
        $Groups['CP-ONLY'] = [pscustomobject]@{ tierName = 'ControlPlane'; members = @(@{ id = 'cp' }); totalMembers = 1 }
        $Groups['MIXED'] = [pscustomobject]@{ tierName = 'ControlPlane'; members = @(@{ id = 'cp' }, @{ id = 'breached' }); totalMembers = 2 }
        # One member is not in the Privileged EAM data: a regular user.
        $Groups['WITH-USER'] = [pscustomobject]@{ tierName = 'ControlPlane'; members = @(@{ id = 'cp' }); totalMembers = 2 }
        # A nested group is no approver: its members are listed as well.
        $Groups['NESTED'] = [pscustomobject]@{ tierName = 'ControlPlane'; members = @(@{ id = 'cp' }, @{ id = 'inner'; objectType = 'group' }); totalMembers = 2; principalCount = 1 }
        # The Configuration Analyzer lists only the privileged member; the Access Package Flow data lists the regular user as well.
        $Groups['LISTED-ELSEWHERE'] = [pscustomobject]@{ tierName = 'ControlPlane'; members = @(@{ id = 'cp' }); totalMembers = 2; principalCount = 2 }
        $AssignmentGroups = & $New
        $AssignmentGroups['LISTED-ELSEWHERE'] = [pscustomobject]@{ tierName = 'ControlPlane'; members = @([ordered]@{ id = 'regular'; displayName = 'Regular User'; tierName = 'UserAccess'; objectType = 'user' }, [ordered]@{ id = 'cp'; displayName = 'CP Admin'; tierName = 'ControlPlane'; objectType = 'user' }); totalMembers = 2; principalCount = 2 }
        $script:ReportData = [pscustomobject]@{ ObjectTierIndex = $Objects; ResolvedGroupTierIndex = $Groups; AssignmentResolvedGroupTierIndex = $AssignmentGroups }
    }

    It '<Case>' -ForEach @(
        @{ Case = 'uses the classification of the approver, not its access'; Id = 'breached'; Expected = 'ManagementPlane' }
        @{ Case = 'keeps a Control Plane approver'; Id = 'cp'; Expected = 'ControlPlane' }
        @{ Case = 'uses the only member of a group'; Id = 'cp-only'; Expected = 'ControlPlane' }
        @{ Case = 'uses the least protected member of a group'; Id = 'mixed'; Expected = 'ManagementPlane' }
        @{ Case = 'counts members outside the Privileged EAM data as User Access'; Id = 'with-user'; Expected = 'UserAccess' }
        @{ Case = 'leaves out nested groups, whose members are listed'; Id = 'nested'; Expected = 'ControlPlane' }
        @{ Case = 'returns nothing for a group without member data (its own classification is no protection)'; Id = 'unresolved-group'; Expected = $null }
        @{ Case = 'returns nothing for an unresolved approver'; Id = 'unknown'; Expected = $null }
    ) {
        & (Get-Module EntraOps) { param($ReportData, $Id) Get-EntraOpsApproverProtectionTier -ReportData $ReportData -Id $Id } $script:ReportData $Id | Should -Be $Expected
    }

    It 'names the least protected member of a group' {
        $Result = & (Get-Module EntraOps) { param($ReportData) Get-EntraOpsApproverProtectionTier -ReportData $ReportData -Id 'with-user' -Detail } $script:ReportData
        $Result.Tier | Should -Be 'UserAccess'
        $Result.Member | Should -Be 'a member without privileged access'
    }

    It 'names a member without privileged access that the Access Package Flow data lists' {
        $Result = & (Get-Module EntraOps) { param($ReportData) Get-EntraOpsApproverProtectionTier -ReportData $ReportData -Id 'listed-elsewhere' -Detail } $script:ReportData
        $Result.Tier | Should -Be 'UserAccess'
        $Result.Member | Should -Be 'Regular User'
    }
}
