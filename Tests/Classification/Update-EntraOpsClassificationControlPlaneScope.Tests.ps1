#Requires -Modules Pester

BeforeDiscovery {
    $script:TestRepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
}

Describe 'Update-EntraOpsClassificationControlPlaneScope empty scopes' {
    BeforeDiscovery {
        $ScopeVariables = @(
            'ScopeNamePrivilegedUsers'
            'ScopeNamePrivilegedDevices'
            'ScopeNamePrivilegedGroups'
            'ScopeNamePrivilegedServicePrincipals'
        )
    }

    BeforeAll {
    $script:TestRepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
        $ScriptPath = Join-Path $script:TestRepositoryRoot 'EntraOps/Public/PrivilegedAccess/Update-EntraOpsClassificationControlPlaneScope.ps1'
        $ScriptContent = [System.IO.File]::ReadAllText($ScriptPath)
        $ScopeVariables = @(
            'ScopeNamePrivilegedUsers'
            'ScopeNamePrivilegedDevices'
            'ScopeNamePrivilegedGroups'
            'ScopeNamePrivilegedServicePrincipals'
        )
    }

    It 'serializes <ScopeVariable> only when it contains entries' -ForEach @($ScopeVariables | ForEach-Object { @{ ScopeVariable = $_ } }) {
        $ExpectedGuard = "if (@(`$$ScopeVariable).Count -gt 0)"
        $ScriptContent | Should -Match ([regex]::Escape($ExpectedGuard))
    }

    It 'does not use null checks to decide whether scope collections contain entries' {
        foreach ($ScopeVariable in $ScopeVariables) {
            $UnsafeGuard = "if (`$null -ne `$$ScopeVariable)"
            $ScriptContent | Should -Not -Match ([regex]::Escape($UnsafeGuard))
        }
    }

    It 'does not discard device owners when the home tenant ID is unavailable' {
        $ScriptContent | Should -Match ([regex]::Escape('Home tenant ID is unavailable; device owners will not be filtered by tenant.'))
    }

    It 'computes whether a home tenant ID is available once and reuses it, instead of two independent null checks' {
        $HasHomeTenantIdAssignment = [regex]::Matches($ScriptContent, [regex]::Escape('$HasHomeTenantId = -not [string]::IsNullOrWhiteSpace($HomeTenantId)'))
        $HasHomeTenantIdAssignment.Count | Should -Be 1

        $HasHomeTenantIdUsage = [regex]::Matches($ScriptContent, '\$HasHomeTenantId\b')
        # One assignment plus at least two reads (foreign-tenant detection and the owner filter).
        $HasHomeTenantIdUsage.Count | Should -BeGreaterOrEqual 3
    }
}

Describe 'Intune device scope designated tier gaps' {
    BeforeAll {
        $script:TestRepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
        . (Join-Path $script:TestRepositoryRoot 'EntraOps/Private/Get-EntraOpsIntuneDeviceScopeDesignatedTierGap.ps1')
        . (Join-Path $script:TestRepositoryRoot 'EntraOps/Private/Show-EntraOpsWarningSummary.ps1')

        function New-DeviceScopeUser {
            param([string]$Id = 'user-one', [string]$TenantId = 'home-tenant', [object[]]$OwnedDevices = @('device-one'), [object[]]$PawDevices = @())
            [pscustomobject]@{
                ObjectId            = $Id
                ObjectType          = 'user'
                ObjectDisplayName   = 'Private Admin Name'
                ObjectTenantId      = $TenantId
                OwnedDevices        = $OwnedDevices
                AssociatedPawDevice = $PawDevices
            }
        }
    }

    It 'reports Tier 1 instead of Tier 0 for a ManagementPlane user selected by the active mode' {
        $User = New-DeviceScopeUser
        $Result = @(Get-EntraOpsIntuneDeviceScopeDesignatedTierGap -PrivilegedObjects @($User) -Tier0Users @() -Tier1Users @($User) -HomeTenantId 'home-tenant')

        $Result.Count | Should -Be 1
        $Result[0].Type | Should -Be 'IntuneDeviceScopeDesignatedTierGap.ManagementPlane'
        $Result[0].ObjectId | Should -Be 'user-one'
        $Result[0].DeviceScopeTier | Should -Be 'ManagementPlane'
        $Result[0].Message | Should -Match 'classified as Tier 1 \(ManagementPlane\) instead of Tier 0'
        $Result[0].Message | Should -Not -Match 'not in the privileged'
    }

    It 'reports exclusion for an Unclassified user' {
        $User = New-DeviceScopeUser
        $Result = @(Get-EntraOpsIntuneDeviceScopeDesignatedTierGap -PrivilegedObjects @($User) -Tier0Users @() -Tier1Users @() -HomeTenantId 'home-tenant')

        $Result.Count | Should -Be 1
        $Result[0].Type | Should -Be 'IntuneDeviceScopeDesignatedTierGap.Excluded'
        $Result[0].DeviceScopeTier | Should -Be 'None'
        $Result[0].Message | Should -Match 'not in the privileged Intune device scope'
    }

    It 'distinguishes Tier 1 and excluded gaps in the summary when object details are disabled' {
        $Tier1User = New-DeviceScopeUser -Id '11111111-1111-1111-1111-111111111111'
        $ExcludedUser = New-DeviceScopeUser -Id '22222222-2222-2222-2222-222222222222'
        $Gaps = @(Get-EntraOpsIntuneDeviceScopeDesignatedTierGap -PrivilegedObjects @($Tier1User, $ExcludedUser) -Tier0Users @() -Tier1Users @($Tier1User) -HomeTenantId 'home-tenant')
        $Warnings = [System.Collections.Generic.List[psobject]]::new()
        foreach ($Gap in $Gaps) { $Warnings.Add($Gap) }

        $Summary = @(Show-EntraOpsWarningSummary -WarningMessages $Warnings -IncludeObjectDetails $false 6>&1) -join "`n"

        $Summary | Should -Match 'IntuneDeviceScopeDesignatedTierGap\.ManagementPlane:'
        $Summary | Should -Match 'IntuneDeviceScopeDesignatedTierGap\.Excluded:'
        $Summary | Should -Match 'Object ID\(s\): 11111111-1111-1111-1111-111111111111'
        $Summary | Should -Match 'Object ID\(s\): 22222222-2222-2222-2222-222222222222'
        $Summary | Should -Not -Match 'Private Admin Name|Control Plane user'
    }

    It 'does not report a designated ControlPlane user' {
        $User = New-DeviceScopeUser
        @(Get-EntraOpsIntuneDeviceScopeDesignatedTierGap -PrivilegedObjects @($User) -Tier0Users @($User) -Tier1Users @() -HomeTenantId 'home-tenant').Count | Should -Be 0
    }

    It 'does not report users without owned or PAW devices' {
        $User = New-DeviceScopeUser -OwnedDevices @() -PawDevices @($null, '')
        @(Get-EntraOpsIntuneDeviceScopeDesignatedTierGap -PrivilegedObjects @($User) -Tier0Users @() -Tier1Users @() -HomeTenantId 'home-tenant').Count | Should -Be 0
    }

    It 'includes PAW-only users and keeps display names out of gap messages' {
        $User = New-DeviceScopeUser -OwnedDevices @() -PawDevices @('paw-one')
        $Result = @(Get-EntraOpsIntuneDeviceScopeDesignatedTierGap -PrivilegedObjects @($User) -Tier0Users @() -Tier1Users @() -HomeTenantId 'home-tenant')

        $Result.Count | Should -Be 1
        $Result[0].Message | Should -Not -Match 'Private Admin Name'
    }

    It 'excludes foreign-tenant users and non-user objects' {
        $ForeignUser = New-DeviceScopeUser -Id 'foreign-user' -TenantId 'other-tenant'
        $Group = New-DeviceScopeUser -Id 'group-one'
        $Group.ObjectType = 'group'
        @(Get-EntraOpsIntuneDeviceScopeDesignatedTierGap -PrivilegedObjects @($ForeignUser, $Group) -Tier0Users @() -Tier1Users @() -HomeTenantId 'home-tenant').Count | Should -Be 0
    }

    It 'includes users when the home tenant or the user tenant is unknown' {
        $ForeignUser = New-DeviceScopeUser -TenantId 'other-tenant'
        $UnknownTenantUser = New-DeviceScopeUser -TenantId ''

        @(Get-EntraOpsIntuneDeviceScopeDesignatedTierGap -PrivilegedObjects @($ForeignUser) -Tier0Users @() -Tier1Users @() -HomeTenantId '').Count | Should -Be 1
        @(Get-EntraOpsIntuneDeviceScopeDesignatedTierGap -PrivilegedObjects @($UnknownTenantUser) -Tier0Users @() -Tier1Users @() -HomeTenantId 'home-tenant').Count | Should -Be 1
    }

    It 'deduplicates users and matches designated tiers without regard to ID casing' {
        $User = New-DeviceScopeUser -Id 'USER-ONE'
        $Tier1User = New-DeviceScopeUser -Id 'user-one'
        $Result = @(Get-EntraOpsIntuneDeviceScopeDesignatedTierGap -PrivilegedObjects @($User, $User) -Tier0Users @() -Tier1Users @($Tier1User) -HomeTenantId 'home-tenant')

        $Result.Count | Should -Be 1
        $Result[0].DeviceScopeTier | Should -Be 'ManagementPlane'
        @(Get-EntraOpsIntuneDeviceScopeDesignatedTierGap -PrivilegedObjects @($User) -Tier0Users @($Tier1User) -Tier1Users @() -HomeTenantId 'home-tenant').Count | Should -Be 0
    }

    It 'handles null collections under strict mode' {
        Set-StrictMode -Version Latest
        @(Get-EntraOpsIntuneDeviceScopeDesignatedTierGap -PrivilegedObjects $null -Tier0Users $null -Tier1Users $null -HomeTenantId $null).Count | Should -Be 0
    }
}
