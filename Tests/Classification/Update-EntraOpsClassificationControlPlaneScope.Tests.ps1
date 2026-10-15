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


    It 'checks Intune device selection gaps against the devices selected in the active mode' {
        $ScriptContent | Should -Match ([regex]::Escape('$SelectedDeviceIds = @($Tier0DeviceIds) + @($Tier1DeviceIds)'))
        $ScriptContent | Should -Match ([regex]::Escape('Get-EntraOpsIntuneDeviceScopeSelectionGap -PrivilegedObjects $PrivilegedObjects -Tier0Users $Tier0Users -Tier1Users $Tier1Users -SelectedDeviceIds $SelectedDeviceIds -HomeTenantId $HomeTenantId'))
    }
}

Describe 'Intune device scope selection gaps' {
    BeforeAll {
        $script:TestRepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
        . (Join-Path $script:TestRepositoryRoot 'EntraOps/Private/Get-EntraOpsIntuneDeviceScopeSelectionGap.ps1')
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

        # Mirrors the caller: selected devices are the owned and PAW devices of the selected users.
        function Get-SelectedDeviceIds {
            param([object[]]$Users)
            @($Users | ForEach-Object { @($_.OwnedDevices) + @($_.AssociatedPawDevice) } | Where-Object { $_ } | Select-Object -Unique)
        }
    }

    It 'reports only the unselected devices of a user with partial selection' {
        $User = New-DeviceScopeUser -OwnedDevices @('device-selected', 'device-missing')
        $Result = @(Get-EntraOpsIntuneDeviceScopeSelectionGap -PrivilegedObjects @($User) -Tier0Users @() -Tier1Users @() -SelectedDeviceIds @('device-selected') -HomeTenantId 'home-tenant')

        $Result.Count | Should -Be 1
        $Result[0].Type | Should -Be 'IntuneDeviceScopeSelectionGap'
        $Result[0].ObjectId | Should -Be 'user-one'
        $Result[0].SourceSelection | Should -Be 'None'
        @($Result[0].UnselectedDeviceIds) | Should -Be @('device-missing')
        $Result[0].Message | Should -Match 'has 1 owned or PAW device\(s\) not selected for privileged Intune scope generation in the active mode \(user not selected as source\)'
    }

    It 'does not report a PAW shared with a selected ControlPlane user' {
        $User = New-DeviceScopeUser -OwnedDevices @() -PawDevices @('shared-paw')
        $Tier0User = New-DeviceScopeUser -Id 'tier0-user' -OwnedDevices @() -PawDevices @('shared-paw')
        @(Get-EntraOpsIntuneDeviceScopeSelectionGap -PrivilegedObjects @($User, $Tier0User) -Tier0Users @($Tier0User) -Tier1Users @() -SelectedDeviceIds (Get-SelectedDeviceIds @($Tier0User)) -HomeTenantId 'home-tenant').Count | Should -Be 0
    }

    It 'does not report a ManagementPlane user whose devices are selected in the default mode' {
        $User = New-DeviceScopeUser -PawDevices @('paw-one')
        @(Get-EntraOpsIntuneDeviceScopeSelectionGap -PrivilegedObjects @($User) -Tier0Users @() -Tier1Users @($User) -SelectedDeviceIds (Get-SelectedDeviceIds @($User)) -HomeTenantId 'home-tenant').Count | Should -Be 0
    }

    It 'reports the same ManagementPlane user in ControlPlaneDevicesOnly mode' {
        $User = New-DeviceScopeUser -PawDevices @('paw-one')
        $Result = @(Get-EntraOpsIntuneDeviceScopeSelectionGap -PrivilegedObjects @($User) -Tier0Users @() -Tier1Users @() -SelectedDeviceIds @() -HomeTenantId 'home-tenant')

        $Result.Count | Should -Be 1
        $Result[0].SourceSelection | Should -Be 'None'
        @($Result[0].UnselectedDeviceIds) | Should -Be @('device-one', 'paw-one')
    }

    It 'reports devices missing from selection for a selected user as context, not as a designation gap' {
        # Live resolution can add devices that the export used for selection does not contain.
        $Tier0User = New-DeviceScopeUser -Id 'tier0-user' -OwnedDevices @('export-device', 'live-device')
        $ExportTier0User = New-DeviceScopeUser -Id 'tier0-user' -OwnedDevices @('export-device')
        $Tier1User = New-DeviceScopeUser -Id 'tier1-user' -OwnedDevices @('tier1-live-device')
        $Result = @(Get-EntraOpsIntuneDeviceScopeSelectionGap -PrivilegedObjects @($Tier0User, $Tier1User) -Tier0Users @($ExportTier0User) -Tier1Users @($Tier1User) -SelectedDeviceIds @('export-device') -HomeTenantId 'home-tenant')

        $Result.Count | Should -Be 2
        ($Result | Where-Object ObjectId -eq 'tier0-user').SourceSelection | Should -Be 'ControlPlane'
        @(($Result | Where-Object ObjectId -eq 'tier0-user').UnselectedDeviceIds) | Should -Be @('live-device')
        ($Result | Where-Object ObjectId -eq 'tier0-user').Message | Should -Match '\(user selected as ControlPlane source\)'
        ($Result | Where-Object ObjectId -eq 'tier1-user').SourceSelection | Should -Be 'ManagementPlane'
    }

    It 'does not assert effective coverage, RBAC tier or the cause in the message' {
        $User = New-DeviceScopeUser
        $Result = @(Get-EntraOpsIntuneDeviceScopeSelectionGap -PrivilegedObjects @($User) -Tier0Users @() -Tier1Users @() -SelectedDeviceIds @() -HomeTenantId 'home-tenant')

        $Result[0].Message | Should -Not -Match 'not in the privileged Intune device scope|classified as Tier|because'
    }

    It 'compares device and user IDs without regard to casing and whitespace' {
        $User = New-DeviceScopeUser -Id 'USER-ONE' -OwnedDevices @('DEVICE-ONE ') -PawDevices @('Device-One')
        @(Get-EntraOpsIntuneDeviceScopeSelectionGap -PrivilegedObjects @($User) -Tier0Users @() -Tier1Users @() -SelectedDeviceIds @('device-one') -HomeTenantId 'home-tenant').Count | Should -Be 0

        $Result = @(Get-EntraOpsIntuneDeviceScopeSelectionGap -PrivilegedObjects @($User) -Tier0Users @() -Tier1Users @([pscustomobject]@{ ObjectId = 'user-one' }) -SelectedDeviceIds @() -HomeTenantId 'home-tenant')
        $Result[0].SourceSelection | Should -Be 'ManagementPlane'
        @($Result[0].UnselectedDeviceIds) | Should -Be @('DEVICE-ONE')
    }

    It 'merges duplicate user entries and reports each unselected device once' {
        $Entry1 = New-DeviceScopeUser -OwnedDevices @('device-one', 'device-two')
        $Entry2 = New-DeviceScopeUser -Id 'User-One' -OwnedDevices @('device-two') -PawDevices @('paw-one')
        $Result = @(Get-EntraOpsIntuneDeviceScopeSelectionGap -PrivilegedObjects @($Entry1, $Entry2) -Tier0Users @() -Tier1Users @() -SelectedDeviceIds @('device-one') -HomeTenantId 'home-tenant')

        $Result.Count | Should -Be 1
        @($Result[0].UnselectedDeviceIds) | Should -Be @('device-two', 'paw-one')
    }

    It 'does not report users without owned or PAW devices' {
        $User = New-DeviceScopeUser -OwnedDevices @() -PawDevices @($null, '')
        @(Get-EntraOpsIntuneDeviceScopeSelectionGap -PrivilegedObjects @($User) -Tier0Users @() -Tier1Users @() -SelectedDeviceIds @() -HomeTenantId 'home-tenant').Count | Should -Be 0
    }

    It 'includes PAW-only users and keeps display names out of gap messages' {
        $User = New-DeviceScopeUser -OwnedDevices @() -PawDevices @('paw-one')
        $Result = @(Get-EntraOpsIntuneDeviceScopeSelectionGap -PrivilegedObjects @($User) -Tier0Users @() -Tier1Users @() -SelectedDeviceIds @() -HomeTenantId 'home-tenant')

        $Result.Count | Should -Be 1
        $Result[0].Message | Should -Not -Match 'Private Admin Name'
    }

    It 'excludes foreign-tenant users and non-user objects' {
        $ForeignUser = New-DeviceScopeUser -Id 'foreign-user' -TenantId 'other-tenant'
        $Group = New-DeviceScopeUser -Id 'group-one'
        $Group.ObjectType = 'group'
        @(Get-EntraOpsIntuneDeviceScopeSelectionGap -PrivilegedObjects @($ForeignUser, $Group) -Tier0Users @() -Tier1Users @() -SelectedDeviceIds @() -HomeTenantId 'home-tenant').Count | Should -Be 0
    }

    It 'includes users when the home tenant or the user tenant is unknown' {
        $ForeignUser = New-DeviceScopeUser -TenantId 'other-tenant'
        $UnknownTenantUser = New-DeviceScopeUser -TenantId ''

        @(Get-EntraOpsIntuneDeviceScopeSelectionGap -PrivilegedObjects @($ForeignUser) -Tier0Users @() -Tier1Users @() -SelectedDeviceIds @() -HomeTenantId '').Count | Should -Be 1
        @(Get-EntraOpsIntuneDeviceScopeSelectionGap -PrivilegedObjects @($UnknownTenantUser) -Tier0Users @() -Tier1Users @() -SelectedDeviceIds @() -HomeTenantId 'home-tenant').Count | Should -Be 1
    }

    It 'shows user IDs without display names in the summary when object details are disabled' {
        $UserA = New-DeviceScopeUser -Id '11111111-1111-1111-1111-111111111111'
        $UserB = New-DeviceScopeUser -Id '22222222-2222-2222-2222-222222222222'
        $Gaps = @(Get-EntraOpsIntuneDeviceScopeSelectionGap -PrivilegedObjects @($UserA, $UserB) -Tier0Users @() -Tier1Users @($UserA) -SelectedDeviceIds @() -HomeTenantId 'home-tenant')
        $Warnings = [System.Collections.Generic.List[psobject]]::new()
        foreach ($Gap in $Gaps) { $Warnings.Add([pscustomobject]@{ Type = $Gap.Type; Message = $Gap.Message }) }

        $Summary = @(Show-EntraOpsWarningSummary -WarningMessages $Warnings -IncludeObjectDetails $false 6>&1) -join "`n"

        $Summary | Should -Match 'IntuneDeviceScopeSelectionGap:'
        $Summary | Should -Match '11111111-1111-1111-1111-111111111111'
        $Summary | Should -Match '22222222-2222-2222-2222-222222222222'
        $Summary | Should -Not -Match 'Private Admin Name|Control Plane user'
    }

    It 'handles null collections and missing optional properties under strict mode' {
        Set-StrictMode -Version Latest
        @(Get-EntraOpsIntuneDeviceScopeSelectionGap -PrivilegedObjects $null -Tier0Users $null -Tier1Users $null -SelectedDeviceIds $null -HomeTenantId $null).Count | Should -Be 0
        $SparseUser = [pscustomobject]@{ ObjectId = 'sparse-user'; ObjectType = 'user'; OwnedDevices = @('device-one') }
        @(Get-EntraOpsIntuneDeviceScopeSelectionGap -PrivilegedObjects @($SparseUser) -Tier0Users @() -Tier1Users @() -SelectedDeviceIds @() -HomeTenantId 'home-tenant').Count | Should -Be 1
    }
}
