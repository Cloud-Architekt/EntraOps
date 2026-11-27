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

Describe 'Update-EntraOpsClassificationControlPlaneScope during an Exposure Management outage' {
    BeforeAll {
        $script:TestRepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
        Import-Module (Join-Path $script:TestRepositoryRoot 'EntraOps') -Force
        $script:PreviousDefaultFolderClassification = $Global:DefaultFolderClassification
        $script:PreviousTenantNameContext = $Global:TenantNameContext
    }

    AfterAll {
        $Global:DefaultFolderClassification = $script:PreviousDefaultFolderClassification
        $Global:TenantNameContext = $script:PreviousTenantNameContext
    }

    BeforeEach {
        $Global:DefaultFolderClassification = Join-Path $TestDrive 'Classification'
        $Global:TenantNameContext = 'contoso.onmicrosoft.com'
        $script:TenantFolder = Join-Path $Global:DefaultFolderClassification $Global:TenantNameContext
        New-Item -Path $script:TenantFolder -ItemType Directory -Force | Out-Null
        $script:PreviousReasoning = '{ "PrivilegedObjects": [ { "ObjectId": "a", "ClassificationSource": [ "XSPM" ] } ] }'
        Set-Content -LiteralPath (Join-Path $script:TenantFolder 'ScopeReasoning_ControlPlane.json') -Value $script:PreviousReasoning
        Mock -ModuleName EntraOps Get-EntraOpsAzContextValue { '99999999-9999-9999-9999-999999999999' }
    }

    It 'keeps all previous classification files when Exposure Management results cannot be carried forward' {
        Mock -ModuleName EntraOps Get-EntraOpsClassificationControlPlaneObjects {
            param([hashtable]$ExposureManagementResult)
            $ExposureManagementResult['Status'] = 'Failed'
            $ExposureManagementResult['HasUnusablePreviousResults'] = $true
            $ExposureManagementResult['Warnings'] = @([pscustomobject]@{ Type = 'ExposureManagementUnavailable'; Message = 'Exposure Management query for Control Plane objects failed' })
            Write-Warning 'Exposure Management query for Control Plane objects failed'
        }

        $Output = Update-EntraOpsClassificationControlPlaneScope -ClassificationParameterScope 'EntraID' -WarningAction SilentlyContinue 6>&1 | Out-String

        $Output | Should -Match 'ExposureManagementScopeNotUpdated'
        $Output | Should -Match 'ExposureManagementUnavailable'
        Get-Content -LiteralPath (Join-Path $script:TenantFolder 'ScopeReasoning_ControlPlane.json') -Raw | Should -Be ($script:PreviousReasoning + [Environment]::NewLine)
        @(Get-ChildItem -LiteralPath $script:TenantFolder).Name | Should -Be @('ScopeReasoning_ControlPlane.json')
    }

    It 'names the RBAC systems without an EAM export once with -SkipMissingEamDataWarning (Skip: <Skip>)' -ForEach @(@{ Skip = $true }, @{ Skip = $false }) {
        # The outage ends the update early with the warnings summary, which shows how the missing exports are reported.
        Mock -ModuleName EntraOps Get-EntraOpsClassificationControlPlaneObjects {
            param([hashtable]$ExposureManagementResult)
            Write-Warning 'No privileged objects found for EntraID in EntraOps! File /eam/EntraID/EntraID.json not found.'
            Write-Warning 'No privileged objects found for Azure in EntraOps! File /eam/Azure/Azure.json not found.'
            Write-Warning 'No privileged objects found in EntraOps!'
            $ExposureManagementResult['Status'] = 'Failed'
            $ExposureManagementResult['HasUnusablePreviousResults'] = $true
            $ExposureManagementResult['Warnings'] = @()
        }

        $Output = Update-EntraOpsClassificationControlPlaneScope -ClassificationParameterScope 'EntraID' -SkipMissingEamDataWarning:$Skip -WarningAction SilentlyContinue 6>&1 | Out-String

        if ($Skip) {
            $Output | Should -Match ([regex]::Escape("No Privileged EAM export yet for EntraID, Azure: the Control Plane scope is refined from this run's export."))
            $Output | Should -Not -Match 'MissingEamData'
            $Output | Should -Not -Match 'No privileged objects found'
        } else {
            $Output | Should -Not -Match 'No Privileged EAM export yet'
            $Output | Should -Match 'MissingEamData'
            $Output | Should -Match 'No privileged objects found for Azure in EntraOps'
        }
    }
}

Describe 'Intune device scope selection gaps' {
    BeforeAll {
        $script:TestRepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
        . (Join-Path $script:TestRepositoryRoot 'EntraOps/Private/Get-EntraOpsIntuneDeviceScopeSelectionGap.ps1')
        . (Join-Path $script:TestRepositoryRoot 'EntraOps/Private/Get-EntraOpsPawDeviceObjectId.ps1')
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

Describe 'Update-EntraOpsClassificationControlPlaneScope deterministic scope output' {
    BeforeAll {
        $script:TestRepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
        $ScriptPath = Join-Path $script:TestRepositoryRoot 'EntraOps/Public/PrivilegedAccess/Update-EntraOpsClassificationControlPlaneScope.ps1'
        $script:ScriptContent = [System.IO.File]::ReadAllText($ScriptPath)
        $script:ScriptAst = [System.Management.Automation.Language.Parser]::ParseFile($ScriptPath, [ref]$null, [ref]$null)
    }

    It 'sorts Intune scope tag names before joining them' {
        # Graph returns role assignments in no fixed order; unsorted joins produced both 'Tier0.SAW, Tier1.SAW' and 'Tier1.SAW, Tier0.SAW'.
        $script:ScriptContent | Should -Not -Match ([regex]::Escape('Select-Object -Unique ScopeTagName | ForEach-Object { $_.ScopeTagName }) -join'))
        $SortedJoin = [regex]::Escape('ScopeTagNames    = (@($MatchedTags | ForEach-Object { "$($_.ScopeTagName)" }) | Sort-Object -Unique) -join '', ''')
        [regex]::Matches($script:ScriptContent, $SortedJoin).Count | Should -Be 2
    }

    It 'joins scope tag names in the same order regardless of input order' {
        $Expression = [regex]::Match($script:ScriptContent, 'ScopeTagNames    = (\(@\(\$MatchedTags[^\r\n]+)').Groups[1].Value
        $Expression | Should -Not -BeNullOrEmpty
        $Join = [scriptblock]::Create("param(`$MatchedTags) $Expression")
        $Forward = & $Join @([pscustomobject]@{ ScopeTagName = 'Tier0.SAW' }, [pscustomobject]@{ ScopeTagName = 'Tier1.SAW' }, [pscustomobject]@{ ScopeTagName = 'Tier0.SAW' })
        $Reverse = & $Join @([pscustomobject]@{ ScopeTagName = 'Tier1.SAW' }, [pscustomobject]@{ ScopeTagName = 'Tier0.SAW' })
        $Forward | Should -BeExactly 'Tier0.SAW, Tier1.SAW'
        $Reverse | Should -BeExactly $Forward
    }

    It 'writes the directory-level ScopeId of ScopeReasoning_EntraID.json as a string' {
        $script:ScriptContent | Should -Not -Match 'ScopeId\s*=\s*\$DirectoryLevelAssignmentScope'
        [regex]::Matches($script:ScriptContent, "ScopeId\s*=\s*'/'").Count | Should -Be 3
    }

    It 'de-duplicates DeviceManagement scope group IDs of groups that are both Tier0 and Tier1' {
        $DedupLoop = $script:ScriptAst.Find({
                param($Node)
                $Node -is [System.Management.Automation.Language.ForEachStatementAst] -and $Node.Variable.VariablePath.UserPath -eq 'DeviceMgmtTier'
            }, $true)
        $DedupLoop | Should -Not -BeNullOrEmpty

        $Template = Get-Content -Raw (Join-Path $script:TestRepositoryRoot 'Classification/Templates/Classification_DeviceManagement.Param.json')
        $Template = $Template.Replace('<Tier0IncludedGroupIds>', '"group-a", "group-b"').Replace('<Tier1IncludedGroupIds>', '"group-b", "group-c"')
        $DeviceMgmtRoleClassificationDefinition = @($Template | ConvertFrom-Json -Depth 10)
        . ([scriptblock]::Create($DedupLoop.Extent.Text))

        $Definitions = @($DeviceMgmtRoleClassificationDefinition.TierLevelDefinition)
        $Combined = @($Definitions | Where-Object { @($_.RoleAssignmentScopeName) -contains 'group-c' -or @($_.ExcludedRoleAssignmentScopeName) -contains 'group-c' })
        $Combined.Count | Should -BeGreaterThan 0
        foreach ($Definition in $Definitions) {
            foreach ($Property in 'RoleAssignmentScopeName', 'ExcludedRoleAssignmentScopeName') {
                $Values = @($Definition.$Property)
                @($Values | Select-Object -Unique).Count | Should -Be $Values.Count -Because "$($Definition.Service) $Property must not repeat group IDs"
                if ($Values -contains 'group-c') { @($Values | Where-Object { $_ -like 'group-*' }) | Should -Be @('group-a', 'group-b', 'group-c') }
            }
        }
        # Arrays stay arrays (also with a single entry) so the JSON shape of the template is unchanged.
        $Json = $DeviceMgmtRoleClassificationDefinition | ConvertTo-Json -Depth 10
        $Json | Should -Match '"RoleAssignmentScopeName": \[\s*("/",\s*)?"group-a",\s*"group-b",\s*"group-c"\s*\]'
        $Json | Should -Not -Match '"RoleAssignmentScopeName": "'
    }
}
