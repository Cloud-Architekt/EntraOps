#Requires -Modules Pester

BeforeAll {
    $script:TestRepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
    Import-Module (Join-Path $script:TestRepositoryRoot 'EntraOps') -Force
    $script:PreviousDefaultFolderClassification = $Global:DefaultFolderClassification
    $script:PreviousTenantNameContext = $Global:TenantNameContext

    $script:UserId = '11111111-1111-1111-1111-111111111111'
    $script:TenantId = '99999999-9999-9999-9999-999999999999'

    function New-EamFixture {
        param([string]$Root, [bool]$RestrictedManagementByRMAU = $false)

        foreach ($RoleSystem in @('EntraID', 'Azure')) {
            $Folder = Join-Path $Root $RoleSystem
            New-Item -Path $Folder -ItemType Directory -Force | Out-Null
            @(
                [ordered]@{
                    ObjectId                      = $script:UserId
                    ObjectType                    = 'user'
                    ObjectSubType                 = 'Member'
                    ObjectDisplayName             = 'Admin User'
                    ObjectUserPrincipalName       = 'admin@contoso.onmicrosoft.com'
                    ObjectTenantId                = $script:TenantId
                    ObjectAdminTierLevel          = 'Unclassified'
                    ObjectAdminTierLevelName      = 'Unclassified'
                    RoleSystem                    = $RoleSystem
                    AssignedAdministrativeUnits   = @([ordered]@{ id = 'aaaaaaaa-0000-0000-0000-000000000001'; displayName = 'AU1' })
                    RestrictedManagementByRAG     = $false
                    RestrictedManagementByAadRole = $false
                    RestrictedManagementByRMAU    = $RestrictedManagementByRMAU
                    OwnedDevices                  = @()
                    AssociatedPawDevice           = @()
                    Classification                = @([ordered]@{ AdminTierLevel = '0'; AdminTierLevelName = 'ControlPlane'; Service = 'Test' })
                    RoleAssignments               = @()
                }
            ) | ConvertTo-Json -Depth 10 -AsArray | Set-Content -LiteralPath (Join-Path $Folder "$RoleSystem.json")
        }
    }

    function Invoke-ControlPlaneObjects {
        param([string]$EamRoot, [bool]$LiveRestrictedManagementByRMAU)

        $Global:DefaultFolderClassification = Join-Path $TestDrive 'Classification'
        $Global:TenantNameContext = 'contoso.onmicrosoft.com'
        $script:LiveRestrictedManagementByRMAU = $LiveRestrictedManagementByRMAU

        Mock -ModuleName EntraOps Invoke-EntraOpsAzGraphQuery {
            @([pscustomobject]@{ PrincipalId = '11111111-1111-1111-1111-111111111111'; PrincipalType = 'user'; RoleScope = '/'; RoleName = 'Owner' })
        }
        Mock -ModuleName EntraOps Invoke-EntraOpsParallelObjectResolution {
            @{
                '11111111-1111-1111-1111-111111111111' = [pscustomobject]@{
                    ObjectId                      = '11111111-1111-1111-1111-111111111111'
                    ObjectType                    = 'User'
                    ObjectSubType                 = 'Member'
                    ObjectDisplayName             = 'Admin User'
                    ObjectSignInName              = 'admin@contoso.onmicrosoft.com'
                    ObjectTenantId                = '99999999-9999-9999-9999-999999999999'
                    AssignedAdministrativeUnits   = @([pscustomobject]@{ id = 'aaaaaaaa-0000-0000-0000-000000000002'; displayName = 'AU2' })
                    RestrictedManagementByRAG     = $false
                    RestrictedManagementByAadRole = $false
                    RestrictedManagementByRMAU    = $script:LiveRestrictedManagementByRMAU
                    OwnedDevices                  = @('dddddddd-0000-0000-0000-000000000001')
                    AssociatedPawDevice           = $null
                }
            }
        }

        @(Get-EntraOpsClassificationControlPlaneObjects `
                -PrivilegedObjectClassificationSource 'All' `
                -EntraOpsEamFolder $EamRoot `
                -EntraOpsScopes @('EntraID', 'Azure') `
                -TenantId $script:TenantId `
                -EnableParallelProcessing $false 6>$null 3>$null)
    }

    function New-ManualMergeSource {
        param([object]$Protection = $null, [object[]]$AdministrativeUnits = @(), [switch]$MissingProtectionFlags, [string]$DisplayName = 'Admin User')

        $Source = [pscustomobject]@{
            ObjectId                      = $script:UserId
            ObjectType                    = 'User'
            ObjectSubType                 = 'Member'
            ObjectDisplayName             = $DisplayName
            ObjectSignInName              = 'admin@contoso.onmicrosoft.com'
            ObjectTenantId                = $script:TenantId
            AssignedAdministrativeUnits   = $AdministrativeUnits
            RestrictedManagementByAadRole = $Protection
            RestrictedManagementByRAG     = $Protection
            RestrictedManagementByRMAU    = $Protection
            OwnedDevices                  = @('device-one')
            AssociatedPawDevice           = @('paw-one')
        }
        if ($MissingProtectionFlags) {
            foreach ($Name in @('RestrictedManagementByAadRole', 'RestrictedManagementByRAG', 'RestrictedManagementByRMAU')) {
                $Source.PSObject.Properties.Remove($Name)
            }
        }
        $Source
    }

    function Invoke-ManualIdentityMerge {
        param([object[]]$Sources)

        $Global:DefaultFolderClassification = Join-Path $TestDrive 'Classification'
        $Global:TenantNameContext = 'contoso.onmicrosoft.com'
        $script:ManualSources = @{}
        $Ids = @(for ($Index = 0; $Index -lt $Sources.Count; $Index++) {
                $Id = 'aaaaaaaa-0000-0000-0000-{0:D12}' -f $Index
                $script:ManualSources[$Id] = $Sources[$Index]
                $Id
            })
        Mock -ModuleName EntraOps Get-EntraOpsPrivilegedEntraObject {
            param($AadObjectId)
            $script:ManualSources[$AadObjectId]
        }
        $script:MergeWarnings = @()
        $MergeResult = InModuleScope EntraOps -Parameters @{ Ids = $Ids; TenantId = $script:TenantId } {
            param($Ids, $TenantId)
            Set-StrictMode -Version Latest
            $Objects = @(Get-EntraOpsClassificationControlPlaneObjects -PrivilegedObjectClassificationSource PrivilegedObjectIds -PrivilegedObjectIds $Ids -EntraOpsEamFolder '' -TenantId $TenantId -WarningVariable Warnings -WarningAction SilentlyContinue 6>$null)
            [pscustomobject]@{ Objects = $Objects; Warnings = @($Warnings) }
        }
        $script:MergeWarnings = @($MergeResult.Warnings)
        $MergeResult.Objects
    }
}

AfterAll {
    $Global:DefaultFolderClassification = $script:PreviousDefaultFolderClassification
    $Global:TenantNameContext = $script:PreviousTenantNameContext
}

Describe 'Get-EntraOpsClassificationControlPlaneObjects identity merge' {
    BeforeEach {
        # The Exposure Management source is not under test.
        Mock -ModuleName EntraOps Invoke-EntraOpsMsGraphQuery { [pscustomobject]@{ results = $null } }
    }

    It 'returns one entry per identity across EntraOps exports and live sources' {
        $EamRoot = Join-Path $TestDrive 'eam-merge'
        New-EamFixture -Root $EamRoot -RestrictedManagementByRMAU $false

        $Result = Invoke-ControlPlaneObjects -EamRoot $EamRoot -LiveRestrictedManagementByRMAU $true

        $Result.Count | Should -Be 1
        $Result[0].ObjectId | Should -Be $script:UserId
        $Result[0].ObjectType | Should -Be 'user'
        @($Result[0].AssignedAdministrativeUnits.id) | Should -Be @('aaaaaaaa-0000-0000-0000-000000000001', 'aaaaaaaa-0000-0000-0000-000000000002')
        ($Result[0].AssignedAdministrativeUnits -is [object[]]) | Should -BeTrue
        @($Result[0].OwnedDevices) | Should -Be @('dddddddd-0000-0000-0000-000000000001')
        @($Result[0].Classification.ClassificationSource | Sort-Object -Unique) | Should -Be @('Azure Resource Graph', 'EntraOps')
    }

    It 'treats conflicting protection flags as unprotected (fail safe)' {
        $EamRoot = Join-Path $TestDrive 'eam-conflict'
        New-EamFixture -Root $EamRoot -RestrictedManagementByRMAU $false

        $Result = Invoke-ControlPlaneObjects -EamRoot $EamRoot -LiveRestrictedManagementByRMAU $true

        $Result[0].RestrictedManagementByRMAU | Should -BeFalse
    }

    It 'keeps protection when every source reports it' {
        $EamRoot = Join-Path $TestDrive 'eam-protected'
        New-EamFixture -Root $EamRoot -RestrictedManagementByRMAU $true

        $Result = Invoke-ControlPlaneObjects -EamRoot $EamRoot -LiveRestrictedManagementByRMAU $true

        $Result[0].RestrictedManagementByRMAU | Should -BeTrue
    }

    It 'produces deterministic output across reversed EntraOps scope order' {
        $EamRoot = Join-Path $TestDrive 'eam-deterministic'
        New-EamFixture -Root $EamRoot

        $First = Invoke-ControlPlaneObjects -EamRoot $EamRoot -LiveRestrictedManagementByRMAU $false | ConvertTo-Json -Depth 8 -Compress
        $Second = Get-EntraOpsClassificationControlPlaneObjects -PrivilegedObjectClassificationSource All -EntraOpsEamFolder $EamRoot -EntraOpsScopes @('Azure', 'EntraID') -TenantId $script:TenantId -EnableParallelProcessing $false 6>$null 3>$null | ConvertTo-Json -Depth 8 -Compress

        $Second | Should -Be $First
    }

    It 'preserves a single administrative unit as an object array' {
        $Units = @([pscustomobject]@{ id = 'au-one'; displayName = 'One AU' })
        $Result = @(Invoke-ManualIdentityMerge -Sources @(New-ManualMergeSource -AdministrativeUnits $Units))

        ($Result[0].AssignedAdministrativeUnits -is [object[]]) | Should -BeTrue
        $Result[0].AssignedAdministrativeUnits.Count | Should -Be 1
        $RoundTrip = $Result[0] | ConvertTo-Json -Depth 8 | ConvertFrom-Json
        ($RoundTrip.AssignedAdministrativeUnits -is [object[]]) | Should -BeTrue
    }

    It 'returns null administrative units when none are assigned' {
        $Result = @(Invoke-ManualIdentityMerge -Sources @(New-ManualMergeSource))

        $Result[0].AssignedAdministrativeUnits | Should -BeNullOrEmpty
        ($null -eq $Result[0].AssignedAdministrativeUnits) | Should -BeTrue
    }

    It 'treats true plus null as unknown and warns about each conflicting flag' {
        $Result = @(Invoke-ManualIdentityMerge -Sources @(
                New-ManualMergeSource -Protection $true
                New-ManualMergeSource -Protection $null
            ))

        foreach ($Name in @('RestrictedManagementByAadRole', 'RestrictedManagementByRAG', 'RestrictedManagementByRMAU')) {
            ($null -eq $Result[0].$Name) | Should -BeTrue
            ($Result[0].$Name -ne $true) | Should -BeTrue
            @($script:MergeWarnings | Where-Object { $_.Message -like "Conflicting $Name values*" }).Count | Should -Be 1
        }
    }

    It 'treats missing protection flags as unknown under strict mode' {
        $Result = @(Invoke-ManualIdentityMerge -Sources @(New-ManualMergeSource -MissingProtectionFlags))

        $Result.Count | Should -Be 1
        foreach ($Name in @('RestrictedManagementByAadRole', 'RestrictedManagementByRAG', 'RestrictedManagementByRMAU')) {
            ($null -eq $Result[0].$Name) | Should -BeTrue
        }
        $script:MergeWarnings.Count | Should -Be 0
    }

    It 'warns and returns unknown when protected and missing-flag sources disagree under strict mode' {
        $Result = @(Invoke-ManualIdentityMerge -Sources @(
                New-ManualMergeSource -Protection $true
                New-ManualMergeSource -MissingProtectionFlags
            ))

        foreach ($Name in @('RestrictedManagementByAadRole', 'RestrictedManagementByRAG', 'RestrictedManagementByRMAU')) {
            ($null -eq $Result[0].$Name) | Should -BeTrue
            @($script:MergeWarnings | Where-Object { $_.Message -like "Conflicting $Name values*" }).Count | Should -Be 1
        }
    }

    It 'tolerates missing optional scalar and collection metadata under strict mode' {
        $Source = New-ManualMergeSource
        $OptionalNames = @('ObjectSubType', 'ObjectDisplayName', 'ObjectSignInName', 'ObjectTenantId', 'OwnedDevices', 'AssociatedPawDevice', 'AssignedAdministrativeUnits')
        foreach ($Name in $OptionalNames) { $Source.PSObject.Properties.Remove($Name) }

        $Result = @(Invoke-ManualIdentityMerge -Sources @($Source))

        $Result.Count | Should -Be 1
        foreach ($Name in $OptionalNames) { ($null -eq $Result[0].$Name) | Should -BeTrue }
    }

    It 'retains metadata from complete sources when another source lacks optional properties under strict mode' {
        $IncompleteSource = New-ManualMergeSource
        $OptionalNames = @('ObjectSubType', 'ObjectSignInName', 'ObjectTenantId', 'OwnedDevices', 'AssociatedPawDevice', 'AssignedAdministrativeUnits')
        foreach ($Name in $OptionalNames) { $IncompleteSource.PSObject.Properties.Remove($Name) }
        $CompleteSource = New-ManualMergeSource -AdministrativeUnits @([pscustomobject]@{ id = 'au-one'; displayName = 'One AU' })

        $Result = @(Invoke-ManualIdentityMerge -Sources @($IncompleteSource, $CompleteSource))

        $Result[0].ObjectSubType | Should -Be 'Member'
        $Result[0].ObjectSignInName | Should -Be 'admin@contoso.onmicrosoft.com'
        $Result[0].ObjectTenantId | Should -Be $script:TenantId
        ($Result[0].OwnedDevices -is [object[]]) | Should -BeTrue
        $Result[0].OwnedDevices | Should -Be @('device-one')
        ($Result[0].AssociatedPawDevice -is [object[]]) | Should -BeTrue
        $Result[0].AssociatedPawDevice | Should -Be @('paw-one')
        ($Result[0].AssignedAdministrativeUnits -is [object[]]) | Should -BeTrue
        $Result[0].AssignedAdministrativeUnits.id | Should -Be 'au-one'
    }

    It 'merges conflicting metadata independently of source arrival order' {
        $Sources = @(
            New-ManualMergeSource -Protection $true -DisplayName 'Older Name' -AdministrativeUnits @([pscustomobject]@{ id = 'au-one'; displayName = 'One AU' })
            New-ManualMergeSource -Protection $null -DisplayName 'Current Name' -AdministrativeUnits @([pscustomobject]@{ id = 'au-two'; displayName = 'Two AU' })
        )
        $First = Invoke-ManualIdentityMerge -Sources $Sources | ConvertTo-Json -Depth 8 -Compress
        $Second = Invoke-ManualIdentityMerge -Sources @($Sources[1], $Sources[0]) | ConvertTo-Json -Depth 8 -Compress

        $Second | Should -Be $First
    }
}
