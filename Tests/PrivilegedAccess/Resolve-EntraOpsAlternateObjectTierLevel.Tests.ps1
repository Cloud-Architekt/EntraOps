#Requires -Modules Pester

BeforeAll {
    $script:TestRepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
    function Invoke-EntraOpsMsGraphQuery {
        param($Method, $Uri, $OutputType, $Body, [switch]$SuppressNotFoundWarning, [switch]$ThrowOnFailure, [switch]$DisableCache, $WarningAction, $ConsistencyLevel)
        throw 'Invoke-EntraOpsMsGraphQuery must be mocked'
    }

    . "$script:TestRepositoryRoot/EntraOps/Private/Test-EntraOpsCustomSecurityAttributeClassificationEnabled.ps1"
    . "$script:TestRepositoryRoot/EntraOps/Private/Test-EntraOpsAlternateObjectTierLevelEnabled.ps1"
    . "$script:TestRepositoryRoot/EntraOps/Private/Resolve-EntraOpsAlternateObjectTierLevel.ps1"
    . "$script:TestRepositoryRoot/EntraOps/Public/PrivilegedAccess/Get-EntraOpsPrivilegedEntraObject.ps1"

    $script:GroupFilters = [pscustomobject]@{
        Enabled = $false
        Group   = [pscustomobject]@{
            ControlPlane    = '$Object.AssignedAdministrativeUnits.displayName -contains "Tier0-ControlPlane.EntraID"'
            ManagementPlane = '$Object.ObjectDisplayName -like "PRG-Tier1-*"'
            UserAccess      = ''
        }
    }
}

Describe 'Resolve-EntraOpsAlternateObjectTierLevel for groups' {
    It 'classifies a group by Group filters even when Enabled is false' {
        $Object = [pscustomobject]@{ ObjectId = '1'; ObjectDisplayName = 'PRG-Tier1-Admins'; AssignedAdministrativeUnits = @() }

        $Result = Resolve-EntraOpsAlternateObjectTierLevel -ObjectType Group -Object $Object -AlternateObjectTierLevelAttributes $script:GroupFilters -WarningAction SilentlyContinue

        $Result.AdminTierLevel | Should -Be '1'
        $Result.AdminTierLevelName | Should -Be 'ManagementPlane'
    }

    It 'lets the most privileged matching tier win' {
        $Object = [pscustomobject]@{ ObjectId = '1'; ObjectDisplayName = 'PRG-Tier1-Admins'; AssignedAdministrativeUnits = @([pscustomobject]@{ id = 'a'; displayName = 'Tier0-ControlPlane.EntraID' }) }

        $Result = Resolve-EntraOpsAlternateObjectTierLevel -ObjectType Group -Object $Object -AlternateObjectTierLevelAttributes $script:GroupFilters -WarningAction SilentlyContinue

        $Result.AdminTierLevelName | Should -Be 'ControlPlane'
    }

    It 'returns Unclassified when Group filters are defined but none match' {
        $Object = [pscustomobject]@{ ObjectId = '1'; ObjectDisplayName = 'Other'; AssignedAdministrativeUnits = @() }

        $Result = Resolve-EntraOpsAlternateObjectTierLevel -ObjectType Group -Object $Object -AlternateObjectTierLevelAttributes $script:GroupFilters -WarningAction SilentlyContinue

        $Result.AdminTierLevelName | Should -Be 'Unclassified'
    }

    It 'returns $null when no Group filter is defined' {
        $Config = [pscustomobject]@{
            Enabled = $true
            User    = [pscustomobject]@{ ControlPlane = '$true' }
            Group   = [pscustomobject]@{ ControlPlane = ''; ManagementPlane = ''; UserAccess = '' }
        }
        $Object = [pscustomobject]@{ ObjectId = '1'; ObjectDisplayName = 'Any' }

        Resolve-EntraOpsAlternateObjectTierLevel -ObjectType Group -Object $Object -AlternateObjectTierLevelAttributes $Config | Should -BeNullOrEmpty
        Resolve-EntraOpsAlternateObjectTierLevel -ObjectType Group -Object $Object -AlternateObjectTierLevelAttributes ([pscustomobject]@{ Enabled = $true }) | Should -BeNullOrEmpty
    }

    It 'keeps User classification gated by Enabled' {
        $Config = [pscustomobject]@{
            Enabled = $false
            User    = [pscustomobject]@{ ControlPlane = '$true' }
        }
        $Object = [pscustomobject]@{ ObjectId = '1'; ObjectDisplayName = 'Any' }

        Resolve-EntraOpsAlternateObjectTierLevel -ObjectType User -Object $Object -AlternateObjectTierLevelAttributes $Config | Should -BeNullOrEmpty
    }
}

Describe 'Alternate Tier Level Attributes enabled per object type' {
    BeforeAll {
        $script:Object = [pscustomobject]@{ ObjectId = '1'; ObjectDisplayName = 'PRG-Tier1-Admins'; AssignedAdministrativeUnits = @() }
    }

    It 'classifies only the object types whose Enabled is true' {
        $Config = [pscustomobject]@{
            User             = [pscustomobject]@{ Enabled = $true; ControlPlane = '$true' }
            ServicePrincipal = [pscustomobject]@{ Enabled = $false; ControlPlane = '$true' }
            Group            = [pscustomobject]@{ Enabled = $true; ManagementPlane = '$Object.ObjectDisplayName -like "PRG-Tier1-*"' }
        }

        (Resolve-EntraOpsAlternateObjectTierLevel -ObjectType User -Object $script:Object -AlternateObjectTierLevelAttributes $Config -WarningAction SilentlyContinue).AdminTierLevelName | Should -Be 'ControlPlane'
        Resolve-EntraOpsAlternateObjectTierLevel -ObjectType ServicePrincipal -Object $script:Object -AlternateObjectTierLevelAttributes $Config | Should -BeNullOrEmpty
        (Resolve-EntraOpsAlternateObjectTierLevel -ObjectType Group -Object $script:Object -AlternateObjectTierLevelAttributes $Config -WarningAction SilentlyContinue).AdminTierLevelName | Should -Be 'ManagementPlane'
    }

    It 'lets the per-type Enabled win over the legacy top-level Enabled and Group filter presence' {
        $Config = [pscustomobject]@{
            Enabled = $true
            User    = [pscustomobject]@{ Enabled = $false; ControlPlane = '$true' }
            Group   = [pscustomobject]@{ Enabled = $false; ControlPlane = '$true' }
        }

        Test-EntraOpsAlternateObjectTierLevelEnabled -ObjectType User -AlternateObjectTierLevelAttributes $Config | Should -BeFalse
        Test-EntraOpsAlternateObjectTierLevelEnabled -ObjectType ServicePrincipal -AlternateObjectTierLevelAttributes $Config | Should -BeTrue
        Test-EntraOpsAlternateObjectTierLevelEnabled -ObjectType Group -AlternateObjectTierLevelAttributes $Config | Should -BeFalse
    }

    It 'returns $false without configuration' {
        Test-EntraOpsAlternateObjectTierLevelEnabled -ObjectType User -AlternateObjectTierLevelAttributes $null | Should -BeFalse
    }

    It 'warns and returns Unclassified when an object type is enabled without filters' {
        $Config = [pscustomobject]@{ Group = [pscustomobject]@{ Enabled = $true; ControlPlane = ''; ManagementPlane = ''; UserAccess = '' } }

        $Result = Resolve-EntraOpsAlternateObjectTierLevel -ObjectType Group -Object $script:Object -AlternateObjectTierLevelAttributes $Config -WarningVariable Warnings -WarningAction SilentlyContinue

        $Result.AdminTierLevelName | Should -Be 'Unclassified'
        ($Warnings -join ' ') | Should -Match "enabled for object type 'Group' but no filter expression"
    }
}

Describe 'Get-EntraOpsPrivilegedEntraObject group classification' {
    BeforeEach {
        $global:TenantIdContext = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
        $global:EntraOpsConfig = [pscustomobject]@{
            CustomSecurityAttributes           = [pscustomobject]@{}
            AlternateObjectTierLevelAttributes = $null
        }
        $script:GroupId = '55555555-5555-5555-5555-555555555555'

        Mock Invoke-EntraOpsMsGraphQuery {
            if ($Uri -like "/beta/directoryObjects/$script:GroupId?*") {
                return [pscustomobject]@{
                    '@odata.type'          = '#microsoft.graph.group'
                    id                     = $script:GroupId
                    displayName            = 'PRG-Tier1-Admins'
                    isAssignableToRole     = $false
                    isManagementRestricted = $false
                }
            }
            if ($Uri -like '*/memberOf/microsoft.graph.administrativeUnit*') {
                return [pscustomobject]@{ id = 'au-1'; displayName = 'Tier0-ControlPlane.EntraID' }
            }
            return @()
        }
    }

    It 'classifies a group by Group filters' {
        $Result = Get-EntraOpsPrivilegedEntraObject -AadObjectId $script:GroupId -TenantId $global:TenantIdContext `
            -AlternateObjectTierLevelAttributes $script:GroupFilters -WarningAction SilentlyContinue

        $Result.ObjectType | Should -Be 'group'
        $Result.AdminTierLevel | Should -Be '0'
        $Result.AdminTierLevelName | Should -Be 'ControlPlane'
    }

    It 'keeps a group Unclassified without Group filters' {
        $Result = Get-EntraOpsPrivilegedEntraObject -AadObjectId $script:GroupId -TenantId $global:TenantIdContext `
            -AlternateObjectTierLevelAttributes ([pscustomobject]@{ Enabled = $true })

        $Result.AdminTierLevel | Should -Be 'Unclassified'
        $Result.AdminTierLevelName | Should -Be 'Unclassified'
    }
}
