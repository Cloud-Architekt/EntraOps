#Requires -Modules Pester

BeforeDiscovery {
    $script:TestRepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
}

BeforeAll {
    $script:TestRepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
    function Get-AzContext { throw "Get-AzContext must be mocked" }
    function Invoke-EntraOpsMsGraphQuery {
        param($Method, $Uri, $OutputType, $Body, [switch]$DisableCache, [switch]$ThrowOnFailure, [switch]$SuppressNotFoundWarning)
        throw "Invoke-EntraOpsMsGraphQuery must be mocked"
    }
    function Select-EntraOpsUniqueGraphObject {
        param($InputObject, $ObjectDescription, [switch]$AllowNotFound)
        throw "Select-EntraOpsUniqueGraphObject must be mocked"
    }
    function ConvertTo-EntraOpsODataStringLiteral { param($Value) return $Value }
    function Show-EntraOpsWarningSummary { param($WarningMessages) }

    . "$script:TestRepositoryRoot/EntraOps/Private/Test-EntraOpsRemovalSafetyThreshold.ps1"
    . "$script:TestRepositoryRoot/EntraOps/Public/PrivilegedAccess/Update-EntraOpsPrivilegedUnprotectedAdministrativeUnit.ps1"
}

Describe "Update-EntraOpsPrivilegedUnprotectedAdministrativeUnit removal safety" {
    BeforeEach {
        $global:DefaultFolderClassifiedEam = "/classified"
        $global:DefaultFolderClassification = "/classification"
        $script:CurrentMembers = [System.Collections.Generic.List[psobject]]::new()
        1..4 | ForEach-Object {
            $script:CurrentMembers.Add([pscustomobject]@{
                    id            = "stale-$_"
                    displayName   = "Stale $_"
                    '@odata.type' = '#microsoft.graph.user'
                })
        }

        Mock Get-AzContext { [pscustomobject]@{ Tenant = [pscustomobject]@{ Id = 'tenant-1' } } }
        Mock Get-ChildItem { [pscustomobject]@{ FullName = '/classification/ControlPlane.json' } }
        Mock Get-Content {
            if ($Path -like '/classified/*') {
                return '{"ObjectId":"desired-1","ObjectType":"User","RestrictedManagementByRAG":false,"RestrictedManagementByAadRole":false,"RestrictedManagementByRMAU":false,"Classification":{"AdminTierLevel":0,"AdminTierLevelName":"ControlPlane"}}'
            }
            return '{"EAMTierLevelName":"ControlPlane","EAMTierLevelTagValue":0}'
        }
        Mock Select-EntraOpsUniqueGraphObject { [pscustomobject]@{ id = 'au-1' } }
        Mock Show-EntraOpsWarningSummary {}
        Mock Invoke-EntraOpsMsGraphQuery {
            if ($Uri.StartsWith('/beta/administrativeUnits?$filter=')) {
                return [pscustomobject]@{ id = 'au-1'; displayName = 'Tier0-ControlPlane.UnprotectedObjects' }
            }
            if ($Uri -eq '/beta/administrativeUnits/au-1/members') {
                return $script:CurrentMembers.ToArray()
            }
            if ($Uri -eq '/beta/directoryObjects/desired-1') {
                return [pscustomobject]@{ id = 'desired-1'; displayName = 'Desired'; '@odata.type' = '#microsoft.graph.user' }
            }
            if ($Method -eq 'POST' -and $Uri -eq '/beta/administrativeUnits/au-1/members/$ref') {
                $script:CurrentMembers.Add([pscustomobject]@{ id = 'desired-1'; displayName = 'Desired'; '@odata.type' = '#microsoft.graph.user' })
                return
            }
            throw "Unexpected Graph request: $Method $Uri"
        }
    }

    It "does not erode an oversized removal plan across repeated runs and still applies additions" {
        1..2 | ForEach-Object {
            { Update-EntraOpsPrivilegedUnprotectedAdministrativeUnit -RbacSystems EntraID } | Should -Throw '*removal safety*'
        }

        Should -Invoke Invoke-EntraOpsMsGraphQuery -Times 0 -Exactly -ParameterFilter { $Method -eq 'DELETE' }
        Should -Invoke Invoke-EntraOpsMsGraphQuery -Times 1 -Exactly -ParameterFilter {
            $Method -eq 'POST' -and $Uri -eq '/beta/administrativeUnits/au-1/members/$ref'
        }
        $script:CurrentMembers.Count | Should -Be 5
    }
}
