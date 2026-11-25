#Requires -Modules Pester

BeforeDiscovery {
    $script:TestRepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
}

BeforeAll {
    $script:TestRepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
    function Invoke-EntraOpsMsGraphQuery {
        param($Method, $Uri, $OutputType, $Body, [switch]$SuppressNotFoundWarning, [switch]$ThrowOnFailure, [switch]$DisableCache, $WarningAction)
        throw 'Invoke-EntraOpsMsGraphQuery must be mocked'
    }

    . "$script:TestRepositoryRoot/EntraOps/Private/Test-EntraOpsCustomSecurityAttributeClassificationEnabled.ps1"
    . "$script:TestRepositoryRoot/EntraOps/Private/Test-EntraOpsAlternateObjectTierLevelEnabled.ps1"
    . "$script:TestRepositoryRoot/EntraOps/Public/PrivilegedAccess/Get-EntraOpsPrivilegedEntraObject.ps1"
    . "$script:TestRepositoryRoot/EntraOps/Private/Resolve-EntraOpsObjectOrigin.ps1"
    . "$script:TestRepositoryRoot/EntraOps/Private/Get-EntraOpsObjectOriginTenantInfo.ps1"
    . "$script:TestRepositoryRoot/EntraOps/Private/Findings/Test-EntraOpsMicrosoftFirstParty.ps1"
}

Describe 'Get-EntraOpsPrivilegedEntraObject resolution status' {
    BeforeEach {
        $global:TenantIdContext = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
        $global:EntraOpsConfig = [pscustomobject]@{
            CustomSecurityAttributes           = [pscustomobject]@{}
            AlternateObjectTierLevelAttributes = $null
        }

        Mock Invoke-EntraOpsMsGraphQuery {
            $Exception = [System.InvalidOperationException]::new("Microsoft Graph query '$Uri' failed")
            $Exception.Data['StatusCode'] = 404
            throw $Exception
        }
    }

    It 'marks the orphan as not found only after both identity endpoints return 404' {
        $ObjectId = 'dddddddd-dddd-dddd-dddd-dddddddddddd'

        $Result = Get-EntraOpsPrivilegedEntraObject -AadObjectId $ObjectId -TenantId $global:TenantIdContext

        $Result.ObjectId | Should -Be $ObjectId
        $Result.ObjectType | Should -Be 'unknown'
        $Result.ResolutionStatus | Should -Be 'NotFound'
        Should -Invoke Invoke-EntraOpsMsGraphQuery -Times 1 -Exactly -ParameterFilter {
            $Uri -like '/beta/directoryObjects/*' -and $SuppressNotFoundWarning -and $ThrowOnFailure
        }
        Should -Invoke Invoke-EntraOpsMsGraphQuery -Times 1 -Exactly -ParameterFilter {
            $Uri -like '/beta/users/*' -and $SuppressNotFoundWarning -and $ThrowOnFailure
        }
        Should -Invoke Invoke-EntraOpsMsGraphQuery -Times 2 -Exactly
    }

    It 'does not mark a principal as not found when the directory lookup returns 403' {
        Mock Invoke-EntraOpsMsGraphQuery {
            if ($Uri -like '/beta/directoryObjects/*' -and $ThrowOnFailure) {
                $Exception = [System.InvalidOperationException]::new("Microsoft Graph query '$Uri' failed")
                $Exception.Data['StatusCode'] = 403
                throw $Exception
            }
            if ($Uri -like '/beta/users/*') {
                $Exception = [System.InvalidOperationException]::new("Microsoft Graph query '$Uri' failed")
                $Exception.Data['StatusCode'] = 404
                throw $Exception
            }
            return @()
        }

        $Result = Get-EntraOpsPrivilegedEntraObject -AadObjectId '33333333-3333-3333-3333-333333333333' -TenantId $global:TenantIdContext

        $Result.ResolutionStatus | Should -Be 'Unresolved'
    }

    It 'keeps the tenant of a Tenant Governance principal that is not found in this tenant' {
        $ObjectId = '55555555-5555-5555-5555-555555555555'
        Mock Invoke-EntraOpsMsGraphQuery {
            if ($Uri -eq '/beta/directory/remoteTenantGroups') {
                return @([pscustomobject]@{ id = 'r1'; remoteGroupId = '66666666-6666-6666-6666-666666666666'; remoteTenantId = 'cccccccc-cccc-cccc-cccc-cccccccccccc'; remoteGroupDisplayName = 'Other remote group' })
            }
            $Exception = [System.InvalidOperationException]::new("Microsoft Graph query '$Uri' failed")
            $Exception.Data['StatusCode'] = 404
            throw $Exception
        }

        $Result = Get-EntraOpsPrivilegedEntraObject -AadObjectId $ObjectId -TenantId $global:TenantIdContext `
            -IsForeignPrincipal -ForeignTenantId 'BBBBBBBB-BBBB-BBBB-BBBB-BBBBBBBBBBBB' 6>$null

        $Result.ObjectId | Should -Be $ObjectId
        $Result.ObjectType | Should -Be 'unknown'
        $Result.ObjectDisplayName | Should -Be 'Identity not found'
        # The tenant of its role assignment, not the home tenant, so the findings report it as an object of another tenant.
        $Result.ObjectTenantId | Should -Be 'BBBBBBBB-BBBB-BBBB-BBBB-BBBBBBBBBBBB'
        $Result.OutsideOfHomeTenant | Should -BeTrue
        $Result.OriginType | Should -Be 'TenantGovernance'
        $Result.OriginTenantId | Should -Be 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb'
        $Result.OriginId | Should -Be $ObjectId
        # A foreign principal is not probed at /users.
        Should -Invoke Invoke-EntraOpsMsGraphQuery -Times 0 -Exactly -ParameterFilter { $Uri -like '/beta/users/*' }
    }

    It 'marks a Tenant Governance principal that is not found as of Tenant Governance also without its tenant' {
        Mock Invoke-EntraOpsMsGraphQuery {
            if ($Uri -eq '/beta/directory/remoteTenantGroups') { return @() }
            $Exception = [System.InvalidOperationException]::new("Microsoft Graph query '$Uri' failed")
            $Exception.Data['StatusCode'] = 404
            throw $Exception
        }

        $Result = Get-EntraOpsPrivilegedEntraObject -AadObjectId '77777777-7777-7777-7777-777777777777' -TenantId $global:TenantIdContext -IsForeignPrincipal 6>$null

        $Result.ObjectTenantId | Should -Be $global:TenantIdContext
        $Result.OriginType | Should -Be 'TenantGovernance'
        $Result.OriginTenantId | Should -BeNullOrEmpty
    }

    It 'classifies an unhandled directory object type as unknown and identifies it in a warning' {
        $ObjectId = '44444444-4444-4444-4444-444444444444'
        Mock Invoke-EntraOpsMsGraphQuery {
            if ($Uri -like "/beta/directoryObjects/$ObjectId?*") {
                return [pscustomobject]@{
                    '@odata.type' = '#microsoft.graph.futureIdentity'
                    id            = $ObjectId
                    displayName   = 'Future identity'
                }
            }
            return @()
        }

        $Warnings = @()
        $Result = Get-EntraOpsPrivilegedEntraObject -AadObjectId $ObjectId `
            -TenantId $global:TenantIdContext -WarningVariable Warnings

        $Result.ObjectType | Should -Be 'unknown'
        $Result.ObjectSubType | Should -Be 'unknown'
        # The object exists, so the aggregation must not turn it into a fail-closed placeholder
        $Result.ResolutionStatus | Should -Be 'UnhandledType'
        $Warnings | Should -HaveCount 1
        $Warnings[0].Message | Should -Match '#microsoft\.graph\.futureIdentity'
        $Warnings[0].Message | Should -Match $ObjectId
    }
}
