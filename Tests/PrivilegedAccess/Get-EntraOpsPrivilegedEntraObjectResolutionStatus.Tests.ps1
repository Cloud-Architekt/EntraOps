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

    . "$script:TestRepositoryRoot/EntraOps/Public/PrivilegedAccess/Get-EntraOpsPrivilegedEntraObject.ps1"
}

Describe 'Get-EntraOpsPrivilegedEntraObject resolution status' {
    BeforeEach {
        $global:TenantIdContext = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
        $global:EntraOpsConfig = [pscustomobject]@{
            CustomSecurityAttributes = [pscustomobject]@{}
            AlternateObjectTierLevelAttributes = $null
        }

        Mock Invoke-EntraOpsMsGraphQuery {
            $Exception = [System.InvalidOperationException]::new("Microsoft Graph query '$Uri' failed")
            $Exception.Data['StatusCode'] = 404
            throw $Exception
        }
    }

    It 'marks the CloudLab orphan as not found only after both identity endpoints return 404' {
        $ObjectId = '4fbcb88a-18b5-42cf-82ac-30ca6d4f6919'

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

    It 'classifies an unhandled directory object type as unknown and identifies it in a warning' {
        $ObjectId = '44444444-4444-4444-4444-444444444444'
        Mock Invoke-EntraOpsMsGraphQuery {
            if ($Uri -like "/beta/directoryObjects/$ObjectId?*") {
                return [pscustomobject]@{
                    '@odata.type' = '#microsoft.graph.futureIdentity'
                    id = $ObjectId
                    displayName = 'Future identity'
                }
            }
            return @()
        }

        $Warnings = @()
        $Result = Get-EntraOpsPrivilegedEntraObject -AadObjectId $ObjectId `
            -TenantId $global:TenantIdContext -WarningVariable Warnings

        $Result.ObjectType | Should -Be 'unknown'
        $Result.ObjectSubType | Should -Be 'unknown'
        $Result.ResolutionStatus | Should -Be 'Unresolved'
        $Warnings | Should -HaveCount 1
        $Warnings[0].Message | Should -Match '#microsoft\.graph\.futureIdentity'
        $Warnings[0].Message | Should -Match $ObjectId
    }
}
