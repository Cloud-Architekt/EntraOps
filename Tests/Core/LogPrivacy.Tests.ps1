#Requires -Modules Pester

BeforeDiscovery {
    $script:TestRepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
}

BeforeAll {
    $script:TestRepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
    . "$script:TestRepositoryRoot/EntraOps/Private/Write-EntraOpsGroupedRequestDetail.ps1"
    . "$script:TestRepositoryRoot/EntraOps/Private/Show-EntraOpsWarningSummary.ps1"
}

Describe 'EntraOps automation log privacy' {
    BeforeEach {
        $Global:EntraOpsIncludeObjectDetails = $false
        $script:ObjectId = '11111111-1111-1111-1111-111111111111'
        $script:PrincipalName = 'person@example.com'
        $script:RequestGroup = [pscustomobject]@{
            DistinctIds   = @($script:ObjectId)
            Count         = 1
            NormalizedUri = '/beta/users/{id}'
            StatusCode    = 404
            ErrorMessage  = "User $script:PrincipalName with id $script:ObjectId was not found"
        }
    }

    It 'keeps object IDs but omits descriptive request details by default' {
        $Output = Write-EntraOpsGroupedRequestDetail -Group $script:RequestGroup 6>&1 | Out-String

        $Output | Should -Match ([regex]::Escape($script:ObjectId))
        $Output | Should -Not -Match ([regex]::Escape($script:PrincipalName))
        $Output | Should -Match 'Object-specific error details omitted'
    }

    It 'includes descriptive request details when explicitly enabled' {
        $Output = Write-EntraOpsGroupedRequestDetail -Group $script:RequestGroup -IncludeObjectDetails $true 6>&1 | Out-String

        $Output | Should -Match ([regex]::Escape($script:ObjectId))
        $Output | Should -Match ([regex]::Escape($script:PrincipalName))
    }

    It 'keeps object IDs but omits descriptive warning details by default' {
        $Warnings = [System.Collections.Generic.List[psobject]]::new()
        $Warnings.Add([pscustomobject]@{
                Type    = 'Lookup'
                Message = "User $script:PrincipalName with id $script:ObjectId was not found"
            })

        $Output = Show-EntraOpsWarningSummary -WarningMessages $Warnings 6>&1 | Out-String

        $Output | Should -Match ([regex]::Escape($script:ObjectId))
        $Output | Should -Not -Match ([regex]::Escape($script:PrincipalName))
        $Output | Should -Match 'Object ID\(s\)'
    }

    It 'uses the configured session preference for descriptive warning details' {
        $Global:EntraOpsIncludeObjectDetails = $true
        $Warnings = [System.Collections.Generic.List[psobject]]::new()
        $Warnings.Add([pscustomobject]@{
                Type    = 'Lookup'
                Message = "User $script:PrincipalName with id $script:ObjectId was not found"
            })

        $Output = Show-EntraOpsWarningSummary -WarningMessages $Warnings 6>&1 | Out-String

        $Output | Should -Match ([regex]::Escape($script:ObjectId))
        $Output | Should -Match ([regex]::Escape($script:PrincipalName))
    }
}
