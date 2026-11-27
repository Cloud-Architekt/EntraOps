#Requires -Modules Pester

BeforeDiscovery {
    $script:TestRepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
}

BeforeAll {
    $script:TestRepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
    . "$script:TestRepositoryRoot/EntraOps/Private/Write-EntraOpsGroupedRequestDetail.ps1"
    . "$script:TestRepositoryRoot/EntraOps/Private/Show-EntraOpsWarningSummary.ps1"
    . "$script:TestRepositoryRoot/EntraOps/Private/Write-EntraOpsConsoleItemList.ps1"
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

    It 'merges hidden-detail warnings that would print the same object IDs' {
        $Warnings = [System.Collections.Generic.List[psobject]]::new()
        $Warnings.Add([pscustomobject]@{ Type = 'Lookup'; Message = "Object $script:ObjectId in context one was not found" })
        $Warnings.Add([pscustomobject]@{ Type = 'Lookup'; Message = "Object $script:ObjectId in context two was not found" })

        $Output = Show-EntraOpsWarningSummary -WarningMessages $Warnings 6>&1 | Out-String

        ([regex]::Matches($Output, [regex]::Escape($script:ObjectId))).Count | Should -Be 1
        $Output | Should -Match '\[1 distinct ID\(s\) in 2 warning\(s\)\]'
        $Output | Should -Not -Match 'context'
    }

    It 'keeps tenant IDs as message context instead of listing them as object IDs' {
        $TenantId = '22222222-2222-2222-2222-222222222222'
        $Warnings = [System.Collections.Generic.List[psobject]]::new()
        $Warnings.Add([pscustomobject]@{ Type = 'ForeignTenantObject'; Message = "Skipped 9 object(s) not owned by tenant $TenantId for Tier1-ManagementPlane.Azure" })
        $Warnings.Add([pscustomobject]@{ Type = 'ForeignTenantObject'; Message = "Skipped 11 object(s) not owned by tenant $TenantId for Tier1-ManagementPlane.EntraID" })
        $Warnings.Add([pscustomobject]@{ Type = 'ForeignTenantDeviceOwner'; Message = "Excluded devices for 1 privileged user(s) not owned by home tenant ID: $TenantId (user $script:ObjectId)" })

        $Output = Show-EntraOpsWarningSummary -WarningMessages $Warnings 6>&1 | Out-String

        $Output | Should -Not -Match "Object ID\(s\): $TenantId"
        $Output | Should -Match "Skipped 9 object\(s\) not owned by tenant $TenantId for Tier1-ManagementPlane.Azure"
        $Output | Should -Match "Skipped 11 object\(s\) not owned by tenant $TenantId"
        # An object ID in the same message is still listed as object ID
        $Output | Should -Match "Object ID\(s\): $([regex]::Escape($script:ObjectId)) \[1 distinct ID\(s\) in 1 warning\(s\)\]"
    }
}

Describe 'Write-EntraOpsConsoleItemList' {
    It 'writes only the count of an informational list by default' {
        $Output = Write-EntraOpsConsoleItemList -Label 'Scope entries added' -Items @('/', '/administrativeUnits/11111111-1111-1111-1111-111111111111') -IncludeObjectDetails $false 6>&1 | Out-String

        $Output | Should -Match 'Scope entries added: 2 \(including the directory scope /\)'
        $Output | Should -Not -Match '11111111-1111-1111-1111-111111111111'
    }

    It 'writes every item when object details are enabled' {
        $Output = Write-EntraOpsConsoleItemList -Label 'Scope entries added' -Items @('/administrativeUnits/11111111-1111-1111-1111-111111111111') -IncludeObjectDetails $true 6>&1 | Out-String

        $Output | Should -Match '/administrativeUnits/11111111-1111-1111-1111-111111111111'
    }
}
