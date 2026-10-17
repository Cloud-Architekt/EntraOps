#Requires -Modules Pester

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
    function Show-EntraOpsWarningSummary { param($WarningMessages, $IncludeObjectDetails) }

    . "$script:TestRepositoryRoot/EntraOps/Private/Test-EntraOpsGraphNotFoundError.ps1"
    . "$script:TestRepositoryRoot/EntraOps/Private/Test-EntraOpsRemovalSafetyThreshold.ps1"
    . "$script:TestRepositoryRoot/EntraOps/Public/PrivilegedAccess/Update-EntraOpsPrivilegedAdministrativeUnit.ps1"
    . "$script:TestRepositoryRoot/EntraOps/Public/PrivilegedAccess/Update-EntraOpsPrivilegedUnprotectedAdministrativeUnit.ps1"

    function New-GraphFailure {
        param([int]$StatusCode, [string]$ErrorCode)
        $Exception = [System.InvalidOperationException]::new("Microsoft Graph query failed with HTTP $StatusCode")
        $Exception.Data['StatusCode'] = $StatusCode
        $Exception.Data['ErrorCode'] = $ErrorCode
        return $Exception
    }
}

Describe "Test-EntraOpsGraphNotFoundError" {
    It "detects HTTP 404 and Request_ResourceNotFound" {
        $NotFound = try { throw (New-GraphFailure -StatusCode 404 -ErrorCode 'Request_ResourceNotFound') } catch { $_ }
        $ByCode = try { throw (New-GraphFailure -StatusCode 400 -ErrorCode 'Request_ResourceNotFound') } catch { $_ }
        Test-EntraOpsGraphNotFoundError -ErrorRecord $NotFound | Should -BeTrue
        Test-EntraOpsGraphNotFoundError -ErrorRecord $ByCode | Should -BeTrue
    }

    It "does not treat other failures as not found" {
        $Forbidden = try { throw (New-GraphFailure -StatusCode 403 -ErrorCode 'Authorization_RequestDenied') } catch { $_ }
        $Plain = try { throw "plain failure" } catch { $_ }
        Test-EntraOpsGraphNotFoundError -ErrorRecord $Forbidden | Should -BeFalse
        Test-EntraOpsGraphNotFoundError -ErrorRecord $Plain | Should -BeFalse
    }
}

Describe "Update-EntraOpsPrivilegedAdministrativeUnit with objects deleted after the last Pull" {
    BeforeEach {
        $global:DefaultFolderClassifiedEam = "/classified"
        $global:DefaultFolderClassification = "/classification"
        $script:CurrentMembers = @()
        $script:DeletedObjectFailure = New-GraphFailure -StatusCode 404 -ErrorCode 'Request_ResourceNotFound'
        $script:DestinationMissing = $false
        $script:PostFailure = $null

        Mock Invoke-WebRequest { '[]' }
        Mock Get-ChildItem { [pscustomobject]@{ FullName = "$Path" } }
        Mock Get-Content {
            if ($Path -like '/classified/*') {
                return '[{"ObjectId":"keep-1","ObjectType":"User","ObjectTenantId":"tenant-1","RoleSystem":"EntraID","Classification":[{"AdminTierLevel":"0","AdminTierLevelName":"ControlPlane"}]},{"ObjectId":"gone-1","ObjectType":"User","ObjectTenantId":"tenant-1","RoleSystem":"EntraID","Classification":[{"AdminTierLevel":"0","AdminTierLevelName":"ControlPlane"}]}]'
            }
            return '[{"EAMTierLevelName":"ControlPlane","EAMTierLevelTagValue":"0"}]'
        }
        Mock Select-EntraOpsUniqueGraphObject { [pscustomobject]@{ id = 'au-1'; isMemberManagementRestricted = $false } }
        Mock Show-EntraOpsWarningSummary {}
        Mock Invoke-EntraOpsMsGraphQuery {
            if ($Uri.StartsWith('/beta/administrativeUnits?$filter=')) { return [pscustomobject]@{ id = 'au-1' } }
            if ($Uri -eq '/beta/administrativeUnits/au-1/members') { return $script:CurrentMembers }
            if ($Uri -eq '/beta/administrativeUnits/au-1') {
                if ($script:DestinationMissing) { throw (New-GraphFailure -StatusCode 404 -ErrorCode 'Request_ResourceNotFound') }
                return [pscustomobject]@{ id = 'au-1' }
            }
            if ($Uri -eq '/beta/directoryObjects/keep-1') { return [pscustomobject]@{ id = 'keep-1'; '@odata.type' = '#microsoft.graph.user' } }
            if ($Uri -eq '/beta/directoryObjects/gone-1') { throw $script:DeletedObjectFailure }
            if ($Method -eq 'POST') {
                if ($null -ne $script:PostFailure) { throw $script:PostFailure }
                return
            }
            throw "Unexpected Graph request: $Method $Uri"
        }
    }

    It "fails the sync when the membership request answers 404 because the AU itself no longer exists" {
        $script:DeletedObjectFailure = $null
        $script:DestinationMissing = $true
        $script:PostFailure = New-GraphFailure -StatusCode 404 -ErrorCode 'Request_ResourceNotFound'
        Mock Invoke-EntraOpsMsGraphQuery {
            if ($Uri.StartsWith('/beta/administrativeUnits?$filter=')) { return [pscustomobject]@{ id = 'au-1' } }
            if ($Uri -eq '/beta/administrativeUnits/au-1/members') { return @() }
            if ($Uri -eq '/beta/administrativeUnits/au-1') { throw (New-GraphFailure -StatusCode 404 -ErrorCode 'Request_ResourceNotFound') }
            if ($Uri -like '/beta/directoryObjects/*') { return [pscustomobject]@{ id = $Uri.Split('/')[-1]; '@odata.type' = '#microsoft.graph.user' } }
            if ($Method -eq 'POST') { throw $script:PostFailure }
            throw "Unexpected Graph request: $Method $Uri"
        }
        { Update-EntraOpsPrivilegedAdministrativeUnit -RbacSystems EntraID -ApplyToAccessTierLevel ControlPlane -TenantId 'tenant-1' -WarningAction SilentlyContinue } | Should -Throw '*2 membership operation(s) failed*'
        Should -Invoke Show-EntraOpsWarningSummary -Times 1 -Exactly -ParameterFilter { @($WarningMessages | Where-Object Type -eq 'ObjectNotFound').Count -eq 0 -and @($WarningMessages | Where-Object Type -eq 'ApiError').Count -eq 2 }
    }

    It "keeps skipping a deleted object when the AU still exists" {
        $script:CurrentMembers = @([pscustomobject]@{ Id = 'keep-1' })
        { Update-EntraOpsPrivilegedAdministrativeUnit -RbacSystems EntraID -ApplyToAccessTierLevel ControlPlane -TenantId 'tenant-1' -WarningAction SilentlyContinue } | Should -Not -Throw
        Should -Invoke Invoke-EntraOpsMsGraphQuery -Times 1 -Exactly -ParameterFilter { $Method -eq 'GET' -and $Uri -eq '/beta/administrativeUnits/au-1' }
    }

    It "skips a deleted object instead of failing the sync of a populated AU" {
        $script:CurrentMembers = @([pscustomobject]@{ Id = 'keep-1' })
        { Update-EntraOpsPrivilegedAdministrativeUnit -RbacSystems EntraID -ApplyToAccessTierLevel ControlPlane -TenantId 'tenant-1' -WarningAction SilentlyContinue } | Should -Not -Throw
        Should -Invoke Invoke-EntraOpsMsGraphQuery -Times 0 -Exactly -ParameterFilter { $Method -eq 'POST' }
        Should -Invoke Show-EntraOpsWarningSummary -Times 1 -Exactly -ParameterFilter { @($WarningMessages | Where-Object Type -eq 'ObjectNotFound').Count -eq 1 -and @($WarningMessages | Where-Object Type -eq 'ApiError').Count -eq 0 }
    }

    It "skips a deleted object when the AU is still empty and adds the remaining objects" {
        { Update-EntraOpsPrivilegedAdministrativeUnit -RbacSystems EntraID -ApplyToAccessTierLevel ControlPlane -TenantId 'tenant-1' -WarningAction SilentlyContinue } | Should -Not -Throw
        Should -Invoke Invoke-EntraOpsMsGraphQuery -Times 1 -Exactly -ParameterFilter { $Method -eq 'POST' }
    }

    It "still fails the sync for other Graph errors" {
        $script:DeletedObjectFailure = New-GraphFailure -StatusCode 403 -ErrorCode 'Authorization_RequestDenied'
        $script:CurrentMembers = @([pscustomobject]@{ Id = 'keep-1' })
        { Update-EntraOpsPrivilegedAdministrativeUnit -RbacSystems EntraID -ApplyToAccessTierLevel ControlPlane -TenantId 'tenant-1' -WarningAction SilentlyContinue } | Should -Throw '*1 membership operation(s) failed*'
    }
}

Describe "Update-EntraOpsPrivilegedUnprotectedAdministrativeUnit with objects deleted after the last Pull" {
    BeforeEach {
        $global:DefaultFolderClassifiedEam = "/classified"
        $global:DefaultFolderClassification = "/classification"
        $script:DesiredFailure = New-GraphFailure -StatusCode 404 -ErrorCode 'Request_ResourceNotFound'

        Mock Get-AzContext { [pscustomobject]@{ Tenant = [pscustomobject]@{ Id = 'tenant-1' } } }
        Mock Get-ChildItem { [pscustomobject]@{ FullName = '/classification/ControlPlane.json' } }
        Mock Get-Content {
            if ($Path -like '/classified/*') {
                return '{"ObjectId":"desired-1","ObjectType":"User","RestrictedManagementByRAG":false,"RestrictedManagementByAadRole":false,"RestrictedManagementByRMAU":false,"Classification":{"AdminTierLevel":0,"AdminTierLevelName":"ControlPlane"}}'
            }
            return '{"EAMTierLevelName":"ControlPlane","EAMTierLevelTagValue":0}'
        }
        Mock Select-EntraOpsUniqueGraphObject { [pscustomobject]@{ id = 'au-1' } }
        Mock Invoke-EntraOpsMsGraphQuery {
            if ($Uri.StartsWith('/beta/administrativeUnits?$filter=')) { return [pscustomobject]@{ id = 'au-1' } }
            if ($Uri -eq '/beta/administrativeUnits/au-1/members') { return @() }
            if ($Uri -eq '/beta/administrativeUnits/au-1') { return [pscustomobject]@{ id = 'au-1' } }
            if ($Uri -eq '/beta/directoryObjects/desired-1') { throw $script:DesiredFailure }
            throw "Unexpected Graph request: $Method $Uri"
        }
    }

    It "fails the RMAU sync when the membership request answers 404 because the AU itself no longer exists" {
        $NotFound = New-GraphFailure -StatusCode 404 -ErrorCode 'Request_ResourceNotFound'
        Mock Invoke-EntraOpsMsGraphQuery {
            if ($Uri.StartsWith('/beta/administrativeUnits?$filter=')) { return [pscustomobject]@{ id = 'au-1' } }
            if ($Uri -eq '/beta/administrativeUnits/au-1/members') { return @() }
            if ($Uri -eq '/beta/administrativeUnits/au-1') { throw $NotFound }
            if ($Uri -eq '/beta/directoryObjects/desired-1') { return [pscustomobject]@{ id = 'desired-1'; '@odata.type' = '#microsoft.graph.user' } }
            if ($Method -eq 'POST') { throw $NotFound }
            throw "Unexpected Graph request: $Method $Uri"
        }
        { Update-EntraOpsPrivilegedUnprotectedAdministrativeUnit -RbacSystems EntraID -WarningAction SilentlyContinue } | Should -Throw '*RMAU sync did not complete*'
    }

    It "skips a deleted principal instead of failing the RMAU sync" {
        { Update-EntraOpsPrivilegedUnprotectedAdministrativeUnit -RbacSystems EntraID -WarningAction SilentlyContinue } | Should -Not -Throw
        Should -Invoke Invoke-EntraOpsMsGraphQuery -Times 0 -Exactly -ParameterFilter { $Method -eq 'POST' }
    }

    It "still fails the RMAU sync for other Graph errors" {
        $script:DesiredFailure = New-GraphFailure -StatusCode 403 -ErrorCode 'Authorization_RequestDenied'
        { Update-EntraOpsPrivilegedUnprotectedAdministrativeUnit -RbacSystems EntraID -WarningAction SilentlyContinue } | Should -Throw '*RMAU sync did not complete*'
    }
}
