#Requires -Modules Pester
#Requires -Version 7.4

BeforeAll {
    $root = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
    foreach ($name in 'ConvertTo-EntraOpsODataStringLiteral', 'Wait-EntraOpsServiceEMCondition', 'Get-EntraOpsServiceEMConfigValue', 'Set-EntraOpsServiceEMWorkloadClassification', 'Undo-EntraOpsServiceEMUnregisteredGroup') {
        . "$root/EntraOps/Private/$name.ps1"
    }
    foreach ($name in 'New-EntraOpsServiceEntraGroup', 'New-EntraOpsServiceBootstrap', 'New-EntraOpsServiceEMCatalog', 'New-EntraOpsServiceEMCatalogResource', 'New-EntraOpsServiceEMCatalogResourceRole', 'New-EntraOpsServiceEMAccessPackage', 'New-EntraOpsServicePIMPolicy', 'New-EntraOpsServicePIMAssignment') {
        . "$root/EntraOps/Public/ServiceEM/$name.ps1"
    }
    function Get-MgContext { }
    function Invoke-EntraOpsMsGraphQuery {
        param($Method, $Uri, $Body, $OutputType, $ConsistencyLevel, [switch]$DisableCache,
            [switch]$ThrowOnFailure, [switch]$SuppressNotFoundWarning, [switch]$SuppressBadRequestWarning)
        throw 'Graph must be mocked'
    }
}

Describe 'ServiceEM interrupted provisioning recovery' {
    BeforeEach {
        $script:Groups = @{}
        $script:Resources = @{}
        $script:Created = [System.Collections.Generic.List[string]]::new()
        $script:Deleted = [System.Collections.Generic.List[string]]::new()
        $script:Warnings = [System.Collections.Generic.List[string]]::new()
        Mock Write-Warning { $script:Warnings.Add("$Message") }
        $script:FailPolicy = $false
        $script:FailGroupCreationAt = 0
        $script:FailRegistrationAt = 0
        $script:RegistrationCalls = 0
        $script:FailResourceLookup = $false
        $script:HideResources = $false
        $script:FailDelete = $false
        $script:Deployment = @{
            ServiceName = 'Rg-Recovery'
            SkipAzureResourceGroup = $true
            ServiceMembers = @()
            EnablePimForGroups = $true
            ServiceRoles = @(
                [pscustomobject]@{ accessLevel = 'WorkloadPlane'; name = 'Users'; groupType = 'Security' }
                [pscustomobject]@{ accessLevel = 'WorkloadPlane'; name = 'Admins'; groupType = 'Security' }
                [pscustomobject]@{ accessLevel = 'ManagementPlane'; name = 'Admins'; groupType = 'Security' }
            )
        }
        Mock Get-EntraOpsServiceEMConfigValue { $null }
        Mock Get-MgContext { [pscustomobject]@{ AuthType = 'AppOnly' } }
        $script:ServiceEMNow = [datetime]'2026-01-01T00:00:00Z'
        Mock Get-Date { $script:ServiceEMNow }
        Mock Start-Sleep { $script:ServiceEMNow = $script:ServiceEMNow.AddSeconds($Seconds) }
        Mock Set-EntraOpsServiceEMWorkloadClassification { @() }
        Mock New-EntraOpsServiceEMCatalog { [pscustomobject]@{ Id = 'catalog' } }
        Mock New-EntraOpsServiceEMCatalogResourceRole { @() }
        Mock New-EntraOpsServiceEMAccessPackage { @() }
        Mock New-EntraOpsServicePIMPolicy { if ($script:FailPolicy) { throw 'PIM policy failure' }; @() }
        Mock New-EntraOpsServicePIMAssignment { @() }
        Mock Invoke-EntraOpsMsGraphQuery {
            if ($Method -eq 'GET' -and $Uri -like '/v1.0/groups[?]*') { return @($script:Groups.Values) }
            if ($Method -eq 'GET' -and $Uri -like '/v1.0/groups/*') {
                $id = ($Uri -replace '^/v1.0/groups/', '') -replace '\?.*$', ''
                if ($script:Groups.ContainsKey($id)) { return $script:Groups[$id] }
                throw "Unexpected group lookup: $id"
            }
            if ($Method -eq 'POST' -and $Uri -eq '/v1.0/groups') {
                if ($script:FailGroupCreationAt -eq $script:Created.Count + 1) { throw 'Group creation failure' }
                $b = $Body | ConvertFrom-Json
                $g = [pscustomobject]@{
                    Id = [guid]::NewGuid().Guid
                    DisplayName = $b.displayName
                    MailNickname = $b.mailNickname
                    SecurityEnabled = $b.securityEnabled
                    IsAssignableToRole = $b.isAssignableToRole
                    GroupTypes = $b.groupTypes
                }
                $script:Groups[$g.Id] = $g
                $script:Created.Add($g.Id)
                return $g
            }
            if ($Method -eq 'DELETE' -and $Uri -like '/v1.0/groups/*') {
                if ($script:FailDelete) { throw 'Group deletion denied' }
                $id = $Uri -replace '^/v1.0/groups/', ''
                $script:Deleted.Add($id)
                $script:Groups.Remove($id)
                return
            }
            if ($Method -eq 'GET' -and $Uri -like '*/catalogs[?]*') {
                return [pscustomobject]@{ Id = 'catalog'; DisplayName = 'Catalog-Rg-Recovery'; Resources = @($script:Resources.Values) }
            }
            if ($Method -eq 'GET' -and $Uri -like '*/catalogs/catalog/resources?*') {
                if ($script:FailResourceLookup) { throw 'Catalog lookup denied' }
                if ($script:HideResources) { return @() }
                return @($script:Resources.Values)
            }
            if ($Method -eq 'POST' -and $Uri -like '*/resourceRequests') {
                $script:RegistrationCalls++
                if ($script:FailRegistrationAt -eq $script:RegistrationCalls) { throw 'Resource registration failure' }
                $id = ($Body | ConvertFrom-Json).resource.originId
                $script:Resources[$id] = [pscustomobject]@{
                    Id = "resource-$id"; OriginId = $id; OriginSystem = 'AadGroup'; DisplayName = $script:Groups[$id].DisplayName
                }
                return [pscustomobject]@{ Id = 'request' }
            }
            throw "Unexpected Graph request: $Method $Uri"
        }
    }

    It 'can retry a PIM policy failure using fresh groups without weakening the reuse guard' {
        $script:FailPolicy = $true
        { New-EntraOpsServiceBootstrap @script:Deployment -WarningAction SilentlyContinue 6>$null } | Should -Throw '*PIM policy failure*'

        $script:Created.Count | Should -Be 3
        $script:Groups.Count | Should -Be 0
        $script:Deleted.Count | Should -Be 3
        Should -Invoke New-EntraOpsServiceEMCatalog -Times 0 -Exactly
        Should -Invoke Set-EntraOpsServiceEMWorkloadClassification -Times 0 -Exactly

        $script:FailPolicy = $false
        { New-EntraOpsServiceBootstrap @script:Deployment -WarningAction SilentlyContinue 6>$null } | Should -Not -Throw
        $script:Created.Count | Should -Be 6
        $script:Groups.Count | Should -Be 3
        $script:Resources.Count | Should -Be 3
    }

    It 'cleans up groups created before a later group creation fails' {
        $script:FailGroupCreationAt = 2
        { New-EntraOpsServiceBootstrap @script:Deployment -WarningAction SilentlyContinue 6>$null } | Should -Throw '*Group creation failure*'
        $script:Groups.Count | Should -Be 0
        $script:Deleted.Count | Should -Be 1

        $script:FailGroupCreationAt = 0
        { New-EntraOpsServiceBootstrap @script:Deployment -WarningAction SilentlyContinue 6>$null } | Should -Not -Throw
        $script:Groups.Count | Should -Be 3
    }

    It 'keeps registered groups on a partial registration failure and can retry' {
        $script:FailRegistrationAt = 2
        { New-EntraOpsServiceBootstrap @script:Deployment -WarningAction SilentlyContinue 6>$null } | Should -Throw '*Resource registration failure*'
        $script:Groups.Count | Should -Be 1
        $script:Deleted.Count | Should -Be 2
        $retained = @($script:Groups.Keys)[0]
        $script:Resources.ContainsKey($retained) | Should -BeTrue

        $script:FailRegistrationAt = 0
        { New-EntraOpsServiceBootstrap @script:Deployment -WarningAction SilentlyContinue 6>$null } | Should -Not -Throw
        $script:Groups.Count | Should -Be 3
        $script:Groups.ContainsKey($retained) | Should -BeTrue
        $script:Created.Count | Should -Be 5
    }

    It 'keeps accepted registrations even when resource indexing has not caught up' {
        $script:HideResources = $true
        { New-EntraOpsServiceBootstrap @script:Deployment -WarningAction SilentlyContinue 6>$null } | Should -Throw '*Catalog Resource object consistency*'
        $script:Groups.Count | Should -Be 3
        $script:Deleted.Count | Should -Be 0
    }

    It 'keeps all groups if catalog registration cannot be checked and preserves the original error' {
        $script:FailResourceLookup = $true
        { New-EntraOpsServiceBootstrap @script:Deployment -WarningAction SilentlyContinue 6>$null } | Should -Throw '*Catalog lookup denied*'
        $script:Groups.Count | Should -Be 3
        $script:Deleted.Count | Should -Be 0
        @($script:Warnings | Where-Object { "$_" -like '*Could not verify catalog registration*Verify these IDs*' }).Count | Should -Be 1
    }

    It 'reports failed cleanup with group IDs while preserving the original provisioning error' {
        $script:FailPolicy = $true
        $script:FailDelete = $true
        { New-EntraOpsServiceBootstrap @script:Deployment -WarningAction SilentlyContinue 6>$null } | Should -Throw '*PIM policy failure*'
        $script:Groups.Count | Should -Be 3
        $message = "$($script:Warnings | Where-Object { "$_" -like '*Could not remove newly created*' })"
        foreach ($id in $script:Created) { $message | Should -BeLike "*$id*" }
    }

    It 'rejects a pre-created lookalike without deleting or adopting it' {
        $id = [guid]::NewGuid().Guid
        $script:Groups[$id] = [pscustomobject]@{
            Id = $id; DisplayName = 'SG-Rg-Recovery-WorkloadPlane-Users'; MailNickname = 'Rg-Recovery.WorkloadPlane.Users'
            SecurityEnabled = $true; IsAssignableToRole = $false
        }
        { New-EntraOpsServiceBootstrap @script:Deployment -WarningAction SilentlyContinue 6>$null } | Should -Throw "*isn't a resource of the catalog*"
        $script:Groups.ContainsKey($id) | Should -BeTrue
        $script:Created.Count | Should -Be 0
        $script:Deleted.Count | Should -Be 0
    }

    It 'keeps reused and delegated groups when PIM setup fails' {
        $existing = [guid]::NewGuid().Guid
        $delegated = [guid]::NewGuid().Guid
        $script:Groups[$existing] = [pscustomobject]@{
            Id = $existing; DisplayName = 'SG-Rg-Recovery-WorkloadPlane-Users'; MailNickname = 'Rg-Recovery.WorkloadPlane.Users'
            SecurityEnabled = $true; IsAssignableToRole = $false
        }
        $script:Groups[$delegated] = [pscustomobject]@{ Id = $delegated; DisplayName = 'Tenant-ControlPlane'; SecurityEnabled = $true; IsAssignableToRole = $true }
        $script:Resources[$existing] = [pscustomobject]@{ OriginId = $existing; OriginSystem = 'AadGroup' }
        $script:FailPolicy = $true

        { New-EntraOpsServiceBootstrap @script:Deployment -ControlPlaneDelegationGroupId $delegated -WarningAction SilentlyContinue 6>$null } | Should -Throw '*PIM policy failure*'
        $script:Groups.ContainsKey($existing) | Should -BeTrue
        $script:Groups.ContainsKey($delegated) | Should -BeTrue
        $script:Deleted.Count | Should -Be 2
    }

    It 'keeps the completed catalog resources when eligible owner assignment fails' {
        Mock Get-MgContext { [pscustomobject]@{ Account = 'owner@contoso.com'; AuthType = 'Delegated' } }
        Mock Invoke-EntraOpsMsGraphQuery -ParameterFilter { $Uri -like '/v1.0/users/*' } { [pscustomobject]@{ Id = 'owner' } }
        Mock New-EntraOpsServicePIMAssignment { throw 'Eligible owner assignment failure' }

        { New-EntraOpsServiceBootstrap @script:Deployment -GroupOwnership Eligible -WarningAction SilentlyContinue 6>$null } | Should -Throw '*Eligible owner assignment failure*'
        $script:Groups.Count | Should -Be 3
        $script:Resources.Count | Should -Be 3
        $script:Deleted.Count | Should -Be 0

        Mock New-EntraOpsServicePIMAssignment { @() }
        { New-EntraOpsServiceBootstrap @script:Deployment -GroupOwnership Eligible -WarningAction SilentlyContinue 6>$null } | Should -Not -Throw
        $script:Created.Count | Should -Be 3
    }
}
