#Requires -Modules Pester

BeforeAll {
    $script:TestRepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
    . "$script:TestRepositoryRoot/EntraOps/Private/Undo-EntraOpsServiceEMUnregisteredGroup.ps1"

    # Local stub so Mock binds here and command discovery never auto-loads an installed EntraOps module
    function Invoke-EntraOpsMsGraphQuery {
        param(
            [string]$Method,
            [string]$Uri,
            [string]$Body,
            [string]$ConsistencyLevel,
            [string]$OutputType,
            [switch]$DisableCache,
            [switch]$ThrowOnFailure,
            [switch]$SuppressNotFoundWarning,
            [switch]$SuppressBadRequestWarning
        )
        throw 'Invoke-EntraOpsMsGraphQuery must be mocked'
    }

    $script:NewGraphError = {
        param($StatusCode)
        $ex = [System.InvalidOperationException]::new("Graph $StatusCode")
        $ex.Data['StatusCode'] = $StatusCode
        $ex
    }
}

Describe 'Undo-EntraOpsServiceEMUnregisteredGroup' {
    BeforeEach {
        # Graph state: groups by ID with their types, the catalog's registered group IDs, and the calls made
        $script:Groups = @{ 'sec-1' = @(); 'sec-2' = @(); 'm365-1' = @('Unified') }
        $script:CatalogResourceIds = @()
        $script:CatalogLookupError = $null
        $script:DeleteError = @{}
        $script:Calls = [System.Collections.Generic.List[string]]::new()
        Mock Invoke-EntraOpsMsGraphQuery {
            $script:Calls.Add("$Method $Uri")
            if ($Uri -like '*/catalogs/*/resources*') {
                if ($script:CatalogLookupError) { throw $script:CatalogLookupError }
                return @($script:CatalogResourceIds | ForEach-Object { [pscustomobject]@{ OriginSystem = 'AadGroup'; OriginId = $_ } })
            }
            if ($Method -eq 'DELETE' -and $Uri -match '^/v1.0/groups/(.+)$') {
                $id = $Matches[1]
                if ($script:DeleteError.ContainsKey($id)) { throw $script:DeleteError[$id] }
                if (-not $script:Groups.ContainsKey($id)) { throw (& $script:NewGraphError 404) }
                $script:Groups.Remove($id)
                return $null
            }
            throw "Unexpected call $Method $Uri"
        }
    }

    It 'does nothing without newly created groups' {
        Undo-EntraOpsServiceEMUnregisteredGroup -CreatedGroupIds @() -ServiceCatalogId 'cat'

        $script:Calls.Count | Should -Be 0
    }

    It 'removes unregistered groups and keeps the ones registered in the catalog or reported as registered' {
        $script:CatalogResourceIds = @('sec-1')

        Undo-EntraOpsServiceEMUnregisteredGroup -CreatedGroupIds @('sec-1', 'sec-2', 'm365-1') -RegisteredGroupIds @('m365-1') -ServiceCatalogId 'cat' -WarningVariable warnings -WarningAction SilentlyContinue

        @($script:Groups.Keys | Sort-Object) | Should -Be @('m365-1', 'sec-1')
        @($script:Calls | Where-Object { $_ -like 'DELETE *' }) | Should -Be @('DELETE /v1.0/groups/sec-2')
        ($warnings -join "`n") | Should -Match 'Removed newly created, unregistered groups.*sec-2'
    }

    It 'keeps every group when the catalog lookup fails' {
        $script:CatalogLookupError = (& $script:NewGraphError 503)

        Undo-EntraOpsServiceEMUnregisteredGroup -CreatedGroupIds @('sec-1', 'sec-2') -ServiceCatalogId 'cat' -WarningVariable warnings -WarningAction SilentlyContinue

        $script:Groups.Count | Should -Be 3
        @($script:Calls | Where-Object { $_ -like 'DELETE *' }).Count | Should -Be 0
        ($warnings -join "`n") | Should -Match 'Could not verify catalog registration; newly created groups were kept: sec-1, sec-2'
    }

    It 'deletes every created group when no catalog was created yet' {
        Undo-EntraOpsServiceEMUnregisteredGroup -CreatedGroupIds @('sec-1', 'sec-2') -WarningAction SilentlyContinue

        @($script:Calls | Where-Object { $_ -like '*/catalogs/*' }).Count | Should -Be 0
        @($script:Groups.Keys) | Should -Be @('m365-1')
    }

    It 'only soft-deletes a Microsoft 365 group, so it stays restorable' {
        Undo-EntraOpsServiceEMUnregisteredGroup -CreatedGroupIds @('m365-1', 'sec-1') -ServiceCatalogId 'cat' -WarningVariable warnings -WarningAction SilentlyContinue

        @($script:Calls | Where-Object { $_ -notlike '*/catalogs/*' }) | Should -Be @('DELETE /v1.0/groups/m365-1', 'DELETE /v1.0/groups/sec-1')
        ($warnings -join "`n") | Should -Match 'restorable from the deleted groups for 30 days\): m365-1, sec-1'
    }

    It 'tolerates a group that is already gone and reports the ones it could not remove' {
        $script:DeleteError['sec-2'] = (& $script:NewGraphError 403)

        Undo-EntraOpsServiceEMUnregisteredGroup -CreatedGroupIds @('gone', 'sec-1', 'sec-2') -WarningVariable warnings -WarningAction SilentlyContinue

        $script:Groups.ContainsKey('sec-1') | Should -BeFalse
        $script:Groups.ContainsKey('sec-2') | Should -BeTrue
        ($warnings -join "`n") | Should -Match 'Could not remove newly created, unregistered groups: sec-2 \(Graph 403\)'
        ($warnings -join "`n") | Should -Not -Match 'gone'
    }

    It 'never throws, so the provisioning error of the caller is the one reported' {
        $script:DeleteError['sec-1'] = (& $script:NewGraphError 500)
        $script:CatalogLookupError = (& $script:NewGraphError 500)

        { Undo-EntraOpsServiceEMUnregisteredGroup -CreatedGroupIds @('sec-1') -ServiceCatalogId 'cat' -WarningAction SilentlyContinue } | Should -Not -Throw
        { Undo-EntraOpsServiceEMUnregisteredGroup -CreatedGroupIds @('sec-1') -WarningAction SilentlyContinue } | Should -Not -Throw
    }
}
