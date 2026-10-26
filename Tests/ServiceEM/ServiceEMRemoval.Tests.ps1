#Requires -Modules Pester
#Requires -Version 7.0

BeforeAll {
    $root = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
    . "$root/EntraOps/Private/ConvertTo-EntraOpsODataStringLiteral.ps1"
    . "$root/EntraOps/Private/Wait-EntraOpsServiceEMCondition.ps1"
    . "$root/EntraOps/Private/Get-EntraOpsServiceEMConfigValue.ps1"
    . "$root/EntraOps/Public/ServiceEM/Remove-EntraOpsServiceCatalog.ps1"
    function Invoke-EntraOpsMsGraphQuery {
        param($Method, $Uri, $Body, $OutputType, $ConsistencyLevel, [switch]$DisableCache,
            [switch]$ThrowOnFailure, [switch]$SuppressNotFoundWarning, [switch]$SuppressBadRequestWarning)
        throw 'Graph must be mocked'
    }
    function Remove-AzResourceGroup { param($Name, [switch]$Force) }
    function New-TestGraphError ($Code, $Status = 400) {
        $ex = [System.InvalidOperationException]::new("Graph $Status $Code")
        $ex.Data['StatusCode'] = $Status
        $ex.Data['ErrorCode'] = $Code
        return $ex
    }
}

Describe 'ServiceEM removal verification and replication recovery' {
    BeforeEach {
        $script:Now = [datetime]'2026-01-01T00:00:00Z'
        Mock Get-Date { $script:Now }
        Mock Start-Sleep { $script:Now = $script:Now.AddSeconds($Seconds) }
        Mock Remove-AzResourceGroup {}
        Mock Get-EntraOpsServiceEMConfigValue { $false }
        $script:Events = [System.Collections.Generic.List[string]]::new()
        $script:RemovalState = 'delivered'
        $script:RemovalObserved = $false
        $script:RemainingChecks = 0
        $script:RemainingForChecks = 0
        $script:KeepExpiredAssignment = $false
        $script:DeleteFailures = 0
        $script:DeleteError = 'InvalidDeleteEntitlementHasGrants'
        $script:DeleteStatus = 400
        $script:ReadFailure = $null
        $script:MissingRequest = $false
        Mock Invoke-EntraOpsMsGraphQuery {
            $script:Events.Add("$Method $Uri")
            if ($Method -eq 'GET' -and (-not $ThrowOnFailure -or -not $DisableCache)) { throw 'Unsafe lookup' }
            if ($Method -eq 'GET' -and $Uri -like $script:ReadFailure) { throw (New-TestGraphError 'Forbidden' 403) }
            if ($Method -eq 'DELETE') {
                if ($Uri -like '*/accessPackages/ap-1' -and $script:DeleteFailures -gt 0) {
                    $script:DeleteFailures--
                    throw (New-TestGraphError $script:DeleteError $script:DeleteStatus)
                }
                return
            }
            if ($Method -eq 'POST') { return [pscustomobject]@{ id = 'remove-1' } }
            if ($Uri -like '*/catalogs[?]*') {
                return [pscustomobject]@{
                    id = 'catalog-1'
                    accessPackages = @([pscustomobject]@{ id = 'ap-1'; displayName = 'AP-Test' })
                    Resources = @([pscustomobject]@{ OriginSystem = 'AadGroup'; OriginId = 'group-1'; DisplayName = 'Group-Test' })
                }
            }
            if ($Uri -like '*/assignmentRequests[?]*') { return @() }
            if ($Uri -like '*/assignmentRequests/remove-1') {
                if ($script:MissingRequest) { return $null }
                $script:RemovalObserved = $true
                return [pscustomobject]@{ id = 'remove-1'; state = $script:RemovalState; status = 'Delivered' }
            }
            if ($Uri -like '*/assignments[?]*') {
                if ($script:RemovalObserved) {
                    $script:RemainingChecks++
                    if ($script:RemainingChecks -gt $script:RemainingForChecks) {
                        if ($script:KeepExpiredAssignment) { return [pscustomobject]@{ id = 'assignment-1'; state = 'expired' } }
                        return @()
                    }
                }
                return [pscustomobject]@{ id = 'assignment-1'; state = 'delivered'; target = [pscustomobject]@{ displayName = 'User' } }
            }
            if ($Uri -like '*/resourceRoleScopes') { return [pscustomobject]@{ id = 'role-scope-1' } }
            if ($Uri -like '/v1.0/groups/*') { return [pscustomobject]@{ id = 'group-1'; MailNickname = 'Rg-Test.WorkloadPlane.Users' } }
            throw "Unexpected request $Method $Uri"
        }
        $script:RemoveOptions = @{ ServiceCatalogName = 'Catalog-Rg-Test'; Force = $true; WarningAction = 'SilentlyContinue' }
    }

    It 'rejects duplicate catalog names before reading or changing their contents (WhatIf: <UseWhatIf>)' -TestCases @(
        @{ UseWhatIf = $false }, @{ UseWhatIf = $true }
    ) {
        param($UseWhatIf)
        Mock Invoke-EntraOpsMsGraphQuery -ParameterFilter { $Method -eq 'GET' -and $Uri -like '*/catalogs[?]*' } {
            foreach ($index in 1, 2) {
                [pscustomobject]@{
                    id = "catalog-$index"
                    accessPackages = @([pscustomobject]@{ id = "ap-$index"; displayName = "AP-$index" })
                    Resources = @([pscustomobject]@{ OriginSystem = 'AadGroup'; OriginId = "group-$index" })
                }
            }
        }

        { Remove-EntraOpsServiceCatalog @script:RemoveOptions -WhatIf:$UseWhatIf } |
        Should -Throw "*Found 2 catalogs named 'Catalog-Rg-Test'; no resources were removed*"

        Should -Invoke Invoke-EntraOpsMsGraphQuery -Times 1 -Exactly
        Should -Invoke Invoke-EntraOpsMsGraphQuery -Times 0 -Exactly -ParameterFilter { $Method -ne 'GET' }
        Should -Invoke Remove-AzResourceGroup -Times 0 -Exactly
    }

    It 'rejects a catalog without an object ID before reading or changing its contents' {
        Mock Invoke-EntraOpsMsGraphQuery -ParameterFilter { $Method -eq 'GET' -and $Uri -like '*/catalogs[?]*' } {
            [pscustomobject]@{ accessPackages = @([pscustomobject]@{ id = 'ap-1' }); Resources = @() }
        }

        { Remove-EntraOpsServiceCatalog @script:RemoveOptions } |
        Should -Throw "*Catalog 'Catalog-Rg-Test' has no object ID; no resources were removed*"

        Should -Invoke Invoke-EntraOpsMsGraphQuery -Times 1 -Exactly
        Should -Invoke Remove-AzResourceGroup -Times 0 -Exactly
    }

    It 'keeps the no-match behavior for an empty or null catalog response (<ReturnNull>)' -TestCases @(
        @{ ReturnNull = $false }, @{ ReturnNull = $true }
    ) {
        param($ReturnNull)
        $script:ReturnNullCatalog = $ReturnNull
        Mock Invoke-EntraOpsMsGraphQuery -ParameterFilter { $Method -eq 'GET' -and $Uri -like '*/catalogs[?]*' } {
            if ($script:ReturnNullCatalog) { return $null }
            return @()
        }

        Remove-EntraOpsServiceCatalog @script:RemoveOptions -WarningVariable noCatalogWarnings | Out-Null

        @($noCatalogWarnings | Where-Object { "$_" -like '*Unable to obtain catalog by name*' }).Count | Should -Be 1
        Should -Invoke Invoke-EntraOpsMsGraphQuery -Times 1 -Exactly
        Should -Invoke Remove-AzResourceGroup -Times 0 -Exactly
    }

    It 'waits for assignments to disappear before deleting resource roles and packages' {
        $script:RemainingForChecks = 2

        Remove-EntraOpsServiceCatalog @script:RemoveOptions | Out-Null

        $script:RemainingChecks | Should -Be 3
        $script:Events | Should -Contain 'DELETE /v1.0/groups/group-1'
        $firstDelete = @($script:Events | Where-Object { $_ -like 'DELETE *' })[0]
        $firstDelete | Should -BeLike '*/resourceRoleScopes/role-scope-1'
        $lastLookup = @($script:Events | Where-Object { $_ -like 'GET */assignments[?]*' })[-1]
        $script:Events.LastIndexOf($lastLookup) | Should -BeLessThan $script:Events.IndexOf($firstDelete)
    }

    It 'writes a completion message separately from the unchanged return value and clears progress' {
        Mock Write-Progress {}

        $result = Remove-EntraOpsServiceCatalog @script:RemoveOptions -InformationVariable feedback 6>$null

        $result | Should -BeOfType [hashtable]
        $result.Count | Should -Be 0
        ($feedback.MessageData -join ' ') | Should -BeLike "*Catalog 'Catalog-Rg-Test' removed; 1 service group(s) deleted; Azure resource group kept.*"
        Should -Invoke Write-Progress -Times 1 -Exactly -ParameterFilter { $Activity -eq 'Removing ServiceEM: Catalog-Rg-Test' -and $Completed }
    }

    It 'clears removal progress on failure without a completion message' {
        $script:RemovalState = 'deliveryFailed'
        Mock Write-Progress {}
        Mock Write-Host {}

        { Remove-EntraOpsServiceCatalog @script:RemoveOptions } | Should -Throw '*did not succeed*'

        Should -Invoke Write-Progress -Times 1 -Exactly -ParameterFilter { $Activity -eq 'Removing ServiceEM: Catalog-Rg-Test' -and $Completed }
        Should -Invoke Write-Host -Times 0 -Exactly
    }

    It 'shows WhatIf without progress or a completion message' {
        Mock Write-Progress {}
        Mock Write-Host {}

        Remove-EntraOpsServiceCatalog @script:RemoveOptions -WhatIf | Out-Null

        Should -Invoke Write-Progress -Times 0 -Exactly
        Should -Invoke Write-Host -Times 0 -Exactly
        @($script:Events | Where-Object { $_ -like 'DELETE *' -or $_ -like 'POST *' }).Count | Should -Be 0
    }

    It 'preserves all resources when removal ends in <State> even if status says Delivered' -TestCases @(
        @{ State = 'deliveryFailed' }, @{ State = 'partiallyDelivered' }, @{ State = 'canceled' }, @{ State = 'denied' }
    ) {
        param($State)
        $script:RemovalState = $State

        { Remove-EntraOpsServiceCatalog @script:RemoveOptions } | Should -Throw "*did not succeed*state '$State'*"

        @($script:Events | Where-Object { $_ -like 'DELETE *' }).Count | Should -Be 0
        Should -Invoke Remove-AzResourceGroup -Times 0 -Exactly
    }

    It 'preserves all resources when an active assignment remains after successful removal requests' {
        $script:RemainingForChecks = 1000

        { Remove-EntraOpsServiceCatalog @script:RemoveOptions } | Should -Throw '*assignments still present*assignment-1*'

        @($script:Events | Where-Object { $_ -like 'DELETE *' }).Count | Should -Be 0
        ($script:Now - [datetime]'2026-01-01T00:00:00Z').TotalSeconds | Should -Be 300
    }

    It 'allows expired assignment history to remain after successful removal' {
        $script:KeepExpiredAssignment = $true

        Remove-EntraOpsServiceCatalog @script:RemoveOptions | Out-Null

        $script:Events | Should -Contain 'DELETE /v1.0/groups/group-1'
        $script:RemainingChecks | Should -Be 1
    }

    It 'does not treat an unknown request state as successful because status says Delivered' {
        $script:RemovalState = 'unknownFutureValue'

        { Remove-EntraOpsServiceCatalog @script:RemoveOptions } | Should -Throw "*still in progress*state 'unknownFutureValue'*"

        @($script:Events | Where-Object { $_ -like 'DELETE *' }).Count | Should -Be 0
    }

    It 'fails closed when a request lookup returns no matching object' {
        $script:MissingRequest = $true

        { Remove-EntraOpsServiceCatalog @script:RemoveOptions } | Should -Throw '*Unable to verify assignment request remove-1*'

        @($script:Events | Where-Object { $_ -like 'DELETE *' }).Count | Should -Be 0
    }

    It 'accepts an empty request list without polling a missing request ID' {
        Mock Invoke-EntraOpsMsGraphQuery -ParameterFilter { $Method -eq 'GET' -and $Uri -like '*/assignmentRequests[?]*' } { $null }

        Remove-EntraOpsServiceCatalog @script:RemoveOptions | Out-Null

        $script:Events | Should -Contain 'DELETE /v1.0/groups/group-1'
        Should -Invoke Invoke-EntraOpsMsGraphQuery -Times 1 -Exactly -ParameterFilter { $Method -eq 'GET' -and $Uri -like '*/assignmentRequests/*' }
    }

    It 'fails closed on forbidden <Lookup> lookups' -TestCases @(
        @{ Lookup = 'catalog'; Pattern = '*/catalogs[?]*' },
        @{ Lookup = 'request list'; Pattern = '*/assignmentRequests[?]*' },
        @{ Lookup = 'request status'; Pattern = '*/assignmentRequests/remove-1' },
        @{ Lookup = 'assignments'; Pattern = '*/assignments[?]*' },
        @{ Lookup = 'resource roles'; Pattern = '*/resourceRoleScopes' }
    ) {
        param($Lookup, $Pattern)
        $script:ReadFailure = $Pattern

        { Remove-EntraOpsServiceCatalog @script:RemoveOptions } | Should -Throw '*Graph 403 Forbidden*'

        @($script:Events | Where-Object { $_ -like 'DELETE *' }).Count | Should -Be 0
    }

    It 'fails closed when assignment verification fails after removals were delivered' {
        Mock Invoke-EntraOpsMsGraphQuery -ParameterFilter { $Method -eq 'GET' -and $Uri -like '*/assignments[?]*' -and $script:RemovalObserved } {
            throw (New-TestGraphError 'Forbidden' 403)
        }

        { Remove-EntraOpsServiceCatalog @script:RemoveOptions } | Should -Throw '*Graph 403 Forbidden*'

        @($script:Events | Where-Object { $_ -like 'DELETE *' }).Count | Should -Be 0
    }

    It 'retries the specific grants-index error and completes teardown' {
        $script:DeleteFailures = 2

        Remove-EntraOpsServiceCatalog @script:RemoveOptions | Out-Null

        Should -Invoke Invoke-EntraOpsMsGraphQuery -Times 3 -Exactly -ParameterFilter { $Method -eq 'DELETE' -and $Uri -like '*/accessPackages/ap-1' }
        $script:Events | Should -Contain 'DELETE /v1.0/groups/group-1'
        ($script:Now - [datetime]'2026-01-01T00:00:00Z').TotalSeconds | Should -Be 4
    }

    It 'bounds grants-index retries and preserves the catalog and groups on exhaustion' {
        $script:DeleteFailures = 1000

        { Remove-EntraOpsServiceCatalog @script:RemoveOptions } | Should -Throw '*incomplete*Active grants still prevent package deletion*'

        $script:Events | Should -Not -Contain 'DELETE /v1.0/groups/group-1'
        $script:Events | Should -Not -Contain 'DELETE /v1.0/identityGovernance/entitlementManagement/catalogs/catalog-1'
        ($script:Now - [datetime]'2026-01-01T00:00:00Z').TotalSeconds | Should -Be 60
    }

    It 'does not retry unrelated package deletion errors (<Status> <Code>)' -TestCases @(
        @{ Status = 403; Code = 'Forbidden' }, @{ Status = 400; Code = 'InvalidRequest' }
    ) {
        param($Status, $Code)
        $script:DeleteFailures = 1000
        $script:DeleteStatus = $Status
        $script:DeleteError = $Code

        { Remove-EntraOpsServiceCatalog @script:RemoveOptions } | Should -Throw "*Graph $Status $Code*"

        Should -Invoke Invoke-EntraOpsMsGraphQuery -Times 1 -Exactly -ParameterFilter { $Method -eq 'DELETE' -and $Uri -like '*/accessPackages/ap-1' }
        $script:Events | Should -Not -Contain 'DELETE /v1.0/groups/group-1'
    }
}
