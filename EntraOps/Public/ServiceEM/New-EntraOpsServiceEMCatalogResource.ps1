<#
.SYNOPSIS
    Registers Entra security groups as resources inside an EM catalog.

.DESCRIPTION
    Submits adminAdd resource requests to onboard each provided Entra group
    as an AadGroup resource inside the specified Entitlement Management
    catalog. Only groups not already registered are onboarded.

    Idempotent: groups already present in the catalog (ResourceAlreadyOnboarded)
    are silently skipped.

    Note: Only owned (non-delegated) groups should be passed. Delegated groups
    are not catalog resources and must not be registered here.

.PARAMETER ServiceGroups
    Entra group objects to register as catalog resources. Pass only the
    $ownedGroups subset from New-EntraOpsServiceBootstrap (IsDelegated -ne true).

.PARAMETER ServiceCatalogId
    Object ID of the Entitlement Management catalog to register resources in.

.PARAMETER logPrefix
    Text prepended to verbose messages. Defaults to the function name.

.PARAMETER RegisteredGroupIds
    Used by New-EntraOpsServiceBootstrap to record groups whose registration was accepted, even when a
    later lookup fails. These groups are kept during failure cleanup while Graph indexing catches up.

.EXAMPLE
    New-EntraOpsServiceEMCatalogResource `
        -ServiceGroups ($groups | Where-Object { -not $_.IsDelegated }) `
        -ServiceCatalogId "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"

    Registers all owned service groups as AadGroup resources in the catalog.

#>
function New-EntraOpsServiceEMCatalogResource {
    [OutputType([psobject[]])]
    [cmdletbinding()]
    param(
        [Parameter(Mandatory)]
        [psobject[]]$ServiceGroups,

        [Parameter(Mandatory)]
        [string]$ServiceCatalogId,

        [Parameter(DontShow)]
        [AllowEmptyCollection()]
        [System.Collections.Generic.List[string]]$RegisteredGroupIds,

        [string]$logPrefix = "[$($MyInvocation.MyCommand)]"
    )

    begin {
        $resources = @()
        Write-Verbose "$logPrefix Looking up Catalog Resources"
        try {
            #Catalog Resource Registration
            $catalogResourceUri = "/v1.0/identityGovernance/entitlementManagement/catalogs/$ServiceCatalogId/resources?`$expand=roles,scopes"
            $resources += Invoke-EntraOpsMsGraphQuery -Method GET -Uri $catalogResourceUri -OutputType PSObject -DisableCache -ThrowOnFailure
        } catch {
            Write-Verbose "$logPrefix Failed to find Catalog Resources"
            throw "Failed to look up catalog resources for ${ServiceCatalogId}: $($_.Exception.Message)"
        }
    }

    process {
        Write-Verbose "$logPrefix Beginning EM Catalog Resource"

        Write-Verbose "$logPrefix Processing $(($ServiceGroups|Measure-Object).Count) Catalog Resources"
        foreach ($group in $ServiceGroups) {
            $resourceRequestParam = @{
                requestType = "adminAdd"
                resource    = @{
                    originId     = $group.Id
                    originSystem = "AadGroup"
                }
                catalog     = @{
                    id = $ServiceCatalogId
                }
            }

            if ($group.Id -notin @($resources | Where-Object { $_.OriginSystem -eq 'AadGroup' } | ForEach-Object { $_.OriginId })) {
                $added = Wait-EntraOpsServiceEMCondition -Activity "Group $($group.DisplayName) in Entitlement Management" -logPrefix $logPrefix -Condition {
                    try {
                        Write-Verbose "$logPrefix $($group.DisplayName) not found as catalog resource, adding"
                        Invoke-EntraOpsMsGraphQuery -Method POST -Uri "/v1.0/identityGovernance/entitlementManagement/resourceRequests" -Body ($resourceRequestParam | ConvertTo-Json -Depth 10) -OutputType PSObject -ThrowOnFailure -SuppressBadRequestWarning -SuppressNotFoundWarning | Out-Null
                        return $true
                    } catch {
                        switch ($_.Exception.Data['ErrorCode']) {
                            'ResourceAlreadyOnboarded' {
                                Write-Verbose "$logPrefix Resource already onboarded"
                                return $true
                            }
                            'ResourceNotFoundInOriginSystem' {
                                Write-Verbose "$logPrefix Group not yet indexed by Entitlement Management, will retry"
                                return $false
                            }
                        }
                        if ($_.Exception.Data['StatusCode'] -eq 404) { return $false }
                        throw
                    }
                }
                if (-not $added) {
                    throw "Group object consistency with Entitlement Management not achieved for $($group.DisplayName)"
                }
            }
            if ($null -ne $RegisteredGroupIds) { $RegisteredGroupIds.Add($group.Id) }
        }
    }

    end {
        $check = @{ LastError = $null }
        $confirmed = Wait-EntraOpsServiceEMCondition -Activity "Catalog resources" -logPrefix $logPrefix -Condition {
            try {
                $check.Resources = Invoke-EntraOpsMsGraphQuery -Method GET -Uri $catalogResourceUri -OutputType PSObject -DisableCache -ThrowOnFailure
            } catch {
                # Invoke-EntraOpsMsGraphQuery already retried throttling and transient server errors. Keep polling
                # only while the state can still change (network error, catalog not replicated yet, server error);
                # a permission or request error won't resolve by waiting, so it is reported as it is.
                $StatusCode = $_.Exception.Data['StatusCode']
                if ($null -ne $StatusCode -and $StatusCode -notin @(404, 408, 429) -and $StatusCode -lt 500) { throw }
                $check.LastError = $_.Exception.Message
                Write-Verbose "$logPrefix Catalog resource lookup failed during the consistency check, retrying: $($check.LastError)"
                return $false
            }
            $check.LastError = $null
            $refIds = @($ServiceGroups.Id | Where-Object { $_ })
            $chkIds = @($check.Resources | Where-Object { $_.OriginSystem -eq 'AadGroup' } | ForEach-Object { $_.OriginId })
            # The catalog may hold further resources (e.g. shared or manually added groups)
            $refIds.Count -gt 0 -and @($refIds | Where-Object { $_ -notin $chkIds }).Count -eq 0
        }
        if (-not $confirmed) {
            if ($check.LastError) {
                throw "Catalog Resource object consistency with Entra not achieved. Last catalog resource lookup error: $($check.LastError)"
            }
            throw "Catalog Resource object consistency with Entra not achieved"
        }
        return [psobject[]]$check.Resources
    }
}
