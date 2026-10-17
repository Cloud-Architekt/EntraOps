function Undo-EntraOpsServiceEMUnregisteredGroup {
    <#
    .SYNOPSIS
        Cleans up newly created, unregistered groups after early ServiceEM provisioning fails.
    .DESCRIPTION
        Called only before catalog resource registration completes. IDs come from successful group
        creation responses in this attempt, never from a name search. When resource registration was
        attempted, reads the catalog again and keeps its registered groups. An inconclusive lookup
        keeps every group. Cleanup failures are warnings; the caller rethrows the provisioning error.
        Groups are only soft-deleted, so every removed group stays restorable for 30 days.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [string[]]$CreatedGroupIds,

        [string[]]$RegisteredGroupIds = @(),

        [string]$ServiceCatalogId,

        [string]$logPrefix = '[New-EntraOpsServiceBootstrap]'
    )

    if ($CreatedGroupIds.Count -eq 0) { return }

    if (-not [string]::IsNullOrWhiteSpace($ServiceCatalogId)) {
        try {
            $Resources = @(Invoke-EntraOpsMsGraphQuery -Method GET -Uri "/v1.0/identityGovernance/entitlementManagement/catalogs/$ServiceCatalogId/resources?`$select=originId,originSystem" -OutputType PSObject -DisableCache -ThrowOnFailure)
            $RegisteredGroupIds += @($Resources | Where-Object { $_.OriginSystem -eq 'AadGroup' } | ForEach-Object { $_.OriginId })
        } catch {
            Write-Warning "$logPrefix Could not verify catalog registration; newly created groups were kept: $($CreatedGroupIds -join ', '). Verify these IDs and register the intended groups as resources of catalog '$ServiceCatalogId' before retrying. Error: $($_.Exception.Message)"
            return
        }
    }

    $Removed = [System.Collections.Generic.List[string]]::new()
    $Failures = [System.Collections.Generic.List[string]]::new()
    foreach ($GroupId in $CreatedGroupIds | Select-Object -Unique) {
        if ($GroupId -in $RegisteredGroupIds) {
            Write-Verbose "$logPrefix Keeping newly created group ${GroupId}: it is registered in catalog '$ServiceCatalogId' and can be reused on retry."
            continue
        }
        try {
            Invoke-EntraOpsMsGraphQuery -Method DELETE -Uri "/v1.0/groups/$GroupId" -ThrowOnFailure -SuppressNotFoundWarning | Out-Null
            $Removed.Add($GroupId)
        } catch {
            if ($_.Exception.Data['StatusCode'] -eq 404) { continue }
            $Failures.Add("$GroupId ($($_.Exception.Message))")
        }
    }
    if ($Removed.Count -gt 0) {
        Write-Warning "$logPrefix Provisioning failed before catalog registration completed. Removed newly created, unregistered groups so the deployment can be retried (restorable from the deleted groups for 30 days): $($Removed -join ', ')."
    }
    if ($Failures.Count -gt 0) {
        Write-Warning "$logPrefix Could not remove newly created, unregistered groups: $($Failures -join '; '). Verify these IDs and delete the unused groups, or register the intended groups as catalog resources, before retrying."
    }
}
