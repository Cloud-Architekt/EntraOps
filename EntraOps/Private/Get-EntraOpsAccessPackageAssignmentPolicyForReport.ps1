<#
.SYNOPSIS
    Looks up an access package assignment policy for the report generators and remembers deleted policies for the
    reporting run.

.DESCRIPTION
    New-EntraOpsTenantGovernanceConfigurationAnalyzerData and New-EntraOpsAccessPackageFlowData both look up the
    assignment policies of the Tenant Governance snapshot. A policy deleted in the tenant answers 404 in both, and each
    used to write its own warning per policy, so every deleted policy was reported twice per reporting run.

    The functions in this file share a run-scoped set of policy Ids that Microsoft Graph answered with 404:
    - Start-EntraOpsReportingRunCache starts the set. New-EntraOpsReportingData starts it with -Force at the beginning
      of every run, so a long-lived session never reuses the results of an earlier run. A generator called on its own
      starts its own set; inside a run it uses the run's set.
    - Get-EntraOpsAccessPackageAssignmentPolicyForReport returns the policy, or $null for a deleted policy (known from
      the set or answered 404 now) without a Graph request or a warning. Any other error is thrown to the caller.
    - Complete-EntraOpsReportingRunCache writes one warning that lists all deleted policies and ends the set.

    The not-found result is only kept for the run: the policies are deleted for good, but a new run must not depend
    on what an earlier one found.
#>
function Start-EntraOpsReportingRunCache {
    [CmdletBinding()]
    [OutputType([bool])]
    param (
        # Start a new set even when one is active (beginning of a reporting run).
        [Parameter(Mandatory = $false)]
        [switch]$Force,

        # The command that owns an active set. When it is no longer on the call stack, the set is left over from a run
        # that ended with an error and is replaced.
        [Parameter(Mandatory = $false)]
        [System.String]$Owner = 'New-EntraOpsReportingData'
    )

    $Cache = $Script:EntraOpsReportingRunCache
    if (-not $Force -and $null -ne $Cache -and $Cache.Active) {
        if (@(Get-PSCallStack | Where-Object { $_.FunctionName -eq $Cache.Owner }).Count -gt 0) {
            return $false
        }
        Write-Verbose "Replacing the reporting run cache of '$($Cache.Owner)', which is no longer running."
    }
    $Script:EntraOpsReportingRunCache = @{
        Active                      = $true
        Owner                       = if ($Force) { $Owner } else { (Get-PSCallStack)[1].FunctionName }
        NotFoundAssignmentPolicyIds = [System.Collections.Generic.SortedSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    }
    return $true
}

function Get-EntraOpsAccessPackageAssignmentPolicyForReport {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [System.String]$PolicyId
    )

    $Cache = $Script:EntraOpsReportingRunCache
    $HasCache = $null -ne $Cache -and $Cache.Active
    if ($HasCache -and $Cache.NotFoundAssignmentPolicyIds.Contains($PolicyId)) {
        Write-Verbose "Access package assignment policy $PolicyId was not found earlier in this reporting run; skipped."
        return $null
    }
    try {
        # A deleted policy is reported once per run by Complete-EntraOpsReportingRunCache, not by the Graph helper
        return Invoke-EntraOpsMsGraphQuery -Uri "/beta/identityGovernance/entitlementManagement/accessPackageAssignmentPolicies/$PolicyId" -OutputType PSObject -ThrowOnFailure -SuppressNotFoundWarning
    } catch {
        # Invoke-EntraOpsMsGraphQuery -ThrowOnFailure puts the HTTP status into Exception.Data. Without a run cache the
        # caller's own warning reports the 404.
        if ($HasCache -and $null -ne $_.Exception.Data -and "$($_.Exception.Data['StatusCode'])" -eq '404') {
            [void]$Cache.NotFoundAssignmentPolicyIds.Add($PolicyId)
            return $null
        }
        throw
    }
}

function Complete-EntraOpsReportingRunCache {
    [CmdletBinding()]
    param ()

    $Cache = $Script:EntraOpsReportingRunCache
    if ($null -eq $Cache -or -not $Cache.Active) { return }
    $Script:EntraOpsReportingRunCache = $null
    $NotFoundIds = @($Cache.NotFoundAssignmentPolicyIds)
    if ($NotFoundIds.Count -gt 0) {
        Write-Warning "Access package assignment policies of the Tenant Governance snapshot not found in Microsoft Graph (NotFound) and skipped in the report data ($($NotFoundIds.Count)): $($NotFoundIds -join ', '). They were deleted in the tenant; the next Save-EntraOpsTenantGovernanceSnapshotJson removes their snapshot files once Microsoft Graph confirms the deletion."
    }
}
