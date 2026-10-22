function Invoke-EntraOpsExposureManagementQuery {
    <#
    .SYNOPSIS
        Runs an Exposure Management hunting query and falls back to the results of the last successful query.
    .DESCRIPTION
        A failed query uses the results of the baseline (Status "CarriedForward") and reports a warning; without
        a valid baseline the status is "Failed". Metadata is the "ExposureManagement" block the caller persists; its
        date has day precision.
    .PARAMETER Query
        KQL query for /security/runHuntingQuery.
    .PARAMETER Context
        What the query classifies, used in warnings (e.g. "Control Plane objects").
    .PARAMETER Baseline
        Result of Get-EntraOpsExposureManagementBaseline.
    .PARAMETER StaleAfterDays
        Age of carried forward results from which the warning is escalated.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Query,
        [Parameter(Mandatory = $true)]
        [string]$Context,
        [Parameter(Mandatory = $false)]
        [object]$Baseline,
        [Parameter(Mandatory = $false)]
        [string]$TenantId,
        [Parameter(Mandatory = $false)]
        [string]$ExposureCriticalityLevel,
        [Parameter(Mandatory = $true)]
        [int]$QueryVersion,
        [Parameter(Mandatory = $false)]
        [string]$Timespan = "P1D",
        [Parameter(Mandatory = $false)]
        [int]$StaleAfterDays = 7,
        [Parameter(Mandatory = $false)]
        [datetime]$UtcNow = [datetime]::UtcNow
    )

    $Metadata = [ordered]@{
        Status                   = $null
        LastSuccessfulQueryDate  = $null
        TenantId                 = $TenantId
        ExposureCriticalityLevel = $ExposureCriticalityLevel
        QueryVersion             = $QueryVersion
    }

    $Body = @{ "Query" = $Query; "Timespan" = $Timespan } | ConvertTo-Json
    try {
        # -ThrowOnFailure: a failed query must not look like a successful query without results.
        $Response = Invoke-EntraOpsMsGraphQuery -Method POST -Uri "/beta/security/runHuntingQuery" -Body $Body -OutputType PSObject -ThrowOnFailure -SuppressNotFoundWarning -SuppressBadRequestWarning -SuppressForbiddenWarning
        $Metadata.Status = 'Succeeded'
        $Metadata.LastSuccessfulQueryDate = $UtcNow.ToString('yyyy-MM-dd', [cultureinfo]::InvariantCulture)
        return [pscustomobject]@{
            Status                     = 'Succeeded'
            Results                    = @($Response.results | Where-Object { $null -ne $_ })
            Metadata                   = $Metadata
            Warnings                   = @()
            HasUnusablePreviousResults = $false
        }
    } catch {
        $QueryError = $_
    }

    $StatusCode = $null
    if ($null -ne $QueryError.Exception.Data -and $QueryError.Exception.Data.Contains('StatusCode')) {
        $StatusCode = $QueryError.Exception.Data['StatusCode']
    }
    # Missing permission or license is not transient, but doesn't mean the tenant has no critical assets.
    $Category = if ($StatusCode -in @(401, 403)) { 'AccessDenied' } elseif ($StatusCode -eq 400) { 'QueryRejected' } else { 'Unavailable' }
    $Cause = switch ($Category) {
        'AccessDenied' { "access denied (HTTP $StatusCode); check the ThreatHunting.Read.All permission and the Exposure Management license" }
        'QueryRejected' { "query rejected (HTTP 400); check the criticality level filter '$ExposureCriticalityLevel'" }
        default { if ($null -ne $StatusCode) { "service unavailable (HTTP $StatusCode)" } else { "service unavailable" } }
    }
    $ErrorMessage = ("$($QueryError.Exception.Message)" -replace '\s+', ' ').Trim()
    if ($ErrorMessage.Length -gt 300) { $ErrorMessage = $ErrorMessage.Substring(0, 300) }
    $Metadata.LastFailure = [ordered]@{
        Category   = $Category
        StatusCode = $StatusCode
        Message    = $ErrorMessage
    }

    if ($null -ne $Baseline -and $Baseline.IsValid) {
        $LastSuccessfulQueryDate = $Baseline.LastSuccessfulQueryDate.ToString('yyyy-MM-dd', [cultureinfo]::InvariantCulture)
        $AgeInDays = [int][Math]::Floor(($UtcNow.Date - $Baseline.LastSuccessfulQueryDate.Date).TotalDays)
        $Metadata.Status = 'CarriedForward'
        $Metadata.LastSuccessfulQueryDate = $LastSuccessfulQueryDate

        $WarningType = "ExposureManagement$Category"
        $Message = "Exposure Management query for $Context failed: $Cause. Kept $(@($Baseline.Results).Count) result(s) of the last successful query from $LastSuccessfulQueryDate (UTC)."
        if ($AgeInDays -ge $StaleAfterDays) {
            $WarningType = 'ExposureManagementStale'
            $Message += " These results are $AgeInDays days old and no longer reflect current attack paths; restore the Exposure Management query."
        }
        return [pscustomobject]@{
            Status                     = 'CarriedForward'
            Results                    = @($Baseline.Results)
            Metadata                   = $Metadata
            Warnings                   = @([pscustomobject]@{ Type = $WarningType; Message = $Message })
            HasUnusablePreviousResults = $false
        }
    }

    $InvalidReason = if ($null -ne $Baseline -and -not [string]::IsNullOrWhiteSpace($Baseline.InvalidReason)) { $Baseline.InvalidReason } else { "no previous scope reasoning file" }
    $Metadata.Status = 'Failed'
    [pscustomobject]@{
        Status                     = 'Failed'
        Results                    = @()
        Metadata                   = $Metadata
        Warnings                   = @([pscustomobject]@{ Type = "ExposureManagement$Category"; Message = "Exposure Management query for $Context failed: $Cause. No results of a previous successful query are available ($InvalidReason)." })
        HasUnusablePreviousResults = ($null -ne $Baseline -and [bool]$Baseline.HasUnusablePreviousResults)
    }
}
