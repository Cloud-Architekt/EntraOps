function Get-EntraOpsExposureManagementBaseline {
    <#
    .SYNOPSIS
        Reads the results of the last successful Exposure Management query from a scope reasoning file.
    .DESCRIPTION
        The "ExposureManagement" block is a usable baseline only for a successful query with the same tenant,
        criticality level and query version. HasUnusablePreviousResults tells whether the previous classification
        may contain Exposure Management results that can't be carried forward.
    .PARAMETER Path
        Path of the previous scope reasoning file.
    .PARAMETER TenantId
        Tenant of the current query.
    .PARAMETER ExposureCriticalityLevel
        Criticality level filter of the current query.
    .PARAMETER QueryVersion
        Version of the current query. Changes only when the meaning of the query result changes.
    .PARAMETER GetLegacyResults
        Returns the Exposure Management entries of a file written before the block existed.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [string]$Path,
        [Parameter(Mandatory = $false)]
        [string]$TenantId,
        [Parameter(Mandatory = $false)]
        [string]$ExposureCriticalityLevel,
        [Parameter(Mandatory = $true)]
        [int]$QueryVersion,
        [Parameter(Mandatory = $false)]
        [scriptblock]$GetLegacyResults = { param($Content) @() }
    )

    $Baseline = [pscustomobject]@{
        FileExists                 = $false
        IsValid                    = $false
        HasUnusablePreviousResults = $false
        InvalidReason              = $null
        LastSuccessfulQueryDate    = $null
        Results                    = @()
    }

    if ([string]::IsNullOrWhiteSpace($Path) -or -not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        $Baseline.InvalidReason = "no previous scope reasoning file"
        return $Baseline
    }
    $Baseline.FileExists = $true

    try {
        $Content = Get-Content -LiteralPath $Path -Raw -ErrorAction Stop | ConvertFrom-Json -Depth 20 -ErrorAction Stop
    } catch {
        $Baseline.InvalidReason = "previous scope reasoning file is unreadable"
        $Baseline.HasUnusablePreviousResults = $true
        return $Baseline
    }

    $BlockProperty = if ($null -ne $Content) { $Content.PSObject.Properties['ExposureManagement'] }
    if ($null -eq $BlockProperty -or $null -eq $BlockProperty.Value) {
        $Baseline.InvalidReason = "previous scope reasoning file has no recorded Exposure Management query"
        $Baseline.HasUnusablePreviousResults = @(& $GetLegacyResults $Content).Count -gt 0
        return $Baseline
    }

    $Block = $BlockProperty.Value
    $GetValue = {
        param($Name)
        $Property = $Block.PSObject.Properties[$Name]
        if ($null -ne $Property) { $Property.Value }
    }
    $Results = @(& $GetValue 'Results' | Where-Object { $null -ne $_ })

    if ((& $GetValue 'Status') -notin @('Succeeded', 'CarriedForward')) {
        # The query never succeeded, so the previous classification has no Exposure Management results to lose.
        $Baseline.InvalidReason = "no successful Exposure Management query recorded"
        return $Baseline
    }

    $LastSuccessfulQueryDate = [datetime]::MinValue
    $DateStyles = [System.Globalization.DateTimeStyles]::AssumeUniversal -bor [System.Globalization.DateTimeStyles]::AdjustToUniversal
    if (-not [datetime]::TryParseExact("$(& $GetValue 'LastSuccessfulQueryDate')", 'yyyy-MM-dd', [cultureinfo]::InvariantCulture, $DateStyles, [ref]$LastSuccessfulQueryDate)) {
        $Baseline.InvalidReason = "previous Exposure Management query has no valid date"
        $Baseline.HasUnusablePreviousResults = $Results.Count -gt 0
        return $Baseline
    }

    $Mismatches = @(
        if ([string]::IsNullOrWhiteSpace($TenantId) -or "$(& $GetValue 'TenantId')" -ne $TenantId) { 'tenant' }
        if ("$(& $GetValue 'ExposureCriticalityLevel')".Trim() -ne "$ExposureCriticalityLevel".Trim()) { 'criticality level' }
        if ("$(& $GetValue 'QueryVersion')" -ne "$QueryVersion") { 'query version' }
    )
    if ($Mismatches.Count -gt 0) {
        $Baseline.InvalidReason = "previous Exposure Management results were collected with a different $($Mismatches -join ', ')"
        $Baseline.HasUnusablePreviousResults = $Results.Count -gt 0
        return $Baseline
    }

    $Baseline.IsValid = $true
    $Baseline.LastSuccessfulQueryDate = $LastSuccessfulQueryDate
    $Baseline.Results = $Results
    $Baseline
}
