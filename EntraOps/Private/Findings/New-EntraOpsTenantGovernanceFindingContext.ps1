function New-EntraOpsTenantGovernanceFindingContext {
    <#
    .SYNOPSIS
        Builds the Tenant Governance settings that the Tenant Governance finding rules evaluate.
    .DESCRIPTION
        Uses the newest Tenant Governance snapshot with embedded content of the generated report data
        (Import-EntraOpsReportFindingData): the PIM role settings with their role tiers
        (New-EntraOpsPimRequestFlowFindingContext), the access package assignment policies with the tiers of
        their resources (New-EntraOpsAccessPackageFlowFindingContext), the enabled Conditional Access policies
        and the administrative units. Without a snapshot with embedded content, SnapshotKey is $null and
        Invoke-EntraOpsFindingRuleSet skips the rules.

        Used by Invoke-EntraOpsFindingEvaluation.
    .PARAMETER ReportData
        Datasets from Import-EntraOpsReportFindingData.
    .PARAMETER Pim
        Context of New-EntraOpsPimRequestFlowFindingContext for the same data, to reuse instead of building it again.
    .PARAMETER AccessPackage
        Context of New-EntraOpsAccessPackageFlowFindingContext for the same data, to reuse instead of building it again.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [object]$ReportData,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]$Pim,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]$AccessPackage
    )

    if ($null -eq $Pim) { $Pim = New-EntraOpsPimRequestFlowFindingContext -ReportData $ReportData }
    if ($null -eq $AccessPackage) { $AccessPackage = New-EntraOpsAccessPackageFlowFindingContext -ReportData $ReportData }
    $Snapshot = $ReportData.Snapshots | Where-Object { $_.key -ceq $Pim.SnapshotKey } | Select-Object -First 1
    $Blobs = $ReportData.ConfigurationAnalyzer['blobs']

    $ConditionalAccessPolicies = [System.Collections.Generic.List[object]]::new()
    $AdministrativeUnits = [System.Collections.Generic.List[object]]::new()
    foreach ($Resource in @(if ($Snapshot) { $Snapshot.resources })) {
        $Type = "$($Resource.type)".ToLowerInvariant()
        if ($Type -notin 'microsoft.entra.conditionalaccesspolicy', 'microsoft.entra.administrativeunit') { continue }
        if (-not (Test-EntraOpsJsTruthy $Resource.h) -or $Blobs -isnot [System.Collections.IDictionary] -or -not $Blobs.Contains("$($Resource.h)")) { continue }
        $Blob = $Blobs["$($Resource.h)"]
        if ($Blob -isnot [System.Collections.IDictionary] -or $Blob['properties'] -isnot [System.Collections.IDictionary]) { continue }
        $Properties = $Blob['properties']
        if ($Type -eq 'microsoft.entra.conditionalaccesspolicy') {
            if ("$($Properties['State'])" -eq 'enabled') { $ConditionalAccessPolicies.Add($Properties) }
        } else {
            $AdministrativeUnits.Add($Properties)
        }
    }

    # Groups resolved via their transitive membership, by display name (Conditional Access policies
    # reference groups by display name in the snapshot).
    $ResolvedGroupTierByName = [System.Collections.Generic.Dictionary[string, object]]::new([System.StringComparer]::Ordinal)
    # A name of several groups resolves to none of them: the policy doesn't tell which one it means.
    $AmbiguousGroupNames = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
    foreach ($Group in $ReportData.ResolvedGroupTierIndex.Values) {
        if (-not $Group.displayName) { continue }
        $NameKey = "$($Group.displayName)".ToUpperInvariant()
        if ($AmbiguousGroupNames.Contains($NameKey)) { continue }
        $Named = $null
        if ($ResolvedGroupTierByName.TryGetValue($NameKey, [ref]$Named) -and -not [object]::ReferenceEquals($Named, $Group)) {
            $null = $ResolvedGroupTierByName.Remove($NameKey)
            $null = $AmbiguousGroupNames.Add($NameKey)
        } else { $ResolvedGroupTierByName[$NameKey] = $Group }
    }

    [pscustomobject]@{
        Area                      = 'TenantGovernance'
        SnapshotKey               = $Pim.SnapshotKey
        ReportData                = $ReportData
        Pim                       = $Pim
        AccessPackage             = $AccessPackage
        ConditionalAccessPolicies = $ConditionalAccessPolicies
        AdministrativeUnits       = $AdministrativeUnits
        ResolvedGroupTierByName   = $ResolvedGroupTierByName
        AmbiguousGroupNames       = $AmbiguousGroupNames
    }
}
