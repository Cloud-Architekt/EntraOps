# Tier table of the Findings rules and the reports, from the most privileged tier. Tier names are
# compared case-sensitively, like the reports (tierRank() of Reports/ConfigurationAnalyzer/js/core.js).
#   * EntraOpsTierName: the tier names in rank order (index = rank).
#   * EntraOpsTierRank: rank of a tier name (ControlPlane = 0 ... Unclassified = 4).
#   * EntraOpsAdminTierLevel: admin tier level of a tier name or number (case-insensitive), see
#     ConvertTo-EntraOpsAdminTierLevel. Hot paths look the level up here directly.
$script:EntraOpsTierName = [string[]]@('ControlPlane', 'ManagementPlane', 'WorkloadPlane', 'UserAccess', 'Unclassified')
$script:EntraOpsTierRank = [System.Collections.Generic.Dictionary[string, int]]::new([System.StringComparer]::Ordinal)
for ($TierIndex = 0; $TierIndex -lt $script:EntraOpsTierName.Count; $TierIndex++) { $script:EntraOpsTierRank[$script:EntraOpsTierName[$TierIndex]] = $TierIndex }
$script:EntraOpsAdminTierLevel = @{ ControlPlane = 0; ManagementPlane = 1; WorkloadPlane = 1; UserAccess = 2; '0' = 0; '1' = 1; '2' = 2 }
Remove-Variable -Name TierIndex

function ConvertTo-EntraOpsAdminTierLevel {
    <#
    .SYNOPSIS
        Normalizes a tier name or number to the Enterprise Access Model admin tier level (0/1/2).
    .DESCRIPTION
        Shared tier table of the Findings rules. The level follows EAMTierLevelTagValue of the
        classification templates: ControlPlane = 0, ManagementPlane and WorkloadPlane = 1,
        UserAccess = 2. A lower level is more privileged. Numeric values 0-2 are returned unchanged.
        Empty values, "Unclassified" and unknown values return -Default (Tier 2, the least privileged
        tier), matching the handling of unclassified objects in the reports.

        This is a privilege level for tier comparisons, not a sort order: WorkloadPlane and
        ManagementPlane share level 1, while reports sort WorkloadPlane after ManagementPlane.
    .PARAMETER Value
        Tier name (ControlPlane, ManagementPlane, WorkloadPlane, UserAccess, Unclassified) or number.
    .PARAMETER Default
        Level returned for empty, unclassified or unknown values. Defaults to 2.
    #>
    [CmdletBinding()]
    [OutputType([int])]
    param (
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]$Value,

        [Parameter(Mandatory = $false)]
        [int]$Default = 2
    )

    if ($null -eq $Value) { return $Default }
    $Text = "$Value".Trim()
    $Level = $script:EntraOpsAdminTierLevel[$Text]
    if ($null -ne $Level) { return $Level }
    # Other spellings of the numbers 0-2 (for example "01").
    $Number = 0
    if ([int]::TryParse($Text, [ref]$Number) -and $Number -in 0, 1, 2) { return $Number }
    return $Default
}

function Get-EntraOpsAdminTierLevel {
    <#
    .SYNOPSIS
        Fast admin tier level of a tier name or number for the hot paths of the Findings rules.
    .DESCRIPTION
        Same result as ConvertTo-EntraOpsAdminTierLevel with the default level 2, as a hashtable lookup in a
        simple function without CmdletBinding: the rules convert the tier of every path, assignment or object.
    #>
    param($Value)

    $Level = $script:EntraOpsAdminTierLevel["$Value"]
    if ($null -ne $Level) { return $Level }
    return (ConvertTo-EntraOpsAdminTierLevel -Value $Value)
}

function Get-EntraOpsReportTierRank {
    <#
    .SYNOPSIS
        Privilege rank of a tier name like tierRank() of Reports/ConfigurationAnalyzer/js/core.js.
    .DESCRIPTION
        ControlPlane = 0, ManagementPlane = 1, WorkloadPlane = 2, UserAccess = 3, Unclassified = 4; any other
        value (also an empty one) ranks 5, after all tiers. Tier names are compared case-sensitively.
    #>
    [CmdletBinding()]
    [OutputType([int])]
    param (
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]$TierName
    )

    $Rank = 0
    if ($null -ne $TierName -and $script:EntraOpsTierRank.TryGetValue([string]$TierName, [ref]$Rank)) { return $Rank }
    return 5
}

function Get-EntraOpsTierDisplayName {
    <#
    .SYNOPSIS
        Display name of a tier for the messages of the finding rules (Control Plane, Management Plane, ...).
    .DESCRIPTION
        Tier names (ControlPlane, ManagementPlane, WorkloadPlane, UserAccess, Unclassified) become their display
        names, admin tier levels (0, 1, 2) the tier of the level (0 Control Plane, 1 Management Plane, 2 User
        Access). An empty value is "Unclassified"; any other value is returned unchanged.
    #>
    param($Value)

    $Text = "$Value".Trim()
    switch -CaseSensitive ($Text) {
        'ControlPlane' { return 'Control Plane' }
        'ManagementPlane' { return 'Management Plane' }
        'WorkloadPlane' { return 'Workload Plane' }
        'UserAccess' { return 'User Access' }
        'Unclassified' { return 'Unclassified' }
        '' { return 'Unclassified' }
        '0' { return 'Control Plane' }
        '1' { return 'Management Plane' }
        '2' { return 'User Access' }
    }
    return $Text
}

function Test-EntraOpsPrivilegedTier {
    <#
    .SYNOPSIS
        Tests whether a tier name is a privileged tier (ControlPlane or ManagementPlane).
    .DESCRIPTION
        "Privileged" in the finding rules and the reports means Control Plane or Management Plane. Tier names
        are compared case-sensitively, like the reports.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param (
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]$TierName
    )

    $TierName -ceq 'ControlPlane' -or $TierName -ceq 'ManagementPlane'
}

function Get-EntraOpsMostPrivilegedTier {
    <#
    .SYNOPSIS
        Returns the most privileged of the tier names, or $null when none is a tier.
    .DESCRIPTION
        Unknown names are ignored; Unclassified only counts with -IncludeUnclassified (it ranks after all
        other tiers).
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param (
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [AllowEmptyCollection()]
        [object[]]$TierName = @(),

        [Parameter(Mandatory = $false)]
        [switch]$IncludeUnclassified
    )

    $Limit = if ($IncludeUnclassified) { 4 } else { 3 }
    $Best = 5
    foreach ($Name in @($TierName)) {
        $Rank = 0
        if ($null -ne $Name -and $script:EntraOpsTierRank.TryGetValue([string]$Name, [ref]$Rank) -and $Rank -le $Limit -and $Rank -lt $Best) { $Best = $Rank }
    }
    if ($Best -gt $Limit) { return $null }
    return $script:EntraOpsTierName[$Best]
}
