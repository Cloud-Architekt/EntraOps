function Get-EntraOpsCrossTenantExpansionWarning {
    <#
    .SYNOPSIS
        The warning of the Privileged EAM collection about groups of other tenants whose members were not read.
    .DESCRIPTION
        Stage 5b of Get-EntraOpsPrivilegedEAMEntraId reads the members of groups of other tenants (remote groups of Tenant
        Governance) only in the managing tenant (ManagingTenantId of EntraOpsConfig.json). Without it, for a group of
        another tenant than the managing tenant, or after a failed expansion, the members and their access are missing
        in the export and in the findings (EO.4010, EO.4011). Returns one warning text that names the groups with
        privileged roles (Control or Management Plane classification of their own role assignments), or nothing.
    .PARAMETER CrossTenantGroupEntries
        The groups of other tenants (ObjectId, ObjectTenantId).
    .PARAMETER MembersExpanded
        Whether the members of a group were read, by object ID.
    .PARAMETER RbacClassification
        The classified role assignments (ObjectId, RoleAssignmentType, Classification with AdminTierLevelName).
    .PARAMETER ObjectDetailsCache
        The resolved objects by object ID (ObjectDisplayName), for the names of the groups.
    .PARAMETER ManagingTenantId
        The managing tenant of the session, empty when ManagingTenantId is not set.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param (
        [Parameter(Mandatory = $false)]
        [AllowEmptyCollection()]
        [object[]]$CrossTenantGroupEntries = @(),

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [System.Collections.IDictionary]$MembersExpanded,

        [Parameter(Mandatory = $false)]
        [AllowEmptyCollection()]
        [AllowNull()]
        [object[]]$RbacClassification = @(),

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [System.Collections.IDictionary]$ObjectDetailsCache,

        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [AllowNull()]
        [string]$ManagingTenantId
    )

    $PrivilegedTierNames = @('ControlPlane', 'ManagementPlane')
    $Groups = @(foreach ($GroupEntry in @($CrossTenantGroupEntries | Where-Object { $null -ne $_ })) {
            $GroupId = "$($GroupEntry.ObjectId)"
            if ($null -ne $MembersExpanded -and $MembersExpanded.Contains($GroupId) -and $MembersExpanded[$GroupId]) { continue }
            $GroupTiers = @(@($RbacClassification) | Where-Object { $null -ne $_ -and "$($_.ObjectId)" -eq $GroupId -and "$($_.RoleAssignmentType)" -ne 'Transitive' } |
                    ForEach-Object { @($_.Classification) } | Where-Object { $null -ne $_ } | ForEach-Object { "$($_.AdminTierLevelName)" })
            if (@($GroupTiers | Where-Object { $_ -in $PrivilegedTierNames }).Count -eq 0) { continue }
            $Details = if ($null -ne $ObjectDetailsCache -and $ObjectDetailsCache.Contains($GroupId)) { $ObjectDetailsCache[$GroupId] } else { $null }
            $GroupName = if ($null -ne $Details -and "$($Details.ObjectDisplayName)".Trim()) { "$($Details.ObjectDisplayName)".Trim() } else { $GroupId }
            "'$GroupName' (tenant $($GroupEntry.ObjectTenantId))"
        })
    if ($Groups.Count -eq 0) { return }

    $Hint = if ([string]::IsNullOrWhiteSpace($ManagingTenantId)) {
        'Set ManagingTenantId in EntraOpsConfig.json to the governing tenant (Tenant Governance) and collect again to read the members of its groups.'
    } else {
        "Members are read only in the managing tenant '$ManagingTenantId': review the members of groups of other tenants in their tenant, and see the warnings above for groups whose expansion failed."
    }
    "The members of $($Groups.Count) group(s) of other tenants with Control or Management Plane roles were not collected, so their access is missing in the Privileged EAM data and its findings (EO.4010, EO.4011): $(@($Groups | Select-Object -First 10) -join ', ')$(if ($Groups.Count -gt 10) { " and $($Groups.Count - 10) more" }). $Hint"
}
