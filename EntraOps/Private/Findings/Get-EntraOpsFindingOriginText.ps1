function Get-EntraOpsFindingObjectTenant {
    <#
    .SYNOPSIS
        The tenant that manages a privileged object, for the rules about principals of other tenants (EO.4010, EO.4011).
    .DESCRIPTION
        The origin tenant of the Privileged EAM export (OriginTenantId, EntraOps 1.2.0 or later: the source tenant of
        cross-tenant synchronization, the home tenant of a guest, the tenant of an application), else the tenant of
        the object itself (ObjectTenantId: a group or member of a governing tenant, a remote group). Lowercase.
    .PARAMETER Object
        An object of the inventory of New-EntraOpsPrivilegedAssetsFindingContext.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param (
        [Parameter(Mandatory = $true)]
        [object]$Object
    )
    $Tenant = if ("$($Object.originTenantId)") { "$($Object.originTenantId)" } else { "$($Object.objectTenantId)" }
    $Tenant.Trim().ToLowerInvariant()
}

function Test-EntraOpsFindingManagingTenant {
    <#
    .SYNOPSIS
        Tests whether a privileged object is managed by the managing tenant (ManagingTenantId of EntraOpsConfig.json).
    .DESCRIPTION
        The managing tenant governs this tenant through Tenant Governance, so access of its principals is the intended
        design of the relationship. Without ManagingTenantId, no object is of the managing tenant.
    .PARAMETER Object
        An object of the inventory of New-EntraOpsPrivilegedAssetsFindingContext.
    .PARAMETER ManagingTenantId
        ManagingTenantId of EntraOpsConfig.json (a tenant ID), or empty.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param (
        [Parameter(Mandatory = $true)]
        [object]$Object,

        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string]$ManagingTenantId
    )
    $Managing = "$ManagingTenantId".Trim().ToLowerInvariant()
    [bool]($Managing -and (Get-EntraOpsFindingObjectTenant -Object $Object) -eq $Managing)
}

function Get-EntraOpsFindingOriginText {
    <#
    .SYNOPSIS
        How a privileged object of another tenant came to this tenant, for the messages of EO.4010 and EO.4011.
    .DESCRIPTION
        From the origin of the Privileged EAM export (OriginType and OriginTenantId, EntraOps 1.2.0 or later):
        "synchronized from tenant <id> (cross-tenant synchronization)", "a guest invited from tenant <id>" or "an external
        member invited from tenant <id>" (userType Member), "an
        object of tenant <id> with access through Tenant Governance", "the application of tenant <id>", and for data
        without an origin "a guest or external user" or "an object of tenant <id>". The managing tenant
        (ManagingTenantId of EntraOpsConfig.json) is named as such: "tenant <id> (the managing tenant <name>)".
    .PARAMETER Object
        An object of the inventory of New-EntraOpsPrivilegedAssetsFindingContext.
    .PARAMETER HomeTenantId
        The tenant of the Privileged EAM export.
    .PARAMETER ManagingTenantId
        ManagingTenantId of EntraOpsConfig.json, or empty.
    .PARAMETER ManagingTenantName
        ManagingTenantName of EntraOpsConfig.json, or empty.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param (
        [Parameter(Mandatory = $true)]
        [object]$Object,

        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string]$HomeTenantId,

        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string]$ManagingTenantId,

        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string]$ManagingTenantName
    )
    $HomeTenant = "$HomeTenantId".ToLowerInvariant()
    $Managing = "$ManagingTenantId".Trim().ToLowerInvariant()
    function Get-TenantText([string]$TenantId) {
        if ($Managing -and $TenantId.ToLowerInvariant() -eq $Managing) {
            return "tenant $TenantId (the managing tenant$(if ("$ManagingTenantName".Trim()) { " $("$ManagingTenantName".Trim())" }))"
        }
        "tenant $TenantId"
    }
    $OriginTenant = "$($Object.originTenantId)"
    switch -CaseSensitive ("$($Object.originType)") {
        'CrossTenantSync' { "synchronized from $(Get-TenantText $OriginTenant) (cross-tenant synchronization)"; break }
        'B2BInvitation' {
            # An invited user is a guest or, with userType Member, an external member.
            $Invited = if ("$($Object.objectSubType)" -eq 'Guest') { 'a guest' } else { 'an external member' }
            if ($OriginTenant) { "$Invited invited from $(Get-TenantText $OriginTenant)" } elseif ("$($Object.objectSubType)" -eq 'Guest') { 'a guest' } else { 'an external member' }
            break
        }
        'TenantGovernance' { "an object of $(Get-TenantText $(if ($OriginTenant) { $OriginTenant } else { "$($Object.objectTenantId)" })) with access through Tenant Governance"; break }
        default {
            if ($Object.objectType -eq 'user' -and $Object.outsideOfHomeTenant) { 'a guest or external user' }
            elseif ($Object.objectType -eq 'serviceprincipal' -and $OriginTenant -and $OriginTenant -ne $HomeTenant) { "the application of $(Get-TenantText $OriginTenant)" }
            elseif ($OriginTenant -and $OriginTenant -ne $HomeTenant) { "an object of $(Get-TenantText $OriginTenant)" }
            elseif ("$($Object.objectTenantId)") { "an object of $(Get-TenantText "$($Object.objectTenantId)")" }
            else { 'outside the home tenant' }
        }
    }
}
