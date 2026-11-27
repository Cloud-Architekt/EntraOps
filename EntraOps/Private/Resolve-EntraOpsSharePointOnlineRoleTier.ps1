function Resolve-EntraOpsSharePointOnlineRoleTier {
    <#
    .SYNOPSIS
        Maps a SharePoint Online access package resource role to an EAM tier.
    .DESCRIPTION
        Role-aware SharePoint tiering: administrative roles (owners, full control, site collection
        admin, designer) are ManagementPlane; member/visitor/read roles are UserAccess; unknown
        roles conservatively fall back to ManagementPlane (site-level roles cannot grant
        tenant-wide control, so ManagementPlane is the ceiling - genuinely sensitive sites should
        be raised via tenant classification overwrites).

        Resolution order:
        1. English display-name match - unambiguous when it hits.
        2. Role originId against the default associated site group IDs (Owners = 3, Visitors = 4,
           Members = 5). These IDs are assigned at site provisioning and are locale-independent,
           so localized group names (e.g. "Besucher", "Mitglieder", "Besitzer") still resolve.
           Verified against real ELM payloads (Visitors role originId 4); sites with recreated
           default groups may deviate, in which case the conservative fallback applies.
        3. ManagementPlane fallback with IsFallback = $true so callers can surface a warning.

        A call with neither a role display name nor an originId is a catalog-level resource entry
        (the catalog inventory does not carry roles). It returns ManagementPlane with
        IsCatalogLevel = $true and IsFallback = $false: the tier is conservative because the
        catalog can expose any of the site's roles (including owner-level) through its access
        packages, but it is not an "unknown role" condition and must not raise that warning.
    .PARAMETER RoleDisplayName
        Display name of the accessPackageResourceRole (e.g. "Give @ Contoso Visitors").
    .PARAMETER RoleOriginId
        originId of the accessPackageResourceRole - the SharePoint site group ID as a string.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string]$RoleDisplayName,

        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string]$RoleOriginId
    )

    # Catalog-level resource entry: no role information exists at this level by definition.
    if ([string]::IsNullOrEmpty($RoleDisplayName) -and [string]::IsNullOrEmpty($RoleOriginId)) {
        return [pscustomobject]@{ AdminTierLevel = '1'; AdminTierLevelName = 'ManagementPlane'; IsFallback = $false; IsCatalogLevel = $true }
    }

    # 1) English display-name match
    if ($RoleDisplayName -match '(?i)(owner|full\s*control|site\s*collection\s*admin|administrator|manage|designer)') {
        return [pscustomobject]@{ AdminTierLevel = '1'; AdminTierLevelName = 'ManagementPlane'; IsFallback = $false; IsCatalogLevel = $false }
    }
    if ($RoleDisplayName -match '(?i)(member|contribut|visitor|read|view|limited\s*access|edit)') {
        return [pscustomobject]@{ AdminTierLevel = '2'; AdminTierLevelName = 'UserAccess'; IsFallback = $false; IsCatalogLevel = $false }
    }

    # 2) Default associated site group IDs (locale-independent)
    switch ($RoleOriginId) {
        '3' { return [pscustomobject]@{ AdminTierLevel = '1'; AdminTierLevelName = 'ManagementPlane'; IsFallback = $false; IsCatalogLevel = $false } }
        '4' { return [pscustomobject]@{ AdminTierLevel = '2'; AdminTierLevelName = 'UserAccess'; IsFallback = $false; IsCatalogLevel = $false } }
        '5' { return [pscustomobject]@{ AdminTierLevel = '2'; AdminTierLevelName = 'UserAccess'; IsFallback = $false; IsCatalogLevel = $false } }
    }

    # 3) Unknown role - conservative ManagementPlane ceiling
    return [pscustomobject]@{ AdminTierLevel = '1'; AdminTierLevelName = 'ManagementPlane'; IsFallback = $true; IsCatalogLevel = $false }
}
