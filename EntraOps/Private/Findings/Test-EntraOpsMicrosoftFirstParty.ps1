function Test-EntraOpsMicrosoftFirstParty {
    <#
    .SYNOPSIS
        Tests whether a service principal belongs to a Microsoft first-party application.
    .DESCRIPTION
        Microsoft operates the service principals of its own applications (for example MS-PIM, the service of
        Privileged Identity Management for Azure resources, or the services of Microsoft Entra ID Governance):
        the tenant cannot add credentials to them or change their code, so they are not a path of the tenant
        into a more privileged tier. A service principal is Microsoft first-party when the application belongs
        to a Microsoft tenant (OriginTenantId of the Privileged EAM export, EntraOps 1.2.0 or later).
        Exports without the property recognize MS-PIM by its well-known application ID.

        Microsoft also publishes applications from other tenants: Microsoft Graph Command Line Tools and Graph
        Explorer belong to the tenant cdc5aeea-15c5-4db6-b079-fcadd2505dc2. They are recognized by their
        application ID together with this tenant (or without a tenant in older exports), so a tenant of another
        organization is never taken as Microsoft. Their delegated permissions are still granted by the consent
        of the tenant: see Test-EntraOpsMicrosoftConsentClient.
    .PARAMETER AppOwnerOrganizationId
        The tenant of the application (appOwnerOrganizationId of the service principal).
    .PARAMETER AppId
        The application ID of the service principal (ObjectUserPrincipalName of the export).
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param (
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$AppOwnerOrganizationId,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$AppId
    )

    # Microsoft Services, Microsoft (corporate) and the Microsoft AME tenant (for example Windows Virtual Desktop and
    # Azure DevOps service principals), which own the Microsoft first-party applications.
    $MicrosoftTenantIds = @('f8cdef31-a31e-4b4a-93e4-5f571e91255a', '72f988bf-86f1-41af-91ab-2d7cd011db47', '33e01921-4d64-4f8c-a055-5bdaffd5e33d')
    # MS-PIM, for exports without the application tenant.
    $WellKnownAppIds = @('01fc33a7-78ba-4d2f-a4b7-768e336e890e')
    # Microsoft applications of other Microsoft tenants: application ID and the tenant of the application.
    $MicrosoftAppsOfOtherTenants = @{
        '14d82eec-204b-4c2f-b7e8-296a70dab67e' = 'cdc5aeea-15c5-4db6-b079-fcadd2505dc2' # Microsoft Graph Command Line Tools
        'de8bc8b5-d9f9-48b1-a8ad-b748da725064' = 'cdc5aeea-15c5-4db6-b079-fcadd2505dc2' # Graph Explorer
    }

    $Owner = if ($AppOwnerOrganizationId) { $AppOwnerOrganizationId.ToLowerInvariant() } else { '' }
    $Id = if ($AppId) { $AppId.ToLowerInvariant() } else { '' }
    if ($Id -and $MicrosoftAppsOfOtherTenants.ContainsKey($Id) -and (-not $Owner -or $Owner -eq $MicrosoftAppsOfOtherTenants[$Id])) { return $true }
    if ($Owner) { return $MicrosoftTenantIds -contains $Owner }
    return [bool]$Id -and $WellKnownAppIds -contains $Id
}

function Test-EntraOpsMicrosoftConsentClient {
    <#
    .SYNOPSIS
        Tests whether a service principal belongs to a Microsoft client application whose delegated permissions
        the tenant grants by consent.
    .DESCRIPTION
        Microsoft Graph Command Line Tools, Graph Explorer, Microsoft Intune PowerShell (retired by Microsoft, but
        its grants can remain), SharePoint Online Web Client Extensibility (the permissions approved for SharePoint
        Framework solutions), Microsoft Developer Sample Data Packs, Azure AD Assessment and M365 Lighthouse API (each
        consented to when an administrator sets it up) are Microsoft applications (see Test-EntraOpsMicrosoftFirstParty), but unlike
        pre-authorized first-party clients their delegated permissions exist only because an administrator or user
        of the tenant consented to them. The tenant controls and can revoke these grants, so the delegated
        permission rule (EO.5005) still reports them.
    .PARAMETER AppId
        The application ID of the service principal (ObjectUserPrincipalName of the export).
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param (
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$AppId
    )

    $ConsentClientAppIds = @(
        '14d82eec-204b-4c2f-b7e8-296a70dab67e' # Microsoft Graph Command Line Tools
        'de8bc8b5-d9f9-48b1-a8ad-b748da725064' # Graph Explorer
        'd1ddf0e4-d672-4dae-b554-9d5bdfd93547' # Microsoft Intune PowerShell
        '08e18876-6177-487e-b8b5-cf950c1e598c' # SharePoint Online Web Client Extensibility
        'a1cffbc6-1cb3-44e4-a1d2-cee9cce700f1' # Microsoft Developer Sample Data Packs (Microsoft 365 Developer Program)
        '68bc31c0-f891-4f4c-9309-c6104f7be41b' # Azure AD Assessment (Microsoft Entra assessment)
        '4eaa7769-3cf1-458c-a693-e9827e39cc95' # M365 Lighthouse API (onboarding of Microsoft 365 Lighthouse)
    )
    return [bool]$AppId -and $ConsentClientAppIds -contains $AppId.ToLowerInvariant()
}
