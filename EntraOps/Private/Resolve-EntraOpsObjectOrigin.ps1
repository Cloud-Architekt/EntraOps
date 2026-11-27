function Resolve-EntraOpsObjectOrigin {
    <#
    .SYNOPSIS
        Where a privileged object comes from: OriginType, OriginTenantId and OriginId of the Privileged EAM export.
    .DESCRIPTION
        OriginType names how the object came into the tenant, OriginTenantId the tenant it comes from and OriginId its
        identifier there. Empty values mean that the origin is unknown, for example a group read without the
        permission Group-XTenantIdentitySync.Read.All; a local object has its own tenant and ID.

        Users and groups, in this order:
        - TenantGovernance: an object of another tenant that has access through Tenant Governance (a group of the
          governing tenant, also a ForeignGroup of Azure RBAC, or a member of such a group): its tenant and ID.
        - CrossTenantSync: originTenantInfo of Microsoft Graph with synchronizationInfo.creationType
          tenantToTenantSync: originTenantId and originId. Another creationType is kept as the OriginType.
        - B2BInvitation: originTenantInfo without synchronizationInfo (an invited guest of another Microsoft Entra
          tenant): originTenantId and originId. A guest or #EXT# user without originTenantInfo (one-time passcode,
          Microsoft account, Google, SAML/WS-Fed) is B2BInvitation without tenant and ID.
        - OnPremises: synchronized from Active Directory (onPremisesSyncEnabled true): this tenant and the SID
          (onPremisesSecurityIdentifier). An object whose management moved to the cloud is Cloud.
        - Cloud: this tenant and the object ID. Without originTenantInfo (OriginTenantInfoAvailable false) a member
          that is not synchronized from Active Directory is unknown, as it can be synchronized from another tenant.

        Service principals: the tenant of the application (appOwnerOrganizationId; an agent identity takes the tenant
        of its blueprint, a managed identity is of this tenant) and the application ID.
        - FirstPartyApplication: an application of Microsoft (Test-EntraOpsMicrosoftFirstParty).
        - InternalApplication: an application, managed identity or agent identity of this tenant.
        - ExternalApplication: an application of another organization.
        An application object (app registration) is InternalApplication.
    .PARAMETER ObjectType
        user, group, serviceprincipal or application.
    .PARAMETER ObjectSubType
        The subtype of the export (Member, Guest, ManagedIdentity, AgentIdentity, ...).
    .PARAMETER ObjectId
        The ID of the object.
    .PARAMETER TenantId
        The tenant the object was read in.
    .PARAMETER TenantGovernance
        The object has access through Tenant Governance: a remote tenant group, or an object read in the managing tenant.
    .PARAMETER OriginTenantInfo
        originTenantInfo of the user or group (Microsoft Graph beta).
    .PARAMETER OriginTenantInfoAvailable
        originTenantInfo was read; without it, a member that is not synchronized from Active Directory is unknown.
    .PARAMETER UserType
        userType of a user.
    .PARAMETER UserPrincipalName
        The user principal name of a user.
    .PARAMETER OnPremisesSyncEnabled
        onPremisesSyncEnabled of a user or group.
    .PARAMETER OnPremisesSecurityIdentifier
        onPremisesSecurityIdentifier (SID) of a user or group.
    .PARAMETER AppId
        The application ID of a service principal or application.
    .PARAMETER AppOwnerOrganizationId
        appOwnerOrganizationId of a service principal; for an agent identity the one of its blueprint.
    .EXAMPLE
        Resolve-EntraOpsObjectOrigin -ObjectType user -ObjectId $Id -TenantId $TenantId -OriginTenantInfo $User.originTenantInfo -OriginTenantInfoAvailable $true -UserType Member

        OriginType CrossTenantSync with the tenant and the ID of the user in the tenant that synchronizes it.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param (
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$ObjectType,

        [AllowEmptyString()]
        [string]$ObjectSubType,

        [AllowEmptyString()]
        [string]$ObjectId,

        [AllowEmptyString()]
        [string]$TenantId,

        [switch]$TenantGovernance,

        [AllowNull()]
        [object]$OriginTenantInfo,

        [bool]$OriginTenantInfoAvailable = $false,

        [AllowEmptyString()]
        [string]$UserType,

        [AllowEmptyString()]
        [string]$UserPrincipalName,

        [AllowNull()]
        [object]$OnPremisesSyncEnabled,

        [AllowEmptyString()]
        [string]$OnPremisesSecurityIdentifier,

        [AllowEmptyString()]
        [string]$AppId,

        [AllowEmptyString()]
        [string]$AppOwnerOrganizationId
    )

    $New = { param($Type, $Tenant, $Id) [pscustomobject]@{ OriginType = $Type; OriginTenantId = $(if ($Tenant) { "$Tenant".ToLowerInvariant() } else { $null }); OriginId = $(if ($Id) { "$Id" } else { $null }) } }
    $Unknown = & $New $null $null $null

    switch ($ObjectType.ToLowerInvariant()) {
        { $_ -in 'user', 'group' } {
            if ($TenantGovernance) { return (& $New 'TenantGovernance' $TenantId $ObjectId) }
            $Info = $OriginTenantInfo
            if ($null -ne $Info -and -not [string]::IsNullOrWhiteSpace("$($Info.originTenantId)")) {
                $CreationType = "$($Info.synchronizationInfo.creationType)"
                $Type = if ([string]::IsNullOrWhiteSpace($CreationType)) { 'B2BInvitation' }
                elseif ($CreationType -eq 'tenantToTenantSync') { 'CrossTenantSync' }
                else { $CreationType }
                # The originId of a user may be named originUserId (originTenantInfo of userAccountInformation).
                $InfoId = if ("$($Info.originId)") { "$($Info.originId)" } else { "$($Info.originUserId)" }
                return (& $New $Type $Info.originTenantId $InfoId)
            }
            if ($_ -eq 'user' -and ($UserType -eq 'Guest' -or $UserPrincipalName -like '*#EXT#@*')) { return (& $New 'B2BInvitation' $null $null) }
            if ($OnPremisesSyncEnabled -eq $true) { return (& $New 'OnPremises' $TenantId $OnPremisesSecurityIdentifier) }
            if (-not $OriginTenantInfoAvailable) { return $Unknown }
            return (& $New 'Cloud' $TenantId $ObjectId)
        }
        'serviceprincipal' {
            $Owner = $AppOwnerOrganizationId
            # A managed identity has no application tenant: Azure creates it in this tenant.
            if ([string]::IsNullOrWhiteSpace($Owner) -and $ObjectSubType -eq 'ManagedIdentity') { $Owner = $TenantId }
            if ([string]::IsNullOrWhiteSpace($Owner)) { return $Unknown }
            $Type = if (Test-EntraOpsMicrosoftFirstParty -AppOwnerOrganizationId $Owner -AppId $AppId) { 'FirstPartyApplication' }
            elseif ($TenantId -and $Owner -eq $TenantId) { 'InternalApplication' }
            else { 'ExternalApplication' }
            return (& $New $Type $Owner $AppId)
        }
        'application' { return (& $New 'InternalApplication' $TenantId $AppId) }
        default { return $Unknown }
    }
}
