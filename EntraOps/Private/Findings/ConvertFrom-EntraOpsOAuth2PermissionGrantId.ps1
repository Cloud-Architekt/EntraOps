function ConvertFrom-EntraOpsOAuth2PermissionGrantId {
    <#
    .SYNOPSIS
        Reads the consent type and the consenting user from the ID of a delegated permission grant (oauth2PermissionGrant).
    .DESCRIPTION
        Microsoft Entra ID builds the ID of an oauth2PermissionGrant from the object IDs it connects, Base64url-encoded
        (byte order of .NET GUIDs): the client service principal and the resource service principal for a grant to all
        users (consentType AllPrincipals, admin consent), followed by the user for a grant of one user (consentType
        Principal). The Privileged EAM export keeps the grant ID (RoleAssignmentId of a delegated permission), but not
        the consent type, so two grants of the same permission to an application (one for all users, one of a user)
        are told apart by their ID.
        Returns $null for an ID of another format.
    .PARAMETER GrantId
        The ID of the oauth2PermissionGrant.
    .EXAMPLE
        ConvertFrom-EntraOpsOAuth2PermissionGrantId -GrantId $Grant.id

        ConsentType AllPrincipals with ClientId and ResourceId for a grant to all users; Principal with PrincipalId for the grant of one user.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param (
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$GrantId
    )

    if ([string]::IsNullOrWhiteSpace($GrantId) -or $GrantId -notmatch '^[A-Za-z0-9_-]+$') { return $null }
    $Base64 = $GrantId.Replace('-', '+').Replace('_', '/')
    $Base64 += '=' * ((4 - $Base64.Length % 4) % 4)
    try { $Bytes = [System.Convert]::FromBase64String($Base64) } catch { return $null }
    if ($Bytes.Length -notin 32, 48) { return $null }
    $Ids = @(for ($Offset = 0; $Offset -lt $Bytes.Length; $Offset += 16) { [guid]::new([byte[]]$Bytes[$Offset..($Offset + 15)]).ToString() })
    [pscustomobject]@{
        ConsentType = if ($Ids.Count -eq 3) { 'Principal' } else { 'AllPrincipals' }
        ClientId    = $Ids[0]
        ResourceId  = $Ids[1]
        PrincipalId = if ($Ids.Count -eq 3) { $Ids[2] } else { $null }
    }
}
