function Get-EntraOpsObjectOriginTenantInfo {
    <#
    .SYNOPSIS
        Reads originTenantInfo (and for groups onPremisesSecurityIdentifier) of a user or group from Microsoft Graph.
    .DESCRIPTION
        originTenantInfo (Microsoft Graph beta, only returned on $select) names the tenant and the ID of a user or group
        in the tenant it comes from: cross-tenant synchronization or the invitation of a guest. Reading it for groups
        needs the permission Group-XTenantIdentitySync.Read.All; users need User.Read.All.

        The request is separate from the other object queries, so that a missing permission costs only the origin and
        not the object details. When Microsoft Graph refuses originTenantInfo (403 or 400), the session reads it no
        longer for this object type, warns once, and reads the groups' SID without it. Available tells whether
        originTenantInfo was read: without it, Resolve-EntraOpsObjectOrigin leaves a member that is not synchronized
        from Active Directory as unknown.
    .PARAMETER ObjectType
        user or group.
    .PARAMETER ObjectId
        The ID of the user or group.
    .EXAMPLE
        Get-EntraOpsObjectOriginTenantInfo -ObjectType group -ObjectId $GroupId

        Available, OriginTenantInfo and (for groups) OnPremisesSecurityIdentifier.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateSet('user', 'group')]
        [string]$ObjectType,

        [Parameter(Mandatory = $true)]
        [string]$ObjectId
    )

    $Endpoint = if ($ObjectType -eq 'user') { 'users' } else { 'groups' }
    # The groups' SID is read here; the users' SID comes with the user details of Get-EntraOpsPrivilegedEntraObject.
    $Extra = if ($ObjectType -eq 'group') { ',onPremisesSecurityIdentifier' } else { '' }
    # The session (shared with the parallel runspaces) remembers a refused originTenantInfo per object type.
    $Session = Get-Variable -Name __EntraOpsSession -Scope Script -ValueOnly -ErrorAction SilentlyContinue
    if ($null -eq $Session) { $Session = @{} }
    if ($null -eq $Session['OriginTenantInfoDenied']) { $Session['OriginTenantInfoDenied'] = [hashtable]::Synchronized(@{}) }
    $Denied = $Session['OriginTenantInfoDenied']
    # Connect-EntraOps and Invoke-EntraOpsPrivilegedEAM record whether the Graph token has
    # Group-XTenantIdentitySync.Read.All ($null: not known, for example without the Graph SDK). Without it, the origin
    # of groups is unknown: Microsoft Graph could leave originTenantInfo out instead of refusing it.
    if ($ObjectType -eq 'group' -and $Session['GroupOriginTenantInfoAccess'] -eq $false -and -not $Denied.ContainsKey('group')) {
        $Denied['group'] = $true
        Write-Warning "The Microsoft Graph permission Group-XTenantIdentitySync.Read.All is not granted: the origin of groups from other tenants (cross-tenant synchronization) is not collected. Grant it to read it."
    }

    if (-not $Denied.ContainsKey($ObjectType)) {
        try {
            $Details = Invoke-EntraOpsMsGraphQuery -Method Get -Uri "/beta/$Endpoint/$($ObjectId)?`$select=id,originTenantInfo$Extra" -OutputType PSObject -ThrowOnFailure -SuppressNotFoundWarning -SuppressForbiddenWarning -SuppressBadRequestWarning
            return [pscustomobject]@{
                Available                    = $true
                OriginTenantInfo             = $Details.originTenantInfo
                OnPremisesSecurityIdentifier = "$($Details.onPremisesSecurityIdentifier)"
            }
        } catch {
            $StatusCode = $_.Exception.Data['StatusCode']
            if ($StatusCode -in 400, 403) {
                $Denied[$ObjectType] = $true
                $Permission = if ($ObjectType -eq 'group') { 'Group-XTenantIdentitySync.Read.All' } else { 'User.Read.All' }
                Write-Warning "Microsoft Graph refused originTenantInfo of $($Endpoint) (HTTP $StatusCode): the origin of $($Endpoint) from other tenants (cross-tenant synchronization, guests) is not collected in this session. Grant $Permission to read it."
            } else {
                Write-Verbose "originTenantInfo of $ObjectType $ObjectId could not be read$(if ($StatusCode) { " (HTTP $StatusCode)" }): $($_.Exception.Message)"
                return [pscustomobject]@{ Available = $false; OriginTenantInfo = $null; OnPremisesSecurityIdentifier = '' }
            }
        }
    }

    # Without originTenantInfo: the groups' SID only.
    $Sid = ''
    if ($ObjectType -eq 'group') {
        $Details = Invoke-EntraOpsMsGraphQuery -Method Get -Uri "/beta/groups/$($ObjectId)?`$select=id,onPremisesSecurityIdentifier" -OutputType PSObject -SuppressNotFoundWarning
        $Sid = "$($Details.onPremisesSecurityIdentifier)"
    }
    [pscustomobject]@{ Available = $false; OriginTenantInfo = $null; OnPremisesSecurityIdentifier = $Sid }
}
