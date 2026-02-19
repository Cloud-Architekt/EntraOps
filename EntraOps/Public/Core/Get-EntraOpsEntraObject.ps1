<#
.SYNOPSIS
    Get basic information of Entra Object by using Microsoft Graph API

.DESCRIPTION
    Get basic information of Entra Object by using Microsoft Graph API

.PARAMETER AadObjectId
    The ObjectId of the Entra Object

.PARAMETER TenantId
    The TenantId of the Entra Object

.EXAMPLE
    Details of Entra Object with a specific ObjectId
    Get-EntraOpsEntraObject -AadObjectId "bdf10e92-30c7-4cc8-93e7-2982ea6cf371"
#>
function Get-EntraOpsEntraObject {
    [cmdletbinding()]
    param (
        [Parameter(Mandatory = $True)]
        [ValidatePattern('^([0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12})$')]
        [System.String]$AadObjectId
        ,
        [Parameter(Mandatory = $false)]
        [System.String]$TenantId
    )

    try {
        # Optimization: Use getByIds to fetch all details in a single call (N+1 fix)
        # We request properties for all potential types (User, Group, ServicePrincipal)
        $Body = @{
            ids   = @($AadObjectId)
            types = @('user', 'group', 'servicePrincipal')
        } | ConvertTo-Json

        $Uri = "/beta/directoryObjects/getByIds?`$select=id,displayName,userPrincipalName,onPremisesSyncEnabled,servicePrincipalType,isAssignableToRole,userType,appOwnerOrganizationId,createdDateTime,accountEnabled,groupTypes,mailEnabled,securityEnabled"
        
        $Result = Invoke-EntraOpsMsGraphQuery -Method POST -Uri $Uri -Body $Body -OutputType PSObject
        $ObjectDetails = if ($Result -is [array]) { $Result[0] } else { $Result }
        
        if ($null -eq $ObjectDetails) {
            throw "ResourceNotFound: Object $AadObjectId not returned by getByIds"
        }
    } catch {
        # Resiliency: Differentiate between "Object Not Found" (404) and connectivity/auth errors.
        # Fail fast on connectivity errors rather than returning null.
        if ($_.Exception.Message -match "ResourceNotFound" -or $_.Exception.Message -match "Request_ResourceNotFound" -or $_.Exception.Message -match "404") {
            $ObjectDetails = $null
            # User Output: Ensure 'Warning' streams are reserved for actionable issues.
            Write-Verbose "No object has been found with Id: $AadObjectId (404 Not Found)"
        } else {
            throw $_
        }
    }

    if ($ObjectDetails.'@odata.type' -eq '#microsoft.graph.servicePrincipal') {
        # Optimized: Details already fetched via getByIds
        $SPObject = $ObjectDetails
        $ObjectType = 'servicePrincipal'
        $ObjectSubType = $SPObject.servicePrincipalType
        $RestrictedManagementByRAG = $false
    } elseif ($ObjectDetails.'@odata.type' -eq '#microsoft.graph.group') {
        $ObjectType = 'group'
        if ($ObjectDetails.isAssignableToRole -eq $True) { $ObjectSubType = "Role-assignable" } else { $ObjectSubType = "Security" }
        $RestrictedManagementByRAG = $ObjectDetails.isAssignableToRole
    } elseif ($ObjectDetails.'@odata.type' -eq '#microsoft.graph.user') {
        $ObjectType = 'user'
        if ($ObjectDetails.UserType -eq "Member") {
            $ObjectSubType = "Member"
        } else {
            $ObjectSubType = "Guest"
        }
        $RestrictedManagementByRAG = $ObjectDetails.isAssignableToRole -eq $true
    } else {
        $ObjectDetails = [PSCustomObject]@{
            'id'          = "$($AadObjectId)"
            'displayName' = "Identity not found"
        }
        $ObjectType = 'unknown'
        $ObjectSubType = 'unknown'
        $RestrictedManagementByRAG = $false
    }

    if ($null -ne $ObjectDetails) {
        [PSCustomObject]@{
            'ObjectId'                      = $ObjectDetails.Id
            'ObjectType'                    = $ObjectType.ToLower()
            'ObjectSubType'                 = $ObjectSubType
            'ObjectDisplayName'             = $ObjectDetails.displayName
            'ObjectSignInName'              = $ObjectDetails.userPrincipalName
            'OnPremSynchronized'            = if ($null -eq $ObjectDetails.onPremisesSyncEnabled) { $false } else { $ObjectDetails.onPremisesSyncEnabled }
            'RestrictedManagementByAadRole' = $RestrictedManagementByRAG
        }
    }
}