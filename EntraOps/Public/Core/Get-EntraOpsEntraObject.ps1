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
        [System.String]$AadObjectId
        ,
        [Parameter(Mandatory = $false)]
        [System.String]$TenantId
    )

    try {
        $ObjectDetails = Invoke-EntraOpsMsGraphQuery -Method Get -Uri ("/beta/directoryObjects/$($AadObjectId)") -OutputType PSObject
    }
    catch {
        $ObjectDetails = $null
        Write-Warning "No object has been found with Id: $AadObjectId"
        Write-Error $_.Exception.Message
    }

    if ($ObjectDetails.'@odata.type' -eq '#microsoft.graph.servicePrincipal') {
        $SPObject = Invoke-EntraOpsMsGraphQuery -Method Get -Uri ("/beta/servicePrincipals/$($AadObjectId)") -OutputType PSObject
        $ObjectType = 'servicePrincipal'
        $ObjectSubType = $SPObject.ServicePrincipalType
        $RestrictedManagementByRAG = $false
    }
    elseif ($ObjectDetails.'@odata.type' -eq '#microsoft.graph.group') {
        $ObjectType = 'group'
        if ($ObjectDetails.isAssignableToRole -eq $True) { $ObjectSubType = "Role-assignable" } else { $ObjectSubType -eq "Security" }
        $RestrictedManagementByRAG = $ObjectDetails.isAssignableToRole
    }
    elseif ($ObjectDetails.'@odata.type' -eq '#microsoft.graph.user') {
        $ObjectType = 'user'
        if ($ObjectDetails.UserType -eq "Member") {
            $ObjectSubType = "Member"
        }
        else {
            $ObjectSubType -eq "Guest"
        }
        $RestrictedManagementByRAG = $ObjectMemberships.isAssignableToRole -contains $true
    }
    else {
        $ObjectDetails = [PSCustomObject]@{
            'id'          = "$($AadObjectId)"
            'displayName' = "Identity not found"
        }
        $ObjectType = 'unknown'
        $ObjectSubType = 'unknown'
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