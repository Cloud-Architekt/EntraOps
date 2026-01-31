<#
.SYNOPSIS
    Get information of Managed Identities and their assignments to Azure Resources.

.DESCRIPTION
    Get information of Managed Identities and their assignments to Azure Resources.

.EXAMPLE
    Get a list of all assignments of System- and User-Assigned Managed Identities to Azure Resources
    Get-EntraOpsManagedIdentityAssignments
#>
function Get-EntraOpsManagedIdentityAssignments {

    $Query = "
    resources
    | where identity has 'SystemAssigned' or type == 'microsoft.managedidentity/userassignedidentities'
    | extend IdentityType = iff(type == 'microsoft.managedidentity/userassignedidentities', 'UserAssigned', 'SystemAssigned')
    | extend ObjectId = iff(IdentityType == 'SystemAssigned', tostring(identity.principalId), tostring(properties.principalId))
    | project ObjectId, ResourceId = tostring(tolower(id)), ResourceName = name, ResourceType = type, ResourceTags = tags, ResourceTenantId = tenantId, IdentityType
    | join kind=leftouter (resources
    | where identity.type has 'UserAssigned'
    | mv-expand parse_json(identity.userAssignedIdentities)
    | extend ResourceId = tostring(tolower(bag_keys(identity_userAssignedIdentities)[0]))
    | project ResourceId, AssignedResourceId = id
    ) on ResourceId
    | project-away ResourceId1
    | extend AssociatedWorkloadId = iff(IdentityType == 'SystemAssigned', ResourceId, AssignedResourceId)
    | summarize AssociatedWorkloadId=make_set(AssociatedWorkloadId) by ObjectId, ResourceId, ResourceType, ResourceTenantId, IdentityType
    "
    
    $AssignedManagedIdentities = Invoke-EntraOpsAzGraphQuery -KqlQuery $Query
    return $AssignedManagedIdentities
}
