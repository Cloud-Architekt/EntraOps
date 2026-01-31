<#
.SYNOPSIS
    Get information of Attack Paths in Microsoft Defender for Cloud CSPM.

.DESCRIPTION
    Get information of Attack Paths including entity types of Service Principal and Managed Identity in Microsoft Defender for Cloud CSPM.

.EXAMPLE
    Get a list of all assignments of Attack Paths in Microsoft Defender for Cloud CSPM
    Get-EntraOpsManagedIdentityAssignments
#>
function Get-EntraOpsWorkloadIdentityAttackPaths {

    [Parameter(Mandatory = $false)]
    [ValidateSet("PSCustomObject", "WatchList")]
    [string]$OutputType = "PSCustomObject"
    ,    

    $Query = 'securityresources
    | where type == "microsoft.security/attackpaths"
    | extend AttackPathDisplayName = tostring(properties["displayName"])
    | mvexpand (properties.graphComponent.entities)
    | extend Entity = parse_json(properties_graphComponent_entities)
    | extend EntityId = (Entity.entityIdentifiers.principalOid)
    | extend EntityType = (Entity.entityType)
    | where EntityType == "serviceprincipal" or EntityType == "managedidentity"
    | project id, AttackPathDisplayName, EntityId, EntityType, Description = tostring(properties["description"]), RiskFactors = tostring(properties["riskFactors"]), MitreTtp = tostring(properties["mITRETacticsAndTechniques"]), AttackStory = tostring(properties["attackStory"]), RiskLevel = tostring(properties["riskLevel"]), Target = tostring(properties["target"])'

    $AttackPathResults = Invoke-EntraOpsAzGraphQuery -KqlQuery $Query
    $WorkloadIdentityAttackPaths = foreach ($AttackPath in $AttackPathResults) {

        if ($OutputType -eq "WatchList") {
            $AttackPath.MitreTtp = $AttackPath.MitreTtp | ConvertFrom-Json -Depth 10 | ConvertTo-Json -Compress
            $AttackPath.Target = $AttackPath.Target | ConvertFrom-Json -Depth 10 | ConvertTo-Json -Compress
        }
        else {
            $AttackPath.MitreTtp = $AttackPath.MitreTtp | ConvertFrom-Json -Depth 10
            $AttackPath.Target = $AttackPath.Target | ConvertFrom-Json -Depth 10
        }

        [PSCustomObject]@{
            'AttackPathId'          = $AttackPath.Id
            'AttackPathDisplayName' = $AttackPath.AttackPathDisplayName
            'AttackStory'           = $AttackPath.AttackStory
            'EntityId'              = $AttackPath.EntityId
            'EntityType'            = $AttackPath.EntityType
            'Description'           = $AttackPath.Description
            'RiskFactors'           = $AttackPath.RiskFactors
            'RiskLevel'             = $AttackPath.RiskLevel
            'MitreTtp'              = $AttackPath.MitreTtp
            'Target'                = $AttackPath.Target
        }
    }
    return $WorkloadIdentityAttackPaths
}
