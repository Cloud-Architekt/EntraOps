<#
.SYNOPSIS
    Get agent objects (agent identities, agent identity blueprints and blueprint principals, agent users) of Microsoft Entra.

.DESCRIPTION
    Returns agent objects in the same schema as Get-EntraOpsPrivilegedEntraObject (ObjectId, ObjectType, ObjectSubType,
    owners, sponsors, identity parent, protection status, admin tier level ...). All agent objects are returned,
    regardless of whether they hold privileged role assignments.

.PARAMETER All
    Returns all agent objects of the tenant.

.PARAMETER ObjectId
    Object IDs of agent objects to return. Objects that aren't agent objects are skipped with a warning.

.PARAMETER AgentObjectType
    Limits the result to the given agent object types. Default is all types:
    AgentIdentity, AgentIdentityBlueprint (application), AgentIdentityBlueprintPrincipal (service principal) and AgentUser.

.PARAMETER TenantId
    Tenant ID of the Microsoft Entra ID tenant. Default is the current tenant ID.

.PARAMETER EnableParallelProcessing
    Enable parallel processing for object detail resolution. Default is $true.

.PARAMETER ParallelThrottleLimit
    Maximum number of parallel threads. Default is 10.

.EXAMPLE
    Get-EntraOpsAgentObject -All

    Returns all agent identities, agent identity blueprints, blueprint principals and agent users.

.EXAMPLE
    Get-EntraOpsAgentObject -All -AgentObjectType AgentIdentity, AgentUser

    Returns all agent identities and agent users.

.EXAMPLE
    Get-EntraOpsAgentObject -ObjectId "bdf10e92-30c7-4cc8-93e7-2982ea6cf371"
#>
function Get-EntraOpsAgentObject {
    [CmdletBinding(DefaultParameterSetName = 'ObjectId')]
    [OutputType([psobject])]
    param (
        [Parameter(Mandatory = $true, ParameterSetName = 'All')]
        [switch]$All
        ,
        [Parameter(Mandatory = $true, ParameterSetName = 'ObjectId', ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [ValidatePattern('^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$')]
        [System.String[]]$ObjectId
        ,
        [Parameter(Mandatory = $false)]
        [ValidateSet('AgentIdentity', 'AgentIdentityBlueprint', 'AgentIdentityBlueprintPrincipal', 'AgentUser')]
        [System.String[]]$AgentObjectType = @('AgentIdentity', 'AgentIdentityBlueprint', 'AgentIdentityBlueprintPrincipal', 'AgentUser')
        ,
        [Parameter(Mandatory = $false)]
        [ValidatePattern('^$|^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$')]
        [System.String]$TenantId = $Global:TenantIdContext
        ,
        [Parameter(Mandatory = $false)]
        [System.Boolean]$EnableParallelProcessing = $true
        ,
        [Parameter(Mandatory = $false)]
        [System.Int32]$ParallelThrottleLimit = 10
    )

    begin {
        $AgentObjectIds = [System.Collections.Generic.List[string]]::new()
        $AgentTypeUris = [ordered]@{
            AgentIdentity                   = "/beta/servicePrincipals/microsoft.graph.agentIdentity?`$select=id"
            AgentIdentityBlueprint          = "/beta/applications/microsoft.graph.agentIdentityBlueprint?`$select=id"
            AgentIdentityBlueprintPrincipal = "/beta/servicePrincipals/microsoft.graph.agentIdentityBlueprintPrincipal?`$select=id"
            AgentUser                       = "/beta/users/microsoft.graph.agentUser?`$select=id"
        }
    }

    process {
        if ($PSCmdlet.ParameterSetName -eq 'ObjectId') {
            foreach ($Id in $ObjectId) { $AgentObjectIds.Add($Id) }
        }
    }

    end {
        if ($All) {
            foreach ($Type in $AgentObjectType) {
                Write-Verbose "Looking up objects of type $Type"
                try {
                    Invoke-EntraOpsMsGraphQuery -Method GET -Uri $AgentTypeUris[$Type] -OutputType PSObject -ThrowOnFailure |
                        Where-Object { $null -ne $_.id } |
                        ForEach-Object { $AgentObjectIds.Add($_.id) }
                } catch {
                    Write-Warning "Unable to list objects of type $($Type): $($_.Exception.Message)"
                }
            }
        }

        $UniqueObjects = @($AgentObjectIds | Select-Object -Unique | ForEach-Object { [PSCustomObject]@{ ObjectId = $_ } })
        if ($UniqueObjects.Count -eq 0) {
            Write-Verbose "No agent objects found"
            return
        }

        $ObjectDetails = Invoke-EntraOpsParallelObjectResolution -UniqueObjects $UniqueObjects -TenantId $TenantId -EnableParallelProcessing $EnableParallelProcessing -ParallelThrottleLimit $ParallelThrottleLimit

        $AgentObjects = foreach ($Object in $UniqueObjects) {
            $Details = $ObjectDetails[$Object.ObjectId]
            if ($null -eq $Details) {
                Write-Warning "Unable to resolve details of agent object $($Object.ObjectId)"
            } elseif ($Details.ObjectSubType -notin $AgentObjectType) {
                if ($PSCmdlet.ParameterSetName -eq 'ObjectId') {
                    Write-Warning "Object $($Object.ObjectId) is not an agent object of type $($AgentObjectType -join ', ') (ObjectSubType: $($Details.ObjectSubType)), skipping"
                }
            } else {
                $Details
            }
        }
        $AgentObjects | Sort-Object ObjectSubType, ObjectDisplayName, ObjectId
    }
}
