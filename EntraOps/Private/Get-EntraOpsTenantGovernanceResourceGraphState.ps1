<#
.SYNOPSIS
    Checks with a direct Microsoft Graph GET whether a Tenant Governance snapshot resource still exists.

.DESCRIPTION
    Save-EntraOpsTenantGovernanceSnapshotJson retains the previously published file of a resource that a
    PublishedWithErrors resource type did not return. The snapshot error alone can't tell whether such a
    resource was deleted: Request_ResourceNotFound is also reported for a resource that exists but references
    a deleted object (for example "Couldn't find ExcludedGroup '<id>', that is defined in policy '...'" for a
    Conditional Access policy, or "Resource '<id>' does not exist or one of its queried reference-property
    objects are not present" for an access package assignment policy). Only a GET of the resource's own Id
    answers that question, so this helper requests exactly that resource and classifies the answer:

    - Exists:      Graph returned the resource.
    - NotFound:    Graph answered HTTP 404 for the resource itself, so it was deleted in the tenant.
    - Unknown:     any other outcome (403, 429, 5xx, network error, empty answer). The caller must keep the file.
    - Unsupported: no direct endpoint is known for the resource type. The caller must keep the file.

    Only resource types are listed whose Graph endpoint is certain and whose snapshot properties.Id was verified
    against real snapshots to be the Graph object Id. UTCM replaces some references with display names (for
    example AccessPackageId of an assignment policy), so the Id of an unverified type must not be assumed.

.PARAMETER ResourceType
    Snapshot resource type, for example microsoft.entra.entitlementmanagementaccesspackageassignmentpolicy (case-insensitive).

.PARAMETER ResourceId
    The resource's own Id, as stored in properties.Id of its snapshot file.

.PARAMETER ListSupportedResourceTypes
    Return the lowercase resource types with a known direct endpoint instead of checking a resource.

.EXAMPLE
    Get-EntraOpsTenantGovernanceResourceGraphState -ResourceType 'microsoft.entra.entitlementmanagementaccesspackageassignmentpolicy' -ResourceId '11111111-1111-1111-1111-111111111111'
#>
function Get-EntraOpsTenantGovernanceResourceGraphState {
    [CmdletBinding(DefaultParameterSetName = 'Check')]
    param (
        [Parameter(Mandatory = $true, ParameterSetName = 'Check')]
        [System.String]$ResourceType,

        [Parameter(Mandatory = $true, ParameterSetName = 'Check')]
        [AllowEmptyString()]
        [System.String]$ResourceId,

        [Parameter(Mandatory = $true, ParameterSetName = 'List')]
        [switch]$ListSupportedResourceTypes
    )

    # Direct v1.0 GET endpoint per lowercase resource type; {0} is the escaped resource Id.
    $ResourceUriTemplates = @{
        'microsoft.entra.entitlementmanagementaccesspackageassignmentpolicy' = '/v1.0/identityGovernance/entitlementManagement/assignmentPolicies/{0}'
        'microsoft.entra.entitlementmanagementconnectedorganization'         = '/v1.0/identityGovernance/entitlementManagement/connectedOrganizations/{0}'
        'microsoft.entra.conditionalaccesspolicy'                            = '/v1.0/identity/conditionalAccess/policies/{0}'
        'microsoft.entra.namedlocationpolicy'                                = '/v1.0/identity/conditionalAccess/namedLocations/{0}'
        'microsoft.entra.authenticationstrengthpolicy'                       = '/v1.0/identity/conditionalAccess/authenticationStrength/policies/{0}'
        'microsoft.entra.authenticationcontextclassreference'                = '/v1.0/identity/conditionalAccess/authenticationContextClassReferences/{0}'
        'microsoft.entra.administrativeunit'                                 = '/v1.0/directory/administrativeUnits/{0}'
        'microsoft.entra.roledefinition'                                     = '/v1.0/roleManagement/directory/roleDefinitions/{0}'
    }

    if ($ListSupportedResourceTypes) {
        return @($ResourceUriTemplates.Keys | Sort-Object)
    }

    $Template = $ResourceUriTemplates[$ResourceType.Trim().ToLowerInvariant()]
    if ([string]::IsNullOrWhiteSpace($Template) -or [string]::IsNullOrWhiteSpace($ResourceId)) {
        return [PSCustomObject]@{ State = 'Unsupported'; StatusCode = $null; Uri = $null; Message = "No direct Microsoft Graph endpoint is known for resource type '$ResourceType'." }
    }

    # The Id comes from a file in the repository: escaping keeps it a single path segment of the request.
    $Uri = $Template -f [System.Uri]::EscapeDataString($ResourceId.Trim())
    try {
        # Fresh answer (no module cache), few retries: an unanswered check only postpones the cleanup to the next
        # snapshot. A 404 is the expected answer for a deleted resource and is reported by the caller, not as warning.
        $Resource = Invoke-EntraOpsMsGraphQuery -Method GET -Uri $Uri -OutputType PSObject -DisableCache -ThrowOnFailure -MaxRetries 2 -SuppressNotFoundWarning -SuppressForbiddenWarning
    } catch {
        # Invoke-EntraOpsMsGraphQuery -ThrowOnFailure puts the HTTP status of a non-retryable error into Exception.Data.
        # Throttling that persists after the retries and network errors carry no status code and stay Unknown.
        $StatusCode = $null
        if ($null -ne $_.Exception.Data -and $_.Exception.Data.Contains('StatusCode')) { $StatusCode = $_.Exception.Data['StatusCode'] }
        $State = if ("$StatusCode" -eq '404') { 'NotFound' } else { 'Unknown' }
        return [PSCustomObject]@{ State = $State; StatusCode = $StatusCode; Uri = $Uri; Message = $_.Exception.Message }
    }
    if ($null -eq $Resource -or @($Resource | Where-Object { $null -ne $_ }).Count -eq 0) {
        return [PSCustomObject]@{ State = 'Unknown'; StatusCode = $null; Uri = $Uri; Message = 'Microsoft Graph returned no content.' }
    }
    return [PSCustomObject]@{ State = 'Exists'; StatusCode = 200; Uri = $Uri; Message = $null }
}
