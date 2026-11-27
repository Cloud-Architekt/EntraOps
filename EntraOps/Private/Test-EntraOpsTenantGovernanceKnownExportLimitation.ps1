function Test-EntraOpsTenantGovernanceKnownExportLimitation {
    <#
    .SYNOPSIS
        Tells whether a Tenant Governance snapshot diagnostic is the known limitation of the snapshot export.
    .DESCRIPTION
        The snapshot export (UTCM) cannot resolve the group and connected organization members that access package
        assignment policies name (approvers, requestors, reviewers). It reports each one as a not found resource
        without policy context ("[Request_ResourceNotFound] : Resource '<id>' does not exist ..."), although the policy
        itself is exported. EntraOps reads the approvers and requestors of the policies from Microsoft Graph for the
        Access Package Flow data, so these diagnostics leave no gap - as long as no policy had to be retained from the
        previous snapshot (Save-EntraOpsTenantGovernanceSnapshotJson checks that per resource type).
        A diagnostic that names a policy ("... defined in policy ...") is about a reference the policy itself holds and
        is not this limitation.
    .PARAMETER ResourceType
        Resource type of the diagnostic.
    .PARAMETER ErrorCategory
        ErrorCategory of the diagnostic (ExportError).
    .PARAMETER ErrorCode
        ErrorCode of the diagnostic (Request_ResourceNotFound).
    .PARAMETER Message
        The normalized message of the diagnostic.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param (
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$ResourceType,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$ErrorCategory,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$ErrorCode,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$Message
    )

    "$ResourceType".ToLowerInvariant() -eq 'microsoft.entra.entitlementmanagementaccesspackageassignmentpolicy' -and
    $ErrorCategory -eq 'ExportError' -and $ErrorCode -eq 'Request_ResourceNotFound' -and "$Message" -notlike '*defined in policy*'
}
