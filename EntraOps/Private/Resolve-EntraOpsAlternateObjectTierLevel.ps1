function Resolve-EntraOpsAlternateObjectTierLevel {
    <#
    .SYNOPSIS
        Classifies a User, ServicePrincipal or Group object by evaluating PowerShell filter expressions
        against its own already-resolved EntraOps details, as an alternative to Custom Security
        Attributes (which are not available for groups at all).
    .DESCRIPTION
        EntraOpsConfig.json can define an "AlternateObjectTierLevelAttributes" section with one
        PowerShell filter expression per Enterprise Access Model tier (ControlPlane, ManagementPlane,
        WorkloadPlane, UserAccess) and object type (User, ServicePrincipal, Group). Each filter expression is evaluated
        against the object's own details already resolved by Get-EntraOpsPrivilegedEntraObject (e.g.
        AssignedAdministrativeUnits, ObjectDisplayName) - the same details that end up in the
        PrivilegedEAM export - exposed to the expression as the $Object variable.

        Filters are evaluated in order of decreasing privilege (ControlPlane, then ManagementPlane,
        then WorkloadPlane, then UserAccess) and the first matching tier wins, matching the Enterprise Access Model
        principle that an object should be classified at its most privileged applicable tier.

        User/ServicePrincipal: returns $null when alternate classification is not enabled (caller should
        then fall back to Custom Security Attribute classification). Once enabled, returns an explicit
        Unclassified result (never $null) when no tier filter is defined/matches or a filter expression
        throws - it does not fall back to Custom Security Attributes for that object.

        Group: groups have no Custom Security Attributes, so the Group filters are evaluated independently
        of the 'Enabled' switch whenever at least one Group filter expression is defined. Returns $null when
        no Group filter is defined (caller keeps the object Unclassified).
    .PARAMETER ObjectType
        The EntraOps object type to classify. One of 'User', 'ServicePrincipal' or 'Group'.
    .PARAMETER Object
        PSCustomObject with the resolved object details available to the filter expressions (exposed
        as $Object). Only primitive/array properties already known at classification time should be
        included (e.g. AssignedAdministrativeUnits, ObjectDisplayName, ObjectSignInName, ObjectSubType).
    .PARAMETER AlternateObjectTierLevelAttributes
        The "AlternateObjectTierLevelAttributes" section of EntraOpsConfig.json (or $null/absent).
    .OUTPUTS
        [PSCustomObject] with AdminTierLevel/AdminTierLevelName, or $null if alternate classification
        is not enabled.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateSet('User', 'ServicePrincipal', 'Group')]
        [string]$ObjectType,

        [Parameter(Mandatory = $true)]
        [PSObject]$Object,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [PSObject]$AlternateObjectTierLevelAttributes
    )

    if ($null -eq $AlternateObjectTierLevelAttributes) {
        return $null
    }

    # Most privileged tier first - first matching filter wins. Tag values follow the canonical
    # map in New-EntraOpsEAMOutputObject (WorkloadPlane shares tag "1" with ManagementPlane).
    $TierTagValueByName = [ordered]@{
        ControlPlane    = "0"
        ManagementPlane = "1"
        WorkloadPlane   = "1"
        UserAccess      = "2"
    }

    $TypeConfig = $AlternateObjectTierLevelAttributes.$ObjectType

    if ($ObjectType -eq 'Group') {
        $HasGroupFilter = $null -ne $TypeConfig -and @($TierTagValueByName.Keys | Where-Object { -not [string]::IsNullOrWhiteSpace($TypeConfig.$_) }).Count -gt 0
        if (-not $HasGroupFilter) {
            return $null
        }
    } elseif ($AlternateObjectTierLevelAttributes.Enabled -ne $true) {
        return $null
    }

    # SECURITY NOTE: AlternateObjectTierLevelAttributes filter expressions from EntraOpsConfig.json
    # are executed as PowerShell code in this module's context. Anyone who can modify the config file
    # can run arbitrary code with the privileges of the EntraOps run - treat EntraOpsConfig.json as
    # trusted code (same protection level as the module scripts themselves). Warned once per session.
    if (-not $Script:AlternateTierFilterSecurityWarned) {
        Write-Warning "AlternateObjectTierLevelAttributes expressions from EntraOpsConfig.json execute as PowerShell code — treat the config file as trusted code."
        $Script:AlternateTierFilterSecurityWarned = $true
    }

    # Compile each filter expression only once per session (cache keyed by the expression string) -
    # this function runs per principal and re-creating the scriptblock for every object is wasteful.
    if ($null -eq $Script:AlternateTierFilterScriptBlockCache) {
        $Script:AlternateTierFilterScriptBlockCache = @{}
    }

    if ($null -eq $TypeConfig) {
        Write-Warning "AlternateObjectTierLevelAttributes is enabled but no filter definitions found for object type '$ObjectType'. Classifying as Unclassified."
        return [PSCustomObject]@{ AdminTierLevel = "Unclassified"; AdminTierLevelName = "Unclassified" }
    }

    foreach ($TierName in $TierTagValueByName.Keys) {
        $FilterExpression = $TypeConfig.$TierName
        if ([string]::IsNullOrWhiteSpace($FilterExpression)) { continue }

        try {
            $FilterScriptBlock = $Script:AlternateTierFilterScriptBlockCache[$FilterExpression]
            if ($null -eq $FilterScriptBlock) {
                $FilterScriptBlock = [scriptblock]::Create($FilterExpression)
                $Script:AlternateTierFilterScriptBlockCache[$FilterExpression] = $FilterScriptBlock
            }
            $IsMatch = [bool](& $FilterScriptBlock)
        } catch {
            Write-Warning "AlternateObjectTierLevelAttributes filter for $ObjectType/$TierName failed to evaluate for object '$($Object.ObjectDisplayName)' ($($Object.ObjectId)): $($_.Exception.Message). Treating as no match."
            $IsMatch = $false
        }

        if ($IsMatch) {
            Write-Verbose "Object '$($Object.ObjectDisplayName)' ($($Object.ObjectId)) classified as $TierName by AlternateObjectTierLevelAttributes filter for $ObjectType."
            return [PSCustomObject]@{ AdminTierLevel = $TierTagValueByName[$TierName]; AdminTierLevelName = $TierName }
        }
    }

    Write-Verbose "Object '$($Object.ObjectDisplayName)' ($($Object.ObjectId)) matched no AlternateObjectTierLevelAttributes filter for $ObjectType. Classifying as Unclassified."
    return [PSCustomObject]@{ AdminTierLevel = "Unclassified"; AdminTierLevelName = "Unclassified" }
}
