function Invoke-EntraOpsTierBreachFindingRule {
    <#
    .SYNOPSIS
        Evaluates a Tier Breach finding rule against the assignment paths of the Tier Breach context.
    .DESCRIPTION
        Pure evaluation of the paths from New-EntraOpsTierBreachFindingContext (no file or Graph access):
          * breach: the object tier is less privileged (higher level) than the service tier, and the service is
            not Control Plane (Tier 0 services are reported by tier0Breach, so a path is never reported twice).
            Paths of unclassified objects are marked Unclassified: their tier is unknown, so they are counted
            apart from the results (UnclassifiedResults) instead of being reported as breaches.
          * tier0Breach: an object that is not Tier 0 reaches a Tier 0 (Control Plane) service.
        An instance is one role assignment of an object, with the services it reaches (a path per service in the
        context). The breach rule leaves out assignments that also reach a Control Plane service (tier0Breach
        reports them). Both rules leave out delegated permissions (reported by EO.5005) and the service principals
        of Microsoft first-party applications; the Tier Breach Analyzer still flags their paths.
        Returns the evaluated instances (see Invoke-EntraOpsFindingRuleSet): every assignment, failed when it breaches.
    .PARAMETER Context
        Context from New-EntraOpsTierBreachFindingContext.
    .PARAMETER Rule
        The Tier Breach finding rule (from Get-EntraOpsFindingRule).
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [object]$Context,

        [Parameter(Mandatory = $true)]
        [object]$Rule
    )

    if ($Rule.Key -notin 'breach', 'tier0Breach') { throw "No Tier Breach evaluator for finding rule '$($Rule.Id)' ($($Rule.Key))." }

    # One instance per role assignment of an object (RBAC system, object and assignment instance; the assignment
    # instance distinguishes scopes and the group of a transitive assignment). A path is one service of the
    # assignment, so an assignment that reaches several services is reported once, with its services.
    $Excluded = @(if ($null -ne $Rule.PSObject.Properties['ExcludedRules']) { $Rule.ExcludedRules })
    $Tier0Excluded = $Excluded -contains 'EO.1001' -or $Excluded -contains 'TierBreach.tier0Breach'
    # Display name of a tier level (0 Control Plane, 1 Management Plane, 2 User Access) or name.
    function Get-Tier($Value) { Get-EntraOpsTierDisplayName $Value }
    $Groups = [ordered]@{}
    foreach ($Path in $Context.Paths) {
        # Delegated permissions act within the rights of the signed-in user, not with the application's own
        # access: EO.5005 reports them. Microsoft first-party service principals are operated by Microsoft.
        if ($Path.delegatedPermission -or $Path.microsoftFirstParty) { continue }
        # A PIM activation is a temporary instance of an eligible assignment that the export lists next to it: the
        # eligible assignment is reported, so the breach is reported once and its exception keeps applying.
        if ("$($Path.pimAssignmentType)" -eq 'Activated') { continue }
        $Key = "$($Path.system)|$($Path.objectId)|$(if ($Path.assignmentInstanceId) { $Path.assignmentInstanceId } else { $Path.pathId })"
        if (-not $Groups.Contains($Key)) { $Groups[$Key] = [System.Collections.Generic.List[object]]::new() }
        $Groups[$Key].Add($Path)
    }

    foreach ($Key in $Groups.Keys) {
        $GroupPaths = @($Groups[$Key])
        $Failing = @($GroupPaths | Where-Object { Test-EntraOpsTierBreachPath -Key $Rule.Key -Path $_ } | Sort-Object { [int]$_.serviceTier }, { "$($_.service)" })
        # The breach rule leaves out the assignments that reach a Control Plane service: tier0Breach reports them -
        # unless tier0Breach is excluded, then the breach rule reports them with their Management Plane services.
        $ReportedByTier0 = $Rule.Key -eq 'breach' -and -not $Tier0Excluded -and @($GroupPaths | Where-Object { Test-EntraOpsTierBreachPath -Key 'tier0Breach' -Path $_ }).Count -gt 0
        if ($Failing.Count -eq 0 -or $ReportedByTier0) { [pscustomobject]@{ Failed = $false; InstanceKey = $Key }; continue }

        $Path = $Failing[0]
        # Unclassified objects count as User Access; the message says so instead of calling them User Access objects.
        $IsUnclassified = "$($Path.objectTierName)" -eq 'Unclassified'
        $ObjectTierName = if ($script:EntraOpsTierRank.ContainsKey("$($Path.objectTierName)")) { "$($Path.objectTierName)" } else { Get-Tier $Path.objectTier }
        $ObjectLabel = if ($IsUnclassified) { "Unclassified object (counted as $(Get-Tier $Path.objectTier))" } else { "$(Get-Tier $ObjectTierName) object" }
        $ServiceTier = if ("$($Path.serviceTierName)") { Get-Tier $Path.serviceTierName } else { Get-Tier $Path.serviceTier }
        $Via = if ("$($Path.transitiveBy)") { " via '$($Path.transitiveBy)'" } else { '' }
        $Scope = if ("$($Path.scopeName)") { " at '$($Path.scopeName)'" } else { '' }
        $Services = @($Failing | ForEach-Object { "$($_.service)" } | Select-Object -Unique)
        $ServiceText = if ($Services.Count -eq 1) {
            "the $ServiceTier service '$($Services[0])'"
        } else {
            $Shown = @($Services | Select-Object -First 3 | ForEach-Object { "'$_'" }) -join ', '
            $More = if ($Services.Count -gt 3) { " and $($Services.Count - 3) more" } else { '' }
            "$($Services.Count) $ServiceTier services ($Shown$More)"
        }
        [pscustomobject]@{
            Failed         = $true
            Unclassified   = $IsUnclassified -and $Rule.Key -eq 'breach'
            InstanceKey    = $Key
            ObjectId       = $Path.objectId
            ObjectType     = $Path.objectType
            DisplayName    = $Path.objectName
            AdminTierLevel = $Path.objectTier
            AdminTierLevelName = $(if ($IsUnclassified) { 'Unclassified' } elseif ($script:EntraOpsTierRank.ContainsKey("$($Path.objectTierName)")) { "$($Path.objectTierName)" } else { $null })
            Message        = "$ObjectLabel '$($Path.objectName)' reaches $ServiceText through the role '$($Path.role)' ($($Path.system))$Scope$Via."
            Evidence       = [ordered]@{
                System               = $Path.system
                Role                 = $Path.role
                RoleType             = $Path.roleType
                RoleIsPrivileged     = $Path.roleIsPrivileged
                # The most privileged service opens the path in the Tier Breach Analyzer; Services lists all of them.
                Service              = $Path.service
                Services             = $Services
                ServiceTierLevel     = $Path.serviceTier
                ScopeId              = $Path.scopeId
                ScopeName            = $Path.scopeName
                AssignmentInstanceId = $Path.assignmentInstanceId
                AssignmentType       = $Path.assignmentType
                PimAssignmentType    = $Path.pimAssignmentType
                TransitiveBy         = $Path.transitiveBy
                PathIds              = @($Failing | ForEach-Object { $_.pathId })
            }
        }
    }
}

function Test-EntraOpsTierBreachPath {
    <#
    .SYNOPSIS
        Tests whether an assignment path of the Tier Breach context crosses a tier boundary.
    .DESCRIPTION
        Shared by the Tier Breach finding rules and the Tier Breach Analyzer, which flags every path that
        crosses a tier (also the paths the rules leave out: delegated permissions and Microsoft first-party
        service principals).
          * breach: the object tier is less privileged than the service tier, and the service is not Control Plane.
          * tier0Breach: an object that is not Tier 0 reaches a Tier 0 (Control Plane) service.
    .PARAMETER Key
        The rule key: breach or tier0Breach.
    .PARAMETER Path
        A path from New-EntraOpsTierBreachFindingContext.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateSet('breach', 'tier0Breach')]
        [string]$Key,

        [Parameter(Mandatory = $true)]
        [object]$Path
    )

    if ($Key -eq 'tier0Breach') { return $Path.objectTier -gt 0 -and $Path.serviceTier -eq 0 }
    return $Path.serviceTier -gt 0 -and $Path.objectTier -gt $Path.serviceTier
}
