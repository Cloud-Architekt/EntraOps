<#
.SYNOPSIS
    Get the catalog of EntraOps finding rules.

.DESCRIPTION
    Returns the metadata of the EntraOps finding rules: the checks of privileged access and the Enterprise
    Access Model that Invoke-EntraOpsFindingEvaluation evaluates and that the EntraOps reports and the
    EntraOps Maester Pack show.

    The catalog (Private/Findings/FindingRules.json) is the single source for the rule ID, key, title,
    description, remediation, effort, user impact and severity. Each rule has a stable ID (EO.<n>) and a key (for example
    tierBreach) that is unique within its area, so review states and excluded risk flags of the reports
    keep working. Title names the finding as the reports show it; CheckTitle states the expected (passing)
    state, the title of the rule as a test of the EntraOps Maester Pack with the ID MaesterTestId
    (MP.EOPS.<n>).

    Rules are grouped by Category, the security theme. The first digit of the rule ID is the number of the
    category (CategoryNumber):
      1 TierBoundaries         Lower tiers that control objects, services or access of a more privileged tier
      2 Classification         Objects, role assignments and approvers without a tier, roles to review
      3 JustInTimeAccess       Standing access and the PIM settings of eligible assignments and activations
      4 AccountProtection      Restricted management, cloud-only and member accounts, PAW, Conditional Access
      5 WorkloadIdentities     Service principals, applications and agent identities with privileged access
      6 AccessGovernance       Access packages: approval, requestor scope, expiration, access reviews, access drift
      7 OwnershipAndDelegation Owners of privileged objects, role assignment delegation, nested groups, AUs
      8 Drift                  Changes of privileged access between Privileged EAM snapshots
    Area is the data the rule evaluates (see Invoke-EntraOpsFindingEvaluation).

    Rule IDs never change once they are released (FindingRules.lock.json): a new rule is appended to its
    category, and a released rule that is no longer needed keeps its ID with Lifecycle Deprecated (it is not
    evaluated: Invoke-EntraOpsFindingEvaluation returns it as Excluded).
    ReportSeverity is the severity the reports show, derived from the rule: the breach type of the Tier Breach
    rules (tier0Breach, breach), fail (High) or warn (Medium) for the risk flags of PIM Request Flow and Access
    Package Flow, else the severity in lower case.
    Parameters lists the settings a rule uses, with their EntraOpsConfig.json setting (Findings.<Setting>)
    and default value.
    Effort and UserImpact rate the remediation of a failed rule as Low, Medium or High, each explained in
    one sentence (EffortDescription, UserImpactDescription), to plan and prioritize the remediation.
    References lists the resources of a rule (Title, Url and Type: Learn for Microsoft Learn, Graph for the
    Microsoft Graph reference, EntraOps for the EntraOps documentation), which the reports and the Maester
    test descriptions link.

.PARAMETER Area
    Return only the rules of these areas. The areas and categories come from the catalog (tab completion);
    an unknown value fails with the list of valid values.

.PARAMETER Category
    Return only the rules of these categories.

.PARAMETER Id
    Return only the rules with these IDs (for example EO.1001). Wildcards are supported.

.PARAMETER Key
    Return only the rules with these keys (for example tierBreach). Wildcards are supported.

.EXAMPLE
    Get-EntraOpsFindingRule

    Lists all finding rules (Id, Area, Severity and Title).

.EXAMPLE
    Get-EntraOpsFindingRule | Format-Table Id, Category, Severity, CheckTitle

    Lists the check titles of the rules by category.

.EXAMPLE
    Get-EntraOpsFindingRule -Category JustInTimeAccess

    Lists the rules on standing privileged access and the PIM settings.
#>

function Get-EntraOpsFindingRule {

    [CmdletBinding()]
    param (
        # Areas and categories come from the catalog (tab completion in the module scope, validation in the body).
        [Parameter(Mandatory = $false)]
        [ArgumentCompleter({ param($CommandName, $ParameterName, $WordToComplete) & (Get-Command $CommandName).Module { Get-EntraOpsFindingCatalogCompletion -Name $args[0] -WordToComplete $args[1] } Area $WordToComplete })]
        [string[]]$Area,

        [Parameter(Mandatory = $false)]
        [ArgumentCompleter({ param($CommandName, $ParameterName, $WordToComplete) & (Get-Command $CommandName).Module { Get-EntraOpsFindingCatalogCompletion -Name $args[0] -WordToComplete $args[1] } Category $WordToComplete })]
        [string[]]$Category,

        [Parameter(Mandatory = $false)]
        [string[]]$Id,

        [Parameter(Mandatory = $false)]
        [string[]]$Key
    )

    Assert-EntraOpsFindingCatalogValue -Name Area -Value $Area
    Assert-EntraOpsFindingCatalogValue -Name Category -Value $Category
    $FindingCatalog = Get-EntraOpsFindingCatalog
    $Catalog = $FindingCatalog.Catalog
    $Categories = $FindingCatalog.Categories

    foreach ($Rule in @($Catalog.rules)) {
        if ($Area -and $Rule.Area -notin $Area) { continue }
        if ($Category -and $Rule.Category -notin $Category) { continue }
        if ($Id -and -not @($Id | Where-Object { $Rule.Id -like $_ })) { continue }
        if ($Key -and -not @($Key | Where-Object { $Rule.Key -like $_ })) { continue }

        # The severity the reports show: the breach type of Tier Breach, fail (Critical, High), warn (Medium, Low) or
        # info (Info) for the risk flags of the flow reports, else the severity in lower case.
        $ReportSeverity = if ($Rule.Area -eq 'TierBreach') { $Rule.Key }
        elseif ($Rule.Area -in 'PimRequestFlow', 'AccessPackageFlow' -and $Rule.Severity -in 'Critical', 'High') { 'fail' }
        elseif ($Rule.Area -in 'PimRequestFlow', 'AccessPackageFlow' -and $Rule.Severity -in 'Medium', 'Low') { 'warn' }
        else { "$($Rule.Severity)".ToLowerInvariant() }

        [pscustomobject]@{
            PSTypeName            = 'EntraOps.FindingRule'
            Id                    = $Rule.Id
            Key                   = $Rule.Key
            Area                  = $Rule.Area
            Category              = $Rule.Category
            CategoryTitle         = $Categories[$Rule.Category].Title
            CategoryNumber        = $Categories[$Rule.Category].Number
            Title                 = $Rule.Title
            CheckTitle            = $Rule.CheckTitle
            Description           = $Rule.Description
            Remediation           = $Rule.Remediation
            Effort                = $Rule.Effort
            EffortDescription     = $Rule.EffortDescription
            UserImpact            = $Rule.UserImpact
            UserImpactDescription = $Rule.UserImpactDescription
            Severity              = $Rule.Severity
            # The rule asks for a review of what it finds, not a fix (Maester: Investigate instead of Failed).
            Investigate           = [bool]$Rule.Investigate
            ReportSeverity        = $ReportSeverity
            Product               = $(if ($Rule.Product) { $Rule.Product } else { 'entra' })
            Feature               = $Rule.Feature
            ResourceType          = $Rule.ResourceType
            Lifecycle             = $(if ($Rule.Lifecycle) { $Rule.Lifecycle } else { 'Stable' })
            Parameters            = @(@($Rule.Parameters) | Where-Object { $_ })
            References            = @(@($Rule.References) | Where-Object { $_ })
            MaesterTestId         = 'MP.{0}.{1}' -f $Catalog.maesterPackCode, ($Rule.Id -replace '^EO\.', '')
        }
    }
}
