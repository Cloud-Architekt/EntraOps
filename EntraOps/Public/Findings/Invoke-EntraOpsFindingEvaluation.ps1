<#
.SYNOPSIS
    Evaluate the EntraOps finding rules.

.DESCRIPTION
    Evaluates the finding rules (see Get-EntraOpsFindingRule) against the EntraOps data and returns one
    result per rule with its status, the number of evaluated and failed instances and the failed instances
    (Results), sorted by rule ID, so by category (see Get-EntraOpsFindingRule):
      * Failed: at least one instance failed the rule. Passed: instances were evaluated and none failed.
      * Skipped: the data of the rule is missing, nothing is in the scope of the rule, or only unclassified
        objects are affected (Reason).
      * Excluded: the rule is excluded (Findings.ExcludedRules, -ExcludeRule) or deprecated (Reason).
      * Error: the rule could not be evaluated (Reason): its data could not be read, a Findings setting of
        its parameters is invalid, or the evaluation failed.
    Parameters lists the values of the rule parameters the rule used (Findings settings of EntraOpsConfig.json).
    Rules whose result depends on the tier of the affected object (EO.1003) don't report unclassified objects,
    whose tier is unknown: UnclassifiedCount counts them and UnclassifiedResults lists them, apart from Results.
    Results dismissed or risk accepted in the Finding Exceptions File (Findings.ExceptionsFilePath, default
    ./Classification/FindingExceptions.json) are not failures: AcceptedCount counts them and AcceptedResults
    lists them with their exception, and Exceptions lists the exceptions of the rule with their status
    (Active, Expired, Stale or NotEvaluated). The Privileged Assets Findings view maintains the file.
    DataGaps lists the data gaps that affect a rule (Code, Message, Count and RuleIds): data that is missing, so the rule
    evaluates less than it seems to, for example groups whose origin is unknown (permission
    Group-XTenantIdentitySync.Read.All missing), groups of other tenants whose members were not collected (no
    ManagingTenantId), or an enabled Object Classification File that does not exist. Save-EntraOpsFindingJson lists them
    in findings.json (DataGaps), and the Privileged Assets Findings view shows them above the results.

    The reports use the same evaluation, so the results match what the reports show. The results can be
    saved with Save-EntraOpsFindingJson, for example for the EntraOps Maester Pack.

    Areas and their data:
      * PrivilegedAssets: privileged objects (users, groups, service principals and applications) from the
        Privileged EAM export, merged across all RBAC systems.
      * TierBreach: assignment paths from the Privileged EAM export (PrivilegedEAM/<RbacSystem>/<RbacSystem>.json).
      * PrivilegedEAM: privileged objects and every role assignment of the Privileged EAM export.
      * PimRequestFlow: PIM role settings of the newest Tenant Governance snapshot with embedded content.
      * AccessPackageFlow: access package assignment policies of the newest Tenant Governance snapshot with
        embedded content.
      * TenantGovernance: PIM role settings, access package assignment policies, Conditional Access policies
        and administrative units of the newest Tenant Governance snapshot with embedded content.
      * PrivilegeHistory: the newest and the previous snapshot of the Privilege History.
    PimRequestFlow, AccessPackageFlow, TenantGovernance and PrivilegeHistory evaluate the generated report data
    in -ReportPath, like the reports: the Configuration Analyzer data (required), the Classification Explorer
    tier map, the EAM Dashboard data, the Access Package Flow data and the Privilege History data. Generate it
    with New-EntraOpsReportingData first.

    The data of every area is read once: the Privileged EAM export is parsed once for PrivilegedAssets,
    TierBreach and PrivilegedEAM, and the Tenant Governance rules reuse the PIM Request Flow and Access Package
    Flow models.

.PARAMETER Area
    Areas to evaluate (see Get-EntraOpsFindingRule; tab completion lists them). Defaults to all areas.

.PARAMETER Category
    Return only the rules of these categories (see Get-EntraOpsFindingRule). Defaults to all categories.

.PARAMETER ImportPath
    Folder with the Privileged EAM export. Defaults to <EntraOpsRoot>/PrivilegedEAM.

.PARAMETER ReportPath
    Reports folder with the generated report data. Defaults to <EntraOpsRoot>/Reports.

.PARAMETER ExcludeRule
    Rules to skip, by ID (EO.1003) or by area and key (TierBreach.breach), in addition to the rules excluded
    in EntraOpsConfig.json (Findings.ExcludedRules). Excluded rules are returned with status Excluded. An entry
    that matches no rule is reported with a warning that lists the valid rule IDs.

.PARAMETER ConfigFilePath
    EntraOpsConfig.json with the Findings settings: ExcludedRules and the values of the rule parameters
    (ControlPlaneActivationMaxHours, EligibleAssignmentMaxDays, EmergencyAccessAccounts; see the Parameters of
    Get-EntraOpsFindingRule). Defaults to <EntraOpsRoot>/EntraOpsConfig.json; without the file, the rules use
    their defaults. ExceptionsFilePath and ExceptionMaxDays set the Finding Exceptions File, which is read
    relative to the folder of the file. ConfigurationAnalyzer.PimRequestFlowExcludedRiskFlags and
    .AccessPackageFlowExcludedRiskFlags (EntraOps 1.1.0) are still read as deprecated aliases of
    Findings.ExcludedRules (PimRequestFlow.<Key>, AccessPackageFlow.<Key>).

.PARAMETER ReportDataSkipReason
    Skips the rules that evaluate the Tenant Governance report data (TenantGovernance, PimRequestFlow and
    AccessPackageFlow) with this reason instead of reading the Configuration Analyzer data of -ReportPath.
    New-EntraOpsReportingData sets it when the Configuration Analyzer data could not be generated in its run, so
    the results don't present the data of an earlier run as current.

.EXAMPLE
    Invoke-EntraOpsFindingEvaluation

    Evaluates all rules and lists them with severity, status and failed/evaluated instances.

.EXAMPLE
    (Invoke-EntraOpsFindingEvaluation -Area TierBreach | Where-Object Key -eq 'tier0Breach').Results

    Lists the assignment paths of lower-tier objects that reach a Control Plane service (rule, severity, object
    and message).

.EXAMPLE
    Invoke-EntraOpsFindingEvaluation -Category JustInTimeAccess | Where-Object Status -eq 'Failed'

    Lists the failed rules on standing privileged access and the PIM settings.
#>

function Invoke-EntraOpsFindingEvaluation {

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
        [System.String]$ImportPath,

        [Parameter(Mandatory = $false)]
        [System.String]$ReportPath,

        [Parameter(Mandatory = $false)]
        [string[]]$ExcludeRule = @(),

        [Parameter(Mandatory = $false)]
        [System.String]$ConfigFilePath,

        [Parameter(Mandatory = $false)]
        [System.String]$ReportDataSkipReason
    )

    Assert-EntraOpsFindingCatalogValue -Name Area -Value $Area
    Assert-EntraOpsFindingCatalogValue -Name Category -Value $Category
    if (-not $Area) { $Area = (Get-EntraOpsFindingCatalog).Areas }
    $RepositoryRoot = (Get-EntraOpsFindingRoot).RepositoryRoot
    if ([string]::IsNullOrWhiteSpace($ImportPath)) { $ImportPath = Join-Path $RepositoryRoot 'PrivilegedEAM' }
    if ([string]::IsNullOrWhiteSpace($ReportPath)) { $ReportPath = Join-Path $RepositoryRoot 'Reports' }
    if ([string]::IsNullOrWhiteSpace($ConfigFilePath)) { $ConfigFilePath = Join-Path $RepositoryRoot 'EntraOpsConfig.json' }
    $Setting = Get-EntraOpsFindingSetting -ConfigFilePath $ConfigFilePath
    $ExcludeRule = @(Resolve-EntraOpsFindingExclusion -ExcludeRule $ExcludeRule -Source '-ExcludeRule') + @($Setting.ExcludedRules)

    # Only evaluate the areas that have rules of the selected categories.
    if ($Category) { $Area = @($Area | Where-Object { @(Get-EntraOpsFindingRule -Area $_ -Category $Category).Count -gt 0 }) }

    # The inputs of the context builders by parameter name, each read once: the context builder of an area
    # (New-EntraOps<Area>FindingContext) gets the inputs its parameters name. A missing input skips the rules
    # of the area with the reason, an input that cannot be read returns them with status Error.
    $Inputs = @{}
    $Contexts = @{}
    $Sources = @{
        ImportPath    = { [pscustomobject]@{ Value = $ImportPath } }
        ReportPath    = { [pscustomobject]@{ Value = $ReportPath } }
        Export        = {
            if (-not (Test-Path -LiteralPath $ImportPath)) { return [pscustomobject]@{ SkipReason = "No Privileged EAM export found in $ImportPath. Run Invoke-EntraOpsPrivilegedEAM (or Save-EntraOpsPrivilegedEAMJson) first, or pass -ImportPath." } }
            try {
                [pscustomobject]@{ Value = Read-EntraOpsPrivilegedEamExport -ImportPath $ImportPath }
            } catch {
                Write-Warning "The Privileged EAM export in $ImportPath could not be read: $($_.Exception.Message)"
                [pscustomobject]@{ ErrorReason = "The Privileged EAM export in $ImportPath could not be read: $($_.Exception.Message)" }
            }
        }
        ReportData    = {
            if (-not [string]::IsNullOrWhiteSpace($ReportDataSkipReason)) { return [pscustomobject]@{ SkipReason = $ReportDataSkipReason } }
            Write-Verbose "Reading the Tenant Governance report data from $ReportPath."
            try {
                $Data = Import-EntraOpsReportFindingData -ReportPath $ReportPath
                if ($null -eq $Data) { return [pscustomobject]@{ SkipReason = "No Configuration Analyzer data found in $ReportPath. Generate the report data with New-EntraOpsReportingData, or pass -ReportPath." } }
                [pscustomobject]@{ Value = $Data }
            } catch {
                Write-Warning "The Tenant Governance report data in $ReportPath could not be read: $($_.Exception.Message)"
                [pscustomobject]@{ ErrorReason = "The Tenant Governance report data in $ReportPath could not be read: $($_.Exception.Message)" }
            }
        }
        # Contexts that other context builders reuse.
        Inventory     = { Get-ContextInput 'PrivilegedAssets' }
        Pim           = { Get-ContextInput 'PimRequestFlow' }
        AccessPackage = { Get-ContextInput 'AccessPackageFlow' }
    }
    function Get-Input([string]$Name) {
        if (-not $Inputs.ContainsKey($Name)) { $Inputs[$Name] = & $Sources[$Name] }
        $Inputs[$Name]
    }
    # The context of another area as input; its skip or error reason applies to the dependent area as well.
    function Get-ContextInput([string]$ContextArea) {
        $Built = Get-AreaContext $ContextArea
        if ($null -ne $Built.PSObject.Properties['ErrorReason']) { return [pscustomobject]@{ ErrorReason = $Built.ErrorReason } }
        if ($null -ne $Built.PSObject.Properties['SkipReason'] -and $Built.SkipReason) { return [pscustomobject]@{ SkipReason = $Built.SkipReason } }
        [pscustomobject]@{ Value = $Built }
    }
    function Get-AreaContext([string]$ContextArea) {
        if ($Contexts.ContainsKey($ContextArea)) { return $Contexts[$ContextArea] }
        $Builder = "New-EntraOps$($ContextArea)FindingContext"
        $Parameters = @{}
        $Context = $null
        foreach ($Name in (Get-Command $Builder).Parameters.Keys) {
            if (-not $Sources.ContainsKey($Name)) { continue }
            $Value = Get-Input -Name $Name
            if ($null -ne $Value.PSObject.Properties['ErrorReason']) { $Context = [pscustomobject]@{ Area = $ContextArea; ErrorReason = $Value.ErrorReason }; break }
            if ($null -ne $Value.PSObject.Properties['SkipReason']) { $Context = [pscustomobject]@{ Area = $ContextArea; SkipReason = $Value.SkipReason }; break }
            $Parameters[$Name] = $Value.Value
        }
        # A builder that reads -ImportPath itself is given the parsed export instead.
        if ($Parameters.ContainsKey('Export')) { $Parameters.Remove('ImportPath') }
        if ($null -eq $Context) {
            try {
                $Context = & $Builder @Parameters
            } catch {
                Write-Warning "The $ContextArea finding rules could not be evaluated: $($_.Exception.Message)"
                $Context = [pscustomobject]@{ Area = $ContextArea; ErrorReason = "The $ContextArea data could not be evaluated: $($_.Exception.Message)" }
            }
        }
        $Contexts[$ContextArea] = $Context
        $Context
    }

    $RuleResults = foreach ($CurrentArea in $Area) {
        Write-Verbose "Evaluating the $CurrentArea finding rules."
        Invoke-EntraOpsFindingRuleSet -Context (Get-AreaContext $CurrentArea) -ExcludeRule $ExcludeRule -Setting $Setting
    }
    $RuleResults = @($RuleResults | Where-Object { -not $Category -or $_.Category -in $Category })

    # Data gaps: data that is missing, so that rules evaluate less than they seem to (see Get-EntraOpsFindingDataGap).
    # Each rule result carries the gaps that affect it (DataGaps); Save-EntraOpsFindingJson lists them in findings.json.
    $Inventory = if ($Contexts.ContainsKey('PrivilegedAssets') -and $null -ne $Contexts['PrivilegedAssets'].PSObject.Properties['Objects']) { $Contexts['PrivilegedAssets'] }
    $ReportDataInput = if ($Inputs.ContainsKey('ReportData') -and $null -ne $Inputs['ReportData'].PSObject.Properties['Value']) { $Inputs['ReportData'].Value }
    $DataGaps = @(Get-EntraOpsFindingDataGap -Inventory $Inventory -ManagingTenantId "$($Setting.Values['ManagingTenantId'])" -ConfigFilePath $ConfigFilePath -ReportData $ReportDataInput)
    foreach ($Gap in $DataGaps) { Write-Verbose "Data gap $($Gap.Code) ($(@($Gap.RuleIds) -join ', ')): $($Gap.Message)" }
    foreach ($RuleResult in $RuleResults) {
        $RuleResult | Add-Member -NotePropertyName DataGaps -NotePropertyValue @($DataGaps | Where-Object { @($_.RuleIds) -contains $RuleResult.RuleId }) -Force
    }
    $RuleResults | Sort-Object RuleId
}
