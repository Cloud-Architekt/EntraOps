<#
.SYNOPSIS
    Generate (refresh) the findings of the EntraOps PIM Request Flow and Access Package Flow static web apps.

.DESCRIPTION
    Evaluates the PIM Request Flow and Access Package Flow finding rules (Get-EntraOpsFindingRule) for every
    Tenant Governance snapshot with embedded content and writes the risk flags per flow, together with the
    tiers the rules evaluated (the report model: role tiers and approvers of PIM roles; requestors,
    approvers, target resources and assigned principals of access package assignment policies):
      * Reports/PimRequestFlow/data/pim-request-flow-findings.js (window.ENTRAOPS_PIM_REQUEST_FLOW_FINDINGS)
      * Reports/AccessPackageFlow/data/access-package-flow-findings.js (window.ENTRAOPS_ACCESS_PACKAGE_FLOW_FINDINGS)
    The reports show only these risk flags and tiers: without the files, or when the files were evaluated from other
    datasets than the reports show (for example after only one data generator ran again), they show a notice
    that the risk flags were not evaluated.

    The rules evaluate the generated report data the reports show (Configuration Analyzer data, Classification
    Explorer tier map, EAM Dashboard data and Access Package Flow data), so run this after the other report
    data generators. New-EntraOpsReportingData runs it as its last step. Rules excluded in EntraOpsConfig.json
    (Findings.ExcludedRules, or the deprecated ConfigurationAnalyzer.PimRequestFlowExcludedRiskFlags and
    .AccessPackageFlowExcludedRiskFlags of EntraOps 1.1.0) and deprecated rules are not written. The severity of
    a risk flag is the ReportSeverity of its rule (fail or warn), and each flag names its rule (ruleId).

    Finding exceptions (the Finding Exceptions File, Findings.ExceptionsFilePath) apply as in the finding results: the
    flag of a flow with an active exception for its rule (by instance, or by the object: the role of a PIM role
    setting, the policy of an access package) is not a risk flag but an accepted one (accepted, with the state,
    expiry and justification of the exception). For the access drift flags, the exception is the one of the resource.

.PARAMETER RepoRoot
    Path to the EntraOps repository root (alias: -Path). Defaults to the repository this module lives in.

.PARAMETER ReportPath
    Reports folder with the generated report data and the report apps. Defaults to <RepoRoot>/Reports.

.PARAMETER ConfigFilePath
    EntraOpsConfig.json with the Findings settings (ExcludedRules and rule parameters). Defaults to
    <RepoRoot>/EntraOpsConfig.json.

.PARAMETER PassThru
    Emit the generated payloads to the pipeline.

.EXAMPLE
    New-EntraOpsReportFindingData

    Refreshes the findings of the PIM Request Flow and Access Package Flow reports.
#>

function New-EntraOpsReportFindingData {

    [CmdletBinding(SupportsShouldProcess = $true)]
    param (
        [Parameter(Mandatory = $false)]
        [Alias('Path')]
        [System.String]$RepoRoot,

        [Parameter(Mandatory = $false)]
        [System.String]$ReportPath,

        [Parameter(Mandatory = $false)]
        [System.String]$ConfigFilePath,

        [Parameter(Mandatory = $false)]
        [switch]$PassThru
    )

    if ([string]::IsNullOrWhiteSpace($RepoRoot)) { $RepoRoot = (Get-EntraOpsFindingRoot).RepositoryRoot }
    if ([string]::IsNullOrWhiteSpace($ReportPath)) { $ReportPath = Join-Path $RepoRoot 'Reports' }

    $ReportData = Import-EntraOpsReportFindingData -ReportPath $ReportPath
    if ($null -eq $ReportData) {
        Write-Warning "No Configuration Analyzer data found in $ReportPath. The PIM Request Flow and Access Package Flow findings are not generated."
        return
    }
    if ([string]::IsNullOrWhiteSpace($ConfigFilePath)) { $ConfigFilePath = Join-Path $RepoRoot 'EntraOpsConfig.json' }
    $Setting = Get-EntraOpsFindingSetting -ConfigFilePath $ConfigFilePath
    $ExcludeRule = @($Setting.ExcludedRules)

    # Model entries without the properties that are not set, to keep the files small.
    function ConvertTo-ModelEntry($Entry) {
        $Model = [ordered]@{}
        foreach ($Name in 'label', 'scopeType', 'resourceName', 'tier', 'reason', 'declaredBy', 'protectionTier', 'protectionMember', 'resolved', 'source', 'idSource', 'id', 'groupId', 'isBackup', 'noMembers') {
            $Property = $Entry.PSObject.Properties[$Name]
            if ($null -eq $Property -or $null -eq $Property.Value -or $Property.Value -is [bool] -and -not $Property.Value) { continue }
            $Model[$Name] = $Property.Value
        }
        $Model
    }

    $Targets = @(
        @{ Area = 'PimRequestFlow'; App = 'PimRequestFlow'; File = 'data/pim-request-flow-findings.js'; Variable = 'ENTRAOPS_PIM_REQUEST_FLOW_FINDINGS'; Sources = @('configurationAnalyzer', 'eam', 'tierMap') }
        @{ Area = 'AccessPackageFlow'; App = 'AccessPackageFlow'; File = 'data/access-package-flow-findings.js'; Variable = 'ENTRAOPS_ACCESS_PACKAGE_FLOW_FINDINGS'; Sources = @('configurationAnalyzer', 'eam', 'accessPackage') }
    )
    foreach ($Target in $Targets) {
        $AppRoot = Join-Path $ReportPath $Target.App
        if (-not (Test-Path -LiteralPath $AppRoot -PathType Container)) {
            Write-Verbose "Skipped the $($Target.Area) findings: report app folder $AppRoot not found."
            continue
        }

        # Rule status of the newest snapshot like Invoke-EntraOpsFindingEvaluation; its evaluated rules (not
        # excluded or deprecated) give the risk flags, with the severity of the rule.
        $NewestIndex = -1
        for ($Index = 0; $Index -lt $ReportData.Snapshots.Count; $Index++) { if ($ReportData.Snapshots[$Index].hasDetail) { $NewestIndex = $Index } }
        $Rules = @(Get-EntraOpsFindingRule -Area $Target.Area)
        $Severities = @{}
        $RuleIds = @{}
        foreach ($Rule in $Rules) {
            $RuleIds[$Rule.Key] = $Rule.Id
            if ($Rule.Lifecycle -ne 'Deprecated' -and $ExcludeRule -notcontains $Rule.Id -and $ExcludeRule -notcontains "$($Rule.Area).$($Rule.Key)") { $Severities[$Rule.Key] = $Rule.ReportSeverity }
        }
        # Active finding exceptions of the rules of this area, by rule ID: instance exceptions by instance ID, object
        # exceptions by object ID (lowercase), like Split-EntraOpsFindingResultByException.
        $ExceptionIndex = @{}
        foreach ($Exception in @(if ($null -ne $Setting.PSObject.Properties['Exceptions']) { $Setting.Exceptions })) {
            if ($null -eq $Exception -or $Exception.Expired) { continue }
            if (-not $ExceptionIndex.ContainsKey($Exception.RuleId)) { $ExceptionIndex[$Exception.RuleId] = @{ Instance = @{}; Object = @{} } }
            if ($Exception.InstanceId) { $ExceptionIndex[$Exception.RuleId].Instance["$($Exception.InstanceId)".ToLowerInvariant()] = $Exception }
            elseif ($Exception.ObjectId) { $ExceptionIndex[$Exception.RuleId].Object["$($Exception.ObjectId)".ToLowerInvariant()] = $Exception }
        }
        # The exception of a flag: by the instance ID of the result (the flow id, | as .) or by its object.
        function Get-FlowException([string]$RuleId, [string]$InstanceKey, [string]$ObjectId) {
            if (-not $ExceptionIndex.ContainsKey($RuleId)) { return $null }
            $InstanceId = if ($InstanceKey -match '^[A-Za-z0-9][A-Za-z0-9._|-]{0,127}$') { $InstanceKey.Replace('|', '.') } else { ConvertTo-EntraOpsFindingInstanceId -Value $InstanceKey }
            $Found = $ExceptionIndex[$RuleId].Instance[$InstanceId.ToLowerInvariant()]
            if ($null -eq $Found -and $ObjectId) { $Found = $ExceptionIndex[$RuleId].Object[$ObjectId.ToLowerInvariant()] }
            $Found
        }
        # The exception that a flag accepted by several exceptions shows: a risk acceptance before a dismissal, and the
        # one that expires first, so the report reopens the flag when the first of them expires.
        function Select-FlowException([object[]]$Found) {
            @($Found | Where-Object { $null -ne $_ } | Sort-Object @{ Expression = { if ("$($_.State)" -eq 'Dismissed') { 1 } else { 0 } } }, @{ Expression = { if ($_.ExpiresOn) { "$($_.ExpiresOn)" } else { '9999-12-31' } } })[0]
        }
        # The exception that accepts a flag of a flow, or $null. Access drift flags are results of the resources:
        # accepted when every drifted privileged resource of the flow has an exception.
        function Get-FlagException($Flow, [string]$Key) {
            $RuleId = $RuleIds[$Key]
            if ($Key -cin 'unauthorizedAccess', 'missingAccess') {
                $DriftType = if ($Key -ceq 'unauthorizedAccess') { 'unauthorized' } else { 'missing' }
                $Drifted = @($Flow.targets | Where-Object { (Test-EntraOpsPrivilegedTier $_.tier) -and $null -ne $_.drift -and [int]$_.drift.$DriftType -gt 0 -and (Test-EntraOpsJsTruthy $_.originId) })
                if ($Drifted.Count -eq 0) { return $null }
                $Found = @(foreach ($DriftTarget in $Drifted) { Get-FlowException $RuleId "$($DriftTarget.originId)" "$($DriftTarget.originId)" })
                if (@($Found | Where-Object { $null -ne $_ }).Count -ne $Drifted.Count) { return $null }
                return (Select-FlowException $Found)
            }
            # Unclassified target groups are results of the groups: accepted when every one of the flow has an exception.
            if ($Key -ceq 'unclassifiedTarget') {
                $Unclassified = @($Flow.targets | Where-Object { $null -ne $_.PSObject.Properties['source'] -and $_.source -ceq 'unclassified' -and (Test-EntraOpsJsTruthy $_.originId) })
                if ($Unclassified.Count -eq 0) { return $null }
                $Found = @(foreach ($Group in $Unclassified) { Get-FlowException $RuleId "$($Group.originId)" "$($Group.originId)" })
                if (@($Found | Where-Object { $null -ne $_ }).Count -ne $Unclassified.Count) { return $null }
                return (Select-FlowException $Found)
            }
            $ObjectId = if ($Target.Area -eq 'PimRequestFlow') { "$($Flow.roleId)" } else { "$($Flow.id)" }
            Get-FlowException $RuleId "$($Flow.id)" $ObjectId
        }

        # Risk flags per flow for every snapshot the report can show (snapshots with embedded content). The
        # context checks every flow once; the newest context also gives the rule status.
        $Snapshots = [ordered]@{}
        $LatestContext = $null
        for ($Index = 0; $Index -lt $ReportData.Snapshots.Count; $Index++) {
            if (-not $ReportData.Snapshots[$Index].hasDetail) { continue }
            $Context = & "New-EntraOps$($Target.Area)FindingContext" -ReportData $ReportData -SnapshotIndex $Index
            $FlagsByFlow = [ordered]@{}
            $AcceptedByFlow = [ordered]@{}
            $Evaluated = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
            foreach ($Flow in $Context.Flows) {
                if (-not $Evaluated.Add($Flow.id)) { continue }
                $Flags = [System.Collections.Generic.List[object]]::new()
                $Accepted = [System.Collections.Generic.List[object]]::new()
                foreach ($Key in $Flow.checks.Keys) {
                    $Check = $Flow.checks[$Key]
                    if (-not ($Check.Failed -and $Severities.ContainsKey($Key))) { continue }
                    $Exception = Get-FlagException $Flow $Key
                    if ($null -eq $Exception) {
                        $Flags.Add([pscustomobject]@{ id = $Key; ruleId = $RuleIds[$Key]; severity = $Severities[$Key]; text = $Check.Text })
                    } else {
                        $Accepted.Add([pscustomobject]@{ id = $Key; ruleId = $RuleIds[$Key]; severity = $Severities[$Key]; text = $Check.Text; state = $Exception.State; expiresOn = $Exception.ExpiresOn; justification = $Exception.Justification })
                    }
                }
                if ($Flags.Count -gt 0) { $FlagsByFlow[$Flow.id] = @($Flags) }
                if ($Accepted.Count -gt 0) { $AcceptedByFlow[$Flow.id] = @($Accepted) }
            }
            # accepted: the flags with an active finding exception (not risk flags of the report).
            $SnapshotModel = [ordered]@{ flags = $FlagsByFlow; accepted = $AcceptedByFlow }
            if ($Target.Area -eq 'PimRequestFlow') {
                # Per role ("<roleId>|..." flows): its tier and the activation approvers.
                $Roles = [ordered]@{}
                foreach ($Flow in @($Context.Flows | Where-Object path -eq 'activation')) {
                    $RoleKey = $Flow.id.Substring(0, $Flow.id.Length - '|activation'.Length)
                    if ($Roles.Contains($RoleKey)) { continue }
                    $Role = [ordered]@{}
                    if ($Flow.roleTier) { $Role.tier = $Flow.roleTier }
                    if ($Flow.roleTierService) { $Role.service = $Flow.roleTierService }
                    if (@($Flow.approvers).Count -gt 0) { $Role.approvers = @($Flow.approvers | ForEach-Object { ConvertTo-ModelEntry $_ }) }
                    if ($Role.Count -gt 0) { $Roles[$RoleKey] = $Role }
                }
                $SnapshotModel.roles = $Roles
            } else {
                # Per access package: its target resources; per assignment policy: requestors, approvers and
                # assigned principals.
                $PackageModel = [ordered]@{}
                foreach ($PackageKey in $Context.Packages.Keys) {
                    $Package = $Context.Packages[$PackageKey]
                    if ($Package.hasTargets) { $PackageModel[$PackageKey] = [ordered]@{ targets = @($Package.targets | ForEach-Object { ConvertTo-ModelEntry $_ }) } }
                }
                $FlowModel = [ordered]@{}
                foreach ($Flow in $Context.Flows) {
                    if ($FlowModel.Contains($Flow.id)) { continue }
                    $FlowModel[$Flow.id] = [ordered]@{
                        requestors = @($Flow.requestors | ForEach-Object { ConvertTo-ModelEntry $_ })
                        approvers  = @($Flow.approvers | ForEach-Object { ConvertTo-ModelEntry $_ })
                        assigned   = @($Flow.assignedPrincipals | ForEach-Object { ConvertTo-ModelEntry ([pscustomobject]@{ label = $_.label; tier = $_.tierName; resolved = $_.resolved; source = $_.source }) })
                    }
                    # The tier the approval is protected for, as the approver checks compare it (not set without a resolved approver).
                    if ($Flow.approvalTier) { $FlowModel[$Flow.id].approvalTier = $Flow.approvalTier }
                }
                $SnapshotModel.packages = $PackageModel
                $SnapshotModel.flows = $FlowModel
            }
            $Snapshots[$Context.SnapshotKey] = $SnapshotModel
            if ($Index -eq $NewestIndex) { $LatestContext = $Context }
        }

        # Without a snapshot with embedded content, the context has no snapshot and the rules are skipped.
        if ($null -eq $LatestContext) { $LatestContext = & "New-EntraOps$($Target.Area)FindingContext" -ReportData $ReportData }
        $RuleSummaries = @(Invoke-EntraOpsFindingRuleSet -Context $LatestContext -ExcludeRule $ExcludeRule -Setting $Setting | ConvertTo-EntraOpsFindingRuleSummary)
        # excluded: the rule writes no risk flags (excluded in the settings, or deprecated).
        foreach ($Summary in $RuleSummaries) { $Summary['excluded'] = $Summary['status'] -eq 'Excluded' }

        # The generation time of the datasets the findings were evaluated from: the report ignores the
        # findings when it shows other datasets (for example after only one generator ran again).
        $Sources = [ordered]@{}
        foreach ($Source in $Target.Sources) { $Sources[$Source] = $ReportData.SourceStamps[$Source] }
        # schemaVersion 2: snapshots hold the risk flags (flags, each with its ruleId), the flags accepted by a finding
        # exception (accepted) and the report model (roles, or packages and flows); rules lists the rules (excluded).
        $Payload = [ordered]@{
            schemaVersion = 2
            generatedAt   = (Get-Date).ToUniversalTime().ToString('o')
            sources       = $Sources
            rules         = $RuleSummaries
            snapshots     = $Snapshots
        }
        $OutFile = Join-Path $AppRoot $Target.File
        $Content = "// Auto-generated by New-EntraOpsReportFindingData - do not edit by hand.`n" +
        "window.$($Target.Variable) = $($Payload | ConvertTo-Json -Depth 10 -Compress);`n"
        if ($PSCmdlet.ShouldProcess($OutFile, "Write $($Target.Area) findings")) {
            Save-EntraOpsReportDataFile -Content $Content -LiteralPath $OutFile
            $FlagCount = @($Snapshots.Values | ForEach-Object { $_.flags.Values } | ForEach-Object { $_ }).Count
            Write-Host "$($Target.Area) findings: $FlagCount risk flag(s) in $($Snapshots.Count) snapshot(s) - wrote $OutFile"
        }
        if ($PassThru) { [pscustomobject]@{ Area = $Target.Area; OutFile = $OutFile; Payload = $Payload } }
    }
}
