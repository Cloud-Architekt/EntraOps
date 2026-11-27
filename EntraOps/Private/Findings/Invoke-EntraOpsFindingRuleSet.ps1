# PIM role setting rules: a role setting that fails for every evaluated role suggests the default setting of the tenant.
$script:EntraOpsTenantWideRoleSettingKeys = [string[]]@('permanentEligible', 'permanentActive', 'noMfaActivation', 'noApprovalActivation', 'noMfaActiveAssign', 'controlPlaneActivationAuthContext', 'eligibleAssignmentDuration', 'controlPlaneActivationDuration', 'privilegedRoleAlert')

function Invoke-EntraOpsFindingRuleSet {
    <#
    .SYNOPSIS
        Evaluates the finding rules of one area against a prepared context.
    .DESCRIPTION
        Shared by Invoke-EntraOpsFindingEvaluation and the reporting data generators, so the reports and
        the exported findings use the same evaluation. Returns one result per rule with its status:
          * Failed: at least one instance failed the rule.
          * Passed: instances were evaluated and none failed.
          * Skipped: there was nothing to evaluate (for example no assignment paths), the data the rule
            needs is missing (Reason, from the SkipReason of the context or of the evaluation), or only
            unclassified objects failed the rule (Reason): their tier is unknown, so they need a
            classification before the rule can report them.
          * Excluded: the rule is listed in -ExcludeRule, or it is deprecated (Lifecycle Deprecated), and was
            not evaluated.
          * Error: the rule could not be evaluated (Reason): its data could not be read (ErrorReason of the
            context), a setting of its parameters is invalid, or its evaluator failed.

        The evaluator of the area (Invoke-EntraOps<Area>FindingRule) returns the evaluated instances of a
        rule: objects with Failed, InstanceKey and the fields of New-EntraOpsFindingResult (ObjectId,
        ObjectType, DisplayName, AdminTierLevel, Message, Evidence), or one object with SkipReason when the
        data of the rule is missing. ConvertTo-EntraOpsFindingEvaluation turns them into the results.
        Failed instances of unclassified objects (Unclassified) are not results: the rule result counts them
        (UnclassifiedCount) and keeps them apart (UnclassifiedResults), so the reports can show them on request.
        Results with a finding exception of the settings (Exceptions, the Finding Exceptions File) that has not
        expired are accepted: the rule result counts them (AcceptedCount) and keeps them apart (AcceptedResults,
        with Status RiskAccepted or Dismissed and the Exception), so a rule whose results are all accepted
        passes. Exceptions lists the exceptions of the rule with their Status: Active (accepts results),
        Expired (its results are reported again), Stale (no result matches, for example the finding was
        fixed) or NotEvaluated (the rule was not evaluated).
        ReasonCode tells what the Reason is: NotApplicable (nothing in the scope of the rule), MissingData (the data
        of the rule is missing), Unclassified (only unclassified objects failed), Note (a note of a Failed or Passed
        rule, for example data it could not evaluate or a hint how to fix the results), Excluded, Deprecated or Error.
        The evaluator can add a note of the rule with an instance that has only Note and NoteOnly.
        The rules get the excluded rules (ExcludedRules), so a rule can report what an excluded rule would report.
    .PARAMETER Context
        Area context, for example from New-EntraOpsTierBreachFindingContext. Its Area property selects
        the rules and the evaluator. A SkipReason property skips all rules of the area with that reason, an
        ErrorReason property returns them with status Error; a context with a SnapshotKey property but no
        snapshot (Tenant Governance report data without a snapshot with embedded content) is skipped.
    .PARAMETER ExcludeRule
        Rules to skip, by ID (EO.1003) or by area and key (TierBreach.breach).
    .PARAMETER Setting
        Settings from Get-EntraOpsFindingSetting. The rules get the values of their parameters as
        ParameterValues (the setting value, else the default of the parameter), and the results list them.
        Its Exceptions accept results.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [object]$Context,

        [Parameter(Mandatory = $false)]
        [string[]]$ExcludeRule = @(),

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]$Setting
    )

    $ContextReason = $null
    $ContextStatus = $null
    if ($null -ne $Context.PSObject.Properties['ErrorReason'] -and $Context.ErrorReason) {
        $ContextStatus = 'Error'; $ContextReason = $Context.ErrorReason
    } elseif ($null -ne $Context.PSObject.Properties['SkipReason'] -and $Context.SkipReason) {
        $ContextStatus = 'Skipped'; $ContextReason = $Context.SkipReason
    } elseif ($null -ne $Context.PSObject.Properties['SnapshotKey'] -and $null -eq $Context.SnapshotKey) {
        $ContextStatus = 'Skipped'; $ContextReason = 'The Configuration Analyzer data has no Tenant Governance snapshot with embedded content.'
    }

    foreach ($Rule in @(Get-EntraOpsFindingRule -Area $Context.Area)) {
        $ParameterValues = [ordered]@{}
        $SettingError = $null
        foreach ($Parameter in $Rule.Parameters) {
            # Assigned in the branches (not from an if expression), so a list stays a list: an empty or one-element
            # list would otherwise become $null or the element.
            if ($null -ne $Setting -and $Setting.Values.ContainsKey($Parameter.Setting)) { $Value = $Setting.Values[$Parameter.Setting] } else { $Value = $Parameter.Default }
            if ($Parameter.Default -is [array] -and $Value -isnot [array]) { $Value = @(if ($null -ne $Value) { $Value }) }
            $ParameterValues[$Parameter.Name] = $Value
            if ($null -ne $Setting -and $null -ne $Setting.PSObject.Properties['Errors'] -and $Setting.Errors.ContainsKey($Parameter.Setting)) { $SettingError = $Setting.Errors[$Parameter.Setting] }
        }
        $Rule | Add-Member -NotePropertyName ParameterValues -NotePropertyValue $ParameterValues -Force
        $Rule | Add-Member -NotePropertyName ExcludedRules -NotePropertyValue @($ExcludeRule) -Force
        $Results = @()
        $UnclassifiedResults = @()
        $AcceptedResults = @()
        $EvaluatedCount = 0
        $Reason = $null
        $ReasonCode = $null
        $RuleExceptions = @(if ($null -ne $Setting -and $null -ne $Setting.PSObject.Properties['Exceptions']) { @($Setting.Exceptions) | Where-Object { $_.RuleId -eq $Rule.Id } })
        $Matched = @{}
        if ($ExcludeRule -contains $Rule.Id -or $ExcludeRule -contains "$($Rule.Area).$($Rule.Key)") {
            $Status = 'Excluded'
            $ReasonCode = 'Excluded'
        } elseif ($Rule.Lifecycle -eq 'Deprecated') {
            $Status = 'Excluded'
            $ReasonCode = 'Deprecated'
            $Reason = 'Deprecated rule: it is no longer evaluated and keeps its ID so that its Maester test stays reserved.'
        } elseif ($ContextStatus) {
            $Status = $ContextStatus
            $ReasonCode = if ($ContextStatus -eq 'Error') { 'Error' } else { 'MissingData' }
            $Reason = $ContextReason
        } elseif ($SettingError) {
            $Status = 'Error'
            $ReasonCode = 'Error'
            $Reason = $SettingError
        } else {
            try {
                $Instances = @(& "Invoke-EntraOps$($Rule.Area)FindingRule" -Context $Context -Rule $Rule)
                # A rule whose own data is missing (for example access drift) is skipped with the reason.
                $Skip = $Instances.Where({ $null -ne $_ -and $null -ne $_.PSObject.Properties['SkipReason'] -and $_.SkipReason }, 'First') | Select-Object -First 1
                if ($null -ne $Skip) {
                    $Status = 'Skipped'
                    $Reason = $Skip.SkipReason
                    # A skip reason of the evaluator is missing data, unless the rule says nothing applies (SkipCode).
                    $ReasonCode = if ($null -ne $Skip.PSObject.Properties['SkipCode'] -and $Skip.SkipCode) { "$($Skip.SkipCode)" } else { 'MissingData' }
                } else {
                    $Evaluation = ConvertTo-EntraOpsFindingEvaluation -Rule $Rule -Instance $Instances
                    $Results = @($Evaluation.Results)
                    $UnclassifiedResults = @($Evaluation.UnclassifiedResults)
                    if ($RuleExceptions.Count -gt 0) {
                        $Accepted = Split-EntraOpsFindingResultByException -Results $Results -Exceptions $RuleExceptions
                        $Results = @($Accepted.Results)
                        $AcceptedResults = @($Accepted.AcceptedResults)
                        $Matched = $Accepted.MatchedCount
                    }
                    $EvaluatedCount = $Evaluation.EvaluatedCount
                    # A note of the evaluated instances (for example data the rule could not evaluate) is the reason of
                    # a Failed or Passed result, so a pass that is not complete says so.
                    $Notes = [System.Collections.Generic.List[string]]::new()
                    foreach ($Text in @($Instances | Where-Object { $null -ne $_ -and $null -ne $_.PSObject.Properties['Note'] -and $_.Note } | ForEach-Object { "$($_.Note)" } | Select-Object -Unique)) { $Notes.Add($Text) }
                    # A PIM setting that fails for every evaluated role is usually still Microsoft's default (inferred, not
                    # checked). Each role has its own policy, so the fix is a change of every role's policy, best scripted.
                    if ($Results.Count -gt 1 -and $Results.Count -eq $EvaluatedCount -and $Rule.Key -cin $script:EntraOpsTenantWideRoleSettingKeys) {
                        $Notes.Add("All $EvaluatedCount evaluated roles fail this check, so the setting was probably never changed from Microsoft's default. PIM keeps one policy per role: change it on every role, for example with a Microsoft Graph PowerShell script that updates the rule of each role's policy (Get-MgPolicyRoleManagementPolicyAssignment, Update-MgPolicyRoleManagementPolicyRule).")
                    }
                    $Note = $Notes -join ' '
                    if ($Results.Count -gt 0) {
                        $Status = 'Failed'
                        if ($Note) { $Reason = $Note; $ReasonCode = 'Note' }
                    } elseif ($UnclassifiedResults.Count -gt 0) {
                        $Status = 'Skipped'
                        $ReasonCode = 'Unclassified'
                        $Reason = Get-EntraOpsFindingUnclassifiedReason -Rule $Rule -UnclassifiedResults $UnclassifiedResults
                    } elseif ($EvaluatedCount -gt 0) {
                        $Status = 'Passed'
                        if ($Note) { $Reason = $Note; $ReasonCode = 'Note' }
                    } else {
                        $Status = 'Skipped'
                        $ReasonCode = 'NotApplicable'
                        $Reason = "No $(Get-EntraOpsFindingScopeName -ResourceType $Rule.ResourceType) in the scope of this rule (0 evaluated)."
                        if ($Note) { $Reason += " $Note" }
                    }
                }
            } catch {
                # A rule that cannot be evaluated returns the error; the other rules are evaluated.
                Write-Warning "Finding rule $($Rule.Id) ($($Rule.Area).$($Rule.Key)) could not be evaluated: $($_.Exception.Message)"
                $Status = 'Error'
                $ReasonCode = 'Error'
                $Reason = "The rule could not be evaluated: $($_.Exception.Message)"
                $Results = @()
                $UnclassifiedResults = @()
                $AcceptedResults = @()
                $Matched = @{}
                $EvaluatedCount = 0
            }
        }
        $Evaluated = $Status -in @('Failed', 'Passed') -or ($Status -eq 'Skipped' -and $EvaluatedCount -gt 0)
        $ExceptionStatus = @($RuleExceptions | ForEach-Object {
                $Count = if ($Matched.ContainsKey($_.Key)) { $Matched[$_.Key] } else { 0 }
                $Record = [ordered]@{}
                foreach ($Property in $_.PSObject.Properties) { if ($Property.Name -ne 'Expired') { $Record[$Property.Name] = $Property.Value } }
                $Record.Status = if (-not $Evaluated) { 'NotEvaluated' } elseif ($_.Expired) { 'Expired' } elseif ($Count -gt 0) { 'Active' } else { 'Stale' }
                $Record.MatchedCount = $Count
                [pscustomobject]$Record
            })

        [pscustomobject]@{
            PSTypeName            = 'EntraOps.FindingRuleResult'
            RuleId                = $Rule.Id
            Key                   = $Rule.Key
            Area                  = $Rule.Area
            Category              = $Rule.Category
            CategoryTitle         = $Rule.CategoryTitle
            CategoryNumber        = $Rule.CategoryNumber
            Title                 = $Rule.Title
            CheckTitle            = $Rule.CheckTitle
            Description           = $Rule.Description
            Remediation           = $Rule.Remediation
            Effort                = $Rule.Effort
            EffortDescription     = $Rule.EffortDescription
            UserImpact            = $Rule.UserImpact
            UserImpactDescription = $Rule.UserImpactDescription
            Severity              = $Rule.Severity
            Investigate           = [bool]$Rule.Investigate
            ReportSeverity        = $Rule.ReportSeverity
            MaesterTestId         = $Rule.MaesterTestId
            References            = @($Rule.References)
            Status                = $Status
            Reason                = $Reason
            ReasonCode            = $ReasonCode
            Parameters            = $ParameterValues
            EvaluatedCount        = $EvaluatedCount
            FailedCount           = $Results.Count
            Results               = $Results
            UnclassifiedCount     = $UnclassifiedResults.Count
            UnclassifiedResults   = $UnclassifiedResults
            AcceptedCount         = $AcceptedResults.Count
            AcceptedResults       = $AcceptedResults
            Exceptions            = $ExceptionStatus
        }
    }
}

function Split-EntraOpsFindingResultByException {
    <#
    .SYNOPSIS
        Splits the results of a rule into the reported and the accepted results by its finding exceptions.
    .DESCRIPTION
        An exception with InstanceId matches the result of this instance, one without InstanceId all results
        of its ObjectId. A result is accepted by any matching exception that has not expired (an instance
        exception is taken first when both are active), so an object exception still accepts a result whose own
        instance exception expired. Results of an exception that has not expired are accepted: their Status becomes the State of the exception (RiskAccepted or Dismissed)
        and Exception holds it. Expired exceptions accept nothing; MatchedCount counts the results of every
        exception by its Key, also of expired ones.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [AllowEmptyCollection()]
        [object[]]$Results = @(),

        [Parameter(Mandatory = $true)]
        [object[]]$Exceptions
    )

    $ByInstance = @{}
    $ByObject = @{}
    foreach ($Exception in $Exceptions) {
        if ($Exception.InstanceId) { $ByInstance[$Exception.InstanceId.ToLowerInvariant()] = $Exception }
        else { $ByObject[$Exception.ObjectId.ToLowerInvariant()] = $Exception }
    }
    $Reported = [System.Collections.Generic.List[object]]::new()
    $Accepted = [System.Collections.Generic.List[object]]::new()
    $MatchedCount = @{}
    foreach ($Result in $Results) {
        $Candidates = @(
            $ByInstance["$($Result.Instance.Id)".ToLowerInvariant()]
            if ($Result.Instance.ObjectId) { $ByObject["$($Result.Instance.ObjectId)".ToLowerInvariant()] }
        ) | Where-Object { $null -ne $_ }
        foreach ($Candidate in $Candidates) { $MatchedCount[$Candidate.Key] = 1 + $(if ($MatchedCount.ContainsKey($Candidate.Key)) { $MatchedCount[$Candidate.Key] } else { 0 }) }
        $Exception = $Candidates | Where-Object { -not $_.Expired } | Select-Object -First 1
        if ($null -eq $Exception) { $Reported.Add($Result); continue }
        $Result.Status = $Exception.State
        $Result | Add-Member -NotePropertyName Exception -NotePropertyValue ([pscustomobject][ordered]@{
                Key           = $Exception.Key
                State         = $Exception.State
                Justification = $Exception.Justification
                AcceptedBy    = $Exception.AcceptedBy
                AcceptedOn    = $Exception.AcceptedOn
                ExpiresOn     = $Exception.ExpiresOn
                Reference     = $Exception.Reference
            }) -Force
        $Accepted.Add($Result)
    }
    [pscustomobject]@{ Results = $Reported; AcceptedResults = $Accepted; MatchedCount = $MatchedCount }
}

function Get-EntraOpsFindingUnclassifiedReason {
    <#
    .SYNOPSIS
        Reason of a rule that is skipped because only unclassified objects failed it.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param (
        [Parameter(Mandatory = $true)]
        [object]$Rule,

        [Parameter(Mandatory = $true)]
        [object[]]$UnclassifiedResults
    )

    $ObjectCount = @($UnclassifiedResults | ForEach-Object { if ($_.Instance.ObjectId) { $_.Instance.ObjectId } else { $_.Instance.Id } } | Select-Object -Unique).Count
    $InstanceText = if ($UnclassifiedResults.Count -ne $ObjectCount) { " with $($UnclassifiedResults.Count) affected $(Get-EntraOpsFindingScopeName -ResourceType $Rule.ResourceType)" } else { '' }
    "Only unclassified objects are affected: $ObjectCount unclassified object(s)$InstanceText. Classify these objects (EO.2001) to evaluate this check: their tier is unknown, so they are not reported as findings."
}

function Get-EntraOpsFindingScopeName {
    <#
    .SYNOPSIS
        Names the instances of a rule by its resource type (plural), for the reason of a skipped rule.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param (
        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string]$ResourceType
    )

    $Names = @{
        AccessPackage           = 'access packages'
        AdministrativeUnit      = 'administrative units'
        Agent                   = 'agent identities'
        ConditionalAccessPolicy = 'Conditional Access policies'
        DirectoryRole           = 'directory roles'
        Group                   = 'groups'
        PrivilegedObject        = 'privileged objects'
        RoleAssignment          = 'role assignments'
        RoleDefinition          = 'role definitions'
        ServicePrincipal        = 'service principals'
        Tenant                  = 'tenant data'
        User                    = 'users'
    }
    if ($Names.ContainsKey($ResourceType)) { return $Names[$ResourceType] }
    return 'instances'
}

function Join-EntraOpsFindingName {
    <#
    .SYNOPSIS
        Lists names for the note of a rule: the first names, then "and N more".
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param (
        [Parameter(Mandatory = $false)]
        [AllowEmptyCollection()]
        [string[]]$Name = @(),

        [Parameter(Mandatory = $false)]
        [int]$First = 5
    )

    "$(@($Name | Select-Object -First $First) -join ', ')$(if ($Name.Count -gt $First) { " and $($Name.Count - $First) more" })"
}
