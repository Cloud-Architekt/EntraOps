function ConvertTo-EntraOpsFindingRuleSummary {
    <#
    .SYNOPSIS
        Converts a rule result to the rule summary of the report data (camelCase, without the results).
    .DESCRIPTION
        Shared by the report data generators (New-EntraOpsPrivilegedAssetsData, New-EntraOpsReportFindingData):
        the rule metadata the reports show (title, check title, description, remediation, effort and user
        impact, category with its title and number, severity and report severity, Maester test ID, references)
        and its evaluation (status, reason, evaluated, failed and accepted count).
    .PARAMETER RuleResult
        Rule result of Invoke-EntraOpsFindingRuleSet.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [object]$RuleResult
    )

    process {
        [ordered]@{
            id                    = $RuleResult.RuleId
            key                   = $RuleResult.Key
            title                 = $RuleResult.Title
            checkTitle            = $RuleResult.CheckTitle
            description           = $RuleResult.Description
            remediation           = $RuleResult.Remediation
            effort                = $RuleResult.Effort
            effortDescription     = $RuleResult.EffortDescription
            userImpact            = $RuleResult.UserImpact
            userImpactDescription = $RuleResult.UserImpactDescription
            category              = $RuleResult.Category
            categoryTitle         = $RuleResult.CategoryTitle
            categoryNumber        = $RuleResult.CategoryNumber
            severity              = $RuleResult.Severity
            reportSeverity        = $RuleResult.ReportSeverity
            maesterTestId         = $RuleResult.MaesterTestId
            references            = @(@($RuleResult.References) | Where-Object { $_ } | ForEach-Object { [ordered]@{ title = $_.Title; url = $_.Url; type = $_.Type } })
            status                = $RuleResult.Status
            reason                = $RuleResult.Reason
            reasonCode            = $(if ($null -ne $RuleResult.PSObject.Properties['ReasonCode']) { $RuleResult.ReasonCode } else { $null })
            evaluatedCount        = $RuleResult.EvaluatedCount
            failedCount           = $RuleResult.FailedCount
            acceptedCount         = [int]$RuleResult.AcceptedCount
        }
    }
}
