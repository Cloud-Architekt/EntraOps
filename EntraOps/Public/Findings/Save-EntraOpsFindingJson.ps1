<#
.SYNOPSIS
    Save the EntraOps finding results as JSON file.

.DESCRIPTION
    Writes the results of Invoke-EntraOpsFindingEvaluation to <ExportFolder>/findings.json, for example
    to read them with the EntraOps Maester Pack without running the evaluation again. Without pipeline
    input, all rules are evaluated with the defaults of Invoke-EntraOpsFindingEvaluation; an empty pipeline
    saves a file without rules.

    The default folder Reports/Findings/data is part of the generated report data: it is ignored by git,
    kept when the reporting apps are updated, removed by Remove-EntraOpsReportingData and published with
    the reports by the EntraOps reporting pipelines (artifact EntraOps-Reporting, Findings/data).
    New-EntraOpsReportingData saves the results there as part of the report generation.

    The file has a versioned schema (SchemaVersion) with the time of generation, the EntraOps version
    and the tenant, so a consumer can reject results of another tenant or results that are too old.
    Each rule has the Status of Invoke-EntraOpsFindingEvaluation (Failed, Passed, Skipped, Excluded or
    Error) with its Reason, and its category (Category, CategoryTitle, CategoryNumber). UnclassifiedCount
    and UnclassifiedResults hold the failed instances of unclassified objects, which are not results (see
    Invoke-EntraOpsFindingEvaluation); the reports show them on request. AcceptedCount and AcceptedResults
    hold the results accepted by a finding exception (Finding Exceptions File, Status RiskAccepted or
    Dismissed with the Exception), and Exceptions the exceptions of the rule with their status (Active,
    Expired, Stale or NotEvaluated). ExceptionSettings names the Finding Exceptions File and the longest time
    a risk can be accepted (Findings.ExceptionsFilePath and .ExceptionMaxDays of -ConfigFilePath), for the
    Privileged Assets Findings view, which exports the file.
    DataGaps lists the data gaps of the evaluation (DataGaps of the rule results, see Invoke-EntraOpsFindingEvaluation):
    data that is missing, so that rules evaluate less than they seem to, each with Code, Message, Count and the RuleIds
    of the saved rules it affects. The list is empty without gaps; files of earlier versions have no DataGaps.
    GlobalExclusions lists the principals of the Global Exclusion List (Classification/Global.json): the
    Privileged EAM collection leaves them out, so the results do not cover their privileged access.
    The file is written to a temporary file first and then moved into place. The same results are written
    to findings.js (window.ENTRAOPS_FINDINGS) for the reports, which load their data as scripts: Privileged
    Assets shows the findings of its objects from it.

.PARAMETER InputObject
    Rule results from Invoke-EntraOpsFindingEvaluation.

.PARAMETER ExportFolder
    Folder for findings.json. Defaults to <EntraOpsRoot>/Reports/Findings/data.

.PARAMETER TenantId
    Tenant ID written to the file. Defaults to the tenant of Connect-EntraOps, else the TenantId of
    EntraOpsConfig.json. The Maester Pack and the Privileged Assets report check it against their tenant, so a
    file without tenant ID is written with a warning.

.PARAMETER TenantName
    Tenant name written to the file. Defaults to the tenant of Connect-EntraOps or EntraOpsConfig.json.

.PARAMETER ConfigFilePath
    EntraOpsConfig.json with the settings of the Finding Exceptions File. Defaults to
    <EntraOpsRoot>/EntraOpsConfig.json.

.PARAMETER PassThru
    Emit the saved content to the pipeline.

.EXAMPLE
    Invoke-EntraOpsFindingEvaluation | Save-EntraOpsFindingJson

    Evaluates all rules and saves the results to <EntraOpsRoot>/Reports/Findings/data/findings.json.
#>

function Save-EntraOpsFindingJson {

    [CmdletBinding(SupportsShouldProcess = $true)]
    param (
        [Parameter(Mandatory = $false, ValueFromPipeline = $true)]
        [object[]]$InputObject,

        [Parameter(Mandatory = $false)]
        [System.String]$ExportFolder,

        [Parameter(Mandatory = $false)]
        [System.String]$TenantId,

        [Parameter(Mandatory = $false)]
        [System.String]$TenantName,

        [Parameter(Mandatory = $false)]
        [System.String]$ConfigFilePath,

        [Parameter(Mandatory = $false)]
        [switch]$PassThru
    )

    begin {
        $RuleResults = [System.Collections.Generic.List[object]]::new()
    }

    process {
        foreach ($Item in @($InputObject)) {
            if ($null -ne $Item) { $RuleResults.Add($Item) }
        }
    }

    end {
        $RepositoryRoot = (Get-EntraOpsFindingRoot).RepositoryRoot
        if ([string]::IsNullOrWhiteSpace($ExportFolder)) { $ExportFolder = Join-Path $RepositoryRoot 'Reports/Findings/data' }
        if ([string]::IsNullOrWhiteSpace($TenantId)) { $TenantId = "$(Get-Variable -Name TenantIdContext -Scope Global -ValueOnly -ErrorAction SilentlyContinue)" }
        if ([string]::IsNullOrWhiteSpace($TenantName)) { $TenantName = Get-EntraOpsReportingTenantName -RepoRoot $RepositoryRoot }
        if ([string]::IsNullOrWhiteSpace($ConfigFilePath)) { $ConfigFilePath = Join-Path $RepositoryRoot 'EntraOpsConfig.json' }
        # Without a connection (for example offline report generation), the tenant of EntraOpsConfig.json.
        if ([string]::IsNullOrWhiteSpace($TenantId) -and (Test-Path -LiteralPath $ConfigFilePath -PathType Leaf)) {
            try { $TenantId = "$((Get-Content -LiteralPath $ConfigFilePath -Raw | ConvertFrom-Json -ErrorAction Stop).TenantId)" } catch { Write-Verbose "No tenant ID read from $($ConfigFilePath): $($_.Exception.Message)" }
        }
        if ([string]::IsNullOrWhiteSpace($TenantId)) {
            Write-Warning "The finding results have no tenant ID (no Connect-EntraOps and no TenantId in $ConfigFilePath), so the Maester Pack and the Privileged Assets report cannot check that they belong to their tenant. Pass -TenantId or set TenantId in EntraOpsConfig.json."
        }
        # The evaluation reported the problems of the settings already.
        $ExceptionSetting = Get-EntraOpsFindingSetting -ConfigFilePath $ConfigFilePath -WarningAction SilentlyContinue

        # Without pipeline input, evaluate all rules; an empty pipeline (no rule selected) saves no rules.
        if ($RuleResults.Count -eq 0 -and -not $MyInvocation.ExpectingInput -and -not $PSBoundParameters.ContainsKey('InputObject')) {
            Write-Verbose "No rule results passed - evaluating the finding rules."
            foreach ($Item in @(Invoke-EntraOpsFindingEvaluation -ConfigFilePath $ConfigFilePath)) { $RuleResults.Add($Item) }
        }

        # The Global Exclusion List (Classification/Global.json): the Privileged EAM collection leaves these principals
        # out, so no finding rule covers their privileged access. The file names them, so that the reports and the
        # Maester Pack can say that the results do not cover them.
        $GlobalExclusionPath = Join-Path $RepositoryRoot 'Classification/Global.json'
        $GlobalExclusionIds = @(if (Test-Path -LiteralPath $GlobalExclusionPath -PathType Leaf) {
                try {
                    @((Get-Content -LiteralPath $GlobalExclusionPath -Raw | ConvertFrom-Json -Depth 10 -ErrorAction Stop).ExcludedPrincipalId) |
                        Where-Object { -not [string]::IsNullOrWhiteSpace("$_") } | ForEach-Object { "$_".Trim().ToLowerInvariant() } | Select-Object -Unique
                } catch { Write-Warning "The Global Exclusion List $GlobalExclusionPath could not be read: $($_.Exception.Message)" }
            })

        $DataGaps = [ordered]@{}
        foreach ($RuleResult in $RuleResults) {
            if ($null -eq $RuleResult.PSObject.Properties['DataGaps']) { continue }
            foreach ($Gap in @($RuleResult.DataGaps | Where-Object { $null -ne $_ -and "$($_.Code)" })) {
                if (-not $DataGaps.Contains("$($Gap.Code)")) {
                    $DataGaps["$($Gap.Code)"] = [ordered]@{ Code = "$($Gap.Code)"; Message = "$($Gap.Message)"; Count = $(if ($null -ne $Gap.Count) { [int]$Gap.Count } else { $null }); RuleIds = [System.Collections.Generic.List[string]]::new() }
                }
                if (-not $DataGaps["$($Gap.Code)"].RuleIds.Contains("$($RuleResult.RuleId)")) { $DataGaps["$($Gap.Code)"].RuleIds.Add("$($RuleResult.RuleId)") }
            }
        }

        $Content = [ordered]@{
            SchemaVersion     = '1.0'
            GeneratedAt       = (Get-Date -AsUTC).ToString('o')
            Generator         = [ordered]@{
                Name    = 'EntraOps'
                Version = "$(Get-EntraOpsModuleVersion)"
            }
            TenantId          = $TenantId
            TenantName        = $TenantName
            ExceptionSettings = [ordered]@{
                FilePath = $ExceptionSetting.ExceptionsFilePath
                MaxDays  = $ExceptionSetting.ExceptionMaxDays
            }
            GlobalExclusions  = [ordered]@{
                FilePath     = './Classification/Global.json'
                Count        = $GlobalExclusionIds.Count
                PrincipalIds = $GlobalExclusionIds
            }
            DataGaps          = @($DataGaps.Values | Sort-Object { $_.Code } | ForEach-Object { [ordered]@{ Code = $_.Code; Message = $_.Message; Count = $_.Count; RuleIds = @($_.RuleIds | Sort-Object) } })
            Rules             = @($RuleResults | ForEach-Object {
                    [ordered]@{
                        RuleId                = $_.RuleId
                        Key                   = $_.Key
                        Area                  = $_.Area
                        Category              = $_.Category
                        CategoryTitle         = $_.CategoryTitle
                        CategoryNumber        = $_.CategoryNumber
                        Title                 = $_.Title
                        CheckTitle            = $_.CheckTitle
                        Description           = $_.Description
                        Remediation           = $_.Remediation
                        Effort                = $_.Effort
                        EffortDescription     = $_.EffortDescription
                        UserImpact            = $_.UserImpact
                        UserImpactDescription = $_.UserImpactDescription
                        Severity              = $_.Severity
                        # The rule asks for a review of its results (the Maester Pack reports them as Investigate).
                        Investigate           = [bool]$_.Investigate
                        MaesterTestId         = $_.MaesterTestId
                        References            = @($_.References)
                        Status                = $_.Status
                        Reason                = $_.Reason
                        # NotApplicable, MissingData, Unclassified, Note, Excluded, Deprecated or Error (see Invoke-EntraOpsFindingRuleSet).
                        ReasonCode            = $(if ($null -ne $_.PSObject.Properties['ReasonCode']) { $_.ReasonCode } else { $null })
                        Parameters            = $_.Parameters
                        EvaluatedCount        = $_.EvaluatedCount
                        FailedCount           = $_.FailedCount
                        Results               = @($_.Results)
                        UnclassifiedCount     = [int]$_.UnclassifiedCount
                        UnclassifiedResults   = @($_.UnclassifiedResults)
                        AcceptedCount         = [int]$_.AcceptedCount
                        AcceptedResults       = @($_.AcceptedResults)
                        Exceptions            = @($_.Exceptions)
                    }
                })
        }

        $FilePath = Join-Path $ExportFolder 'findings.json'
        if ($PSCmdlet.ShouldProcess($FilePath, 'Save EntraOps finding results')) {
            if (-not (Test-Path -LiteralPath $ExportFolder)) {
                New-Item -ItemType Directory -Path $ExportFolder -Force | Out-Null
            }
            # Atomic swap: write to a temp file next to the target, then move it into place.
            $TempPath = "$FilePath.tmp"
            $Json = $Content | ConvertTo-Json -Depth 10
            $Json | Set-Content -LiteralPath $TempPath -Encoding UTF8
            Move-Item -LiteralPath $TempPath -Destination $FilePath -Force
            # The reports load their data as scripts (file:// pages can't read JSON files).
            Save-EntraOpsReportDataFile -LiteralPath (Join-Path $ExportFolder 'findings.js') -Content ("// Auto-generated by Save-EntraOpsFindingJson - do not edit by hand.`nwindow.ENTRAOPS_FINDINGS = " + ($Content | ConvertTo-Json -Depth 10 -Compress) + ";`n")
            $FailedRules = @($RuleResults | Where-Object Status -eq 'Failed').Count
            $SkippedRules = @($RuleResults | Where-Object Status -eq 'Skipped').Count
            $ErrorRules = @($RuleResults | Where-Object Status -eq 'Error').Count
            $AcceptedFindings = ($RuleResults | ForEach-Object { [int]$_.AcceptedCount } | Measure-Object -Sum).Sum
            $Exceptions = @($RuleResults | ForEach-Object { $_.Exceptions } | Where-Object { $_ })
            $StaleExceptions = @($Exceptions | Where-Object Status -eq 'Stale').Count
            Write-Host "Finding results: $($RuleResults.Count) rule(s), $FailedRules failed, $SkippedRules skipped$(if ($ErrorRules) { ", $ErrorRules with errors" })$(if ($AcceptedFindings) { ", $AcceptedFindings accepted finding(s)" }) - wrote $FilePath"
            if ($DataGaps.Count) { Write-Host "$($DataGaps.Count) data gap(s) limit the results (DataGaps of findings.json): $(@($DataGaps.Values | ForEach-Object { "$($_.Code) ($(@($_.RuleIds) -join ', '))" }) -join '; ')." }
            if ($StaleExceptions) { Write-Host "$StaleExceptions finding exception(s) match no finding anymore (Stale): remove them from $($ExceptionSetting.ExceptionsFilePath), for example in the Privileged Assets Findings view." }
        }

        if ($PassThru) { [pscustomobject]$Content }
    }
}
