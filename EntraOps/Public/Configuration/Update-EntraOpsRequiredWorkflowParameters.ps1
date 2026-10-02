<#
.SYNOPSIS
    Update workflow definitions for GitHub actions with required environment values for EntraOps automation from config file.

.DESCRIPTION
    Update workflow definitions for GitHub actions with required environment values for EntraOps automation from config file.

.PARAMETER WorkflowFolderPath
    Folder where the workflow files are stored. Default is "./.github/workflows".

.PARAMETER ConfigFile
    Location of the config file which will be used to update the workflow files. Default is "./EntraOpsConfig.json".

.EXAMPLE
    Update all workflows in default location (/.github/workflows) with values from config file:
    Update-EntraOpsRequiredWorkflowParameters -ConfigFile "./EntraOps.config"
 #>

function Update-EntraOpsRequiredWorkflowParameters {

    [CmdletBinding()]
    param (
        [parameter(Mandatory = $false)]
        [ValidateScript({ Test-Path $_ })]
        [string]$WorkflowFolderPath = "./.github/workflows",

        [Parameter(Mandatory = $false)]
        [ValidateScript({ Test-Path $_ })]
        [string]$ConfigFile = "./EntraOpsConfig.json"
    )

    # Get all workflow files and content
    Write-Verbose -Message "Reading all workflow files from $WorkflowFolderPath"
    $Workflows = Get-ChildItem -Path $WorkflowFolderPath -Filter "*.yaml" -Recurse
    $Config = Get-Content -Path $ConfigFile | ConvertFrom-Json

    # Validate update policy before writing any workflow so a malformed configuration cannot leave a
    # partially materialized workflow set behind.
    $ValidationFrequency = [string]$Config.AutomatedEntraOpsUpdate.ValidationFrequency
    if ([string]::IsNullOrWhiteSpace($ValidationFrequency)) {
        $ValidationFrequency = 'OnChange'
    }
    if ($ValidationFrequency -notin @('OnChange', 'Always', 'Never')) {
        throw "Unsupported AutomatedEntraOpsUpdate.ValidationFrequency '$ValidationFrequency'. Use OnChange, Always, or Never."
    }
    $ConfiguredRunBrowserTests = $Config.AutomatedEntraOpsUpdate.RunBrowserTests
    $RunBrowserTests = if ($null -eq $ConfiguredRunBrowserTests) {
        $true
    } elseif ($ConfiguredRunBrowserTests -isnot [bool]) {
        throw 'AutomatedEntraOpsUpdate.RunBrowserTests must be a JSON boolean (true or false).'
    } else {
        $ConfiguredRunBrowserTests
    }
    $PublicationMode = [string]$Config.AutomatedEntraOpsUpdate.PublicationMode
    if ([string]::IsNullOrWhiteSpace($PublicationMode)) {
        $PublicationMode = 'PullRequest'
    }
    if ($PublicationMode -notin @('PullRequest', 'DirectPush')) {
        throw "Unsupported AutomatedEntraOpsUpdate.PublicationMode '$PublicationMode'. Use PullRequest or DirectPush."
    }

    # Only the deployment workflows carry tenant parameters. CI workflows such as Test-EntraOps.yaml
    # have no "env" block and must not be rewritten with tenant values.
    $DeploymentWorkflowNames = @(
        "Pull-EntraOpsPrivilegedEAM.yaml"
        "Pull-EntraOpsTenantGovernance.yaml"
        "Push-EntraOpsPrivilegedEAM.yaml"
        "Push-EntraOpsPrivilegedReporting.yaml"
        "Update-EntraOps.yaml"
    )
    $DeploymentWorkflows = @($Workflows | Where-Object { $_.Name -in $DeploymentWorkflowNames })
    $MissingWorkflowNames = @($DeploymentWorkflowNames | Where-Object { $_ -notin $DeploymentWorkflows.Name })
    if ($MissingWorkflowNames.Count -gt 0) {
        Write-Warning "The following expected EntraOps workflow file(s) were not found in $($WorkflowFolderPath): $($MissingWorkflowNames -join ', '). Their parameters cannot be updated."
    }

    # powershell-yaml does not preserve comments. Capture immutable action version annotations once
    # and restore them after every serialization so configuration updates do not invalidate the
    # repository's GitHub Action reference policy.
    $ActionVersionByReference = @{}
    foreach ($Workflow in $Workflows) {
        $WorkflowText = Get-Content -LiteralPath $Workflow.FullName -Raw
        foreach ($Match in [regex]::Matches(
                $WorkflowText,
                '(?m)^\s*(?:-\s*)?uses:\s*(?<Reference>[^\s#]+)\s+#\s*(?<Version>v\d+(?:\.\d+){0,2})\s*$')) {
            $ActionVersionByReference[$Match.Groups['Reference'].Value] = $Match.Groups['Version'].Value
        }
    }

    function ConvertTo-EntraOpsWorkflowYaml {
        param (
            [Parameter(Mandatory = $true)]
            [object]$WorkflowObject
        )

        $Yaml = ($WorkflowObject | ConvertTo-Yaml).Replace('"on"', 'on')
        foreach ($Reference in $ActionVersionByReference.Keys) {
            $Pattern = '(?m)^(?<Use>\s*(?:-\s*)?uses:\s*' + [regex]::Escape($Reference) + ')\s*$'
            $Replacement = '${Use} # ' + $ActionVersionByReference[$Reference]
            $Yaml = [regex]::Replace($Yaml, $Pattern, $Replacement)
        }
        return $Yaml
    }

    # Check if required module is available
    Write-Verbose -Message "Checking if powershell-yaml module is available"
    Install-EntraOpsRequiredModule -ModuleName powershell-yaml

    #region Update all Workflows with default values
    Write-Verbose -Message "Updating all workflows with default values"
    foreach ($Workflow in $DeploymentWorkflows) {
        try {
            $WorkflowContent = Get-Content -Path $workflow.FullName | ConvertFrom-Yaml -Ordered

            # Set Parameters
            $WorkflowContent.env.ClientId = $Config.ClientId
            $WorkflowContent.env.AuthenticationType = $Config.AuthenticationType
            $WorkflowContent.env.TenantId = $Config.TenantId
            $WorkflowContent.env.TenantName = $Config.TenantName
            $WorkflowContent.env.ConfigFile = $ConfigFile
            $UpdatedWorkflowContent = ConvertTo-EntraOpsWorkflowYaml -WorkflowObject $WorkflowContent
            $UpdatedWorkflowContent | Set-Content -Path $workflow.FullName
        } catch {
            Write-Error "Failed to update workflow $($workflow.FullName). Error: $_"
        }

    }
    #endregion

    #region Set specific parameters for push pipeline
    Write-Verbose -Message "Updating specific parameters for push pipeline"
    $PushWorkflow = $Workflows | Where-Object { $_.Name -eq "Push-EntraOpsPrivilegedEAM.yaml" }
    $PushWorkflowObject = Get-Content -Path $PushWorkflow.FullName | ConvertFrom-Yaml -Ordered

    # Always persist these values, including $false, so the workflow template never overrides config.
    $PushWorkflowObject.env.IngestToLogAnalytics = [bool]$Config.LogAnalytics.IngestToLogAnalytics
    $PushWorkflowObject.env.IngestToWatchLists = [bool]$Config.SentinelWatchLists.IngestToWatchLists
    $PushWorkflowObject.env.ApplyAdministrativeUnitAssignments = [bool]$Config.AutomatedAdministrativeUnitManagement.ApplyAdministrativeUnitAssignments
    $PushWorkflowObject.env.ApplyRmauAssignmentsForUnprotectedObjects = [bool]$Config.AutomatedRmauAssignmentsForUnprotectedObjects.ApplyRmauAssignmentsForUnprotectedObjects

    $PushWorkflowObject.env.ApplyPrivilegedElmCatalogProtection = [bool]$Config.AutomatedElmCatalogProtection.ApplyPrivilegedElmCatalogProtection
    
    $PushWorkflowObject.env.ApplyConditionalAccessTargetGroups = [bool]$Config.AutomatedConditionalAccessTargetGroups.ApplyConditionalAccessTargetGroups

    # Reconcile workflow_run so disabling and later re-enabling the trigger are both supported.
    if ($Config.WorkflowTrigger.PushAfterPullWorkflowTrigger -ne $false) {
        $PushWorkflowObject['on']['workflow_run'] = [ordered]@{
            workflows = @('Pull-EntraOpsPrivilegedEAM')
            types     = @('completed')
        }
    } elseif ($PushWorkflowObject['on'].Contains('workflow_run')) {
        $PushWorkflowObject.on.Remove('workflow_run')
    }

    # Save settings to workflow
    $UpdatedPushWorkflowContent = ConvertTo-EntraOpsWorkflowYaml -WorkflowObject $PushWorkflowObject
    $UpdatedPushWorkflowContent | Set-Content -Path $PushWorkflow.FullName
    #endregion

    #region Set specific parameters for reporting pipeline
    Write-Verbose -Message "Updating specific parameters for reporting pipeline"
    $ReportingWorkflow = $Workflows | Where-Object { $_.Name -eq "Push-EntraOpsPrivilegedReporting.yaml" }
    if ($ReportingWorkflow) {
        $ReportingWorkflowObject = Get-Content -Path $ReportingWorkflow.FullName | ConvertFrom-Yaml -Ordered

        # Always persist master/publication switches, including $false. Older configs did not expose
        # release publishing; keep that safely disabled until the operator opts in explicitly.
        $ReportingWorkflowObject.env.ApplyAutomatedReportingGeneration = [bool]$Config.AutomatedReportingGeneration.ApplyAutomatedReportingGeneration
        $ReportingWorkflowObject.env.PublishReportsAsRelease = if ($null -ne $Config.AutomatedReportingGeneration.PublishReportsAsRelease) {
            [bool]$Config.AutomatedReportingGeneration.PublishReportsAsRelease
        } else {
            $false
        }
        # An explicitly configured empty value keeps the workflow's "no pruning" mode; only a missing value falls back.
        $ReportingWorkflowObject.env.ReportingReleasesToKeep = if ($null -eq $Config.AutomatedReportingGeneration.ReportingReleasesToKeep) {
            '10'
        } else {
            [string]$Config.AutomatedReportingGeneration.ReportingReleasesToKeep
        }

        if ($null -ne $Config.AutomatedReportingGeneration.GenerateClassificationExplorer) {
            # Set GenerateClassificationExplorer Parameter
            $ReportingWorkflowObject.env.GenerateClassificationExplorer = $Config.AutomatedReportingGeneration.GenerateClassificationExplorer
        }

        if ($null -ne $Config.AutomatedReportingGeneration.GenerateTierBreachAnalyzer) {
            # Set GenerateTierBreachAnalyzer Parameter
            $ReportingWorkflowObject.env.GenerateTierBreachAnalyzer = $Config.AutomatedReportingGeneration.GenerateTierBreachAnalyzer
        }

        if ($null -ne $Config.AutomatedReportingGeneration.GenerateEamDashboard) {
            # Set GenerateEamDashboard Parameter
            $ReportingWorkflowObject.env.GenerateEamDashboard = $Config.AutomatedReportingGeneration.GenerateEamDashboard
        }

        $ReportingWorkflowObject.env.GeneratePrivilegedAssets = $Config.AutomatedReportingGeneration.GeneratePrivilegedAssets -ne $false
        $ReportingWorkflowObject.env.PrivilegedAssetsResolveRelatedObjectIds = $Config.PrivilegedAssets.ResolveRelatedObjectIds -ne $false

        if ($null -ne $Config.AutomatedReportingGeneration.GenerateAccessPathMap) {
            # Set GenerateAccessPathMap Parameter
            $ReportingWorkflowObject.env.GenerateAccessPathMap = $Config.AutomatedReportingGeneration.GenerateAccessPathMap
        }

        if ($null -ne $Config.AutomatedReportingGeneration.GenerateConfigurationAnalyzer) {
            # Set GenerateConfigurationAnalyzer Parameter
            $ReportingWorkflowObject.env.GenerateConfigurationAnalyzer = $Config.AutomatedReportingGeneration.GenerateConfigurationAnalyzer
        }

        if ($null -ne $Config.AutomatedReportingGeneration.GenerateAccessPackageFlow) {
            # Set GenerateAccessPackageFlow Parameter
            $ReportingWorkflowObject.env.GenerateAccessPackageFlow = $Config.AutomatedReportingGeneration.GenerateAccessPackageFlow
        }

        if ($null -ne $Config.AutomatedReportingGeneration.GeneratePrivilegeHistory) {
            # Set GeneratePrivilegeHistory Parameter
            $ReportingWorkflowObject.env.GeneratePrivilegeHistory = $Config.AutomatedReportingGeneration.GeneratePrivilegeHistory
        }

        $PrivilegeHistoryEnabled = if ($null -ne $Config.PrivilegeHistory.EnablePrivilegeHistory) {
            [bool]$Config.PrivilegeHistory.EnablePrivilegeHistory
        } else {
            $true
        }
        $ReportingWorkflowObject.env.EnablePrivilegeHistory = $PrivilegeHistoryEnabled
        $ReportingWorkflowObject.env.PrivilegeHistoryTimeRangeInDays = if ($null -ne $Config.PrivilegeHistory.TimeRangeInDays) {
            [string]$Config.PrivilegeHistory.TimeRangeInDays
        } else {
            ''
        }
        $ReportingWorkflowObject.env.PrivilegeHistorySnapshotInterval = if (-not [string]::IsNullOrWhiteSpace($Config.PrivilegeHistory.SnapshotInterval)) {
            [string]$Config.PrivilegeHistory.SnapshotInterval
        } else {
            'P2W'
        }

        if ($null -ne $Config.AccessPathMap.ResolveObjectIdsOutsidePrivilegedEAM) {
            # Set AccessPathMapResolveObjectIdsOutsidePrivilegedEAM Parameter
            $ReportingWorkflowObject.env.AccessPathMapResolveObjectIdsOutsidePrivilegedEAM = $Config.AccessPathMap.ResolveObjectIdsOutsidePrivilegedEAM
        }

        $AllowPartialTenantGovernanceSnapshot = if ($null -ne $Config.ConfigurationAnalyzer.AllowPartialTenantGovernanceSnapshot) {
            [bool]$Config.ConfigurationAnalyzer.AllowPartialTenantGovernanceSnapshot
        } else {
            $true
        }
        $ReportingWorkflowObject.env.AllowPartialTenantGovernanceSnapshot = $AllowPartialTenantGovernanceSnapshot
        $ReportingWorkflowObject.on.workflow_dispatch.inputs.allowPartialTenantGovernance.default = $AllowPartialTenantGovernanceSnapshot

        if ($Config.AutomatedReportingGeneration.ClassificationExplorerRepository) {
            # Set ClassificationExplorerRepository Parameter
            $ReportingWorkflowObject.env.ClassificationExplorerRepository = $Config.AutomatedReportingGeneration.ClassificationExplorerRepository
        }

        # Only checkout depth depends on this workflow value; the generator reads the same positive
        # config setting directly and keeps its explicit -SkipHistory switch as an invocation override.
        $ReportingWorkflowObject.env.ClassificationExplorerGenerateChangeHistory = if ($null -ne $Config.ClassificationExplorer.GenerateChangeHistory) {
            [bool]$Config.ClassificationExplorer.GenerateChangeHistory
        } else {
            $false
        }

        # Reconcile workflow_run so disabling and later re-enabling the trigger are both supported.
        if ($Config.WorkflowTrigger.PushReportingAfterPullWorkflowTrigger -ne $false) {
            $ReportingWorkflowObject['on']['workflow_run'] = [ordered]@{
                workflows = @('Pull-EntraOpsPrivilegedEAM')
                types     = @('completed')
            }
        } elseif ($ReportingWorkflowObject['on'].Contains('workflow_run')) {
            $ReportingWorkflowObject.on.Remove('workflow_run')
        }

        # Reconcile the schedule trigger on the parsed object. String replacement of the placeholder is
        # one-way: once the schedule block is removed, re-enabling the trigger could never restore it.
        $DefaultReportingSchedule = $Config.WorkflowTrigger.PushReportingScheduledCron # By default weekly, every Monday at 09:00 UTC
        if ($Config.WorkflowTrigger.PushReportingScheduledTrigger -eq $true) {
            $ReportingWorkflowObject['on']['schedule'] = @([ordered]@{ cron = $DefaultReportingSchedule })
        } elseif ($ReportingWorkflowObject['on'].Contains('schedule')) {
            $ReportingWorkflowObject['on'].Remove('schedule')
        }

        # Save settings to workflow
        $UpdatedReportingWorkflowContent = ConvertTo-EntraOpsWorkflowYaml -WorkflowObject $ReportingWorkflowObject
        $UpdatedReportingWorkflowContent | Set-Content -Path $ReportingWorkflow.FullName
    }
    #endregion

    #region Set specific parameters for pull pipeline
    Write-Verbose -Message "Updating specific parameters for pull pipeline"
    $PullWorkflow = $Workflows | Where-Object { $_.Name -eq "Pull-EntraOpsPrivilegedEAM.yaml" }
    $PullWorkflowObject = Get-Content -Path $PullWorkflow.FullName | ConvertFrom-Yaml -Ordered

    if ($Config.AutomatedControlPlaneScopeUpdate.ApplyAutomatedControlPlaneScopeUpdate) {
        # Set ApplyAutomatedControlPlaneScopeUpdate Parameter
        $PullWorkflowObject.env.ApplyAutomatedControlPlaneScopeUpdate = $Config.AutomatedControlPlaneScopeUpdate.ApplyAutomatedControlPlaneScopeUpdate
    } else {
        $PullWorkflowObject.env.ApplyAutomatedControlPlaneScopeUpdate = $false
    }

    if ($Config.AutomatedClassificationUpdate.ApplyAutomatedClassificationUpdate) {
        # Set ApplyAutomatedClassificationUpdate Parameter
        $PullWorkflowObject.env.ApplyAutomatedClassificationUpdate = $Config.AutomatedClassificationUpdate.ApplyAutomatedClassificationUpdate
    } else {
        $PullWorkflowObject.env.ApplyAutomatedClassificationUpdate = $false
    }

    if ($Config.GeneratedArtifactValidation.FailOnContradictoryTierPair) {
        $PullWorkflowObject.env.FailOnContradictoryTierPair = $Config.GeneratedArtifactValidation.FailOnContradictoryTierPair
    } else {
        $PullWorkflowObject.env.FailOnContradictoryTierPair = $false
    }
    if ($Config.GeneratedArtifactValidation.FailOnPrivilegedAssignmentWithoutClassification) {
        $PullWorkflowObject.env.FailOnPrivilegedAssignmentWithoutClassification = $Config.GeneratedArtifactValidation.FailOnPrivilegedAssignmentWithoutClassification
    } else {
        $PullWorkflowObject.env.FailOnPrivilegedAssignmentWithoutClassification = $false
    }

    # Reconcile the schedule trigger on the parsed object so it can be disabled and re-enabled.
    $DefaultPullSchedule = $config.WorkflowTrigger.PullScheduledCron # By default every day at 10:00 UTC
    if ($config.WorkflowTrigger.PullScheduledTrigger -eq $true) {
        $PullWorkflowObject['on']['schedule'] = @([ordered]@{ cron = $DefaultPullSchedule })
    } elseif ($PullWorkflowObject['on'].Contains('schedule')) {
        $PullWorkflowObject['on'].Remove('schedule')
    }

    # Save settings to workflow
    $UpdatedPullWorkflowContent = ConvertTo-EntraOpsWorkflowYaml -WorkflowObject $PullWorkflowObject
    $UpdatedPullWorkflowContent | Set-Content -Path $PullWorkflow.FullName
    #endregion

    #region Set specific parameters for update pipeline
    Write-Verbose -Message "Updating specific parameters for update pipeline"
    $UpdateWorkflow = $Workflows | Where-Object { $_.Name -eq "Update-EntraOps.yaml" }
    $UpdateWorkflowObject = Get-Content -Path $UpdateWorkflow.FullName | ConvertFrom-Yaml -Ordered

    if ($Config.AutomatedEntraOpsUpdate.ApplyAutomatedEntraOpsUpdate) {
        # Set ApplyAutomatedEntraOpsUpdate Parameter
        $UpdateWorkflowObject.env.ApplyAutomatedEntraOpsUpdate = $Config.AutomatedEntraOpsUpdate.ApplyAutomatedEntraOpsUpdate
    } else {
        $UpdateWorkflowObject.env.ApplyAutomatedEntraOpsUpdate = $false
    }

    $UpdateWorkflowObject.env.ValidationFrequency = $ValidationFrequency
    $UpdateWorkflowObject.env.RunBrowserTests = $RunBrowserTests
    $UpdateWorkflowObject.env.PublicationMode = $PublicationMode
    if ($Config.AutomatedEntraOpsUpdate.ApplyAutomatedEntraOpsUpdate -eq $true -and $PublicationMode -eq 'PullRequest') {
        Write-Warning "AutomatedEntraOpsUpdate publishes through pull requests. Enable 'Allow GitHub Actions to create and approve pull requests' under Settings > Actions > General > Workflow permissions of the repository (or organization), otherwise the Update-EntraOps workflow cannot open the review pull request. See https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/enabling-features-for-your-repository/managing-github-actions-settings-for-a-repository#preventing-github-actions-from-creating-or-approving-pull-requests"
    }
    if ($Config.AutomatedEntraOpsUpdate.ApplyAutomatedEntraOpsUpdate -eq $true -and
        @($Config.AutomatedEntraOpsUpdate.TargetUpdateFolders) -contains './.github/workflows') {
        Write-Warning "Automated workflow-template updates require a dedicated GitHub App installed on this repository with Contents, Workflows, Pull requests, and Commit statuses write permissions. Configure its client ID as the EntraOpsUpdateAppClientId repository variable and its private key as the EntraOpsUpdateAppPrivateKey repository secret. GITHUB_TOKEN cannot publish .github/workflows changes."
    }
    if ($Config.AutomatedEntraOpsUpdate.ApplyAutomatedEntraOpsUpdate -eq $true -and [string]$Config.AutomatedEntraOpsUpdate.Repository -eq 'EntraOps-Insiders') {
        Write-Warning "AutomatedEntraOpsUpdate.Repository is the private 'EntraOps-Insiders' channel. The Update-EntraOps workflow requires the 'EntraOpsUpdatePat' repository secret to clone it; the public 'EntraOps' release repository needs no secret."
    }

    # Reconcile the schedule trigger on the parsed object so it can be disabled and re-enabled.
    $DefaultUpdateSchedule = $config.AutomatedEntraOpsUpdate.UpdateScheduledCron # By default Wednesday at 9:00 UTC
    if ($config.AutomatedEntraOpsUpdate.UpdateScheduledTrigger -eq $true) {
        $UpdateWorkflowObject['on']['schedule'] = @([ordered]@{ cron = $DefaultUpdateSchedule })
    } elseif ($UpdateWorkflowObject['on'].Contains('schedule')) {
        $UpdateWorkflowObject['on'].Remove('schedule')
    }

    # Save settings to workflow
    $UpdatedUpdateWorkflowContent = ConvertTo-EntraOpsWorkflowYaml -WorkflowObject $UpdateWorkflowObject
    $UpdatedUpdateWorkflowContent | Set-Content -Path $UpdateWorkflow.FullName
    #endregion

    #region Set specific parameters for tenant governance pull pipeline
    Write-Verbose -Message "Updating specific parameters for tenant governance pull pipeline"
    $TenantGovernanceWorkflow = $Workflows | Where-Object { $_.Name -eq "Pull-EntraOpsTenantGovernance.yaml" }
    if ($TenantGovernanceWorkflow) {
        $TenantGovernanceWorkflowObject = Get-Content -Path $TenantGovernanceWorkflow.FullName | ConvertFrom-Yaml -Ordered

        if ($null -ne $Config.TenantGovernanceSnapshot.EnableTenantGovernanceSnapshot) {
            # Set EnableTenantGovernanceSnapshot Parameter
            $TenantGovernanceWorkflowObject.env.EnableTenantGovernanceSnapshot = $Config.TenantGovernanceSnapshot.EnableTenantGovernanceSnapshot
        } else {
            $TenantGovernanceWorkflowObject.env.EnableTenantGovernanceSnapshot = $false
        }

        # Set the start and one-shot collection schedules. SnapshotScheduledCronComplete is retained
        # as the primary collector setting for compatibility with existing configuration files.
        $DefaultTenantGovernanceStartSchedule = $Config.TenantGovernanceSnapshot.SnapshotScheduledCron # By default daily at 06:00 UTC
        $DefaultTenantGovernanceCompleteSchedule = if ($Config.TenantGovernanceSnapshot.SnapshotScheduledCronComplete) { $Config.TenantGovernanceSnapshot.SnapshotScheduledCronComplete } else { "0 7 * * *" } # By default daily at 07:00 UTC
        $DefaultTenantGovernanceCompleteRetry1Schedule = if ($Config.TenantGovernanceSnapshot.SnapshotScheduledCronCompleteRetry1) { $Config.TenantGovernanceSnapshot.SnapshotScheduledCronCompleteRetry1 } else { "30 7 * * *" }
        $DefaultTenantGovernanceCompleteRetry2Schedule = if ($Config.TenantGovernanceSnapshot.SnapshotScheduledCronCompleteRetry2) { $Config.TenantGovernanceSnapshot.SnapshotScheduledCronCompleteRetry2 } else { "0 8 * * *" }

        $TenantGovernanceWorkflowObject.env.SnapshotStartCron = $DefaultTenantGovernanceStartSchedule
        if ($Config.TenantGovernanceSnapshot.EnableTenantGovernanceSnapshot -eq $true -and $Config.TenantGovernanceSnapshot.SnapshotScheduledTrigger -eq $true) {
            $TenantGovernanceWorkflowObject['on'].schedule = @(
                [ordered]@{ cron = $DefaultTenantGovernanceStartSchedule }
                [ordered]@{ cron = $DefaultTenantGovernanceCompleteSchedule }
                [ordered]@{ cron = $DefaultTenantGovernanceCompleteRetry1Schedule }
                [ordered]@{ cron = $DefaultTenantGovernanceCompleteRetry2Schedule }
            )
        } else {
            $TenantGovernanceWorkflowObject['on'].Remove('schedule')
        }

        # Save settings to workflow
        $UpdatedTenantGovernanceWorkflowContent = ConvertTo-EntraOpsWorkflowYaml -WorkflowObject $TenantGovernanceWorkflowObject
        $UpdatedTenantGovernanceWorkflowContent | Set-Content -Path $TenantGovernanceWorkflow.FullName
    }
    #endregion
}
