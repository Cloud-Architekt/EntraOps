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

    # Check if required module is available
    Write-Verbose -Message "Checking if powershell-yaml module is available"
    Install-EntraOpsRequiredModule -ModuleName powershell-yaml

    #region Update all Workflows with default values
    Write-Verbose -Message "Updating all workflows with default values"
    foreach ($Workflow in $Workflows) {
        try {
            $WorkflowContent = Get-Content -Path $workflow.FullName | ConvertFrom-Yaml -Ordered

            # Set Parameters
            $WorkflowContent.env.ClientId = $Config.ClientId
            $WorkflowContent.env.AuthenticationType = $Config.AuthenticationType
            $WorkflowContent.env.TenantId = $Config.TenantId
            $WorkflowContent.env.TenantName = $Config.TenantName
            $WorkflowContent.env.ConfigFile = $ConfigFile
            $UpdatedWorkflowContent = $WorkflowContent | ConvertTo-Yaml

            # Workaround for powershell-yaml which adds quotes to on/off values
            $UpdatedWorkflowContent.Replace('"on"', "on") | Set-Content -Path $workflow.FullName
        }
        catch {
            Write-Error "Failed to update workflow $($workflow.FullName). Error: $_"
        }

    }
    #endregion

    #region Set specific parameters for push pipeline
    Write-Verbose -Message "Updating specific parameters for push pipeline"
    $PushWorkflow = $Workflows | Where-Object { $_.Name -eq "Push-EntraOpsPrivilegedEAM.yaml" }
    $PushWorkflowObject = Get-Content -Path $PushWorkflow.FullName | ConvertFrom-Yaml -Ordered

    if ($Config.LogAnalytics.IngestToLogAnalytics) {
        # Set IngestToLogAnalytics Parameter
        $PushWorkflowObject.env.IngestToLogAnalytics = $Config.LogAnalytics.IngestToLogAnalytics
    }

    if ($Config.SentinelWatchLists.IngestToWatchLists) {
        # Set IngestToWatchLists Parameter
        $PushWorkflowObject.env.IngestToWatchLists = $Config.SentinelWatchLists.IngestToWatchLists
    }

    if ($Config.AutomatedAdministrativeUnitManagement.ApplyAdministrativeUnitAssignments) {
        # Set ApplyAdministrativeUnitAssignments Parameter
        $PushWorkflowObject.env.ApplyAdministrativeUnitAssignments = $Config.AutomatedAdministrativeUnitManagement.ApplyAdministrativeUnitAssignments
    }

    if ($Config.AutomatedRmauAssignmentsForUnprotectedObjects.ApplyRmauAssignmentsForUnprotectedObjects) {
        # Set ApplyRmauAssignmentsForUnprotectedObjects Parameter
        $PushWorkflowObject.env.ApplyRmauAssignmentsForUnprotectedObjects = $Config.AutomatedRmauAssignmentsForUnprotectedObjects.ApplyRmauAssignmentsForUnprotectedObjects
    }
    
    if ($Config.AutomatedConditionalAccessTargetGroups.ApplyConditionalAccessTargetGroups) {
        # Set ApplyConditionalAccessTargetGroups Parameter
        $PushWorkflowObject.env.ApplyConditionalAccessTargetGroups = $Config.AutomatedConditionalAccessTargetGroups.ApplyConditionalAccessTargetGroups
    }    

    # Remove workflow_run trigger if not configured in config file
    if ($config.WorkflowTrigger.PushAfterPullWorkflowTrigger -eq $false -and $PushWorkflowObject.on.'workflow_run'.workflows -eq 'Pull-EntraOpsPrivilegedEAM') {
        $PushWorkflowObject.on.Remove('workflow_run')
    }

    # Save settings to workflow
    $UpdatedPushWorkflowContent = $PushWorkflowObject | ConvertTo-Yaml

    # Workaround for powershell-yaml which adds quotes to on/off values
    $UpdatedPushWorkflowContent = $UpdatedPushWorkflowContent.Replace('"on"', "on")
    $UpdatedPushWorkflowContent | Set-Content -Path $PushWorkflow.FullName
    #endregion

    #region Set specific parameters for pull pipeline
    Write-Verbose -Message "Updating specific parameters for pull pipeline"
    $PullWorkflow = $Workflows | Where-Object { $_.Name -eq "Pull-EntraOpsPrivilegedEAM.yaml" }
    $PullWorkflowObject = Get-Content -Path $PullWorkflow.FullName | ConvertFrom-Yaml -Ordered

    if ($Config.AutomatedControlPlaneScopeUpdate.ApplyAutomatedControlPlaneScopeUpdate) {
        # Set ApplyAutomatedControlPlaneScopeUpdate Parameter
        $PullWorkflowObject.env.ApplyAutomatedControlPlaneScopeUpdate = $Config.AutomatedControlPlaneScopeUpdate.ApplyAutomatedControlPlaneScopeUpdate
    }
    else {
        $PullWorkflowObject.env.ApplyAutomatedControlPlaneScopeUpdate = $false
    }

    if ($Config.AutomatedClassificationUpdate.ApplyAutomatedClassificationUpdate) {
        # Set ApplyAutomatedClassificationUpdate Parameter
        $PullWorkflowObject.env.ApplyAutomatedClassificationUpdate = $Config.AutomatedClassificationUpdate.ApplyAutomatedClassificationUpdate
    }
    else {
        $PullWorkflowObject.env.ApplyAutomatedClassificationUpdate = $false
    }

    # Save settings to workflow
    $UpdatedPullWorkflowContent = $PullWorkflowObject | ConvertTo-Yaml

    # Set schedule for Pull pipelines if configured in environment file
    $DefaultPullSchedule = $config.WorkflowTrigger.PullScheduledCron # By default every day at 10:00 UTC
    if ($config.WorkflowTrigger.PullScheduledTrigger -eq $true) {
        $UpdatedPullWorkflowContent = $UpdatedPullWorkflowContent.Replace("YourCronSchedule", $DefaultPullSchedule)
    }
    elseif ($config.WorkflowTrigger.PullScheduledTrigger -eq $false) {
        if ($UpdatedPullWorkflowContent.Contains("YourCronSchedule") -eq $true) {
            $UpdatedPullWorkflowContent = $UpdatedPullWorkflowContent.Replace('  schedule:', '').Replace('  - cron: YourCronSchedule', '')
        }
        else {
            $UpdatedPullWorkflowContent = $UpdatedPullWorkflowContent.Replace('  schedule:', '').Replace("  - cron: $($DefaultPullSchedule)", '')
        }
    }

    # Workaround for powershell-yaml which adds quotes to on/off values
    $UpdatedPullWorkflowContent = $UpdatedPullWorkflowContent.Replace('"on"', "on")
    $UpdatedPullWorkflowContent | Set-Content -Path $PullWorkflow.FullName
    #endregion

    #region Set specific parameters for update pipeline
    Write-Verbose -Message "Updating specific parameters for update pipeline"
    $UpdateWorkflow = $Workflows | Where-Object { $_.Name -eq "Update-EntraOps.yaml" }
    $UpdateWorkflowObject = Get-Content -Path $UpdateWorkflow.FullName | ConvertFrom-Yaml -Ordered

    if ($Config.AutomatedEntraOpsUpdate.ApplyAutomatedEntraOpsUpdate) {
        # Set ApplyAutomatedEntraOpsUpdate Parameter
        $UpdateWorkflowObject.env.ApplyAutomatedEntraOpsUpdate = $Config.AutomatedEntraOpsUpdate.ApplyAutomatedEntraOpsUpdate
    }
    else {
        $UpdateWorkflowObject.env.ApplyAutomatedEntraOpsUpdate = $false
    }

    # Save settings to workflow
    $UpdatedUpdateWorkflowContent = $UpdateWorkflowObject | ConvertTo-Yaml

    # Set schedule for Pull pipelines if configured in environment file
    $DefaultPullSchedule = $config.AutomatedEntraOpsUpdate.UpdateScheduledCron # By default Wednesday at 9:00 UTC
    if ($config.AutomatedEntraOpsUpdate.UpdateScheduledTrigger -eq $true) {
        $UpdatedUpdateWorkflowContent = $UpdatedUpdateWorkflowContent.Replace("YourCronSchedule", $DefaultPullSchedule)
    }
    elseif ($config.AutomatedEntraOpsUpdate.UpdateScheduledTrigger -eq $false) {
        if ($UpdatedUpdateWorkflowContent.Contains("YourCronSchedule") -eq $true) {
            $UpdatedUpdateWorkflowContent = $UpdatedUpdateWorkflowContent.Replace('  schedule:', '').Replace('  - cron: YourCronSchedule', '')
        }
        else {
            $UpdatedUpdateWorkflowContent = $UpdatedUpdateWorkflowContent.Replace('  schedule:', '').Replace("  - cron: $($DefaultPullSchedule)", '')
        }
    }

    # Workaround for powershell-yaml which adds quotes to on/off values
    $UpdatedUpdateWorkflowContent = $UpdatedUpdateWorkflowContent.Replace('"on"', "on")
    $UpdatedUpdateWorkflowContent | Set-Content -Path $UpdateWorkflow.FullName
    #endregion
}