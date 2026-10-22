<#
.SYNOPSIS
    Updates Azure DevOps pipeline schedules and the service connection from EntraOpsConfig.json.

.DESCRIPTION
    Materializes the Azure DevOps YAML values that cannot be populated from runtime variables. Only
    regions delimited by the EntraOps managed schedule and service connection markers are changed.
    The service connection name is read from AzureDevOpsServiceConnection (default
    EntraOps-ServiceConnection) and written as the default of the compile-time serviceConnection
    parameter, because Azure Pipelines resolves service connections before runtime variables exist.

.PARAMETER ConfigFile
    Location of the EntraOps configuration file. Defaults to ./EntraOpsConfig.json.

.PARAMETER PipelineFolder
    Folder containing the EntraOps Azure DevOps pipeline YAML files. Defaults to
    ./.azure-pipelines.

.PARAMETER BranchName
    Branch included by generated Azure DevOps schedules. Defaults to main.

.EXAMPLE
    Update-EntraOpsAzureDevOpsSchedules -ConfigFile ./EntraOpsConfig.json -BranchName main
#>

function Update-EntraOpsAzureDevOpsSchedules {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
        [string]$ConfigFile = './EntraOpsConfig.json',

        [Parameter(Mandatory = $false)]
        [ValidateScript({ Test-Path -LiteralPath $_ -PathType Container })]
        [string]$PipelineFolder = './.azure-pipelines',

        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string]$BranchName = 'main'
    )

    $Config = Get-Content -LiteralPath $ConfigFile -Raw | ConvertFrom-Json -Depth 20
    # Validated before any pipeline is changed
    $ServiceConnection = [string]$Config.AzureDevOpsServiceConnection
    if ([string]::IsNullOrWhiteSpace($ServiceConnection)) { $ServiceConnection = 'EntraOps-ServiceConnection' }
    if ($ServiceConnection -match '[\r\n]') {
        throw 'AzureDevOpsServiceConnection must be a single-line service connection name.'
    }
    $ScheduleRegionPattern = '(?ms)^# BEGIN EntraOps managed schedules\r?\n.*?^# END EntraOps managed schedules\s*$'

    function Assert-EntraOpsCronExpression {
        param (
            [Parameter(Mandatory = $true)]
            [string]$Name,

            [Parameter(Mandatory = $true)]
            [string]$Value
        )

        if ($Value -match '[\r\n]' -or @($Value -split '\s+' | Where-Object { $_ }).Count -ne 5) {
            throw "$Name must be a single-line, five-field cron expression."
        }
    }

    function ConvertTo-EntraOpsYamlScalar {
        param ([Parameter(Mandatory = $true)][string]$Value)

        return "'$($Value.Replace("'", "''"))'"
    }

    function Set-EntraOpsPipelineSchedules {
        param (
            [Parameter(Mandatory = $true)]
            [string]$PipelineName,

            [Parameter(Mandatory = $true)]
            [AllowEmptyCollection()]
            [object[]]$Schedules
        )

        $PipelinePath = Join-Path -Path $PipelineFolder -ChildPath $PipelineName
        if (-not (Test-Path -LiteralPath $PipelinePath -PathType Leaf)) {
            throw "Azure DevOps pipeline not found: $PipelinePath"
        }

        $PipelineContent = Get-Content -LiteralPath $PipelinePath -Raw
        if ($PipelineContent -notmatch $ScheduleRegionPattern) {
            throw "Azure DevOps pipeline '$PipelinePath' does not contain the managed schedule markers."
        }

        $ScheduleLines = [System.Collections.Generic.List[string]]::new()
        $ScheduleLines.Add('# BEGIN EntraOps managed schedules')
        if ($Schedules.Count -gt 0) {
            $ScheduleLines.Add('schedules:')
            foreach ($Schedule in $Schedules) {
                Assert-EntraOpsCronExpression -Name $Schedule.Name -Value $Schedule.Cron
                $ScheduleLines.Add("- cron: $(ConvertTo-EntraOpsYamlScalar -Value $Schedule.Cron)")
                $ScheduleLines.Add("  displayName: $(ConvertTo-EntraOpsYamlScalar -Value $Schedule.DisplayName)")
                $ScheduleLines.Add('  branches:')
                $ScheduleLines.Add('    include:')
                $ScheduleLines.Add("    - $(ConvertTo-EntraOpsYamlScalar -Value $BranchName)")
                $ScheduleLines.Add('  always: true')
            }
        }
        $ScheduleLines.Add('# END EntraOps managed schedules')

        $UpdatedContent = [regex]::Replace($PipelineContent, $ScheduleRegionPattern, ($ScheduleLines -join [Environment]::NewLine), 1)
        if ($UpdatedContent -cne $PipelineContent) {
            Set-Content -LiteralPath $PipelinePath -Value $UpdatedContent -Encoding UTF8 -NoNewline
            Write-Host "Updated schedules in $PipelineName."
        } else {
            Write-Host "Schedules in $PipelineName are already current."
        }
    }

    $PullSchedules = @()
    if ($Config.WorkflowTrigger.PullScheduledTrigger -eq $true) {
        $PullSchedules = @([pscustomobject]@{
                Name        = 'WorkflowTrigger.PullScheduledCron'
                Cron        = [string]$Config.WorkflowTrigger.PullScheduledCron
                DisplayName = 'EntraOps privileged access pull'
            })
    }

    $ReportingSchedules = @()
    if ($Config.WorkflowTrigger.PushReportingScheduledTrigger -eq $true) {
        $ReportingSchedules = @([pscustomobject]@{
                Name        = 'WorkflowTrigger.PushReportingScheduledCron'
                Cron        = [string]$Config.WorkflowTrigger.PushReportingScheduledCron
                DisplayName = 'EntraOps reporting generation'
            })
    }

    $UpdateSchedules = @()
    if ($Config.AutomatedEntraOpsUpdate.UpdateScheduledTrigger -eq $true) {
        $UpdateSchedules = @([pscustomobject]@{
                Name        = 'AutomatedEntraOpsUpdate.UpdateScheduledCron'
                Cron        = [string]$Config.AutomatedEntraOpsUpdate.UpdateScheduledCron
                DisplayName = 'EntraOps update'
            })
    }

    $TenantGovernanceSchedules = @()
    if ($Config.TenantGovernanceSnapshot.EnableTenantGovernanceSnapshot -eq $true -and
        $Config.TenantGovernanceSnapshot.SnapshotScheduledTrigger -eq $true) {
        $TenantGovernanceSchedules = @(
            [pscustomobject]@{ Name = 'TenantGovernanceSnapshot.SnapshotScheduledCron'; Cron = [string]$Config.TenantGovernanceSnapshot.SnapshotScheduledCron; DisplayName = 'EntraOps Tenant Governance start' }
            [pscustomobject]@{ Name = 'TenantGovernanceSnapshot.SnapshotScheduledCronComplete'; Cron = [string]$Config.TenantGovernanceSnapshot.SnapshotScheduledCronComplete; DisplayName = 'EntraOps Tenant Governance collect' }
            [pscustomobject]@{ Name = 'TenantGovernanceSnapshot.SnapshotScheduledCronCompleteRetry1'; Cron = [string]$Config.TenantGovernanceSnapshot.SnapshotScheduledCronCompleteRetry1; DisplayName = 'EntraOps Tenant Governance collect retry 1' }
            [pscustomobject]@{ Name = 'TenantGovernanceSnapshot.SnapshotScheduledCronCompleteRetry2'; Cron = [string]$Config.TenantGovernanceSnapshot.SnapshotScheduledCronCompleteRetry2; DisplayName = 'EntraOps Tenant Governance collect retry 2' }
        )
    }

    Set-EntraOpsPipelineSchedules -PipelineName 'entraops-pull.yml' -Schedules $PullSchedules
    Set-EntraOpsPipelineSchedules -PipelineName 'entraops-push-reporting.yml' -Schedules $ReportingSchedules
    Set-EntraOpsPipelineSchedules -PipelineName 'entraops-update.yml' -Schedules $UpdateSchedules
    Set-EntraOpsPipelineSchedules -PipelineName 'entraops-pull-tenant-governance.yml' -Schedules $TenantGovernanceSchedules

    $ServiceConnectionRegionPattern = '(?m)^(?<indent>[ \t]*)# BEGIN EntraOps managed service connection\r?\n(?:.*\r?\n)*?\k<indent># END EntraOps managed service connection[ \t]*(?=\r?$)'
    foreach ($PipelineName in @('entraops-pull.yml', 'entraops-push.yml', 'entraops-push-reporting.yml', 'entraops-pull-tenant-governance.yml')) {
        $PipelinePath = Join-Path -Path $PipelineFolder -ChildPath $PipelineName
        if (-not (Test-Path -LiteralPath $PipelinePath -PathType Leaf)) {
            throw "Azure DevOps pipeline not found: $PipelinePath"
        }
        $PipelineContent = Get-Content -LiteralPath $PipelinePath -Raw
        $RegionMatch = [regex]::Match($PipelineContent, $ServiceConnectionRegionPattern)
        if (-not $RegionMatch.Success) {
            Write-Warning "Azure DevOps pipeline '$PipelinePath' does not contain the managed service connection markers; update the pipeline definitions with Update-EntraOps to set the service connection from the configuration."
            continue
        }
        $Indent = $RegionMatch.Groups['indent'].Value
        $RegionLines = @(
            "$Indent# BEGIN EntraOps managed service connection"
            "$Indent- name: serviceConnection"
            "$Indent  displayName: Azure Resource Manager service connection"
            "$Indent  type: string"
            "$Indent  default: $(ConvertTo-EntraOpsYamlScalar -Value $ServiceConnection)"
            "$Indent# END EntraOps managed service connection"
        )
        $NewLine = if ($RegionMatch.Value -match "`r`n") { "`r`n" } else { "`n" }
        $UpdatedContent = $PipelineContent.Remove($RegionMatch.Index, $RegionMatch.Length).Insert($RegionMatch.Index, ($RegionLines -join $NewLine))
        if ($UpdatedContent -cne $PipelineContent) {
            Set-Content -LiteralPath $PipelinePath -Value $UpdatedContent -Encoding UTF8 -NoNewline
            Write-Host "Updated the service connection in $PipelineName."
        } else {
            Write-Host "Service connection in $PipelineName is already current."
        }
    }
}