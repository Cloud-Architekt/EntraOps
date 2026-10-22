#Requires -Version 7.4
<#
.SYNOPSIS
    Generates the configured EntraOps reports from the Push-EntraOpsPrivilegedReporting workflow.

.DESCRIPTION
    Wraps Invoke-EntraOpsReportingGeneration with the workflow inputs. A manual run (workflow_dispatch)
    uses its own partial snapshot choice; only a manual stale override skips the stale snapshot check,
    otherwise ConfigurationAnalyzer.StaleTenantGovernanceSnapshotAction from EntraOpsConfig.json applies.
#>
[CmdletBinding()]
param (
    [Parameter(Mandatory = $false)]
    [string]$ConfigFilePath = $env:ConfigFile,

    [Parameter(Mandatory = $false)]
    [string]$EventName = $env:GITHUB_EVENT_NAME,

    [Parameter(Mandatory = $false)]
    [string]$AllowStaleTenantGovernance = $env:AllowStaleTenantGovernance,

    [Parameter(Mandatory = $false)]
    [string]$AllowPartialTenantGovernance = $env:AllowPartialTenantGovernance,

    [Parameter(Mandatory = $false)]
    [string]$ManualAllowPartialTenantGovernance = $env:ManualAllowPartialTenantGovernance
)

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot '../../EntraOps')

$AllowPartial = if ($EventName -eq 'workflow_dispatch') { $ManualAllowPartialTenantGovernance -eq 'true' } else { $AllowPartialTenantGovernance -eq 'true' }
$ReportingParameters = @{
    ConfigFilePath                         = $ConfigFilePath
    AuthenticationType                     = 'FederatedCredentials'
    AllowPartialTenantGovernanceSnapshot   = $AllowPartial
    RemoveClassificationRepositoryAfterRun = $true
}
if ($AllowStaleTenantGovernance -eq 'true') { $ReportingParameters.AllowStaleTenantGovernanceSnapshot = $true }
Invoke-EntraOpsReportingGeneration @ReportingParameters | Out-Host
