<#
.SYNOPSIS
    Name the deployment that runs EntraOps, so data written to shared targets can be attributed to it.

.DESCRIPTION
    GitHub Actions: GitHub <owner/repository> (<workflow>). Azure Pipelines: Azure DevOps <project>/<repository>.
    Anywhere else: the machine name. Used to record the writer of shared targets such as Sentinel WatchLists.

.OUTPUTS
    [string]
#>
function Get-EntraOpsDeploymentIdentity {

    [CmdletBinding()]
    [OutputType([string])]
    param ()

    if (-not [string]::IsNullOrWhiteSpace($env:GITHUB_REPOSITORY)) {
        $Identity = "GitHub $($env:GITHUB_REPOSITORY)"
        if (-not [string]::IsNullOrWhiteSpace($env:GITHUB_WORKFLOW)) {
            $Identity += " ($($env:GITHUB_WORKFLOW))"
        }
        return $Identity
    }

    if (-not [string]::IsNullOrWhiteSpace($env:BUILD_REPOSITORY_NAME) -or -not [string]::IsNullOrWhiteSpace($env:SYSTEM_TEAMPROJECT)) {
        return "Azure DevOps $(@($env:SYSTEM_TEAMPROJECT, $env:BUILD_REPOSITORY_NAME | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }) -join '/')"
    }

    return "Machine $([System.Environment]::MachineName)"
}
