function Get-EntraOpsAzureDevOpsPipelineBranch {
    <#
    .SYNOPSIS
        Returns the branch that the EntraOps Azure DevOps pipelines are configured for, or $null when it can't be determined.
    .DESCRIPTION
        The branch of the managed schedules and of the pipeline completion trigger isn't stored in EntraOpsConfig.json.
        Update-EntraOps replaces the pipeline definitions with the upstream templates (branch main), so it reads the
        branch from the current definitions first and passes it to Update-EntraOpsAzureDevOpsSchedules. The first
        branch of a managed schedule or pipeline trigger region is used; without one, the branch of the running Azure
        DevOps job (BUILD_SOURCEBRANCH) is used.
    .PARAMETER PipelineFolder
        Folder containing the EntraOps Azure DevOps pipeline YAML files.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param (
        [Parameter(Mandatory = $true)]
        [string]$PipelineFolder
    )

    $RegionPattern = '(?ms)^[ \t]*# BEGIN EntraOps managed (?:schedules|pipeline trigger)[ \t]*\r?\n(?<body>.*?)^[ \t]*# END EntraOps managed (?:schedules|pipeline trigger)'
    # Only the branch entries of a region are list items that consist of a single quoted scalar
    $BranchPattern = "(?m)^[ \t]*-[ \t]*'(?<branch>(?:[^']|'')+)'[ \t]*\r?$"
    foreach ($PipelineName in @('entraops-pull.yml', 'entraops-push.yml', 'entraops-push-reporting.yml', 'entraops-update.yml', 'entraops-pull-tenant-governance.yml')) {
        $PipelinePath = Join-Path -Path $PipelineFolder -ChildPath $PipelineName
        if (-not (Test-Path -LiteralPath $PipelinePath -PathType Leaf)) { continue }
        $PipelineContent = Get-Content -LiteralPath $PipelinePath -Raw
        foreach ($Region in [regex]::Matches($PipelineContent, $RegionPattern)) {
            $BranchMatch = [regex]::Match($Region.Groups['body'].Value, $BranchPattern)
            if ($BranchMatch.Success) {
                return $BranchMatch.Groups['branch'].Value.Replace("''", "'")
            }
        }
    }

    if ("$env:BUILD_SOURCEBRANCH" -like 'refs/heads/*') {
        return "$env:BUILD_SOURCEBRANCH".Substring('refs/heads/'.Length)
    }
    return $null
}
