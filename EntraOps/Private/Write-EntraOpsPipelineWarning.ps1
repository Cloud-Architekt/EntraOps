function Write-EntraOpsPipelineWarning {
    <#
    .SYNOPSIS
        Shows a warning as annotation of the GitHub Actions or Azure DevOps run.
    .DESCRIPTION
        Write-Warning is only visible in the job log; degraded results are also shown on the run summary.
        Outside of a pipeline nothing is written.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Message,
        [Parameter(Mandatory = $false)]
        [string]$Title = "EntraOps"
    )

    $SingleLineMessage = ($Message -replace '\r?\n', ' ').Trim()
    if ($env:GITHUB_ACTIONS -eq 'true') {
        $EscapedTitle = $Title.Replace('%', '%25').Replace(',', '%2C').Replace(':', '%3A')
        Write-Host "::warning title=$($EscapedTitle)::$($SingleLineMessage.Replace('%', '%25'))"
    } elseif ($env:TF_BUILD -eq 'True') {
        Write-Host "##vso[task.logissue type=warning]$SingleLineMessage"
    }
}
