function Test-EntraOpsInteractiveHost {
    <#
    .SYNOPSIS
        Tests whether the session can ask the user: an interactive console without redirected input, outside a pipeline
        (GitHub Actions, Azure DevOps and other CI systems set CI or TF_BUILD).
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param ()

    [Environment]::UserInteractive -and -not [Console]::IsInputRedirected -and
    [string]::IsNullOrWhiteSpace($env:CI) -and [string]::IsNullOrWhiteSpace($env:TF_BUILD)
}
