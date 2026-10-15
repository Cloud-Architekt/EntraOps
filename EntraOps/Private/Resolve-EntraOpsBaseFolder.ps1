function Resolve-EntraOpsBaseFolder {
    <#
    .SYNOPSIS
        Resolves the EntraOps working folder ($EntraOpsBaseFolder) for configuration, classification, exports and reports.

    .DESCRIPTION
        Order: ENTRAOPS_ROOT, the repository checkout that contains the module (unchanged behavior for
        GitHub, Azure DevOps and local clones), the current folder when it contains EntraOpsConfig.json,
        and finally <home>/EntraOps for module-only installs such as the PowerShell Gallery.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param (
        [Parameter(Mandatory = $true)]
        [string]$ModuleRoot,

        [Parameter(Mandatory = $false)]
        [string]$EnvironmentRoot = $env:ENTRAOPS_ROOT,

        [Parameter(Mandatory = $false)]
        [string]$CurrentPath = (Get-Location -PSProvider FileSystem).ProviderPath,

        [Parameter(Mandatory = $false)]
        [string]$UserHome = $HOME
    )

    if (-not [string]::IsNullOrWhiteSpace($EnvironmentRoot)) {
        $Path = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($EnvironmentRoot)
        return [pscustomobject]@{ Path = $Path.TrimEnd([char[]]@('/', '\')); Source = 'EnvironmentVariable' }
    }

    $ModuleParent = Split-Path -Parent $ModuleRoot
    if (Test-EntraOpsRepositoryCheckout -Path $ModuleParent) {
        return [pscustomobject]@{ Path = $ModuleParent; Source = 'RepositoryCheckout' }
    }

    if (-not [string]::IsNullOrWhiteSpace($CurrentPath) -and (Test-Path -LiteralPath (Join-Path $CurrentPath 'EntraOpsConfig.json') -PathType Leaf)) {
        return [pscustomobject]@{ Path = $CurrentPath; Source = 'CurrentFolder' }
    }

    return [pscustomobject]@{ Path = (Join-Path $UserHome 'EntraOps'); Source = 'UserFolder' }
}
