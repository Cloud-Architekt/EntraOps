<#
.SYNOPSIS
    Version requirements of the PowerShell modules that EntraOps installs.

.DESCRIPTION
    The one place for the module versions used by Install-EntraOpsRequiredModule, Install-EntraOpsAllRequiredModules
    and Connect-EntraOps. RequiredVersion pins a third-party module to the version validated with EntraOps. Optional
    modules are installed only by the commands that use them.

.PARAMETER ModuleName
    Returns only the requirement of this module; nothing when the module has none.
#>
function Get-EntraOpsModuleRequirement {

    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param (
        [Parameter(Mandatory = $false)]
        [string]$ModuleName
    )

    # Minimum versions: the modules of the GitHub-hosted ubuntu-latest runner image (Az 15.6.1, Microsoft.Graph 2.41.2),
    # so hosted runs install nothing at sign-in. A higher minimum makes every hosted run install the module.
    $Requirements = @(
        [pscustomobject]@{ ModuleName = 'Az.Accounts'; MinimalVersion = '5.4.0'; RequiredVersion = $null; Optional = $false }
        [pscustomobject]@{ ModuleName = 'Az.Resources'; MinimalVersion = '9.1.0'; RequiredVersion = $null; Optional = $false }
        [pscustomobject]@{ ModuleName = 'Microsoft.Graph.Authentication'; MinimalVersion = '2.41.2'; RequiredVersion = $null; Optional = $false }
        # New-EntraOpsWorkloadIdentity; same version as Microsoft.Graph.Authentication, which the Graph modules require in their version
        [pscustomobject]@{ ModuleName = 'Microsoft.Graph.Applications'; MinimalVersion = '2.41.2'; RequiredVersion = $null; Optional = $true }
        # Update-EntraOpsRequiredWorkflowParameters
        [pscustomobject]@{ ModuleName = 'powershell-yaml'; MinimalVersion = '0.4.12'; RequiredVersion = $null; Optional = $true }
        # Sentinel WatchLists
        [pscustomobject]@{ ModuleName = 'SentinelEnrichment'; MinimalVersion = $null; RequiredVersion = '0.2.2'; Optional = $true }
    )

    if ($PSBoundParameters.ContainsKey('ModuleName')) {
        return $Requirements | Where-Object { $_.ModuleName -eq $ModuleName }
    }
    $Requirements
}
