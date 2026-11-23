function Get-EntraOpsFindingRoot {
    <#
    .SYNOPSIS
        Returns the module folder and the EntraOps working folder for the Findings cmdlets.
    .DESCRIPTION
        ModuleRoot is the folder of the loaded module (its ModuleBase, else derived from this file);
        RepositoryRoot is $EntraOpsBaseFolder, else the parent folder of the module. The Findings cmdlets
        default their paths to RepositoryRoot (PrivilegedEAM, Reports, EntraOpsConfig.json).
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param ()

    # Prefer the module's ModuleBase over $PSScriptRoot (see New-EntraOpsTierBreachAnalyzerData).
    $ModuleRoot = $MyInvocation.MyCommand.Module.ModuleBase
    if ([string]::IsNullOrWhiteSpace($ModuleRoot) -and -not [string]::IsNullOrWhiteSpace($PSScriptRoot)) {
        $ModuleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    }
    [pscustomobject]@{
        ModuleRoot     = $ModuleRoot
        RepositoryRoot = $(if (-not [string]::IsNullOrWhiteSpace($Global:EntraOpsBaseFolder)) { $Global:EntraOpsBaseFolder } else { Split-Path -Parent $ModuleRoot })
    }
}
