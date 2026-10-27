function Get-EntraOpsRepositoryRoot {
    <#
    .SYNOPSIS
        Returns the repository checkout that contains the loaded EntraOps module, or $null for a module-only install.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param ()

    $ModuleRoot = $MyInvocation.MyCommand.Module.ModuleBase
    if ([string]::IsNullOrWhiteSpace($ModuleRoot) -and -not [string]::IsNullOrWhiteSpace($PSScriptRoot)) {
        $ModuleRoot = Split-Path -Parent $PSScriptRoot
    }
    if ([string]::IsNullOrWhiteSpace($ModuleRoot)) { return $null }
    $Candidate = Split-Path -Parent $ModuleRoot
    if (Test-EntraOpsRepositoryCheckout -Path $Candidate) { return $Candidate }
    return $null
}
