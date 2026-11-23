function Get-EntraOpsModuleVersion {
    <#
    .SYNOPSIS
        Returns the version of the loaded EntraOps module from its manifest.

    .DESCRIPTION
        The module object has the version 0.0 when the module is imported from EntraOps.psm1 instead of the
        manifest, so the version is read from EntraOps.psd1 in the module folder. Returns $null when it is unknown.
    #>
    [CmdletBinding()]
    [OutputType([version])]
    param ()

    $ModuleBase = $MyInvocation.MyCommand.Module.ModuleBase
    if ([string]::IsNullOrWhiteSpace($ModuleBase)) { $ModuleBase = Split-Path -Parent $PSScriptRoot }
    $ManifestPath = Join-Path $ModuleBase 'EntraOps.psd1'
    if (Test-Path -LiteralPath $ManifestPath -PathType Leaf) {
        try {
            $Version = [version]::new(0, 0)
            if ([version]::TryParse([string](Import-PowerShellDataFile -LiteralPath $ManifestPath).ModuleVersion, [ref]$Version)) { return $Version }
        } catch {
            Write-Verbose "The EntraOps module manifest $ManifestPath could not be read: $($_.Exception.Message)"
        }
    }
    $ModuleVersion = $MyInvocation.MyCommand.Module.Version
    if ($ModuleVersion -and $ModuleVersion -ne [version]::new(0, 0)) { return $ModuleVersion }
    return $null
}
