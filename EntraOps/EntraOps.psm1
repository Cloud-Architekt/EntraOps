# Get public and private function definition files.
$Public = @( Get-ChildItem -Path $PSScriptRoot\Public\*.ps1 -Recurse -ErrorAction SilentlyContinue )
$Private = @( Get-ChildItem -Path $PSScriptRoot\Private\*.ps1 -Recurse -ErrorAction SilentlyContinue )

# Dot source the files
Foreach ($import in @($Public + $Private)) {
    Try {
        Write-Verbose "Importing $($Import.FullName)"
        . $import.fullname
    }
    Catch {
        Write-Error -Message "Failed to import function $($import.fullname): $_"
    }
}

# Set Error Action
$ErrorActionPreference = "Stop"
Export-ModuleMember -Function $Public.Basename
Install-EntraOpsAllRequiredModules

# Update Clear-ModuleVariable function in internal/Clear-ModuleVariable.ps1 if you add new variables here
# This function has been adopted from the Maester Framework and has been originally written by Merill Fernando
$__EntraOpsSession = @{
    GraphCache = @{}
}
New-Variable -Name __EntraOpsSession -Value $__EntraOpsSession -Scope Script -Force

# Global variable
$EntraOpsBasefolder = (Get-Item -Path $PSScriptRoot).Parent.FullName
New-Variable -Name EntraOpsBaseFolder -Value $EntraOpsBasefolder -Scope Global -Force

# Welcome message and logo
$ModuleManifest = Import-PowerShellDataFile "$PSScriptRoot\EntraOps.psd1"
$PSEnvironment = "PowerShell " + ($PSVersionTable.PSEdition) + " " + ($PSVersionTable.PSVersion.ToString())
$ModuleVersion = $($ModuleManifest.ModuleVersion)
$host.ui.RawUI.WindowTitle = "EntraOps "

$Splash = @"
 ______       _              ____
|  ____|     | |            / __ \
| |__   _ __ | |_ _ __ __ _| |  | |_ __  ___
|  __| | '_ \| __| '__/ _`  | |  | | '_ \/ __|
| |____| | | | |_| | | (_| | |__| | |_) \__ \
|______|_| |_|\__|_|  \__,_|\____/| .__/|___/
                                  | |
                                  |_|

Version $($ModuleVersion) on $($PSEnvironment)
PoC Project by Thomas Naunheim - www.cloud-architekt.net
"@

Write-Host $Splash -ForegroundColor Blue
