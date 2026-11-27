<#
.SYNOPSIS
    Install all required modules for EntraOps PowerShell Module

.DESCRIPTION
    Wrapper function to check if all required modules for EntraOps PowerShell Module are installed and install them if not.

.EXAMPLE
    Verify if all required modules are installed with the required version
    Install-EntraOpsAllRequiredModules
#>

function Install-EntraOpsAllRequiredModules {

    $ErrorActionPreference = "Stop"

    foreach ($RequiredModule in @(Get-EntraOpsModuleRequirement | Where-Object { -not $_.Optional })) {
        Install-EntraOpsRequiredModule -ModuleName $RequiredModule.ModuleName
    }
}