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

    $RequiredModules = @(
        @{
            ModuleName    = 'Az.Accounts'
            ModuleVersion = '2.19.0'
        }
        @{
            ModuleName    = 'Az.Resources'
            ModuleVersion = '6.16.2'
        }
        @{
            ModuleName    = 'Az.ResourceGraph'
            ModuleVersion = '0.13.1'
        }
        @{
            ModuleName    = 'Microsoft.Graph.Authentication'
            ModuleVersion = '2.18.0'
        }
    )

    foreach ($RequiredModule in $RequiredModules) {
        Install-EntraOpsRequiredModule -ModuleName $RequiredModule.ModuleName -MinimalVersion $RequiredModule.ModuleVersion
    }
}