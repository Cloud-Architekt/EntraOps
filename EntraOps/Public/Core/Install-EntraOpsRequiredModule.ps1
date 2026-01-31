<#
.SYNOPSIS
    Install PowerShell module if it's not already available on the client, agent or runner.

.DESCRIPTION
    Install PowerShell module if it's not already available on the client, agent or runner.

.PARAMETER ModuleName
    Name of the module to be installed.

.PARAMETER MinimalVersion
    Minimal version of the module to be installed.

.NOTES
    Fork from PowerShell example on Stackoverflow dicussion
    (https://stackoverflow.com/questions/28740320/how-do-i-check-if-a-powershell-module-is-installed) by TJ Galama.
#>
function Install-EntraOpsRequiredModule {

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$ModuleName,

        [Parameter(Mandatory = $false)]
        [string] $MinimalVersion
    )

    $module = Get-Module -Name $ModuleName -ListAvailable |`
        Where-Object { $null -eq $MinimalVersion -or $MinimalVersion -ge $_.Version } `
    | Sort-Object Version `
    | Select-Object -Last 1
    if ($null -ne $module) {
        Write-Output ('Module {0} (v{1}) is available.' -f $ModuleName, $module.Version)
    }
    else {
        Import-Module -Name 'PowershellGet'
        $installedModule = Get-InstalledModule -Name $ModuleName -ErrorAction SilentlyContinue
        if ($null -ne $installedModule) {
            Write-Verbose ('Module [{0}] (v {1}) is installed.' -f $ModuleName, $installedModule.Version)
        }
        if ($null -eq $installedModule -or ($null -ne $MinimalVersion -and $installedModule.Version -lt $MinimalVersion)) {
            Write-Verbose ('Module {0} min.vers {1}: not installed; check if nuget v2.8.5.201 or later is installed.' -f $ModuleName, $MinimalVersion)
            #First check if package provider NuGet is installed. Incase an older version is installed the required version is installed explicitly
            if ((Get-PackageProvider -Name NuGet -Force).Version -lt '2.8.5.201') {
                Write-Warning ('Module {0} min.vers {1}: Install nuget!' -f $ModuleName, $MinimalVersion)
                Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Scope CurrentUser -Force
            }
            $optionalArgs = New-Object -TypeName Hashtable
            if ($null -ne $MinimalVersion) {
                $optionalArgs['MinimumVersion'] = $MinimalVersion
            }
            Write-Warning ('Install module {0} (version [{1}]) within scope of the current user.' -f $ModuleName, $MinimalVersion)
            Install-Module -Name $ModuleName @optionalArgs -Scope CurrentUser -Force
        }
    }
}