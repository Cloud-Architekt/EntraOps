<#
.SYNOPSIS
    Install PowerShell module if it's not already available on the client, agent or runner.

.DESCRIPTION
    Install PowerShell module if it's not already available on the client, agent or runner.
    A module that is already loaded in the session is used without scanning the module paths. Without
    -MinimalVersion and -RequiredVersion, the version requirement of EntraOps for the module is used
    (Az.Accounts, Az.Resources, Microsoft.Graph.Authentication and the pinned SentinelEnrichment).

.PARAMETER ModuleName
    Name of the module to be installed.

.PARAMETER MinimalVersion
    Minimal version of the module. It only decides whether the module needs to be installed: when no
    version at or above it is available, the latest version is installed.

.PARAMETER RequiredVersion
    Exact version of the module to be installed. Takes precedence over MinimalVersion. Nothing is installed when
    this version is already available, even if a newer version is published.

.PARAMETER Import
    Import the module in the global scope after the check. With an exact version, that version is imported even
    when a newer one is installed (PowerShell would otherwise load the newest one on the first command).

.NOTES
    Adapted from TJ Galama's Stack Overflow answer:
    https://stackoverflow.com/questions/28740320/how-do-i-check-if-a-powershell-module-is-installed
#>
function Install-EntraOpsRequiredModule {

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$ModuleName,

        [Parameter(Mandatory = $false)]
        [string] $MinimalVersion,

        [Parameter(Mandatory = $false)]
        [string] $RequiredVersion,

        [Parameter(Mandatory = $false)]
        [switch] $Import
    )

    if ([string]::IsNullOrWhiteSpace($MinimalVersion) -and [string]::IsNullOrWhiteSpace($RequiredVersion)) {
        $Requirement = Get-EntraOpsModuleRequirement -ModuleName $ModuleName
        if ($null -ne $Requirement) {
            $MinimalVersion = $Requirement.MinimalVersion
            $RequiredVersion = $Requirement.RequiredVersion
        }
    }

    $IsMatchingVersion = {
        param($Module)
        if ([string]::IsNullOrWhiteSpace($Module.Version)) {
            return [string]::IsNullOrWhiteSpace($RequiredVersion) -and [string]::IsNullOrWhiteSpace($MinimalVersion)
        }
        if (-not [string]::IsNullOrWhiteSpace($RequiredVersion)) {
            return [version]$Module.Version -eq [version]$RequiredVersion
        }
        [string]::IsNullOrWhiteSpace($MinimalVersion) -or [version]$Module.Version -ge [version]$MinimalVersion
    }
    $RequestedVersionLabel = if (-not [string]::IsNullOrWhiteSpace($RequiredVersion)) { $RequiredVersion } else { $MinimalVersion }
    $InstallVersionLabel = if (-not [string]::IsNullOrWhiteSpace($RequiredVersion)) { "version $RequiredVersion" }
    elseif (-not [string]::IsNullOrWhiteSpace($MinimalVersion)) { "latest version, $MinimalVersion or later required" }
    else { 'latest version' }

    # A module loaded in this session (e.g. Az.Accounts imported by the pipeline task) needs no module path scan
    $module = Get-Module -Name $ModuleName | Where-Object { & $IsMatchingVersion $_ } | Sort-Object Version | Select-Object -Last 1
    if ($null -eq $module) {
        $module = Get-Module -Name $ModuleName -ListAvailable |
        Where-Object { & $IsMatchingVersion $_ } |
        Sort-Object Version |
        Select-Object -Last 1
    }
    if ($null -ne $module) {
        Write-Output ('Module {0} (v{1}) is available.' -f $ModuleName, $module.Version)
    } elseif (Get-Command -Name 'Install-PSResource' -ErrorAction SilentlyContinue) {
        $optionalArgs = @{}
        if (-not [string]::IsNullOrWhiteSpace($RequiredVersion)) {
            $optionalArgs['Version'] = '[{0}]' -f $RequiredVersion
        }
        Write-Warning ('Install module {0} ({1}) within scope of the current user.' -f $ModuleName, $InstallVersionLabel)
        Install-PSResource -Name $ModuleName @optionalArgs -Scope CurrentUser -TrustRepository
    } else {
        # Fallback when PSResourceGet is unavailable (e.g. removed or blocked).
        Import-Module -Name 'PowershellGet'
        $installedModule = Get-InstalledModule -Name $ModuleName -AllVersions -ErrorAction SilentlyContinue |
        Where-Object { & $IsMatchingVersion $_ } |
        Sort-Object Version |
        Select-Object -Last 1
        if ($null -ne $installedModule) {
            Write-Verbose ('Module [{0}] (v {1}) is installed.' -f $ModuleName, $installedModule.Version)
        } else {
            Write-Verbose ('Module {0} version {1}: not installed; check if nuget v2.8.5.201 or later is installed.' -f $ModuleName, $RequestedVersionLabel)
            #First check if package provider NuGet is installed. Incase an older version is installed the required version is installed explicitly
            if ((Get-PackageProvider -Name NuGet -Force).Version -lt '2.8.5.201') {
                Write-Warning ('Module {0} version {1}: Install nuget!' -f $ModuleName, $RequestedVersionLabel)
                Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Scope CurrentUser -Force
            }
            $optionalArgs = New-Object -TypeName Hashtable
            if (-not [string]::IsNullOrWhiteSpace($RequiredVersion)) {
                $optionalArgs['RequiredVersion'] = $RequiredVersion
            }
            Write-Warning ('Install module {0} ({1}) within scope of the current user.' -f $ModuleName, $InstallVersionLabel)
            Install-Module -Name $ModuleName @optionalArgs -Scope CurrentUser -Force
        }
    }

    if ($Import) {
        $ImportVersion = @{}
        if (-not [string]::IsNullOrWhiteSpace($RequiredVersion)) {
            $ImportVersion['RequiredVersion'] = $RequiredVersion
        } elseif (-not [string]::IsNullOrWhiteSpace($MinimalVersion)) {
            $ImportVersion['MinimumVersion'] = $MinimalVersion
        }
        Import-Module -Name $ModuleName @ImportVersion -Global -ErrorAction Stop -WarningAction SilentlyContinue
    }
}
