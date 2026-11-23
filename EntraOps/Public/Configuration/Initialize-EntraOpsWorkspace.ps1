<#
.SYNOPSIS
    Prepares an EntraOps working folder for a module-only installation, e.g. from the PowerShell Gallery.

.DESCRIPTION
    A module-only installation contains no classification templates, samples or reporting apps. This
    cmdlet downloads them from an EntraOps distribution repository (GitHub source archive) into the
    EntraOps working folder ($EntraOpsBaseFolder), so Connect-EntraOps, the Privileged EAM cmdlets and
    the report generators find them there. It never writes into the module folder.

    The working folder is resolved at module import: ENTRAOPS_ROOT, the repository checkout that
    contains the module (GitHub, Azure DevOps or local clone), the current folder when it contains
    EntraOpsConfig.json, and otherwise <home>/EntraOps.

    Existing files are kept unless -Force is used. Even with -Force, Classification/Global.json and the
    generated report data (Reports/<App>/data) are never replaced. Only Classification/Templates and
    Classification/Global.json are installed, so tenant classification folders (Classification/<TenantName>)
    are never changed.

.PARAMETER Path
    Working folder to prepare. Defaults to $EntraOpsBaseFolder. A different folder becomes the EntraOps
    working folder for the current session (sets $EntraOpsBaseFolder and ENTRAOPS_ROOT), unless
    -KeepWorkingFolder is used. Set ENTRAOPS_ROOT for new sessions.

.PARAMETER Content
    Content to install: Classification (templates and Global.json), Samples and Reports. Defaults to all.

.PARAMETER Repository
    EntraOps distribution repository: the public 'EntraOps' release repository or the private
    'EntraOps-Insiders' repository, which requires -PersonalAccessToken or ENTRAOPS_PAT. Defaults to
    AutomatedEntraOpsUpdate.Repository of EntraOpsConfig.json in -Path (the release channel of the
    deployment), otherwise 'EntraOps'.

.PARAMETER Ref
    Branch, release tag or full commit SHA to download (alias: -Branch). Without it, the content that
    matches the module version is installed: the newest content of the main branch whose EntraOps.psd1
    has the module version (branch head, release tag or commit; Reports and Samples alone also from the
    repository checkout that contains the module, files tracked in git only). When the branch has no such commit (a module newer than the
    branch, for example an Insiders build), the branch head is installed with a warning.

.PARAMETER PersonalAccessToken
    GitHub token for the private 'EntraOps-Insiders' repository. Defaults to ENTRAOPS_PAT.

.PARAMETER Force
    Replace existing files with the downloaded version (except the protected files above), e.g.
    after Update-PSResource EntraOps (or Update-Module EntraOps).

.PARAMETER KeepWorkingFolder
    Install into -Path without switching the session's EntraOps working folder, e.g. to prepare a
    folder for another tenant or machine.

.EXAMPLE
    Initialize-EntraOpsWorkspace

    Downloads the classification templates, samples and reporting apps into the EntraOps working folder.

.EXAMPLE
    Initialize-EntraOpsWorkspace -Path 'D:\EntraOps'

    Installs the content that matches the module version into D:\EntraOps and uses it as working folder for this session.

.EXAMPLE
    $env:ENTRAOPS_ROOT = 'D:\EntraOps'; Import-Module EntraOps -Force; Initialize-EntraOpsWorkspace

    Uses D:\EntraOps as working folder and installs the content that matches the module version.

.EXAMPLE
    Initialize-EntraOpsWorkspace -Branch 'dev' -Force

    Installs the content of the 'dev' branch and replaces existing files (except the protected files).
#>

function Initialize-EntraOpsWorkspace {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param (
        [Parameter(Mandatory = $false)]
        [System.String]$Path,

        [Parameter(Mandatory = $false)]
        [ValidateSet('Classification', 'Samples', 'Reports')]
        [System.String[]]$Content = @('Classification', 'Samples', 'Reports'),

        [Parameter(Mandatory = $false)]
        [ValidateSet('EntraOps', 'EntraOps-Insiders')]
        [System.String]$Repository = 'EntraOps',

        [Parameter(Mandatory = $false)]
        [Alias('Branch')]
        [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9._/-]{0,199}$')]
        [System.String]$Ref,

        [Parameter(Mandatory = $false)]
        [System.String]$PersonalAccessToken,

        [Parameter(Mandatory = $false)]
        [switch]$Force,

        [Parameter(Mandatory = $false)]
        [switch]$KeepWorkingFolder
    )

    $ErrorActionPreference = 'Stop'

    if ([string]::IsNullOrWhiteSpace($Path)) {
        if ([string]::IsNullOrWhiteSpace($Global:EntraOpsBaseFolder)) {
            throw "The EntraOps working folder is not set. Pass -Path or import the module with 'Import-Module EntraOps -Force'."
        }
        $Path = $Global:EntraOpsBaseFolder
    }
    $Path = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path).TrimEnd([char[]]@('/', '\'))

    $ModuleRoot = $MyInvocation.MyCommand.Module.ModuleBase
    if (-not [string]::IsNullOrWhiteSpace($ModuleRoot)) {
        $ModuleRoot = $ModuleRoot.TrimEnd([char[]]@('/', '\'))
        $Separator = [System.IO.Path]::DirectorySeparatorChar
        $IgnoreCase = [System.StringComparison]::OrdinalIgnoreCase
        if ($Path.Equals($ModuleRoot, $IgnoreCase) -or $Path.StartsWith("$ModuleRoot$Separator", $IgnoreCase) -or $ModuleRoot.StartsWith("$Path$Separator", $IgnoreCase)) {
            if (Test-EntraOpsRepositoryCheckout -Path $Path) {
                throw "'$Path' is the repository checkout that contains the EntraOps module and already includes this content. Use Update-EntraOps to update it."
            }
            throw "Working folder '$Path' contains or is inside the EntraOps module folder '$ModuleRoot'. Use a separate folder, e.g. set ENTRAOPS_ROOT and import the module again."
        }
    }

    # Patterns are relative to the content folder; Classification is limited to the shipped templates.
    $ContentDefinitions = [ordered]@{
        Classification = @{ IncludePattern = '^(Templates[/\\]|Global\.json$)'; KeepPattern = '^Global\.json$' }
        Samples        = @{ IncludePattern = $null; KeepPattern = $null }
        Reports        = @{ IncludePattern = $null; KeepPattern = '^[^/\\]+[/\\]data[/\\]' }
    }

    # Without -Repository, the content follows the release channel of the deployment.
    if ($PSBoundParameters.ContainsKey('Repository')) {
        $RepositoryReason = '-Repository'
    } else {
        $SelectedRepository = Resolve-EntraOpsContentRepository -ConfigFilePath (Join-Path $Path 'EntraOpsConfig.json')
        $Repository = $SelectedRepository.Repository
        $RepositoryReason = $SelectedRepository.Reason
    }
    Write-Host "Content repository: $Repository ($RepositoryReason)"

    $Archive = Get-EntraOpsContentSource -Repository $Repository -Ref $Ref -PersonalAccessToken $PersonalAccessToken -Folder $Content
    $SourceText = "$($Archive.Repository)$(if ($Archive.Ref) { " at '$($Archive.Ref)'" })"
    if (-not $Archive.Matched) {
        Write-Warning "The content of $SourceText is version $(if ($Archive.ContentVersion) { $Archive.ContentVersion } else { 'unknown' }), the EntraOps module is $($Archive.ModuleVersion): templates, samples and reporting apps can miss what this module version needs. Install matching content with -Ref <branch or commit> (with -Repository EntraOps-Insiders for an Insiders build)."
    }
    try {
        foreach ($Name in $ContentDefinitions.Keys) {
            if ($Content -notcontains $Name) { continue }
            $Source = Join-Path $Archive.SourceRoot $Name
            if (-not (Test-Path -LiteralPath $Source -PathType Container)) {
                Write-Warning "$SourceText doesn't contain the folder '$Name'. Skipped."
                continue
            }
            $Destination = Join-Path $Path $Name
            if (-not $PSCmdlet.ShouldProcess($Destination, "Install $Name from $SourceText")) { continue }
            $Result = Copy-EntraOpsSourceFolder -Source $Source -Destination $Destination -KeepPattern $ContentDefinitions[$Name].KeepPattern -IncludePattern $ContentDefinitions[$Name].IncludePattern -Force:$Force
            if ($Name -eq 'Reports') {
                # The marker tells Invoke-EntraOpsAssessment that the apps are of this version, so it doesn't update them.
                # Kept app files of an earlier version (without -Force) would be taken for current ones.
                if ($Result.Skipped -eq 0) {
                    Write-EntraOpsContentMarker -Path $Destination -Source $Archive
                } else {
                    Write-Warning "Kept $($Result.Skipped) existing reporting app file(s) in $Destination, which can be of another version than $SourceText. Run Initialize-EntraOpsWorkspace -Content Reports -Force to update them (generated report data is kept)."
                }
            }
            [pscustomobject]@{
                Content       = $Name
                Path          = $Destination
                Repository     = $Archive.Repository
                Ref            = $Archive.Ref
                ContentVersion = $Archive.ContentVersion
                Matched        = $Archive.Matched
                InstalledFile = $Result.Installed
                KeptFile      = $Result.Kept
                SkippedFile   = $Result.Skipped
            }
        }
    } finally {
        if ($Archive.TemporaryFolder) { Remove-Item -LiteralPath $Archive.TemporaryFolder -Recurse -Force -ErrorAction SilentlyContinue -WhatIf:$false }
    }

    if (-not $WhatIfPreference) {
        $CurrentWorkingFolder = "$Global:EntraOpsBaseFolder".TrimEnd([char[]]@('/', '\'))
        if ($Path -ne $CurrentWorkingFolder -and -not $KeepWorkingFolder) {
            # Cmdlets read $Global:EntraOpsBaseFolder at run time, so no module re-import is needed.
            $Global:EntraOpsBaseFolder = $Path
            $env:ENTRAOPS_ROOT = $Path
            Write-Host "EntraOps working folder for this session: $Path"
            Write-Host "For new sessions, set ENTRAOPS_ROOT to '$Path' before importing the module (or run EntraOps from this folder with EntraOpsConfig.json)."
            if (Get-Variable -Name TenantNameContext -Scope Global -ValueOnly -ErrorAction SilentlyContinue) {
                Write-Host "Run Connect-EntraOps again to use the new working folder for the current connection."
            }
        } else {
            Write-Host "EntraOps working folder: $Path"
            if ($Path -ne $CurrentWorkingFolder) {
                Write-Host "Set ENTRAOPS_ROOT to '$Path' (or run EntraOps from this folder) and import the module again to use it."
            }
        }
        if (-not (Test-Path -LiteralPath (Join-Path $Path 'EntraOpsConfig.json') -PathType Leaf)) {
            Write-Host "Next: create EntraOpsConfig.json in this folder with New-EntraOpsConfigFile or Configuration Wizard in EntraOps Docs, or run Invoke-EntraOpsPrivilegedEAM without configuration."
        }
    }
}
