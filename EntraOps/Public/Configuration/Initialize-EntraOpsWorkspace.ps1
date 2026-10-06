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
    Working folder to prepare. Defaults to $EntraOpsBaseFolder.

.PARAMETER Content
    Content to install: Classification (templates and Global.json), Samples and Reports. Defaults to all.

.PARAMETER Repository
    EntraOps distribution repository: the public 'EntraOps' release repository (default) or the
    private 'EntraOps-Insiders' repository, which requires -PersonalAccessToken or ENTRAOPS_PAT.

.PARAMETER Ref
    Branch, release tag or full commit SHA to download. Defaults to 'main'. Use the ref that matches
    the installed module version.

.PARAMETER PersonalAccessToken
    GitHub token for the private 'EntraOps-Insiders' repository. Defaults to ENTRAOPS_PAT.

.PARAMETER Force
    Replace existing files with the downloaded version (except the protected files above), e.g.
    after Update-Module EntraOps.

.EXAMPLE
    Initialize-EntraOpsWorkspace

    Downloads the classification templates, samples and reporting apps into the EntraOps working folder.

.EXAMPLE
    $env:ENTRAOPS_ROOT = 'D:\EntraOps'; Import-Module EntraOps -Force; Initialize-EntraOpsWorkspace -Ref 'v1.2.0'

    Uses D:\EntraOps as working folder and installs the content of release v1.2.0.
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
        [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9._/-]{0,199}$')]
        [System.String]$Ref = 'main',

        [Parameter(Mandatory = $false)]
        [System.String]$PersonalAccessToken,

        [Parameter(Mandatory = $false)]
        [switch]$Force
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

    $Archive = Get-EntraOpsSourceArchive -Repository $Repository -Ref $Ref -PersonalAccessToken $PersonalAccessToken
    try {
        foreach ($Name in $ContentDefinitions.Keys) {
            if ($Content -notcontains $Name) { continue }
            $Source = Join-Path $Archive.SourceRoot $Name
            if (-not (Test-Path -LiteralPath $Source -PathType Container)) {
                Write-Warning "$($Archive.Repository) at '$Ref' doesn't contain the folder '$Name'. Skipped."
                continue
            }
            $Destination = Join-Path $Path $Name
            if (-not $PSCmdlet.ShouldProcess($Destination, "Install $Name from $($Archive.Repository) at '$Ref'")) { continue }
            $Result = Copy-EntraOpsSourceFolder -Source $Source -Destination $Destination -KeepPattern $ContentDefinitions[$Name].KeepPattern -IncludePattern $ContentDefinitions[$Name].IncludePattern -Force:$Force
            [pscustomobject]@{
                Content       = $Name
                Path          = $Destination
                Repository    = $Archive.Repository
                Ref           = $Ref
                InstalledFile = $Result.Installed
                KeptFile      = $Result.Kept
                SkippedFile   = $Result.Skipped
            }
        }
    } finally {
        Remove-Item -LiteralPath $Archive.TemporaryFolder -Recurse -Force -ErrorAction SilentlyContinue -WhatIf:$false
    }

    if (-not $WhatIfPreference) {
        Write-Host "EntraOps working folder: $Path"
        if (-not (Test-Path -LiteralPath (Join-Path $Path 'EntraOpsConfig.json') -PathType Leaf)) {
            Write-Host "Next: create EntraOpsConfig.json in this folder with New-EntraOpsConfigFile."
        }
        if ($Path -ne $Global:EntraOpsBaseFolder) {
            Write-Host "Set ENTRAOPS_ROOT to '$Path' (or run EntraOps from this folder) and import the module again to use it."
        }
    }
}
