<#
.SYNOPSIS
    Downloads the EntraOps reporting apps (Reports folder) from GitHub.

.DESCRIPTION
    The report data generators (New-EntraOpsReportingData and the New-EntraOps*Data cmdlets) write
    their data into the static reporting apps in the Reports folder of the EntraOps working folder
    ($EntraOpsBaseFolder). When only the EntraOps module has been downloaded or installed, this
    cmdlet downloads the Reports folder of an EntraOps release repository as a GitHub source archive
    and installs it there (or to -DestinationPath). Initialize-EntraOpsWorkspace installs it together
    with the classification templates and samples.

    Existing report data (the data folder of each app) is never overwritten. An existing Reports
    folder is only updated with -Force. Browser test specs (*.spec.mjs) are not installed.

.PARAMETER Repository
    EntraOps distribution repository: the public 'EntraOps' release repository (default) or the
    private 'EntraOps-Insiders' repository, which requires -PersonalAccessToken or ENTRAOPS_PAT.

.PARAMETER Ref
    Branch, release tag or full commit SHA to download. Defaults to 'main'. Use the ref that
    matches the installed module, so the apps and the generated data format fit together.

.PARAMETER DestinationPath
    Target Reports folder. Defaults to the Reports folder in the EntraOps working folder, where the
    report data generators expect it.

.PARAMETER PersonalAccessToken
    GitHub token for the private 'EntraOps-Insiders' repository. Defaults to ENTRAOPS_PAT.

.PARAMETER Force
    Update an existing Reports folder. App files are replaced; generated report data is kept.

.EXAMPLE
    Install-EntraOpsReportingFolder

    Downloads the Reports folder of the main branch into the EntraOps working folder.

.EXAMPLE
    Install-EntraOpsReportingFolder -Ref '0123456789abcdef0123456789abcdef01234567' -Force -WhatIf

    Shows which Reports folder would be updated from a pinned commit without changing files.
#>

function Install-EntraOpsReportingFolder {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param (
        [Parameter(Mandatory = $false)]
        [ValidateSet('EntraOps', 'EntraOps-Insiders')]
        [System.String]$Repository = 'EntraOps',

        [Parameter(Mandatory = $false)]
        [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9._/-]{0,199}$')]
        [System.String]$Ref = 'main',

        [Parameter(Mandatory = $false)]
        [System.String]$DestinationPath,

        [Parameter(Mandatory = $false)]
        [System.String]$PersonalAccessToken,

        [Parameter(Mandatory = $false)]
        [switch]$Force
    )

    $ErrorActionPreference = 'Stop'

    if ([string]::IsNullOrWhiteSpace($DestinationPath)) {
        if ([string]::IsNullOrWhiteSpace($Global:EntraOpsBaseFolder)) {
            throw "The EntraOps working folder is not set. Pass -DestinationPath or import the module with 'Import-Module <path-to-EntraOps> -Force'."
        }
        $DestinationPath = Join-Path $Global:EntraOpsBaseFolder 'Reports'
    }
    $DestinationPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($DestinationPath)
    if ((Test-Path -LiteralPath $DestinationPath) -and -not $Force) {
        throw "Reports folder '$DestinationPath' already exists. Use -Force to update its app files; generated report data is kept."
    }

    $Archive = Get-EntraOpsSourceArchive -Repository $Repository -Ref $Ref -PersonalAccessToken $PersonalAccessToken
    try {
        $SourceReports = Join-Path $Archive.SourceRoot 'Reports'
        if (-not (Test-Path -LiteralPath (Join-Path $SourceReports 'index.html') -PathType Leaf)) {
            throw "The download of $($Archive.Repository) at '$Ref' doesn't contain Reports/index.html. No local folder was changed."
        }
        if ($PSCmdlet.ShouldProcess($DestinationPath, "Install the reporting apps from $($Archive.Repository) at '$Ref'")) {
            # <App>/data/* holds the generated report data of this installation.
            $Result = Copy-EntraOpsSourceFolder -Source $SourceReports -Destination $DestinationPath -KeepPattern '^[^/\\]+[/\\]data[/\\]' -Force
            Write-Host "Installed $($Result.Installed) EntraOps reporting app file(s) from $($Archive.Repository) at '$Ref' to $DestinationPath$(if ($Result.Kept) { " (kept $($Result.Kept) existing report data file(s))" })."
            [pscustomobject]@{
                Path          = $DestinationPath
                Repository    = $Archive.Repository
                Ref           = $Ref
                InstalledFile = $Result.Installed
                KeptDataFile  = $Result.Kept
            }
        }
    } finally {
        Remove-Item -LiteralPath $Archive.TemporaryFolder -Recurse -Force -ErrorAction SilentlyContinue -WhatIf:$false
    }
}
