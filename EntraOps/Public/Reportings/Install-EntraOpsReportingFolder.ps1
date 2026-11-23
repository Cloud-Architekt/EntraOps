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
    EntraOps distribution repository: the public 'EntraOps' release repository or the private
    'EntraOps-Insiders' repository, which requires -PersonalAccessToken or ENTRAOPS_PAT. Defaults to
    AutomatedEntraOpsUpdate.Repository of EntraOpsConfig.json in the folder that holds the Reports
    folder (the working folder by default), the release channel of the deployment, otherwise 'EntraOps'.

.PARAMETER Ref
    Branch, release tag or full commit SHA to download. Without it, the apps that match the module
    version are installed, so the apps and the generated data format fit together: from the repository
    checkout that contains the module (files tracked in git only), otherwise from the newest content of
    the main branch whose EntraOps.psd1 has the module version (branch head, release tag or commit). When the branch has no such commit (a
    module newer than the branch, for example an Insiders build), the branch head is installed with a
    warning. The source and version are recorded in .EntraOpsContent.json of the Reports folder.

.PARAMETER DestinationPath
    Target Reports folder. Defaults to the Reports folder in the EntraOps working folder, where the
    report data generators expect it.

.PARAMETER PersonalAccessToken
    GitHub token for the private 'EntraOps-Insiders' repository. Defaults to ENTRAOPS_PAT.

.PARAMETER Force
    Update an existing Reports folder. App files are replaced; generated report data is kept.

.PARAMETER KeepExistingWithoutMatch
    With -Force: keep the existing reporting apps when no apps of the module version are available
    (for example an Insiders module newer than the main branch), instead of replacing them with apps
    of another version. Invoke-EntraOpsAssessment uses it to update apps only to the module version.
    When the main branch already shows that it has no apps of the module version, nothing is downloaded.

.EXAMPLE
    Install-EntraOpsReportingFolder

    Installs the reporting apps that match the module version into the EntraOps working folder.

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
        [System.String]$Ref,

        [Parameter(Mandatory = $false)]
        [System.String]$DestinationPath,

        [Parameter(Mandatory = $false)]
        [System.String]$PersonalAccessToken,

        [Parameter(Mandatory = $false)]
        [switch]$Force,

        [Parameter(Mandatory = $false)]
        [switch]$KeepExistingWithoutMatch
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

    # Without -Repository, the apps follow the release channel of the deployment.
    if ($PSBoundParameters.ContainsKey('Repository')) {
        $RepositoryReason = '-Repository'
    } else {
        # The deployment that the Reports folder belongs to (the working folder for the default -DestinationPath).
        $SelectedRepository = Resolve-EntraOpsContentRepository -ConfigFilePath (Join-Path (Split-Path -Parent $DestinationPath) 'EntraOpsConfig.json')
        $Repository = $SelectedRepository.Repository
        $RepositoryReason = $SelectedRepository.Reason
    }
    Write-Host "Content repository: $Repository ($RepositoryReason)"

    $KeepExisting = $KeepExistingWithoutMatch -and (Test-Path -LiteralPath (Join-Path $DestinationPath 'index.html') -PathType Leaf)
    $Archive = Get-EntraOpsContentSource -Repository $Repository -Ref $Ref -PersonalAccessToken $PersonalAccessToken -Folder Reports -SkipDownloadWithoutMatch:$KeepExisting
    $SourceText = "$($Archive.Repository)$(if ($Archive.Ref) { " at '$($Archive.Ref)'" })"
    try {
        if (-not $Archive.Matched -and $KeepExisting) {
            Write-Warning "No reporting apps of the EntraOps module version $($Archive.ModuleVersion) are available from $SourceText (version $(if ($Archive.ContentVersion) { $Archive.ContentVersion } else { 'unknown' })). The existing apps in $DestinationPath are kept. Install matching apps with -Ref <branch or commit> (with -Repository EntraOps-Insiders for an Insiders build), or from a repository clone."
            return [pscustomobject]@{
                Path           = $DestinationPath
                Repository     = $Archive.Repository
                Ref            = $Archive.Ref
                ContentVersion = $Archive.ContentVersion
                Matched        = $false
                InstalledFile  = 0
                KeptDataFile   = 0
            }
        }
        $SourceReports = Join-Path $Archive.SourceRoot 'Reports'
        if (-not (Test-Path -LiteralPath (Join-Path $SourceReports 'index.html') -PathType Leaf)) {
            throw "The download of $SourceText doesn't contain Reports/index.html. No local folder was changed."
        }
        if (-not $Archive.Matched) {
            Write-Warning "The reporting apps of $SourceText are version $(if ($Archive.ContentVersion) { $Archive.ContentVersion } else { 'unknown' }), the EntraOps module is $($Archive.ModuleVersion): views and data of this module version can be missing. Install matching apps with -Ref <branch or commit> (with -Repository EntraOps-Insiders for an Insiders build), or from a repository clone."
        }
        if ($PSCmdlet.ShouldProcess($DestinationPath, "Install the reporting apps from $SourceText")) {
            # <App>/data/* holds the generated report data of this installation.
            # With -Force no app file is skipped, so the marker describes all apps (Initialize-EntraOpsWorkspace can keep some).
            $Result = Copy-EntraOpsSourceFolder -Source $SourceReports -Destination $DestinationPath -KeepPattern '^[^/\\]+[/\\]data[/\\]' -Force
            Write-EntraOpsContentMarker -Path $DestinationPath -Source $Archive
            Write-Host "Installed $($Result.Installed) EntraOps reporting app file(s) $(if ($Archive.ContentVersion) { "(version $($Archive.ContentVersion)) " })from $SourceText to $DestinationPath$(if ($Result.Kept) { " (kept $($Result.Kept) existing report data file(s))" })."
            [pscustomobject]@{
                Path           = $DestinationPath
                Repository     = $Archive.Repository
                Ref            = $Archive.Ref
                ContentVersion = $Archive.ContentVersion
                Matched        = $Archive.Matched
                InstalledFile  = $Result.Installed
                KeptDataFile   = $Result.Kept
            }
        }
    } finally {
        if ($Archive.TemporaryFolder) { Remove-Item -LiteralPath $Archive.TemporaryFolder -Recurse -Force -ErrorAction SilentlyContinue -WhatIf:$false }
    }
}
