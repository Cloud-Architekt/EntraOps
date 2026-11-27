function Get-EntraOpsSourceArchive {
    <#
    .SYNOPSIS
        Downloads and extracts the GitHub source archive of an EntraOps distribution repository.

    .DESCRIPTION
        Returns the extracted repository root (SourceRoot), the temporary folder, which the caller must
        remove, and the ModuleVersion of the downloaded content (ContentVersion). Nothing outside the
        temporary folder is changed. The public repository is downloaded from github.com/<repo>/archive,
        which doesn't count against the GitHub API rate limit; the private Insiders repository through the
        API with the personal access token.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateSet('EntraOps', 'EntraOps-Insiders')]
        [string]$Repository,

        [Parameter(Mandatory = $true)]
        [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9._/-]{0,199}$')]
        [string]$Ref,

        [Parameter(Mandatory = $false)]
        [string]$PersonalAccessToken
    )

    if ($Ref -match '\.\.') {
        throw "Unsupported ref '$Ref'. Use a branch, release tag or full commit SHA."
    }
    if ([string]::IsNullOrWhiteSpace($PersonalAccessToken) -and -not [string]::IsNullOrWhiteSpace($env:ENTRAOPS_PAT)) {
        $PersonalAccessToken = $env:ENTRAOPS_PAT
    }
    if ($Repository -eq 'EntraOps-Insiders' -and [string]::IsNullOrWhiteSpace($PersonalAccessToken)) {
        throw "Repository 'EntraOps-Insiders' is private and requires -PersonalAccessToken or ENTRAOPS_PAT. Use the public 'EntraOps' repository otherwise."
    }
    $SourceUri = if ($Repository -eq 'EntraOps-Insiders') {
        "https://api.github.com/repos/Cloud-Architekt/$Repository/zipball/$Ref"
    } else {
        "https://github.com/Cloud-Architekt/$Repository/archive/$Ref.zip"
    }

    $TemporaryFolder = Join-Path ([System.IO.Path]::GetTempPath()) "EntraOpsSource-$([guid]::NewGuid().ToString('N'))"
    try {
        New-Item -ItemType Directory -Path $TemporaryFolder -Force -WhatIf:$false | Out-Null
        $ArchivePath = Join-Path $TemporaryFolder 'source.zip'
        $ExtractPath = Join-Path $TemporaryFolder 'source'
        Write-Verbose "Downloading Cloud-Architekt/$Repository at '$Ref' from $SourceUri"
        try {
            # The personal access token is only sent to the Insiders repository; for the public repository,
            # GITHUB_TOKEN or GH_TOKEN of the environment raises the rate limit.
            $DownloadToken = if ($Repository -eq 'EntraOps-Insiders') { $PersonalAccessToken } else { $null }
            Invoke-EntraOpsGitHubRequest -Uri $SourceUri -Token $DownloadToken -OutFile $ArchivePath
        } catch {
            throw "Download of Cloud-Architekt/$Repository at '$Ref' failed: $($_.Exception.Message) Verify the ref and, for 'EntraOps-Insiders', the token. No local folder was changed."
        }
        Expand-Archive -LiteralPath $ArchivePath -DestinationPath $ExtractPath -Force -WhatIf:$false

        # GitHub source archives contain one top-level folder (<owner>-<repo>-<sha>).
        $SourceRoot = @(Get-ChildItem -LiteralPath $ExtractPath -Directory)
        if ($SourceRoot.Count -ne 1) {
            throw "The download of Cloud-Architekt/$Repository at '$Ref' has an unexpected layout. No local folder was changed."
        }
        $ContentVersion = $null
        $ContentManifest = Join-Path $SourceRoot[0].FullName 'EntraOps/EntraOps.psd1'
        if (Test-Path -LiteralPath $ContentManifest -PathType Leaf) {
            $ParsedVersion = [version]::new(0, 0)
            try {
                if ([version]::TryParse([string](Import-PowerShellDataFile -LiteralPath $ContentManifest).ModuleVersion, [ref]$ParsedVersion)) { $ContentVersion = $ParsedVersion }
            } catch {
                Write-Verbose "The module manifest of the download could not be read: $($_.Exception.Message)"
            }
        }
        return [pscustomobject]@{
            SourceRoot      = $SourceRoot[0].FullName
            TemporaryFolder = $TemporaryFolder
            Repository      = "Cloud-Architekt/$Repository"
            Ref             = $Ref
            ContentVersion  = $ContentVersion
        }
    } catch {
        Remove-Item -LiteralPath $TemporaryFolder -Recurse -Force -ErrorAction SilentlyContinue -WhatIf:$false
        throw
    }
}
