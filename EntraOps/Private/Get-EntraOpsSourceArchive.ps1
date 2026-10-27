function Get-EntraOpsSourceArchive {
    <#
    .SYNOPSIS
        Downloads and extracts the GitHub source archive of an EntraOps distribution repository.

    .DESCRIPTION
        Returns the extracted repository root (SourceRoot) and the temporary folder, which the caller
        must remove. Nothing outside the temporary folder is changed.
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
    $Headers = @{ 'User-Agent' = 'EntraOps'; 'Accept' = 'application/vnd.github+json' }
    if ($Repository -eq 'EntraOps-Insiders') {
        if ([string]::IsNullOrWhiteSpace($PersonalAccessToken)) {
            throw "Repository 'EntraOps-Insiders' is private and requires -PersonalAccessToken or ENTRAOPS_PAT. Use the public 'EntraOps' repository otherwise."
        }
        $Headers['Authorization'] = "Bearer $PersonalAccessToken"
    }
    $SourceUri = "https://api.github.com/repos/Cloud-Architekt/$Repository/zipball/$Ref"

    $TemporaryFolder = Join-Path ([System.IO.Path]::GetTempPath()) "EntraOpsSource-$([guid]::NewGuid().ToString('N'))"
    try {
        New-Item -ItemType Directory -Path $TemporaryFolder -Force -WhatIf:$false | Out-Null
        $ArchivePath = Join-Path $TemporaryFolder 'source.zip'
        $ExtractPath = Join-Path $TemporaryFolder 'source'
        Write-Verbose "Downloading Cloud-Architekt/$Repository at '$Ref' from $SourceUri"
        try {
            Invoke-WebRequest -Uri $SourceUri -Headers $Headers -OutFile $ArchivePath -UseBasicParsing
        } catch {
            throw "Download of Cloud-Architekt/$Repository at '$Ref' failed: $($_.Exception.Message) Verify the ref and, for 'EntraOps-Insiders', the token. No local folder was changed."
        }
        Expand-Archive -LiteralPath $ArchivePath -DestinationPath $ExtractPath -Force -WhatIf:$false

        # GitHub source archives contain one top-level folder (<owner>-<repo>-<sha>).
        $SourceRoot = @(Get-ChildItem -LiteralPath $ExtractPath -Directory)
        if ($SourceRoot.Count -ne 1) {
            throw "The download of Cloud-Architekt/$Repository at '$Ref' has an unexpected layout. No local folder was changed."
        }
        return [pscustomobject]@{
            SourceRoot      = $SourceRoot[0].FullName
            TemporaryFolder = $TemporaryFolder
            Repository      = "Cloud-Architekt/$Repository"
            Ref             = $Ref
        }
    } catch {
        Remove-Item -LiteralPath $TemporaryFolder -Recurse -Force -ErrorAction SilentlyContinue -WhatIf:$false
        throw
    }
}
