function Get-EntraOpsClassificationSourceCache {
    <#
    .SYNOPSIS
        Returns a folder that contains the AzurePrivilegedIAM classification catalog files, downloaded into the EntraOps user cache on demand.

    .DESCRIPTION
        Replaces a (temporary) git clone of the AzurePrivilegedIAM repository for reporting. Only the requested
        Classification/<file>.json files are downloaded from raw.githubusercontent.com into
        <PersistentCachePath>/AzurePrivilegedIAM/<Ref>/Classification and re-used until MaxAgeHours has elapsed.
        The subfolder is not removed by Clear-EntraOpsCache or Disconnect-EntraOps, which only delete top-level *.json
        files of the cache folder. A failed refresh falls back to an older cached copy of the file. The returned path
        can be used as RepoRoot / search root because the files keep the 'Classification/' sub-path of the repository.
        Returns $null when none of the requested files is available.

    .PARAMETER FileName
        Classification catalog files to provide. Defaults to the eight files the Classification Explorer needs.

    .PARAMETER CachePath
        Base folder of the cache. Defaults to <PersistentCachePath>/AzurePrivilegedIAM of the EntraOps session.

    .PARAMETER Ref
        Branch, tag or commit SHA of the AzurePrivilegedIAM repository. Default is 'main'.

    .PARAMETER MaxAgeHours
        Maximum age of a cached file before it is downloaded again. Default is 24 hours; 0 always downloads.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param (
        [Parameter(Mandatory = $false)]
        [ValidatePattern('^Classification_[A-Za-z0-9]+\.json$')]
        [string[]]$FileName = @(
            'Classification_EntraIdDirectoryRoles.json',
            'Classification_EntraIdDirectoryRolesFromMsftDocs.json',
            'Classification_IdentityGovernance.json',
            'Classification_AzureResources.json',
            'Classification_DeviceManagementRoles.json',
            'Classification_ApiPermissions.json',
            'Classification_AppRoles.json',
            'Classification_Scopes.json'
        ),

        [Parameter(Mandatory = $false)]
        [string]$CachePath,

        [Parameter(Mandatory = $false)]
        [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9._/-]{0,199}$')]
        [string]$Ref = 'main',

        [Parameter(Mandatory = $false)]
        [ValidateRange(0, 8760)]
        [int]$MaxAgeHours = 24
    )

    if ($Ref -match '\.\.') {
        throw "Unsupported ref '$Ref'. Use a branch, release tag or full commit SHA."
    }

    if ([string]::IsNullOrWhiteSpace($CachePath)) {
        $Session = Get-Variable -Name __EntraOpsSession -Scope Script -ValueOnly -ErrorAction SilentlyContinue
        $BasePath = if ($Session -and -not [string]::IsNullOrWhiteSpace($Session.PersistentCachePath)) {
            $Session.PersistentCachePath
        } else {
            Join-Path ([System.IO.Path]::GetTempPath()) 'EntraOps'
        }
        $CachePath = Join-Path $BasePath 'AzurePrivilegedIAM'
    }

    $CacheRoot = Join-Path $CachePath ($Ref -replace '[^A-Za-z0-9._-]', '_')
    $ClassificationFolder = Join-Path $CacheRoot 'Classification'
    $OldestAcceptedUtc = [datetime]::UtcNow.AddHours(-$MaxAgeHours)
    $AvailableCount = 0

    foreach ($Name in $FileName) {
        $Target = Join-Path $ClassificationFolder $Name
        $HasCachedCopy = Test-Path -LiteralPath $Target -PathType Leaf
        if ($HasCachedCopy -and (Get-Item -LiteralPath $Target).LastWriteTimeUtc -gt $OldestAcceptedUtc) {
            $AvailableCount++
            continue
        }

        $TemporaryFile = "$Target.$([guid]::NewGuid().ToString('N')).tmp"
        $SourceUri = "https://raw.githubusercontent.com/Cloud-Architekt/AzurePrivilegedIAM/$Ref/Classification/$Name"
        try {
            New-Item -ItemType Directory -Path $ClassificationFolder -Force -WhatIf:$false | Out-Null
            Write-Verbose "Downloading $SourceUri"
            Invoke-WebRequest -Uri $SourceUri -Headers @{ 'User-Agent' = 'EntraOps' } -OutFile $TemporaryFile -UseBasicParsing -TimeoutSec 120
            # Reject truncated or non-JSON (for example HTML error page) content before it replaces a good copy.
            $Stream = [System.IO.File]::OpenRead($TemporaryFile)
            try { [System.Text.Json.JsonDocument]::Parse($Stream).Dispose() } finally { $Stream.Dispose() }
            Move-Item -LiteralPath $TemporaryFile -Destination $Target -Force -WhatIf:$false
            $AvailableCount++
        } catch {
            if ($HasCachedCopy) {
                Write-Warning "Could not refresh $Name from AzurePrivilegedIAM ($Ref): $($_.Exception.Message) Using the cached copy from $Target."
                $AvailableCount++
            } else {
                Write-Warning "Could not download $Name from AzurePrivilegedIAM ($Ref): $($_.Exception.Message)"
            }
        } finally {
            Remove-Item -LiteralPath $TemporaryFile -Force -ErrorAction SilentlyContinue -WhatIf:$false
        }
    }

    if ($AvailableCount -eq 0) { return $null }
    return $CacheRoot
}
