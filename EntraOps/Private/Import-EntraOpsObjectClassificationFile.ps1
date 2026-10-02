function Import-EntraOpsObjectClassificationFile {
    <#
    .SYNOPSIS
        Loads and validates the Object Classification File configured in EntraOpsConfig.json.
    .DESCRIPTION
        The Object Classification File is a declarative list of object IDs with an intended Enterprise
        Access Model tier (JSON array or CSV with the columns ObjectId, ObjectType, ObjectDisplayName,
        AdminTierLevelName, Justification). It is data, not code: rows are only matched by ObjectId and
        the tier name must be one of the canonical tier names. The tier level is always derived from
        the tier name, so a file entry can never produce a contradictory ObjectAdminTierLevel pair.

        Invalid rows are skipped with a warning. When the same ObjectId is listed with different tiers,
        the most privileged tier wins (Enterprise Access Model principle). The parsed result is cached
        per session by resolved path and last write time, because the collector calls this per object.
    .PARAMETER FilePath
        Path of the file, relative to RootFolder or absolute. Must resolve inside RootFolder.
    .PARAMETER RootFolder
        EntraOps repository root. Defaults to $EntraOpsBaseFolder.
    .OUTPUTS
        [hashtable] keyed by lowercase ObjectId with PSCustomObject values (ObjectId, ObjectType,
        ObjectDisplayName, AdminTierLevel, AdminTierLevelName, Justification). Empty when the file
        does not exist.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param (
        [Parameter(Mandatory = $true)]
        [System.String]$FilePath,

        [Parameter(Mandatory = $false)]
        [System.String]$RootFolder = $EntraOpsBaseFolder
    )

    if ([string]::IsNullOrWhiteSpace($RootFolder)) {
        throw "Object Classification File: the EntraOps root folder is not known. Import the EntraOps module or pass -RootFolder."
    }

    $ResolvedPath = if ([System.IO.Path]::IsPathFullyQualified($FilePath)) {
        [System.IO.Path]::GetFullPath($FilePath)
    } else {
        [System.IO.Path]::GetFullPath([System.IO.Path]::Combine($RootFolder, $FilePath))
    }
    if (-not (Test-EntraOpsPathWithinRoot -Path $ResolvedPath -Root $RootFolder)) {
        throw "Object Classification File '$FilePath' resolves to '$ResolvedPath', which is outside the EntraOps root folder '$RootFolder'."
    }

    $Extension = [System.IO.Path]::GetExtension($ResolvedPath).ToLowerInvariant()
    if ($Extension -notin @('.json', '.csv')) {
        throw "Object Classification File '$ResolvedPath' must be a .json or .csv file."
    }

    $FileExists = Test-Path -LiteralPath $ResolvedPath -PathType Leaf
    $CacheKey = if ($FileExists) { "$ResolvedPath|$([System.IO.File]::GetLastWriteTimeUtc($ResolvedPath).Ticks)" } else { "$ResolvedPath|missing" }
    if ($null -ne $Script:ObjectClassificationFileCache -and $Script:ObjectClassificationFileCache.Key -eq $CacheKey) {
        return $Script:ObjectClassificationFileCache.Entries
    }

    $Entries = @{}
    if (-not $FileExists) {
        Write-Warning "Object Classification File is enabled but '$ResolvedPath' does not exist. No object is classified by the file."
        $Script:ObjectClassificationFileCache = @{ Key = $CacheKey; Entries = $Entries }
        return $Entries
    }

    $Content = [System.IO.File]::ReadAllText($ResolvedPath)
    $Rows = @()
    if (-not [string]::IsNullOrWhiteSpace($Content)) {
        try {
            $Rows = if ($Extension -eq '.json') { @($Content | ConvertFrom-Json -Depth 5 -ErrorAction Stop) } else { @($Content | ConvertFrom-Csv -ErrorAction Stop) }
        } catch {
            throw "Object Classification File '$ResolvedPath' could not be parsed: $($_.Exception.Message)"
        }
    }

    $TierLevelByName = [ordered]@{ ControlPlane = '0'; ManagementPlane = '1'; WorkloadPlane = '1'; UserAccess = '2' }
    $TierRank = @{ ControlPlane = 0; ManagementPlane = 1; WorkloadPlane = 2; UserAccess = 3 }
    $ObjectTypes = @{ user = 'user'; group = 'group'; serviceprincipal = 'serviceprincipal'; application = 'application' }
    $GuidPattern = '^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$'

    $RowNumber = 0
    foreach ($Row in $Rows) {
        $RowNumber++
        if ($null -eq $Row) { continue }
        $ObjectId = "$($Row.ObjectId)".Trim()
        $TierName = "$($Row.AdminTierLevelName)".Trim()
        $ObjectType = "$($Row.ObjectType)".Trim().ToLowerInvariant()

        if ($ObjectId -notmatch $GuidPattern) {
            Write-Warning "Object Classification File row $($RowNumber): ObjectId '$ObjectId' is not a GUID. Row skipped."
            continue
        }
        $CanonicalTierName = @($TierLevelByName.Keys | Where-Object { $_ -eq $TierName })[0]
        if ($null -eq $CanonicalTierName) {
            Write-Warning "Object Classification File row $($RowNumber) ($ObjectId): AdminTierLevelName '$TierName' is not one of $($TierLevelByName.Keys -join ', '). Row skipped."
            continue
        }
        if (-not [string]::IsNullOrEmpty($ObjectType) -and -not $ObjectTypes.ContainsKey($ObjectType)) {
            Write-Warning "Object Classification File row $($RowNumber) ($ObjectId): ObjectType '$($Row.ObjectType)' is not one of $($ObjectTypes.Keys -join ', '). Row skipped."
            continue
        }

        $Key = $ObjectId.ToLowerInvariant()
        $Entry = [PSCustomObject]@{
            ObjectId           = $Key
            ObjectType         = $ObjectType
            ObjectDisplayName  = "$($Row.ObjectDisplayName)"
            AdminTierLevel     = $TierLevelByName[$CanonicalTierName]
            AdminTierLevelName = $CanonicalTierName
            Justification      = "$($Row.Justification)"
        }
        if ($Entries.ContainsKey($Key)) {
            $Existing = $Entries[$Key]
            if ($Existing.AdminTierLevelName -ne $CanonicalTierName) {
                Write-Warning "Object Classification File lists $ObjectId more than once with different tiers ($($Existing.AdminTierLevelName), $CanonicalTierName). The most privileged tier is used."
                if ($TierRank[$CanonicalTierName] -lt $TierRank[$Existing.AdminTierLevelName]) { $Entries[$Key] = $Entry }
            }
            continue
        }
        $Entries[$Key] = $Entry
    }

    Write-Verbose "Object Classification File '$ResolvedPath' loaded with $($Entries.Count) valid entr$(if ($Entries.Count -eq 1) { 'y' } else { 'ies' })."
    $Script:ObjectClassificationFileCache = @{ Key = $CacheKey; Entries = $Entries }
    return $Entries
}
