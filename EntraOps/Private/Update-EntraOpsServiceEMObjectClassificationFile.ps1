<#
.SYNOPSIS
    Adds or removes ServiceEM group entries in the Object Classification File.

.DESCRIPTION
    Uses the file of the ObjectClassificationFile section of the loaded EntraOps configuration (default
    ./Classification/ObjectClassification.json below $EntraOpsBaseFolder). New entries are only added for
    object IDs that aren't listed yet; an existing entry with another tier is kept with a warning, because it
    may be a deliberate classification. -RemoveObjectIds removes the entries of deleted groups.

.PARAMETER Entries
    Entries to add, with ObjectId, ObjectDisplayName, AdminTierLevelName and Justification.

.PARAMETER RemoveObjectIds
    Object IDs whose entries are removed.

.PARAMETER logPrefix
    Text prepended to verbose and warning messages.
#>
function Update-EntraOpsServiceEMObjectClassificationFile {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [psobject[]]$Entries = @(),

        [string[]]$RemoveObjectIds = @(),

        [string]$logPrefix = ""
    )

    $fileConfig = $Global:EntraOpsConfig.ObjectClassificationFile
    $filePath = if (-not [string]::IsNullOrWhiteSpace($fileConfig.FilePath)) { [string]$fileConfig.FilePath } else { './Classification/ObjectClassification.json' }
    $rootFolder = $EntraOpsBaseFolder
    $resolvedPath = if ([System.IO.Path]::IsPathFullyQualified($filePath)) { [System.IO.Path]::GetFullPath($filePath) } else { [System.IO.Path]::GetFullPath([System.IO.Path]::Combine($rootFolder, $filePath)) }
    if (-not (Test-EntraOpsPathWithinRoot -Path $resolvedPath -Root $rootFolder)) {
        Write-Warning "$logPrefix Object Classification File '$filePath' is outside the EntraOps folder '$rootFolder'; it isn't updated."
        return
    }
    $extension = [System.IO.Path]::GetExtension($resolvedPath).ToLowerInvariant()
    if ($extension -notin @('.json', '.csv')) {
        Write-Warning "$logPrefix Object Classification File '$resolvedPath' must be a .json or .csv file; it isn't updated."
        return
    }

    $rows = [System.Collections.Generic.List[object]]::new()
    if (Test-Path -LiteralPath $resolvedPath -PathType Leaf) {
        $content = [System.IO.File]::ReadAllText($resolvedPath)
        if (-not [string]::IsNullOrWhiteSpace($content)) {
            try {
                $parsed = if ($extension -eq '.json') { @($content | ConvertFrom-Json -Depth 5 -ErrorAction Stop) } else { @($content | ConvertFrom-Csv -ErrorAction Stop) }
            } catch {
                Write-Warning "$logPrefix Object Classification File '$resolvedPath' could not be parsed and isn't updated: $($_.Exception.Message)"
                return
            }
            foreach ($row in $parsed) { if ($null -ne $row) { $rows.Add($row) } }
        }
    }

    $changed = $false
    $removeIds = @($RemoveObjectIds | ForEach-Object { "$_".ToLowerInvariant() })
    if ($removeIds.Count -gt 0) {
        $kept = @($rows | Where-Object { "$($_.ObjectId)".Trim().ToLowerInvariant() -notin $removeIds })
        $removed = $rows.Count - $kept.Count
        if ($removed -gt 0) {
            $rows = [System.Collections.Generic.List[object]]::new([object[]]$kept)
            Write-Verbose "$logPrefix Removed $removed entr$(if ($removed -eq 1) { 'y' } else { 'ies' }) from the Object Classification File"
            $changed = $true
        }
    }

    foreach ($entry in $Entries) {
        $existing = $rows | Where-Object { "$($_.ObjectId)".Trim() -eq $entry.ObjectId } | Select-Object -First 1
        if ($existing) {
            if ("$($existing.AdminTierLevelName)" -ne $entry.AdminTierLevelName) {
                Write-Warning "$logPrefix Object Classification File already lists $($entry.ObjectDisplayName) ($($entry.ObjectId)) as '$($existing.AdminTierLevelName)'; the entry is kept instead of '$($entry.AdminTierLevelName)'."
            }
            continue
        }
        $rows.Add([pscustomobject]@{
                ObjectId           = $entry.ObjectId
                ObjectType         = 'group'
                ObjectDisplayName  = $entry.ObjectDisplayName
                AdminTierLevelName = $entry.AdminTierLevelName
                Justification      = $entry.Justification
            })
        $changed = $true
    }

    if (-not $changed) { return }
    $directory = [System.IO.Path]::GetDirectoryName($resolvedPath)
    if (-not (Test-Path -LiteralPath $directory)) { New-Item -ItemType Directory -Path $directory -Force | Out-Null }
    if ($extension -eq '.json') {
        ConvertTo-Json -InputObject ([object[]]$rows.ToArray()) -Depth 5 | Set-Content -LiteralPath $resolvedPath -Encoding utf8NoBOM
    } else {
        $rows | Select-Object ObjectId, ObjectType, ObjectDisplayName, AdminTierLevelName, Justification |
        Export-Csv -LiteralPath $resolvedPath -NoTypeInformation -Encoding utf8NoBOM
    }
    if ($fileConfig.Enabled -ne $true) {
        Write-Warning "$logPrefix ObjectClassificationFile.Enabled is not true: the entries written to '$resolvedPath' aren't used for classification until it is enabled."
    }
    Write-Verbose "$logPrefix Object Classification File '$resolvedPath' updated; commit it to the repository"
    return $resolvedPath
}
