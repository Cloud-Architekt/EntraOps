function Save-EntraOpsEAMRbacSystemJson {
    <#
    .SYNOPSIS
        Saves EAM data for a single RBAC system to JSON files.
    .DESCRIPTION
        Shared helper that replaces the ~50-line save block duplicated 5 times in
        Save-EntraOpsPrivilegedEAMJson. Handles cleanup, directory creation,
        aggregate JSON export, and parallel per-object JSON writes.
    .PARAMETER ExportFolder
        The target export folder for this RBAC system.
    .PARAMETER RbacSystemName
        Display name for progress messages (e.g., "EntraID", "Defender").
    .PARAMETER EamData
        The EAM classified objects to save.
    .PARAMETER AggregateFileName
        Name of the aggregate JSON file (e.g., "EntraID.json").
    .PARAMETER ExportTransitiveByNestingDetails
        When $true (default), TransitiveByNestingObjectIds and TransitiveByNestingDisplayNames
        are included in the exported JSON. Set to $false to omit these fields.
    .PARAMETER ExportTaggedByDetails
        When $true (default), TaggedByObjectIds, TaggedByObjectDisplayNames, and
        TaggedByRoleSystem are included in the exported JSON. Set to $false to omit these fields.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$ExportFolder,

        [Parameter(Mandatory = $true)]
        [string]$RbacSystemName,

        [Parameter(Mandatory = $true)]
        [AllowNull()]
        [object]$EamData,

        [Parameter(Mandatory = $true)]
        [string]$AggregateFileName,

        [Parameter(Mandatory = $false)]
        [bool]$ExportTransitiveByNestingDetails = $true,

        [Parameter(Mandatory = $false)]
        [bool]$ExportTaggedByDetails = $true
    )

    # --- Path safety: ensure ExportFolder is under the expected base directory ---
    $ResolvedExportFolder = [System.IO.Path]::GetFullPath($ExportFolder)
    $ResolvedBaseFolder = [System.IO.Path]::GetFullPath($EntraOpsBaseFolder)

    # Guard against misconfigured paths that could cause destructive deletion outside the workspace
    if (-not $ResolvedExportFolder.StartsWith($ResolvedBaseFolder, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Security check failed: ExportFolder '$ResolvedExportFolder' is not under the expected base directory '$ResolvedBaseFolder'. Aborting to prevent accidental data loss."
    }

    # Additional safety: reject obviously dangerous root-level or short paths
    if ($ResolvedExportFolder.Length -le 4 -or $ResolvedExportFolder -in @('/', '\', 'C:\', "$HOME", "$env:USERPROFILE")) {
        throw "Security check failed: ExportFolder '$ResolvedExportFolder' resolves to a system-critical path. Aborting."
    }

    # Clean up and recreate export folder
    if (Test-Path -Path $ExportFolder) {
        Write-Host "Cleaning up old files in $ExportFolder..." -ForegroundColor Gray
        $FilesToDelete = Get-ChildItem -Path $ExportFolder -Recurse -File -Force -ErrorAction SilentlyContinue
        $TotalToDelete = $FilesToDelete.Count

        if ($TotalToDelete -gt 0) {
            $i = 0
            foreach ($File in $FilesToDelete) {
                $i++
                if ($i % 20 -eq 0 -or $i -eq $TotalToDelete) {
                    Write-Progress -Activity "Cleaning up $RbacSystemName" -Status "Deleting file $i of $TotalToDelete" -PercentComplete (($i / $TotalToDelete) * 100)
                }
                Remove-Item $File.FullName -Force -ErrorAction SilentlyContinue
            }
        }
        Remove-Item $ExportFolder -Force -Recurse -ErrorAction SilentlyContinue | Out-Null
        Write-Progress -Activity "Cleaning up $RbacSystemName" -Completed
    }
    New-Item $ExportFolder -ItemType Directory -Force | Out-Null

    if ($null -eq $EamData -or @($EamData).Count -eq 0) {
        Write-Warning "Result for $RbacSystemName is empty because of an issue or empty entries in the RBAC system."
        return
    }

    # Pre-filter
    $OriginalCount = @($EamData).Count
    $EamData = @($EamData | Where-Object { $null -ne $_.ObjectType -and $null -ne $_.ObjectId })
    $FilteredCount = $EamData.Count
    if ($FilteredCount -ne $OriginalCount) {
        Write-Warning "Filtered out $($OriginalCount - $FilteredCount) objects with null ObjectType or ObjectId before saving."
    }

    $EamData = $EamData | Sort-Object ObjectDisplayName, ObjectType, ObjectId

    # Strip optional detail properties based on export flags
    $ExcludeProperties = @()
    if (-not $ExportTransitiveByNestingDetails) {
        $ExcludeProperties += 'TransitiveByNestingObjectIds', 'TransitiveByNestingDisplayNames'
    }
    if (-not $ExportTaggedByDetails) {
        $ExcludeProperties += 'TaggedByObjectIds', 'TaggedByObjectDisplayNames', 'TaggedByRoleSystem'
    }
    if ($ExcludeProperties.Count -gt 0) {
        $EamData = $EamData | Select-Object -ExcludeProperty $ExcludeProperties
    }

    # Save aggregate JSON
    $EamData | ConvertTo-Json -Depth 10 | Out-File -Path "$ExportFolder/$AggregateFileName" -Force

    # Create subdirectories per object type
    $EamData | Group-Object ObjectType | ForEach-Object {
        $Dir = "$ExportFolder/$($_.Name)"
        if (-not (Test-Path $Dir)) { New-Item -ItemType Directory -Force -Path $Dir | Out-Null }
    }

    # Parallel per-object JSON writes
    $Results = $EamData | ForEach-Object -Parallel {
        $Obj = $_
        $Path = "$using:ExportFolder/$($Obj.ObjectType)/$($Obj.ObjectId).json"
        try {
            $Obj | ConvertTo-Json -Depth 10 | Out-File -Path $Path -Force -ErrorAction Stop
            $true
        } catch {
            Write-Warning "Failed to save file for $($Obj.ObjectId): $_"
            $false
        }
    } -ThrottleLimit 50

    $SuccessCount = ($Results | Where-Object { $_ -eq $true }).Count
    if ($SuccessCount -ne $EamData.Count) {
        Write-Warning "Parallel file write had failures. Expected: $($EamData.Count), Success: $SuccessCount"
    }

    Write-Host "Saved $($EamData.Count) $RbacSystemName objects to $ExportFolder" -ForegroundColor Green
}
