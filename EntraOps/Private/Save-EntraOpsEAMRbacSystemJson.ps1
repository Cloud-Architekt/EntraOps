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
        When $true (default), TransitiveByNestingObjectIds and TransitiveByNestingObjectDisplayNames
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
    # Resolved against the PowerShell location: GetFullPath would use the process directory
    $ResolvedExportFolder = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($ExportFolder)
    $ResolvedBaseFolder = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($EntraOpsBaseFolder)

    # Guard against misconfigured paths that could cause destructive deletion outside the workspace
    if (-not (Test-EntraOpsPathWithinRoot -Path $ExportFolder -Root $EntraOpsBaseFolder)) {
        throw "Security check failed: ExportFolder '$ResolvedExportFolder' is not under the expected base directory '$ResolvedBaseFolder'. Aborting to prevent accidental data loss."
    }

    # Additional safety: reject obviously dangerous root-level or short paths
    if ($ResolvedExportFolder.Length -le 4 -or $ResolvedExportFolder -in @('/', '\', 'C:\', "$HOME", "$env:USERPROFILE")) {
        throw "Security check failed: ExportFolder '$ResolvedExportFolder' resolves to a system-critical path. Aborting."
    }

    # Refuse to touch the previous export when the new collection came back empty (error, throttling,
    # interrupted run): later pipeline stages depend on these files - IdentityGovernance classifies
    # catalog groups from the PREVIOUS run's Azure/EntraID exports since Azure is collected last -
    # so deleting a good previous state on an empty result silently degrades their classification.
    if ($null -eq $EamData -or @($EamData).Count -eq 0) {
        Write-Warning "Result for $RbacSystemName is empty because of an issue or empty entries in the RBAC system. Keeping previous export in $ExportFolder untouched."
        return
    }

    # Pre-filter (before the previous export is touched, so invalid input can never replace it)
    $OriginalCount = @($EamData).Count
    $EamData = @($EamData | Where-Object { $null -ne $_.ObjectType -and $null -ne $_.ObjectId })
    $FilteredCount = $EamData.Count
    if ($FilteredCount -ne $OriginalCount) {
        Write-Warning "Filtered out $($OriginalCount - $FilteredCount) objects with null ObjectType or ObjectId before saving."
    }

    # Validate ObjectType and ObjectId don't contain path traversal characters
    $PathTraversalPattern = '[/\\:*?"<>|]|\.\.'
    $SafeData = @($EamData | Where-Object {
            if ($_.ObjectType -match $PathTraversalPattern) {
                Write-Warning "Skipping object with unsafe ObjectType: $($_.ObjectType)"
                return $false
            }
            if ($_.ObjectId -match $PathTraversalPattern) {
                Write-Warning "Skipping object with unsafe ObjectId: $($_.ObjectId)"
                return $false
            }
            return $true
        })
    if ($SafeData.Count -ne $EamData.Count) {
        Write-Warning "Filtered out $($EamData.Count - $SafeData.Count) objects with path traversal characters in ObjectType or ObjectId."
    }
    $EamData = $SafeData
    if ($EamData.Count -eq 0) {
        Write-Warning "No valid $RbacSystemName objects remain after validation. Keeping previous export in $ExportFolder untouched."
        return
    }

    $EamData = @($EamData | Sort-Object ObjectDisplayName, ObjectType, ObjectId)

    # A single-item pipeline result collapses an array into one value, so the JSON shape would depend
    # on the number of entries and change between runs. Classification collections are always written as arrays.
    $ArrayShapedEntryProperties = @('MatchedActions', 'ScopedObjects')
    $NormalizeClassificationShape = {
        param($Owner)
        $ClassificationProperty = $Owner.PSObject.Properties['Classification']
        if ($null -eq $ClassificationProperty -or $null -eq $ClassificationProperty.Value) { return }
        # A scalar string is not a collapsed entry but an unsupported shape; it is left for Test-EntraOpsGeneratedArtifacts to reject.
        if ($ClassificationProperty.Value -is [string]) { return }
        if ($ClassificationProperty.Value -isnot [array]) { $Owner.Classification = @($ClassificationProperty.Value) }
        foreach ($Entry in @($Owner.Classification)) {
            if ($null -eq $Entry) { continue }
            foreach ($PropertyName in $ArrayShapedEntryProperties) {
                if ($Entry -is [System.Collections.IDictionary]) {
                    if ($Entry.Contains($PropertyName) -and $null -ne $Entry[$PropertyName] -and $Entry[$PropertyName] -isnot [array]) {
                        $Entry[$PropertyName] = @($Entry[$PropertyName])
                    }
                    continue
                }
                $EntryProperty = $Entry.PSObject.Properties[$PropertyName]
                if ($null -ne $EntryProperty -and $null -ne $EntryProperty.Value -and $EntryProperty.Value -isnot [array]) {
                    $Entry.$PropertyName = @($EntryProperty.Value)
                }
            }
        }
    }

    # Ensure stable RoleAssignments schema so null-only fields are still included in JSON output.
    foreach ($EamObject in $EamData) {
        & $NormalizeClassificationShape $EamObject
        if ($null -eq $EamObject.RoleAssignments) {
            continue
        }

        $SeenRoleAssignments = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
        $UniqueRoleAssignments = [System.Collections.Generic.List[object]]::new()
        foreach ($RoleAssignment in @($EamObject.RoleAssignments)) {
            if ($null -eq $RoleAssignment) {
                continue
            }
            & $NormalizeClassificationShape $RoleAssignment

            if (-not $RoleAssignment.PSObject.Properties.Match('RoleAssignmentInstanceId').Count -or [string]::IsNullOrWhiteSpace("$($RoleAssignment.RoleAssignmentInstanceId)")) {
                $RoleAssignment | Add-Member -NotePropertyName 'RoleAssignmentInstanceId' -NotePropertyValue (
                    Get-EntraOpsRoleAssignmentInstanceId -RoleSystem $RbacSystemName -RoleAssignment $RoleAssignment
                ) -Force
            }

            if (-not $RoleAssignment.PSObject.Properties.Match('TransitiveByNestingObjectIds').Count) {
                $RoleAssignment | Add-Member -NotePropertyName 'TransitiveByNestingObjectIds' -NotePropertyValue $null -Force
            }

            if (-not $RoleAssignment.PSObject.Properties.Match('TransitiveByNestingObjectDisplayNames').Count) {
                $RoleAssignment | Add-Member -NotePropertyName 'TransitiveByNestingObjectDisplayNames' -NotePropertyValue $null -Force
            }

            # RoleAssignmentInstanceId identifies the normalized source row; the ordered nesting
            # chain distinguishes separate transitive paths through which that row reaches an object.
            $NestingObjectIds = @($RoleAssignment.TransitiveByNestingObjectIds | ForEach-Object {
                    if ($null -eq $_) { '' } else { "$($_)".Trim().ToLowerInvariant() }
                })
            $AssignmentKey = @(
                "$($RoleAssignment.RoleAssignmentInstanceId)".Trim().ToLowerInvariant(),
                ($NestingObjectIds -join [char]0x1E)
            ) -join [char]0x1F
            if ($SeenRoleAssignments.Add($AssignmentKey)) {
                $UniqueRoleAssignments.Add($RoleAssignment)
            }
        }

        if ($UniqueRoleAssignments.Count -ne @($EamObject.RoleAssignments).Count) {
            Write-Verbose "Removed $(@($EamObject.RoleAssignments).Count - $UniqueRoleAssignments.Count) exact duplicate role assignment row(s) for object '$($EamObject.ObjectId)' in $RbacSystemName."
        }
        $EamObject.RoleAssignments = $UniqueRoleAssignments.ToArray()
    }

    # Strip optional detail properties based on export flags
    $ExcludeProperties = @()
    if (-not $ExportTransitiveByNestingDetails) {
        $ExcludeProperties += 'TransitiveByNestingObjectIds', 'TransitiveByNestingObjectDisplayNames'
    }
    if (-not $ExportTaggedByDetails) {
        $ExcludeProperties += 'TaggedByObjectIds', 'TaggedByObjectDisplayNames', 'TaggedByRoleSystem'
    }
    if ($ExcludeProperties.Count -gt 0) {
        $EamData = @($EamData | Select-Object -ExcludeProperty $ExcludeProperties)
    }

    # Write to a staging folder and replace the previous export only after every file was written
    $ExportParentFolder = Split-Path -Path $ResolvedExportFolder -Parent
    $ExportFolderName = Split-Path -Path $ResolvedExportFolder -Leaf
    $OperationId = [guid]::NewGuid().ToString('N')
    $StagingFolder = Join-Path $ExportParentFolder ".$ExportFolderName.staging-$OperationId"
    $BackupFolder = Join-Path $ExportParentFolder ".$ExportFolderName.backup-$OperationId"

    try {
        New-Item -Path $StagingFolder -ItemType Directory -Force | Out-Null

        # Save aggregate JSON; -InputObject keeps a single object as a one-element array
        ConvertTo-Json -InputObject $EamData -Depth 10 | Out-File -Path (Join-Path $StagingFolder $AggregateFileName) -Force -ErrorAction Stop

        # Create subdirectories per object type
        $EamData | Group-Object ObjectType | ForEach-Object {
            New-Item -ItemType Directory -Force -Path (Join-Path $StagingFolder $_.Name) | Out-Null
        }

        # Parallel per-object JSON writes. The runspaces have no access to module-private functions,
        # so the containment prefix is precomputed here instead of calling Test-EntraOpsPathWithinRoot.
        $StagingFolderPrefix = [System.IO.Path]::TrimEndingDirectorySeparator($StagingFolder) + [System.IO.Path]::DirectorySeparatorChar
        $Results = $EamData | ForEach-Object -Parallel {
            $Obj = $_
            $Path = "$using:StagingFolder/$($Obj.ObjectType)/$($Obj.ObjectId).json"
            # Final resolved-path check to guard against path traversal
            $ResolvedPath = [System.IO.Path]::GetFullPath($Path)
            if (-not $ResolvedPath.StartsWith($using:StagingFolderPrefix, [System.StringComparison]::Ordinal)) {
                Write-Warning "Path traversal detected for ObjectId '$($Obj.ObjectId)', skipping."
                return $false
            }
            try {
                $Obj | ConvertTo-Json -Depth 10 | Out-File -Path $Path -Force -ErrorAction Stop
                $true
            } catch {
                Write-Warning "Failed to save file for $($Obj.ObjectId): $_"
                $false
            }
        } -ThrottleLimit 50

        $SuccessCount = @($Results | Where-Object { $_ -eq $true }).Count
        if ($SuccessCount -ne $EamData.Count) {
            throw "Parallel file write had failures. Expected: $($EamData.Count), Success: $SuccessCount. Keeping previous export in $ExportFolder untouched."
        }

        if (Test-Path -LiteralPath $ResolvedExportFolder) {
            Write-Host "Replacing previous export in $ExportFolder..." -ForegroundColor Gray
            Move-Item -LiteralPath $ResolvedExportFolder -Destination $BackupFolder -ErrorAction Stop
        }
        try {
            Move-Item -LiteralPath $StagingFolder -Destination $ResolvedExportFolder -ErrorAction Stop
        } catch {
            if (Test-Path -LiteralPath $BackupFolder) {
                Move-Item -LiteralPath $BackupFolder -Destination $ResolvedExportFolder -ErrorAction SilentlyContinue
            }
            throw "Failed to replace the export in $ExportFolder. The previous export was restored. Error: $($_.Exception.Message)"
        }
    } finally {
        if (Test-Path -LiteralPath $StagingFolder) {
            Remove-Item -LiteralPath $StagingFolder -Recurse -Force -ErrorAction SilentlyContinue
        }
        # The backup is the only copy of the previous export until an export folder is in place again.
        if (Test-Path -LiteralPath $BackupFolder) {
            if (Test-Path -LiteralPath $ResolvedExportFolder) {
                Remove-Item -LiteralPath $BackupFolder -Recurse -Force -ErrorAction SilentlyContinue
            } else {
                Write-Warning "The previous export of $RbacSystemName could not be restored and was kept in $BackupFolder."
            }
        }
    }

    Write-Host "Saved $($EamData.Count) $RbacSystemName objects to $ExportFolder" -ForegroundColor Green
}
