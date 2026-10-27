<#
.SYNOPSIS
    Validates the integrity of generated Privileged EAM exports and Tenant Governance snapshots.

.DESCRIPTION
    Checks the RBAC-system aggregate files (<PrivilegedEamPath>/<RbacSystem>/<RbacSystem>.json) for invalid JSON,
    missing or duplicate object IDs, role assignments without RoleAssignmentInstanceId, duplicate assignment paths,
    unsupported Classification shapes and Classification/MatchedActions/ScopedObjects collections that collapsed
    from an array into a single value. Optionally checks a Tenant Governance snapshot folder for its manifest,
    invalid JSON, resource types that don't match their folder, identities stored in multiple files and count
    mismatches with the manifest.
    Violations stop the validation with one error that lists all of them. Contradictory object tier pairs and
    privileged assignments without classification are reported as warnings unless the related switch is set.
    Collapsed collections in an aggregate file that is tracked by git and unchanged since HEAD were written by
    an earlier version (the RBAC system returned no data or is no longer collected) and are reported as one
    warning per file; the next non-empty export rewrites them as arrays.
    Used by the Privileged EAM pull workflow/pipeline and Invoke-EntraOpsTenantGovernanceSnapshot before generated
    artifacts are committed.

.PARAMETER PrivilegedEamPath
    Folder of the Privileged EAM export. Default is ./PrivilegedEAM. Pass an empty value to validate only
    -TenantGovernancePath.

.PARAMETER FailOnContradictoryTierPair
    Treats an object whose tier level contradicts its tier name (ObjectAdminTierLevel/ObjectAdminTierLevelName,
    e.g. 0/ManagementPlane) as violation instead of a warning.

.PARAMETER TenantGovernancePath
    Folder of the Tenant Governance snapshots (e.g. ./TenantGovernance/Snapshots) to validate. Not validated
    when empty (default).

.PARAMETER FailOnPrivilegedAssignmentWithoutClassification
    Treats a role assignment marked as privileged (RoleIsPrivileged) without classification as violation
    instead of a warning.

.EXAMPLE
    Validate the Privileged EAM export in the default folder.
    Test-EntraOpsGeneratedArtifacts

.EXAMPLE
    Validate the Privileged EAM export and the Tenant Governance snapshots, and fail on contradictory tier pairs.
    Test-EntraOpsGeneratedArtifacts -PrivilegedEamPath ./PrivilegedEAM -TenantGovernancePath ./TenantGovernance/Snapshots -FailOnContradictoryTierPair
#>
function Test-EntraOpsGeneratedArtifacts {
[CmdletBinding()]
param (
    [Parameter(Mandatory = $false)]
    [string]$PrivilegedEamPath = './PrivilegedEAM',

    [Parameter(Mandatory = $false)]
    [switch]$FailOnContradictoryTierPair,

    [Parameter(Mandatory = $false)]
    [string]$TenantGovernancePath,

    [Parameter(Mandatory = $false)]
    [switch]$FailOnPrivilegedAssignmentWithoutClassification
)

$CanonicalTierLevelByName = @{
    ControlPlane   = '0'
    ManagementPlane = '1'
    WorkloadPlane = '1'
    UserAccess     = '2'
    Unclassified  = 'Unclassified'
}
$Violations = [System.Collections.Generic.List[string]]::new()
# Consumers (KQL parsers, watchlists, report apps) index these collections. A single-item array that
# collapsed into a scalar causes git churn without content change, so it is rejected as a violation.
# Collected per file: an unchanged committed export was written by an earlier version and is only
# reported (see below).
$ArrayShapeProperties = @('MatchedActions', 'ScopedObjects')
$ShapeIssues = [System.Collections.Generic.List[string]]::new()
function Test-ArtifactCollectionShape {
    param($Value, [string]$Context)
    if ($null -ne $Value -and $Value -isnot [array]) {
        $ShapeIssues.Add("$Context is stored as a single value instead of an array.")
    }
}
# True when the file is tracked and matches HEAD, i.e. it isn't output of the current run. An RBAC
# system with an empty result or one removed from RbacSystems keeps its previous export, so a strict
# check would fail every run until that system is exported again.
function Test-ArtifactCommittedUnchanged {
    param([string]$Path)
    if (-not (Get-Command git -CommandType Application -ErrorAction SilentlyContinue)) { return $false }
    $Directory = Split-Path -Parent $Path
    $Name = Split-Path -Leaf $Path
    & git -C $Directory ls-files --error-unmatch -- $Name *> $null
    if ($LASTEXITCODE -ne 0) { return $false }
    # 0 = working tree and index match HEAD; 1 = changed; anything else (e.g. no commit yet) = unknown
    & git -C $Directory diff --quiet HEAD -- $Name *> $null
    return $LASTEXITCODE -eq 0
}
function Test-ArtifactClassificationEntryShape {
    param($Classification, [string]$Context)
    foreach ($Entry in @($Classification)) {
        if ($null -eq $Entry -or $Entry -isnot [pscustomobject]) { continue }
        foreach ($PropertyName in $ArrayShapeProperties) {
            $Property = $Entry.PSObject.Properties[$PropertyName]
            if ($null -ne $Property) {
                Test-ArtifactCollectionShape -Value $Property.Value -Context "$Context classification '$($Entry.AdminTierLevelName)/$($Entry.Service)' $PropertyName"
            }
        }
    }
}
$TierPairWarnings = [System.Collections.Generic.List[string]]::new()
$DataQualityWarnings = [System.Collections.Generic.List[string]]::new()
$ObjectCount = 0
$AssignmentCount = 0
$TenantGovernanceResourceCount = 0

if ([string]::IsNullOrWhiteSpace($PrivilegedEamPath) -and [string]::IsNullOrWhiteSpace($TenantGovernancePath)) {
    throw 'Nothing to validate: pass -PrivilegedEamPath and/or -TenantGovernancePath.'
}
$ResolvedPrivilegedEamPath = if ([string]::IsNullOrWhiteSpace($PrivilegedEamPath)) { $null } else { $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($PrivilegedEamPath) }
if ($ResolvedPrivilegedEamPath) {
    if (-not (Test-Path -LiteralPath $ResolvedPrivilegedEamPath -PathType Container)) {
        throw "Privileged EAM path '$ResolvedPrivilegedEamPath' does not exist."
    }

    $AggregateFiles = @(
        Get-ChildItem -LiteralPath $ResolvedPrivilegedEamPath -Directory | ForEach-Object {
            $AggregatePath = Join-Path $_.FullName "$($_.Name).json"
            if (Test-Path -LiteralPath $AggregatePath -PathType Leaf) {
                Get-Item -LiteralPath $AggregatePath
            }
        }
    )
    if ($AggregateFiles.Count -eq 0) {
        throw "No RBAC-system aggregate JSON files were found under '$ResolvedPrivilegedEamPath'."
    }

    foreach ($AggregateFile in $AggregateFiles) {
        $SeenObjectIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        $ShapeIssues.Clear()
        try {
            $EamObjects = @([System.IO.File]::ReadAllText($AggregateFile.FullName) | ConvertFrom-Json -Depth 100 -ErrorAction Stop)
        } catch {
            $Violations.Add("$($AggregateFile.FullName): invalid JSON - $($_.Exception.Message)")
            continue
        }

        foreach ($EamObject in $EamObjects) {
            $ObjectCount++
            $ObjectId = "$($EamObject.ObjectId)".Trim()
            if ([string]::IsNullOrWhiteSpace($ObjectId)) {
                $Violations.Add("$($AggregateFile.Name): an object is missing ObjectId.")
                $ObjectId = '<missing>'
            } elseif (-not $SeenObjectIds.Add($ObjectId)) {
                $Violations.Add("$($AggregateFile.Name): duplicate object '$ObjectId' appears in the RBAC-system aggregate.")
            }
            $TierName = "$($EamObject.ObjectAdminTierLevelName)"
            $TierLevel = "$($EamObject.ObjectAdminTierLevel)"
            if (-not $CanonicalTierLevelByName.ContainsKey($TierName) -or $TierLevel -ne $CanonicalTierLevelByName[$TierName]) {
            # Most commonly caused by two independently-tagged Custom Security Attribute fields
            # drifting apart on the source object (see EntraOpsConfig.json CustomSecurityAttributes
            # section and docs/core.html "Classify by Custom Security Attributes" for the paired
            # *AdminTierLevelAttribute / *AdminTierLevelNameAttribute field names to check and fix
            # at the source in Microsoft Entra) - or, if enabled, an AlternateObjectTierLevelAttributes
            # filter expression. This is tenant data, not a code defect: fix the tagging, then re-run.
            $Message = "$($AggregateFile.Name): object '$ObjectId' has contradictory tier pair '$TierLevel/$TierName' - check this object's Custom Security Attribute (or AlternateObjectTierLevelAttributes filter) values; see docs/core.html 'Classify by Custom Security Attributes'."
            if ($FailOnContradictoryTierPair) {
                $Violations.Add($Message)
            } else {
                $TierPairWarnings.Add($Message)
            }
            }

            $ObjectClassificationProperty = $EamObject.PSObject.Properties['Classification']
            if ($null -ne $ObjectClassificationProperty) {
                Test-ArtifactCollectionShape -Value $ObjectClassificationProperty.Value -Context "$($AggregateFile.Name): object '$ObjectId' Classification"
                Test-ArtifactClassificationEntryShape -Classification $ObjectClassificationProperty.Value -Context "$($AggregateFile.Name): object '$ObjectId'"
            }

            $SeenAssignmentPaths = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
            foreach ($RoleAssignment in @($EamObject.RoleAssignments)) {
                if ($null -eq $RoleAssignment) { continue }
                $AssignmentCount++
                $InstanceId = "$($RoleAssignment.RoleAssignmentInstanceId)".Trim().ToLowerInvariant()
                if ([string]::IsNullOrWhiteSpace($InstanceId)) {
                    $Violations.Add("$($AggregateFile.Name): object '$ObjectId' has a role assignment without RoleAssignmentInstanceId.")
                    continue
                }

                $Classification = $RoleAssignment.Classification
                $ClassificationIsEmpty = $null -eq $Classification -or
                    ($Classification -is [array] -and $Classification.Count -eq 0) -or
                    ($Classification -is [System.Collections.IDictionary] -and $Classification.Count -eq 0) -or
                    ($Classification -is [pscustomobject] -and @($Classification.PSObject.Properties).Count -eq 0)
                $ClassificationHasSupportedShape = $null -eq $Classification -or $Classification -is [array] -or $Classification -is [System.Collections.IDictionary] -or $Classification -is [pscustomobject]
                if (-not $ClassificationHasSupportedShape) {
                    $Violations.Add("$($AggregateFile.Name): assignment '$InstanceId' has unsupported Classification shape '$($Classification.GetType().FullName)'.")
                } elseif ($null -ne $Classification -and $Classification -isnot [array]) {
                    # Consumers indexing Classification[0] (KQL/workbooks, report apps) expect an array.
                    $ShapeIssues.Add("$($AggregateFile.Name): assignment '$InstanceId' for object '$ObjectId' stores Classification as a single object instead of an array.")
                }
                Test-ArtifactClassificationEntryShape -Classification $Classification -Context "$($AggregateFile.Name): assignment '$InstanceId' for object '$ObjectId'"
                if ($RoleAssignment.RoleIsPrivileged -eq $true -and $ClassificationIsEmpty) {
                    $Message = "$($AggregateFile.Name): privileged assignment '$InstanceId' ('$($RoleAssignment.RoleDefinitionName)') for object '$ObjectId' has no classification result."
                    if ($FailOnPrivilegedAssignmentWithoutClassification) { $Violations.Add($Message) } else { $DataQualityWarnings.Add($Message) }
                }

                $NestingObjectIds = @($RoleAssignment.TransitiveByNestingObjectIds | ForEach-Object {
                        if ($null -eq $_) { '' } else { "$($_)".Trim().ToLowerInvariant() }
                    })
                $AssignmentPathKey = @($InstanceId, ($NestingObjectIds -join [char]0x1E)) -join [char]0x1F
                if (-not $SeenAssignmentPaths.Add($AssignmentPathKey)) {
                    $Violations.Add("$($AggregateFile.Name): object '$ObjectId' contains duplicate assignment path '$InstanceId'.")
                }
            }
        }

        if ($ShapeIssues.Count -gt 0) {
            if (Test-ArtifactCommittedUnchanged -Path $AggregateFile.FullName) {
                $Examples = @($ShapeIssues | Select-Object -First 3) -join ' '
                $DataQualityWarnings.Add("$($AggregateFile.Name): $($ShapeIssues.Count) collection(s) are stored as a single value instead of an array in the committed export of an earlier EntraOps version (for example: $Examples) The file is rewritten with arrays on the next non-empty export of $($AggregateFile.Directory.Name); delete the folder if the RBAC system is no longer collected.")
            } else {
                foreach ($Issue in $ShapeIssues) { $Violations.Add($Issue) }
            }
        }
    }
}

if (-not [string]::IsNullOrWhiteSpace($TenantGovernancePath)) {
    $ResolvedTenantGovernancePath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($TenantGovernancePath)
    if (-not (Test-Path -LiteralPath $ResolvedTenantGovernancePath -PathType Container)) {
        throw "Tenant Governance path '$ResolvedTenantGovernancePath' does not exist."
    }
    $ManifestPath = Join-Path $ResolvedTenantGovernancePath '.SnapshotManifest.json'
    if (-not (Test-Path -LiteralPath $ManifestPath -PathType Leaf)) {
        $Violations.Add("Tenant Governance snapshot manifest is missing: $ManifestPath")
    } else {
        try { $SnapshotManifest = Get-Content -LiteralPath $ManifestPath -Raw | ConvertFrom-Json -Depth 100 -ErrorAction Stop }
        catch { $Violations.Add("$ManifestPath`: invalid JSON - $($_.Exception.Message)") }
    }

    $IdentityFiles = @{}
    $ActualCounts = @{}
    foreach ($ResourceFile in @(Get-ChildItem -LiteralPath $ResolvedTenantGovernancePath -Filter '*.json' -File -Recurse | Where-Object { -not $_.Name.StartsWith('.') -and $_.FullName -notmatch '[\\/]\.(?:staging|backup)-' })) {
        # -AsHashtable accepts valid JSON objects that contain an empty property
        # name. Microsoft Graph emits those in some Tenant Governance payloads.
        try { $Resource = [System.IO.File]::ReadAllText($ResourceFile.FullName) | ConvertFrom-Json -AsHashtable -Depth 100 -ErrorAction Stop }
        catch { $Violations.Add("$($ResourceFile.FullName): invalid JSON - $($_.Exception.Message)"); continue }
        $TenantGovernanceResourceCount++
        $ResourceType = "$($Resource.resourceType)".Trim().ToLowerInvariant()
        $RelativePath = [System.IO.Path]::GetRelativePath($ResolvedTenantGovernancePath, $ResourceFile.FullName) -replace '\\', '/'
        $FolderResourceType = ($RelativePath -split '/')[0].ToLowerInvariant()
        if ([string]::IsNullOrWhiteSpace($ResourceType)) {
            $ResourceType = $FolderResourceType
        } elseif ($ResourceType -ne $FolderResourceType) {
            $Violations.Add("$($ResourceFile.FullName): resourceType '$ResourceType' does not match its top-level snapshot folder '$FolderResourceType'.")
        }
        if (-not $ActualCounts.ContainsKey($ResourceType)) { $ActualCounts[$ResourceType] = 0 }
        $ActualCounts[$ResourceType]++
        $ResourceId = "$($Resource.properties.Id)".Trim().ToLowerInvariant()
        if ([string]::IsNullOrWhiteSpace($ResourceId)) { continue }
        $Identity = "$ResourceType|$ResourceId"
        if (-not $IdentityFiles.ContainsKey($Identity)) { $IdentityFiles[$Identity] = [System.Collections.Generic.List[string]]::new() }
        $IdentityFiles[$Identity].Add($ResourceFile.FullName)
    }
    foreach ($Identity in $IdentityFiles.Keys) {
        if ($IdentityFiles[$Identity].Count -gt 1) {
            $Violations.Add("Tenant Governance identity '$Identity' is stored in $($IdentityFiles[$Identity].Count) files: $($IdentityFiles[$Identity] -join ', ')")
        }
    }
    if ($SnapshotManifest) {
        $ManifestCountProperties = @($SnapshotManifest.PublishedResourceTypeCounts.PSObject.Properties)
        $ManifestCountResourceTypes = @($ManifestCountProperties | ForEach-Object { $_.Name.ToLowerInvariant() })
        foreach ($CountProperty in $ManifestCountProperties) {
            $ResourceType = $CountProperty.Name.ToLowerInvariant()
            $ActualCount = if ($ActualCounts.ContainsKey($ResourceType)) { $ActualCounts[$ResourceType] } else { 0 }
            if ([int]$CountProperty.Value -ne $ActualCount) {
                $Violations.Add("Tenant Governance manifest count for '$ResourceType' is $($CountProperty.Value), but $ActualCount JSON file(s) exist.")
            }
        }
        # Folders of resource types that are no longer configured are intentionally preserved by
        # Save-EntraOpsTenantGovernanceSnapshotJson and reported as NotInConfig by the snapshot
        # report. They are not part of the manifest counts, so they are reported here without
        # failing the run; their files were still checked for JSON validity and duplicate identities.
        $ManifestResourceFileCount = 0
        foreach ($ResourceType in @($ActualCounts.Keys | Sort-Object)) {
            if ($ManifestCountResourceTypes -contains $ResourceType) {
                $ManifestResourceFileCount += $ActualCounts[$ResourceType]
            } else {
                $DataQualityWarnings.Add("Tenant Governance resource type '$ResourceType' has $($ActualCounts[$ResourceType]) JSON file(s) on disk but is not part of the current snapshot manifest (removed from the configured resource types). Delete the folder to stop tracking it.")
            }
        }
        if ($SnapshotManifest.IsComplete -eq $true -and [int]$SnapshotManifest.CapturedResourceCount -ne $ManifestResourceFileCount) {
            $Violations.Add("Complete Tenant Governance manifest captured count is $($SnapshotManifest.CapturedResourceCount), but $ManifestResourceFileCount resource file(s) exist for the manifest's resource types.")
        }
    }
}

if ($Violations.Count -gt 0) {
    throw "Generated artifact integrity validation failed with $($Violations.Count) violation(s):`n$($Violations -join "`n")"
}

foreach ($Warning in $TierPairWarnings) {
    Write-Warning $Warning
}
foreach ($Warning in $DataQualityWarnings) {
    Write-Warning $Warning
}

$SummaryParts = @()
if ($ResolvedPrivilegedEamPath) { $SummaryParts += "$ObjectCount object(s) and $AssignmentCount role assignment(s) across $($AggregateFiles.Count) RBAC system(s)" }
if (-not [string]::IsNullOrWhiteSpace($TenantGovernancePath)) { $SummaryParts += "$TenantGovernanceResourceCount Tenant Governance resource(s)" }
Write-Output "Validated $($SummaryParts -join ' and ')."
}
