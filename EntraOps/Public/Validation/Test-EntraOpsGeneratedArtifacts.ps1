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
                    # Still readable, but consumers indexing Classification[0] (KQL/workbooks, report apps) expect an array.
                    $DataQualityWarnings.Add("$($AggregateFile.Name): assignment '$InstanceId' for object '$ObjectId' stores Classification as a single object instead of an array.")
                }
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
