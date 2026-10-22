<#
.SYNOPSIS
    Build Azure resource/subscription scope buckets (Tier0/Tier1/all subscriptions) from Exposure Management
    and Managed Identity host resources, for reuse by Azure RBAC and Microsoft Defender for Cloud scope
    parameterization.

.DESCRIPTION
    Queries Microsoft Security Exposure Management for critical Azure resources and Azure Resource Graph for
    resources hosting system-assigned or user-assigned managed identities (and their consumers), then expands
    each resource to its full ARM hierarchy (resource -> resource group -> subscription -> management groups).
    Resources are bucketed into Tier0 (ControlPlane, or Exposure Management critical assets) and Tier1
    (ManagementPlane) based on the EFFECTIVE tier of the associated managed identity in EntraOps EAM data - the
    most privileged tier found across (1) ObjectAdminTierLevelName (a manually-tagged custom security attribute,
    rarely set on managed identities) and (2) the identity's own aggregated Classification entries (its actually
    granted, classified role/API-permission assignments, e.g. a Microsoft Graph "Sites.Selected" permission
    classified as ManagementPlane). Considering only ObjectAdminTierLevelName would report "Unclassified" for
    every un-tagged managed identity regardless of its real privileges. Also returns the full list of tenant
    subscriptions for building an "everything else" Tier2 scope.

    Tier bucketing fallback: only an empty or "Unknown" effective tier defaults to Tier0 (nothing could be
    evaluated - fail closed). An effective tier of "Unclassified" means the identity WAS evaluated against the
    loaded EAM data and no privileged classification was found, so its host resource is bucketed Tier1
    (ManagementPlane scope) rather than widening the Control Plane. Note this makes the Tier1 bucket sensitive
    to the EAM data actually loaded: with narrowed EntraOpsScopes or a stale/missing EAM export, a genuinely
    privileged managed identity can come back "Unclassified" and land in Tier1.

.PARAMETER EntraOpsEamFolder
    Path to the folder where the EntraOps classification definition (EAM) files are stored.

.PARAMETER EntraOpsScopes
    Array of EntraOps scopes whose EAM json files should be loaded to identify managed identity objects.

.PARAMETER ExposureCriticalityLevel
    Criticality level filter (KQL comparison, e.g. "<1") for Exposure Management critical Azure resources.

.PARAMETER WarningMessages
    Optional list to collect warning messages raised during resource resolution.

.PARAMETER ExposureManagementBaselineFile
    Previous ScopeReasoning_Azure.json. When the Exposure Management query fails, the critical resources of the
    last successful query recorded in this file are used instead. The query outcome is returned as
    ExposureManagement (Status, Metadata, Results, Warnings, HasUnusablePreviousResults); its warnings are
    reported by the caller.

.EXAMPLE
    Get-EntraOpsClassificationAzureResourceScope -EntraOpsEamFolder ".\Classification\EAM" -EntraOpsScopes @("Azure","EntraID") -ExposureCriticalityLevel "<1"
#>

function Get-EntraOpsClassificationAzureResourceScope {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$EntraOpsEamFolder
        ,
        [Parameter(Mandatory = $true)]
        [object]$EntraOpsScopes
        ,
        [Parameter(Mandatory = $false)]
        [string]$ExposureCriticalityLevel = "<1"
        ,
        [Parameter(Mandatory = $false)]
        [System.Collections.Generic.List[psobject]]$WarningMessages
        ,
        [Parameter(Mandatory = $false)]
        [string]$ExposureManagementBaselineFile
    )

    $AzTenantId = (Get-AzContext).Tenant.Id
    $AzureResourceScopeDetails = [System.Collections.Generic.List[PSCustomObject]]::new()

    # Helper: expand a resource ARM path to its full ARM hierarchy
    function Expand-AzureArmHierarchy {
        param(
            [string]$ResourceId,
            [hashtable]$SubToMgLookup
        )
        # Parsed generically rather than by matching a fixed set of resource shapes. The previous three
        # regexes only recognised "<sub>/resourcegroups/<rg>/...", a bare resource group and a bare
        # subscription, so a subscription-level provider resource
        # (/subscriptions/<id>/providers/microsoft.<rp>/...) or a management-group-level resource
        # contributed only its own path - leaving the containing subscription and management groups
        # unmarked, and an Owner assignment at the subscription covering that critical asset
        # unclassified.
        $Paths = [System.Collections.Generic.List[string]]::new()
        $Lower = $ResourceId.ToLower().TrimEnd('/')
        if ([string]::IsNullOrEmpty($Lower)) { return @() }
        $Paths.Add($Lower)

        # Management group scope: /providers/microsoft.management/managementgroups/<name>[/...]
        if ($Lower -match '^(/providers/microsoft\.management/managementgroups/[^/]+)') {
            $Paths.Add($Matches[1])
        }

        # Subscription-rooted scope of any depth. Everything below the subscription contributes its
        # ancestors: the resource group (when present) and always the subscription plus its management
        # group chain.
        if ($Lower -match '^/subscriptions/([^/]+)') {
            $SubId = $Matches[1]
            if ($Lower -match '^/subscriptions/[^/]+/resourcegroups/([^/]+)') {
                $Paths.Add("/subscriptions/$SubId/resourcegroups/$($Matches[1])")
            }
            $Paths.Add("/subscriptions/$SubId")
            if ($SubToMgLookup.ContainsKey($SubId)) {
                foreach ($Mg in $SubToMgLookup[$SubId]) { $Paths.Add($Mg) }
            }
        }

        # Case-insensitive dedup while preserving discovery order ($Lower is already lowercased, but
        # $SubToMgLookup values come from ARG and may differ in casing).
        return @($Paths | Group-Object -Property { "$_".ToLowerInvariant() } | ForEach-Object { $_.Group[0] })
    }

    #region Build subscription -> management group hierarchy map and full subscription list via ARG
    $MgHierarchyQuery = @'
resourcecontainers
| where type == 'microsoft.resources/subscriptions'
| mv-expand mgAncestor = properties.managementGroupAncestorsChain
| where isnotempty(mgAncestor.name)
| project subscriptionId, managementGroupId = tolower(strcat('/providers/microsoft.management/managementgroups/', tostring(mgAncestor.name)))
'@
    # The ARM hierarchy and subscription list are STRUCTURAL inputs: every Tier0/Tier1 scope below is derived
    # from them. A failure here must abort - silently continuing with an empty map collapses $Tier0Paths to
    # "/" and drops every management-group/subscription scoped Owner assignment out of the Control Plane.
    # -ThrowOnFailure is required because the query helpers otherwise report failure with a non-terminating
    # Write-Error and return a (possibly partial) result, which would never reach these catch blocks.
    $SubToMgMap = @{}
    try {
        $MgHierarchyData = Invoke-EntraOpsAzGraphQuery -KqlQuery $MgHierarchyQuery -ThrowOnFailure
        foreach ($Row in $MgHierarchyData) {
            $SubId = $Row.subscriptionId.ToLower()
            if (-not $SubToMgMap.ContainsKey($SubId)) {
                $SubToMgMap[$SubId] = [System.Collections.Generic.List[string]]::new()
            }
            if (-not [string]::IsNullOrEmpty($Row.managementGroupId)) {
                $SubToMgMap[$SubId].Add($Row.managementGroupId) | Out-Null
            }
        }
    } catch {
        if ($null -ne $WarningMessages) {
            $WarningMessages.Add([PSCustomObject]@{ Type = "ApiError"; Message = "Failed to build Azure ARM hierarchy map: $_" })
        }
        throw "Failed to build the subscription -> management group hierarchy map, which the entire Azure Control Plane scope is derived from: $_. Refusing to generate a narrowed Azure classification scope."
    }

    $AllSubsQuery = @'
resourcecontainers
| where type == 'microsoft.resources/subscriptions'
| project subscriptionId
'@
    $AllSubscriptionScope = @()
    try {
        $AllSubsData = Invoke-EntraOpsAzGraphQuery -KqlQuery $AllSubsQuery -ThrowOnFailure
        $AllSubscriptionScope = @($AllSubsData | Select-Object -ExpandProperty subscriptionId -Unique | ForEach-Object { "/subscriptions/$($_.ToLower())" })
    } catch {
        if ($null -ne $WarningMessages) {
            $WarningMessages.Add([PSCustomObject]@{ Type = "ApiError"; Message = "Failed to enumerate Azure subscriptions: $_" })
        }
        throw "Failed to enumerate Azure subscriptions, which the Azure Management Plane scope is derived from: $_. Refusing to generate a narrowed Azure classification scope."
    }

    # Plausibility guard: even when both queries "succeed", an empty result set would collapse the Control
    # Plane scope to the hard-coded "/" fallback and reclassify every management-group and subscription
    # scoped Owner / User Access Administrator assignment as Management Plane. A tenant with Azure enabled
    # as an RBAC system always has at least one subscription or management group.
    if ($SubToMgMap.Count -eq 0 -and $AllSubscriptionScope.Count -eq 0) {
        $PlausibilityError = "Azure scope discovery returned no subscriptions and no management groups. This usually indicates missing ARM Reader permissions or a throttled Resource Graph, not an empty tenant. Refusing to generate Classification_Azure.json with a collapsed Control Plane scope."
        if ($null -ne $WarningMessages) {
            $WarningMessages.Add([PSCustomObject]@{ Type = "ApiError"; Message = $PlausibilityError })
        }
        throw $PlausibilityError
    }
    #endregion

    #region Source 1: Exposure Management critical Azure resources (always ControlPlane)
    $ExposureMgmtQuery = @"
ExposureGraphNodes
| where EntityIds has "AzureResourceId"
| extend CriticalityLevel = toint(NodeProperties.rawData.criticalityLevel.criticalityLevel)
| extend CriticalityRules = tostring(NodeProperties.rawData.criticalityLevel.ruleNames)
| where isnotnull(CriticalityLevel) and CriticalityLevel $ExposureCriticalityLevel
| mv-expand EntityId = parse_json(EntityIds)
| where EntityId.type =~ "AzureResourceId"
| extend ResourceId = tolower(tostring(EntityId.id))
| distinct NodeName, ResourceId, CriticalityLevel, CriticalityRules
"@
    # Increase when the meaning of the results changes: older results are then no longer carried forward
    $ExposureManagementQueryVersion = 1
    $ExposureManagementBaseline = Get-EntraOpsExposureManagementBaseline -Path $ExposureManagementBaselineFile -TenantId $AzTenantId -ExposureCriticalityLevel $ExposureCriticalityLevel -QueryVersion $ExposureManagementQueryVersion -GetLegacyResults {
        param($Content)
        @($Content.ScopeDetails | Where-Object { $_.Source -eq 'ExposureManagement' })
    }
    # A failed query falls back to the critical resources of the last successful query
    $ExposureManagementQuery = Invoke-EntraOpsExposureManagementQuery -Query $ExposureMgmtQuery -Context "critical Azure resources" -Baseline $ExposureManagementBaseline -TenantId $AzTenantId -ExposureCriticalityLevel $ExposureCriticalityLevel -QueryVersion $ExposureManagementQueryVersion
    foreach ($ExposureManagementWarning in $ExposureManagementQuery.Warnings) {
        Write-Warning $ExposureManagementWarning.Message
    }
    $ExposureResources = @($ExposureManagementQuery.Results | Where-Object { -not [string]::IsNullOrEmpty($_.ResourceId) } | ForEach-Object {
            [PSCustomObject][ordered]@{
                NodeName         = $_.NodeName
                ResourceId       = $_.ResourceId
                CriticalityLevel = $_.CriticalityLevel
                CriticalityRules = $_.CriticalityRules
            }
        } | Sort-Object ResourceId, NodeName)
    foreach ($ExRes in $ExposureResources) {
        $ExposureResourceDetail = [PSCustomObject]@{
            ResourceId       = $ExRes.ResourceId
            ResourceName     = $ExRes.NodeName
            Source           = "ExposureManagement"
            EAMTier          = "ControlPlane"
            CriticalityLevel = $ExRes.CriticalityLevel
            CriticalityRules = $ExRes.CriticalityRules
            Reason           = "Critical asset (CriticalityLevel: $($ExRes.CriticalityLevel); CriticalityRules: $($ExRes.CriticalityRules))"
        }
        if ($ExposureManagementQuery.Status -eq 'CarriedForward') {
            $ExposureResourceDetail | Add-Member -NotePropertyName XspmLastSuccessfulQueryDate -NotePropertyValue $ExposureManagementQuery.Metadata.LastSuccessfulQueryDate
        }
        $AzureResourceScopeDetails.Add($ExposureResourceDetail) | Out-Null
    }
    #endregion

    #region Load EAM data and extract managed identity object IDs
    $LoadedEamFileCount = 0
    $AllEamObjects = foreach ($EamScope in $EntraOpsScopes) {
        $EamFile = Join-Path -Path $EntraOpsEamFolder -ChildPath $EamScope -AdditionalChildPath "$($EamScope).json"
        if (-not (Test-Path -LiteralPath $EamFile -PathType Leaf)) {
            Write-Verbose "No EAM data for ${EamScope}: $EamFile not found"
            continue
        }
        # Only a missing export is skipped: an unreadable one would silently drop its managed identities' tiers
        try {
            $EamObjects = Get-Content -LiteralPath $EamFile -Raw -ErrorAction Stop | ConvertFrom-Json -Depth 10 -ErrorAction Stop
        } catch {
            throw "EAM export '$EamFile' could not be read: $($_.Exception.Message). Refusing to generate a narrowed Azure classification scope."
        }
        $LoadedEamFileCount++
        $EamObjects
    }
    if ($LoadedEamFileCount -eq 0) {
        $MissingEamMessage = "No EntraOps EAM files were available in '$EntraOpsEamFolder'. Managed-identity host resources cannot contribute to Azure Tier0/Tier1 scope reasoning until an EAM export exists."
        Write-Warning $MissingEamMessage
        if ($null -ne $WarningMessages) {
            $WarningMessages.Add([PSCustomObject]@{ Type = 'AzureScopeReasoningEamUnavailable'; Message = $MissingEamMessage })
        }
    }

    # Rank tiers by privilege (lower = more privileged); anything unrecognized (blank/"Unclassified"/"Unknown")
    # ranks last so it never wins over a real ControlPlane/ManagementPlane tier.
    # Canonical model order: ControlPlane < ManagementPlane < WorkloadPlane < UserAccess.
    # UserAccess was previously 2 (tied with WorkloadPlane), diverging from every other tier-rank
    # map in the module - a WorkloadPlane scope must outrank UserAccess consistently.
    $TierRank = @{ ControlPlane = 0; ManagementPlane = 1; WorkloadPlane = 2; UserAccess = 3 }
    function Get-TierRank {
        param([string]$Tier)
        if ([string]::IsNullOrEmpty($Tier) -or -not $TierRank.ContainsKey($Tier)) { return 99 }
        return $TierRank[$Tier]
    }

    function Get-ManagedIdentityClassificationEvidence {
        param(
            [object]$ManagedIdentity,
            [string]$Tier,
            [string]$Service
        )

        $Evidence = [System.Collections.Generic.List[string]]::new()
        $RoleNames = [System.Collections.Generic.List[string]]::new()
        $Methods = [System.Collections.Generic.List[string]]::new()
        $Actions = [System.Collections.Generic.List[string]]::new()
        foreach ($Assignment in @($ManagedIdentity.RoleAssignments)) {
            foreach ($Classification in @($Assignment.Classification)) {
                if ($Classification.AdminTierLevelName -ne $Tier -or $Classification.Service -ne $Service) { continue }
                if (-not [string]::IsNullOrWhiteSpace("$($Assignment.RoleDefinitionName)")) {
                    $RoleNames.Add("$($Assignment.RoleDefinitionName)") | Out-Null
                }
                if (-not [string]::IsNullOrWhiteSpace("$($Classification.TaggedBy)")) {
                    $Methods.Add("$($Classification.TaggedBy)") | Out-Null
                }
                foreach ($Action in @($Classification.MatchedActions)) {
                    if (-not [string]::IsNullOrWhiteSpace("$Action")) { $Actions.Add("$Action") | Out-Null }
                }
            }
        }

        $Evidence.Add("Aggregated classification: $Service ($Tier)") | Out-Null
        $UniqueRoles = @($RoleNames | Sort-Object -Unique)
        if ($UniqueRoles.Count -gt 0) { $Evidence.Add("Classified role(s): $($UniqueRoles -join ', ')") | Out-Null }
        $UniqueMethods = @($Methods | Sort-Object -Unique)
        if ($UniqueMethods.Count -gt 0) { $Evidence.Add("Classification method(s): $($UniqueMethods -join ', ')") | Out-Null }
        $UniqueActions = @($Actions | Sort-Object -Unique)
        if ($UniqueActions.Count -gt 0) {
            $ActionPreview = @($UniqueActions | Select-Object -First 5)
            $ActionLabel = $ActionPreview -join ', '
            if ($UniqueActions.Count -gt $ActionPreview.Count) { $ActionLabel += " (+$($UniqueActions.Count - $ActionPreview.Count) more)" }
            $Evidence.Add("Matched role action(s): $ActionLabel") | Out-Null
        }
        return @($Evidence)
    }

    # A managed identity's own privilege tier can come from two independent sources that do not always agree:
    # (1) ObjectAdminTierLevelName - a manually-tagged custom security attribute on the directory object,
    # rarely set for managed identities - and (2) the object's aggregated Classification array, reflecting the
    # role/API-permission assignments EntraOps actually classified for it. Relying on ObjectAdminTierLevelName
    # alone silently reports "Unclassified" for every un-tagged managed identity regardless of its real granted
    # privileges, which would bucket its host resource Tier1 (see the bucketing fallback below) and hide a
    # genuine ControlPlane tier. The same managed identity can also appear in more than one loaded EntraOpsScopes EAM
    # file (e.g. both ResourceApps.json and Azure.json); its effective tier must be the MOST PRIVILEGED tier
    # found across every appearance and every Classification entry, not an arbitrary "first match".
    $ManagedIdentityLookup = @{}
    foreach ($MiObj in ($AllEamObjects | Where-Object { $_.ObjectType -eq "serviceprincipal" -and $_.ObjectSubType -eq "ManagedIdentity" })) {
        $ObjId = $MiObj.ObjectId
        if ([string]::IsNullOrEmpty($ObjId)) { continue }
        if (-not $ManagedIdentityLookup.ContainsKey($ObjId)) {
            $ManagedIdentityLookup[$ObjId] = [PSCustomObject]@{
                ObjectId          = $ObjId
                ObjectDisplayName = $MiObj.ObjectDisplayName
                EffectiveTier     = "Unclassified"
                TierSource        = $null
                TierEvidence      = @()
            }
        }
        $Entry = $ManagedIdentityLookup[$ObjId]
        if ([string]::IsNullOrEmpty($Entry.ObjectDisplayName)) { $Entry.ObjectDisplayName = $MiObj.ObjectDisplayName }

        # Candidate 1: the manually-tagged directory-level tier (ObjectAdminTierLevelName)
        if ((Get-TierRank $MiObj.ObjectAdminTierLevelName) -lt (Get-TierRank $Entry.EffectiveTier)) {
            $Entry.EffectiveTier = $MiObj.ObjectAdminTierLevelName
            $Entry.TierSource = "tagged"
            $Entry.TierEvidence = @("Directory object tier tag: ObjectAdminTierLevelName = $($MiObj.ObjectAdminTierLevelName)")
        }
        # Candidate 2: the most-privileged tier among this object's own classified role/permission grants
        foreach ($ClassEntry in @($MiObj.Classification)) {
            if ((Get-TierRank $ClassEntry.AdminTierLevelName) -lt (Get-TierRank $Entry.EffectiveTier)) {
                $Entry.EffectiveTier = $ClassEntry.AdminTierLevelName
                $Entry.TierSource = "classified via $($ClassEntry.Service)"
                $Entry.TierEvidence = @(Get-ManagedIdentityClassificationEvidence -ManagedIdentity $MiObj -Tier $ClassEntry.AdminTierLevelName -Service $ClassEntry.Service)
            }
        }
    }
    $AllManagedIdentities = @($ManagedIdentityLookup.Values)
    #endregion

    #region Source 2: ARG queries for managed identity host resources and UAMI consumers
    if ($AllManagedIdentities.Count -gt 0) {
        $MiObjectIds = @($AllManagedIdentities | ForEach-Object { $_.ObjectId } | Select-Object -Unique)
        $ObjIdFilterList = ($MiObjectIds | ForEach-Object { "'$_'" }) -join ','

        $SysAssignedQuery = @"
resources
| where tenantId == '$AzTenantId'
| where isnotempty(identity.principalId)
| where tostring(identity.principalId) in ($ObjIdFilterList)
| project id = tolower(id), name, type, resourceGroup, subscriptionId, objectid = tostring(identity.principalId)
"@
        $UamiQuery = @"
resources
| where tenantId == '$AzTenantId'
| where type =~ "microsoft.managedidentity/userassignedidentities"
| where tostring(properties.principalId) in ($ObjIdFilterList)
| project id = tolower(id), name, type, resourceGroup, subscriptionId, objectid = tostring(properties.principalId)
"@

        $SysAssignedResults = @()
        $UamiResults = @()
        # Failed managed identity queries stop the update like the hierarchy query: the host scopes would drop out

        try {
            $SysAssignedResults = @(Invoke-EntraOpsAzGraphQuery -KqlQuery $SysAssignedQuery -ThrowOnFailure)
        } catch {
            if ($null -ne $WarningMessages) {
                $WarningMessages.Add([PSCustomObject]@{ Type = "ApiError"; Message = "ARG system-assigned MI query failed: $_" })
            }
            throw "Azure Resource Graph system-assigned MI query failed: $_. Refusing to generate a narrowed Azure classification scope."
        }

        try {
            $UamiResults = @(Invoke-EntraOpsAzGraphQuery -KqlQuery $UamiQuery -ThrowOnFailure)
        } catch {
            if ($null -ne $WarningMessages) {
                $WarningMessages.Add([PSCustomObject]@{ Type = "ApiError"; Message = "ARG user-assigned MI query failed: $_" })
            }
            throw "Azure Resource Graph user-assigned MI query failed: $_. Refusing to generate a narrowed Azure classification scope."
        }

        foreach ($SysRes in $SysAssignedResults) {
            $MiInfo = $ManagedIdentityLookup[$SysRes.objectid]
            $EamTier = if ($null -ne $MiInfo) { $MiInfo.EffectiveTier } else { "Unknown" }
            $MiLabel = if ($null -ne $MiInfo) { "$($MiInfo.ObjectDisplayName) ($($SysRes.objectid))" } else { $SysRes.objectid }
            $TierNote = if ($null -ne $MiInfo -and @($MiInfo.TierEvidence).Count -gt 0) { " [$($MiInfo.TierEvidence[0])]" } elseif ($null -ne $MiInfo -and $MiInfo.TierSource) { " [$($MiInfo.TierSource)]" } else { "" }
            $AzureResourceScopeDetails.Add([PSCustomObject]@{
                    ResourceId              = $SysRes.id
                    ResourceName            = $SysRes.name
                    Source                  = "SystemAssignedMI"
                    EAMTier                 = $EamTier
                    TierSource              = if ($null -ne $MiInfo) { $MiInfo.TierSource } else { $null }
                    TierEvidence            = if ($null -ne $MiInfo) { @($MiInfo.TierEvidence) } else { @() }
                    ManagedIdentityObjectId = $SysRes.objectid
                    Reason                  = "Hosts system-assigned MI: $MiLabel$TierNote"
                }) | Out-Null
        }

        foreach ($UamiRes in $UamiResults) {
            $MiInfo = $ManagedIdentityLookup[$UamiRes.objectid]
            $EamTier = if ($null -ne $MiInfo) { $MiInfo.EffectiveTier } else { "Unknown" }
            $MiLabel = if ($null -ne $MiInfo) { "$($MiInfo.ObjectDisplayName) ($($UamiRes.objectid))" } else { $UamiRes.objectid }
            $TierNote = if ($null -ne $MiInfo -and @($MiInfo.TierEvidence).Count -gt 0) { " [$($MiInfo.TierEvidence[0])]" } elseif ($null -ne $MiInfo -and $MiInfo.TierSource) { " [$($MiInfo.TierSource)]" } else { "" }
            $AzureResourceScopeDetails.Add([PSCustomObject]@{
                    ResourceId              = $UamiRes.id
                    ResourceName            = $UamiRes.name
                    Source                  = "UserAssignedMI"
                    EAMTier                 = $EamTier
                    TierSource              = if ($null -ne $MiInfo) { $MiInfo.TierSource } else { $null }
                    TierEvidence            = if ($null -ne $MiInfo) { @($MiInfo.TierEvidence) } else { @() }
                    ManagedIdentityObjectId = $UamiRes.objectid
                    Reason                  = "User-assigned MI resource: $MiLabel$TierNote"
                }) | Out-Null
        }

        if ($UamiResults.Count -gt 0) {
            $UamiIdFilterList = ($UamiResults | ForEach-Object { "'$($_.id)'" }) -join ','
            $UamiConsumerQuery = @"
resources
| where tenantId == '$AzTenantId'
| where isnotempty(identity.userAssignedIdentities)
| mv-expand uamiKey = bag_keys(identity.userAssignedIdentities)
| where tolower(tostring(uamiKey)) in ($UamiIdFilterList)
| project id = tolower(id), name, type, resourceGroup, subscriptionId, uamiId = tolower(tostring(uamiKey))
"@
            $UamiConsumerResults = @()
            try {
                $UamiConsumerResults = @(Invoke-EntraOpsAzGraphQuery -KqlQuery $UamiConsumerQuery -ThrowOnFailure)
            } catch {
                if ($null -ne $WarningMessages) {
                    $WarningMessages.Add([PSCustomObject]@{ Type = "ApiError"; Message = "ARG UAMI consumer query failed: $_" })
                }
                throw "Azure Resource Graph UAMI consumer query failed: $_. Refusing to generate a narrowed Azure classification scope."
            }
            foreach ($Consumer in $UamiConsumerResults) {
                $MatchedUami = $UamiResults | Where-Object { $_.id -eq $Consumer.uamiId } | Select-Object -First 1
                $MiInfo = if ($null -ne $MatchedUami) { $ManagedIdentityLookup[$MatchedUami.objectid] } else { $null }
                $EamTier = if ($null -ne $MiInfo) { $MiInfo.EffectiveTier } else { "Unknown" }
                $UamiName = if ($null -ne $MatchedUami) { $MatchedUami.name } else { $Consumer.uamiId }
                $MiName = if ($null -ne $MiInfo) { $MiInfo.ObjectDisplayName } else { "" }
                $TierNote = if ($null -ne $MiInfo -and @($MiInfo.TierEvidence).Count -gt 0) { " [$($MiInfo.TierEvidence[0])]" } elseif ($null -ne $MiInfo -and $MiInfo.TierSource) { " [$($MiInfo.TierSource)]" } else { "" }
                $AzureResourceScopeDetails.Add([PSCustomObject]@{
                        ResourceId              = $Consumer.id
                        ResourceName            = $Consumer.name
                        Source                  = "UAMIConsumer"
                        EAMTier                 = $EamTier
                        TierSource              = if ($null -ne $MiInfo) { $MiInfo.TierSource } else { $null }
                        TierEvidence            = if ($null -ne $MiInfo) { @($MiInfo.TierEvidence) } else { @() }
                        ManagedIdentityObjectId = if ($null -ne $MatchedUami) { $MatchedUami.objectid } else { $null }
                        Reason                  = "Uses UAMI: $UamiName$(if ($MiName) { " / MI: $MiName" })$TierNote"
                    }) | Out-Null
            }
        }
    }
    #endregion

    #region Expand each resource to its ARM hierarchy and bucket into Tier0 (ControlPlane) / Tier1 (ManagementPlane)
    $Tier0Paths = [System.Collections.Generic.List[string]]::new()
    $Tier1Paths = [System.Collections.Generic.List[string]]::new()
    foreach ($Detail in $AzureResourceScopeDetails) {
        $HierarchyPaths = Expand-AzureArmHierarchy -ResourceId $Detail.ResourceId -SubToMgLookup $SubToMgMap
        $Detail | Add-Member -NotePropertyName ExpandedScopePaths -NotePropertyValue @($HierarchyPaths | Sort-Object -Unique) -Force
        if ($Detail.EAMTier -eq "ControlPlane" -or [string]::IsNullOrEmpty($Detail.EAMTier) -or $Detail.EAMTier -eq "Unknown") {
            # ControlPlane, or nothing could be evaluated (empty/"Unknown") - err on the side of Tier0.
            foreach ($Path in $HierarchyPaths) { if (-not [string]::IsNullOrEmpty($Path)) { $Tier0Paths.Add($Path) | Out-Null } }
        } else {
            # ManagementPlane, UserAccess, WorkloadPlane, or "Unclassified" -> Tier1. "Unclassified" is an
            # intentional Tier1 fallback: the identity was evaluated against the loaded EAM data and no
            # privileged classification was found, so it must not widen the Control Plane. Caveat: narrowed
            # EntraOpsScopes or a stale/missing EAM export can also produce "Unclassified" for a genuinely
            # privileged identity - keep the EAM exports current when relying on this bucketing.
            foreach ($Path in $HierarchyPaths) { if (-not [string]::IsNullOrEmpty($Path)) { $Tier1Paths.Add($Path) | Out-Null } }
        }
    }
    if ($AzureResourceScopeDetails.Count -eq 0) {
        $DegenerateScopeMessage = "Azure resource scope discovery found no Exposure Management critical resources or managed-identity host resources. ScopeReasoning_Azure.json will contain only the synthetic '/' Tier0 fallback and cannot classify Defender CloudSet subscriptions as privileged."
        Write-Warning $DegenerateScopeMessage
        if ($null -ne $WarningMessages) {
            $WarningMessages.Add([PSCustomObject]@{ Type = 'AzureScopeReasoningRootOnly'; Message = $DegenerateScopeMessage })
        }
    }
    # Always include the tenant root group scope ("/") in Tier0, since role assignments made directly at the
    # root scope are not covered by the expanded ARM hierarchy paths.
    $Tier0Paths.Add('/') | Out-Null

    $Tier0ResourceScope = @($Tier0Paths | Select-Object -Unique | Sort-Object)
    $Tier1ResourceScope = @($Tier1Paths | Select-Object -Unique | Where-Object { $Tier0ResourceScope -notcontains $_ } | Sort-Object)
    #endregion

    return [PSCustomObject]@{
        Tier0ResourceScope      = $Tier0ResourceScope
        Tier1ResourceScope      = $Tier1ResourceScope
        AllSubscriptionScope    = @($AllSubscriptionScope | Select-Object -Unique | Sort-Object)
        ResourceScopeDetails    = $AzureResourceScopeDetails
        SubToManagementGroupMap = $SubToMgMap
        ExposureManagement      = [PSCustomObject]@{
            Status                     = $ExposureManagementQuery.Status
            Metadata                   = $ExposureManagementQuery.Metadata
            Results                    = $ExposureResources
            Warnings                   = @($ExposureManagementQuery.Warnings)
            HasUnusablePreviousResults = $ExposureManagementQuery.HasUnusablePreviousResults
        }
    }
}
