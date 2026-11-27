<#
.SYNOPSIS
    Classify every Identity Governance access package catalog and access package scope
    (Tier0/ControlPlane, Tier1/ManagementPlane or Tier2/UserAccess) based on the resources
    actually assigned to them, for Classification_IdentityGovernance parameterization and
    ScopeReasoning_IdentityGovernance.json.

.DESCRIPTION
    Enumerates all Entitlement Management catalogs and their access packages via Microsoft Graph and
    determines the effective EAM tier of each scope from its assigned resources:

    - AadGroup            : classification of the group object in the classified EntraOps EAM data
                            (Azure/EntraID/DeviceManagement json files).
    - DirectoryRole       : classification of the directory role from classified EntraID EAM data at
                            directory scope, with fallback to the AzurePrivilegedIAM community
                            classification. Unclassifiable roles are treated as ControlPlane
                            (conservative).
    - OAuthApplication    : ONLY evaluated on access package level. The catalog-level
                            accessPackageResourceRoles enumeration for API resources returns
                            permissions across catalogs (Microsoft Graph beta bug), so the union of
                            API permissions assigned to the catalog's access packages is used for
                            the catalog tier instead.
    - AadApplication      : service-principal object classification from ResourceApps EAM data.
    - SharePointOnline    : role-aware classification; administrative roles are ManagementPlane,
                            member/read roles are UserAccess, and unknown roles conservatively use
                            ManagementPlane.
    - AzureResources      : ARM scope (originId) matched against the Tier0/Tier1 resource scope
                            buckets resolved by Get-EntraOpsClassificationAzureResourceScope. A scope
                            is Tier0/Tier1 when it hierarchically overlaps a bucketed scope path
                            (equals it, contains one beneath it, or lies beneath one) - shared
                            convention, see Find-EntraOpsAzureScopeContainmentMatch. Without
                            resolved buckets the resource is treated as ControlPlane (conservative).

    The scope tier is the most privileged tier found across all assigned resources. Scopes without
    any (classified) privileged resource are UserAccess. Unknown origin systems are treated as
    ControlPlane (conservative).

.PARAMETER EntraOpsEamFolder
    Path to the folder with the classified EntraOps EAM json files (e.g. ./PrivilegedEAM).

.PARAMETER FilterClassifiedRbacs
    RBAC systems whose classified EAM data is used to classify assigned groups.

.PARAMETER FolderClassification
    Folder path to the classification definition files (for the API permissions template).

.PARAMETER AzureResourceTierScope
    Result object of Get-EntraOpsClassificationAzureResourceScope (Tier0ResourceScope /
    Tier1ResourceScope) used to classify AzureResources catalog resources. Optional - without it,
    Azure resources are classified ControlPlane (conservative).

.PARAMETER WarningMessages
    Optional list to collect warning messages raised during classification.

.EXAMPLE
    Get-EntraOpsIdGovScopeClassification -EntraOpsEamFolder $DefaultFolderClassifiedEam -AzureResourceTierScope $SharedAzureResourceScope
#>

function Get-EntraOpsIdGovScopeClassification {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$EntraOpsEamFolder
        ,
        [Parameter(Mandatory = $false)]
        [ValidateSet("Azure", "EntraID", "DeviceManagement")]
        [Array]$FilterClassifiedRbacs = ("Azure", "EntraID", "DeviceManagement")
        ,
        [Parameter(Mandatory = $false)]
        [System.String]$FolderClassification = "$DefaultFolderClassification"
        ,
        [Parameter(Mandatory = $false)]
        [psobject]$AzureResourceTierScope
        ,
        [Parameter(Mandatory = $false)]
        [System.Collections.Generic.List[psobject]]$WarningMessages
    )

    function Add-IdGovScopeWarning {
        param([string]$Type, [string]$Message, [string]$Target)
        if ($null -ne $WarningMessages) {
            $WarningMessages.Add([PSCustomObject]@{ Type = $Type; Message = $Message; Target = $Target })
        } else {
            Write-Warning $Message
        }
    }

    # Map an EAM tier tag/name to a numeric rank (lower = more privileged) and normalized names.
    # Distinct rank per tier in canonical order (ControlPlane, ManagementPlane, WorkloadPlane,
    # UserAccess, Unclassified). Unknown values map to the Unclassified rank instead of being
    # asserted as a real UserAccess classification. Numeric tag values follow the canonical map
    # (ControlPlane=0, ManagementPlane=1, WorkloadPlane=1 by name only, UserAccess=2).
    function ConvertTo-IdGovTierRank {
        param([string]$TierValue)
        switch -Regex ($TierValue) {
            '^(0|ControlPlane)$' { return 0 }
            '^(1|ManagementPlane)$' { return 1 }
            '^WorkloadPlane$' { return 2 }
            '^(2|UserAccess)$' { return 3 }
            default { return 4 }
        }
    }
    $TierRankToName = @{ 0 = "ControlPlane"; 1 = "ManagementPlane"; 2 = "WorkloadPlane"; 3 = "UserAccess"; 4 = "Unclassified" }
    # Scope buckets: WorkloadPlane shares tag value 1 (Tier1) with ManagementPlane. Unclassified is
    # deliberately NOT bucketed as Tier2 so it can no longer masquerade as a real UserAccess scope.
    $TierRankToScope = @{ 0 = "Tier0"; 1 = "Tier1"; 2 = "Tier1"; 3 = "Tier2"; 4 = "Unclassified" }

    #region Build lookups from classified EntraOps EAM data
    # Classified principals (groups) by RBAC system - same source as Get-EntraOpsPrivilegedEamIdGov
    $ClassifiedObjectsByRbac = @{}
    $ClassifiedObjectsByRbacAndId = @{}
    foreach ($RbacSystem in $FilterClassifiedRbacs) {
        $ClassificationSource = Join-Path -Path $EntraOpsEamFolder -ChildPath $RbacSystem -AdditionalChildPath "$($RbacSystem).json"
        if (Test-Path -Path $ClassificationSource) {
            try {
                $ClassifiedObjectsByRbac[$RbacSystem] = @(Get-Content -Path $ClassificationSource -ErrorAction Stop | ConvertFrom-Json -Depth 10)
                $ObjectsById = @{}
                foreach ($ClassifiedObject in $ClassifiedObjectsByRbac[$RbacSystem]) {
                    if ([string]::IsNullOrEmpty($ClassifiedObject.ObjectId)) { continue }
                    if (-not $ObjectsById.ContainsKey($ClassifiedObject.ObjectId)) {
                        $ObjectsById[$ClassifiedObject.ObjectId] = [System.Collections.Generic.List[object]]::new()
                    }
                    $ObjectsById[$ClassifiedObject.ObjectId].Add($ClassifiedObject)
                }
                $ClassifiedObjectsByRbacAndId[$RbacSystem] = $ObjectsById
            } catch {
                Add-IdGovScopeWarning -Type "ClassificationSourceError" -Message "Failed to load classified EAM file $($ClassificationSource): $_" -Target $RbacSystem
            }
        } else {
            Add-IdGovScopeWarning -Type "ClassificationSourceMissing" -Message "Classified EAM file $ClassificationSource not found - groups classified in $RbacSystem cannot be considered for Identity Governance scope classification. Run the $RbacSystem RBAC system first." -Target $RbacSystem
        }
    }

    # AadApplication origin IDs are service-principal object IDs, so classify them from the
    # ResourceApps EAM output rather than from the API-permission appId lookup.
    $ResourceAppsClassificationCache = @{}
    $ResourceAppsFile = Join-Path -Path $EntraOpsEamFolder -ChildPath "ResourceApps" -AdditionalChildPath "ResourceApps.json"
    if (Test-Path -Path $ResourceAppsFile) {
        try {
            $ResourceApps = @(Get-Content -Path $ResourceAppsFile -Raw -ErrorAction Stop | ConvertFrom-Json -Depth 10 -ErrorAction Stop)
            $ResourceAppsByObjectId = @{}
            foreach ($ResourceApp in $ResourceApps) {
                if ([string]::IsNullOrEmpty($ResourceApp.ObjectId)) { continue }
                if (-not $ResourceAppsByObjectId.ContainsKey($ResourceApp.ObjectId)) {
                    $ResourceAppsByObjectId[$ResourceApp.ObjectId] = [System.Collections.Generic.List[object]]::new()
                }
                $ResourceAppsByObjectId[$ResourceApp.ObjectId].Add($ResourceApp)
            }
            $ResourceAppsClassificationCache['ResourceApps:ByObjectId'] = $ResourceAppsByObjectId
        } catch {
            Add-IdGovScopeWarning -Type "ClassificationSourceError" -Message "Failed to load ResourceApps EAM file for AadApplication classification: $_" -Target "ResourceApps"
        }
    } else {
        Add-IdGovScopeWarning -Type "ClassificationSourceMissing" -Message "ResourceApps EAM file not found at $ResourceAppsFile - AadApplication resources will be treated as ControlPlane." -Target "ResourceApps"
    }

    # Directory role classification from classified EntraID EAM data (directory scope only)
    $EntraIdRoleAssignments = @()
    $EntraIdEamFile = Join-Path -Path $EntraOpsEamFolder -ChildPath "EntraID" -AdditionalChildPath "EntraID.json"
    if (Test-Path -Path $EntraIdEamFile) {
        try {
            $EntraIdRoleAssignments = (Get-Content -Path $EntraIdEamFile -ErrorAction Stop | ConvertFrom-Json -Depth 10).RoleAssignments
        } catch {
            Add-IdGovScopeWarning -Type "ClassificationSourceError" -Message "Failed to load EntraID EAM file for directory role classification: $_" -Target "EntraID"
        }
    }
    $EntraIdRolesByDefinitionId = @{}
    foreach ($RoleAssignment in @($EntraIdRoleAssignments)) {
        if ($RoleAssignment.RoleAssignmentScopeId -ne "/" -or [string]::IsNullOrEmpty($RoleAssignment.RoleDefinitionId)) { continue }
        if (-not $EntraIdRolesByDefinitionId.ContainsKey($RoleAssignment.RoleDefinitionId)) {
            $EntraIdRolesByDefinitionId[$RoleAssignment.RoleDefinitionId] = $RoleAssignment
        }
    }

    # Community default classification for Entra ID roles as fallback (same source as Get-EntraOpsPrivilegedEamIdGov)
    $EntraRolesDefaultClassification = @()
    try {
        $EntraRolesDefaultClassification = Invoke-RestMethod -Method Get -Uri "https://raw.githubusercontent.com/Cloud-Architekt/AzurePrivilegedIAM/refs/heads/main/Classification/Classification_EntraIdDirectoryRoles.json"
    } catch {
        Add-IdGovScopeWarning -Type "DefaultClassificationUnavailable" -Message "Could not load default Entra ID role classification from AzurePrivilegedIAM repository: $($_.Exception.Message). Unclassified directory roles will be treated as ControlPlane (conservative)." -Target "EntraIdDirectoryRoles"
    }
    $DefaultRolesByDefinitionId = @{}
    foreach ($DefaultRole in @($EntraRolesDefaultClassification)) {
        if (-not [string]::IsNullOrEmpty($DefaultRole.RoleId) -and -not $DefaultRolesByDefinitionId.ContainsKey($DefaultRole.RoleId)) {
            $DefaultRolesByDefinitionId[$DefaultRole.RoleId] = $DefaultRole
        }
    }

    # API permission classification lookup ("<resource appId>|<permission displayName>")
    $ApiPermissionsFilePath = Join-Path -Path $FolderClassification -ChildPath "Templates" -AdditionalChildPath "Classification_ApiPermissions.json"
    if (-not (Test-Path -Path $ApiPermissionsFilePath)) {
        $ApiPermissionsFilePath = Join-Path -Path $FolderClassification -ChildPath "Templates" -AdditionalChildPath "Classification_AppRoles.json"
    }
    $ApiPermissionsClassLookup = @{}
    if (Test-Path -Path $ApiPermissionsFilePath) {
        $ApiPermissionsClassification = Get-Content -Path $ApiPermissionsFilePath | ConvertFrom-Json -Depth 10
        foreach ($ApiPermissionsClass in $ApiPermissionsClassification) {
            foreach ($RoleDef in $ApiPermissionsClass.TierLevelDefinition) {
                foreach ($RoleAction in $RoleDef.RoleDefinitionActions) {
                    $key = "$($RoleDef.ResourceAppId)|$($RoleAction)"
                    if (-not $ApiPermissionsClassLookup.ContainsKey($key)) {
                        $ApiPermissionsClassLookup[$key] = [PSCustomObject]@{
                            EAMTierLevelName     = $ApiPermissionsClass.EAMTierLevelName
                            EAMTierLevelTagValue = $ApiPermissionsClass.EAMTierLevelTagValue
                            Service              = $RoleDef.Service
                        }
                    }
                }
            }
        }
    } else {
        Add-IdGovScopeWarning -Type "ClassificationSourceMissing" -Message "API permission classification template not found at $ApiPermissionsFilePath - API permissions in access packages cannot be classified." -Target "ApiPermissions"
    }

    # Normalized ARM scope buckets for AzureResources catalog resources
    $AzureTier0Scopes = @()
    $AzureTier1Scopes = @()
    if ($null -ne $AzureResourceTierScope) {
        $AzureTier0Scopes = @($AzureResourceTierScope.Tier0ResourceScope | Where-Object { $_ -and $_ -ne "/" } | ForEach-Object { $_.ToLower().TrimEnd('/') })
        $AzureTier1Scopes = @($AzureResourceTierScope.Tier1ResourceScope | Where-Object { $_ -and $_ -ne "/" } | ForEach-Object { $_.ToLower().TrimEnd('/') })
    }
    # Scope-match memoization: the same ARM scope typically recurs across catalogs and access
    # packages (e.g. a subscription onboarded to several catalogs), and each containment check is a
    # linear scan over the buckets. Keyed by normalized scope; the buckets are fixed for the whole
    # invocation, so entries can never go stale. Only the match outcome is cached - the per-call
    # detail object (ResourceName/Source/RoleContext) is still built fresh for each resource.
    $AzureScopeMatchCache = @{}
    #endregion

    #region Per-resource classification helpers
    # Graph returns catalog resources, access packages and resource role scopes in no guaranteed order, so the
    # collected detail lists (ClassifiedResources) and the "first 3" tier drivers picked for the Reason text
    # changed between runs without any data change (e.g. two equally classified groups swapping places).
    # Sorting by name/id/reason makes ScopeReasoning_IdentityGovernance.json deterministic; -Stable keeps
    # exact duplicates in their original relative order.
    function Sort-IdGovResourceDetail {
        param([object[]]$Details)
        @($Details | Where-Object { $null -ne $_ } | Sort-Object -Stable -Property ResourceName, ResourceId, Reason)
    }

    # Returns detail entries: ResourceName, ResourceId, OriginSystem, Source, EAMTier, Reason
    function Get-ClassifiedGroupDetail {
        param([string]$GroupId, [string]$GroupDisplayName, [string]$Source)
        $Details = [System.Collections.Generic.List[psobject]]::new()
        # Iterate the fixed, parameter-declared RBAC system order (not $ClassifiedObjectsByRbac.Keys) - a plain
        # PowerShell hashtable gives no enumeration-order guarantee, so using .Keys here made the resulting
        # Reason list (and thus ScopeReasoning_IdentityGovernance.json) reorder on every run with no data change.
        foreach ($RbacSystem in $FilterClassifiedRbacs) {
            if (-not $ClassifiedObjectsByRbac.ContainsKey($RbacSystem)) { continue }
            $ClassifiedObject = @($ClassifiedObjectsByRbacAndId[$RbacSystem][$GroupId])
            # Also sort the per-object Classification entries deterministically (by tier then Service) rather
            # than trusting their upstream order, for the same reason.
            $ClassItems = @($ClassifiedObject.Classification | Where-Object { $null -ne $_.AdminTierLevel } | Sort-Object AdminTierLevel, Service)
            foreach ($ClassItem in $ClassItems) {
                $Details.Add([PSCustomObject]@{
                        ResourceName = $GroupDisplayName
                        ResourceId   = $GroupId
                        OriginSystem = "AadGroup"
                        Source       = $Source
                        EAMTier      = $TierRankToName[(ConvertTo-IdGovTierRank -TierValue "$($ClassItem.AdminTierLevel)")]
                        Reason       = "Group '$GroupDisplayName' is classified as $($ClassItem.AdminTierLevelName) ($($ClassItem.Service)) in $RbacSystem"
                    }) | Out-Null
            }
        }
        if ($Details.Count -eq 0) {
            $Details.Add([PSCustomObject]@{
                    ResourceName = $GroupDisplayName
                    ResourceId   = $GroupId
                    OriginSystem = "AadGroup"
                    Source       = $Source
                    EAMTier      = "UserAccess"
                    Reason       = "Group '$GroupDisplayName' is not classified in any RBAC system ($($FilterClassifiedRbacs -join ', '))"
                }) | Out-Null
        }
        return $Details
    }

    function Get-ClassifiedDirectoryRoleDetail {
        param([string]$RoleDefinitionId, [string]$RoleDisplayName, [string]$Source)
        $MatchedRole = $EntraIdRolesByDefinitionId[$RoleDefinitionId]
        if ($null -ne $MatchedRole -and $null -ne $MatchedRole.Classification.AdminTierLevel) {
            # The access package resource role scope expansion only carries the scope's generic display
            # name (e.g. "Root"), so prefer the resolved role definition name from the EAM data.
            if (-not [string]::IsNullOrEmpty($MatchedRole.RoleDefinitionName)) { $RoleDisplayName = $MatchedRole.RoleDefinitionName }
            $BestRank = ($MatchedRole.Classification | ForEach-Object { ConvertTo-IdGovTierRank -TierValue "$($_.AdminTierLevel)" } | Measure-Object -Minimum).Minimum
            return [PSCustomObject]@{
                ResourceName = $RoleDisplayName
                ResourceId   = $RoleDefinitionId
                OriginSystem = "DirectoryRole"
                Source       = $Source
                EAMTier      = $TierRankToName[[int]$BestRank]
                Reason       = "Directory role '$RoleDisplayName' is classified as $($TierRankToName[[int]$BestRank]) in EntraID EAM data"
            }
        }
        $MatchedDefaultRole = $DefaultRolesByDefinitionId[$RoleDefinitionId]
        if ($null -ne $MatchedDefaultRole -and $null -ne $MatchedDefaultRole.RolePermissions) {
            if (-not [string]::IsNullOrEmpty($MatchedDefaultRole.RoleName)) { $RoleDisplayName = $MatchedDefaultRole.RoleName }
            $BestRank = ($MatchedDefaultRole.RolePermissions | ForEach-Object { ConvertTo-IdGovTierRank -TierValue "$($_.EAMTierLevelTagValue)" } | Measure-Object -Minimum).Minimum
            return [PSCustomObject]@{
                ResourceName = $RoleDisplayName
                ResourceId   = $RoleDefinitionId
                OriginSystem = "DirectoryRole"
                Source       = $Source
                EAMTier      = $TierRankToName[[int]$BestRank]
                Reason       = "Directory role '$RoleDisplayName' is classified as $($TierRankToName[[int]$BestRank]) in the default classification (AzurePrivilegedIAM)"
            }
        }
        return [PSCustomObject]@{
            ResourceName = $RoleDisplayName
            ResourceId   = $RoleDefinitionId
            OriginSystem = "DirectoryRole"
            Source       = $Source
            EAMTier      = "ControlPlane"
            Reason       = "Directory role '$RoleDisplayName' ($RoleDefinitionId) has no classification - treated as ControlPlane (conservative)"
        }
    }

    function Get-ClassifiedApiPermissionDetail {
        param([string]$ResourceAppId, [string]$ResourceAppDisplayName, [string]$PermissionDisplayName, [string]$PermissionOriginId, [string]$Source)
        $AppRoleMatch = $ApiPermissionsClassLookup["$ResourceAppId|$PermissionDisplayName"]
        if ($null -ne $AppRoleMatch) {
            $Rank = ConvertTo-IdGovTierRank -TierValue "$($AppRoleMatch.EAMTierLevelTagValue)"
            return [PSCustomObject]@{
                ResourceName = $PermissionDisplayName
                ResourceId   = $PermissionOriginId
                OriginSystem = "OAuthApplication"
                Source       = $Source
                EAMTier      = $TierRankToName[$Rank]
                Reason       = "API permission '$PermissionDisplayName' of '$ResourceAppDisplayName' is classified as $($AppRoleMatch.EAMTierLevelName) ($($AppRoleMatch.Service))"
            }
        }
        return [PSCustomObject]@{
            ResourceName = $PermissionDisplayName
            ResourceId   = $PermissionOriginId
            OriginSystem = "OAuthApplication"
            Source       = $Source
            EAMTier      = "ControlPlane"
            Reason       = "API permission '$PermissionDisplayName' of '$ResourceAppDisplayName' has no classification - treated as ControlPlane (conservative)"
        }
    }

    function Get-ClassifiedAadApplicationDetail {
        param([string]$ServicePrincipalObjectId, [string]$ApplicationDisplayName, [string]$Source, [string]$RoleContext)
        $Classifications = @(Get-EntraOpsAadApplicationClassification -ServicePrincipalObjectId $ServicePrincipalObjectId -ClassificationCache $ResourceAppsClassificationCache -DisplayName $ApplicationDisplayName -ContextLabel $Source -WarningMessages $WarningMessages)
        $BestRank = ($Classifications | ForEach-Object { ConvertTo-IdGovTierRank -TierValue $_.AdminTierLevelName } | Measure-Object -Minimum).Minimum
        $TierDrivers = @($Classifications | Where-Object { (ConvertTo-IdGovTierRank -TierValue $_.AdminTierLevelName) -eq $BestRank })
        $Services = @($TierDrivers.Service | Where-Object { $_ } | Select-Object -Unique)
        $RoleSuffix = if ([string]::IsNullOrEmpty($RoleContext)) { "" } else { " (role: $RoleContext)" }
        return [pscustomobject]@{
            ResourceName = $ApplicationDisplayName
            ResourceId   = $ServicePrincipalObjectId
            OriginSystem = "AadApplication"
            Source       = $Source
            EAMTier      = $TierRankToName[[int]$BestRank]
            # The tier is a proxy: it reflects the application's OWN classified permissions
            # (ResourceApps), on the basis that access to an app which itself holds
            # privileged permissions is equivalent exposure - not permissions granted to the assignee.
            Reason       = "Application '$ApplicationDisplayName' is classified as $($TierRankToName[[int]$BestRank]) based on its own ResourceApps permission classification (app access tiered by the application's privilege)$RoleSuffix$(if ($Services.Count -gt 0) { ' (' + ($Services -join ', ') + ')' })"
        }
    }

    function Get-ClassifiedSharePointOnlineDetail {
        param([string]$SiteUrl, [string]$SiteDisplayName, [string]$RoleDisplayName, [string]$RoleOriginId, [string]$Source)
        $Tier = Resolve-EntraOpsSharePointOnlineRoleTier -RoleDisplayName $RoleDisplayName -RoleOriginId $RoleOriginId
        if ($Tier.IsFallback) {
            Add-IdGovScopeWarning -Type "UnknownSharePointRole" -Message "SharePoint role '$RoleDisplayName' (originId '$RoleOriginId') for '$SiteDisplayName' is not recognized - treated as ManagementPlane (conservative)." -Target $SiteUrl
        }
        $Reason = if ($Tier.IsCatalogLevel) {
            "SharePoint site '$SiteDisplayName' is exposed at catalog level - contained roles (including owner-level) are not enumerated here - treated as $($Tier.AdminTierLevelName) (conservative)"
        } else {
            "SharePoint site '$SiteDisplayName' with role '$RoleDisplayName' is classified as $($Tier.AdminTierLevelName)"
        }
        return [pscustomobject]@{
            ResourceName = $SiteDisplayName
            ResourceId   = $SiteUrl
            OriginSystem = "SharePointOnline"
            Source       = $Source
            EAMTier      = $Tier.AdminTierLevelName
            Reason       = $Reason
        }
    }

    function Get-ClassifiedAzureResourceDetail {
        param([string]$ArmScopeId, [string]$ResourceDisplayName, [string]$Source, [string]$RoleContext)
        $RoleSuffix = if ([string]::IsNullOrEmpty($RoleContext)) { "" } else { " (role: $RoleContext)" }
        if ($null -eq $AzureResourceTierScope) {
            return [PSCustomObject]@{
                ResourceName = $ResourceDisplayName
                ResourceId   = $ArmScopeId
                OriginSystem = "AzureResources"
                Source       = $Source
                EAMTier      = "ControlPlane"
                Reason       = "Azure scope '$ArmScopeId' could not be evaluated (no Azure resource tier scope resolved) - treated as ControlPlane (conservative)$RoleSuffix"
            }
        }
        $NormalizedScope = "$ArmScopeId".ToLower().TrimEnd('/')
        # Shared containment convention (Find-EntraOpsAzureScopeContainmentMatch), identical to the
        # EAM-side Resolve-EntraOpsAzureScopeReasoningTier so both outputs agree for the same catalog.
        # The match outcome per normalized scope is memoized in $AzureScopeMatchCache (see its
        # declaration for the invariants); the detail object stays per-call.
        $ScopeMatch = $AzureScopeMatchCache[$NormalizedScope]
        if ($null -eq $ScopeMatch) {
            $Tier0Match = Find-EntraOpsAzureScopeContainmentMatch -Scope $NormalizedScope -BucketedScopes $AzureTier0Scopes
            if ($null -ne $Tier0Match) {
                $ScopeMatch = [PSCustomObject]@{ EAMTier = "ControlPlane"; TierLabel = "Tier0 (ControlPlane)"; MatchedScope = $Tier0Match }
            } else {
                $Tier1Match = Find-EntraOpsAzureScopeContainmentMatch -Scope $NormalizedScope -BucketedScopes $AzureTier1Scopes
                if ($null -ne $Tier1Match) {
                    $ScopeMatch = [PSCustomObject]@{ EAMTier = "ManagementPlane"; TierLabel = "Tier1 (ManagementPlane)"; MatchedScope = $Tier1Match }
                } else {
                    $ScopeMatch = [PSCustomObject]@{ EAMTier = "UserAccess"; TierLabel = $null; MatchedScope = $null }
                }
            }
            $AzureScopeMatchCache[$NormalizedScope] = $ScopeMatch
        }
        if ($null -ne $ScopeMatch.MatchedScope) {
            return [PSCustomObject]@{
                ResourceName = $ResourceDisplayName
                ResourceId   = $ArmScopeId
                OriginSystem = "AzureResources"
                Source       = $Source
                EAMTier      = $ScopeMatch.EAMTier
                Reason       = "Azure scope '$ArmScopeId' equals, contains or lies within $($ScopeMatch.TierLabel) resource scope '$($ScopeMatch.MatchedScope)'$RoleSuffix"
            }
        }
        return [PSCustomObject]@{
            ResourceName = $ResourceDisplayName
            ResourceId   = $ArmScopeId
            OriginSystem = "AzureResources"
            Source       = $Source
            EAMTier      = "UserAccess"
            Reason       = "Azure scope '$ArmScopeId' has no hierarchy overlap with any Tier0/Tier1 classified resource scope$RoleSuffix"
        }
    }

    # Classify a single accessPackageResourceRoleScope (expanded with role and scope)
    function Get-ClassifiedResourceRoleScopeDetail {
        param([psobject]$ResourceRoleScope, [string]$Source)
        $ResourceRole = $ResourceRoleScope.accessPackageResourceRole
        $ResourceScope = $ResourceRoleScope.accessPackageResourceScope
        $IsPending = ($null -ne $ResourceRoleScope.PSObject.Properties['isPending'] -and $ResourceRoleScope.isPending -eq $true)

        $Details = switch ($ResourceScope.originSystem) {
            'AadGroup' { Get-ClassifiedGroupDetail -GroupId $ResourceScope.originId -GroupDisplayName $ResourceScope.displayName -Source $Source }
            'DirectoryRole' { Get-ClassifiedDirectoryRoleDetail -RoleDefinitionId $ResourceScope.originId -RoleDisplayName $ResourceScope.displayName -Source $Source }
            'OAuthApplication' { Get-ClassifiedApiPermissionDetail -ResourceAppId $ResourceScope.originId -ResourceAppDisplayName $ResourceScope.displayName -PermissionDisplayName $ResourceRole.displayName -PermissionOriginId $ResourceRole.originId -Source $Source }
            'AadApplication' { Get-ClassifiedAadApplicationDetail -ServicePrincipalObjectId $ResourceScope.originId -ApplicationDisplayName $ResourceScope.displayName -Source $Source -RoleContext $ResourceRole.displayName }
            'SharePointOnline' { Get-ClassifiedSharePointOnlineDetail -SiteUrl $ResourceScope.originId -SiteDisplayName $ResourceScope.displayName -RoleDisplayName $ResourceRole.displayName -RoleOriginId "$($ResourceRole.originId)" -Source $Source }
            'AzureResources' { Get-ClassifiedAzureResourceDetail -ArmScopeId $ResourceScope.originId -ResourceDisplayName $ResourceScope.displayName -Source $Source -RoleContext $ResourceRole.displayName }
            default {
                Add-IdGovScopeWarning -Type "UnknownOriginSystem" -Message "Origin system $($ResourceScope.originSystem) not supported for Identity Governance scope classification - treated as ControlPlane (conservative)." -Target "$($ResourceScope.originSystem)"
                [PSCustomObject]@{
                    ResourceName = $ResourceScope.displayName
                    ResourceId   = $ResourceScope.originId
                    OriginSystem = $ResourceScope.originSystem
                    Source       = $Source
                    EAMTier      = "ControlPlane"
                    Reason       = "Origin system '$($ResourceScope.originSystem)' is not supported for classification - treated as ControlPlane (conservative)"
                }
            }
        }
        if ($IsPending) {
            foreach ($Detail in @($Details)) {
                $Detail.Reason = "$($Detail.Reason) [pending approval]"
            }
        }
        return @($Details)
    }
    #endregion

    #region Enumerate and classify catalogs and access packages
    $ScopeClassifications = [System.Collections.Generic.List[psobject]]::new()

    try {
        $AllCatalogs = @(Invoke-EntraOpsMsGraphQuery -Uri "/beta/identityGovernance/entitlementManagement/accessPackageCatalogs?`$select=id,displayName" -OutputType PSObject)
    } catch {
        Add-IdGovScopeWarning -Type "CatalogEnumerationError" -Message "Failed to enumerate access package catalogs: $($_.Exception.Message). Identity Governance scope classification will keep the conservative Tier0 default for all scopes." -Target "AccessPackageCatalogs"
        return @()
    }

    $AccessPackageHydrationCache = @{}
    foreach ($Catalog in $AllCatalogs) {
        $CatalogScopeId = "/AccessPackageCatalog/$($Catalog.id)"
        $CatalogResourceDetails = [System.Collections.Generic.List[psobject]]::new()

        try {
            $CatalogResources = @(Invoke-EntraOpsMsGraphQuery -Uri "/beta/identityGovernance/entitlementManagement/accessPackageCatalogs/$($Catalog.id)/accessPackageResources?`$expand=accessPackageResourceScopes,accessPackageResourceRoles" -ConsistencyLevel "eventual" -OutputType PSObject | Where-Object { $null -ne $_.originId })
        } catch {
            Add-IdGovScopeWarning -Type "CatalogResolutionError" -Message "Error resolving resources of catalog $($Catalog.id): $($_.Exception.Message) - catalog is treated as ControlPlane (conservative)." -Target $Catalog.id
            $CatalogResources = $null
        }
        try {
            # Neither accessPackageCatalogs/{id}/accessPackages (invalid navigation path, 404) nor
            # the top-level accessPackages collection with $filter=catalogId/catalog-id eq (Graph
            # returns InvalidFilter - $filter isn't supported on that collection at all) work.
            # Expanding accessPackages directly on the catalog's own single-entity GET does work -
            # the response is the CATALOG entity with access package stubs nested under
            # .accessPackages (not a flat list), unwrapped here. Also deliberately no nested $expand
            # of accessPackageResourceRoleScopes - each access package's resource role scopes are
            # hydrated individually below instead.
            $CatalogWithAccessPackages = Invoke-EntraOpsMsGraphQuery -Uri "/beta/identityGovernance/entitlementManagement/accessPackageCatalogs('$($Catalog.id)')?`$expand=accessPackages" -ConsistencyLevel "eventual" -OutputType PSObject
            $CatalogAccessPackageStubs = @(@($CatalogWithAccessPackages) | Select-Object -First 1 -ExpandProperty accessPackages -ErrorAction SilentlyContinue)
            $CatalogAccessPackages = @(
                foreach ($AccessPackageStub in $CatalogAccessPackageStubs) {
                    if ($null -eq $AccessPackageStub -or [string]::IsNullOrEmpty($AccessPackageStub.id)) {
                        continue
                    }
                    if (-not $AccessPackageHydrationCache.ContainsKey($AccessPackageStub.id)) {
                        $AccessPackageHydrationCache[$AccessPackageStub.id] = Invoke-EntraOpsMsGraphQuery -Uri "/beta/identityGovernance/entitlementManagement/accessPackages/$($AccessPackageStub.id)?`$expand=accessPackageResourceRoleScopes(`$expand=accessPackageResourceRole,accessPackageResourceScope)" -ConsistencyLevel "eventual" -OutputType PSObject
                    }
                    $AccessPackageHydrationCache[$AccessPackageStub.id]
                }
            )
        } catch {
            Add-IdGovScopeWarning -Type "AccessPackageResolutionError" -Message "Error resolving access packages of catalog $($Catalog.id): $($_.Exception.Message) - catalog is treated as ControlPlane (conservative)." -Target $Catalog.id
            $CatalogAccessPackages = $null
        }

        # A failed Graph resolution must not silently downgrade the catalog to UserAccess
        $CatalogResolutionFailed = ($null -eq $CatalogResources -or $null -eq $CatalogAccessPackages)

        # Catalog-level resources: groups, directory roles and Azure resources. API permissions are
        # intentionally NOT taken from the catalog resource inventory: the catalog-level
        # accessPackageResourceRoles enumeration for API resources returns permissions across catalogs
        # (Microsoft Graph beta bug), so they are classified from the access packages below instead.
        foreach ($CatalogResource in @($CatalogResources)) {
            switch ($CatalogResource.originSystem) {
                'AadGroup' {
                    foreach ($Detail in @(Get-ClassifiedGroupDetail -GroupId $CatalogResource.originId -GroupDisplayName $CatalogResource.displayName -Source "CatalogResource")) {
                        $CatalogResourceDetails.Add($Detail) | Out-Null
                    }
                }
                'DirectoryRole' {
                    if ($CatalogResource.accessPackageResourceScopes.isRootScope -ne $true) {
                        Add-IdGovScopeWarning -Type "ScopeLimitation" -Message "Assigned catalog resource scope of directory role '$($CatalogResource.displayName)' is not root scope - directory roles are currently only supported on root scope!" -Target $CatalogResource.displayName
                    }
                    $CatalogResourceDetails.Add((Get-ClassifiedDirectoryRoleDetail -RoleDefinitionId $CatalogResource.originId -RoleDisplayName $CatalogResource.displayName -Source "CatalogResource")) | Out-Null
                }
                'OAuthApplication' {
                    Write-Verbose "Skipping catalog-level API permission enumeration of '$($CatalogResource.displayName)' in catalog $($Catalog.id) (unreliable across catalogs) - classified from access package resource role scopes instead."
                }
                'AadApplication' {
                    $CatalogResourceDetails.Add((Get-ClassifiedAadApplicationDetail -ServicePrincipalObjectId $CatalogResource.originId -ApplicationDisplayName $CatalogResource.displayName -Source "CatalogResource" -RoleContext $null)) | Out-Null
                }
                'SharePointOnline' {
                    # Catalog-level entry carries no role - the resolver returns the conservative
                    # ManagementPlane catalog-level result without an unknown-role warning.
                    $CatalogResourceDetails.Add((Get-ClassifiedSharePointOnlineDetail -SiteUrl $CatalogResource.originId -SiteDisplayName $CatalogResource.displayName -RoleDisplayName "" -RoleOriginId "" -Source "CatalogResource")) | Out-Null
                }
                'AzureResources' {
                    $CatalogResourceDetails.Add((Get-ClassifiedAzureResourceDetail -ArmScopeId $CatalogResource.originId -ResourceDisplayName $CatalogResource.displayName -Source "CatalogResource" -RoleContext $null)) | Out-Null
                }
                default {
                    Add-IdGovScopeWarning -Type "UnknownOriginSystem" -Message "Origin system $($CatalogResource.originSystem) not supported for Identity Governance scope classification - treated as ControlPlane (conservative)." -Target "$($CatalogResource.originSystem)"
                    $CatalogResourceDetails.Add([PSCustomObject]@{
                            ResourceName = $CatalogResource.displayName
                            ResourceId   = $CatalogResource.originId
                            OriginSystem = $CatalogResource.originSystem
                            Source       = "CatalogResource"
                            EAMTier      = "ControlPlane"
                            Reason       = "Origin system '$($CatalogResource.originSystem)' is not supported for classification - treated as ControlPlane (conservative)"
                        }) | Out-Null
                }
            }
        }

        # Access packages: classify each access package scope AND feed API permissions (and any other
        # resource role scopes) into the catalog tier
        foreach ($AccessPackage in @($CatalogAccessPackages | Where-Object { $null -ne $_ })) {
            $AccessPackageScopeId = "/AccessPackage/$($AccessPackage.id)"
            $AccessPackageResourceDetails = [System.Collections.Generic.List[psobject]]::new()
            $ResourceRoleScopes = @($AccessPackage.accessPackageResourceRoleScopes | Where-Object { $null -ne $_.accessPackageResourceRole -and $null -ne $_.accessPackageResourceScope })
            foreach ($ResourceRoleScope in $ResourceRoleScopes) {
                foreach ($Detail in @(Get-ClassifiedResourceRoleScopeDetail -ResourceRoleScope $ResourceRoleScope -Source "AccessPackageResource")) {
                    $AccessPackageResourceDetails.Add($Detail) | Out-Null
                    # API permissions only count towards the catalog tier via access packages (see above);
                    # groups/roles/Azure scopes are already covered by the catalog resource inventory.
                    if ($Detail.OriginSystem -eq "OAuthApplication") {
                        $CatalogResourceDetails.Add($Detail) | Out-Null
                    }
                }
            }

            $AccessPackageResourceDetails = @(Sort-IdGovResourceDetail -Details $AccessPackageResourceDetails)
            $ApBestRank = 3   # UserAccess rank - scopes without any assigned resource are UserAccess (see .DESCRIPTION)
            $ApReason = "No resource role scopes are assigned to this access package"
            $ApSource = "AccessPackageResource"
            if ($AccessPackageResourceDetails.Count -gt 0) {
                $ApBestRank = ($AccessPackageResourceDetails | ForEach-Object { ConvertTo-IdGovTierRank -TierValue $_.EAMTier } | Measure-Object -Minimum).Minimum
                $ApTierDrivers = @($AccessPackageResourceDetails | Where-Object { (ConvertTo-IdGovTierRank -TierValue $_.EAMTier) -eq $ApBestRank })
                $ApReason = (@($ApTierDrivers | Select-Object -First 3 | ForEach-Object { $_.Reason }) -join "; ")
                if ($ApTierDrivers.Count -gt 3) { $ApReason += "; (+$($ApTierDrivers.Count - 3) more)" }
            }
            $ScopeClassifications.Add([PSCustomObject]@{
                    ScopeName           = $AccessPackage.displayName
                    ScopeId             = $AccessPackageScopeId
                    ScopeType           = "AccessPackage"
                    CatalogId           = $Catalog.id
                    CatalogDisplayName  = $Catalog.displayName
                    Source              = $ApSource
                    EAMTier             = $TierRankToName[[int]$ApBestRank]
                    ResultingScope      = $TierRankToScope[[int]$ApBestRank]
                    Reason              = $ApReason
                    ClassifiedResources = @($AccessPackageResourceDetails)
                }) | Out-Null
        }

        $CatalogResourceDetails = @(Sort-IdGovResourceDetail -Details $CatalogResourceDetails)
        $CatalogBestRank = 3   # UserAccess rank - scopes without any assigned resource are UserAccess (see .DESCRIPTION)
        $CatalogReason = "No resources are assigned to this catalog or its access packages"
        if ($CatalogResolutionFailed) {
            $CatalogBestRank = 0
            $CatalogReason = "Catalog resources or access packages could not be resolved - treated as ControlPlane (conservative)"
        } elseif ($CatalogResourceDetails.Count -gt 0) {
            $CatalogBestRank = ($CatalogResourceDetails | ForEach-Object { ConvertTo-IdGovTierRank -TierValue $_.EAMTier } | Measure-Object -Minimum).Minimum
            $CatalogTierDrivers = @($CatalogResourceDetails | Where-Object { (ConvertTo-IdGovTierRank -TierValue $_.EAMTier) -eq $CatalogBestRank })
            $CatalogReason = (@($CatalogTierDrivers | Select-Object -First 3 | ForEach-Object { $_.Reason }) -join "; ")
            if ($CatalogTierDrivers.Count -gt 3) { $CatalogReason += "; (+$($CatalogTierDrivers.Count - 3) more)" }
        }
        $ScopeClassifications.Add([PSCustomObject]@{
                ScopeName           = $Catalog.displayName
                ScopeId             = $CatalogScopeId
                ScopeType           = "AccessPackageCatalog"
                CatalogId           = $Catalog.id
                CatalogDisplayName  = $Catalog.displayName
                Source              = "CatalogResource"
                EAMTier             = $TierRankToName[[int]$CatalogBestRank]
                ResultingScope      = $TierRankToScope[[int]$CatalogBestRank]
                Reason              = $CatalogReason
                ClassifiedResources = @($CatalogResourceDetails)
            }) | Out-Null
    }
    #endregion

    # Deliberately NOT using ", @($ScopeClassifications)" here: the caller wraps this call in its own
    # @(...) (Update-EntraOpsClassificationControlPlaneScope.ps1), and a leading comma would emit the
    # whole list as a single pipeline object, which the caller's @() then wraps AGAIN into a 1-element
    # outer array containing the inner array - collapsing every entry into one item and breaking
    # property access (e.g. Where-Object/Select-Object -ExpandProperty) on the individual objects.
    return $ScopeClassifications
}
