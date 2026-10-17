<#
.SYNOPSIS
    Get a list in schema of EntraOps with all privileged principals in Identity Governance and assigned roles and classifications.

.DESCRIPTION
    Get a list in schema of EntraOps with all privileged principals in Identity Governance and assigned roles and classifications.

.PARAMETER TenantId
    Tenant ID of the Microsoft Entra ID tenant. Default is the current tenant ID.

.PARAMETER FolderClassification
    Folder path to the classification definition files. Default is "./Classification".

.PARAMETER FolderClassifiedObjects
    Folder path to the JSON files of classified objects which will be used to identify privileged objects in access packages or catalogs.
    Default is "./PrivilegedEAM".

.PARAMETER FilterClassifiedRbacs
    Filter classified objects by selected RBAC system. Default is "Azure", "EntraID", "DeviceManagement".
    All classified objects will be used to apply classification to to the access package or catalog if a group object is assigned.

.PARAMETER SampleMode
    Use sample data for testing or offline mode. Default is $False. Default sample data is stored in "./Samples"

.PARAMETER GlobalExclusion
    Use global exclusion list for classification. Default is $true. Global exclusion list is stored in "./Classification/Global.json".

.PARAMETER IncludeJustification
    Include the Justification property (documenting a manual classification overwrite) on all Classification
    entries of the returned objects. Default is $false, so the property is not present in the output at all.

.PARAMETER ExcludeInvalidOrDeletedScopes
    Exclude role assignments whose scope (e.g. access package catalog) could not be resolved and is
    shown as "Invalid or deleted object" from the output. Default is $true.

.PARAMETER HideTaggedBy
    Hide the TaggedBy properties (TaggedBy, TaggedByObjectIds, TaggedByObjectDisplayNames,
    TaggedByRoleSystem - documenting which assigned catalog/access package resource caused a
    classification) on all Classification entries of the returned objects. Default is $false.
    Note: reports and exports (e.g. BloodHound, dashboards) consume TaggedBy from the persisted
    EAM JSON files - only set this to $true if the output is not used for those consumers, or use
    ScopeReasoning_IdentityGovernance.json for the per-scope reasoning instead.

.PARAMETER IncludeObjectDetails
    Include descriptive object details in warning output. Defaults to ConsoleOutput.IncludeObjectDetails from
    EntraOpsConfig.json. Object IDs are always shown.
#>

function Get-EntraOpsPrivilegedEamIdGov {
    [cmdletbinding()]
    param (
        [Parameter(Mandatory = $false)]
        [System.String]$TenantId = (Get-EntraOpsAzContextValue -Property TenantId)
        ,
        [Parameter(Mandatory = $false)]
        [System.String]$FolderClassification = "$DefaultFolderClassification"
        ,
        [Parameter(Mandatory = $false)]
        [System.String]$FolderClassifiedObjects = "$DefaultFolderClassifiedEam"
        ,
        [Parameter(Mandatory = $false)]
        [ValidateSet("Azure", "EntraID", "DeviceManagement")]
        [Array]$FilterClassifiedRbacs = ("Azure", "EntraID", "DeviceManagement")
        ,
        [Parameter(Mandatory = $false)]
        [System.Boolean]$SampleMode = $False
        ,
        [Parameter(Mandatory = $false)]
        [System.Boolean]$GlobalExclusion = $true
        ,
        [Parameter(Mandatory = $false)]
        [System.Boolean]$EnableParallelProcessing = $true
        ,
        [Parameter(Mandatory = $false)]
        [System.Int32]$ParallelThrottleLimit = 10
        ,
        [Parameter(Mandatory = $false)]
        [switch]$IncludeJustification
        ,
        [Parameter(Mandatory = $false)]
        [System.Boolean]$ExcludeInvalidOrDeletedScopes = $true
        ,
        [Parameter(Mandatory = $false)]
        [System.Boolean]$HideTaggedBy = $false
        ,
        [Parameter(Mandatory = $false)]
        [System.Boolean]$IncludeObjectDetails = [bool]$Global:EntraOpsIncludeObjectDetails
    )

    # Configuration for batch processing
    $BatchSize = 100  # Number of objects to process before showing progress
    $WarningMessages = New-Object -TypeName "System.Collections.Generic.List[psobject]"

    # Check if classification file custom and/or template file exists, choose custom template for tenant if available
    $IdGovClassificationFilePath = Resolve-EntraOpsClassificationPath -ClassificationFileName "Classification_IdentityGovernance.json"

    # Default classification for Entra ID roles if no classified role definition found
    $EntraRolesDefaultClassification = Invoke-RestMethod -Method Get -Uri "https://raw.githubusercontent.com/Cloud-Architekt/AzurePrivilegedIAM/refs/heads/main/Classification/Classification_EntraIdDirectoryRoles.json"

    # Classification for API permissions
    $ApiPermissionsFilePath = $FolderClassification + "/Templates/Classification_ApiPermissions.json"
    if (-not (Test-Path -Path $ApiPermissionsFilePath)) {
        $ApiPermissionsFilePath = $FolderClassification + "/Templates/Classification_AppRoles.json"
    }
    $ApiPermissionsClassification = Get-Content -Path $ApiPermissionsFilePath | ConvertFrom-Json -Depth 10

    # Get all role assignments and global exclusions
    #region Stage 1: Fetch Identity Governance Assignments
    $Stage1Start = Get-Date
    Write-Host ""
    Write-Host "═══════════════════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "  Stage 1/4: Fetching Identity Governance Assignments" -ForegroundColor Cyan
    Write-Host "═══════════════════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "Retrieving Identity Governance role assignments, catalogs, and access packages..." -ForegroundColor Gray
    Write-Progress -Activity "Stage 1/4: Fetching Identity Governance" -Status "Loading role assignments and global exclusions..." -PercentComplete 10

    if ($SampleMode -ne $True) {
        $IdGovRbacAssignments = Get-EntraOpsPrivilegedIdGovRoles -TenantId $TenantId -WarningMessages $WarningMessages -ExcludeInvalidOrDeletedScopes $ExcludeInvalidOrDeletedScopes
    } else {
        $WarningMessages.Add([PSCustomObject]@{Type = "Stage1"; Message = "SampleMode currently not supported!" })
    }

    $GlobalExclusionList = Import-EntraOpsGlobalExclusions -Enabled $GlobalExclusion
    
    $Stage1Duration = ((Get-Date) - $Stage1Start).TotalSeconds
    Write-Host "✓ Stage 1 completed in $([Math]::Round($Stage1Duration, 2)) seconds ($($IdGovRbacAssignments.Count) role assignments retrieved)" -ForegroundColor Green
    Write-Progress -Activity "Stage 1/4: Fetching Identity Governance" -Completed
    #endregion

    # Return early if no role assignments found to prevent null index errors
    if ($null -eq $IdGovRbacAssignments -or @($IdGovRbacAssignments).Count -eq 0) {
        Write-Warning "No Identity Governance role assignments found. Returning empty result."
        return @()
    }

    #region Classification of assignments
    #region Stage 2: Classify Catalog Objects
    $Stage2Start = Get-Date
    Write-Host ""
    Write-Host "═══════════════════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "  Stage 2/4: Classifying Catalog Objects" -ForegroundColor Cyan
    Write-Host "═══════════════════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "Analyzing assigned catalog resources (groups, directory roles, app roles) and matching classifications..." -ForegroundColor Gray
    Write-Progress -Activity "Stage 2/4: Classifying Catalog Objects" -Status "Processing catalog resources..." -PercentComplete 25
    
    # Optimization: Pre-load classification files into memory to avoid N+1 File I/O
    $ClassificationCache = @{}
    foreach ($RbacSystem in $FilterClassifiedRbacs) {
        $ClassificationSource = $FolderClassifiedObjects + $RbacSystem + "/" + $RbacSystem + ".json"
        if (Test-Path $ClassificationSource) {
            Write-Verbose "Pre-loading classification file from $ClassificationSource..."
            try {
                $ClassificationCache[$RbacSystem] = @(
                    Get-Content -Path $ClassificationSource -Raw -ErrorAction Stop |
                        ConvertFrom-Json -Depth 10 -ErrorAction Stop |
                        Where-Object { $null -ne $_ }
                )
                $ObjectsById = @{}
                foreach ($ClassifiedObject in $ClassificationCache[$RbacSystem]) {
                    if ([string]::IsNullOrEmpty($ClassifiedObject.ObjectId)) { continue }
                    if (-not $ObjectsById.ContainsKey($ClassifiedObject.ObjectId)) {
                        $ObjectsById[$ClassifiedObject.ObjectId] = [System.Collections.Generic.List[object]]::new()
                    }
                    $ObjectsById[$ClassifiedObject.ObjectId].Add($ClassifiedObject)
                }
                $ClassificationCache["${RbacSystem}:ByObjectId"] = $ObjectsById
                if ($null -eq $ClassificationCache[$RbacSystem] -or @($ClassificationCache[$RbacSystem]).Count -eq 0) {
                    $WarningMessages.Add([PSCustomObject]@{
                            Type    = "Classification Source Empty"
                            Message = "Classification file $ClassificationSource loaded empty - catalog groups classified in $RbacSystem will be missing their inherited classification. Re-run the $RbacSystem RBAC system first."
                            Target  = $RbacSystem
                        })
                }
            } catch {
                $WarningMessages.Add([PSCustomObject]@{Type = "Stage2"; Message = "Failed to load classification file $($ClassificationSource): $_" })
            }
        } else {
            # A missing source silently drops every classification inherited from this RBAC system
            # (e.g. Azure-classified groups in catalogs) - surface it loudly instead
            $WarningMessages.Add([PSCustomObject]@{
                    Type    = "Classification Source Missing"
                    Message = "Classification file $ClassificationSource not found - catalog groups classified in $RbacSystem will be missing their inherited classification. Run the $RbacSystem RBAC system first (e.g. after an interrupted or failed previous run)."
                    Target  = $RbacSystem
                })
        }
    }
    # AadApplication origin IDs are tenant service-principal object IDs. ResourceApps is loaded
    # independently from FilterClassifiedRbacs because that filter controls group inheritance only.
    $ResourceAppsClassificationSource = Join-Path -Path $FolderClassifiedObjects -ChildPath "ResourceApps/ResourceApps.json"
    if (Test-Path -Path $ResourceAppsClassificationSource) {
        try {
            $ClassificationCache["ResourceApps"] = @(Get-Content -Path $ResourceAppsClassificationSource -Raw -ErrorAction Stop | ConvertFrom-Json -Depth 10 -ErrorAction Stop)
            $ResourceAppsByObjectId = @{}
            foreach ($ResourceApp in $ClassificationCache["ResourceApps"]) {
                if ([string]::IsNullOrEmpty($ResourceApp.ObjectId)) { continue }
                if (-not $ResourceAppsByObjectId.ContainsKey($ResourceApp.ObjectId)) {
                    $ResourceAppsByObjectId[$ResourceApp.ObjectId] = [System.Collections.Generic.List[object]]::new()
                }
                $ResourceAppsByObjectId[$ResourceApp.ObjectId].Add($ResourceApp)
            }
            $ClassificationCache["ResourceApps:ByObjectId"] = $ResourceAppsByObjectId
        } catch {
            $WarningMessages.Add([pscustomobject]@{ Type = "Stage2"; Message = "Failed to load ResourceApps classification: $_" })
        }
    } else {
        $WarningMessages.Add([pscustomobject]@{
                Type    = "Classification Source Missing"
                Message = "Classification file $ResourceAppsClassificationSource not found - AadApplication resources will be treated as ControlPlane. Run the ResourceApps RBAC system first."
                Target  = "ResourceApps"
            })
    }
    # Pre-load EntraID roles specifically for DirectoryRole lookups
    $EntraIdClassificationSource = $FolderClassifiedObjects + "EntraID/EntraID.json"
    if (Test-Path $EntraIdClassificationSource) {
        try {
            $ClassificationCache["EntraIDRoles"] = @((Get-Content -Path $EntraIdClassificationSource | ConvertFrom-Json -Depth 10).RoleAssignments)
            $EntraIdRolesByDefinitionId = @{}
            foreach ($RoleAssignment in $ClassificationCache["EntraIDRoles"]) {
                if ($RoleAssignment.RoleAssignmentScopeId -ne "/" -or [string]::IsNullOrEmpty($RoleAssignment.RoleDefinitionId)) { continue }
                if (-not $EntraIdRolesByDefinitionId.ContainsKey($RoleAssignment.RoleDefinitionId)) {
                    $EntraIdRolesByDefinitionId[$RoleAssignment.RoleDefinitionId] = $RoleAssignment
                }
            }
            $ClassificationCache["EntraIDRoles:ByDefinitionId"] = $EntraIdRolesByDefinitionId
        } catch {
            $WarningMessages.Add([PSCustomObject]@{Type = "Stage2"; Message = "Failed to load EntraID classification: $_" })
        }
    }

    # Pre-load Azure resource scope reasoning (Tier0Scope/Tier1Scope buckets written by
    # Update-EntraOpsClassificationControlPlaneScope) for classifying Azure resources (subscriptions,
    # resource groups, resources) onboarded to catalogs or access packages. Without the file, Azure
    # resources fail closed to ControlPlane (conservative) with a warning when they are actually
    # encountered - the same fail-closed convention used by the IdGov-side scope classifier
    # (Get-EntraOpsIdGovScopeClassification), so both outputs agree for the same catalog.
    $AzureScopeReasoning = $null
    $AzureScopeReasoningFile = "$($FolderClassification)/$($TenantNameContext)/ScopeReasoning_Azure.json"
    if (Test-Path -Path $AzureScopeReasoningFile) {
        try {
            $AzureScopeReasoning = Get-Content -Path $AzureScopeReasoningFile -Raw | ConvertFrom-Json -Depth 10
        } catch {
            $WarningMessages.Add([PSCustomObject]@{Type = "Stage2"; Message = "Failed to load Azure scope reasoning file $($AzureScopeReasoningFile): $_" })
        }
    }

    # Optimization: Build hashtable lookup for Api Permissions classifications
    $ApiPermissionsClassLookup = @{}
    # Resource app id -> Category (e.g. "Microsoft.Graph") from the same classification definitions -
    # used to give resource role scope tagging a readable API name instead of the access package
    # resource scope's own displayName (often just "Root").
    $ApiResourceAppCategoryLookup = @{}
    foreach ($ApiPermissionsClass in $ApiPermissionsClassification) {
        foreach ($RoleDef in $ApiPermissionsClass.TierLevelDefinition) {
            if (-not [string]::IsNullOrEmpty($RoleDef.ResourceAppId) -and -not $ApiResourceAppCategoryLookup.ContainsKey($RoleDef.ResourceAppId)) {
                $ApiResourceAppCategoryLookup[$RoleDef.ResourceAppId] = $RoleDef.Category
            }
            foreach ($RoleAction in $RoleDef.RoleDefinitionActions) {
                $key = "$($RoleDef.ResourceAppId)|$($RoleAction)"
                if (-not $ApiPermissionsClassLookup.ContainsKey($key)) {
                    $ApiPermissionsClassLookup[$key] = @{
                        EAMTierLevelName     = $ApiPermissionsClass.EAMTierLevelName
                        EAMTierLevelTagValue = $ApiPermissionsClass.EAMTierLevelTagValue
                        Service              = $RoleDef.Service
                    }
                }
            }
        }
    }

    # Warning Collection (continued from earlier stages)
    # Note: Do not reinitialize $WarningMessages here to preserve Stage 1 warnings

    $IdGovRbacScopes = $IdGovRbacAssignments | Select-Object -Unique RoleAssignmentScopeId
    $AccessPackageAssignmentManagerRoleId = "e2182095-804a-4656-ae11-64734e9b7ae5"

    #region Pre-fetch: resolve catalog/access package resources for every unique scope up front
    # Optimization: every unique scope's Graph data (catalog resources, catalog access packages for
    # Assignment Manager scopes, single access packages) is resolved exactly once here - in parallel
    # when the dataset and environment allow it - instead of one Invoke-EntraOpsMsGraphQuery call
    # inline per scope iteration below. Independent catalogs/access packages are pure, read-only
    # network I/O with no shared mutable state, so they're safe to fan out; the classification logic
    # that follows (which adds to $WarningMessages) stays untouched and strictly sequential.
    $ScopeFetchPlan = foreach ($IdGovRbacScope in $IdGovRbacScopes) {
        $ScopeId = $IdGovRbacScope.RoleAssignmentScopeId
        if ($ScopeId -like "/AccessPackageCatalog/*") {
            $CatalogId = $ScopeId.Replace("/AccessPackageCatalog/", "")
            [PSCustomObject]@{
                ScopeId = $ScopeId
                Kind    = "Catalog"
                Id      = $CatalogId
            }
        } elseif ($ScopeId -like "/AccessPackage/*") {
            [PSCustomObject]@{
                ScopeId = $ScopeId
                Kind    = "AccessPackage"
                Id      = $ScopeId.Replace("/AccessPackage/", "")
            }
        } else {
            [PSCustomObject]@{ ScopeId = $ScopeId; Kind = "Other"; Id = $null }
        }
    }

    # Deduplicate by URI so a catalog referenced by multiple scopes (shouldn't happen since
    # $IdGovRbacScopes is already unique by ScopeId, but the access package sub-fetch shares the
    # same CatalogId as its parent catalog fetch) is only ever requested once.
    # The catalog's access packages are always fetched: they are needed for the Access Package
    # Assignment Manager override AND for the catalog-wide API permission classification (the
    # catalog-level accessPackageResourceRoles enumeration for API resources returns permissions
    # across catalogs - Microsoft Graph beta bug - so API permissions are classified from the
    # catalog's access packages instead).
    $FetchRequests = [System.Collections.Generic.List[psobject]]::new()
    $SeenFetchKeys = @{}
    foreach ($PlanItem in $ScopeFetchPlan) {
        if ($PlanItem.Kind -eq "Catalog") {
            $Key = "CatalogResources:$($PlanItem.Id)"
            if (-not $SeenFetchKeys.ContainsKey($Key)) {
                $SeenFetchKeys[$Key] = $true
                $FetchRequests.Add([PSCustomObject]@{ Key = $Key; Uri = "/beta/identityGovernance/entitlementManagement/accessPackageCatalogs/$($PlanItem.Id)/accessPackageResources?`$expand=accessPackageResourceScopes,accessPackageResourceRoles" })
            }
            $Key2 = "CatalogAccessPackages:$($PlanItem.Id)"
            if (-not $SeenFetchKeys.ContainsKey($Key2)) {
                $SeenFetchKeys[$Key2] = $true
                # Neither accessPackageCatalogs/{id}/accessPackages (invalid navigation path, 404)
                # nor the top-level accessPackages collection with $filter=catalogId/catalog-id eq
                # (InvalidFilter - $filter isn't supported on that collection at all) work. Expanding
                # accessPackages directly on the catalog's own single-entity GET does work - the
                # response is the CATALOG entity with an "accessPackages" array nested inside (not a
                # flat access package list), unwrapped right after the prefetch below. Also no nested
                # $expand of accessPackageResourceRoleScopes here (see the "AccessPackage:$Id" fetch
                # below for why) - each access package is hydrated individually afterwards instead.
                $FetchRequests.Add([PSCustomObject]@{ Key = $Key2; Uri = "/beta/identityGovernance/entitlementManagement/accessPackageCatalogs('$($PlanItem.Id)')?`$expand=accessPackages" })
            }
        } elseif ($PlanItem.Kind -eq "AccessPackage") {
            $Key = "AccessPackage:$($PlanItem.Id)"
            if (-not $SeenFetchKeys.ContainsKey($Key)) {
                $SeenFetchKeys[$Key] = $true
                $FetchRequests.Add([PSCustomObject]@{ Key = $Key; Uri = "/beta/identityGovernance/entitlementManagement/accessPackages/$($PlanItem.Id)?`$expand=accessPackageResourceRoleScopes(`$expand=accessPackageResourceRole,accessPackageResourceScope)" })
            }
        }
    }

    $ScopeFetchResults = @{}
    $HasSufficientFetches = $FetchRequests.Count -ge 5
    $IsUsingMgGraphSDKForFetch = $false
    try { $IsUsingMgGraphSDKForFetch = $null -ne (Get-MgContext -ErrorAction Stop) } catch { Write-Verbose "Microsoft Graph SDK context not available for parallel catalog pre-fetch: $($_.Exception.Message)" }
    $UseParallelFetch = $EnableParallelProcessing -and $HasSufficientFetches -and $IsUsingMgGraphSDKForFetch

    if ($UseParallelFetch) {
        Write-Verbose "Pre-fetching $($FetchRequests.Count) catalog/access package resource(s) in parallel ($ParallelThrottleLimit threads)..."
        # $PSScriptRoot here is .../EntraOps/Public/PrivilegedAccess - the module manifest lives two
        # levels up at .../EntraOps/EntraOps.psd1, not one (which only reaches .../EntraOps/Public).
        $EntraOpsModulePath = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
        $MgGraphModulePath = (Get-Module Microsoft.Graph.Authentication).Path
        $LocalEntraOpsSession = $Script:__EntraOpsSession

        try {
            $ParallelFetchResults = $FetchRequests | ForEach-Object -ThrottleLimit $ParallelThrottleLimit -Parallel {
                $Req = $_
                $LocalEntraOpsPath = $using:EntraOpsModulePath
                $LocalMgGraphPath = $using:MgGraphModulePath
                try {
                    if (-not (Get-Module -Name Microsoft.Graph.Authentication)) {
                        Import-Module $LocalMgGraphPath -ErrorAction Stop
                    }
                    if ($null -eq (Get-MgContext)) {
                        throw "MgGraph context not available in parallel runspace"
                    }
                    $EntraOpsModuleManifest = Join-Path $LocalEntraOpsPath "EntraOps.psd1"
                    if (Test-Path $EntraOpsModuleManifest) {
                        $env:ENTRAOPS_NOWELCOME = $true
                        if (-not (Get-Module -Name EntraOps)) {
                            Import-Module $EntraOpsModuleManifest -ErrorAction Stop -WarningAction SilentlyContinue
                        }
                    } else {
                        throw "EntraOps module manifest not found at $EntraOpsModuleManifest"
                    }
                    if ($using:LocalEntraOpsSession) {
                        $script:__EntraOpsSession = $using:LocalEntraOpsSession
                    }
                    $FetchedData = Invoke-EntraOpsMsGraphQuery -Uri $Req.Uri -ConsistencyLevel "eventual" -OutputType PSObject -WarningAction SilentlyContinue
                    [PSCustomObject]@{ Key = $Req.Key; Data = $FetchedData; Success = $true; Error = $null }
                } catch {
                    [PSCustomObject]@{ Key = $Req.Key; Data = $null; Success = $false; Error = $_.Exception.Message }
                }
            }
            foreach ($FetchResult in $ParallelFetchResults) {
                $ScopeFetchResults[$FetchResult.Key] = $FetchResult
            }
        } catch {
            Write-Verbose "Parallel catalog pre-fetch failed, falling back to sequential: $($_.Exception.Message)"
            $UseParallelFetch = $false
            $ScopeFetchResults = @{}
        }
    }

    if (-not $UseParallelFetch) {
        foreach ($Req in $FetchRequests) {
            try {
                $FetchedData = Invoke-EntraOpsMsGraphQuery -Uri $Req.Uri -ConsistencyLevel "eventual" -OutputType PSObject -WarningAction SilentlyContinue
                $ScopeFetchResults[$Req.Key] = [PSCustomObject]@{ Key = $Req.Key; Data = $FetchedData; Success = $true; Error = $null }
            } catch {
                $ScopeFetchResults[$Req.Key] = [PSCustomObject]@{ Key = $Req.Key; Data = $null; Success = $false; Error = $_.Exception.Message }
            }
        }
    }

    # Hydrate each catalog's access packages with their resource role scopes individually - the
    # fetch above returns the CATALOG entity with access package stubs nested under .accessPackages
    # (see the Uri comment above), not a flat access package list, and those stubs don't carry
    # accessPackageResourceRoleScopes - so unwrap that nesting and hydrate each one here.
    $HydratedAccessPackagesCache = @{}
    foreach ($FetchKey in @($ScopeFetchResults.Keys | Where-Object { $_ -like "CatalogAccessPackages:*" })) {
        $CatalogAccessPackagesResult = $ScopeFetchResults[$FetchKey]
        if (-not $CatalogAccessPackagesResult.Success -or $null -eq $CatalogAccessPackagesResult.Data) {
            continue
        }
        $AccessPackageStubs = @($CatalogAccessPackagesResult.Data | Select-Object -First 1 -ExpandProperty accessPackages -ErrorAction SilentlyContinue)
        $CatalogAccessPackagesResult.Data = @(
            foreach ($AccessPackageStub in $AccessPackageStubs) {
                if ($null -eq $AccessPackageStub -or [string]::IsNullOrEmpty($AccessPackageStub.id)) {
                    continue
                }
                if (-not $HydratedAccessPackagesCache.ContainsKey($AccessPackageStub.id)) {
                    try {
                        $HydratedAccessPackagesCache[$AccessPackageStub.id] = Invoke-EntraOpsMsGraphQuery -Uri "/beta/identityGovernance/entitlementManagement/accessPackages/$($AccessPackageStub.id)?`$expand=accessPackageResourceRoleScopes(`$expand=accessPackageResourceRole,accessPackageResourceScope)" -ConsistencyLevel "eventual" -OutputType PSObject -WarningAction SilentlyContinue
                    } catch {
                        Write-Verbose "Failed to hydrate resource role scopes of access package $($AccessPackageStub.id): $($_.Exception.Message)"
                        $HydratedAccessPackagesCache[$AccessPackageStub.id] = $AccessPackageStub
                    }
                }
                $HydratedAccessPackagesCache[$AccessPackageStub.id]
            }
        )
    }
    #endregion

    $IdGovRbacClassificationsByAssignedObjects = New-Object System.Collections.Generic.List[psobject]
    foreach ($IdGovRbacScope in $IdGovRbacScopes) {
        $CurrentRoleAssignmentScope = $IdGovRbacScope.RoleAssignmentScopeId
        Write-Verbose -Message "Classify assignment scope $($CurrentRoleAssignmentScope)"
        # Reset per-scope so a "/" or unrecognized scope can't inherit a previous catalog's classification
        $MatchedClassificationToCatalogResources = $null

        if ($CurrentRoleAssignmentScope -like "/AccessPackageCatalog/*") {
            # Get all objects assigned to Access Package Catalog
            $AccessPackageCatalogId = $CurrentRoleAssignmentScope.Replace("/AccessPackageCatalog/", "")

            # Use the pre-fetched result from the parallel/sequential pre-fetch region above instead of
            # querying Graph inline - preserves the exact same warning semantics as before (a null
            # result means "not found/deleted", an Error means the request itself failed).
            $CatalogResourcesFetch = $ScopeFetchResults["CatalogResources:$AccessPackageCatalogId"]
            $CatalogResourcesFetchFailed = $false
            if ($null -ne $CatalogResourcesFetch -and -not $CatalogResourcesFetch.Success) {
                $WarningMessages.Add([PSCustomObject]@{
                        Type    = "CatalogResolutionError"
                        Message = "Error resolving catalog ${AccessPackageCatalogId}: $($CatalogResourcesFetch.Error)"
                        Target  = $AccessPackageCatalogId
                    })
                $AssignedCatalogResources = @()
                $CatalogResourcesFetchFailed = $true
            } elseif ($null -eq $CatalogResourcesFetch -or $null -eq $CatalogResourcesFetch.Data) {
                # A 404 on this catalog-direct accessPackageResources relationship is the common case,
                # not evidence of deletion: Microsoft Graph only returns resources assigned directly to
                # the catalog here, not resources reachable via its access packages (see the "Microsoft
                # Graph beta bug" note in the fetch-plan region above) - most catalogs only ever assign
                # resources through access packages, so this 404s for the majority of perfectly valid,
                # existing catalogs too.
                $WarningMessages.Add([PSCustomObject]@{
                        Type    = "CatalogResolution"
                        Message = "Access Package Catalog $AccessPackageCatalogId returned no directly-assigned resources (404) - expected when resources are only assigned via its access packages; the catalog may also genuinely no longer exist."
                        Target  = $AccessPackageCatalogId
                    })
                $AssignedCatalogResources = @()
                $CatalogResourcesFetchFailed = $true
            } else {
                $AssignedCatalogResources = $CatalogResourcesFetch.Data | Where-Object { $null -ne $_.originId }
            }

            if (@($AssignedCatalogResources).Count -eq 0 -and -not $CatalogResourcesFetchFailed) {
                # No resources means Stage 2 cannot produce any "Assigned*"-tagged classification
                # (with TaggedByObjectIds) for this catalog - every assignment at this scope falls back
                # to the generic JSONwithAction classification instead. Surface it so an unexpectedly
                # empty catalog is visible without needing -Verbose. Skipped when the fetch above
                # already failed/404'd - that warning already covers this same root cause.
                $WarningMessages.Add([PSCustomObject]@{
                        Type    = "Empty Catalog Resources"
                        Message = "Access Package Catalog $AccessPackageCatalogId has no assigned resources - role assignments at this scope will only get the generic JSONwithAction classification, not object-based tagging."
                        Target  = $AccessPackageCatalogId
                    })
            }
            Write-Verbose -Message "Found $($AssignedCatalogResources.Count) assigned catalog resources in catalog $($AccessPackageCatalogId)"
            $MatchedClassificationToCatalogResources = New-Object System.Collections.Generic.List[psobject]
            foreach ($AssignedCatalogResource in $AssignedCatalogResources) {
                # Get classification object of the object from all or filtered RBAC system
                switch ($AssignedCatalogResource.originSystem) {

                    'AadGroup' {
                        Write-Verbose -Message "Classifying assigned catalog object $($AssignedCatalogResource.displayName) from origin system $($AssignedCatalogResource.originSystem) by $FilterClassifiedRbacs"
                        foreach ($RbacSystem in $FilterClassifiedRbacs) {
                            # Optimization: Use In-Memory Cache
                            if ($ClassificationCache.ContainsKey($RbacSystem)) {
                                $ClassifiedObject = @($ClassificationCache["${RbacSystem}:ByObjectId"][$AssignedCatalogResource.originId])
                                if ($null -ne $($ClassifiedObject.Classification)) {
                                    $TaggedObjectDisplayName = $ClassifiedObject.ObjectDisplayName | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -First 1
                                    if ([string]::IsNullOrWhiteSpace($TaggedObjectDisplayName)) { $TaggedObjectDisplayName = $AssignedCatalogResource.displayName }
                                    $MatchedRbacClassification = $ClassifiedObject.Classification
                                    foreach ($ClassItem in $MatchedRbacClassification) {
                                        # Clone before tagging - $ClassItem is a live reference into $ClassificationCache,
                                        # which is loaded once and reused for every catalog/access package scope in this
                                        # run. Mutating it in place would permanently rewrite the same cached object every
                                        # time any other scope's resource happens to match it.
                                        $TaggedClassItem = $ClassItem.PSObject.Copy()
                                        $TaggedClassItem | Add-Member -NotePropertyName "TaggedBy"                   -NotePropertyValue "Assigned$($AssignedCatalogResource.originSystem)" -Force
                                        $TaggedClassItem | Add-Member -NotePropertyName "TaggedByObjectIds"          -NotePropertyValue @($AssignedCatalogResource.originId)               -Force
                                        $TaggedClassItem | Add-Member -NotePropertyName "TaggedByObjectDisplayNames" -NotePropertyValue @($TaggedObjectDisplayName)                         -Force
                                        $TaggedClassItem | Add-Member -NotePropertyName "TaggedByRoleSystem"         -NotePropertyValue $RbacSystem                                       -Force
                                        $MatchedClassificationToCatalogResources.Add($TaggedClassItem) | Out-Null
                                    }
                                } else {
                                    Write-Verbose "No classification for $($AssignedCatalogResource.displayName) $($AssignedCatalogResource.id) found in $RbacSystem"
                                }
                            }
                        }
                    } 'DirectoryRole' {
                        Write-Verbose -Message "Classifying assigned catalog object $($AssignedCatalogResource.displayName) from origin system $($AssignedCatalogResource.originSystem) by EntraID"
                        # Get classification from EntraID roles only on root scope
                        if ($AssignedCatalogResource.accessPackageResourceScopes.isRootScope -eq $true) {
                            Write-Verbose -Message "Assigned catalog resource scope is root scope, get classification from EntraID roles"
                        } else {
                            $WarningMessages.Add([PSCustomObject]@{
                                    Type    = "Scope Limitation"
                                    Message = "Assigned catalog resource scope is not root scope, directory roles are currently only supported on root scope!"
                                    Target  = $AssignedCatalogResource.displayName
                                })
                        }
                        
                        # Optimization: Use In-Memory Cache for Directory Roles
                        $Classification = $null
                        if ($ClassificationCache.ContainsKey("EntraIDRoles")) {
                            $MatchedRole = $ClassificationCache["EntraIDRoles:ByDefinitionId"][$AssignedCatalogResource.originId]
                            if ($null -ne $MatchedRole) {
                                $Classification = $MatchedRole.Classification
                            }
                        }

                        if ($Null -eq $Classification) {
                            $WarningMessages.Add([PSCustomObject]@{
                                    Type    = "Default Classification Fallback"
                                    Message = "No classification for $($AssignedCatalogResource.displayName) ($($AssignedCatalogResource.id)) found in EntraID! Fallback to default."
                                    Target  = $AssignedCatalogResource.displayName
                                })
                            $MatchedDefaultRole = $EntraRolesDefaultClassification | Where-Object { $_.RoleId -eq $AssignedCatalogResource.originId } | Select-Object -First 1
                            if ($null -ne $MatchedDefaultRole -and $null -ne $MatchedDefaultRole.RolePermissions) {
                                $DefaultRoleClassification = $MatchedDefaultRole.RolePermissions | Select-Object -Unique EAMTierLevelTagValue, EAMTierLevelName, Category
                                $Classification = $DefaultRoleClassification | foreach-object {
                                    [PSCustomObject]@{
                                        'AdminTierLevel'     = $_.EAMTierLevelTagValue
                                        'AdminTierLevelName' = $_.EAMTierLevelName
                                        'Service'            = $_.Category | Select-Object -First 1
                                    }
                                }
                            }
                        }
                        if ($Null -eq $Classification.AdminTierLevel) {
                            $WarningMessages.Add([PSCustomObject]@{
                                    Type    = "Unclassified Resource"
                                    Message = "No default classification for $($AssignedCatalogResource.displayName) ($($AssignedCatalogResource.id)) found!"
                                    Target  = $AssignedCatalogResource.displayName
                                })
                            $Classification = [PSCustomObject]@{
                                'AdminTierLevel'     = "Unclassified"
                                'AdminTierLevelName' = "Unclassified"
                                'Service'            = "Unclassified"
                            }
                        }
                        $Classification | Add-Member -NotePropertyName "TaggedBy"                   -NotePropertyValue "Assigned$($AssignedCatalogResource.originSystem)Resource" -Force
                        $Classification | Add-Member -NotePropertyName "TaggedByObjectIds"          -NotePropertyValue @($AssignedCatalogResource.originId)                       -Force
                        $Classification | Add-Member -NotePropertyName "TaggedByObjectDisplayNames" -NotePropertyValue @($AssignedCatalogResource.displayName)                    -Force
                        $Classification | Add-Member -NotePropertyName "TaggedByRoleSystem"         -NotePropertyValue "EntraID"                                                  -Force
                        $MatchedClassificationToCatalogResources.Add($Classification) | Out-Null
                    } 'AadApplication' {
                        $Classifications = @(Get-EntraOpsAadApplicationClassification -ServicePrincipalObjectId $AssignedCatalogResource.originId -ClassificationCache $ClassificationCache -DisplayName $AssignedCatalogResource.displayName -ContextLabel "catalog $AccessPackageCatalogId" -WarningMessages $WarningMessages)
                        foreach ($ClassItem in $Classifications) {
                            $TaggedClassItem = $ClassItem.PSObject.Copy()
                            $TaggedClassItem | Add-Member -NotePropertyName "TaggedBy"                   -NotePropertyValue "AssignedAadApplicationResource" -Force
                            $TaggedClassItem | Add-Member -NotePropertyName "TaggedByObjectIds"          -NotePropertyValue @($AssignedCatalogResource.originId) -Force
                            $TaggedClassItem | Add-Member -NotePropertyName "TaggedByObjectDisplayNames" -NotePropertyValue @($AssignedCatalogResource.displayName) -Force
                            $TaggedClassItem | Add-Member -NotePropertyName "TaggedByRoleSystem"         -NotePropertyValue "ResourceApps" -Force
                            $MatchedClassificationToCatalogResources.Add($TaggedClassItem) | Out-Null
                        }
                    } 'SharePointOnline' {
                        # Catalog-level entry carries no role - the resolver returns the conservative
                        # ManagementPlane catalog-level result without an unknown-role warning.
                        $SharePointTier = Resolve-EntraOpsSharePointOnlineRoleTier -RoleDisplayName "" -RoleOriginId ""
                        $MatchedClassificationToCatalogResources.Add([pscustomobject]@{
                                AdminTierLevel             = $SharePointTier.AdminTierLevel
                                AdminTierLevelName         = $SharePointTier.AdminTierLevelName
                                Service                    = "SharePoint Online"
                                TaggedBy                   = "AssignedSharePointOnlineResource"
                                TaggedByObjectIds          = @($AssignedCatalogResource.originId)
                                TaggedByObjectDisplayNames = @($AssignedCatalogResource.displayName)
                                TaggedByRoleSystem         = "SharePointOnline"
                            }) | Out-Null
                    } 'OAuthApplication' {
                        # The catalog-level accessPackageResourceRoles enumeration for API resources returns
                        # permissions across catalogs (Microsoft Graph beta bug), so it must not be used for
                        # classification. API permissions are classified from the resource role scopes of the
                        # catalog's access packages instead (see below, after the resource loop).
                        Write-Verbose -Message "Skipping catalog-level API permission enumeration of $($AssignedCatalogResource.displayName) (unreliable across catalogs) - classified from the catalog's access packages instead"
                    } 'AzureResources' {
                        # Azure resource (subscription, resource group, resource) onboarded to the catalog:
                        # a Catalog owner/Access package manager can delegate any available Azure role at the
                        # onboarded ARM scope, so the classification follows the scope - matched against the
                        # Tier0/Tier1 resource scope buckets from ScopeReasoning_Azure.json.
                        Write-Verbose -Message "Classifying assigned catalog object $($AssignedCatalogResource.displayName) from origin system $($AssignedCatalogResource.originSystem) by Azure resource scope reasoning"
                        $AzureScopeTier = Resolve-EntraOpsAzureScopeReasoningTier -ArmScopeId $AssignedCatalogResource.originId -AzureScopeReasoning $AzureScopeReasoning
                        if ($null -eq $AzureScopeTier) {
                            $WarningMessages.Add([PSCustomObject]@{
                                    Type    = "Unresolved Azure Scope"
                                    Message = "Azure scope $($AssignedCatalogResource.originId) of catalog resource $($AssignedCatalogResource.displayName) could not be evaluated - ScopeReasoning_Azure.json not available. Run Update-EntraOpsClassificationControlPlaneScope for Azure first. Treated as ControlPlane (conservative)."
                                    Target  = $AssignedCatalogResource.displayName
                                })
                            $AzureScopeTier = [PSCustomObject]@{ AdminTierLevel = "0"; AdminTierLevelName = "ControlPlane"; MatchedScope = $null }
                        }
                        $Classification = [PSCustomObject]@{
                            'AdminTierLevel'             = $AzureScopeTier.AdminTierLevel
                            'AdminTierLevelName'         = $AzureScopeTier.AdminTierLevelName
                            'Service'                    = "Azure Resources"
                            'TaggedBy'                   = "Assigned$($AssignedCatalogResource.originSystem)Resource"
                            'TaggedByObjectIds'          = @($AssignedCatalogResource.originId)
                            'TaggedByObjectDisplayNames' = @($AssignedCatalogResource.displayName)
                            'TaggedByRoleSystem'         = "Azure"
                        }
                        $MatchedClassificationToCatalogResources.Add($Classification) | Out-Null
                    } default {
                        $WarningMessages.Add([PSCustomObject]@{
                                Type    = "Unknown Origin System"
                                Message = "Origin system $($AssignedCatalogResource.originSystem) not supported for classification!"
                                Target  = $AssignedCatalogResource.originSystem
                            })
                    }
                }
            }

            # Catalog-wide API permission classification: the catalog-level accessPackageResourceRoles
            # enumeration for API resources is unreliable (see 'OAuthApplication' case above - Microsoft
            # Graph beta bug returns permissions across catalogs, and can also come back empty even when
            # an access package in the catalog does have an API permission resource role scope), so this
            # is always computed from the catalog's access packages instead of being gated on the
            # catalog-level resource enumeration containing an OAuthApplication entry.
            $CatalogAccessPackagesFetchForOAuth = $ScopeFetchResults["CatalogAccessPackages:$AccessPackageCatalogId"]
            if ($null -ne $CatalogAccessPackagesFetchForOAuth -and -not $CatalogAccessPackagesFetchForOAuth.Success) {
                $WarningMessages.Add([PSCustomObject]@{
                        Type    = "AccessPackageResolutionError"
                        Message = "Error resolving access packages of catalog ${AccessPackageCatalogId} for API permission classification: $($CatalogAccessPackagesFetchForOAuth.Error)"
                        Target  = $AccessPackageCatalogId
                    })
            } else {
                $OAuthResourceRoleScopes = @($CatalogAccessPackagesFetchForOAuth.Data | ForEach-Object { $_.accessPackageResourceRoleScopes } | Where-Object { $null -ne $_.accessPackageResourceRole -and $null -ne $_.accessPackageResourceScope -and $_.accessPackageResourceScope.originSystem -eq 'OAuthApplication' })
                Write-Verbose -Message "Classifying $($OAuthResourceRoleScopes.Count) API permission resource role scope(s) across access packages of catalog $($AccessPackageCatalogId)"
                if ($OAuthResourceRoleScopes.Count -gt 0) {
                    $OAuthClassifications = Get-EntraOpsPrivilegedEamAccessPackageResourceRoleScopeClassification -ResourceRoleScopes $OAuthResourceRoleScopes -FilterClassifiedRbacs $FilterClassifiedRbacs -ClassificationCache $ClassificationCache -ApiPermissionsClassLookup $ApiPermissionsClassLookup -ApiResourceAppCategoryLookup $ApiResourceAppCategoryLookup -EntraIdRolesClassification $ClassificationCache["EntraIDRoles"] -EntraRolesDefaultClassification $EntraRolesDefaultClassification -AzureScopeReasoning $AzureScopeReasoning -ContextLabel "access packages of catalog $AccessPackageCatalogId (API permissions)" -WarningMessages $WarningMessages
                    foreach ($OAuthClassification in @($OAuthClassifications)) {
                        $MatchedClassificationToCatalogResources.Add($OAuthClassification) | Out-Null
                    }
                }
            }

            # Access package assignment manager can only assign/remove users on EXISTING access packages
            # in the catalog - it can't add resources to the catalog or resource roles to an access
            # package. Its effective resource exposure is therefore bounded to resources actually
            # included in the catalog's access packages, not the catalog's full (possibly unused)
            # resource inventory fetched above. Compute and store a narrower override classification for
            # that role only if it's actually held at this scope, so Catalog owner/reader/Access package
            # manager keep the broader catalog-wide classification.
            if (($IdGovRbacAssignments | Where-Object { $_.RoleAssignmentScopeId -eq $CurrentRoleAssignmentScope -and $_.RoleDefinitionId -eq $AccessPackageAssignmentManagerRoleId }).Count -gt 0) {
                # Use the pre-fetched result from the parallel/sequential pre-fetch region above instead
                # of querying Graph inline.
                $CatalogAccessPackagesFetch = $ScopeFetchResults["CatalogAccessPackages:$AccessPackageCatalogId"]
                if ($null -ne $CatalogAccessPackagesFetch -and -not $CatalogAccessPackagesFetch.Success) {
                    $WarningMessages.Add([PSCustomObject]@{
                            Type    = "AccessPackageResolutionError"
                            Message = "Error resolving access packages of catalog ${AccessPackageCatalogId} for Access Package Assignment Manager scope: $($CatalogAccessPackagesFetch.Error)"
                            Target  = $AccessPackageCatalogId
                        })
                    $CatalogAccessPackages = @()
                } else {
                    $CatalogAccessPackages = $CatalogAccessPackagesFetch.Data
                }

                $AssignedResourceRoleScopesAcrossCatalogPackages = @($CatalogAccessPackages | ForEach-Object { $_.accessPackageResourceRoleScopes } | Where-Object { $null -ne $_.accessPackageResourceRole -and $null -ne $_.accessPackageResourceScope })
                if ($AssignedResourceRoleScopesAcrossCatalogPackages.Count -eq 0) {
                    $WarningMessages.Add([PSCustomObject]@{
                            Type    = "Empty Catalog Resources"
                            Message = "Access packages of catalog $AccessPackageCatalogId have no assigned resource role scopes - Access Package Assignment Manager at this scope will fall back to the generic JSONwithAction classification instead of object-based tagging."
                            Target  = $AccessPackageCatalogId
                        })
                }
                Write-Verbose -Message "Found $($AssignedResourceRoleScopesAcrossCatalogPackages.Count) assigned resource role scopes across $($CatalogAccessPackages.Count) access packages in catalog $($AccessPackageCatalogId) for Access Package Assignment Manager scope"

                $AssignmentManagerClassification = Get-EntraOpsPrivilegedEamAccessPackageResourceRoleScopeClassification -ResourceRoleScopes $AssignedResourceRoleScopesAcrossCatalogPackages -FilterClassifiedRbacs $FilterClassifiedRbacs -ClassificationCache $ClassificationCache -ApiPermissionsClassLookup $ApiPermissionsClassLookup -ApiResourceAppCategoryLookup $ApiResourceAppCategoryLookup -EntraIdRolesClassification $ClassificationCache["EntraIDRoles"] -EntraRolesDefaultClassification $EntraRolesDefaultClassification -AzureScopeReasoning $AzureScopeReasoning -ContextLabel "access packages of catalog $AccessPackageCatalogId" -WarningMessages $WarningMessages

                $IdGovRbacClassificationsByAssignedObjects.Add([PSCustomObject]@{
                        'RoleDefinitionId'      = $AccessPackageAssignmentManagerRoleId
                        'RoleAssignmentScopeId' = $CurrentRoleAssignmentScope
                        'Classification'        = $($AssignmentManagerClassification | Sort-Object AdminTierLevel, AdminTierLevelName, Service, TaggedBy | Select-Object -Unique *)
                        # Marks this override as "was actually evaluated". An empty result is then a
                        # meaningful answer (the role can only manage assignments inside existing access
                        # packages, and this catalog has none) rather than a failed lookup - see the
                        # role-specific override handling in Stage 4.
                        'OverrideEvaluated'     = $true
                    }) | Out-Null
            }
        } elseif ($CurrentRoleAssignmentScope -like "/AccessPackage/*") {
            # Narrower scope than a catalog: role is delegated on a single access package.
            # Only classify the resource roles actually selected for THIS access package, not the whole catalog's resource inventory.
            $AccessPackageId = $CurrentRoleAssignmentScope.Replace("/AccessPackage/", "")

            # Use the pre-fetched result from the parallel/sequential pre-fetch region above instead of
            # querying Graph inline.
            $AccessPackageFetch = $ScopeFetchResults["AccessPackage:$AccessPackageId"]
            if ($null -ne $AccessPackageFetch -and -not $AccessPackageFetch.Success) {
                $WarningMessages.Add([PSCustomObject]@{
                        Type    = "AccessPackageResolutionError"
                        Message = "Error resolving access package ${AccessPackageId}: $($AccessPackageFetch.Error)"
                        Target  = $AccessPackageId
                    })
                $AssignedAccessPackageResourceRoleScopes = @()
            } elseif ($null -eq $AccessPackageFetch -or $null -eq $AccessPackageFetch.Data) {
                $WarningMessages.Add([PSCustomObject]@{
                        Type    = "AccessPackageResolution"
                        Message = "Access Package $AccessPackageId not found (likely deleted)."
                        Target  = $AccessPackageId
                    })
                $AssignedAccessPackageResourceRoleScopes = @()
            } else {
                $AssignedAccessPackageResourceRoleScopes = $AccessPackageFetch.Data.accessPackageResourceRoleScopes | Where-Object { $null -ne $_.accessPackageResourceRole -and $null -ne $_.accessPackageResourceScope }
            }

            if (@($AssignedAccessPackageResourceRoleScopes).Count -eq 0) {
                $WarningMessages.Add([PSCustomObject]@{
                        Type    = "Empty Catalog Resources"
                        Message = "Access Package $AccessPackageId has no assigned resource role scopes - role assignments at this scope will fall back to the generic JSONwithAction classification instead of object-based tagging."
                        Target  = $AccessPackageId
                    })
            }
            Write-Verbose -Message "Found $($AssignedAccessPackageResourceRoleScopes.Count) assigned resource role scopes in access package $($AccessPackageId)"
            $MatchedClassificationToCatalogResources = Get-EntraOpsPrivilegedEamAccessPackageResourceRoleScopeClassification -ResourceRoleScopes $AssignedAccessPackageResourceRoleScopes -FilterClassifiedRbacs $FilterClassifiedRbacs -ClassificationCache $ClassificationCache -ApiPermissionsClassLookup $ApiPermissionsClassLookup -ApiResourceAppCategoryLookup $ApiResourceAppCategoryLookup -EntraIdRolesClassification $ClassificationCache["EntraIDRoles"] -EntraRolesDefaultClassification $EntraRolesDefaultClassification -AzureScopeReasoning $AzureScopeReasoning -ContextLabel "access package $AccessPackageId" -WarningMessages $WarningMessages
        } elseif ($CurrentRoleAssignmentScope -eq "/") {
            $WarningMessages.Add([PSCustomObject]@{
                    Type    = "Scope Limitation"
                    Message = "Skipping root scope, currently only delegated roles of catalog creator and connected organization admin available."
                    Target  = "Root Scope"
                })
        } else {
            Write-Error "Invalid scope $CurrentRoleAssignmentScope"
        }

        if ($null -ne $MatchedClassificationToCatalogResources -and $null -ne $CurrentRoleAssignmentScope) {
            $Classification = $($MatchedClassificationToCatalogResources | ForEach-Object { $_ }) | Sort-Object AdminTierLevel, AdminTierLevelName, Service, TaggedBy | Select-Object -Unique *
            $IdGovRbacClassificationsByAssignedObject = [PSCustomObject]@{
                'RoleDefinitionId'      = $null
                'RoleAssignmentScopeId' = $CurrentRoleAssignmentScope
                'Classification'        = $Classification
            }
            $IdGovRbacClassificationsByAssignedObjects.Add($IdGovRbacClassificationsByAssignedObject) | Out-Null
        }
    }
    
    $Stage2Duration = ((Get-Date) - $Stage2Start).TotalSeconds
    Write-Host "✓ Stage 2 completed in $([Math]::Round($Stage2Duration, 2)) seconds ($($IdGovRbacClassificationsByAssignedObjects.Count) catalog scopes classified)" -ForegroundColor Green
    Write-Progress -Activity "Stage 2/4: Classifying Catalog Objects" -Completed
    #endregion

    #region Stage 3: Classify Role Actions
    $Stage3Start = Get-Date
    Write-Host ""
    Write-Host "═══════════════════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "  Stage 3/4: Classifying Role Actions" -ForegroundColor Cyan
    Write-Host "═══════════════════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "Matching role definitions and actions against JSON classification rules..." -ForegroundColor Gray
    Write-Progress -Activity "Stage 3/4: Classifying Role Actions" -Status "Reading classification file and matching role actions..." -PercentComplete 50
    $IdGovResourcesByClassificationJSON = Expand-EntraOpsPrivilegedEAMJsonFile -FilePath "$($IdGovClassificationFilePath)" | select-object EAMTierLevelName, EAMTierLevelTagValue, Category, Service, RoleAssignmentScopeName, ExcludedRoleAssignmentScopeName, RoleDefinitionActions, ExcludedRoleDefinitionActions

    # Load classification overwrites (down-/upgrade of entire role definitions) from tenant-specific folder or Templates fallback.
    # Role action overwrites are already baked into the classification file by Update-EntraOpsClassificationControlPlaneScope.
    $ClassificationOverwrites = Import-EntraOpsClassificationOverwrites -RbacSystem "IdentityGovernance" -FolderClassification $FolderClassification
    $IdGovRbacClassificationsByJSON = @()

    # Optimization: Pre-fetch all Entitlement Management role definitions
    $IdGovRoleDefinitionsCache = @{}
    try {
        if ($SampleMode -ne $True) {
            Write-Verbose "Pre-fetching all Identity Governance role definitions..."
            $AllIdGovRoles = Invoke-EntraOpsMsGraphQuery -Uri "/beta/roleManagement/EntitlementManagement/roleDefinitions" -OutputType PSObject
            foreach ($Role in $AllIdGovRoles) {
                $IdGovRoleDefinitionsCache[$Role.Id] = $Role
            }
        }
    } catch {
        $WarningMessages.Add([PSCustomObject]@{
                Type    = "Pre-fetch Failure"
                Message = "Failed to pre-fetch Identity Governance role definitions: $_"
                Target  = "Role Definitions"
            })
    }

    $UniqueRoleDefs = $IdGovRbacAssignments | Select-Object -Unique RoleDefinitionId, RoleAssignmentScopeId
    $ProcessedCount = 0
    $TotalCount = $UniqueRoleDefs.Count

    $IdGovRbacClassificationsByJSON += foreach ($IdGovRbacAssignment in $UniqueRoleDefs) {
        $ProcessedCount++
        if ($ProcessedCount % 10 -eq 0) {
            Write-Progress -Activity "Stage 3/4: Classifying Role Actions" -Status "Classifying role definition $ProcessedCount of $TotalCount" -PercentComplete (50 + ($ProcessedCount / $TotalCount * 20))
        }

        # Role actions are defined for scope and role definition contains an action of the role, otherwise all role actions within role assignment scope will be applied
        if ($SampleMode -eq $True) {
            # Removed redundant warning
        } else {
            # Optimization: Use In-Memory Cache
            if ($IdGovRoleDefinitionsCache.ContainsKey("$($IdGovRbacAssignment.RoleDefinitionId)")) {
                $IdGovRoleActions = $IdGovRoleDefinitionsCache["$($IdGovRbacAssignment.RoleDefinitionId)"]
            } else {
                $IdGovRoleActions = Invoke-EntraOpsMsGraphQuery -Uri "/beta/roleManagement/EntitlementManagement/roleDefinitions" | Where-Object { $_.Id -eq "$($IdGovRbacAssignment.RoleDefinitionId)" }
            }
        }

        $MatchedClassificationByScope = @()
        # Check if RBAC scope is listed in JSON by wildcard in RoleAssignmentScope (e.g. /azops-rg/*)
        $MatchedClassificationByScope += $IdGovResourcesByClassificationJSON | foreach-object {
            $Classification = $_
            $Classification | where-object { $IdGovRbacAssignment.RoleAssignmentScopeId -like $Classification.RoleAssignmentScopeName -and $IdGovRbacAssignment.RoleAssignmentScopeId -notin $Classification.ExcludedRoleAssignmentScopeName }
        }

        # Check if role action and scope exists in JSON definition. Single matching pass: the
        # previous code ran the identical action x classification wildcard match twice per
        # assignment - once solely to probe .Count -gt 0 and again to build the projection - and
        # grew the result via += array copies. One pass into a List does both.
        $ClassifiedWithMatchedActions = [System.Collections.Generic.List[psobject]]::new()
        # Matchers precomputed once per classification entry (loop-invariant across the action loop).
        $ClassificationMatchers = @(foreach ($MatchedClassification in $MatchedClassificationByScope) {
                [pscustomobject]@{
                    Classification = $MatchedClassification
                    Matcher        = Build-EntraOpsClassificationActionMatcher -RoleDefinitionActions $MatchedClassification.RoleDefinitionActions -ExcludedRoleDefinitionActions $MatchedClassification.ExcludedRoleDefinitionActions
                }
            })
        foreach ($IdGovRoleAction in $IdGovRoleActions.rolePermissions.allowedResourceActions) {
            if ([string]::IsNullOrEmpty($IdGovRoleAction)) { continue }
            foreach ($MatcherEntry in $ClassificationMatchers) {
                $Matcher = $MatcherEntry.Matcher
                $AllowedMatch = $Matcher.AllowedExact.Contains($IdGovRoleAction)
                if (-not $AllowedMatch) {
                    foreach ($Pattern in $Matcher.AllowedWildcards) { if ($IdGovRoleAction -like $Pattern) { $AllowedMatch = $true; break } }
                }
                if (-not $AllowedMatch) { continue }
                $ExcludedMatch = $Matcher.ExcludedExact.Contains($IdGovRoleAction)
                if (-not $ExcludedMatch) {
                    foreach ($Pattern in $Matcher.ExcludedWildcards) { if ($IdGovRoleAction -like $Pattern) { $ExcludedMatch = $true; break } }
                }
                if ($ExcludedMatch) { continue }
                $ClassifiedWithMatchedActions.Add([PSCustomObject]@{
                        EAMTierLevelName     = $MatcherEntry.Classification.EAMTierLevelName
                        EAMTierLevelTagValue = $MatcherEntry.Classification.EAMTierLevelTagValue
                        Service              = $MatcherEntry.Classification.Service
                        MatchedAction        = $IdGovRoleAction
                    })
            }
        }

        if ($ClassifiedWithMatchedActions.Count -gt 0) {
            $UniqueClassifications = $ClassifiedWithMatchedActions | Select-Object -Unique EAMTierLevelName, EAMTierLevelTagValue, Service
            $Classification = foreach ($UniqueClass in $UniqueClassifications) {
                $MatchedEntries = @($ClassifiedWithMatchedActions | Where-Object {
                    $_.EAMTierLevelName -eq $UniqueClass.EAMTierLevelName -and
                    $_.EAMTierLevelTagValue -eq $UniqueClass.EAMTierLevelTagValue -and
                    $_.Service -eq $UniqueClass.Service
                })
                [array]$MatchedActions = @($MatchedEntries | Select-Object -ExpandProperty MatchedAction | Select-Object -Unique)
                [PSCustomObject]@{
                    'AdminTierLevel'             = $UniqueClass.EAMTierLevelTagValue
                    'AdminTierLevelName'         = $UniqueClass.EAMTierLevelName
                    'Service'                    = $UniqueClass.Service
                    'MatchedActions'             = if ($MatchedActions.Count -gt 0) { , @($MatchedActions) } else { $null }
                    'ScopedObjects'              = $null
                    'TaggedBy'                   = "JSONwithAction"
                    'TaggedByObjectIds'          = $null
                    'TaggedByObjectDisplayNames' = $null
                    'TaggedByRoleSystem'         = "IdentityGovernance"
                }
            }

            # Same action can be defined under multiple tier levels (e.g. a superset of actions
            # at a lower tier). Keep each matched action only at its highest tier (lowest
            # AdminTierLevel) and drop it from lower-tier entries to avoid duplicate classifications.
            # Case-insensitive comparer: Graph action-string casing varies between sources
            $SeenMatchedActions = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
            $Classification = foreach ($ClassificationEntry in ($Classification | Sort-Object { [int]$_.AdminTierLevel })) {
                $RemainingActions = @($ClassificationEntry.MatchedActions | Where-Object { -not $SeenMatchedActions.Contains($_) })
                foreach ($MatchedAction in $ClassificationEntry.MatchedActions) {
                    [void]$SeenMatchedActions.Add($MatchedAction)
                }
                if ($RemainingActions.Count -gt 0) {
                    $ClassificationEntry.MatchedActions = $RemainingActions
                    $ClassificationEntry
                }
            }

            [PSCustomObject]@{
                'RoleDefinitionId'      = $IdGovRbacAssignment.RoleDefinitionId
                'RoleAssignmentScopeId' = $IdGovRbacAssignment.RoleAssignmentScopeId
                'Classification'        = $Classification
            }
        } else {
            $ClassifiedIdGovRbacRoleWithActions = @()
        }
    }

    $IdGovRbacClassifications = foreach ($IdGovRbacAssignment in $IdGovRbacAssignments) {
        $IdGovRbacAssignment = $IdGovRbacAssignment | Select-Object -ExcludeProperty Classification
        $ClassificationCollection = @()
        # Prefer a role-specific assigned-object classification (e.g. Access package assignment manager's
        # narrower "resources in existing access packages" override) over the generic catalog/package-wide
        # one shared by every role holding the same scope (RoleDefinitionId = $null).
        $ScopedAssignedObjectClassifications = $IdGovRbacClassificationsByAssignedObjects | Where-Object { $_.RoleAssignmentScopeId -eq $IdGovRbacAssignment.RoleAssignmentScopeId }
        # Only prefer the role-specific override if it actually matched something - an empty override
        # (e.g. no access packages/resource role scopes found yet) must not suppress the broader,
        # catalog-wide classification shared by other roles at this scope.
        $RoleSpecificOverrides = @($ScopedAssignedObjectClassifications | Where-Object { $_.RoleDefinitionId -eq $IdGovRbacAssignment.RoleDefinitionId })
        $RoleSpecificAssignedObjectClassifications = @($RoleSpecificOverrides | Where-Object { @($_.Classification).Count -gt 0 })
        # An override that was evaluated but produced nothing is a RESULT, not a failed lookup: an Access
        # package assignment manager on a catalog whose access packages have no resource role scopes can
        # reach nothing, so it must not inherit the catalog-wide object classification that Catalog owner
        # gets. Only the generic role-action (JSONwithAction) classification applies - which is exactly what
        # the "Empty Catalog Resources" warning raised in Stage 2 tells the operator.
        $HasEmptyEvaluatedOverride = @($RoleSpecificOverrides | Where-Object { $_.OverrideEvaluated -eq $true -and @($_.Classification).Count -eq 0 }).Count -gt 0

        if ($RoleSpecificAssignedObjectClassifications.Count -gt 0) {
            # A role-specific override (e.g. Access package assignment manager) already reflects the
            # role's true, resource-dependent exposure - the generic catalog-wide JSON action classification
            # (e.g. tagging Grants/GrantRequests as ControlPlane regardless of what's actually assigned)
            # must not be added on top of it, or the narrower result would be discarded again.
            $ClassificationCollection += $RoleSpecificAssignedObjectClassifications.Classification
        } else {
            if (-not $HasEmptyEvaluatedOverride) {
                $ClassificationCollection += ($ScopedAssignedObjectClassifications | Where-Object { $null -eq $_.RoleDefinitionId }).Classification
            }
            $ClassificationCollection += ($IdGovRbacClassificationsByJSON | Where-Object { $_.RoleAssignmentScopeId -eq $IdGovRbacAssignment.RoleAssignmentScopeId -and $_.RoleDefinitionId -eq $IdGovRbacAssignment.RoleDefinitionId }).Classification
        }

        # Object-tagged classifications (tier derived from the onboarded resource) never pass through role
        # action matching, so they carry no MatchedActions property at all and the Select-Object below would
        # materialize it as null. Attach the delegating role's matched actions - the entitlement management
        # actions that grant the capability to delegate that resource - so the evidence is not empty.
        $DelegatingRoleActions = @(
            ($IdGovRbacClassificationsByJSON | Where-Object {
                    $_.RoleAssignmentScopeId -eq $IdGovRbacAssignment.RoleAssignmentScopeId -and
                    $_.RoleDefinitionId -eq $IdGovRbacAssignment.RoleDefinitionId
                }).Classification.MatchedActions | Where-Object { -not [string]::IsNullOrEmpty($_) } | Sort-Object -Unique
        )
        if ($DelegatingRoleActions.Count -gt 0) {
            # Clone before writing: catalog-wide classification objects (RoleDefinitionId = $null) are shared
            # by every role assignment at this scope, so mutating them in place would leak one role's actions
            # into another role's classification.
            $ClassificationCollection = @($ClassificationCollection | ForEach-Object {
                    if ($null -eq $_) { return }
                    # @($null).Count is 1 in PowerShell, so an emptiness test must filter the null/empty
                    # entries out rather than counting the wrapped array directly.
                    $ExistingActions = @($_.MatchedActions | Where-Object { -not [string]::IsNullOrEmpty($_) })
                    if ($ExistingActions.Count -gt 0) { return $_ }
                    $ClonedClassification = $_ | Select-Object *
                    $ClonedClassification | Add-Member -NotePropertyName 'MatchedActions' -NotePropertyValue $DelegatingRoleActions -Force
                    $ClonedClassification
                })
        }

        $Classification = @()
        $Classification += $ClassificationCollection | select-object -Unique AdminTierLevel, AdminTierLevelName, MatchedActions, ScopedObjects, Service, TaggedBy, TaggedByObjectIds, TaggedByObjectDisplayNames, TaggedByRoleSystem, Justification | Sort-Object -Unique AdminTierLevel, AdminTierLevelName, Service, TaggedBy
        $IdGovRbacAssignment | Add-Member -NotePropertyName "Classification" -NotePropertyValue $Classification -Force
        $IdGovRbacAssignment
    }
    
    # Apply role definition classification overwrites (down-/upgrade by RoleDefinitionId or RoleDefinitionName)
    if ($ClassificationOverwrites.RoleDefinitionOverwrites.Count -gt 0) {
        Write-Host "Applying $($ClassificationOverwrites.RoleDefinitionOverwrites.Count) role definition classification overwrite(s) from $((@($ClassificationOverwrites.RoleDefinitionOverwrites.SourceFile) | Sort-Object -Unique) -join ', ')..." -ForegroundColor Yellow
        $IdGovRbacClassifications = Invoke-EntraOpsClassificationRoleOverwrite -RbacClassifications $IdGovRbacClassifications -RoleDefinitionOverwrites $ClassificationOverwrites.RoleDefinitionOverwrites -RoleSystem "IdentityGovernance"
    }

    # Every Identity Governance role is a delegation role, so a role definition without any matching
    # classification rule is a blind spot rather than a benign low-privilege role.
    $UnclassifiedIdGovRoles = @($IdGovRbacClassifications | Where-Object {
            @($_.Classification).Count -eq 0
        } | Select-Object -ExpandProperty RoleDefinitionName -Unique | Sort-Object)
    if ($UnclassifiedIdGovRoles.Count -gt 0) {
        $WarningMessages.Add([PSCustomObject]@{
                Type    = "UnclassifiedPrivilegedRole"
                Message = "$($UnclassifiedIdGovRoles.Count) Identity Governance role definition(s) have no matching classification rule and are reported as unclassified: $($UnclassifiedIdGovRoles -join ', '). Add the missing role actions to Classification_IdentityGovernance.json or pin the role in Classification_RoleDefinitionOverwrites.json."
            })
    }

    $Stage3Duration = ((Get-Date) - $Stage3Start).TotalSeconds
    Write-Host "✓ Stage 3 completed in $([Math]::Round($Stage3Duration, 2)) seconds ($($IdGovRbacClassifications.Count) role assignments classified)" -ForegroundColor Green
    Write-Progress -Activity "Stage 3/4: Classifying Role Actions" -Completed
    #endregion

    #region Stage 4: Resolve and Finalize Objects
    $Stage4Start = Get-Date
    Write-Host ""
    Write-Host "═══════════════════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "  Stage 4/4: Resolving Object Details and Finalizing" -ForegroundColor Cyan
    Write-Host "═══════════════════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "Enriching principals with detailed attributes and applying exclusions..." -ForegroundColor Gray

    # Optimization: Group assignments by ObjectId to avoid O(N^2) filtering
    $IdGovRbacByObject = $IdGovRbacClassifications | Group-Object ObjectId -AsHashTable -AsString

    # Optimization: Collect all unique ObjectIds and batch resolve details
    # Case-insensitive dedup (mirrors Get-EntraOpsPrivilegedEAMAzure.ps1): Select-Object -Unique compares
    # ObjectId case-sensitively and would emit the same principal twice when ids differ only in casing.
    $UniqueObjects = @(
        $IdGovRbacAssignments |
            Where-Object { $null -ne $_.ObjectId } |
            Group-Object -Property { "$($_.ObjectId)".ToLowerInvariant() } |
            ForEach-Object { $_.Group[0] | Select-Object ObjectId, ObjectType }
    )
    $ObjectDetailsCache = Invoke-EntraOpsParallelObjectResolution `
        -UniqueObjects $UniqueObjects `
        -TenantId $TenantId `
        -EnableParallelProcessing $EnableParallelProcessing `
        -ParallelThrottleLimit $ParallelThrottleLimit

    # Aggregate classifications and build output objects
    $IdGovRbacClassifiedObjects = Invoke-EntraOpsEAMClassificationAggregation `
        -UniqueObjects $UniqueObjects `
        -ObjectDetailsCache $ObjectDetailsCache `
        -RbacClassificationsByObject $IdGovRbacByObject `
        -RoleSystem "IdentityGovernance" `
        -EnableParallelProcessing $EnableParallelProcessing `
        -ParallelThrottleLimit $ParallelThrottleLimit `
        -WarningMessages $WarningMessages
    
    Write-Progress -Activity "Stage 4/4: Finalizing Results" -Status "Applying global exclusions and sorting..." -PercentComplete 90
    $IdGovRbacClassifiedObjects = $IdGovRbacClassifiedObjects | Where-Object { $GlobalExclusionList -notcontains $_.ObjectId }

    $Stage4Duration = ((Get-Date) - $Stage4Start).TotalSeconds
    $TotalDuration = ((Get-Date) - $Stage1Start).TotalSeconds
    
    Write-Progress -Activity "Stage 4/4: Finalizing Results" -Completed
    Write-Host "✓ Stage 4 completed in $([Math]::Round($Stage4Duration, 2)) seconds ($($IdGovRbacClassifiedObjects.Count) privileged objects after exclusions)" -ForegroundColor Green

    Show-EntraOpsWarningSummary -WarningMessages $WarningMessages -IncludeObjectDetails $IncludeObjectDetails

    Write-Host ""
    Write-Host "═══════════════════════════════════════════════════════════════════════════════" -ForegroundColor Green
    Write-Host "  ✓ All Stages Completed Successfully" -ForegroundColor Green
    Write-Host "═══════════════════════════════════════════════════════════════════════════════" -ForegroundColor Green
    Write-Host "Total execution time: $([Math]::Round($TotalDuration, 2)) seconds" -ForegroundColor Gray
    Write-Host "Final result: $($IdGovRbacClassifiedObjects.Count) privileged objects ready for export" -ForegroundColor Gray
    #endregion
    
    # Optionally strip TaggedBy* provenance properties from all Classification entries. The
    # object-level aggregated Classification is already TaggedBy-free (stripped during aggregation),
    # so only the per-assignment Classification entries under RoleAssignments carry them.
    if ($HideTaggedBy -eq $true) {
        $TaggedByPropertyNames = @('TaggedBy', 'TaggedByObjectIds', 'TaggedByObjectDisplayNames', 'TaggedByRoleSystem')
        foreach ($ClassifiedObject in @($IdGovRbacClassifiedObjects)) {
            foreach ($ClassificationEntries in @(@($ClassifiedObject.Classification), @($ClassifiedObject.RoleAssignments.Classification))) {
                foreach ($ClassificationEntry in @($ClassificationEntries)) {
                    if ($null -eq $ClassificationEntry) { continue }
                    foreach ($TaggedByPropertyName in $TaggedByPropertyNames) {
                        if ($null -ne $ClassificationEntry.PSObject.Properties[$TaggedByPropertyName]) {
                            $ClassificationEntry.PSObject.Properties.Remove($TaggedByPropertyName)
                        }
                    }
                }
            }
        }
    }

    $IdGovRbacClassifiedObjects | Where-Object { $null -ne $_.ObjectType -and $null -ne $_.ObjectId } | Set-EntraOpsEAMClassificationJustification -IncludeJustification:$IncludeJustification | Sort-Object ObjectAdminTierLevel, ObjectDisplayName
}