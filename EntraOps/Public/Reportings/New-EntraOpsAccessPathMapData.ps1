<#
.SYNOPSIS
    Generate (refresh) the embedded dataset for the EntraOps Access Path Map static web app.

.DESCRIPTION
    Transforms EntraOps Privileged EAM data into the Access Path Map dataset using the
    BloodHound OpenGraph integration (Export-EntraOpsPrivilegedEAMBloodHound) as the canonical
    graph model: the same node kinds (AZUser, AZGroup, AZServicePrincipal, AZDevice, AZRole,
    EO_*Role, EO_*RoleAssignment, EO_AdministrativeUnit) and edge kinds (EO_Has*Role,
    EO_EligibleFor*Role, EO_Has*RoleAssignment, EO_*RoleAssigned, EO_ScopedTo,
    EO_ClassifiedViaObject, EO_HasWorkAccount, EO_UsesPAW, EO_OwnsDevice, EO_OwnerOf, ...) are emitted.

    On top of the OpenGraph payload the dataset is enriched for standalone visualization
    (the OpenGraph export relies on AzureHound to provide principal names):

      * Principal nodes get displayname, objecttype/subtype, UPN, sync source, restricted
        management flags and the aggregated classification (tiers + services).
      * Role and role assignment nodes always get a human-readable name/displayname (the
        role definition name, optionally with its assignment scope) instead of the raw GUID
        the BloodHound exporter uses for its own node ids, plus role type, IsPrivileged, the
        role actions ("matchedactions") and classification (tiers + services) that apply to
        them. Role nodes are further enriched with description/categories from the optional
        role catalog files (Classification/Classification_<System>.json, generated separately
        via Export-EntraOpsClassification*Roles.ps1) when present.
      * Role and role assignment nodes are cross-referenced against the same curated,
        documented attack-path catalog the Classification Explorer's Attack Paths view uses
        (Reports/ClassificationExplorer/content/attack-paths/*.md), matched by role name or
        role action. Matches are exposed as knownattackpaths/knownattackpathnames/
        knownattackpathseverity node properties - this is what "known attack path" means
        throughout EntraOps Reporting, as distinct from the separate "tier breach" concept
        below (crossing an Enterprise Access Model tier boundary, whether or not it matches
        a documented technique).
      * Edges from principals to roles / role assignments get tier-breach flags computed with
        the same rules as the Tier Breach Analyzer: a breach is a path where the principal's
        designated tier (ObjectAdminTierLevel, unclassified => Tier 2) is LESS privileged than
        the tier of the service reached through the assignment (edge classification).

    Generates data/access-path-map-data.js exposing `window.ENTRAOPS_APM_DATA` so the static web
    app works both over HTTP and from the file system (no fetch / CORS required).

.PARAMETER TenantId
    Tenant id used to build role node ids (<roleDefinitionId>@<tenantId>) and the tenant scope
    node, matching the BloodHound export. Defaults to the ObjectTenantId found in the export.

.PARAMETER RepoRoot
    Path to the EntraOps repository root that contains the PrivilegedEAM export folder.
    Defaults to the repository this module lives in.

.PARAMETER ImportPath
    Folder with the Privileged EAM export. Defaults to <RepoRoot>/PrivilegedEAM.

.PARAMETER AppRoot
    Path to the AccessPathMap app folder. Defaults to Reports/AccessPathMap.

.PARAMETER OutFile
    Output file. Defaults to <AppRoot>/data/access-path-map-data.js.

.PARAMETER ResolveObjectIdsOutsidePrivilegedEAM
    When $true, edge endpoints that reference an object id which is neither a privileged object in the
    Privileged EAM export nor a known device (OwnedObjects/Owners/AssociatedPawDevice/AssociatedWorkAccount/
    Sponsors can all reference objects outside the classified scope, e.g. a standard, non-privileged work
    account or a group/application owned by a privileged principal) are resolved via Microsoft Graph
    (`POST /v1.0/directoryObjects/getByIds`) to their display name and object type, instead of being shown
    as an anonymous "unresolved" placeholder node. Requires an active Microsoft Graph connection (e.g. via
    Connect-EntraOps/Connect-MgGraph) with at least directory read permissions (User.Read.All, Group.Read.All,
    Application.Read.All or Directory.Read.All). Defaults to the `AccessPathMap.ResolveObjectIdsOutsidePrivilegedEAM`
    setting in EntraOpsConfig.json (at the repository root resolved from -RepoRoot), or $true when that config
    file/setting is not present. Resolution is best-effort: objects that Graph cannot return remain explicit
    unresolved placeholders, and no graph edges are dropped.

.PARAMETER PassThru
    Emit the generated payload object to the pipeline.

.EXAMPLE
    New-EntraOpsAccessPathMapData

    Regenerates the Access Path Map dataset from the PrivilegedEAM folder of this repository.

.EXAMPLE
    New-EntraOpsAccessPathMapData -ImportPath "C:\Exports\PrivilegedEAM" -Verbose -WhatIf

    Shows what would be generated from an explicit Privileged EAM export without changing any files.
#>

function New-EntraOpsAccessPathMapData {

    [CmdletBinding(SupportsShouldProcess = $true)]
    param (
        [Parameter(Mandatory = $false)]
        [System.String]$TenantId,

        [Parameter(Mandatory = $false)]
        [System.String]$RepoRoot,

        [Parameter(Mandatory = $false)]
        [System.String]$ImportPath,

        [Parameter(Mandatory = $false)]
        [System.String]$AppRoot,

        [Parameter(Mandatory = $false)]
        [System.String]$OutFile,

        [Parameter(Mandatory = $false)]
        [System.Boolean]$ResolveObjectIdsOutsidePrivilegedEAM = $true,

        [Parameter(Mandatory = $false)]
        [switch]$PassThru
    )

    # Resolve the app/repository location relative to the module location.
    $ModuleRoot = $MyInvocation.MyCommand.Module.ModuleBase
    if ([string]::IsNullOrWhiteSpace($ModuleRoot) -and -not [string]::IsNullOrWhiteSpace($PSScriptRoot)) {
        $ModuleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    }
    if ([string]::IsNullOrWhiteSpace($ModuleRoot)) {
        throw "Unable to resolve the EntraOps module location. Import the module with 'Import-Module <path-to-EntraOps> -Force' and try again."
    }
    $RepositoryRoot = if (-not [string]::IsNullOrWhiteSpace($Global:EntraOpsBaseFolder)) { $Global:EntraOpsBaseFolder } else { Split-Path -Parent $ModuleRoot }

    if ([string]::IsNullOrWhiteSpace($RepoRoot)) { $RepoRoot = $RepositoryRoot }
    if ([string]::IsNullOrWhiteSpace($AppRoot)) { $AppRoot = Join-Path $RepositoryRoot 'Reports/AccessPathMap' }
    if (-not (Test-Path -LiteralPath $AppRoot -PathType Container)) {
        throw "Access Path Map app folder not found: $AppRoot. Import the EntraOps module from a repository checkout that contains Reports/AccessPathMap, or run Install-EntraOpsReportingFolder to download the Reports folder."
    }
    if ([string]::IsNullOrWhiteSpace($ImportPath)) { $ImportPath = Join-Path $RepoRoot 'PrivilegedEAM' }
    if ([string]::IsNullOrWhiteSpace($OutFile)) { $OutFile = Join-Path $AppRoot 'data/access-path-map-data.js' }

    if (-not (Test-Path -LiteralPath $ImportPath)) {
        throw "Privileged EAM import path not found: $ImportPath. Run Save-EntraOpsPrivilegedEAMJson first or pass -ImportPath."
    }

    # Config-driven default: EntraOpsConfig.json "AccessPathMap.ResolveObjectIdsOutsidePrivilegedEAM"
    # controls Graph resolution of edge endpoints that are not part of the Privileged EAM export.
    # -ResolveObjectIdsOutsidePrivilegedEAM always wins over the config file setting when explicitly bound.
    if (-not $PSBoundParameters.ContainsKey('ResolveObjectIdsOutsidePrivilegedEAM')) {
        $AccessPathMapConfigFilePath = Join-Path $RepoRoot 'EntraOpsConfig.json'
        if (Test-Path -LiteralPath $AccessPathMapConfigFilePath -PathType Leaf) {
            try {
                $AccessPathMapEntraOpsConfig = Get-Content -LiteralPath $AccessPathMapConfigFilePath -Raw | ConvertFrom-Json
                if ($null -ne $AccessPathMapEntraOpsConfig.AccessPathMap -and $null -ne $AccessPathMapEntraOpsConfig.AccessPathMap.ResolveObjectIdsOutsidePrivilegedEAM) {
                    $ResolveObjectIdsOutsidePrivilegedEAM = [bool]$AccessPathMapEntraOpsConfig.AccessPathMap.ResolveObjectIdsOutsidePrivilegedEAM
                }
            } catch {
                Write-Warning "Failed to read AccessPathMap settings from ${AccessPathMapConfigFilePath}: $($_.Exception.Message). Defaulting -ResolveObjectIdsOutsidePrivilegedEAM to `$true."
            }
        }
    }

    function Get-PropValue {
        param($Object, [string] $Name)
        if ($null -eq $Object) { return $null }
        $p = $Object.PSObject.Properties[$Name]
        if ($null -ne $p) { return $p.Value }
        return $null
    }

    function Get-AssignmentKey {
        param($RoleSystem, $Assignment)
        $instanceId = Get-PropValue $Assignment 'RoleAssignmentInstanceId'
        if ($instanceId) { return "$instanceId".ToUpperInvariant() }
        return (Get-EntraOpsRoleAssignmentInstanceId -RoleSystem "$RoleSystem" -RoleAssignment $Assignment).ToUpperInvariant()
    }

    # Export-EntraOpsPrivilegedEAMBloodHound adds pre-built Cypher "cypherSearch" helper
    # queries (e.g. InboundRelationships, Roles, PAWDevices) to nodes for BloodHound's own
    # node-info panel. They are internal/technical (raw Cypher MATCH clauses referencing
    # EO_ relationship kinds) and not useful in the Access Path Map detail drawer,
    # so they are dropped from the embedded dataset.
    $CypherHelperProperties = @(
        'InboundRelationships', 'OutboundRelationships', 'EligibleAssignments',
        'RoleAndAssignments', 'AssignmentScope', 'Roles', 'PAWDevices',
        'AssociatedPrincipals', 'ScopedByRoleAssignments', 'ActiveAssignments',
        'InboundIntunePermissions', 'Members'
    )

    function ConvertTo-TierNumber {
        # Same normalization as the Tier Breach Analyzer: empty / unclassified => Tier 2.
        param($Value, [int]$Default = 2)
        if ($null -eq $Value) { return $Default }
        $s = "$Value".Trim()
        if ($s -eq '' -or $s -eq 'Unclassified') { return $Default }
        $n = 0
        if (-not [int]::TryParse($s, [ref]$n)) { return $Default }
        if ($n -in 0, 1, 2) { return $n }
        return $Default
    }

    # ── Optional: enrich role nodes with descriptions from the role catalog files ──
    # (Classification/Classification_<System>.json), generated separately via the
    # Export-EntraOpsClassification*Roles.ps1 cmdlets (same optional files the
    # Classification Explorer consumes). Best-effort: silently skipped if absent.
    $roleCatalog = @{}   # ROLEDEFID (upper) -> @{ description; categories }
    # The role catalog files live in the AzurePrivilegedIAM repository, so they are not found
    # under the default -RepoRoot (the EntraOps repository). Probe the explicit -RepoRoot
    # first, then the temporary sparse AzurePrivilegedIAM checkout used by the
    # Push-EntraOpsPrivilegedReporting workflow (.reporting/AzurePrivilegedIAM).
    $RoleCatalogRoots = @($RepoRoot, (Join-Path $RepoRoot '.reporting/AzurePrivilegedIAM'))
    $RoleCatalogFileNames = @(
        'Classification/Classification_EntraIdDirectoryRoles.json',
        'Classification/Classification_IdentityGovernance.json',
        'Classification/Classification_AzureResources.json',
        'Classification/Classification_DeviceManagementRoles.json'
    )
    $RoleCatalogFiles = @(
        foreach ($catalogFileName in $RoleCatalogFileNames) {
            $catalogCandidates = @($RoleCatalogRoots | ForEach-Object { Join-Path $_ $catalogFileName })
            @($catalogCandidates | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } | Select-Object -First 1)[0]
        }
    )
    if (-not @($RoleCatalogFiles | Where-Object { $_ })) {
        Write-Warning "No role catalog classification files found; role node descriptions/categories stay empty. Paths tried: $(@($RoleCatalogRoots | ForEach-Object { $root = $_; $RoleCatalogFileNames | ForEach-Object { Join-Path $root $_ } }) -join ', ')"
    }
    foreach ($catalogFile in $RoleCatalogFiles) {
        if (-not $catalogFile) { continue }
        try {
            $catalogRoles = Get-Content -LiteralPath $catalogFile -Raw -Encoding UTF8 | ConvertFrom-Json
            foreach ($role in @($catalogRoles)) {
                if ($null -eq $role) { continue }
                $rid = "$(Get-PropValue $role 'RoleId')".ToUpperInvariant()
                if (-not $rid -or $roleCatalog.ContainsKey($rid)) { continue }
                $description = "$(Get-PropValue $role 'RichDescription')"
                # Microsoft Graph exposes multiple categories as one comma-delimited string.
                $categoriesRaw = @(Get-PropValue $role 'Categories')
                $roleCatalog[$rid] = @{
                    description = $description
                    categories  = @($categoriesRaw | ForEach-Object { "$_" -split ',' } | ForEach-Object { $_.Trim() } | Where-Object { $_ })
                }
            }
        } catch {
            Write-Warning "Could not parse role catalog file $($catalogFile): $($_.Exception.Message)"
        }
    }

    # ── Known attack path catalog ────────────────────────────────────────────────
    # Cross-references roles and role actions against the same curated, documented
    # privilege-escalation techniques used by the Classification Explorer's "Attack
    # Paths" view (Reports/ClassificationExplorer/content/attack-paths/*.md). This is
    # what "known attack path" means throughout EntraOps Reporting - a role/role
    # assignment is tagged here only when it matches an actual documented technique,
    # not merely because it crosses an Enterprise Access Model tier boundary (that is
    # the separate, already-covered "tier breach" concept).
    function ConvertFrom-AttackPathMarkdown {
        param([string]$Markdown)
        $fm = @{}
        if ($Markdown -match '(?s)^---\s*\r?\n(.*?)\r?\n---\s*\r?\n?') {
            foreach ($line in ($Matches[1] -split "\r?\n")) {
                $idx = $line.IndexOf(':')
                if ($idx -lt 0) { continue }
                $fm[$line.Substring(0, $idx).Trim()] = $line.Substring($idx + 1).Trim()
            }
        }
        function Get-PipeList {
            param([string]$SectionName)
            $rows = [System.Collections.Generic.List[object]]::new()
            if ($Markdown -match "(?s)##\s*$SectionName\s*\r?\n(.*?)(\r?\n##\s|\z)") {
                foreach ($line in ($Matches[1] -split "\r?\n")) {
                    $l = $line.Trim() -replace '^[-*]\s*', ''
                    if (-not $l) { continue }
                    $parts = $l -split '\|'
                    if ($parts.Count -ge 2) {
                        $rows.Add(@{ sys = $parts[0].Trim(); value = $parts[1].Trim() })
                    }
                }
            }
            return $rows
        }
        [PSCustomObject]@{
            id         = $fm['id']
            name       = $fm['name']
            severity   = $fm['severity']
            targetTier = $fm['targetTier']
            actions    = Get-PipeList -SectionName 'Actions'
            roles      = Get-PipeList -SectionName 'Roles'
        }
    }

    $attackPathMeta = @{}          # id (lower) -> @{ name; severity; targetTier }
    $attackPathByAction = @{}      # "sys|loweredaction" -> List[id]
    $attackPathByRoleName = @{}    # "sys|loweredrolename" -> List[id]
    $AttackPathCatalogDir = Join-Path $RepoRoot 'Reports/ClassificationExplorer/content/attack-paths'
    if (Test-Path -LiteralPath $AttackPathCatalogDir) {
        Get-ChildItem -LiteralPath $AttackPathCatalogDir -Filter '*.md' -File | ForEach-Object {
            try {
                $md = Get-Content -LiteralPath $_.FullName -Raw -Encoding UTF8
                $p = ConvertFrom-AttackPathMarkdown -Markdown $md
                if (-not $p.id) { return }
                $attackPathMeta[$p.id] = @{ name = $p.name; severity = $p.severity; targetTier = $p.targetTier }
                foreach ($a in $p.actions) {
                    $k = "$($a.sys)|$($a.value.ToLowerInvariant())"
                    if (-not $attackPathByAction.ContainsKey($k)) { $attackPathByAction[$k] = [System.Collections.Generic.List[string]]::new() }
                    if ($attackPathByAction[$k] -notcontains $p.id) { $attackPathByAction[$k].Add($p.id) }
                }
                foreach ($r in $p.roles) {
                    $k = "$($r.sys)|$($r.value.ToLowerInvariant())"
                    if (-not $attackPathByRoleName.ContainsKey($k)) { $attackPathByRoleName[$k] = [System.Collections.Generic.List[string]]::new() }
                    if ($attackPathByRoleName[$k] -notcontains $p.id) { $attackPathByRoleName[$k].Add($p.id) }
                }
            } catch {
                Write-Warning "Could not parse attack path markdown $($_.FullName): $($_.Exception.Message)"
            }
        }
    } else {
        Write-Warning "Attack path catalog not found at $AttackPathCatalogDir - roles/role assignments will not be tagged with known attack paths."
    }

    function Get-KnownAttackPathIds {
        param([string]$RbacSystem, [string]$RoleName, [string[]]$Actions)
        $ids = [System.Collections.Generic.List[string]]::new()
        if ($RoleName) {
            $k = "$RbacSystem|$($RoleName.ToLowerInvariant())"
            if ($attackPathByRoleName.ContainsKey($k)) {
                foreach ($id in $attackPathByRoleName[$k]) { if ($ids -notcontains $id) { $ids.Add($id) } }
            }
        }
        foreach ($a in @($Actions)) {
            if (-not $a) { continue }
            $k = "$RbacSystem|$($a.ToLowerInvariant())"
            if ($attackPathByAction.ContainsKey($k)) {
                foreach ($id in $attackPathByAction[$k]) { if ($ids -notcontains $id) { $ids.Add($id) } }
            }
        }
        return @($ids)
    }

    # ── 1. Read the Privileged EAM export for enrichment lookups ───────────────
    $files = Get-ChildItem -Path $ImportPath -Directory |
    ForEach-Object { Get-ChildItem -Path $_.FullName -Filter '*.json' -File } |
    Sort-Object FullName

    if (-not $files) {
        Write-Warning "No Privileged EAM JSON files found under $ImportPath (expected <RbacSystem>/<RbacSystem>.json). Generating an empty dataset."
    }

    $principals = @{}   # OBJECTID (upper) -> enrichment
    $roleDefs = @{}     # ROLEDEFID (upper) -> @{ name; roleType; isPrivileged; tiernames; services; actions }
    $assignments = @{}  # ROLEASSIGNMENTINSTANCEID (upper) -> @{ rolename; scopename; tiernames; services; actions }
    $azureEamObjects = [System.Collections.Generic.List[object]]::new()  # raw Azure EAM objects for graph synthesis (2b)

    foreach ($file in @($files)) {
        $roleSystem = Split-Path -Leaf (Split-Path -Parent $file.FullName)
        try {
            $data = Get-Content -LiteralPath $file.FullName -Raw -Encoding UTF8 | ConvertFrom-Json
        } catch {
            Write-Warning "Could not parse $($file.FullName): $($_.Exception.Message)"
            continue
        }

        if ($roleSystem -eq 'Azure') {
            foreach ($azObj in @($data)) { if ($null -ne $azObj) { $azureEamObjects.Add($azObj) } }
        }

        foreach ($o in @($data)) {
            if ($null -eq $o) { continue }
            $oid = "$(Get-PropValue $o 'ObjectId')".ToUpperInvariant()
            if (-not $oid) { continue }

            if ([string]::IsNullOrWhiteSpace($TenantId)) {
                $tid = "$(Get-PropValue $o 'ObjectTenantId')"
                if ($tid) { $TenantId = $tid }
            }

            if (-not $principals.ContainsKey($oid)) {
                $tierNames = @(@(Get-PropValue $o 'Classification') | ForEach-Object { Get-PropValue $_ 'AdminTierLevelName' } | Where-Object { $_ } | Select-Object -Unique)
                $services = @(@(Get-PropValue $o 'Classification') | ForEach-Object { Get-PropValue $_ 'Service' } | Where-Object { $_ } | Select-Object -Unique)
                $objTierName = "$(Get-PropValue $o 'ObjectAdminTierLevelName')"
                if (-not $objTierName) { $objTierName = 'Unclassified' }
                # [ordered] so the enrichment copy into node properties (step 3) emits a stable
                # JSON key order across runs (plain hashtable key order is per-process random).
                $principals[$oid] = [ordered]@{
                    displayname                   = "$(Get-PropValue $o 'ObjectDisplayName')"
                    objecttype                    = "$(Get-PropValue $o 'ObjectType')"
                    objectsubtype                 = "$(Get-PropValue $o 'ObjectSubType')"
                    userprincipalname             = "$(Get-PropValue $o 'ObjectUserPrincipalName')"
                    entraopsadmintierlevelname    = $objTierName
                    tiernumber                    = ConvertTo-TierNumber (Get-PropValue $o 'ObjectAdminTierLevel')
                    syncsource                    = $(if ([bool](Get-PropValue $o 'OnPremSynchronized')) { 'Hybrid' } else { 'Cloud-Only' })
                    restrictedmanagementbyaadrole = [bool](Get-PropValue $o 'RestrictedManagementByAadRole')
                    restrictedmanagementbyrag     = [bool](Get-PropValue $o 'RestrictedManagementByRAG')
                    restrictedmanagementbyrmau    = [bool](Get-PropValue $o 'RestrictedManagementByRMAU')
                    classification_tiernames      = @($tierNames | ForEach-Object { "$_" })
                    classification_services       = @($services | ForEach-Object { "$_" })
                    rbacsystems                   = [System.Collections.Generic.List[string]]::new()
                }
            }
            if ($principals[$oid].rbacsystems -notcontains $roleSystem) {
                $principals[$oid].rbacsystems.Add($roleSystem) | Out-Null
            }

            foreach ($ra in @(Get-PropValue $o 'RoleAssignments')) {
                if ($null -eq $ra) { continue }

                # Role actions ("MatchedActions"), tier(s) and service(s) classified for this
                # specific assignment - used to enrich both the role definition node (aggregated
                # across every assignment of that role) and the role assignment node (this one).
                $raClassifications = @(Get-PropValue $ra 'Classification')
                $raTierNames = @($raClassifications | ForEach-Object { Get-PropValue $_ 'AdminTierLevelName' } |
                    Where-Object { $_ -and $_ -ne 'Unclassified' } | Select-Object -Unique)
                $raServices = @($raClassifications | ForEach-Object { Get-PropValue $_ 'Service' } |
                    Where-Object { $_ -and $_ -ne 'Unclassified' } | Select-Object -Unique)
                $raActions = @($raClassifications | ForEach-Object { Get-PropValue $_ 'MatchedActions' } |
                    Where-Object { $_ } | ForEach-Object { $_ } | Where-Object { $_ } | Select-Object -Unique)

                $rdid = "$(Get-PropValue $ra 'RoleDefinitionId')".ToUpperInvariant()
                if ($rdid -and -not $roleDefs.ContainsKey($rdid)) {
                    $roleDefs[$rdid] = @{
                        name         = "$(Get-PropValue $ra 'RoleDefinitionName')"
                        roletype     = "$(Get-PropValue $ra 'RoleType')"
                        isprivileged = [bool](Get-PropValue $ra 'RoleIsPrivileged')
                        rbacsystem   = $roleSystem
                        tiernames    = [System.Collections.Generic.List[string]]::new()
                        services     = [System.Collections.Generic.List[string]]::new()
                        actions      = [System.Collections.Generic.List[string]]::new()
                    }
                }
                if ($rdid) {
                    foreach ($t in $raTierNames) { if ($roleDefs[$rdid].tiernames -notcontains "$t") { $roleDefs[$rdid].tiernames.Add("$t") | Out-Null } }
                    foreach ($s in $raServices) { if ($roleDefs[$rdid].services -notcontains "$s") { $roleDefs[$rdid].services.Add("$s") | Out-Null } }
                    foreach ($a in $raActions) { if ($roleDefs[$rdid].actions -notcontains "$a") { $roleDefs[$rdid].actions.Add("$a") | Out-Null } }
                }

                $raid = Get-AssignmentKey $roleSystem $ra
                if ($raid -and -not $assignments.ContainsKey($raid)) {
                    $assignments[$raid] = @{
                        rolename   = "$(Get-PropValue $ra 'RoleDefinitionName')"
                        scopename  = "$(Get-PropValue $ra 'RoleAssignmentScopeName')"
                        rbacsystem = $roleSystem
                        tiernames  = @($raTierNames | ForEach-Object { "$_" })
                        services   = @($raServices | ForEach-Object { "$_" })
                        actions    = @($raActions | ForEach-Object { "$_" })
                    }
                }
            }
        }
    }

    if ([string]::IsNullOrWhiteSpace($TenantId)) { $TenantId = 'UNKNOWN-TENANT' }
    $TenantIdUpper = $TenantId.ToUpperInvariant()

    # ── 2. Build the canonical OpenGraph payload via the BloodHound exporter ───
    $AvailableSystems = @(@($files) | ForEach-Object { Split-Path -Leaf (Split-Path -Parent $_.FullName) } |
        Where-Object { $_ -in @('EntraID', 'IdentityGovernance', 'DeviceManagement', 'ResourceApps', 'Defender') } |
        Select-Object -Unique)

    $graph = $null
    if ($AvailableSystems.Count -gt 0) {
        $TempFile = Join-Path ([System.IO.Path]::GetTempPath()) ("entraops-apa-" + [guid]::NewGuid().ToString() + ".json")
        $graph = & {
            $WhatIfPreference = $false
            try {
                Export-EntraOpsPrivilegedEAMBloodHound -TenantId $TenantId -ImportPath $ImportPath `
                    -RbacSystems $AvailableSystems -OutputPath $TempFile | Out-Null
                (Get-Content -LiteralPath $TempFile -Raw -Encoding UTF8 | ConvertFrom-Json).graph
            } finally {
                if (Test-Path -LiteralPath $TempFile) { Remove-Item -LiteralPath $TempFile -Force }
            }
        }
    }

    $graphNodes = [System.Collections.Generic.List[object]]::new()
    $graphEdges = [System.Collections.Generic.List[object]]::new()
    if ($null -ne $graph) {
        foreach ($n in @($graph.nodes)) { if ($null -ne $n) { $graphNodes.Add($n) } }
        foreach ($e in @($graph.edges)) { if ($null -ne $e) { $graphEdges.Add($e) } }
    }

    # ── 2b. Azure RBAC graph parts (synthesized - not part of the BloodHound export) ──
    # The BloodHound exporter does not support the Azure RBAC system, so Azure nodes and
    # edges are synthesized here in the exact same OpenGraph shape and naming conventions
    # (EO_AzureRole / EO_AzureRoleAssignment node kinds; EO_HasAzureRole,
    # EO_EligibleForAzureRole, EO_HasAzureRoleAssignment, EO_AzureRoleAssigned,
    # EO_ScopedViaResource edge kinds) and then flattened, enriched and tier-breach-flagged
    # by the very same pipeline below.
    # Ownership (EO_OwnerOf/EO_OwnedBy) and device-ownership (EO_OwnsDevice/EO_DeviceOwner)
    # edges are also synthesized here from the same OwnedObjects/Owners/OwnedDevices
    # properties the BloodHound exporter reads for the other RBAC systems, using the same
    # edge kinds, so Azure-sourced principals (e.g. Azure RBAC-assignable groups) show up
    # in the Access Path Map's "ownership" filter too.
    # The BloodHound integration itself is intentionally left untouched - these kinds only
    # exist inside the Access Path Map dataset.
    if ($azureEamObjects.Count -gt 0) {
        # Azure Tier0/Tier1 resource scope reasoning (Classification/<TenantName>/ScopeReasoning_Azure.json,
        # written by Update-EntraOpsClassificationControlPlaneScope) - explains why an Azure role
        # assignment's RoleAssignmentScopeId (and every ARM path above it) is Tier0/Tier1 resource
        # scope: a privileged resource at/below that scope (e.g. one hosting a system-assigned
        # managed identity) caused the whole ARM hierarchy above it to be included. Surfaced below
        # as EO_ScopedViaResource edges from the role assignment/principal to that managed
        # identity's own node (this edge kind is synthesized here only, like the other Azure RBAC
        # kinds above - the BloodHound exporter does not process the Azure RBAC system).
        $azureScopeReasoningDetails = Import-EntraOpsAzureScopeReasoning -RepoRoot $RepoRoot

        $existingNodeIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
        foreach ($n in $graphNodes) { [void]$existingNodeIds.Add("$(Get-PropValue $n 'id')") }
        $existingEdgeKeys = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
        foreach ($e in $graphEdges) {
            $sVal = "$(Get-PropValue (Get-PropValue $e 'start') 'value')"
            $eVal = "$(Get-PropValue (Get-PropValue $e 'end') 'value')"
            [void]$existingEdgeKeys.Add("$sVal|$(Get-PropValue $e 'kind')|$eVal")
        }

        function Add-ApmGraphNode {
            param([string]$Id, [string[]]$Kinds, [System.Collections.IDictionary]$Properties)
            if ($existingNodeIds.Contains($Id)) { return }
            [void]$existingNodeIds.Add($Id)
            $graphNodes.Add([PSCustomObject]@{ id = $Id; kinds = @($Kinds); properties = [PSCustomObject]$Properties })
        }
        function Add-ApmGraphEdge {
            param([string]$StartId, [string]$EndId, [string]$Kind, [System.Collections.IDictionary]$Properties)
            $key = "$StartId|$Kind|$EndId"
            if ($existingEdgeKeys.Contains($key)) { return }
            [void]$existingEdgeKeys.Add($key)
            $graphEdges.Add([PSCustomObject]@{
                    kind       = $Kind
                    start      = [PSCustomObject]@{ value = $StartId; match_by = 'id' }
                    end        = [PSCustomObject]@{ value = $EndId; match_by = 'id' }
                    properties = [PSCustomObject]$Properties
                })
        }

        $AzurePrincipalKindMap = @{ user = 'AZUser'; group = 'AZGroup'; serviceprincipal = 'AZServicePrincipal'; device = 'AZDevice' }
        $azureEdgeCount = 0
        foreach ($azObj in $azureEamObjects) {
            $azPrincipalId = "$(Get-PropValue $azObj 'ObjectId')".ToUpperInvariant()
            if (-not $azPrincipalId) { continue }
            $azKind = $AzurePrincipalKindMap["$(Get-PropValue $azObj 'ObjectType')".ToLower()]
            if (-not $azKind) { $azKind = 'EO_Base' }
            # Principal node stub - display name/classification enrichment happens in step 3
            # via the $principals lookup (which already contains the Azure EAM objects).
            Add-ApmGraphNode -Id $azPrincipalId -Kinds @($azKind) -Properties ([ordered]@{})

            # Ownership edges (EO_OwnerOf / EO_OwnedBy) and device-ownership edges
            # (EO_OwnsDevice / EO_DeviceOwner) - Azure is not part of the BloodHound
            # exporter's RbacSystems, so these have to be synthesized here from the same
            # OwnedObjects/Owners/OwnedDevices properties that exporter reads for the other
            # RBAC systems. Endpoint nodes are resolved to real principals (or a stub) by
            # the missing-endpoint pass in step 4 - no node is created here on purpose.
            $azOwnedObjectIds = @(Get-PropValue $azObj 'OwnedObjects' | Where-Object { $_ } | ForEach-Object { "$_".ToUpperInvariant() })
            foreach ($ownedId in $azOwnedObjectIds) {
                Add-ApmGraphEdge -StartId $azPrincipalId -EndId $ownedId -Kind 'EO_OwnerOf' -Properties ([ordered]@{ rbacsystem = 'Azure' })
                Add-ApmGraphEdge -StartId $ownedId -EndId $azPrincipalId -Kind 'EO_OwnedBy' -Properties ([ordered]@{ rbacsystem = 'Azure' })
                $azureEdgeCount += 2
            }
            $azOwnerIds = @(Get-PropValue $azObj 'Owners' | Where-Object { $_ } | ForEach-Object { "$_".ToUpperInvariant() })
            foreach ($ownerId in $azOwnerIds) {
                Add-ApmGraphEdge -StartId $ownerId -EndId $azPrincipalId -Kind 'EO_OwnerOf' -Properties ([ordered]@{ rbacsystem = 'Azure' })
                Add-ApmGraphEdge -StartId $azPrincipalId -EndId $ownerId -Kind 'EO_OwnedBy' -Properties ([ordered]@{ rbacsystem = 'Azure' })
                $azureEdgeCount += 2
            }
            $azOwnedDeviceIds = @(Get-PropValue $azObj 'OwnedDevices' | Where-Object { $_ } | ForEach-Object { "$_".ToUpperInvariant() })
            foreach ($devId in $azOwnedDeviceIds) {
                Add-ApmGraphEdge -StartId $azPrincipalId -EndId $devId -Kind 'EO_OwnsDevice' -Properties ([ordered]@{ rbacsystem = 'Azure' })
                Add-ApmGraphEdge -StartId $devId -EndId $azPrincipalId -Kind 'EO_DeviceOwner' -Properties ([ordered]@{ rbacsystem = 'Azure' })
                $azureEdgeCount += 2
            }

            foreach ($ra in @(Get-PropValue $azObj 'RoleAssignments')) {
                if ($null -eq $ra) { continue }
                $raid = Get-AssignmentKey $roleSystem $ra
                if (-not $raid) { continue }

                # Best (most privileged) classification for this assignment - same rule as the
                # BloodHound exporter's Get-BestClassification.
                $bestClass = @(Get-PropValue $ra 'Classification') |
                Where-Object { $null -ne (Get-PropValue $_ 'AdminTierLevel') } |
                Sort-Object { "$(Get-PropValue $_ 'AdminTierLevel')" } |
                Select-Object -First 1

                $pimType = "$(Get-PropValue $ra 'PIMAssignmentType')"
                $edgeProps = [ordered]@{
                    admintierlevel          = "$(Get-PropValue $bestClass 'AdminTierLevel')"
                    admintierlevelname      = "$(Get-PropValue $bestClass 'AdminTierLevelName')"
                    service                 = "$(Get-PropValue $bestClass 'Service')"
                    taggedby                = "$(Get-PropValue $bestClass 'TaggedBy')"
                    taggedbyrolesystem      = "$(Get-PropValue $bestClass 'TaggedByRoleSystem')"
                    roleassignmenttype      = "$(Get-PropValue $ra 'RoleAssignmentType')"
                    roleassignmentsubtype   = "$(Get-PropValue $ra 'RoleAssignmentSubType')"
                    pimassignmenttype       = $pimType
                    pimmanagedrole          = [bool]((Get-PropValue $ra 'PIMManagedRole') -eq $true)
                    roleassignmentscopeid   = "$(Get-PropValue $ra 'RoleAssignmentScopeId')"
                    roleassignmentscopename = "$(Get-PropValue $ra 'RoleAssignmentScopeName')"
                    rbacsystem              = 'Azure'
                }

                Add-ApmGraphNode -Id $raid -Kinds @('EO_AzureRoleAssignment') -Properties ([ordered]@{
                        name                    = $raid
                        displayname             = $raid
                        rbacsystem              = 'Azure'
                        roleassignmentscopeid   = "$(Get-PropValue $ra 'RoleAssignmentScopeId')"
                        roleassignmentscopename = "$(Get-PropValue $ra 'RoleAssignmentScopeName')"
                        roleassignmenttype      = "$(Get-PropValue $ra 'RoleAssignmentType')"
                    })
                Add-ApmGraphEdge -StartId $azPrincipalId -EndId $raid -Kind 'EO_HasAzureRoleAssignment' -Properties $edgeProps
                $azureEdgeCount++

                # EO_ScopedViaResource: why this Azure role assignment's resource scope is
                # Tier0/Tier1 - link to the managed identity/application whose hosting resource
                # caused it (see comment on $azureScopeReasoningDetails above).
                if ($azureScopeReasoningDetails.Count -gt 0) {
                    $azureRoleScopeId = "$(Get-PropValue $ra 'RoleAssignmentScopeId')".Trim()
                    foreach ($ScopeReason in (Find-EntraOpsAzureScopeReasoning -ScopeReasoningDetails $azureScopeReasoningDetails -ScopeId $azureRoleScopeId)) {
                        $miObjectId = "$(Get-PropValue $ScopeReason 'ManagedIdentityObjectId')"
                        if ([string]::IsNullOrEmpty($miObjectId)) { continue }
                        $miObjectId = $miObjectId.ToUpperInvariant()

                        $scopeReasonProps = [ordered]@{
                            resourcename   = "$(Get-PropValue $ScopeReason 'ScopeName')"
                            resourceid     = "$(Get-PropValue $ScopeReason 'ScopeId')"
                            eamtier        = "$(Get-PropValue $ScopeReason 'EAMTier')"
                            resultingscope = "$(Get-PropValue $ScopeReason 'ResultingScope')"
                            reason         = "$(Get-PropValue $ScopeReason 'Reason')"
                            rbacsystem     = 'Azure'
                        }
                        Add-ApmGraphEdge -StartId $azPrincipalId -EndId $miObjectId -Kind 'EO_ScopedViaResource' -Properties $scopeReasonProps
                        Add-ApmGraphEdge -StartId $raid -EndId $miObjectId -Kind 'EO_ScopedViaResource' -Properties $scopeReasonProps
                        $azureEdgeCount += 2
                    }
                }

                $rdid = "$(Get-PropValue $ra 'RoleDefinitionId')".ToUpperInvariant()
                if ($rdid) {
                    $roleNodeId = $rdid + '@' + $TenantIdUpper
                    $roleDefName = "$(Get-PropValue $ra 'RoleDefinitionName')"
                    Add-ApmGraphNode -Id $roleNodeId -Kinds @('EO_AzureRole') -Properties ([ordered]@{
                            name        = $(if ($roleDefName) { $roleDefName } else { $roleNodeId })
                            displayname = $(if ($roleDefName) { $roleDefName } else { $roleNodeId })
                            rbacsystem  = 'Azure'
                        })
                    $roleEdgeKind = if ($pimType -eq 'Eligible') { 'EO_EligibleForAzureRole' } else { 'EO_HasAzureRole' }
                    Add-ApmGraphEdge -StartId $azPrincipalId -EndId $roleNodeId -Kind $roleEdgeKind -Properties $edgeProps
                    Add-ApmGraphEdge -StartId $roleNodeId -EndId $raid -Kind 'EO_AzureRoleAssigned' -Properties $edgeProps
                    $azureEdgeCount += 2
                }
            }
        }
        Write-Verbose "Azure RBAC synthesized into the graph: $($azureEamObjects.Count) principal object(s), $azureEdgeCount edge(s)."
    }

    # ── 3. Flatten + enrich nodes ───────────────────────────────────────────────
    $nodes = [System.Collections.Generic.List[object]]::new()
    $principalTierByNode = @{}

    # Tenant scope node (target of tenant-wide EO_ScopedTo edges).
    $tenantReferenced = $false
    foreach ($e in $graphEdges) {
        $endVal = Get-PropValue (Get-PropValue $e 'end') 'value'
        if ("$endVal" -eq $TenantIdUpper) { $tenantReferenced = $true; break }
    }

    foreach ($n in $graphNodes) {
        if ($null -eq $n) { continue }
        $id = "$(Get-PropValue $n 'id')"
        $props = [ordered]@{}
        $rawProps = Get-PropValue $n 'properties'
        if ($null -ne $rawProps) {
            foreach ($p in $rawProps.PSObject.Properties) {
                if ($p.Name -in $CypherHelperProperties) { continue }
                $props[$p.Name] = $p.Value
            }
        }

        $kinds = @(@(Get-PropValue $n 'kinds') | ForEach-Object { "$_" })
        $primaryKind = if ($kinds.Count -gt 0) { $kinds[0] } else { 'EO_Base' }

        # Principal enrichment (names, sync source, restricted management, ...).
        if ($principals.ContainsKey($id)) {
            $enr = $principals[$id]
            foreach ($k in $enr.Keys) {
                if ($k -eq 'tiernumber') { continue }
                $v = $enr[$k]
                if ($v -is [System.Collections.Generic.List[string]]) { $v = @($v) }
                if ($null -ne $v -and -not $props.Contains($k)) { $props[$k] = $v }
            }
            if (-not $props.Contains('name')) { $props['name'] = $enr.displayname }
            $principalTierByNode[$id] = $enr.tiernumber
        }

        # Role definition enrichment (EntraID AZRole nodes carry no name in the export).
        # Node name/label always resolves to the role definition name - never a raw GUID.
        if ($id -match '^(.*)@' -and ($primaryKind -eq 'AZRole' -or $primaryKind -like 'EO_*Role')) {
            $rdid = $Matches[1]
            if ($roleDefs.ContainsKey($rdid)) {
                $rd = $roleDefs[$rdid]
                if (-not $props.Contains('name') -or -not $props['name']) { $props['name'] = $rd.name }
                if (-not $props.Contains('displayname') -or -not $props['displayname']) { $props['displayname'] = $rd.name }
                if (-not $props.Contains('roletype')) { $props['roletype'] = $rd.roletype }
                if (-not $props.Contains('isprivileged')) { $props['isprivileged'] = $rd.isprivileged }
                # Role actions & classification (tier/service), aggregated across every
                # assignment of this role, so the detail drawer can show what the role can do.
                if ($rd.actions.Count -gt 0 -and -not $props.Contains('matchedactions')) { $props['matchedactions'] = @($rd.actions) }
                if ($rd.tiernames.Count -gt 0 -and -not $props.Contains('classification_tiernames')) { $props['classification_tiernames'] = @($rd.tiernames) }
                if ($rd.services.Count -gt 0 -and -not $props.Contains('classification_services')) { $props['classification_services'] = @($rd.services) }
                # Description/categories from the optional role catalog files (best-effort).
                $rdidUpper = $rdid.ToUpperInvariant()
                if ($roleCatalog.ContainsKey($rdidUpper)) {
                    $cat = $roleCatalog[$rdidUpper]
                    if ($cat.description -and -not $props.Contains('description')) { $props['description'] = $cat.description }
                    if ($cat.categories.Count -gt 0 -and -not $props.Contains('categories')) { $props['categories'] = @($cat.categories) }
                }
                # Known (documented) attack paths this role participates in - matched against
                # the same curated catalog the Classification Explorer's Attack Paths view uses.
                $rdKnownPaths = @(Get-KnownAttackPathIds -RbacSystem $rd.rbacsystem -RoleName $rd.name -Actions @($rd.actions))
                if ($rdKnownPaths.Count -gt 0) {
                    $props['knownattackpaths'] = @($rdKnownPaths)
                    $props['knownattackpathnames'] = @($rdKnownPaths | ForEach-Object { $attackPathMeta[$_].name })
                    $props['knownattackpathseverity'] = if ($rdKnownPaths | Where-Object { $attackPathMeta[$_].severity -eq 'Critical' }) { 'Critical' } else { 'High' }
                }
            }
        }

        # Role assignment nodes: the BloodHound exporter names these nodes after their
        # (GUID) RoleAssignmentId - override with a human-readable "<role> @ <scope>" label
        # and add the role actions/classification for this specific assignment.
        if ($primaryKind -like 'EO_*RoleAssignment' -and $assignments.ContainsKey($id)) {
            $as = $assignments[$id]
            if (-not $props.Contains('roledefinitionname') -or -not $props['roledefinitionname']) { $props['roledefinitionname'] = $as.rolename }
            if ($as.rolename) {
                $assignmentLabel = if ($as.scopename) { "$($as.rolename) @ $($as.scopename)" } else { $as.rolename }
                $props['name'] = $assignmentLabel
                $props['displayname'] = $assignmentLabel
            }
            if ((-not $props.Contains('matchedactions') -or -not $props['matchedactions']) -and $as.actions.Count -gt 0) {
                $props['matchedactions'] = @($as.actions)
            }
            if ($as.tiernames.Count -gt 0 -and -not $props.Contains('classification_tiernames')) { $props['classification_tiernames'] = @($as.tiernames) }
            if ($as.services.Count -gt 0 -and -not $props.Contains('classification_services')) { $props['classification_services'] = @($as.services) }
            # Known (documented) attack paths this specific assignment participates in.
            $asKnownPaths = @(Get-KnownAttackPathIds -RbacSystem $as.rbacsystem -RoleName $as.rolename -Actions @($as.actions))
            if ($asKnownPaths.Count -gt 0) {
                $props['knownattackpaths'] = @($asKnownPaths)
                $props['knownattackpathnames'] = @($asKnownPaths | ForEach-Object { $attackPathMeta[$_].name })
                $props['knownattackpathseverity'] = if ($asKnownPaths | Where-Object { $attackPathMeta[$_].severity -eq 'Critical' }) { 'Critical' } else { 'High' }
            }
        }

        if (-not $props.Contains('name') -or -not $props['name']) { $props['name'] = $id }

        $nodes.Add([ordered]@{
                id         = $id
                kinds      = $kinds
                properties = $props
            })
    }

    if ($tenantReferenced) {
        $nodes.Add([ordered]@{
                id         = $TenantIdUpper
                kinds      = @('EO_Tenant')
                properties = [ordered]@{ name = "Tenant ($TenantId)"; displayname = "Tenant ($TenantId)" }
            })
    }

    # ── 4. Flatten edges + compute tier-breach flags ─────────────────────────────
    function Resolve-EndpointId {
        param($Endpoint)
        $matchBy = "$(Get-PropValue $Endpoint 'match_by')"
        if ($matchBy -eq 'id') { return "$(Get-PropValue $Endpoint 'value')" }
        # Property-matched endpoints (EO_UsesPAW / EO_PAWFor): use the matcher value.
        $matchers = @(Get-PropValue $Endpoint 'property_matchers')
        if ($matchers.Count -gt 0) {
            return "$(Get-PropValue $matchers[0] 'value')".ToUpperInvariant()
        }
        return ''
    }

    $BreachableEdgePattern = '^EO_(Has|EligibleFor)\w*Role(Assignment)?$'
    $edges = [System.Collections.Generic.List[object]]::new()
    $nBreach = 0
    $nTier0 = 0

    foreach ($e in $graphEdges) {
        if ($null -eq $e) { continue }
        $kind = "$(Get-PropValue $e 'kind')"
        $sourceId = Resolve-EndpointId (Get-PropValue $e 'start')
        $targetId = Resolve-EndpointId (Get-PropValue $e 'end')
        if (-not $sourceId -or -not $targetId) { continue }

        $props = [ordered]@{}
        $rawProps = Get-PropValue $e 'properties'
        if ($null -ne $rawProps) {
            foreach ($p in $rawProps.PSObject.Properties) {
                if ($p.Name -in $CypherHelperProperties) { continue }
                $props[$p.Name] = $p.Value
            }
        }

        # Tier-breach flags on principal -> role / role-assignment edges
        # (same semantics as the Tier Breach Analyzer).
        if ($kind -match $BreachableEdgePattern -and $principalTierByNode.ContainsKey($sourceId)) {
            $principalTier = $principalTierByNode[$sourceId]
            $serviceTier = ConvertTo-TierNumber $props['admintierlevel']
            $isBreach = $principalTier -gt $serviceTier
            $isTier0 = ($serviceTier -eq 0 -and $principalTier -gt 0)
            $props['principaltier'] = $principalTier
            $props['servicetier'] = $serviceTier
            $props['tierbreach'] = $isBreach
            $props['tier0breach'] = $isTier0
            if ($isBreach) { $nBreach++ }
            if ($isTier0) { $nTier0++ }
        }

        $edges.Add([ordered]@{
                kind       = $kind
                source     = $sourceId
                target     = $targetId
                properties = $props
            })
    }

    # ── 4b. Resolve edge endpoints that have no graph node ("unresolved objects") ──
    # Edges can reference objects the EAM export carries only by id (owned/PAW devices,
    # work accounts, sponsors, Intune scope group members, ...). The frontend previously
    # dropped those edges from the graph and showed "(unresolved object)" in the drawer.
    # Display names for devices and Intune scope groups are recovered from the persisted
    # group -> device member mapping written by Update-EntraOpsClassificationControlPlaneScope
    # (Classification/<tenant>/DeviceManagement_ScopeGroupDeviceMembers.json); everything
    # else gets an explicit placeholder node (unresolved = true) so the edge stays visible.
    $deviceNameLookup = @{}    # UPPER object id -> @{ name; kind }
    $classificationRoot = Join-Path $RepoRoot 'Classification'
    if (Test-Path -LiteralPath $classificationRoot) {
        foreach ($mapFile in @(Get-ChildItem -Path $classificationRoot -Filter 'DeviceManagement_ScopeGroupDeviceMembers.json' -Recurse -File -ErrorAction SilentlyContinue)) {
            try {
                $mapData = Get-Content -LiteralPath $mapFile.FullName -Raw -Encoding UTF8 | ConvertFrom-Json
            } catch {
                Write-Warning "Could not parse $($mapFile.FullName): $($_.Exception.Message)"
                continue
            }
            $groupMembers = Get-PropValue $mapData 'groupDeviceMembers'
            if ($null -ne $groupMembers) {
                foreach ($gp in @($groupMembers.PSObject.Properties)) {
                    $gid = "$($gp.Name)".ToUpperInvariant()
                    $gName = "$(Get-PropValue $gp.Value 'displayName')"
                    if ($gid -and $gName -and -not $deviceNameLookup.ContainsKey($gid)) {
                        $deviceNameLookup[$gid] = @{ name = $gName; kind = 'AZGroup' }
                    }
                    foreach ($dm in @(Get-PropValue $gp.Value 'deviceMembers')) {
                        $did = "$(Get-PropValue $dm 'id')".ToUpperInvariant()
                        $dName = "$(Get-PropValue $dm 'displayName')"
                        if ($did -and $dName -and -not $deviceNameLookup.ContainsKey($did)) {
                            $deviceNameLookup[$did] = @{ name = $dName; kind = 'AZDevice' }
                        }
                    }
                }
            }
            foreach ($dev in @(Get-PropValue $mapData 'allClassifiedDevices')) {
                $did = "$(Get-PropValue $dev 'id')".ToUpperInvariant()
                $dName = "$(Get-PropValue $dev 'displayName')"
                if ($did -and $dName -and -not $deviceNameLookup.ContainsKey($did)) {
                    $deviceNameLookup[$did] = @{ name = $dName; kind = 'AZDevice' }
                }
            }
        }
    }

    $knownNodeIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
    foreach ($n in $nodes) { [void]$knownNodeIds.Add("$($n.id)") }
    $PrincipalStubKindMap = @{ user = 'AZUser'; group = 'AZGroup'; serviceprincipal = 'AZServicePrincipal'; device = 'AZDevice' }
    $nResolvedEndpoints = 0
    $nStubbedEndpoints = 0
    $nGraphResolvedEndpoints = 0
    $graphResolutionDurationSeconds = 0
    $missingEndpointIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
    foreach ($e in $edges) {
        foreach ($endpointId in @($e.source, $e.target)) {
            if (-not $knownNodeIds.Contains($endpointId)) { [void]$missingEndpointIds.Add($endpointId) }
        }
    }

    # ── Optional: resolve remaining unresolved endpoints (not part of the Privileged EAM
    # export or the Intune device map above) via Microsoft Graph. These are typically
    # non-privileged objects only referenced through OwnedObjects/Owners/AssociatedPawDevice/
    # AssociatedWorkAccount/Sponsors (e.g. a privileged account's standard work account, or a
    # group/application owned by a privileged principal). Opt-in via -ResolveObjectIdsOutsidePrivilegedEAM
    # / EntraOpsConfig.json "AccessPathMap.ResolveObjectIdsOutsidePrivilegedEAM" since it requires an
    # active Graph connection and adds network round-trips.
    $graphResolvedLookup = @{}   # UPPER object id -> @{ name; kind }
    if ($ResolveObjectIdsOutsidePrivilegedEAM -and $missingEndpointIds.Count -gt 0) {
        $GuidPattern = '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
        $idsToResolve = @($missingEndpointIds | Where-Object {
                $u = $_.ToUpperInvariant()
                ($_ -match $GuidPattern) -and -not $deviceNameLookup.ContainsKey($u) -and -not $principals.ContainsKey($u)
            })

        if ($idsToResolve.Count -gt 0) {
            Write-Verbose "Resolving $($idsToResolve.Count) edge endpoint object id(s) outside the Privileged EAM export via Microsoft Graph..."
            $GraphBatchSize = 999   # directoryObjects/getByIds accepts up to 1000 ids per request
            $nGraphResolveFailures = 0
            $graphResolutionStopwatch = [System.Diagnostics.Stopwatch]::StartNew()
            for ($i = 0; $i -lt $idsToResolve.Count; $i += $GraphBatchSize) {
                $idBatch = $idsToResolve[$i..([Math]::Min($i + $GraphBatchSize - 1, $idsToResolve.Count - 1))]
                $getByIdsBody = @{
                    ids   = @($idBatch)
                    types = @('user', 'group', 'servicePrincipal', 'device')
                } | ConvertTo-Json
                try {
                    $resolvedObjects = @(Invoke-EntraOpsMsGraphQuery -Method POST -Uri '/v1.0/directoryObjects/getByIds' -Body $getByIdsBody -OutputType PSObject)
                    foreach ($resolvedObject in $resolvedObjects) {
                        $resolvedId = "$(Get-PropValue $resolvedObject 'id')".ToUpperInvariant()
                        if ([string]::IsNullOrEmpty($resolvedId) -or $graphResolvedLookup.ContainsKey($resolvedId)) { continue }
                        $odataType = "$(Get-PropValue $resolvedObject '@odata.type')"
                        $resolvedKind = switch -Regex ($odataType) {
                            'user$' { 'AZUser' }
                            'group$' { 'AZGroup' }
                            'servicePrincipal$' { 'AZServicePrincipal' }
                            'device$' { 'AZDevice' }
                            default { 'EO_Base' }
                        }
                        $resolvedName = "$(Get-PropValue $resolvedObject 'displayName')"
                        if ([string]::IsNullOrEmpty($resolvedName)) { $resolvedName = $resolvedId }
                        $graphResolvedLookup[$resolvedId] = @{ name = $resolvedName; kind = $resolvedKind }
                    }
                } catch {
                    $nGraphResolveFailures += $idBatch.Count
                    Write-Warning "Failed to resolve $($idBatch.Count) object id(s) outside the Privileged EAM export via Microsoft Graph: $($_.Exception.Message)"
                }
            }
            $graphResolutionStopwatch.Stop()
            $graphResolutionDurationSeconds = [Math]::Round($graphResolutionStopwatch.Elapsed.TotalSeconds, 2)
            if ($nGraphResolveFailures -gt 0) {
                Write-Warning "$nGraphResolveFailures object id(s) outside the Privileged EAM export could not be resolved via Microsoft Graph and will be shown as unresolved placeholders."
            }
            if ($graphResolutionDurationSeconds -ge 30) {
                Write-Warning "Access Path Map resolved $($idsToResolve.Count) outside-EAM endpoint id(s) via Microsoft Graph in $graphResolutionDurationSeconds second(s). If this materially slows report generation, set AccessPathMap.ResolveObjectIdsOutsidePrivilegedEAM to false in EntraOpsConfig.json; unresolved endpoints remain visible as placeholders."
            }
        }
    }

    foreach ($missingId in $missingEndpointIds) {
        $upperId = $missingId.ToUpperInvariant()
        $stub = $null
        if ($deviceNameLookup.ContainsKey($upperId)) {
            # Resolved via the persisted Intune scope group -> device member mapping.
            $hit = $deviceNameLookup[$upperId]
            $stub = [ordered]@{
                id         = $missingId
                kinds      = @($hit.kind)
                properties = [ordered]@{ name = $hit.name; displayname = $hit.name; objectid = $upperId }
            }
            $nResolvedEndpoints++
        } elseif ($principals.ContainsKey($upperId)) {
            # Known privileged object from the EAM export that never got its own graph node.
            $enr = $principals[$upperId]
            $stubKind = $PrincipalStubKindMap["$($enr.objecttype)".ToLower()]
            if (-not $stubKind) { $stubKind = 'EO_Base' }
            $stubName = if ($enr.displayname) { $enr.displayname } else { $missingId }
            $stub = [ordered]@{
                id         = $missingId
                kinds      = @($stubKind)
                properties = [ordered]@{ name = $stubName; displayname = $stubName; objectid = $upperId; entraopsadmintierlevelname = $enr.entraopsadmintierlevelname }
            }
            $nResolvedEndpoints++
        } elseif ($graphResolvedLookup.ContainsKey($upperId)) {
            # Resolved via Microsoft Graph (-ResolveObjectIdsOutsidePrivilegedEAM): a non-privileged
            # object (e.g. a standard work account, or a group/application owned by a privileged
            # principal) that only appears as an OwnedObjects/Owners/AssociatedPawDevice/
            # AssociatedWorkAccount/Sponsors reference, not as a privileged object in the EAM export.
            $hit = $graphResolvedLookup[$upperId]
            $stub = [ordered]@{
                id         = $missingId
                kinds      = @($hit.kind)
                properties = [ordered]@{ name = $hit.name; displayname = $hit.name; objectid = $upperId }
            }
            $nGraphResolvedEndpoints++
        } else {
            # Still unknown - keep the edge visible with an explicit unresolved placeholder.
            $stub = [ordered]@{
                id         = $missingId
                kinds      = @('EO_Base')
                properties = [ordered]@{ name = $missingId; displayname = $missingId; unresolved = $true }
            }
            $nStubbedEndpoints++
        }
        $nodes.Add($stub)
        [void]$knownNodeIds.Add($missingId)
    }

    # ── 5. Write dataset ─────────────────────────────────────────────────────────
    $repoRootFull = (Resolve-Path -LiteralPath $RepoRoot).Path
    $tenantName = Get-EntraOpsReportingTenantName -RepoRoot $RepoRoot
    $payload = [ordered]@{
        tenantName    = $tenantName
        generatedFrom = @(@($files) | ForEach-Object {
                if ($_.FullName.StartsWith($repoRootFull)) {
                    $_.FullName.Substring($repoRootFull.Length).TrimStart('\', '/') -replace '\\', '/'
                } else {
                    $_.Name
                }
            })
        tenantId      = $TenantIdUpper
        nodes         = $nodes
        edges         = $edges
    }

    $json = $payload | ConvertTo-Json -Depth 12 -Compress
    $content = "// Auto-generated by New-EntraOpsAccessPathMapData - do not edit by hand.`n" +
    "window.ENTRAOPS_APM_DATA = $json;`n"

    if ($PSCmdlet.ShouldProcess($OutFile, 'Write Access Path Map dataset')) {
        Save-EntraOpsReportDataFile -Content $content -LiteralPath $OutFile

        Write-Host "Graph nodes:       $($nodes.Count)"
        Write-Host "Graph edges:       $($edges.Count)"
        Write-Host "Tier breach edges: $nBreach"
        Write-Host "Tier 0 breaches:   $nTier0"
        Write-Host "Endpoints resolved via Intune device map / EAM: $nResolvedEndpoints"
        if ($ResolveObjectIdsOutsidePrivilegedEAM) {
            Write-Host "Endpoints resolved via Microsoft Graph (outside Privileged EAM): $nGraphResolvedEndpoints"
            Write-Host "Microsoft Graph endpoint resolution duration:          $graphResolutionDurationSeconds second(s)"
        }
        Write-Host "Endpoints kept as unresolved placeholders:      $nStubbedEndpoints"
        Write-Host "Wrote $OutFile"
    }

    if ($PassThru) { $payload }
}
