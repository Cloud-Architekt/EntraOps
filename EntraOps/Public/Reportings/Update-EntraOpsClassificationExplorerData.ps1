#Requires -Version 7.0
function Update-EntraOpsClassificationExplorerData {

    <#
    .SYNOPSIS
        Refreshes the embedded classification data for the Classification Explorer static web
        app, for either the standalone (AzurePrivilegedIAM) or the EntraOps-embedded deployment.

    .DESCRIPTION
        This is the single, canonical generator for the Classification Explorer app source that
        lives (byte-identical, apart from js/mode.js) in two repositories:

            * AzurePrivilegedIAM/ClassificationExplorer                (standalone deployment)
            * <EntraOps repo>/Reports/ClassificationExplorer            (entraops deployment)

        -Mode selects which deployment is being refreshed:

            Standalone (default) - reads classification-logic templates from the flat
                EntraOps_Classification/ folder of -RepoRoot. No tenant-specific classification
                variants. Also (re)generates the git-log-based change history for the History
                view and notifications (skip with -SkipHistory).

            EntraOps - reads the RBAC system outputs (classified roles) from the AzurePrivilegedIAM
                repository (-RepoRoot, auto-detected as a sibling folder when omitted) and the
                classification-logic templates from Classification/Templates of the EntraOps
                repository (-EntraOpsRoot), plus any tenant-specific parameterized copies written
                by Update-EntraOpsClassificationControlPlaneScope to Classification/<TenantName>/
                (embedded as window.EOCE_TENANTS for the variant picker / Template Comparison
                view). Missing/optional template files are embedded as an empty array with a
                warning instead of failing generation. Generates change history for notifications;
                the full History view remains hidden in this mode.

        The web app is fully self-contained in both modes: it loads its data exclusively from the
        embedded bundle data/classification-data.js (window.EOCE_DATA) - there is no runtime fetch
        fallback, so the app works from the file:// protocol with no web server. Regenerates:

            * data/classification-data.js  - the embedded bundle (window.EOCE_DATA), plus
                                              window.EOCE_TENANTS (entraops mode only).
            * data-manifest.json           - timestamp, size, SHA-256 hash and item count per
                                              source file (traceability only - never read by the
                                              app itself).
            * data/attack-paths.js         - attack-path catalog, from content/attack-paths/*.md.
            * data/tier-map.js             - Overview (Enterprise Access Model Map) Sankey dataset.
            * data/notification-data.js    - compact latest-change summary for the app bar.
            * data/history-data.js         - change history (git log) for notifications and the
                                              standalone History view.

        Each file is validated (the *.Param.json files contain EntraOps scope placeholder tokens
        such as <Tier0IncludedResourceScope>, which are sanitized the same way the app does before
        validation).

    .PARAMETER Mode
        'Standalone' (default) or 'EntraOps'. See DESCRIPTION.

    .PARAMETER RepoRoot
        Path to the AzurePrivilegedIAM repository root (contains 'Classification' and, in
        Standalone mode, 'EntraOps_Classification'). Defaults to the root inferred from the
        imported module in Standalone mode; auto-detected as a sibling folder of -EntraOpsRoot named
        'AzurePrivilegedIAM*' in EntraOps mode.

    .PARAMETER EntraOpsRoot
        EntraOps mode only. Path to the EntraOps repository root (contains 'Classification/Templates'
        and any 'Classification/<TenantName>' tenant-specific copies). Defaults to the parent of
        this script's folder.

    .PARAMETER AppRoot
        Path to the ClassificationExplorer app folder (where the generated content is written).
        Defaults to 'ClassificationExplorer' next to -RepoRoot (Standalone) or
        'Reports/ClassificationExplorer' under -EntraOpsRoot (EntraOps).

    .PARAMETER SkipManifest
        Do not write data-manifest.json.

    .PARAMETER SkipEmbed
        Do not write data/classification-data.js (and data/tier-map.js). By default the script
        generates this embedded bundle, which lets the app run with no web server.

    .PARAMETER SkipHistory
        Do not write data/history-data.js (the git-log-based notification and History dataset).
        Useful while iterating locally, since walking the commit history of every tracked file is
        the slowest part of this script.

    .PARAMETER StrictAttackPaths
        Fail generation when an attack-path action, role or API permission mapping is malformed or
        cannot be resolved against the embedded classification data. Without this switch, mapping
        issues are warnings so contributors can iterate before classifications are updated.

    .PARAMETER PassThru
        Emit the result objects (one per source file) to the pipeline.

    .EXAMPLE
        Update-EntraOpsClassificationExplorerData

        Refreshes the standalone app (AzurePrivilegedIAM/ClassificationExplorer), inferring
        -RepoRoot from this script's location.

    .EXAMPLE
        Update-EntraOpsClassificationExplorerData -Mode EntraOps -Verbose -WhatIf

        Shows what would be generated for the EntraOps-embedded app without changing any files.

    .NOTES
        Cross-platform on PowerShell 7+. This file is synced verbatim
        between the two repositories by Sync-EntraOpsClassificationExplorerSource (to
        <EntraOpsRoot>/EntraOps/Public/Reportings/, where it is loaded as a public function of the
        EntraOps module, same as every Export-EntraOps* cmdlet in this repository) - edit the
        canonical copy in AzurePrivilegedIAM/Modules/EntraOps.Classification/Public.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [ValidateSet('Standalone', 'EntraOps')]
        [string]$Mode = 'Standalone',

        [string]$RepoRoot,
        [string]$EntraOpsRoot,
        [string]$AppRoot,

        [switch]$SkipManifest,
        [switch]$SkipEmbed,
        [switch]$SkipHistory,
        [switch]$StrictAttackPaths,
        [switch]$PassThru
    )

    Set-StrictMode -Version Latest
    $ErrorActionPreference = 'Stop'

    function Resolve-FullPath {
        param([string]$Path)
        return [System.IO.Path]::GetFullPath($Path)
    }

    # Mirror the app's sanitizer: replace <Token> with "«param:Token»" so *.Param.json
    # files (which embed placeholder tokens) parse as valid JSON. Uses [char] codes so it
    # works on both Windows PowerShell 5.1 and PowerShell 7+.
    function ConvertTo-SanitizedJsonText {
        param([string]$Text)
        return [regex]::Replace($Text, '<([A-Za-z0-9_]+)>', {
                param($m)
                '"' + [char]0x00AB + 'param:' + $m.Groups[1].Value + [char]0x00BB + '"'
            })
    }

    function Get-Sha256 {
        param([string]$Path)
        return (Get-FileHash -Path $Path -Algorithm SHA256).Hash.ToLowerInvariant()
    }

    # Strict-mode safe property accessor for the parsed classification objects.
    function Get-JsonProp {
        param($Object, [string]$Name)
        if ($null -ne $Object -and ($Object.PSObject.Properties.Name -contains $Name)) { return $Object.$Name }
        return $null
    }

    $ValidTiers = @('ControlPlane', 'ManagementPlane', 'WorkloadPlane', 'UserAccess', 'Unclassified')

    function Get-TierName {
        param($Value)
        if ($Value -and ($ValidTiers -contains [string]$Value)) { return [string]$Value }
        return 'Unclassified'
    }

    # The role/permission catalogs used by notifications and the History view
    # (data/history-data.js) - kept in sync with EOCE.RBAC_SYSTEMS[*].file /
    # EOCE.PERMISSION_SETS[*].file in js/config.js.
    $HistorySources = [ordered]@{
        EntraID            = [ordered]@{ label = 'Microsoft Entra ID Directory Roles'; kind = 'roles'; file = 'Classification/Classification_EntraIdDirectoryRoles.json' }
        IdentityGovernance = [ordered]@{ label = 'Microsoft Entra Identity Governance'; kind = 'roles'; file = 'Classification/Classification_IdentityGovernance.json' }
        Azure              = [ordered]@{ label = 'Azure Resource Roles'; kind = 'roles'; file = 'Classification/Classification_AzureResources.json' }
        DeviceManagement   = [ordered]@{ label = 'Intune Device Management Roles'; kind = 'roles'; file = 'Classification/Classification_DeviceManagementRoles.json' }
        ApiPermissions     = [ordered]@{ label = 'API Permissions'; kind = 'permissions'; file = 'Classification/Classification_ApiPermissions.json' }
    }

    # Flattens a parsed classification array (at one point in git history) into an ordered
    # dictionary keyed by a stable item id, for cheap diffing between commits (History view).
    function ConvertTo-HistoryIndex {
        param($Parsed, [string]$Kind)

        $index = [ordered]@{}
        if ($null -eq $Parsed) { return $index }
        if ($Parsed -isnot [System.Array]) { $Parsed = @($Parsed) }

        $rolesById = @{}
        if ($Kind -ne 'permissions') {
            foreach ($role in $Parsed) {
                $roleId = [string](Get-JsonProp $role 'RoleId')
                if (-not [string]::IsNullOrEmpty($roleId)) { $rolesById[$roleId] = $role }
            }
        }

        function Add-InheritedActionKeys {
            param([string]$RoleId, [hashtable]$Seen, [hashtable]$ActionKeys)
            if ([string]::IsNullOrEmpty($RoleId) -or $Seen.ContainsKey($RoleId) -or -not $rolesById.ContainsKey($RoleId)) { return }
            $Seen[$RoleId] = $true

            $inheritedRole = $rolesById[$RoleId]
            $inheritedPermissions = Get-JsonProp $inheritedRole 'RolePermissions'
            if ($null -ne $inheritedPermissions) {
                if ($inheritedPermissions -isnot [System.Array]) { $inheritedPermissions = @($inheritedPermissions) }
                foreach ($permission in $inheritedPermissions) {
                    $action = [string](Get-JsonProp $permission 'AuthorizedResourceAction')
                    if ([string]::IsNullOrEmpty($action)) { continue }
                    $category = [string](Get-JsonProp $permission 'Category')
                    $ActionKeys[$action + '|' + $category] = $true
                }
            }

            $parents = Get-JsonProp $inheritedRole 'InheritsPermissionsFrom'
            if ($null -ne $parents) {
                if ($parents -isnot [System.Array]) { $parents = @($parents) }
                foreach ($parentId in $parents) { Add-InheritedActionKeys -RoleId ([string]$parentId) -Seen $Seen -ActionKeys $ActionKeys }
            }
        }

        foreach ($item in $Parsed) {
            if ($null -eq $item) { continue }
            if ($Kind -eq 'permissions') {
                $id = [string](Get-JsonProp $item 'PermissionId')
                if ([string]::IsNullOrEmpty($id)) { $id = [string](Get-JsonProp $item 'PermissionValue') + '|' + [string](Get-JsonProp $item 'TargetAppId') }
                if ([string]::IsNullOrEmpty($id)) { continue }
                $index[$id] = [ordered]@{
                    id       = $id
                    name     = [string](Get-JsonProp $item 'PermissionValue')
                    tier     = Get-TierName (Get-JsonProp $item 'EAMTierLevelName')
                    app      = [string](Get-JsonProp $item 'TargetAppDisplayName')
                    category = [string](Get-JsonProp $item 'Category')
                    type     = [string](Get-JsonProp $item 'PermissionType')
                }
            } else {
                $id = [string](Get-JsonProp $item 'RoleId')
                if ([string]::IsNullOrEmpty($id)) { $id = [string](Get-JsonProp $item 'RoleName') }
                if ([string]::IsNullOrEmpty($id)) { continue }
                $cls = Get-JsonProp $item 'Classification'
                $tier = 'Unclassified'
                if ($cls) { $tier = Get-TierName (Get-JsonProp $cls 'EAMTierLevelName') }
                $actions = [ordered]@{}
                $perms = Get-JsonProp $item 'RolePermissions'
                if ($null -ne $perms) {
                    if ($perms -isnot [System.Array]) { $perms = @($perms) }
                    foreach ($p in $perms) {
                        $act = [string](Get-JsonProp $p 'AuthorizedResourceAction')
                        if ([string]::IsNullOrEmpty($act)) { continue }
                        $cat = [string](Get-JsonProp $p 'Category')
                        $key = $act + '|' + $cat
                        $actions[$key] = [ordered]@{ action = $act; category = $cat; tier = Get-TierName (Get-JsonProp $p 'EAMTierLevelName') }
                    }
                }
                $inheritedActionKeys = @{}
                $parents = Get-JsonProp $item 'InheritsPermissionsFrom'
                if ($null -ne $parents) {
                    if ($parents -isnot [System.Array]) { $parents = @($parents) }
                    $seenParents = @{}
                    foreach ($parentId in $parents) { Add-InheritedActionKeys -RoleId ([string]$parentId) -Seen $seenParents -ActionKeys $inheritedActionKeys }
                }
                foreach ($key in $inheritedActionKeys.Keys) { $actions.Remove($key) }
                $index[$id] = [ordered]@{
                    id           = $id
                    name         = [string](Get-JsonProp $item 'RoleName')
                    tier         = $tier
                    isPrivileged = ((Get-JsonProp $item 'isPrivileged') -eq $true)
                    actionCount  = $actions.Count
                    actions      = $actions
                }
            }
        }
        return $index
    }

    # Compares two consecutive snapshots (ordered dictionaries from ConvertTo-HistoryIndex)
    # and returns the added / removed / changed items for that commit (History view).
    function Compare-HistoryIndex {
        param([System.Collections.IDictionary]$Previous, [System.Collections.IDictionary]$Current, [string]$Kind)

        $added = New-Object System.Collections.Generic.List[object]
        $removed = New-Object System.Collections.Generic.List[object]
        $changed = New-Object System.Collections.Generic.List[object]

        foreach ($id in $Current.Keys) {
            $curr = $Current[$id]
            if (-not $Previous.Contains($id)) {
                $addedEntry = [ordered]@{ id = $id; name = $curr.name; tier = $curr.tier }
                if ($Kind -ne 'permissions') {
                    $addedEntry.actions = @($curr.actions.Values | ForEach-Object { $_.action } | Sort-Object)
                } else {
                    $addedEntry.category = $curr.category
                }
                $added.Add($addedEntry) | Out-Null
                continue
            }
            $prev = $Previous[$id]
            if ($Kind -eq 'permissions') {
                if ($prev.tier -ne $curr.tier -or $prev.category -ne $curr.category) {
                    $changed.Add([ordered]@{
                            id          = $id
                            name        = $curr.name
                            oldTier     = $prev.tier
                            newTier     = $curr.tier
                            oldCategory = $prev.category
                            newCategory = $curr.category
                        }) | Out-Null
                }
            } else {
                $actAdded = @()
                $actRemoved = @()
                foreach ($ak in $curr.actions.Keys) { if (-not $prev.actions.Contains($ak)) { $actAdded += $curr.actions[$ak].action } }
                foreach ($ak in $prev.actions.Keys) { if (-not $curr.actions.Contains($ak)) { $actRemoved += $prev.actions[$ak].action } }
                if ($actAdded.Count -gt 0 -and $actRemoved.Count -gt 0) {
                    $common = @($actAdded | Where-Object { $actRemoved -contains $_ } | Select-Object -Unique)
                    if ($common.Count -gt 0) {
                        $actAdded = @($actAdded | Where-Object { $common -notcontains $_ })
                        $actRemoved = @($actRemoved | Where-Object { $common -notcontains $_ })
                    }
                }
                if ($prev.tier -ne $curr.tier -or $actAdded.Count -gt 0 -or $actRemoved.Count -gt 0) {
                    $changed.Add([ordered]@{
                            id             = $id
                            name           = $curr.name
                            oldTier        = $prev.tier
                            newTier        = $curr.tier
                            actionsAdded   = @($actAdded | Sort-Object)
                            actionsRemoved = @($actRemoved | Sort-Object)
                        }) | Out-Null
                }
            }
        }
        foreach ($id in $Previous.Keys) {
            if (-not $Current.Contains($id)) {
                $prev = $Previous[$id]
                $removedEntry = [ordered]@{ id = $id; name = $prev.name; tier = $prev.tier }
                if ($Kind -ne 'permissions') {
                    $removedEntry.actions = @($prev.actions.Values | ForEach-Object { $_.action } | Sort-Object)
                }
                $removed.Add($removedEntry) | Out-Null
            }
        }

        return [ordered]@{
            added   = @($added.ToArray() | Sort-Object { $_.name })
            removed = @($removed.ToArray() | Sort-Object { $_.name })
            changed = @($changed.ToArray() | Sort-Object { $_.name })
        }
    }

    # Build the flat path dataset that powers the Overview (Enterprise Access Model Map) Sankey:
    #   role system -> role -> service -> role action -> tier level.
    function ConvertTo-TierMapPaths {
        param([System.Collections.IDictionary]$Embed)

        $sysByFile = [ordered]@{
            'Classification/Classification_EntraIdDirectoryRoles.json' = 'EntraID'
            'Classification/Classification_IdentityGovernance.json'    = 'IdentityGovernance'
            'Classification/Classification_AzureResources.json'        = 'Azure'
            'Classification/Classification_DeviceManagementRoles.json' = 'DeviceManagement'
        }
        $docsFile = 'Classification/Classification_EntraIdDirectoryRolesFromMsftDocs.json'
        # Use the function-level $ValidTiers (5 tiers incl. WorkloadPlane) - resolved from the
        # calling scope; do not shadow it with a local subset here.
        $paths = New-Object System.Collections.Generic.List[object]

        function Add-RolePaths {
            param($Role, [string]$Sys, [bool]$DocsOnly, [hashtable]$MismatchActions = $null, $List)
            $roleId = [string](Get-JsonProp $Role 'RoleId')
            if ([string]::IsNullOrEmpty($roleId)) { return }
            $cls = Get-JsonProp $Role 'Classification'
            $roleClass = 'Unclassified'
            if ($cls) { $cv = Get-JsonProp $cls 'EAMTierLevelName'; if ($cv -and ($validTiers -contains [string]$cv)) { $roleClass = [string]$cv } }
            $priv = ((Get-JsonProp $Role 'isPrivileged') -eq $true)
            $cats = [string](Get-JsonProp $Role 'Categories')
            $roleName = [string](Get-JsonProp $Role 'RoleName')
            $perms = Get-JsonProp $Role 'RolePermissions'
            if ($null -eq $perms) { return }
            if ($perms -isnot [System.Array]) { $perms = @($perms) }
            foreach ($p in $perms) {
                $action = Get-JsonProp $p 'AuthorizedResourceAction'
                if ([string]::IsNullOrEmpty([string]$action)) { continue }
                $actionType = if ((Get-JsonProp $p 'ActionType') -eq 'DataAction') { 'DataAction' } else { 'Action' }
                $tv = Get-JsonProp $p 'EAMTierLevelName'
                $tier = if ($tv -and ($validTiers -contains [string]$tv)) { [string]$tv } else { 'Unclassified' }
                $svc = [string](Get-JsonProp $p 'Category')
                if ([string]::IsNullOrEmpty($svc)) { $svc = '(uncategorized)' }
                $graphOnlyDiff = $false
                if ($null -ne $MismatchActions) {
                    $graphOnlyDiff = $MismatchActions.ContainsKey([string]$action.ToLowerInvariant())
                }
                $List.Add([ordered]@{
                        sys           = $Sys
                        roleId        = $roleId
                        role          = $roleName
                        priv          = $priv
                        roleClass     = $roleClass
                        cats          = $cats
                        service       = $svc
                        action        = [string]$action
                        actionType    = $actionType
                        tier          = $tier
                        docsOnly      = $DocsOnly
                        graphOnlyDiff = $graphOnlyDiff
                    }) | Out-Null
            }
        }

        $docsActionsByRole = @{}
        $docsRoleObjects = @{}
        if ($Embed.Contains($docsFile)) {
            foreach ($role in $Embed[$docsFile]) {
                $rid = [string](Get-JsonProp $role 'RoleId')
                if ([string]::IsNullOrEmpty($rid)) { continue }
                $acts = @{}
                $rp = Get-JsonProp $role 'RolePermissions'
                if ($null -ne $rp) {
                    if ($rp -isnot [System.Array]) { $rp = @($rp) }
                    foreach ($p in $rp) {
                        $a = [string](Get-JsonProp $p 'AuthorizedResourceAction')
                        if (-not [string]::IsNullOrEmpty($a)) { $acts[$a.ToLowerInvariant()] = $true }
                    }
                }
                $docsActionsByRole[$rid] = $acts
                $docsRoleObjects[$rid] = $role
            }
        }

        $graphActionsByRole = @{}
        foreach ($file in $sysByFile.Keys) {
            if (-not $Embed.Contains($file)) { continue }
            $sys = $sysByFile[$file]
            foreach ($role in $Embed[$file]) {
                $rid = [string](Get-JsonProp $role 'RoleId')
                $mismatchActions = $null
                if ($sys -eq 'EntraID' -and -not [string]::IsNullOrEmpty($rid)) {
                    $graphActs = @{}
                    $rp = Get-JsonProp $role 'RolePermissions'
                    if ($null -ne $rp) {
                        if ($rp -isnot [System.Array]) { $rp = @($rp) }
                        foreach ($p in $rp) {
                            $a = [string](Get-JsonProp $p 'AuthorizedResourceAction')
                            if (-not [string]::IsNullOrEmpty($a)) { $graphActs[$a.ToLowerInvariant()] = $true }
                        }
                    }
                    $graphActionsByRole[$rid] = $graphActs
                    if ($docsActionsByRole.ContainsKey($rid)) {
                        $docsActs = $docsActionsByRole[$rid]
                        $mismatchActions = @{}
                        foreach ($la in $graphActs.Keys) {
                            if (-not $docsActs.ContainsKey($la)) { $mismatchActions[$la] = $true }
                        }
                    }
                }
                Add-RolePaths -Role $role -Sys $sys -DocsOnly $false -MismatchActions $mismatchActions -List $paths
            }
        }

        foreach ($rid in $docsRoleObjects.Keys) {
            $role = $docsRoleObjects[$rid]
            $graphActs = if ($graphActionsByRole.ContainsKey($rid)) { $graphActionsByRole[$rid] } else { $null }
            $roleClass = 'Unclassified'
            $cls = Get-JsonProp $role 'Classification'
            if ($cls) { $cv = Get-JsonProp $cls 'EAMTierLevelName'; if ($cv -and ($validTiers -contains [string]$cv)) { $roleClass = [string]$cv } }
            $priv = ((Get-JsonProp $role 'isPrivileged') -eq $true)
            $cats = [string](Get-JsonProp $role 'Categories')
            $roleName = [string](Get-JsonProp $role 'RoleName')
            $perms = Get-JsonProp $role 'RolePermissions'
            if ($null -eq $perms) { continue }
            if ($perms -isnot [System.Array]) { $perms = @($perms) }
            foreach ($p in $perms) {
                $action = Get-JsonProp $p 'AuthorizedResourceAction'
                if ([string]::IsNullOrEmpty([string]$action)) { continue }
                if ($null -ne $graphActs -and $graphActs.ContainsKey([string]$action.ToLowerInvariant())) { continue }
                $tv = Get-JsonProp $p 'EAMTierLevelName'
                $tier = if ($tv -and ($validTiers -contains [string]$tv)) { [string]$tv } else { 'Unclassified' }
                $svc = [string](Get-JsonProp $p 'Category')
                if ([string]::IsNullOrEmpty($svc)) { $svc = '(uncategorized)' }
                $paths.Add([ordered]@{
                        sys           = 'EntraID'
                        roleId        = $rid
                        role          = $roleName
                        priv          = $priv
                        roleClass     = $roleClass
                        cats          = $cats
                        service       = $svc
                        action        = [string]$action
                        tier          = $tier
                        docsOnly      = $true
                        graphOnlyDiff = $false
                    }) | Out-Null
            }
        }

        return , $paths.ToArray()
    }

    function ConvertTo-TierMapRoles {
        param([System.Collections.IDictionary]$Embed)

        $sysByFile = [ordered]@{
            'Classification/Classification_EntraIdDirectoryRoles.json' = 'EntraID'
            'Classification/Classification_IdentityGovernance.json'    = 'IdentityGovernance'
            'Classification/Classification_AzureResources.json'        = 'Azure'
            'Classification/Classification_DeviceManagementRoles.json' = 'DeviceManagement'
        }
        # Use the function-level $ValidTiers (5 tiers incl. WorkloadPlane) - resolved from the
        # calling scope; do not shadow it with a local subset here.
        $roles = New-Object System.Collections.Generic.List[object]

        foreach ($file in $sysByFile.Keys) {
            if (-not $Embed.Contains($file)) { continue }
            foreach ($role in $Embed[$file]) {
                $roleId = [string](Get-JsonProp $role 'RoleId')
                if ([string]::IsNullOrEmpty($roleId)) { continue }
                $classification = Get-JsonProp $role 'Classification'
                $tierName = 'Unclassified'
                $service = ''
                if ($classification) {
                    $value = Get-JsonProp $classification 'EAMTierLevelName'
                    if ($value -and ($validTiers -contains [string]$value)) { $tierName = [string]$value }
                    $service = [string](Get-JsonProp $classification 'Service')
                }
                $roles.Add([ordered]@{
                        sys       = $sysByFile[$file]
                        roleId    = $roleId
                        role      = [string](Get-JsonProp $role 'RoleName')
                        roleClass = $tierName
                        service   = $service
                    }) | Out-Null
            }
        }

        return , $roles.ToArray()
    }

    # --- Mode-specific path resolution -------------------------------------------------------
    # Basenames of classification-logic definition/param templates are identical between the two
    # repositories, only the containing folder differs (kept in sync with EOCE.TEMPLATE_BASE in
    # js/config.js).
    $TemplateBase = if ($Mode -eq 'EntraOps') { 'Classification/Templates' } else { 'EntraOps_Classification' }

    if ($Mode -eq 'EntraOps') {
        # This function lives at <EntraOpsRoot>/EntraOps/Public/Reportings/Update-EntraOpsClassificationExplorerData.ps1
        # (synced verbatim from AzurePrivilegedIAM/Modules/EntraOps.Classification/Public by
        # Sync-EntraOpsClassificationExplorerSource) once
        # copied into the EntraOps repository, where it is dot-sourced and exported as a public function by
        # the module loader (EntraOps.psm1). Prefer the module's own ModuleBase (always populated once the
        # module is imported) over $PSScriptRoot, which can be empty depending on how this function was invoked.
        if ([string]::IsNullOrWhiteSpace($EntraOpsRoot)) {
            $ModuleRoot = $MyInvocation.MyCommand.Module.ModuleBase
            if ([string]::IsNullOrWhiteSpace($ModuleRoot) -and -not [string]::IsNullOrWhiteSpace($PSScriptRoot)) {
                $ModuleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
            }
            if ([string]::IsNullOrWhiteSpace($ModuleRoot)) {
                throw "Unable to resolve the EntraOps repository location. Pass -EntraOpsRoot explicitly."
            }
            $EntraOpsRoot = Split-Path -Parent $ModuleRoot
        }
        $EntraOpsRoot = Resolve-FullPath $EntraOpsRoot
        if ([string]::IsNullOrWhiteSpace($AppRoot)) { $AppRoot = Join-Path $EntraOpsRoot 'Reports/ClassificationExplorer' }

        if ([string]::IsNullOrWhiteSpace($RepoRoot)) {
            $SentinelFile = 'Classification/Classification_EntraIdDirectoryRoles.json'
            $Candidates = @((Split-Path -Parent $AppRoot), $EntraOpsRoot)
            $CodingRoot = Split-Path -Parent $EntraOpsRoot
            if ($CodingRoot -and (Test-Path -LiteralPath $CodingRoot -PathType Container)) {
                $Candidates += @(Get-ChildItem -LiteralPath $CodingRoot -Directory -Filter 'AzurePrivilegedIAM*' | ForEach-Object { $_.FullName })
            }
            $RepoRoot = $Candidates | Where-Object { Test-Path -LiteralPath (Join-Path $_ $SentinelFile) -PathType Leaf } | Select-Object -First 1
            if (-not $RepoRoot) {
                throw "Could not auto-detect the AzurePrivilegedIAM repository (looked for '$SentinelFile' in: $($Candidates -join ', ')). Pass -RepoRoot pointing at your AzurePrivilegedIAM clone."
            }
            Write-Verbose "Auto-detected RepoRoot: $RepoRoot"
        }
    } else {
        if ([string]::IsNullOrWhiteSpace($RepoRoot)) {
            $module = $MyInvocation.MyCommand.Module
            if (-not $module -or -not $module.ModuleBase) {
                throw 'Update-EntraOpsClassificationExplorerData must be invoked from an imported module or supplied -RepoRoot.'
            }
            $RepoRoot = Resolve-EntraOpsClassificationRepoRoot -ModuleBase $module.ModuleBase
        }
        if ([string]::IsNullOrWhiteSpace($AppRoot)) { $AppRoot = Join-Path (Resolve-FullPath $RepoRoot) 'ClassificationExplorer' }
    }

    $RepoRoot = Resolve-FullPath $RepoRoot
    $AppRoot = Resolve-FullPath $AppRoot

    Write-Verbose "Mode            : $Mode"
    Write-Verbose "Repository root : $RepoRoot"
    if ($Mode -eq 'EntraOps') { Write-Verbose "EntraOps root   : $EntraOpsRoot" }
    Write-Verbose "App folder      : $AppRoot"

    if (-not (Test-Path -LiteralPath $RepoRoot -PathType Container)) {
        throw "Repository root not found: $RepoRoot"
    }
    if ($Mode -eq 'EntraOps' -and -not (Test-Path -LiteralPath (Join-Path $EntraOpsRoot 'Classification/Templates') -PathType Container)) {
        throw "EntraOps classification templates not found: $(Join-Path $EntraOpsRoot 'Classification/Templates'). Pass -EntraOpsRoot pointing at the EntraOps repository root."
    }
    if (-not (Test-Path -LiteralPath $AppRoot -PathType Container)) {
        throw "App folder not found: $AppRoot$(if ($Mode -eq 'EntraOps') { '. Run Install-EntraOpsReportingFolder to download the Reports folder.' })"
    }
    if ((Resolve-FullPath $RepoRoot) -eq (Resolve-FullPath $AppRoot)) {
        throw "RepoRoot and AppRoot must differ (the app folder is the output target, not the source)."
    }

    # mode.js controls the app's interpretation of the embedded source paths. Refuse to
    # generate a bundle for a different deployment mode, which would otherwise hide
    # tenant features or select the wrong classification-template base at runtime.
    $modePath = Join-Path $AppRoot 'js/mode.js'
    if (-not (Test-Path -LiteralPath $modePath -PathType Leaf)) {
        throw "Deployment mode file not found: $modePath"
    }
    $modeText = Get-Content -LiteralPath $modePath -Raw -Encoding UTF8
    $modeMatch = [regex]::Match($modeText, "(?im)^\s*window\.EOCE_MODE\s*=\s*'(?<mode>standalone|entraops)'\s*;")
    if (-not $modeMatch.Success) {
        throw "Unable to read window.EOCE_MODE from $modePath. It must set 'standalone' or 'entraops'."
    }
    $appMode = $modeMatch.Groups['mode'].Value.ToLowerInvariant()
    $expectedAppMode = $Mode.ToLowerInvariant()
    if ($appMode -ne $expectedAppMode) {
        throw "Deployment mode mismatch: -Mode $Mode targets '$expectedAppMode', but $modePath declares '$appMode'. Update js/mode.js or use the matching -Mode."
    }

    $indexPath = Join-Path $AppRoot 'index.html'
    if (-not (Test-Path -LiteralPath $indexPath -PathType Leaf)) {
        throw "Classification Explorer index file not found: $indexPath"
    }
    $indexText = Get-Content -LiteralPath $indexPath -Raw -Encoding UTF8
    $themePath = if ($Mode -eq 'Standalone') { './theme/' } else { '../shared/' }
    $updatedIndexText = if ($Mode -eq 'Standalone') {
        $indexText.Replace('../shared/', $themePath)
    } else {
        $indexText.Replace('./theme/', $themePath)
    }
    if ($updatedIndexText -ne $indexText -and $PSCmdlet.ShouldProcess($indexPath, "Update $Mode theme asset paths")) {
        Set-Content -LiteralPath $indexPath -Value $updatedIndexText -Encoding UTF8
    }

    # --- Required / optional source files (relative paths, kept in sync with js/config.js) ----
    $RequiredFiles = @(
        # RBAC system outputs (classified roles + role actions) - always from -RepoRoot
        'Classification/Classification_EntraIdDirectoryRoles.json',
        'Classification/Classification_EntraIdDirectoryRolesFromMsftDocs.json',
        'Classification/Classification_IdentityGovernance.json',
        'Classification/Classification_AzureResources.json',
        'Classification/Classification_DeviceManagementRoles.json',
        # Permission catalogs - always from -RepoRoot
        'Classification/Classification_ApiPermissions.json',
        'Classification/Classification_AppRoles.json',
        'Classification/Classification_Scopes.json',
        # Classification-logic definitions and scope-aware parameter files - from $TemplateBase
        # (EntraOps_Classification/ in Standalone mode, Classification/Templates/ in EntraOps mode,
        # the latter from -EntraOpsRoot)
        "$TemplateBase/Classification_AadResources.json",
        "$TemplateBase/Classification_AadResources.Param.json",
        "$TemplateBase/Classification_IdentityGovernance.json",
        "$TemplateBase/Classification_IdentityGovernance.Param.json",
        "$TemplateBase/Classification_Azure.json",
        "$TemplateBase/Classification_Azure.Param.json",
        "$TemplateBase/Classification_DeviceManagement.json",
        "$TemplateBase/Classification_DeviceManagement.Param.json",
        "$TemplateBase/Classification_Defender.json",
        "$TemplateBase/Classification_Defender.Param.json"
    )

    # Optional in EntraOps mode only: embedded when present, otherwise embedded as an empty array
    # instead of failing generation (partial multi-source availability is expected there).
    # Required (must exist) in Standalone mode, matching this app's original single-source behavior.
    $OptionalFiles = @()
    if ($Mode -eq 'EntraOps') {
        $OptionalFiles = @(
            "$TemplateBase/Classification_RoleDefinitionOverwrites.json",
            # Built-in role action / API permission overwrites templates + API permission catalog:
            # consumed by the Customize Overwrites view (action/permission picker / load-template source).
            "$TemplateBase/Classification_RoleActionOverwrites.json",
            "$TemplateBase/Classification_ApiPermissionOverwrites.json",
            "$TemplateBase/Classification_ApiPermissions.json"
        )
    } else {
        $RequiredFiles += "$TemplateBase/Classification_RoleDefinitionOverwrites.json"
    }

    # --- Discover tenant-specific classification folders (EntraOps mode only) -----------------
    # Update-EntraOpsClassificationControlPlaneScope writes parameterized, tenant-specific copies
    # of the classification-logic files to Classification/<TenantName>/. Every such folder (any
    # subfolder of Classification other than Templates that contains classification or reasoning
    # JSON files) is embedded. Classification files remain separate from reasoning artifacts so
    # Template Comparison only receives files with a built-in template counterpart.
    $TenantFileSet = [System.Collections.Generic.HashSet[string]]::new()
    $TenantReasoningFileSet = [System.Collections.Generic.HashSet[string]]::new()
    $Tenants = @()
    if ($Mode -eq 'EntraOps') {
        $EntraOpsClassificationRoot = Join-Path $EntraOpsRoot 'Classification'
        foreach ($TenantDir in @(Get-ChildItem -LiteralPath $EntraOpsClassificationRoot -Directory | Where-Object { $_.Name -ne 'Templates' } | Sort-Object Name)) {
            $TenantJsonFiles = @(Get-ChildItem -LiteralPath $TenantDir.FullName -Filter 'Classification_*.json' -File | Sort-Object Name)
            $TenantReasoningFiles = @(Get-ChildItem -LiteralPath $TenantDir.FullName -File | Where-Object { $_.Name -like 'ScopeReasoning_*.json' -or $_.Name -eq 'DeviceManagement_ScopeGroupDeviceMembers.json' } | Sort-Object Name)
            if ($TenantJsonFiles.Count -eq 0 -and $TenantReasoningFiles.Count -eq 0) { continue }
            $TenantRelPaths = @($TenantJsonFiles | ForEach-Object { "Classification/$($TenantDir.Name)/$($_.Name)" })
            $TenantReasoningRelPaths = @($TenantReasoningFiles | ForEach-Object { "Classification/$($TenantDir.Name)/$($_.Name)" })
            foreach ($TenantRelPath in $TenantRelPaths) { [void]$TenantFileSet.Add($TenantRelPath) }
            foreach ($TenantReasoningRelPath in $TenantReasoningRelPaths) { [void]$TenantReasoningFileSet.Add($TenantReasoningRelPath) }
            $Tenants += [pscustomobject]@{ name = $TenantDir.Name; files = @($TenantRelPaths); reasoningFiles = @($TenantReasoningRelPaths) }
            Write-Verbose ("Tenant variant  : {0} ({1} classification file(s), {2} reasoning file(s))" -f $TenantDir.Name, $TenantRelPaths.Count, $TenantReasoningRelPaths.Count)
        }
    }

    function Get-SourcePath {
        param([string]$Rel)
        if ($Mode -eq 'EntraOps' -and ($Rel -like "$TemplateBase/*" -or $TenantFileSet.Contains($Rel) -or $TenantReasoningFileSet.Contains($Rel))) {
            return Join-Path $EntraOpsRoot $Rel
        }
        return Join-Path $RepoRoot $Rel
    }

    # --- Pre-flight: check which required source files exist ---------------------------------
    $missing = @()
    foreach ($rel in $RequiredFiles) {
        $src = Get-SourcePath -Rel $rel
        if (-not (Test-Path -LiteralPath $src -PathType Leaf)) { $missing += $rel }
    }
    if ($Mode -eq 'EntraOps') {
        # A missing file usually means an RBAC system hasn't been classified/exported yet rather
        # than a broken environment, so this only warns and embeds an empty array (below) - unless
        # *none* of the required files are found, which reliably indicates a wrong -RepoRoot /
        # -EntraOpsRoot rather than a handful of not-yet-available files.
        if ($missing.Count -eq $RequiredFiles.Count) {
            throw "None of the required classification source files were found under RepoRoot '$RepoRoot' / EntraOpsRoot '$EntraOpsRoot'. Pass -RepoRoot pointing at your AzurePrivilegedIAM clone if the auto-detected path is wrong."
        }
        if ($missing.Count -gt 0) {
            Write-Warning ("Missing source file(s) under RepoRoot '$RepoRoot' / EntraOpsRoot '$EntraOpsRoot' - these will be embedded as empty data so generation can continue (affected views may show no data for the corresponding RBAC system):`n  - " + ($missing -join "`n  - "))
        }
    } elseif ($missing.Count -gt 0) {
        throw "Missing source file(s) under '$RepoRoot':`n  - " + ($missing -join "`n  - ")
    }

    $results = New-Object System.Collections.Generic.List[object]
    $errors = 0
    $embed = [ordered]@{}

    $AllSourceFiles = @($RequiredFiles) + @($TenantFileSet | Sort-Object) + @($TenantReasoningFileSet | Sort-Object)
    foreach ($rel in $AllSourceFiles) {
        $src = Get-SourcePath -Rel $rel
        $isParam = $rel -match '\.Param\.json$'

        if ($Mode -eq 'EntraOps' -and -not (Test-Path -LiteralPath $src -PathType Leaf)) {
            $embed[($rel -replace '\\', '/')] = @()
            continue
        }

        $itemCount = $null
        try {
            $raw = Get-Content -LiteralPath $src -Raw -Encoding UTF8
            $jsonText = if ($isParam) { ConvertTo-SanitizedJsonText $raw } else { $raw }
            # PowerShell's ConvertFrom-Json collapses a JSON '[]' to $null and a single-element
            # JSON array to a bare object (not an array). @() around the *entire* if/else
            # normalizes both back to a real array - every classification file here is a JSON
            # array and the app calls .forEach()/.map() on the embedded value.
            $parsedRaw = $jsonText | ConvertFrom-Json
            $parsed = @(if ($null -ne $parsedRaw) { $parsedRaw })
            if ($parsed -is [System.Array]) { $itemCount = $parsed.Count }
        } catch {
            Write-Error "Invalid JSON in '$rel': $($_.Exception.Message)"
            $errors++
            continue
        }

        $embed[($rel -replace '\\', '/')] = $parsed

        $bytes = (Get-Item -LiteralPath $src).Length
        $hash = Get-Sha256 -Path $src
        Write-Verbose ("Read {0} ({1:N0} bytes{2})" -f $rel, $bytes, $(if ($null -ne $itemCount) { ", $itemCount items" } else { '' }))

        $results.Add([pscustomobject]@{
                Path      = ($rel -replace '\\', '/')
                Bytes     = $bytes
                Items     = $itemCount
                IsParam   = [bool]$isParam
                Sha256    = $hash
                UpdatedAt = (Get-Date).ToUniversalTime().ToString('o')
            }) | Out-Null
    }

    # --- Optional source files (EntraOps mode): embed when present, embed an empty array otherwise
    foreach ($rel in $OptionalFiles) {
        $src = Get-SourcePath -Rel $rel
        $relKey = $rel -replace '\\', '/'
        if (-not (Test-Path -LiteralPath $src -PathType Leaf)) {
            Write-Verbose "Optional source file not found, embedding empty array: $rel"
            $embed[$relKey] = @()
            continue
        }

        $itemCount = $null
        try {
            $raw = Get-Content -LiteralPath $src -Raw -Encoding UTF8
            $parsedRaw = $raw | ConvertFrom-Json
            $parsed = @(if ($null -ne $parsedRaw) { $parsedRaw })
            if ($parsed -is [System.Array]) { $itemCount = $parsed.Count }
        } catch {
            Write-Error "Invalid JSON in '$rel': $($_.Exception.Message)"
            $errors++
            continue
        }

        $embed[$relKey] = $parsed
        $bytes = (Get-Item -LiteralPath $src).Length
        $hash = Get-Sha256 -Path $src
        Write-Verbose ("Read {0} ({1:N0} bytes{2})" -f $rel, $bytes, $(if ($null -ne $itemCount) { ", $itemCount items" } else { '' }))
        $results.Add([pscustomobject]@{
                Path      = $relKey
                Bytes     = $bytes
                Items     = $itemCount
                IsParam   = $false
                Sha256    = $hash
                UpdatedAt = (Get-Date).ToUniversalTime().ToString('o')
            }) | Out-Null
    }

    if ($errors -gt 0) {
        throw "$errors source file(s) failed JSON validation. No manifest written."
    }

    # --- Validate attack-path mappings against the embedded classification data ----------------
    # Attack-path markdown is intentionally descriptive, but Actions, Roles and Permissions are
    # machine-linked by the Explorer. Catalog structure is always strict; mapping resolution can
    # remain warning-only while contributors iterate, or fail a release run via -StrictAttackPaths.
    function Test-AttackPathCatalog {
        param([string]$Directory)

        if (-not (Test-Path -LiteralPath $Directory -PathType Container)) { return }

        $files = @(Get-ChildItem -LiteralPath $Directory -Filter '*.md' | Sort-Object Name)
        $ids = @{}
        foreach ($file in $files) {
            $idLine = Get-Content -LiteralPath $file.FullName -Encoding UTF8 | Where-Object { $_ -match '^id:\s*(.+)$' } | Select-Object -First 1
            if (-not $idLine) { throw "Attack-path frontmatter is missing an id: $($file.Name)" }
            $id = [regex]::Match($idLine, '^id:\s*(.+)$').Groups[1].Value.Trim()
            if ($ids.ContainsKey($id)) {
                throw "Duplicate attack-path id '$id' in '$($ids[$id])' and '$($file.Name)'."
            }
            $ids[$id] = $file.Name
            if ($file.BaseName -ne $id) {
                throw "Attack-path id '$id' must match its filename '$($file.BaseName)' in '$($file.Name)'."
            }
        }

        $indexPath = Join-Path $Directory 'index.json'
        if (-not (Test-Path -LiteralPath $indexPath -PathType Leaf)) {
            throw "Attack-path catalog index is missing: $indexPath"
        }
        $indexText = Get-Content -LiteralPath $indexPath -Raw -Encoding UTF8
        if ([string]::IsNullOrWhiteSpace($indexText) -or $indexText.TrimStart()[0] -ne '[') {
            throw "Attack-path catalog index must be a JSON array: $indexPath"
        }
        try {
            $order = @($indexText | ConvertFrom-Json -ErrorAction Stop)
        } catch {
            throw "Invalid attack-path catalog index '$indexPath': $($_.Exception.Message)"
        }

        $duplicateIndexIds = @($order | Group-Object | Where-Object Count -gt 1 | ForEach-Object Name)
        $unknownIndexIds = @($order | Where-Object { -not $ids.ContainsKey([string]$_) })
        $unlistedFileIds = @($ids.Keys | Where-Object { $order -notcontains $_ } | Sort-Object)
        if ($duplicateIndexIds.Count -gt 0) {
            throw "Duplicate attack-path index id(s): $($duplicateIndexIds -join ', ')"
        }
        if ($unknownIndexIds.Count -gt 0) {
            throw "Attack-path index id(s) without matching Markdown files: $($unknownIndexIds -join ', ')"
        }
        if ($unlistedFileIds.Count -gt 0) {
            throw "Attack-path Markdown file(s) missing from index.json: $($unlistedFileIds -join ', ')"
        }
    }

    function Test-AttackPathMappings {
        param([string]$Directory, [hashtable]$Data)

        if (-not (Test-Path -LiteralPath $Directory -PathType Container)) { return }

        $sourceFiles = [ordered]@{
            EntraID            = 'Classification/Classification_EntraIdDirectoryRoles.json'
            IdentityGovernance = 'Classification/Classification_IdentityGovernance.json'
            Azure              = 'Classification/Classification_AzureResources.json'
            DeviceManagement   = 'Classification/Classification_DeviceManagementRoles.json'
        }
        $roleNames = @{}
        $actions = @{}
        foreach ($system in $sourceFiles.Keys) {
            $items = @($Data[$sourceFiles[$system]])
            $roleNames[$system] = @($items | ForEach-Object { Get-JsonProp $_ 'RoleName' })
            $actions[$system] = @($items | ForEach-Object { Get-JsonProp $_ 'RolePermissions' } | ForEach-Object { Get-JsonProp $_ 'AuthorizedResourceAction' })
        }
        $permissions = @($Data['Classification/Classification_ApiPermissions.json'])
        $mappingErrors = New-Object System.Collections.Generic.List[string]

        foreach ($file in Get-ChildItem -LiteralPath $Directory -Filter '*.md') {
            $section = ''
            $lineNumber = 0
            foreach ($line in Get-Content -LiteralPath $file.FullName -Encoding UTF8) {
                $lineNumber++
                if ($line -match '^## (Actions|Roles|Permissions)$') { $section = $Matches[1]; continue }
                if ($line -match '^## ') { $section = ''; continue }
                if ([string]::IsNullOrEmpty($section) -or $line -notmatch '^[-*]\s+(.+)$') { continue }

                $parts = @($Matches[1].Split('|') | ForEach-Object { $_.Trim() })
                if ($section -eq 'Actions' -or $section -eq 'Roles') {
                    if ($parts.Count -ne 2 -or [string]::IsNullOrWhiteSpace($parts[0]) -or [string]::IsNullOrWhiteSpace($parts[1])) {
                        $mappingErrors.Add(("{0}:{1} [{2}] expected '<System> | <Value>': {3}" -f $file.Name, $lineNumber, $section, $Matches[1])) | Out-Null
                        continue
                    }
                    if (-not $sourceFiles.Contains($parts[0])) {
                        $mappingErrors.Add(("{0}:{1} [{2}] unknown system '{3}'" -f $file.Name, $lineNumber, $section, $parts[0])) | Out-Null
                        continue
                    }
                    $isKnown = if ($section -eq 'Actions') {
                        $knownActions = $actions[$parts[0]]
                        ($knownActions -contains $parts[1]) -or @($knownActions | Where-Object {
                                $_ -and $_.Contains('*') -and $parts[1] -like $_
                            }).Count -gt 0
                    } else {
                        $roleNames[$parts[0]] -contains $parts[1]
                    }
                    if (-not $isKnown) {
                        $mappingErrors.Add(("{0}:{1} [{2}] unresolved mapping: {3} | {4}" -f $file.Name, $lineNumber, $section, $parts[0], $parts[1])) | Out-Null
                    }
                    continue
                }
                if ($section -eq 'Permissions') {
                    if ($parts.Count -ne 3 -or @($parts | Where-Object { [string]::IsNullOrWhiteSpace($_) }).Count -gt 0) {
                        $mappingErrors.Add(("{0}:{1} [Permissions] expected '<ResourceApp> | <Permission> | <Type>': {2}" -f $file.Name, $lineNumber, $Matches[1])) | Out-Null
                        continue
                    }
                    $isKnown = @($permissions | Where-Object {
                            (Get-JsonProp $_ 'TargetAppDisplayName') -eq $parts[0] -and
                            (Get-JsonProp $_ 'PermissionValue') -eq $parts[1] -and
                            (Get-JsonProp $_ 'PermissionType') -eq $parts[2]
                        }).Count -gt 0
                    if (-not $isKnown) {
                        $mappingErrors.Add(("{0}:{1} [Permissions] unresolved mapping: {2} | {3} | {4}" -f $file.Name, $lineNumber, $parts[0], $parts[1], $parts[2])) | Out-Null
                    }
                }
            }
        }

        if ($mappingErrors.Count -gt 0) {
            if ($StrictAttackPaths) {
                throw "$($mappingErrors.Count) attack-path mapping error(s):`n  - $($mappingErrors -join "`n  - ")"
            }
            foreach ($mappingError in $mappingErrors) {
                Write-Warning "Attack-path mapping issue: $mappingError"
            }
        }
    }

    $attackPathDirectory = Join-Path $AppRoot 'content/attack-paths'
    Test-AttackPathCatalog -Directory $attackPathDirectory
    Test-AttackPathMappings -Directory $attackPathDirectory -Data $embed

    # --- Write the data manifest ---------------------------------------------------------------
    if (-not $SkipManifest) {
        $manifestPath = Join-Path $AppRoot 'data-manifest.json'
        $manifest = [ordered]@{
            generatedUtc = (Get-Date).ToUniversalTime().ToString('o')
            mode         = $Mode
            repoRoot     = Split-Path -Leaf $RepoRoot
            fileCount    = $results.Count
            files        = @($results | ForEach-Object {
                    [ordered]@{ path = $_.Path; bytes = $_.Bytes; items = $_.Items; param = $_.IsParam; sha256 = $_.Sha256 }
                })
        }
        if ($PSCmdlet.ShouldProcess($manifestPath, 'Write data-manifest.json')) {
            Save-EntraOpsReportDataFile -Content ($manifest | ConvertTo-Json -Depth 5) -LiteralPath $manifestPath
            Write-Verbose "Wrote manifest: $manifestPath"
        }
    }

    # --- Write the embedded JS bundle (lets the app run with no web server, file://) -----------
    $embedBytes = 0
    if (-not $SkipEmbed) {
        $embedDir = Join-Path $AppRoot 'data'
        $embedPath = Join-Path $embedDir 'classification-data.js'
        if (-not (Test-Path -LiteralPath $embedDir)) {
            if ($PSCmdlet.ShouldProcess($embedDir, 'Create directory')) {
                New-Item -ItemType Directory -Path $embedDir -Force | Out-Null
            }
        }

        # Escape angle brackets so a stray '</script>' in any value can never break out of the
        # surrounding <script> tag.
        $jsonData = ($embed | ConvertTo-Json -Depth 100 -Compress)

        $embedMeta = [ordered]@{
            generatedUtc = (Get-Date).ToUniversalTime().ToString('o')
            mode         = $Mode
            fileCount    = $results.Count
            files        = @($results | ForEach-Object { [ordered]@{ path = $_.Path; items = $_.Items; sha256 = $_.Sha256 } })
        }
        $metaJson = ($embedMeta | ConvertTo-Json -Depth 5 -Compress)

        # Tenant-specific classification variants (EntraOps mode only) - consumed by the app's
        # variant selector and the Template Comparison view. Always emitted (empty array in
        # Standalone mode) so js/config.js can read window.EOCE_TENANTS unconditionally.
        $tenantsJson = ConvertTo-Json -InputObject ([object[]]$Tenants) -Depth 5 -Compress
        if ([string]::IsNullOrEmpty($tenantsJson)) { $tenantsJson = '[]' }

        $header = "/* Classification Explorer ($Mode mode) - embedded classification data.`n" +
        "   Auto-generated by Update-EntraOpsClassificationExplorerData on $((Get-Date).ToUniversalTime().ToString('o')).`n" +
        "   Do not edit by hand - re-run the script to refresh. */"
        $content = "$header`nwindow.EOCE_DATA = $jsonData;`nwindow.EOCE_DATA_MANIFEST = $metaJson;`nwindow.EOCE_TENANTS = $tenantsJson;`n"

        if ($PSCmdlet.ShouldProcess($embedPath, 'Write classification-data.js')) {
            Save-EntraOpsReportDataFile -Content $content -LiteralPath $embedPath
            $embedBytes = (Get-Item -LiteralPath $embedPath).Length
            Write-Verbose ("Wrote embedded bundle: {0} ({1:N0} bytes)" -f $embedPath, $embedBytes)
        }
    }

    # --- Build the attack-path catalog from markdown (content/attack-paths/*.md) ---------------
    $attackBytes = 0
    $attackDir = Join-Path $AppRoot 'content/attack-paths'
    if (Test-Path -LiteralPath $attackDir -PathType Container) {
        $mdFiles = Get-ChildItem -LiteralPath $attackDir -Filter '*.md' | Sort-Object Name
        $indexPath = Join-Path $attackDir 'index.json'
        $order = @(Get-Content -LiteralPath $indexPath -Raw -Encoding UTF8 | ConvertFrom-Json)
        $mdFilesById = @{}
        foreach ($file in $mdFiles) { $mdFilesById[$file.BaseName] = $file }
        $mdFiles = @($order | ForEach-Object { $mdFilesById[[string]$_] })
        $mdTexts = @($mdFiles | ForEach-Object { Get-Content -LiteralPath $_.FullName -Raw -Encoding UTF8 })
        $attackJson = ($mdTexts | ConvertTo-Json -Depth 3 -Compress)
        if ($mdTexts.Count -eq 1) { $attackJson = "[$attackJson]" }
        $attackPath = Join-Path $AppRoot 'data/attack-paths.js'
        $attackHeader = "/* Classification Explorer ($Mode mode) - embedded attack-path catalog.`n" +
        "   Auto-generated by Update-EntraOpsClassificationExplorerData from content/attack-paths/*.md on $((Get-Date).ToUniversalTime().ToString('o')).`n" +
        "   Do not edit by hand - edit the markdown files and re-run the script. */"
        $attackContent = "$attackHeader`nwindow.EOCE_ATTACK_PATHS_MD = $attackJson;`n"
        if ($PSCmdlet.ShouldProcess($attackPath, 'Write data/attack-paths.js')) {
            Save-EntraOpsReportDataFile -Content $attackContent -LiteralPath $attackPath
            $attackBytes = (Get-Item -LiteralPath $attackPath).Length
            Write-Verbose ("Wrote attack-path catalog: {0} ({1} paths, {2:N0} bytes)" -f $attackPath, $mdTexts.Count, $attackBytes)
        }
    }

    # --- Build the Enterprise Access Model Map (Overview Sankey) dataset -----------------------
    $tierMapBytes = 0
    $tierMapCount = 0
    if (-not $SkipEmbed) {
        $tierMapRoles = ConvertTo-TierMapRoles -Embed $embed
        $tierMapPaths = ConvertTo-TierMapPaths -Embed $embed
        $tierMapCount = @($tierMapPaths).Count
        $tierMapObj = [ordered]@{
            generatedUtc = (Get-Date).ToUniversalTime().ToString('o')
            roleCount    = @($tierMapRoles).Count
            pathCount    = $tierMapCount
            roles        = @($tierMapRoles)
            paths        = @($tierMapPaths)
        }
        $tierMapJson = ($tierMapObj | ConvertTo-Json -Depth 10 -Compress)
        $tierMapPath = Join-Path $AppRoot 'data/tier-map.js'
        $tierMapHeader = "/* Classification Explorer ($Mode mode) - embedded Enterprise Access Model Map (Overview Sankey) dataset.`n" +
        "   Auto-generated by Update-EntraOpsClassificationExplorerData on $((Get-Date).ToUniversalTime().ToString('o')).`n" +
        "   Do not edit by hand - re-run the script to refresh. */"
        $tierMapContent = "$tierMapHeader`nwindow.EOCE_TIER_MAP = $tierMapJson;`n"
        if ($PSCmdlet.ShouldProcess($tierMapPath, 'Write data/tier-map.js')) {
            Save-EntraOpsReportDataFile -Content $tierMapContent -LiteralPath $tierMapPath
            $tierMapBytes = (Get-Item -LiteralPath $tierMapPath).Length
            Write-Verbose ("Wrote EAM Map dataset: {0} ({1} paths, {2:N0} bytes)" -f $tierMapPath, $tierMapCount, $tierMapBytes)
        }
    }

    # --- Build change history (git log) for notifications and the standalone History view ------
    $historyBytes = 0
    $historySummary = @()
    if (-not $SkipHistory) {
        $historyPath = Join-Path $AppRoot 'data/history-data.js'
        $previousHistory = $null
        if (Test-Path -LiteralPath $historyPath -PathType Leaf) {
            try {
                $previousHistoryText = Get-Content -LiteralPath $historyPath -Raw -Encoding UTF8
                $previousHistoryJson = $previousHistoryText -replace '(?s)^.*?window\.EOCE_HISTORY\s*=\s*', '' -replace ';\s*$', ''
                $previousHistory = $previousHistoryJson | ConvertFrom-Json -Depth 15 -ErrorAction Stop
            } catch {
                Write-Verbose "Existing Classification Explorer history could not be used as a notification baseline: $($_.Exception.Message)"
            }
        }

        $gitOk = $true
        try {
            $null = & git -C $RepoRoot rev-parse --is-inside-work-tree 2>$null
            if ($LASTEXITCODE -ne 0) { $gitOk = $false }
        } catch {
            $gitOk = $false
        }
        if (-not $gitOk) {
            Write-Warning "git is unavailable or '$RepoRoot' is not a git working tree - writing empty history data."
        }

        $historyResultSources = [ordered]@{}
        foreach ($key in $HistorySources.Keys) {
            $src = $HistorySources[$key]
            $commits = New-Object System.Collections.Generic.List[object]

            if ($gitOk) {
                $sep = [char]0x1f
                $format = "%H${sep}%ad${sep}%an${sep}%s"
                $logLines = & git -C $RepoRoot log --reverse --date=iso-strict "--format=$format" -- $src.file 2>$null
                if ($LASTEXITCODE -ne 0) { $logLines = @() }
                if ($null -eq $logLines) { $logLines = @() }
                if ($logLines -isnot [System.Array]) { $logLines = @($logLines) }

                $prevIndex = [ordered]@{}
                foreach ($line in $logLines) {
                    if ([string]::IsNullOrWhiteSpace($line)) { continue }
                    $parts = $line -split [string][char]0x1f, 4
                    if ($parts.Count -lt 4) { continue }
                    $sha = $parts[0]; $date = $parts[1]; $author = $parts[2]; $subject = $parts[3]

                    $content = $null
                    try { $content = & git -C $RepoRoot show "${sha}:$($src.file)" 2>$null } catch { $content = $null }
                    $parsedHist = $null
                    if ($content -and $LASTEXITCODE -eq 0) {
                        $text = ($content -join "`n")
                        try { $parsedHist = $text | ConvertFrom-Json } catch { $parsedHist = $null }
                    }
                    $currIndex = ConvertTo-HistoryIndex -Parsed $parsedHist -Kind $src.kind
                    $diff = Compare-HistoryIndex -Previous $prevIndex -Current $currIndex -Kind $src.kind

                    if ($diff.added.Count -gt 0 -or $diff.removed.Count -gt 0 -or $diff.changed.Count -gt 0) {
                        $commits.Add([ordered]@{
                                sha     = $sha.Substring(0, 10)
                                date    = $date
                                author  = $author
                                subject = $subject
                                added   = $diff.added
                                removed = $diff.removed
                                changed = $diff.changed
                            }) | Out-Null
                    }
                    $prevIndex = $currIndex
                }
            }

            $historyResultSources[$key] = [ordered]@{
                label       = $src.label
                kind        = $src.kind
                file        = $src.file
                commitCount = $commits.Count
                commits     = @($commits.ToArray())
            }
            $historySummary += [pscustomobject]@{ Source = $key; Commits = $commits.Count }
            Write-Verbose ("History {0}: {1} commit(s) with changes" -f $key, $commits.Count)
        }

        $previousHeads = @{}
        if ($null -ne $previousHistory -and $null -ne $previousHistory.sources) {
            foreach ($sourceProperty in @($previousHistory.sources.PSObject.Properties)) {
                $previousCommits = @($sourceProperty.Value.commits)
                if ($previousCommits.Count -gt 0 -and $previousCommits[-1].sha) {
                    $previousHeads[$sourceProperty.Name] = [string]$previousCommits[-1].sha
                }
            }
        }
        $currentHeads = @{}
        $notificationSourceKeys = New-Object System.Collections.Generic.List[string]
        $fallbackNotificationSourceKeys = @{}
        foreach ($sourceKey in $historyResultSources.Keys) {
            $currentCommits = @($historyResultSources[$sourceKey].commits)
            if ($currentCommits.Count -eq 0 -or -not $currentCommits[-1].sha) { continue }
            $currentHeads[$sourceKey] = [string]$currentCommits[-1].sha
            if ($previousHeads.ContainsKey($sourceKey) -and $previousHeads[$sourceKey] -ne $currentHeads[$sourceKey]) {
                $notificationSourceKeys.Add($sourceKey) | Out-Null
            }
        }
        if ($notificationSourceKeys.Count -eq 0) {
            # A generated bundle may be committed alongside its source change. In that case the
            # baseline already contains the current heads, so fall back to the newest recorded
            # classification change instead of emitting an empty notification panel.
            $newestCommitDate = $null
            foreach ($sourceKey in $historyResultSources.Keys) {
                $commits = @($historyResultSources[$sourceKey].commits)
                if ($commits.Count -eq 0) { continue }
                $date = [datetimeoffset]$commits[-1].date
                if ($null -eq $newestCommitDate -or $date -gt $newestCommitDate) {
                    $newestCommitDate = $date
                }
            }
            if ($newestCommitDate) {
                foreach ($sourceKey in $historyResultSources.Keys) {
                    $commits = @($historyResultSources[$sourceKey].commits)
                    if ($commits.Count -gt 0 -and ([datetimeoffset]$commits[-1].date) -eq $newestCommitDate) {
                        $notificationSourceKeys.Add($sourceKey) | Out-Null
                        $fallbackNotificationSourceKeys[$sourceKey] = $true
                    }
                }
            }
        }
        $notificationChangeSetId = (@($currentHeads.Keys | Sort-Object | ForEach-Object { "${_}:$($currentHeads[$_])" }) -join '|')
        if ([string]::IsNullOrWhiteSpace($notificationChangeSetId)) { $notificationChangeSetId = 'none' }

        $historyObj = [ordered]@{
            generatedUtc = (Get-Date).ToUniversalTime().ToString('o')
            sources      = $historyResultSources
            notification = [ordered]@{
                changeSetId = $notificationChangeSetId
                sourceKeys  = @($notificationSourceKeys)
            }
        }
        $historyJson = ($historyObj | ConvertTo-Json -Depth 12 -Compress)

        $historyHeader = "/* Classification Explorer ($Mode mode) - embedded classification change history (git log).`n" +
        "   Auto-generated by Update-EntraOpsClassificationExplorerData on $((Get-Date).ToUniversalTime().ToString('o')).`n" +
        "   Do not edit by hand - re-run the script to refresh. */"
        $historyContent = "$historyHeader`nwindow.EOCE_HISTORY = $historyJson;`n"
        if ($PSCmdlet.ShouldProcess($historyPath, 'Write data/history-data.js')) {
            Save-EntraOpsReportDataFile -Content $historyContent -LiteralPath $historyPath
            $historyBytes = (Get-Item -LiteralPath $historyPath).Length
            Write-Verbose ("Wrote change history: {0} ({1:N0} bytes)" -f $historyPath, $historyBytes)
        }

        $notificationSources = [ordered]@{}
        foreach ($sourceKey in $notificationSourceKeys) {
            $source = $historyResultSources[$sourceKey]
            $commits = @($source.commits)
            if ($commits.Count -eq 0) { continue }
            $notificationCommits = @($commits)
            if ($fallbackNotificationSourceKeys.ContainsKey($sourceKey)) {
                # The committed history already contains the current head. Preserve the newest
                # commit selected by the fallback instead of filtering everything after that head.
                $notificationCommits = @($commits[-1])
            } elseif ($previousHeads.ContainsKey($sourceKey)) {
                $previousIndex = -1
                for ($commitIndex = 0; $commitIndex -lt $commits.Count; $commitIndex++) {
                    if ($commits[$commitIndex].sha -eq $previousHeads[$sourceKey]) {
                        $previousIndex = $commitIndex
                        break
                    }
                }
                if ($previousIndex -ge 0) {
                    $notificationCommits = @($commits | Select-Object -Skip ($previousIndex + 1))
                }
            }
            if ($notificationCommits.Count -eq 0) { continue }
            $notificationSources[$sourceKey] = [ordered]@{
                label   = $source.label
                kind    = $source.kind
                commits = $notificationCommits
            }
        }
        $notificationObj = [ordered]@{
            sources      = $notificationSources
            notification = $historyObj.notification
        }
        $notificationJson = ($notificationObj | ConvertTo-Json -Depth 12 -Compress)
        $notificationPath = Join-Path $AppRoot 'data/notification-data.js'
        $notificationContent = "/* Classification Explorer ($Mode mode) - compact classification change notifications.`n" +
        "   Auto-generated by Update-EntraOpsClassificationExplorerData; do not edit by hand. */`n" +
        "window.EOCE_NOTIFICATION_DATA = $notificationJson;"
        if ($PSCmdlet.ShouldProcess($notificationPath, 'Write data/notification-data.js')) {
            Save-EntraOpsReportDataFile -Content $notificationContent -LiteralPath $notificationPath
            Write-Verbose ("Wrote notification summary: {0}" -f $notificationPath)
        }
    }

    # --- Summary ---------------------------------------------------------------------------
    $totalBytes = ($results | Measure-Object -Property Bytes -Sum).Sum
    Write-Host ("Classification Explorer ($Mode mode) - data refresh complete.") -ForegroundColor Green
    Write-Host ("  Source files  : {0}" -f $results.Count)
    Write-Host ("  Total size    : {0:N0} KB" -f ([math]::Round($totalBytes / 1KB)))
    Write-Host ("  Output folder : {0}" -f $AppRoot)
    if (-not $SkipManifest) {
        Write-Host ("  Manifest      : data-manifest.json")
    }
    if (-not $SkipEmbed) {
        Write-Host ("  Embedded data : data/classification-data.js ({0:N0} KB) - app runs with no web server" -f ([math]::Round($embedBytes / 1KB)))
    }
    if ($attackBytes -gt 0) {
        Write-Host ("  Attack paths  : data/attack-paths.js ({0:N0} KB) - from content/attack-paths/*.md" -f ([math]::Round($attackBytes / 1KB)))
    }
    if ($tierMapBytes -gt 0) {
        Write-Host ("  EAM Map       : data/tier-map.js ({0:N0} KB, {1} paths) - Overview Sankey" -f ([math]::Round($tierMapBytes / 1KB)), $tierMapCount)
    }
    if ($Mode -eq 'EntraOps') {
        Write-Host ("  Tenants       : {0} tenant-specific variant(s)" -f $Tenants.Count)
    }
    if (-not $SkipHistory) {
        Write-Host ("  History       : data/history-data.js ({0:N0} KB) - git log per source:" -f ([math]::Round($historyBytes / 1KB)))
        foreach ($s in $historySummary) { Write-Host ("    {0,-20} {1} commit(s)" -f $s.Source, $s.Commits) }
    }

    if ($PassThru) { $results }
}
