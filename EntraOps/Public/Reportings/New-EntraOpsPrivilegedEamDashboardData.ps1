<#
.SYNOPSIS
    Generate (refresh) the embedded dataset for the EntraOps EAM Dashboard static web app.

.DESCRIPTION
    Transforms EntraOps Privileged EAM data into the EAM Dashboard (Enterprise Access
    Model Dashboard) dataset. The dashboard is the static-web counterpart of the
    "EntraOps Privileged EAM - Overview" Azure workbook and reuses the same
    visualizations, filters and drill-downs.

    Generates data/eam-dashboard-data.js exposing `window.ENTRAOPS_EAM_DATA` so the
    static web app works both when served over HTTP (for example Azure Static Web
    Apps) and when opened directly from the file system (no fetch / CORS required).

    Source data is the Privileged EAM export written by Save-EntraOpsPrivilegedEAMJson:
    PrivilegedEAM/<RbacSystem>/<RbacSystem>.json (only JSON files directly in the RBAC
    system folder are read, not the per-object subfolders user/, group/,
    serviceprincipal/, ...).

    Computed columns follow the PrivilegedEAM parsers (Parsers/PrivilegedEAM_WatchLists)
    and the Overview workbook:

      * EligibilityBy      - "PIM for Entra ID Roles and Groups", "PIM for Entra ID Roles",
                             "PIM for Azure Roles", "PIM for Groups" or "N/A" derived
                             from RoleSystem, PIMAssignmentType and RoleAssignmentSubType.
      * RestrictedManagement - "Applied", "Conflict", "Not applied" or "Not available"
                             derived from ObjectType, ObjectSubType and the
                             RestrictedManagementByAadRole/RAG/RMAU flags (same case
                             logic as the workbook grid).
      * SyncSource         - "Cloud-Only" / "Hybrid" from OnPremSynchronized.
      * PrivilegedType     - "Tenant Governance" (foreign object whose role assignments
                             all originate from a Tenant Governance delegation),
                             "Multi-Tenant Apps" (service principal from another tenant),
                             "B2B Collaboration" (external user from another tenant with at
                             least one non-Tenant-Governance role assignment) or
                             "Local Identities" (everything else) derived from
                             ObjectTenantId, ObjectType and RoleAssignmentSubType.
    * scopeReasoning     - why an Azure, Entra ID, or Identity Governance assignment
                     scope was classified, sourced from the matching
                     ScopeReasoning_<RbacSystem>.json artifact written by
                     Update-EntraOpsClassificationControlPlaneScope.
    * controlPlaneReasoning - why an object entered the Control Plane input set, sourced
                     from Classification/<TenantName>/ScopeReasoning_ControlPlane.json.

    This function requires the module to be imported from a repository checkout that
    contains the Reports/EamDashboard folder.

.PARAMETER RepoRoot
    Path to the EntraOps repository root that contains the PrivilegedEAM export folder.
    Defaults to the repository this module lives in.

.PARAMETER ImportPath
    Folder with the Privileged EAM export. Defaults to <RepoRoot>/PrivilegedEAM.

.PARAMETER AppRoot
    Path to the EamDashboard app folder (where the generated content is written).
    Defaults to Reports/EamDashboard in the EntraOps repository.

.PARAMETER OutFile
    Output file. Defaults to <AppRoot>/data/eam-dashboard-data.js.

.PARAMETER TenantId
    Home tenant id used to detect foreign objects for the PrivilegedType column
    (Multi-Tenant Apps, B2B Collaboration, Tenant Governance). Defaults to the most
    common ObjectTenantId in the export among objects that are neither guest users
    nor Tenant Governance delegated admins.

.PARAMETER ResolveLinkedIdentityObjectIds
    Resolve linked-identity object IDs outside the Privileged EAM export to display
    names with batched Microsoft Graph getByIds requests. Defaults to the
    EamDashboard.ResolveLinkedIdentityObjectIds config setting, or $true.

.PARAMETER PassThru
    Emit the generated payload object to the pipeline.

.EXAMPLE
    New-EntraOpsPrivilegedEamDashboardData

    Regenerates the EAM Dashboard dataset from the PrivilegedEAM folder of this repository.

.EXAMPLE
    New-EntraOpsPrivilegedEamDashboardData -ImportPath "C:\Exports\PrivilegedEAM" -Verbose -WhatIf

    Shows what would be generated from an explicit Privileged EAM export without changing any files.
#>

function New-EntraOpsPrivilegedEamDashboardData {

    [CmdletBinding(SupportsShouldProcess = $true)]
    param (
        [Parameter(Mandatory = $false)]
        [System.String]$RepoRoot,

        [Parameter(Mandatory = $false)]
        [System.String]$ImportPath,

        [Parameter(Mandatory = $false)]
        [System.String]$AppRoot,

        [Parameter(Mandatory = $false)]
        [System.String]$OutFile,

        [Parameter(Mandatory = $false)]
        [System.String]$TenantId,

        [Parameter(Mandatory = $false)]
        [System.Boolean]$ResolveLinkedIdentityObjectIds = $true,

        [Parameter(Mandatory = $false)]
        [switch]$PassThru
    )

    # Resolve the app/repository location relative to the module location:
    # <repo>/EntraOps/Public/<subfolder> -> <repo>/Reports/EamDashboard
    # Prefer the module's own ModuleBase (always populated for exported module
    # functions) over $PSScriptRoot, which can be empty depending on how the
    # function was invoked/loaded.
    $ModuleRoot = $MyInvocation.MyCommand.Module.ModuleBase
    if ([string]::IsNullOrWhiteSpace($ModuleRoot) -and -not [string]::IsNullOrWhiteSpace($PSScriptRoot)) {
        $ModuleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    }
    if ([string]::IsNullOrWhiteSpace($ModuleRoot)) {
        throw "Unable to resolve the EntraOps module location. Import the module with 'Import-Module <path-to-EntraOps> -Force' and try again."
    }
    $RepositoryRoot = if (-not [string]::IsNullOrWhiteSpace($Global:EntraOpsBaseFolder)) { $Global:EntraOpsBaseFolder } else { Split-Path -Parent $ModuleRoot }

    if ([string]::IsNullOrWhiteSpace($RepoRoot)) { $RepoRoot = $RepositoryRoot }
    if ([string]::IsNullOrWhiteSpace($AppRoot)) { $AppRoot = Join-Path $RepositoryRoot 'Reports/EamDashboard' }
    if (-not (Test-Path -LiteralPath $AppRoot -PathType Container)) {
        throw "EAM Dashboard app folder not found: $AppRoot. Import the EntraOps module from a repository checkout that contains Reports/EamDashboard, or run Install-EntraOpsReportingFolder to download the Reports folder."
    }
    if ([string]::IsNullOrWhiteSpace($ImportPath)) { $ImportPath = Join-Path $RepoRoot 'PrivilegedEAM' }
    if ([string]::IsNullOrWhiteSpace($OutFile)) { $OutFile = Join-Path $AppRoot 'data/eam-dashboard-data.js' }

    if (-not (Test-Path -LiteralPath $ImportPath)) {
        throw "Privileged EAM import path not found: $ImportPath. Run Save-EntraOpsPrivilegedEAMJson first or pass -ImportPath."
    }

    if (-not $PSBoundParameters.ContainsKey('ResolveLinkedIdentityObjectIds')) {
        $EamDashboardConfigFilePath = Join-Path $RepoRoot 'EntraOpsConfig.json'
        if (Test-Path -LiteralPath $EamDashboardConfigFilePath -PathType Leaf) {
            try {
                $EamDashboardConfig = Get-Content -LiteralPath $EamDashboardConfigFilePath -Raw | ConvertFrom-Json
                if ($null -ne $EamDashboardConfig.EamDashboard -and $null -ne $EamDashboardConfig.EamDashboard.ResolveLinkedIdentityObjectIds) {
                    $ResolveLinkedIdentityObjectIds = [bool]$EamDashboardConfig.EamDashboard.ResolveLinkedIdentityObjectIds
                }
            } catch {
                Write-Warning "Failed to read EamDashboard settings from ${EamDashboardConfigFilePath}: $($_.Exception.Message). Defaulting -ResolveLinkedIdentityObjectIds to `$true."
            }
        }
    }

    $previousPayload = $null
    if (Test-Path -LiteralPath $OutFile -PathType Leaf) {
        try {
            $previousText = Get-Content -LiteralPath $OutFile -Raw -Encoding UTF8
            $previousJson = $previousText -replace '(?s)^.*?window\.ENTRAOPS_EAM_DATA\s*=\s*', '' -replace ';\s*$', ''
            $previousPayload = $previousJson | ConvertFrom-Json -Depth 15 -ErrorAction Stop
        } catch {
                Write-Warning "Existing EAM Dashboard dataset could not be used as a notification baseline; change notifications will not be generated for this run: $($_.Exception.Message)"
        }
    }

    $sourceFilesRef = [ref]@()
    $scopeReasoningDetails = Import-EntraOpsDashboardScopeReasoning -RepoRoot $RepoRoot
    $controlPlaneReasoningDetails = Import-EntraOpsControlPlaneReasoning -RepoRoot $RepoRoot
    $objects = Get-EntraOpsPrivilegedEamDashboardObjects -ImportPath $ImportPath -TenantId $TenantId -ScopeReasoningDetails $scopeReasoningDetails -ControlPlaneReasoningDetails $controlPlaneReasoningDetails -SourceFiles $sourceFilesRef
    $files = $sourceFilesRef.Value

    $roleDefinitions = [System.Collections.Generic.List[object]]::new()
    # The classified directory roles file lives in the AzurePrivilegedIAM repository, so it is
    # not found under the default -RepoRoot (the EntraOps repository). Probe the explicit
    # -RepoRoot first, then the temporary sparse AzurePrivilegedIAM checkout used by the
    # Push-EntraOpsPrivilegedReporting workflow (.reporting/AzurePrivilegedIAM).
    $directoryRoleClassificationCandidates = @(
        (Join-Path $RepoRoot 'Classification/Classification_EntraIdDirectoryRoles.json'),
        (Join-Path (Join-Path $RepoRoot '.reporting/AzurePrivilegedIAM') 'Classification/Classification_EntraIdDirectoryRoles.json')
    )
    $directoryRoleClassificationPath = @($directoryRoleClassificationCandidates | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } | Select-Object -First 1)[0]
    if ($directoryRoleClassificationPath) {
        try {
            foreach ($role in @([System.IO.File]::ReadAllText($directoryRoleClassificationPath) | ConvertFrom-Json)) {
                try {
                    $classifications = @($role.Classification | Where-Object { $_ -and $_.EAMTierLevelName } | Sort-Object { Get-EntraOpsTierSortOrder -TierValue $_.EAMTierLevelTagValue })
                    $effective = $classifications | Select-Object -First 1
                    if (-not $role.RoleId -or -not $effective) { continue }
                    $roleDefinitions.Add([ordered]@{
                            roleDefinitionId = "$($role.RoleId)"
                            displayName      = "$($role.RoleName)"
                            tierName        = "$($effective.EAMTierLevelName)"
                            service         = "$($effective.Category)"
                            classifications = @($classifications | ForEach-Object {
                                    [ordered]@{ tierName = "$($_.EAMTierLevelName)"; service = "$($_.Category)" }
                                })
                        }) | Out-Null
                } catch {
                    Write-Warning "Skipping directory role classification '$($role.RoleId)' ($($role.RoleName)): $($_.Exception.Message)"
                }
            }
        } catch {
            Write-Warning "Could not import directory role classifications from ${directoryRoleClassificationPath}: $($_.Exception.Message)"
        }
    } else {
        Write-Warning "Directory role classification file not found; PIM role tiers will use classified assignment evidence only. Paths tried: $($directoryRoleClassificationCandidates -join ', ')"
    }

    $linkedIdentityDisplayNames = @{}
    foreach ($object in @($objects)) {
        if ($object.objectId -and $object.objectDisplayName) {
            $linkedIdentityDisplayNames[$object.objectId] = $object.objectDisplayName
        }
    }
    if ($ResolveLinkedIdentityObjectIds) {
        $GuidPattern = '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
        $linkedIds = @($objects | ForEach-Object { @($_.associatedWorkAccount) } | Where-Object { $_ -and $_ -match $GuidPattern } | Sort-Object -Unique)
        $idsToResolve = @($linkedIds | Where-Object { -not $linkedIdentityDisplayNames.ContainsKey($_) })
        if ($idsToResolve.Count -gt 0) {
            Write-Verbose "Resolving $($idsToResolve.Count) linked identity object id(s) outside the Privileged EAM export via Microsoft Graph..."
            $GraphBatchSize = 999 # directoryObjects/getByIds accepts up to 1000 IDs per request.
            for ($index = 0; $index -lt $idsToResolve.Count; $index += $GraphBatchSize) {
                $idBatch = @($idsToResolve[$index..([Math]::Min($index + $GraphBatchSize - 1, $idsToResolve.Count - 1))])
                $body = @{ ids = $idBatch; types = @('user', 'group', 'servicePrincipal') } | ConvertTo-Json
                try {
                    foreach ($resolvedObject in @(Invoke-EntraOpsMsGraphQuery -Method POST -Uri '/v1.0/directoryObjects/getByIds' -Body $body -OutputType PSObject)) {
                        if ($resolvedObject.id -and $resolvedObject.displayName) {
                            $linkedIdentityDisplayNames["$($resolvedObject.id)"] = "$($resolvedObject.displayName)"
                        }
                    }
                } catch {
                    Write-Warning "Failed to resolve $($idBatch.Count) linked identity object id(s) via Microsoft Graph: $($_.Exception.Message)"
                }
            }
        }
    }

    if (-not $files) {
        Write-Warning "No Privileged EAM JSON files found under $ImportPath (expected <RbacSystem>/<RbacSystem>.json). Generating an empty dataset."
    }

    $repoRootFull = (Resolve-Path -LiteralPath $RepoRoot).Path
    $tenantName = Get-EntraOpsReportingTenantName -RepoRoot $RepoRoot
    $generatedAt = (Get-Date).ToUniversalTime().ToString('o')
    $notifications = [System.Collections.Generic.List[object]]::new()
    if ($null -ne $previousPayload -and $null -ne $previousPayload.objects) {
        $previousObjects = @{}
        $currentObjects = @{}
        $previousAssignments = @{}
        $currentAssignments = @{}

        function Get-AssignmentKey {
            param($Assignment)
            if ($Assignment.roleAssignmentInstanceId) { return "$($Assignment.roleAssignmentInstanceId)" }
            return "$($Assignment.roleAssignmentId)"
        }

        foreach ($object in @($previousPayload.objects)) {
            if ($object.objectId -and -not $previousObjects.ContainsKey($object.objectId)) { $previousObjects[$object.objectId] = $object }
            foreach ($assignment in @($object.roleAssignments)) {
                $assignmentKey = Get-AssignmentKey $assignment
                if ($assignmentKey -and -not $previousAssignments.ContainsKey($assignmentKey)) {
                    $previousAssignments[$assignmentKey] = $assignment
                }
            }
        }
        foreach ($object in @($objects)) {
            if ($object.objectId -and -not $currentObjects.ContainsKey($object.objectId)) { $currentObjects[$object.objectId] = $object }
            foreach ($assignment in @($object.roleAssignments)) {
                $assignmentKey = Get-AssignmentKey $assignment
                if ($assignmentKey -and -not $currentAssignments.ContainsKey($assignmentKey)) {
                    $currentAssignments[$assignmentKey] = $assignment
                }
            }
        }

        foreach ($objectId in @($currentObjects.Keys | Sort-Object)) {
            $current = $currentObjects[$objectId]
            if (-not $previousObjects.ContainsKey($objectId)) {
                $notifications.Add([ordered]@{
                        id = "asset-added:$objectId"; kind = 'Asset'; change = 'Added'; severity = 'info'
                        title = "Privileged asset added: $($current.objectDisplayName)"
                        detail = "$($current.objectType) is now classified as $($current.objectAdminTierLevelName)."
                        href = "#asset=$([uri]::EscapeDataString($objectId))"
                    }) | Out-Null
            } elseif ($previousObjects[$objectId].objectAdminTierLevelName -ne $current.objectAdminTierLevelName) {
                $notifications.Add([ordered]@{
                        id = "asset-tier:$objectId"; kind = 'Asset'; change = 'Changed'; severity = 'warning'
                        title = "Asset access level changed: $($current.objectDisplayName)"
                        detail = "$($previousObjects[$objectId].objectAdminTierLevelName) -> $($current.objectAdminTierLevelName)"
                        href = "#asset=$([uri]::EscapeDataString($objectId))"
                    }) | Out-Null
            }
        }
        foreach ($objectId in @($previousObjects.Keys | Where-Object { -not $currentObjects.ContainsKey($_) } | Sort-Object)) {
            $previous = $previousObjects[$objectId]
            $notifications.Add([ordered]@{
                    id = "asset-removed:$objectId"; kind = 'Asset'; change = 'Removed'; severity = 'info'
                    title = "Privileged asset removed: $($previous.objectDisplayName)"
                    detail = 'Open Privilege History to inspect the previous classified resource.'
                    href = '../PrivilegeHistory/index.html'
                }) | Out-Null
        }
        foreach ($assignmentId in @($currentAssignments.Keys | Where-Object { -not $previousAssignments.ContainsKey($_) } | Sort-Object)) {
            $assignment = $currentAssignments[$assignmentId]
            $notifications.Add([ordered]@{
                    id = "assignment-added:$assignmentId"; kind = 'Role assignment'; change = 'Added'; severity = 'info'
                    title = "Role assignment added: $($assignment.roleDefinitionName)"
                    detail = "Scope: $($assignment.roleAssignmentScopeName)"
                    href = "#assignment=$([uri]::EscapeDataString($assignmentId))"
                }) | Out-Null
        }
        foreach ($assignmentId in @($previousAssignments.Keys | Where-Object { -not $currentAssignments.ContainsKey($_) } | Sort-Object)) {
            $assignment = $previousAssignments[$assignmentId]
            $notifications.Add([ordered]@{
                    id = "assignment-removed:$assignmentId"; kind = 'Role assignment'; change = 'Removed'; severity = 'info'
                    title = "Role assignment removed: $($assignment.roleDefinitionName)"
                    detail = 'Open Privilege History to inspect the previous assignment.'
                    href = '../PrivilegeHistory/index.html'
                }) | Out-Null
        }
    }
    # Serialize the linked identity display names with sorted keys so repeated runs produce a
    # stable dataset (plain hashtable enumeration order is nondeterministic).
    $sortedLinkedIdentityDisplayNames = [ordered]@{}
    foreach ($linkedIdentityId in @($linkedIdentityDisplayNames.Keys | Sort-Object)) {
        $sortedLinkedIdentityDisplayNames[$linkedIdentityId] = $linkedIdentityDisplayNames[$linkedIdentityId]
    }

    $payload = [ordered]@{
        tenantName                 = $tenantName
        generatedAt                = $generatedAt
        changeSetId                = $generatedAt
        notifications              = @($notifications)
        generatedFrom              = @(@($files) | ForEach-Object {
                if ($_.FullName.StartsWith($repoRootFull)) {
                    $_.FullName.Substring($repoRootFull.Length).TrimStart('\', '/') -replace '\\', '/'
                } else {
                    $_.Name
                }
            })
        objects                    = $objects
        roleDefinitions            = @($roleDefinitions)
        linkedIdentityDisplayNames = $sortedLinkedIdentityDisplayNames
    }

    $json = $payload | ConvertTo-Json -Depth 12 -Compress
    $content = "// Auto-generated by New-EntraOpsPrivilegedEamDashboardData - do not edit by hand.`n" +
    "window.ENTRAOPS_EAM_DATA = $json;`n"

    if ($PSCmdlet.ShouldProcess($OutFile, 'Write EAM Dashboard dataset')) {
        Save-EntraOpsReportDataFile -Content $content -LiteralPath $OutFile

        $nAssignments = 0
        foreach ($obj in $objects) { $nAssignments += @($obj.roleAssignments).Count }
        Write-Host "Privileged objects: $($objects.Count)"
        Write-Host "Role assignments:   $nAssignments"
        Write-Host "Role definitions:   $($roleDefinitions.Count)"
        Write-Host "Wrote $OutFile"
    }

    if ($PassThru) { $payload }
}
