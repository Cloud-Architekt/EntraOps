function Import-EntraOpsClassificationOverwrites {
    <#
    .SYNOPSIS
        Loads classification overwrite definitions from the tenant-specific classification folder and Templates.
    .DESCRIPTION
        Shared helper that loads the separated overwrite files and returns normalized overwrite
        definitions for a specific RBAC system:

        - Classification_RoleActionOverwrites.json:     Down- or upgrade the tier level of individual
                                                        role definition actions (e.g.,
                                                        "microsoft.directory/bitlockerKeys/key/read" on scope "/*").
                                                        An optional ActionType ("Action" or "DataAction", defaults
                                                        to "Action") declares which plane the actions belong to for
                                                        RBAC systems that distinguish control/management plane
                                                        Actions from data plane DataActions (currently Azure).
                                                        This file is ONLY read from the tenant-specific folder
                                                        ($FolderClassification/$TenantNameContext) alongside the
                                                        other customized classification files. A file in the
                                                        Templates folder is intentionally ignored.
                                                        Role action overwrites are applied at classification file
                                                        generation time by Update-EntraOpsClassificationControlPlaneScope
                                                        (via Invoke-EntraOpsClassificationActionOverwrite) and are
                                                        baked into the tenant-specific Classification_*.json files.
                                                        The Get-EntraOpsPrivilegedEAM* cmdlets do not apply them at runtime.
        - Classification_RoleDefinitionOverwrites.json: Down- or upgrade the tier level of a role
                                definition, identified by RoleDefinitionId and/or
                                RoleDefinitionName (replaces previously hard-coded
                                handling such as ControlPlaneRolesWithoutRoleActions).
                                A named Service replaces or adds only that service;
                                an empty or "*" Service replaces all classifications.
                                                        A tenant-specific file in $FolderClassification/$TenantNameContext
                                                        is preferred; otherwise the file in
                                                        $FolderClassification/Templates is used as fallback.
        - Classification_ApiPermissionOverwrites.json:  Down- or upgrade the tier level of an individual API
                                                        permission (application or delegated), identified by
                                                        PermissionValue and, optionally, TargetAppId/PermissionType.
                                                        Schema is aligned with Classification_ApiPermissions.json
                                                        entries (PermissionValue/PermissionType/TargetAppId/Category)
                                                        instead of the RoleDefinitionActions/scope-pattern shape used
                                                        by Classification_RoleActionOverwrites.json. This file is ONLY
                                                        read from the tenant-specific folder (no Templates fallback),
                                                        same as Classification_RoleActionOverwrites.json. Only
                                                        applicable to RbacSystem "ResourceApps" and applied at
                                                        classification file generation time by
                                                        Update-EntraOpsClassificationControlPlaneScope (baked into the
                                                        tenant-specific Classification_ApiPermissions.json via
                                                        Invoke-EntraOpsClassificationActionOverwrite, reusing the same
                                                        nested-schema mechanism as the other RBAC systems).

        Each file can be split into tagged variants named <BaseName>_<Tag>.json (for example
        Classification_RoleDefinitionOverwrites_PAW.json), stored in the tenant-specific folder. They are
        loaded in addition to the base file, in file name order after it, and their entries are applied in
        that order. For role actions and API permissions, an entry of a later file therefore takes precedence
        over an entry of an earlier file for the same action or permission. For role definitions, two rules
        of Invoke-EntraOpsClassificationRoleOverwrite come first: entries matching the role by
        RoleDefinitionId take precedence over entries matching it only by RoleDefinitionName, and an entry
        for the whole role (empty or "*" Service) is applied after the service-specific entries and replaces
        them. File order only decides between entries of the same kind. Entries of different files for the
        same item are listed in the output so overlaps are visible, once per RBAC system and unchanged file
        set in a session (repeated loads list them in the verbose output).

        All files contain a JSON array of overwrite entries. For role definition overwrites, Service scopes
        the overwrite to that classification service; use an empty or "*" Service to replace the entire role.
        For other overwrite types, Service (Category for API permission overwrites) is used as the service
        of the overwritten entry.

        RbacSystem "ResourceApps" (API permissions) is no longer supported in
        Classification_RoleActionOverwrites.json - such entries are skipped with a warning. Use
        Classification_ApiPermissionOverwrites.json instead.

        Every overwrite entry must contain a Justification to document why the classification
        has been changed. Entries without a Justification are skipped with a warning.
    .PARAMETER RbacSystem
        RBAC system to filter overwrite entries for (e.g., "EntraID", "DeviceManagement", "Defender", "IdentityGovernance", "ResourceApps").
    .PARAMETER FolderClassification
        Base folder for classification files. Defaults to $DefaultFolderClassification.
    .OUTPUTS
        [PSCustomObject] with three array properties: RoleActionOverwrites, RoleDefinitionOverwrites and ApiPermissionOverwrites.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$RbacSystem,

        [Parameter(Mandatory = $false)]
        [string]$FolderClassification = $DefaultFolderClassification
    )

    $RoleActionOverwrites = [System.Collections.Generic.List[object]]::new()
    $RoleDefinitionOverwrites = [System.Collections.Generic.List[object]]::new()
    $ApiPermissionOverwrites = [System.Collections.Generic.List[object]]::new()

    # Translation between the PermissionType values used on Classification_ApiPermissionOverwrites.json entries
    # (matching Classification_ApiPermissions.json / AppRoleAssignment.RoleType semantics: "Application"/"Delegated")
    # and the ResourceScope values used internally by Invoke-EntraOpsClassificationActionOverwrite ("Application"/"Delegation").
    $PermissionTypeToResourceScope = @{
        'Application' = 'Application'
        'Delegated'   = 'Delegation'
    }

    # Mapping to derive tag value from tier level name if not explicitly defined
    $TierLevelTagValueMap = @{
        'ControlPlane'    = '0'
        'ManagementPlane' = '1'
        'WorkloadPlane'   = '1'   # Tier1 sub-plane (cf. Tier1-WorkloadPlane groups / ObjectAdminTierLevel "1" in PrivilegedEAM exports)
        'UserAccess'      = '2'
    }

    $OverwriteFileMap = [System.Collections.Generic.List[object]]::new()

    # Tenant-specific classification folder (only available after Connect-EntraOps has set $TenantNameContext)
    $TenantFolder = if (-not [string]::IsNullOrEmpty($TenantNameContext)) {
        Join-Path -Path $FolderClassification -ChildPath $TenantNameContext
    } else { $null }

    # Role action and API permission overwrites (ResourceApps only): ONLY read from the tenant-specific
    # folder, no Templates fallback. The base file and every tagged variant (<BaseName>_<Tag>.json) are
    # loaded in the order of Get-EntraOpsClassificationOverwriteFile.
    if ($null -ne $TenantFolder) {
        foreach ($TenantOnlyType in @(
                @{ Type = 'RoleAction'; BaseName = 'Classification_RoleActionOverwrites.json' },
                @{ Type = 'ApiPermission'; BaseName = 'Classification_ApiPermissionOverwrites.json' }
            )) {
            $TypeFiles = @(Get-EntraOpsClassificationOverwriteFile -Folder $TenantFolder -BaseName $TenantOnlyType.BaseName)
            if ($TypeFiles.Count -eq 0) {
                Write-Verbose "No tenant-specific $($TenantOnlyType.BaseName) (or tagged variant) found in $TenantFolder"
            }
            foreach ($TypeFile in $TypeFiles) {
                Write-Verbose "Using tenant-specific $($TenantOnlyType.Type) overwrites file: $($TypeFile.Path)"
                $OverwriteFileMap.Add([PSCustomObject]@{ Type = $TenantOnlyType.Type; Path = $TypeFile.Path })
            }
        }
    } else {
        Write-Verbose "No tenant context available, skipping tenant-specific role action and API permission overwrites"
    }

    # Role definition overwrites: the tenant-specific base file is preferred, the Templates base file is
    # the fallback. Tagged variants are only read from the tenant-specific folder and are loaded in
    # addition to whichever base file applies.
    $RoleDefinitionBaseName = 'Classification_RoleDefinitionOverwrites.json'
    $RoleDefinitionFilePath = $null
    if ($null -ne $TenantFolder) {
        $TenantRoleDefinitionFile = @(Get-EntraOpsClassificationOverwriteFile -Folder $TenantFolder -BaseName $RoleDefinitionBaseName | Where-Object { $null -eq $_.Tag })
        if ($TenantRoleDefinitionFile.Count -gt 0) {
            Write-Verbose "Using tenant-specific role definition overwrites file: $($TenantRoleDefinitionFile[0].Path)"
            $RoleDefinitionFilePath = $TenantRoleDefinitionFile[0].Path
        }
    }
    if ($null -eq $RoleDefinitionFilePath) {
        $TemplateRoleDefinitionFilePath = Join-Path -Path $FolderClassification -ChildPath "Templates/$RoleDefinitionBaseName"
        if (Test-Path -Path $TemplateRoleDefinitionFilePath) {
            Write-Verbose "Using template role definition overwrites file: $TemplateRoleDefinitionFilePath"
            $RoleDefinitionFilePath = $TemplateRoleDefinitionFilePath
        } else {
            Write-Verbose "No role definition overwrites file found in tenant-specific folder or Templates"
        }
    }
    if ($null -ne $RoleDefinitionFilePath) {
        $OverwriteFileMap.Add([PSCustomObject]@{ Type = 'RoleDefinition'; Path = $RoleDefinitionFilePath })
    }
    if ($null -ne $TenantFolder) {
        foreach ($TaggedFile in @(Get-EntraOpsClassificationOverwriteFile -Folder $TenantFolder -BaseName $RoleDefinitionBaseName -TaggedOnly)) {
            Write-Verbose "Using tenant-specific role definition overwrites file: $($TaggedFile.Path)"
            $OverwriteFileMap.Add([PSCustomObject]@{ Type = 'RoleDefinition'; Path = $TaggedFile.Path })
        }
    }

    if ($OverwriteFileMap.Count -eq 0) {
        return [PSCustomObject]@{
            RoleActionOverwrites     = @()
            RoleDefinitionOverwrites = @()
            ApiPermissionOverwrites  = @()
        }
    }

    foreach ($OverwriteFileEntry in $OverwriteFileMap) {
        if (-not (Test-Path -Path $OverwriteFileEntry.Path)) {
            Write-Verbose "Classification overwrite file not found: $($OverwriteFileEntry.Path)"
            continue
        }
        $OverwriteFile = Get-Item -Path $OverwriteFileEntry.Path
        try {
            $OverwriteJson = @(Get-Content -Path $OverwriteFile.FullName -Raw | ConvertFrom-Json -Depth 10)
        } catch {
            Write-Warning "Failed to parse classification overwrite file $($OverwriteFile.FullName): $_"
            continue
        }

        # Resolve tier level for an overwrite entry, returns $null if invalid
        $ResolveTierLevel = {
            param($Entry, $EntryDescription)

            if ([string]::IsNullOrEmpty($Entry.EAMTierLevelName)) {
                Write-Warning "Skipping classification overwrite ($EntryDescription) in $($OverwriteFile.Name): EAMTierLevelName is missing."
                return $null
            }

            $TagValue = $Entry.EAMTierLevelTagValue
            if ([string]::IsNullOrEmpty($TagValue)) {
                if ($TierLevelTagValueMap.ContainsKey($Entry.EAMTierLevelName)) {
                    $TagValue = $TierLevelTagValueMap[$Entry.EAMTierLevelName]
                } else {
                    Write-Warning "Skipping classification overwrite ($EntryDescription) in $($OverwriteFile.Name): Unknown EAMTierLevelName '$($Entry.EAMTierLevelName)' and no EAMTierLevelTagValue defined."
                    return $null
                }
            }
            return "$TagValue"
        }

        #region Role action overwrites
        $RoleActionEntries = if ($OverwriteFileEntry.Type -eq 'RoleAction') { @($OverwriteJson) } else { @() }
        foreach ($Entry in $RoleActionEntries) {
            if ($null -eq $Entry) { continue }
            if ("$($Entry.RbacSystem)" -ne $RbacSystem) { continue }

            # RbacSystem "ResourceApps" (API permissions) is no longer supported here - use
            # Classification_ApiPermissionOverwrites.json instead (schema aligned with Classification_ApiPermissions.json).
            if ($Entry.RbacSystem -eq 'ResourceApps') {
                Write-Warning "Skipping ResourceApps entry in $($OverwriteFile.Name): API permission overwrites are no longer supported in Classification_RoleActionOverwrites.json. Move it to Classification_ApiPermissionOverwrites.json."
                continue
            }

            $Actions = @($Entry.RoleDefinitionActions | Where-Object { -not [string]::IsNullOrEmpty($_) })
            if ($Actions.Count -eq 0) {
                Write-Warning "Skipping role action classification overwrite in $($OverwriteFile.Name): RoleDefinitionActions is missing or empty."
                continue
            }

            if ([string]::IsNullOrEmpty($Entry.Justification)) {
                Write-Warning "Skipping role action classification overwrite for '$($Actions -join ', ')' in $($OverwriteFile.Name): Justification is required to document the classification change."
                continue
            }

            $TagValue = & $ResolveTierLevel $Entry "role actions: $($Actions -join ', ')"
            if ($null -eq $TagValue) { continue }

            $Scopes = @($Entry.RoleAssignmentScopeName | Where-Object { -not [string]::IsNullOrEmpty($_) })
            if ($Scopes.Count -eq 0) { $Scopes = @("/*") }

            # Plane of the overwritten actions (Action = control/management plane, DataAction = data plane).
            # Defaults to "Action" when omitted, matching the same default used on TierLevelDefinition entries.
            $ActionType = if ("$($Entry.ActionType)" -eq 'DataAction') { 'DataAction' } else { 'Action' }

            $RoleActionOverwrites.Add([PSCustomObject]@{
                    'RbacSystem'              = $RbacSystem
                    'RoleDefinitionActions'   = $Actions
                    'ActionType'              = $ActionType
                    'RoleAssignmentScopeName' = $Scopes
                    'ResourceAppId'           = $null
                    'ResourceScope'           = $null
                    'EAMTierLevelName'        = $Entry.EAMTierLevelName
                    'EAMTierLevelTagValue'    = $TagValue
                    'Service'                 = $Entry.Service
                    'Justification'           = $Entry.Justification
                    'SourceFile'              = $OverwriteFile.Name
                }) | Out-Null
        }
        #endregion

        #region API permission overwrites (ResourceApps only)
        $ApiPermissionEntries = if ($OverwriteFileEntry.Type -eq 'ApiPermission') { @($OverwriteJson) } else { @() }
        foreach ($Entry in $ApiPermissionEntries) {
            if ($null -eq $Entry) { continue }
            if ("$RbacSystem" -ne 'ResourceApps') { continue }

            $PermissionValue = "$($Entry.PermissionValue)"
            if ([string]::IsNullOrEmpty($PermissionValue)) {
                Write-Warning "Skipping API permission classification overwrite in $($OverwriteFile.Name): PermissionValue is missing."
                continue
            }

            if ([string]::IsNullOrEmpty($Entry.Justification)) {
                Write-Warning "Skipping API permission classification overwrite for '$PermissionValue' in $($OverwriteFile.Name): Justification is required to document the classification change."
                continue
            }

            $TagValue = & $ResolveTierLevel $Entry "API permission: $PermissionValue"
            if ($null -eq $TagValue) { continue }

            $PermissionType = "$($Entry.PermissionType)"
            $ResourceScope = if (-not [string]::IsNullOrEmpty($PermissionType) -and $PermissionType -ne 'All' -and $PermissionTypeToResourceScope.ContainsKey($PermissionType)) {
                $PermissionTypeToResourceScope[$PermissionType]
            } elseif (-not [string]::IsNullOrEmpty($PermissionType) -and $PermissionType -ne 'All') {
                Write-Warning "API permission classification overwrite for '$PermissionValue' in $($OverwriteFile.Name): Unknown PermissionType '$PermissionType', expected 'Application', 'Delegated' or 'All'. Treating as 'All'."
                $null
            } else {
                $null
            }

            $ApiPermissionOverwrites.Add([PSCustomObject]@{
                    'RbacSystem'              = 'ResourceApps'
                    'RoleDefinitionActions'   = @($PermissionValue)
                    'RoleAssignmentScopeName' = @("/")
                    'ResourceAppId'           = if (-not [string]::IsNullOrEmpty($Entry.TargetAppId)) { "$($Entry.TargetAppId)" } else { $null }
                    'ResourceScope'           = $ResourceScope
                    'EAMTierLevelName'        = $Entry.EAMTierLevelName
                    'EAMTierLevelTagValue'    = $TagValue
                    'Service'                 = $Entry.Category
                    'Justification'           = $Entry.Justification
                    'SourceFile'              = $OverwriteFile.Name
                }) | Out-Null
        }
        #endregion

        #region Role definition overwrites
        $RoleDefinitionEntries = if ($OverwriteFileEntry.Type -eq 'RoleDefinition') { @($OverwriteJson) } else { @() }
        foreach ($Entry in $RoleDefinitionEntries) {
            if ($null -eq $Entry) { continue }
            if ("$($Entry.RbacSystem)" -ne $RbacSystem) { continue }

            if ([string]::IsNullOrEmpty($Entry.RoleDefinitionId) -and [string]::IsNullOrEmpty($Entry.RoleDefinitionName)) {
                Write-Warning "Skipping role definition classification overwrite in $($OverwriteFile.Name): RoleDefinitionId or RoleDefinitionName is required."
                continue
            }

            $RoleIdentifier = if (-not [string]::IsNullOrEmpty($Entry.RoleDefinitionName)) { $Entry.RoleDefinitionName } else { $Entry.RoleDefinitionId }
            if ([string]::IsNullOrEmpty($Entry.Justification)) {
                Write-Warning "Skipping role definition classification overwrite for '$RoleIdentifier' in $($OverwriteFile.Name): Justification is required to document the classification change."
                continue
            }

            $TagValue = & $ResolveTierLevel $Entry "role definition: $RoleIdentifier"
            if ($null -eq $TagValue) { continue }

            $Scopes = @($Entry.RoleAssignmentScopeName | Where-Object { -not [string]::IsNullOrEmpty($_) })

            $RoleDefinitionOverwrites.Add([PSCustomObject]@{
                    'RbacSystem'              = $RbacSystem
                    'RoleDefinitionId'        = $Entry.RoleDefinitionId
                    'RoleDefinitionName'      = $Entry.RoleDefinitionName
                    'RoleAssignmentScopeName' = if ($Scopes.Count -gt 0) { $Scopes } else { $null }
                    'EAMTierLevelName'        = $Entry.EAMTierLevelName
                    'EAMTierLevelTagValue'    = $TagValue
                    'Service'                 = $Entry.Service
                    'Justification'           = $Entry.Justification
                    'SourceFile'              = $OverwriteFile.Name
                }) | Out-Null
        }
        #endregion
    }

    # Make overlaps between files visible: tagged files usually overlap the base file on purpose, so this
    # is informational rather than a warning. A role definition entry with ID and name yields two keys with
    # the same label, so messages are deduplicated.
    $OverlapMessages = [System.Collections.Generic.List[string]]::new()
    $ReportOverlaps = {
        param($Overwrites, [string]$Kind, [scriptblock]$GetKeys, [string]$Rule)
        $FilesByKey = @{}
        $LabelByKey = @{}
        foreach ($Overwrite in $Overwrites) {
            foreach ($KeyInfo in @(& $GetKeys $Overwrite)) {
                if (-not $FilesByKey.ContainsKey($KeyInfo.Key)) {
                    $FilesByKey[$KeyInfo.Key] = [System.Collections.Generic.List[string]]::new()
                    $LabelByKey[$KeyInfo.Key] = $KeyInfo.Label
                }
                if (-not $FilesByKey[$KeyInfo.Key].Contains($Overwrite.SourceFile)) { $FilesByKey[$KeyInfo.Key].Add($Overwrite.SourceFile) }
            }
        }
        foreach ($Key in @($FilesByKey.Keys | Sort-Object)) {
            if ($FilesByKey[$Key].Count -lt 2) { continue }
            $Message = "Classification overwrite overlap ($RbacSystem): $Kind $($LabelByKey[$Key]) is defined in $($FilesByKey[$Key] -join ', '). $Rule"
            if (-not $OverlapMessages.Contains($Message)) { $OverlapMessages.Add($Message) }
        }
    }
    & $ReportOverlaps $RoleActionOverwrites 'role action' {
        param($o)
        foreach ($Action in $o.RoleDefinitionActions) {
            foreach ($Scope in $o.RoleAssignmentScopeName) {
                @{ Key = "$($o.ActionType)|$Action|$Scope".ToLowerInvariant(); Label = "'$Action' on '$Scope'" }
            }
        }
    } 'The entry of the last file is applied last and takes precedence.'
    & $ReportOverlaps $ApiPermissionOverwrites 'API permission' {
        param($o)
        @{ Key = "$($o.RoleDefinitionActions[0])|$($o.ResourceScope)|$($o.ResourceAppId)".ToLowerInvariant(); Label = "'$($o.RoleDefinitionActions[0])'" }
    } 'The entry of the last file is applied last and takes precedence.'
    & $ReportOverlaps $RoleDefinitionOverwrites 'role definition' {
        param($o)
        $Service = if ([string]::IsNullOrEmpty($o.Service) -or $o.Service -eq '*') { '*' } else { "$($o.Service)" }
        $Role = if (-not [string]::IsNullOrEmpty($o.RoleDefinitionName)) { $o.RoleDefinitionName } else { $o.RoleDefinitionId }
        foreach ($Identifier in @($o.RoleDefinitionId, $o.RoleDefinitionName) | Where-Object { -not [string]::IsNullOrEmpty($_) }) {
            @{ Key = "$Identifier|$Service".ToLowerInvariant(); Label = "'$Role' (service '$Service')" }
        }
    } 'An entry matching by RoleDefinitionId takes precedence over a name-only match and a whole-role entry (Service empty or "*") over service-specific entries; otherwise the entry of the last file takes precedence.'

    # A full run loads the overwrites of one RBAC system several times (classification file generation and
    # the EAM cmdlets), so the overlaps of an unchanged file set are printed once per session.
    if ($OverlapMessages.Count -gt 0) {
        if ($null -eq $script:EntraOpsReportedOverwriteOverlaps) {
            $script:EntraOpsReportedOverwriteOverlaps = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        }
        $FileSetSignature = @($OverwriteFileMap | ForEach-Object {
                $Item = Get-Item -LiteralPath $_.Path -ErrorAction SilentlyContinue
                if ($Item) { "$($Item.FullName)|$($Item.Length)|$($Item.LastWriteTimeUtc.Ticks)" }
            }) -join ';'
        $FirstReport = $script:EntraOpsReportedOverwriteOverlaps.Add("$RbacSystem|$FileSetSignature")
        foreach ($Message in $OverlapMessages) {
            if ($FirstReport) { Write-Host $Message -ForegroundColor DarkYellow } else { Write-Verbose $Message }
        }
    }

    if ($RoleActionOverwrites.Count -gt 0 -or $RoleDefinitionOverwrites.Count -gt 0 -or $ApiPermissionOverwrites.Count -gt 0) {
        Write-Verbose "Loaded $($RoleActionOverwrites.Count) role action, $($RoleDefinitionOverwrites.Count) role definition and $($ApiPermissionOverwrites.Count) API permission classification overwrite(s) for $RbacSystem from $(@($OverwriteFileMap.Path) -join ', ')"
    }

    return [PSCustomObject]@{
        RoleActionOverwrites     = @($RoleActionOverwrites)
        RoleDefinitionOverwrites = @($RoleDefinitionOverwrites)
        ApiPermissionOverwrites  = @($ApiPermissionOverwrites)
    }
}
