<#
.SYNOPSIS
    Generate (refresh) the embedded dataset for the EntraOps Privileged Assets static web app.

.DESCRIPTION
    Builds one inventory record per privileged object (users, groups, service principals and
    applications incl. all object sub types) from the Privileged EAM export and merges the object
    across all RBAC systems. The inventory focuses on object details that are not visible in the
    role-assignment centric views: owners, sponsors, owned objects and devices, identity parent,
    associated work account and PAW device, administrative units, restricted management and the
    object tier compared with the classification of its role assignments.

    Related object IDs are resolved against the export first. IDs outside the export are resolved
    to display name and object type through Microsoft Graph (directoryObjects/getByIds) when
    -ResolveRelatedObjectIds is enabled; unresolved IDs stay visible as raw IDs.

    The dataset also embeds the Custom Security Attribute field names (for the PowerShell script
    generator of the app) and the current Object Classification File entries (so the app can edit
    the file). Generates data/privileged-assets-data.js exposing `window.ENTRAOPS_PRIVILEGED_ASSETS_DATA`.

.PARAMETER RepoRoot
    Path to the EntraOps repository root that contains the PrivilegedEAM export folder and
    EntraOpsConfig.json. Defaults to the repository this module lives in.

.PARAMETER ImportPath
    Folder with the Privileged EAM export. Defaults to <RepoRoot>/PrivilegedEAM.

.PARAMETER AppRoot
    Path to the PrivilegedAssets app folder. Defaults to Reports/PrivilegedAssets.

.PARAMETER OutFile
    Output file. Defaults to <AppRoot>/data/privileged-assets-data.js.

.PARAMETER ConfigFilePath
    EntraOpsConfig.json used for the Custom Security Attribute and Object Classification File
    settings. Defaults to <RepoRoot>/EntraOpsConfig.json.

.PARAMETER ResolveRelatedObjectIds
    Resolve related object IDs outside the export through Microsoft Graph. Defaults to the
    PrivilegedAssets.ResolveRelatedObjectIds config setting, or $true.

.PARAMETER PassThru
    Emit the generated payload object to the pipeline.

.EXAMPLE
    New-EntraOpsPrivilegedAssetsData

    Regenerates the Privileged Assets dataset from the PrivilegedEAM folder of this repository.

.EXAMPLE
    New-EntraOpsPrivilegedAssetsData -ResolveRelatedObjectIds $false -WhatIf

    Shows what would be generated without Microsoft Graph lookups and without changing any files.
#>

function New-EntraOpsPrivilegedAssetsData {

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
        [System.String]$ConfigFilePath,

        [Parameter(Mandatory = $false)]
        [System.Boolean]$ResolveRelatedObjectIds = $true,

        [Parameter(Mandatory = $false)]
        [switch]$PassThru
    )

    $ModuleRoot = $MyInvocation.MyCommand.Module.ModuleBase
    if ([string]::IsNullOrWhiteSpace($ModuleRoot) -and -not [string]::IsNullOrWhiteSpace($PSScriptRoot)) {
        $ModuleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    }
    if ([string]::IsNullOrWhiteSpace($ModuleRoot)) {
        throw "Unable to resolve the EntraOps module location. Import the module with 'Import-Module <path-to-EntraOps> -Force' and try again."
    }
    $RepositoryRoot = if (-not [string]::IsNullOrWhiteSpace($Global:EntraOpsBaseFolder)) { $Global:EntraOpsBaseFolder } else { Split-Path -Parent $ModuleRoot }

    if ([string]::IsNullOrWhiteSpace($RepoRoot)) { $RepoRoot = $RepositoryRoot }
    if ([string]::IsNullOrWhiteSpace($AppRoot)) { $AppRoot = Join-Path $RepositoryRoot 'Reports/PrivilegedAssets' }
    if (-not (Test-Path -LiteralPath $AppRoot -PathType Container)) {
        throw "Privileged Assets app folder not found: $AppRoot. Import the EntraOps module from a repository checkout that contains Reports/PrivilegedAssets, or run Install-EntraOpsReportingFolder to download the Reports folder."
    }
    if ([string]::IsNullOrWhiteSpace($ImportPath)) { $ImportPath = Join-Path $RepoRoot 'PrivilegedEAM' }
    if ([string]::IsNullOrWhiteSpace($OutFile)) { $OutFile = Join-Path $AppRoot 'data/privileged-assets-data.js' }
    if ([string]::IsNullOrWhiteSpace($ConfigFilePath)) { $ConfigFilePath = Join-Path $RepoRoot 'EntraOpsConfig.json' }

    if (-not (Test-Path -LiteralPath $ImportPath)) {
        throw "Privileged EAM import path not found: $ImportPath. Run Save-EntraOpsPrivilegedEAMJson first or pass -ImportPath."
    }

    $Config = $null
    if (Test-Path -LiteralPath $ConfigFilePath -PathType Leaf) {
        try {
            $Config = Get-Content -LiteralPath $ConfigFilePath -Raw | ConvertFrom-Json
        } catch {
            Write-Warning "Failed to read ${ConfigFilePath}: $($_.Exception.Message). Default Custom Security Attribute names are used and the Object Classification File is not loaded."
        }
    }
    if (-not $PSBoundParameters.ContainsKey('ResolveRelatedObjectIds') -and $null -ne $Config.PrivilegedAssets -and $null -ne $Config.PrivilegedAssets.ResolveRelatedObjectIds) {
        $ResolveRelatedObjectIds = [bool]$Config.PrivilegedAssets.ResolveRelatedObjectIds
    }

    function Get-PropValue {
        param($Object, [string]$Name)
        if ($null -eq $Object) { return $null }
        $Property = $Object.PSObject.Properties[$Name]
        if ($null -ne $Property) { return $Property.Value }
        return $null
    }

    function ConvertTo-StringArray {
        param($Value)
        if ($null -eq $Value) { return @() }
        return @(@($Value) | Where-Object { $null -ne $_ -and "$_" -ne '' } | ForEach-Object { "$_" })
    }

    function Get-ConfigValue {
        param($Section, [string]$Name, [string]$Default)
        $Value = "$(Get-PropValue $Section $Name)"
        if ([string]::IsNullOrWhiteSpace($Value)) { return $Default }
        return $Value
    }

    $TierRank = @{ ControlPlane = 0; ManagementPlane = 1; WorkloadPlane = 2; UserAccess = 3; Unclassified = 4 }
    $GuidPattern = '^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$'
    $RelationshipProperties = [ordered]@{
        owners                = 'Owners'
        sponsors              = 'Sponsors'
        ownedObjects          = 'OwnedObjects'
        ownedDevices          = 'OwnedDevices'
        associatedWorkAccount = 'AssociatedWorkAccount'
        associatedPawDevice   = 'AssociatedPawDevice'
    }

    $Files = @(Get-ChildItem -Path $ImportPath -Directory -ErrorAction SilentlyContinue |
        ForEach-Object { Get-ChildItem -Path $_.FullName -Filter '*.json' -File } |
        Sort-Object FullName)
    if ($Files.Count -eq 0) {
        Write-Warning "No Privileged EAM JSON files found under $ImportPath (expected <RbacSystem>/<RbacSystem>.json). Generating an empty dataset."
    }

    $ObjectsById = [ordered]@{}
    foreach ($File in $Files) {
        $RoleSystem = Split-Path -Leaf (Split-Path -Parent $File.FullName)
        try {
            $Data = [System.IO.File]::ReadAllText($File.FullName) | ConvertFrom-Json
        } catch {
            throw "Failed to read or parse Privileged EAM export file '$($File.FullName)' (RBAC system '$RoleSystem'): $($_.Exception.Message)"
        }

        foreach ($Source in @($Data)) {
            if ($null -eq $Source) { continue }
            $ObjectId = "$(Get-PropValue $Source 'ObjectId')".ToLowerInvariant()
            if ($ObjectId -notmatch $GuidPattern) { continue }

            if (-not $ObjectsById.Contains($ObjectId)) {
                $TierName = "$(Get-PropValue $Source 'ObjectAdminTierLevelName')"
                if ([string]::IsNullOrWhiteSpace($TierName)) { $TierName = 'Unclassified' }
                $DisplayName = "$(Get-PropValue $Source 'ObjectDisplayName')"
                $ObjectsById[$ObjectId] = [ordered]@{
                    objectId                      = $ObjectId
                    objectType                    = "$(Get-PropValue $Source 'ObjectType')".ToLowerInvariant()
                    objectSubType                 = "$(Get-PropValue $Source 'ObjectSubType')"
                    displayName                   = $(if ($DisplayName) { $DisplayName } else { $ObjectId })
                    userPrincipalName             = "$(Get-PropValue $Source 'ObjectUserPrincipalName')"
                    objectTenantId                = "$(Get-PropValue $Source 'ObjectTenantId')"
                    tierLevel                     = "$(Get-PropValue $Source 'ObjectAdminTierLevel')"
                    tierName                      = $TierName
                    onPremSynchronized            = [bool](Get-PropValue $Source 'OnPremSynchronized')
                    restrictedManagementByRAG     = [bool](Get-PropValue $Source 'RestrictedManagementByRAG')
                    restrictedManagementByAadRole = [bool](Get-PropValue $Source 'RestrictedManagementByAadRole')
                    restrictedManagementByRMAU    = [bool](Get-PropValue $Source 'RestrictedManagementByRMAU')
                    identityParent                = "$(Get-PropValue $Source 'IdentityParent')"
                    administrativeUnits           = [System.Collections.Generic.List[object]]::new()
                    roleSystems                   = [System.Collections.Generic.List[string]]::new()
                    assignments                   = [System.Collections.Generic.List[object]]::new()
                }
                foreach ($Key in $RelationshipProperties.Keys) {
                    $ObjectsById[$ObjectId][$Key] = [System.Collections.Generic.List[string]]::new()
                }
            }
            $Object = $ObjectsById[$ObjectId]
            if (-not $Object.roleSystems.Contains($RoleSystem)) { $Object.roleSystems.Add($RoleSystem) }

            # RBAC systems can carry sparser records for the same object: OR flags and fill empty fields.
            foreach ($Flag in @('OnPremSynchronized', 'RestrictedManagementByRAG', 'RestrictedManagementByAadRole', 'RestrictedManagementByRMAU')) {
                $Key = $Flag.Substring(0, 1).ToLowerInvariant() + $Flag.Substring(1)
                $Object[$Key] = $Object[$Key] -or [bool](Get-PropValue $Source $Flag)
            }
            $FieldMap = [ordered]@{ objectSubType = 'ObjectSubType'; userPrincipalName = 'ObjectUserPrincipalName'; objectTenantId = 'ObjectTenantId'; identityParent = 'IdentityParent'; tierLevel = 'ObjectAdminTierLevel' }
            foreach ($Key in $FieldMap.Keys) {
                if ([string]::IsNullOrWhiteSpace($Object[$Key])) { $Object[$Key] = "$(Get-PropValue $Source $FieldMap[$Key])" }
            }
            if ($Object.displayName -eq $ObjectId -and "$(Get-PropValue $Source 'ObjectDisplayName')") { $Object.displayName = "$(Get-PropValue $Source 'ObjectDisplayName')" }
            $SourceTierName = "$(Get-PropValue $Source 'ObjectAdminTierLevelName')"
            if ($Object.tierName -eq 'Unclassified' -and $TierRank.ContainsKey($SourceTierName)) {
                $Object.tierName = $SourceTierName
                $Object.tierLevel = "$(Get-PropValue $Source 'ObjectAdminTierLevel')"
            }

            foreach ($Key in $RelationshipProperties.Keys) {
                foreach ($RelatedId in (ConvertTo-StringArray (Get-PropValue $Source $RelationshipProperties[$Key]))) {
                    $NormalizedId = $RelatedId.ToLowerInvariant()
                    if (-not $Object[$Key].Contains($NormalizedId)) { $Object[$Key].Add($NormalizedId) }
                }
            }
            foreach ($AdministrativeUnit in @(Get-PropValue $Source 'AssignedAdministrativeUnits')) {
                $AdministrativeUnitId = "$(Get-PropValue $AdministrativeUnit 'id')".ToLowerInvariant()
                if (-not $AdministrativeUnitId -or @($Object.administrativeUnits | Where-Object { $_.id -eq $AdministrativeUnitId }).Count -gt 0) { continue }
                $Object.administrativeUnits.Add([ordered]@{ id = $AdministrativeUnitId; displayName = "$(Get-PropValue $AdministrativeUnit 'displayName')" })
            }

            foreach ($RoleAssignment in @(Get-PropValue $Source 'RoleAssignments')) {
                if ($null -eq $RoleAssignment) { continue }
                $ClassificationTiers = @(@(Get-PropValue $RoleAssignment 'Classification') | ForEach-Object { "$(Get-PropValue $_ 'AdminTierLevelName')" } | Where-Object { $TierRank.ContainsKey($_) })
                $AssignmentTier = @($ClassificationTiers | Sort-Object { $TierRank[$_] } | Select-Object -First 1)[0]
                if (-not $AssignmentTier) { $AssignmentTier = 'Unclassified' }
                $InstanceId = "$(Get-PropValue $RoleAssignment 'RoleAssignmentInstanceId')"
                if (-not $InstanceId) { $InstanceId = Get-EntraOpsRoleAssignmentInstanceId -RoleSystem $RoleSystem -RoleAssignment $RoleAssignment }
                $Object.assignments.Add([ordered]@{
                        id                    = $InstanceId
                        roleSystem            = $RoleSystem
                        roleDefinitionName    = "$(Get-PropValue $RoleAssignment 'RoleDefinitionName')"
                        roleDefinitionId      = "$(Get-PropValue $RoleAssignment 'RoleDefinitionId')"
                        scopeName             = "$(Get-PropValue $RoleAssignment 'RoleAssignmentScopeName')"
                        scopeId               = "$(Get-PropValue $RoleAssignment 'RoleAssignmentScopeId')"
                        assignmentType        = "$(Get-PropValue $RoleAssignment 'RoleAssignmentType')"
                        assignmentSubType     = "$(Get-PropValue $RoleAssignment 'RoleAssignmentSubType')"
                        pimAssignmentType     = "$(Get-PropValue $RoleAssignment 'PIMAssignmentType')"
                        transitiveBy          = "$(Get-PropValue $RoleAssignment 'TransitiveByObjectDisplayName')"
                        tierName              = $AssignmentTier
                        services              = @(@(Get-PropValue $RoleAssignment 'Classification') | ForEach-Object { "$(Get-PropValue $_ 'Service')" } | Where-Object { $_ } | Select-Object -Unique)
                    })
            }
        }
    }

    $TenantCounts = @{}
    foreach ($Object in $ObjectsById.Values) {
        if (-not $Object.objectTenantId -or ($Object.objectType -eq 'user' -and $Object.objectSubType -eq 'Guest')) { continue }
        $TenantCounts[$Object.objectTenantId] = [int]$TenantCounts[$Object.objectTenantId] + 1
    }
    $HomeTenantId = ($TenantCounts.GetEnumerator() | Sort-Object -Property Value -Descending | Select-Object -First 1).Key

    $ObjectsByAppId = @{}
    foreach ($Object in $ObjectsById.Values) {
        if ($Object.objectType -in @('serviceprincipal', 'application') -and $Object.userPrincipalName -match $GuidPattern) {
            $ObjectsByAppId[$Object.userPrincipalName.ToLowerInvariant()] = $Object.objectId
        }
    }

    $Objects = [System.Collections.Generic.List[object]]::new()
    $RelatedObjects = [ordered]@{}
    $UnresolvedIds = [System.Collections.Generic.HashSet[string]]::new()
    foreach ($Object in $ObjectsById.Values) {
        $Summary = [ordered]@{ total = $Object.assignments.Count; eligible = 0; active = 0; byTier = [ordered]@{}; bySystem = [ordered]@{}; highestTierName = 'Unclassified' }
        foreach ($TierName in @('ControlPlane', 'ManagementPlane', 'WorkloadPlane', 'UserAccess', 'Unclassified')) { $Summary.byTier[$TierName] = 0 }
        foreach ($Assignment in $Object.assignments) {
            $Summary.byTier[$Assignment.tierName]++
            $Summary.bySystem[$Assignment.roleSystem] = [int]$Summary.bySystem[$Assignment.roleSystem] + 1
            if ($Assignment.pimAssignmentType -eq 'Eligible') { $Summary.eligible++ } else { $Summary.active++ }
            if ($TierRank[$Assignment.tierName] -lt $TierRank[$Summary.highestTierName]) { $Summary.highestTierName = $Assignment.tierName }
        }
        $Object['assignmentSummary'] = $Summary
        $Object['isForeign'] = [bool]($HomeTenantId -and $Object.objectTenantId -and $Object.objectTenantId -ne $HomeTenantId)
        $Object['restrictedManagement'] = if ($Object.objectType -in @('serviceprincipal', 'application')) {
            'Not available'
        } elseif ($Object.objectType -eq 'group' -and $Object.objectSubType -eq 'Role-assignable' -and $Object.restrictedManagementByRMAU) {
            'Conflict'
        } elseif ($Object.restrictedManagementByAadRole -or $Object.restrictedManagementByRAG -or $Object.restrictedManagementByRMAU) {
            'Applied'
        } else {
            'Not applied'
        }

        $RelatedIds = @($RelationshipProperties.Keys | ForEach-Object { $Object[$_] })
        if ($Object.identityParent) {
            $ParentKey = $Object.identityParent.ToLowerInvariant()
            $Object.identityParent = $ParentKey
            if ($ObjectsByAppId.ContainsKey($ParentKey) -and -not $RelatedObjects.Contains($ParentKey)) {
                $ParentObject = $ObjectsById[$ObjectsByAppId[$ParentKey]]
                $RelatedObjects[$ParentKey] = [ordered]@{ objectId = $ParentObject.objectId; displayName = $ParentObject.displayName; objectType = $ParentObject.objectType; objectSubType = $ParentObject.objectSubType; tierName = $ParentObject.tierName; source = 'PrivilegedEAM' }
            } else {
                $RelatedIds += $ParentKey
            }
        }
        foreach ($RelatedId in $RelatedIds) {
            if ($RelatedObjects.Contains($RelatedId)) { continue }
            if ($ObjectsById.Contains($RelatedId)) {
                $RelatedObject = $ObjectsById[$RelatedId]
                $RelatedObjects[$RelatedId] = [ordered]@{ objectId = $RelatedId; displayName = $RelatedObject.displayName; objectType = $RelatedObject.objectType; objectSubType = $RelatedObject.objectSubType; tierName = $RelatedObject.tierName; source = 'PrivilegedEAM' }
            } elseif ($RelatedId -match $GuidPattern) {
                $UnresolvedIds.Add($RelatedId) | Out-Null
            }
        }
        $Objects.Add($Object)
    }

    if ($ResolveRelatedObjectIds -and $UnresolvedIds.Count -gt 0) {
        Write-Verbose "Resolving $($UnresolvedIds.Count) related object id(s) outside the Privileged EAM export via Microsoft Graph..."
        $IdsToResolve = @($UnresolvedIds | Sort-Object)
        $GraphBatchSize = 999 # directoryObjects/getByIds accepts up to 1000 IDs per request.
        for ($Index = 0; $Index -lt $IdsToResolve.Count; $Index += $GraphBatchSize) {
            $IdBatch = @($IdsToResolve[$Index..([Math]::Min($Index + $GraphBatchSize - 1, $IdsToResolve.Count - 1))])
            $Body = @{ ids = $IdBatch } | ConvertTo-Json
            try {
                foreach ($Resolved in @(Invoke-EntraOpsMsGraphQuery -Method POST -Uri '/v1.0/directoryObjects/getByIds' -Body $Body -OutputType PSObject)) {
                    $ResolvedId = "$(Get-PropValue $Resolved 'id')".ToLowerInvariant()
                    if (-not $ResolvedId) { continue }
                    $ResolvedType = "$(Get-PropValue $Resolved '@odata.type')" -replace '^#microsoft\.graph\.', ''
                    $RelatedObjects[$ResolvedId] = [ordered]@{
                        objectId          = $ResolvedId
                        displayName       = "$(Get-PropValue $Resolved 'displayName')"
                        objectType        = $ResolvedType.ToLowerInvariant()
                        userPrincipalName = "$(Get-PropValue $Resolved 'userPrincipalName')"
                        operatingSystem   = "$(Get-PropValue $Resolved 'operatingSystem')"
                        isCompliant       = Get-PropValue $Resolved 'isCompliant'
                        isManaged         = Get-PropValue $Resolved 'isManaged'
                        trustType         = "$(Get-PropValue $Resolved 'trustType')"
                        tierName          = ''
                        source            = 'Microsoft Graph'
                    }
                }
            } catch {
                Write-Warning "Failed to resolve $($IdBatch.Count) related object id(s) via Microsoft Graph: $($_.Exception.Message)"
            }
        }
    }

    $CsaConfig = Get-PropValue $Config 'CustomSecurityAttributes'
    $AlternateConfig = Get-PropValue $Config 'AlternateObjectTierLevelAttributes'
    $FileConfig = Get-PropValue $Config 'ObjectClassificationFile'
    $FilePath = Get-ConfigValue $FileConfig 'FilePath' './Classification/ObjectClassification.json'
    $FileEntries = @()
    $FileError = ''
    try {
        $FileEntries = @((Import-EntraOpsObjectClassificationFile -FilePath $FilePath -RootFolder $RepoRoot -WarningAction SilentlyContinue).Values | Sort-Object ObjectId | ForEach-Object {
                [ordered]@{
                    objectId           = $_.ObjectId
                    objectType         = $_.ObjectType
                    objectDisplayName  = $_.ObjectDisplayName
                    adminTierLevelName = $_.AdminTierLevelName
                    justification      = $_.Justification
                }
            })
    } catch {
        $FileError = $_.Exception.Message
        Write-Warning "Object Classification File could not be loaded for Privileged Assets: $FileError"
    }

    $SortedRelatedObjects = [ordered]@{}
    foreach ($Key in @($RelatedObjects.Keys | Sort-Object)) { $SortedRelatedObjects[$Key] = $RelatedObjects[$Key] }

    $RepoRootFull = (Resolve-Path -LiteralPath $RepoRoot).Path
    $Payload = [ordered]@{
        tenantName             = Get-EntraOpsReportingTenantName -RepoRoot $RepoRoot
        generatedAt            = (Get-Date).ToUniversalTime().ToString('o')
        generatedFrom          = @($Files | ForEach-Object {
                if ($_.FullName.StartsWith($RepoRootFull)) { $_.FullName.Substring($RepoRootFull.Length).TrimStart('\', '/') -replace '\\', '/' } else { $_.Name }
            })
        homeTenantId           = "$HomeTenantId"
        classificationSettings = [ordered]@{
            customSecurityAttributes          = [ordered]@{
                enabledFor                            = [ordered]@{
                    user             = Test-EntraOpsCustomSecurityAttributeClassificationEnabled -ObjectType User -Enabled (Get-PropValue $CsaConfig 'Enabled') -ObjectClassificationFile $FileConfig -AlternateObjectTierLevelAttributes $AlternateConfig
                    servicePrincipal = Test-EntraOpsCustomSecurityAttributeClassificationEnabled -ObjectType ServicePrincipal -Enabled (Get-PropValue $CsaConfig 'Enabled') -ObjectClassificationFile $FileConfig -AlternateObjectTierLevelAttributes $AlternateConfig
                    application      = Test-EntraOpsCustomSecurityAttributeClassificationEnabled -ObjectType Application -Enabled (Get-PropValue $CsaConfig 'Enabled') -ObjectClassificationFile $FileConfig -AlternateObjectTierLevelAttributes $AlternateConfig
                }
                userAttributeSet                      = Get-ConfigValue $CsaConfig 'PrivilegedUserAttribute' 'privilegedUser'
                userTierLevelAttribute                = Get-ConfigValue $CsaConfig 'PrivilegedUserAdminTierLevelAttribute' 'adminTierLevel'
                userTierNameAttribute                 = Get-ConfigValue $CsaConfig 'PrivilegedUserAdminTierLevelNameAttribute' 'adminTierLevelName'
                servicePrincipalAttributeSet          = Get-ConfigValue $CsaConfig 'PrivilegedServicePrincipalAttribute' 'privilegedWorkloadIdentity'
                servicePrincipalTierLevelAttribute    = Get-ConfigValue $CsaConfig 'PrivilegedServicePrincipalAdminTierLevelAttribute' 'adminTierLevel'
                servicePrincipalTierNameAttribute     = Get-ConfigValue $CsaConfig 'PrivilegedServicePrincipalAdminTierLevelNameAttribute' 'adminTierLevelName'
            }
            alternateObjectTierLevelAttributes = [ordered]@{
                user             = Test-EntraOpsAlternateObjectTierLevelEnabled -ObjectType User -AlternateObjectTierLevelAttributes $AlternateConfig
                servicePrincipal = Test-EntraOpsAlternateObjectTierLevelEnabled -ObjectType ServicePrincipal -AlternateObjectTierLevelAttributes $AlternateConfig
                group            = Test-EntraOpsAlternateObjectTierLevelEnabled -ObjectType Group -AlternateObjectTierLevelAttributes $AlternateConfig
            }
            objectClassificationFile          = [ordered]@{
                enabled  = [bool](Get-PropValue $FileConfig 'Enabled')
                filePath = $FilePath
                error    = $FileError
                entries  = @($FileEntries)
            }
        }
        objects                = @($Objects | Sort-Object { $_.displayName })
        relatedObjects         = $SortedRelatedObjects
    }

    $Json = $Payload | ConvertTo-Json -Depth 10 -Compress
    $Content = "// Auto-generated by New-EntraOpsPrivilegedAssetsData - do not edit by hand.`n" +
    "window.ENTRAOPS_PRIVILEGED_ASSETS_DATA = $Json;`n"

    if ($PSCmdlet.ShouldProcess($OutFile, 'Write Privileged Assets dataset')) {
        Save-EntraOpsReportDataFile -Content $Content -LiteralPath $OutFile
        Write-Host "Privileged objects: $($Objects.Count)"
        Write-Host "Related objects:    $($SortedRelatedObjects.Count) resolved, $([Math]::Max(0, $UnresolvedIds.Count - @($SortedRelatedObjects.Values | Where-Object { $_.source -eq 'Microsoft Graph' }).Count)) unresolved"
        Write-Host "Wrote $OutFile"
    }

    if ($PassThru) { $Payload }
}
