<#
.SYNOPSIS
    Update classification definition files for Microsoft Entra ID and/or Microsoft Intune (DeviceManagement) with fine-granular scope of Control Plane permissions based on privileged objects.

.DESCRIPTION
    Classification of Control Plane needs to consider the scope of sensitive permissions. For example, managing group membership of security groups should be managed as Control Plane by default.
    But this enforces to manage service-specific roles (e.g., Knowledge Administrator) as Control Plane. Protection of privileged objects by using Role-assignable groups (PRG), Entra ID Roles or Restricted Management Administrative Units (RMAU) allows to protect them by lower privileged roles with those permissions on directory-level.
    This function checks if privileged objects are protected by the previous mentoined methods and RMAUs with assigned privileged objects.
    A parameter file will be used to generate an updated classification definition file for Microsoft Entra ID and exclude directory roles without impact to privileged objects from Control Plane. All other assignments will be still managed as Control Plane.
    When DeviceManagement is included in ClassificationParameterScope, the function identifies privileged devices (owned by or associated with Control Plane and Management Plane users),
    resolves their transitive Entra ID group memberships, filters those groups to only include groups with Intune scope tag assignments, and replaces the group placeholders in the DeviceManagement classification parameter file.

.PARAMETER PrivilegedObjectClassificationSource
    Source of privileged objects to identify the scope of privileged objects and update the classification definition file for Microsoft Entra ID.
    Possible values are "All", "EntraOps", "PrivilegedObjectIds", "PrivilegedRolesFromAzGraph" and "PrivilegedEdgesFromExposureManagement".

.PARAMETER ClassificationParameterScope
    Array of RBAC systems whose classification files should be processed. Default is all supported RBAC systems.
    Possible values are "EntraID", "DeviceManagement", "Azure", "Defender", "IdentityGovernance" and "ResourceApps".
    EntraID, DeviceManagement, Azure and Defender are generated from their *.Param.json parameter files
    (placeholder substitution). EntraID resolves Administrative Unit (and directory-level fallback) scopes
    separately for privileged Users, Devices, Groups and Service Principals/Applications; WHY each resolved
    scope was added is persisted as ScopeReasoning_EntraID.json (ScopeCategory/ScopeId/ScopeName/Reason), same
    structure/intent as ScopeReasoning_DeviceManagement.json. Azure's <Tier0IncludedResourceScope>/<Tier1IncludedResourceScope> placeholders
    are resolved strictly by the hosted managed identity's own effective tier (ControlPlane-tier MI host ->
    Tier0, ManagementPlane-tier MI host -> Tier1). Defender supports only <Tier0IncludedResourceScope> and
    <Tier1IncludedResourceScope> placeholders, which are populated with the same Azure resource/subscription
    scope discovery, and only apply to RoleDefinitionActions that can genuinely be scoped in Defender Unified
    RBAC via Defender for Cloud (microsoft.xdr/securityposture/* actions). Defender for Identity (MDI) scope
    parameterization is not supported. IdentityGovernance is generated from
    Classification_IdentityGovernance.Param.json: every access package catalog and access package is classified
    by the most privileged resource assigned to it (groups by their EntraOps classification, directory roles by
    EntraID/default classification, API permissions from access package resource role scopes, Azure resources by
    the shared Tier0/Tier1 resource scope buckets). Scopes affirmatively classified as Tier1 (ManagementPlane) or
    Tier2 (UserAccess) are excluded from the ControlPlane wildcard via <Tier0ExcludedIdGovScope> and served by
    their own tier entries (<Tier1IncludedIdGovScope>/<Tier2IncludedIdGovScope>); everything else - including
    unclassifiable scopes and catalogs created between classification runs - stays Tier0 (conservative default).
    The per-scope reasoning is persisted as ScopeReasoning_IdentityGovernance.json (ScopeName/ScopeId/Source/
    EAMTier/ResultingScope/Reason). If the parameter file is missing, the previous template-only behavior applies
    (tenant-specific file only generated when role action overwrites exist). For
    ResourceApps, a tenant-specific classification file is only generated from the shipped template when API
    permission overwrites (Classification_ApiPermissionOverwrites.json) exist in the tenant-specific
    classification folder.
    Role action overwrites are considered and applied for EntraID, DeviceManagement, Defender, Azure and
    IdentityGovernance; API permission overwrites are considered and applied for ResourceApps; always AFTER any
    Tier0/Tier1 placeholder substitution for that RBAC system, and only for the generated tenant-specific
    classification files, never for the shipped templates.
    For Azure, an overwrite whose action already lives in a category whose scope is driven by the hosted
    managed identity's own tier (e.g. "Managed Identity", "Compute", "Storage") will remove that action from
    the dynamically-scoped entry and re-add it under the overwrite's own scope - a console warning is printed
    when this happens.
    Azure RBAC is always processed last to ensure managed identity EAM data from the other scopes is already available.

.PARAMETER EntraIdClassificationParameterFile
    Path to the classification parameter file for Microsoft Entra ID. Default is ./Classification/Templates/Classification_AadResources.Param.json.

.PARAMETER EntraIdCustomizedClassificationFile
    Path to the customized classification file for Microsoft Entra ID. Default is ./Classification/<TenantName>/Classification_AadResources.json.
    The file path will be recognized by the tenant name in the context of EntraOps and used for the classification.
    ScopeReasoning_EntraID.json is written alongside it in the same folder.

.PARAMETER DeviceMgmtClassificationParameterFile
    Path to the classification parameter file for Microsoft Intune (DeviceManagement). Default is ./Classification/Templates/Classification_DeviceManagement.Param.json.

.PARAMETER DeviceMgmtCustomizedClassificationFile
    Path to the customized classification file for Microsoft Intune (DeviceManagement). Default is ./Classification/<TenantName>/Classification_DeviceManagement.json.

.PARAMETER DefenderClassificationTemplateFile
    Path to the classification template for Microsoft Defender. Default is ./Classification/Templates/Classification_Defender.json.
    Not parameterized; used as-is with role action overwrites applied by Import-EntraOpsClassificationOverwrites.

.PARAMETER DefenderClassificationParameterFile
    Path to the classification parameter file for Microsoft Defender. Default is ./Classification/Templates/Classification_Defender.Param.json.
    The file must contain <Tier0IncludedResourceScope> and <Tier1IncludedResourceScope> placeholders.

.PARAMETER DefenderCustomizedClassificationFile
    Path to the customized classification file for Microsoft Defender. Default is ./Classification/<TenantName>/Classification_Defender.json.
    Generated from DefenderClassificationParameterFile with Tier0/Tier1 resource scope substituted.

.PARAMETER IdGovClassificationTemplateFile
    Path to the classification template for Identity Governance. Default is ./Classification/Templates/Classification_IdentityGovernance.json.
    Only used as fallback (together with role action overwrites) when IdGovClassificationParameterFile is missing.

.PARAMETER IdGovClassificationParameterFile
    Path to the classification parameter file for Identity Governance. Default is ./Classification/Templates/Classification_IdentityGovernance.Param.json.
    The file must contain the <Tier0ExcludedIdGovScope>, <Tier1IncludedIdGovScope> and <Tier2IncludedIdGovScope>
    placeholders, which are populated with the catalog/access package scope IDs classified by
    Get-EntraOpsIdGovScopeClassification.

.PARAMETER IdGovCustomizedClassificationFile
    Path to the customized classification file for Identity Governance. Default is ./Classification/<TenantName>/Classification_IdentityGovernance.json.
    Generated from IdGovClassificationParameterFile with per-catalog/access package tier scopes substituted
    (alongside ScopeReasoning_IdentityGovernance.json documenting WHY each scope got its tier).

.PARAMETER ResourceAppsClassificationTemplateFile
    Path to the classification template for Resource Apps (API permissions). Default is ./Classification/Templates/Classification_ApiPermissions.json.

.PARAMETER ResourceAppsCustomizedClassificationFile
    Path to the customized classification file for Resource Apps (API permissions). Default is ./Classification/<TenantName>/Classification_ApiPermissions.json.
    Only created when API permission overwrites (Classification_ApiPermissionOverwrites.json) exist.

.PARAMETER AzureClassificationParameterFile
    Path to the classification parameter file for Azure RBAC. Default is ./Classification/Templates/Classification_Azure.Param.json.
    The file must contain <Tier0IncludedResourceScope> and <Tier1IncludedResourceScope> placeholders.

.PARAMETER AzureCustomizedClassificationFile
    Path to the customized classification file for Azure RBAC. Default is ./Classification/<TenantName>/Classification_Azure.json.
    The file path will be recognised by the tenant name in the context of EntraOps.

.PARAMETER EntraOpsEamFolder
    Path to the folder where the EntraOps classification definition files are stored. Default is ./Classification.

.PARAMETER EntraOpsScopes
    Array of EntraOps scopes which should be considered for the analysis. Default selection are all available scopes: Azure, AzureBilling, EntraID, IdentityGovernance, DeviceManagement and ResourceApps.

.PARAMETER AzureHighPrivilegedRoles
    Array of high privileged roles in Azure RBAC which should be considered for the analysis. Default selection are high-privileged roles: Owner, Role Based Access Control Administrator and User Access Administrator.

.PARAMETER AzureHighPrivilegedScopes
    Scopes of high privileged Azure RBAC role assignments to consider for the Azure Resource Graph source.
    Each configured value is matched exactly against the assignment scope; child scopes are not included.
    Default selection is all scopes including management groups.

.PARAMETER ExposureCriticalityLevel
    Criticality level of assets in Exposure Management which should be considered for the analysis. Default selection is criticality level <1.

.PARAMETER PrivilegedObjectIds
    Manual list of privileged object IDs to identify the scope of privileged objects and update the classification definition file for Microsoft Entra ID.

.PARAMETER DeviceMgmtPrivilegedTierScope
    Controls which privileged tiers and object types are included when building Device Management (Intune) scope tag assignments.
    "ControlPlaneAndManagementPlane" (default): Tier0 (ControlPlane) and Tier1 (ManagementPlane) devices and users are both included.
    "ControlPlaneDevicesOnly": Only devices owned by Tier0 (ControlPlane) users are included; Tier1 and user group memberships are skipped.
    Tier0/Tier1 users are selected by their designated tier (ObjectAdminTierLevelName from Custom Security Attributes or
    AlternateObjectTierLevelAttributes), not by role-derived Control Plane membership. Owned or PAW devices of Control Plane
    users that are not selected for scope generation in the active mode are reported as IntuneDeviceScopeSelectionGap warnings.
    Selected devices still require groups with Intune scope tag assignments to be covered.

.PARAMETER IncludeObjectDetails
    Include object display names, UPNs, classification reasons, and related descriptive metadata in console
    output. Defaults to ConsoleOutput.IncludeObjectDetails from EntraOpsConfig.json. Object IDs are always shown,
    and persisted classification reasoning files retain the full audit data.

.EXAMPLE
    Get privileged objects from various Microsoft Entra RBACs and Microsoft Azure roles to identify the scope of privileged objects and update the classification definition file for Microsoft Entra ID.
    Update-EntraOpsClassificationControlPlaneScope -PrivilegedObjectClassificationSource "EntraOps" -EntraOpsScopes ("Azure","EntraID","IdentityGovernance","DeviceManagement","ResourceApps")

.EXAMPLE
    Get exposure graph edges from Microsoft Security Exposure Management with relation of "has permissions to", "can authenticate as", "has role on", "has credentials of" or "affecting" to assets with criticality level <1.
    This identitfies objects with direct/indirect permissions which leads in attack/access paths to high sensitive assets which can be identified as Control Plane.
    Update-EntraOpsClassificationControlPlaneScope -PrivilegedObjectClassificationSource "PrivilegedEdgesFromExposureManagement" -ExposureCriticalityLevel "<1"

.EXAMPLE
    Get permanent role assignments in Azure RBAC from Azure Resource Graph for high privileged roles (Owner, Role Based Access Control Administrator or User Access Administrator) on specific high-privileged scope ("/", "/providers/microsoft.management/managementgroups/8693dc7e-63c1-47ab-a7ee-acfe488bf52a").
    Update-EntraOpsClassificationControlPlaneScope -PrivilegedObjectClassificationSource "PrivilegedRolesFromAzGraph" -AzureHighPrivilegedRoles ("Owner", "Role Based Access Control Administrator", "User Access Administrator") -AzureHighPrivilegedScopes ("/", "/providers/microsoft.management/managementgroups/8693dc7e-63c1-47ab-a7ee-acfe488bf52a")

.EXAMPLE
    Use previous named data sources to identify high-privileged or sensitive objects from EntraOps, Azure RBAC and Exposure Management to update EntraOps classification definition file.
    Update-EntraOpsClassificationControlPlaneScope -PrivilegedObjectClassificationSource "All"

.EXAMPLE
    Get list of privileged object IDs to identify the scope of privileged objects and update the classification definition file for Microsoft Entra ID.
    $PrivilegedUser = Get-AzAdUser -filter "startswith(DisplayName,'adm')"
    $PrivilegedGroups = Get-AzAdGroup -filter "startswith(DisplayName,'prg')"
    $PrivilegedObjects = $PrivilegedUser + $PrivilegedGroups
    Update-EntraOpsClassificationControlPlaneScope -PrivilegedObjectClassificationSource "PrivilegedObjectIds" -PrivilegedObjectIds $PrivilegedObjects

.EXAMPLE
    Update classification for Entra ID, DeviceManagement (Intune), and Azure RBAC. Azure runs last and uses Exposure Management (criticalityLevel < 1) and EntraOps EAM managed identity data to parameterize Tier0/Tier1 resource scopes.
    Update-EntraOpsClassificationControlPlaneScope -PrivilegedObjectClassificationSource "EntraOps" -ClassificationParameterScope ("EntraID", "DeviceManagement", "Azure")

.EXAMPLE
    Update classification only for Azure RBAC scope parameterization.
    Update-EntraOpsClassificationControlPlaneScope -PrivilegedObjectClassificationSource "EntraOps" -ClassificationParameterScope ("Azure")

.EXAMPLE
    Update classification for both Entra ID and DeviceManagement (Intune) RBAC systems. The DeviceManagement logic resolves privileged devices to scope tags.
    Update-EntraOpsClassificationControlPlaneScope -PrivilegedObjectClassificationSource "EntraOps" -ClassificationParameterScope ("EntraID", "DeviceManagement")

.EXAMPLE
    Update classification only for DeviceManagement (Intune) RBAC based on EntraOps data.
    Update-EntraOpsClassificationControlPlaneScope -PrivilegedObjectClassificationSource "EntraOps" -ClassificationParameterScope ("DeviceManagement")

.EXAMPLE
    Update DeviceManagement classification using only Tier0 (ControlPlane) owned devices - Tier1 and user group memberships are excluded.
    Update-EntraOpsClassificationControlPlaneScope -PrivilegedObjectClassificationSource "EntraOps" -ClassificationParameterScope ("DeviceManagement") -DeviceMgmtPrivilegedTierScope "ControlPlaneDevicesOnly"

.EXAMPLE
    Update Azure RBAC classification and see WHY each Azure resource scope (e.g. the resource hosting a
    user-assigned managed identity that itself became Tier0/ControlPlane via an Entra ID role, API permission
    or other privileged role assignment) was included in Tier0. The per-resource reason is written to the
    console/log AND persisted alongside Classification_Azure.json as
    ScopeReasoning_Azure.json (Tier0Scope, Tier1Scope and
    ScopeDetails with ScopeName/ScopeId/Source/EAMTier/ResultingScope/Reason per resource scope - structure
    aligned with ScopeReasoning_IdentityGovernance.json) for
    later auditing - it is not part of the PrivilegedEAM export itself. Interactively (or in the corresponding
    Pull-EntraOpsPrivilegedEAM / Update-EntraOps.yaml job log) you can also look for the "Azure RBAC
    Classification Summary" section near the end of the console output. It lists every resource grouped by
    Source (SystemAssignedMI, UserAssignedMI, UAMIConsumer or ExposureManagement) together with its EAM tier
    and Reason, for example:
      [UserAssignedMI] (1 resource(s))
        uami-deployment-agent [EAM: ControlPlane]
          Reason    : User-assigned MI resource: uami-deployment-agent (3f2c1a9e-...)
          ResourceId: /subscriptions/<subId>/resourcegroups/<rg>/providers/microsoft.managedidentity/userassignedidentities/uami-deployment-agent
      [UAMIConsumer] (1 resource(s))
        vm-web01 [EAM: ControlPlane]
          Reason    : Uses UAMI: uami-deployment-agent / MI: uami-deployment-agent
          ResourceId: /subscriptions/<subId>/resourcegroups/<rg>/providers/microsoft.compute/virtualmachines/vm-web01
    Update-EntraOpsClassificationControlPlaneScope -PrivilegedObjectClassificationSource "EntraOps" -ClassificationParameterScope ("Azure") -Verbose

#>

function Update-EntraOpsClassificationControlPlaneScope {

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $False)]
        [ValidateSet("All", "EntraOps", "PrivilegedObjectIds", "PrivilegedRolesFromAzGraph", "PrivilegedEdgesFromExposureManagement")]
        [object]$PrivilegedObjectClassificationSource = "All"
        ,
        [Parameter(Mandatory = $false)]
        [ValidateSet("EntraID", "DeviceManagement", "Azure", "Defender", "IdentityGovernance", "ResourceApps")]
        [object]$ClassificationParameterScope = ("Azure", "EntraID", "DeviceManagement", "Defender", "IdentityGovernance", "ResourceApps")
        ,
        [Parameter(Mandatory = $false)]
        [System.String]$EntraIdClassificationParameterFile = "$DefaultFolderClassification/Templates/Classification_AadResources.Param.json"
        ,
        [Parameter(Mandatory = $false)]
        [System.String]$EntraIdCustomizedClassificationFile = "$DefaultFolderClassification/$($TenantNameContext)/Classification_AadResources.json"
        ,
        [Parameter(Mandatory = $false)]
        [System.String]$DeviceMgmtClassificationParameterFile = "$DefaultFolderClassification/Templates/Classification_DeviceManagement.Param.json"
        ,
        [Parameter(Mandatory = $false)]
        [System.String]$DeviceMgmtCustomizedClassificationFile = "$DefaultFolderClassification/$($TenantNameContext)/Classification_DeviceManagement.json"
        ,
        [Parameter(Mandatory = $false)]
        [System.String]$DefenderClassificationTemplateFile = "$DefaultFolderClassification/Templates/Classification_Defender.json"
        ,
        [Parameter(Mandatory = $false)]
        [System.String]$DefenderClassificationParameterFile = "$DefaultFolderClassification/Templates/Classification_Defender.Param.json"
        ,
        [Parameter(Mandatory = $false)]
        [System.String]$DefenderCustomizedClassificationFile = "$DefaultFolderClassification/$($TenantNameContext)/Classification_Defender.json"
        ,
        [Parameter(Mandatory = $false)]
        [System.String]$IdGovClassificationTemplateFile = "$DefaultFolderClassification/Templates/Classification_IdentityGovernance.json"
        ,
        [Parameter(Mandatory = $false)]
        [System.String]$IdGovClassificationParameterFile = "$DefaultFolderClassification/Templates/Classification_IdentityGovernance.Param.json"
        ,
        [Parameter(Mandatory = $false)]
        [System.String]$IdGovCustomizedClassificationFile = "$DefaultFolderClassification/$($TenantNameContext)/Classification_IdentityGovernance.json"
        ,
        [Parameter(Mandatory = $false)]
        [System.String]$ResourceAppsClassificationTemplateFile = "$DefaultFolderClassification/Templates/Classification_ApiPermissions.json"
        ,
        [Parameter(Mandatory = $false)]
        [System.String]$ResourceAppsCustomizedClassificationFile = "$DefaultFolderClassification/$($TenantNameContext)/Classification_ApiPermissions.json"
        ,
        [Parameter(Mandatory = $false)]
        [System.String]$AzureClassificationParameterFile = "$DefaultFolderClassification/Templates/Classification_Azure.Param.json"
        ,
        [Parameter(Mandatory = $false)]
        [System.String]$AzureCustomizedClassificationFile = "$DefaultFolderClassification/$($TenantNameContext)/Classification_Azure.json"
        ,
        [Parameter(Mandatory = $false)]
        [string]$EntraOpsEamFolder = "$DefaultFolderClassifiedEam"
        ,
        [Parameter(Mandatory = $false)]
        [ValidateSet("Azure", "AzureBilling", "EntraID", "IdentityGovernance", "DeviceManagement", "ResourceApps", "Defender")]
        [object]$EntraOpsScopes = ("Azure", "AzureBilling", "EntraID", "IdentityGovernance", "DeviceManagement", "ResourceApps", "Defender")
        ,
        [Parameter(Mandatory = $false)]
        [object]$AzureHighPrivilegedRoles = ("Owner", "Role Based Access Control Administrator", "User Access Administrator")
        ,
        [Parameter(Mandatory = $false)]
        [object]$AzureHighPrivilegedScopes = ("*")
        ,
        [Parameter(Mandatory = $false)]
        [string]$ExposureCriticalityLevel = "<1"
        ,
        [Parameter(Mandatory = $false)]
        [object]$PrivilegedObjectIds
        ,
        [Parameter(Mandatory = $false)]
        [ValidateSet("ControlPlaneAndManagementPlane", "ControlPlaneDevicesOnly")]
        [string]$DeviceMgmtPrivilegedTierScope = "ControlPlaneAndManagementPlane"
        ,
        [Parameter(Mandatory = $false)]
        [boolean]$IncludeObjectDetails = [bool]$Global:EntraOpsIncludeObjectDetails
    )

    $Parameters = @{
        PrivilegedObjectClassificationSource = $PrivilegedObjectClassificationSource
        EntraIdClassificationParameterFile   = $EntraIdClassificationParameterFile
        EntraIdCustomizedClassificationFile  = $EntraIdCustomizedClassificationFile
        EntraOpsEamFolder                    = $EntraOpsEamFolder
        EntraOpsScopes                       = $EntraOpsScopes 
        AzureHighPrivilegedRoles             = $AzureHighPrivilegedRoles
        AzureHighPrivilegedScopes            = $AzureHighPrivilegedScopes
        ExposureCriticalityLevel             = $ExposureCriticalityLevel
        PrivilegedObjectIds                  = $PrivilegedObjectIds
    }

    # Initialize tracking before any calls so captured warnings can be added immediately
    $ScopeSummary = [System.Collections.Generic.List[psobject]]::new()
    $WarningMessages = New-Object -TypeName "System.Collections.Generic.List[psobject]"

    # Cross-tenant discovery can change Graph context; this classification always belongs to the configured tenant.
    $HomeTenantId = $EntraOpsConfig.TenantId
    if ([string]::IsNullOrWhiteSpace($HomeTenantId)) {
        $HomeTenantId = Get-EntraOpsAzContextValue -Property TenantId
    }

    $PrivilegedObjects = Get-EntraOpsClassificationControlPlaneObjects @Parameters -WarningVariable CollectedObjectWarnings -WarningAction SilentlyContinue

    # Classify and collect warnings from object resolution phase into the summary
    foreach ($Warn in $CollectedObjectWarnings) {
        $WarnText = $Warn.Message
        if ($WarnText -match 'No privileged objects found for .+ in EntraOps') {
            $WarningMessages.Add([PSCustomObject]@{ Type = "MissingEamData"; Message = $WarnText })
        } elseif ($WarnText -match 'not found|non-retryable|NotFound') {
            $WarningMessages.Add([PSCustomObject]@{ Type = "ObjectNotFound"; Message = $WarnText })
        } else {
            $WarningMessages.Add([PSCustomObject]@{ Type = "CollectedWarning"; Message = $WarnText })
        }
    }

    #region Get classification file and filter for unique privileged objects
    $DirectoryLevelAssignmentScope = @("/")
    $PrivilegedObjects = $PrivilegedObjects | sort-object ObjectType, ObjectDisplayName | Select-Object -Unique *

    # Ensure an empty role action overwrites file exists alongside the other tenant-specific classification files.
    # This file is only evaluated from the tenant-specific folder (no Templates fallback).
    $RoleActionOverwritesFolder = Join-Path -Path $DefaultFolderClassification -ChildPath $TenantNameContext
    $RoleActionOverwritesFile = Join-Path -Path $RoleActionOverwritesFolder -ChildPath 'Classification_RoleActionOverwrites.json'
    if (-not (Test-Path -Path $RoleActionOverwritesFile)) {
        if (-not (Test-Path -Path $RoleActionOverwritesFolder)) {
            New-Item -Path $RoleActionOverwritesFolder -ItemType Directory -Force | Out-Null
        }
        '[]' | Out-File -FilePath $RoleActionOverwritesFile -Force
        Write-Host "Created empty role action overwrites file: $RoleActionOverwritesFile" -ForegroundColor Cyan
    }

    Write-Host ""
    Write-Host "=========================================================" -ForegroundColor Cyan
    Write-Host " EntraOps - Control Plane Scope Classification Update" -ForegroundColor Cyan
    Write-Host " Source : $PrivilegedObjectClassificationSource" -ForegroundColor Cyan
    Write-Host " RBAC Scope: $($ClassificationParameterScope -join ', ')" -ForegroundColor Cyan
    Write-Host " Objects identified: $(@($PrivilegedObjects).Count)" -ForegroundColor Cyan
    Write-Host "=========================================================" -ForegroundColor Cyan
    Write-Host ""

    # Summary table: unique objects with all contributing sources listed per object
    Write-Host " Identified privileged objects by source:" -ForegroundColor White
    Write-Host "---------------------------------------------------------" -ForegroundColor DarkCyan
    $PrivilegedObjects | Sort-Object ObjectType, ObjectDisplayName | Group-Object -Property ObjectType | Sort-Object Name | ForEach-Object {
        Write-Host "  [$($_.Name)] ($($_.Count) object(s))" -ForegroundColor DarkCyan
        if ($IncludeObjectDetails) {
            $_.Group | Sort-Object ObjectDisplayName | ForEach-Object {
                $Protection = @()
                if ($_.RestrictedManagementByRAG -eq $True) { $Protection += "RAG" }
                if ($_.RestrictedManagementByAadRole -eq $True) { $Protection += "AadRole" }
                if ($_.RestrictedManagementByRMAU -eq $True) { $Protection += "RMAU" }
                $ProtectionLabel = if ($Protection.Count -gt 0) { "[Protected: $($Protection -join ', ')]" } else { "[UNPROTECTED]" }
                $Color = if ($Protection.Count -gt 0) { "DarkGreen" } else { "Yellow" }
                $ObjSources = @($_.Classification.ClassificationSource | Select-Object -Unique | Sort-Object)
                $ObjSourceLabel = if ($ObjSources.Count -gt 0) { $ObjSources -join ', ' } else { $PrivilegedObjectClassificationSource }
                Write-Host "    $($_.ObjectDisplayName) ($($_.ObjectId)) | Source(s): $ObjSourceLabel | $ProtectionLabel" -ForegroundColor $Color
            }
        } else {
            $_.Group | Sort-Object ObjectId | ForEach-Object {
                Write-Host "    $($_.ObjectId)" -ForegroundColor DarkGray
            }
        }
    }
    if (-not $IncludeObjectDetails) {
        Write-Host "  Descriptive object details omitted. Set ConsoleOutput.IncludeObjectDetails to true to include them." -ForegroundColor DarkGray
    }
    Write-Host "---------------------------------------------------------" -ForegroundColor DarkCyan
    Write-Host ""
    #endregion

    #region Persist WHY each privileged object was identified/protected (ControlPlaneScopeReasoning.json)
    # This mirrors the "Identified privileged objects by source" console summary above so it is available for
    # later auditing instead of only being visible in the console/job log at generation time.
    $ControlPlaneScopeReasoningFolder = Join-Path -Path $DefaultFolderClassification -ChildPath $TenantNameContext
    if (-not (Test-Path -Path $ControlPlaneScopeReasoningFolder)) {
        New-Item -Path $ControlPlaneScopeReasoningFolder -ItemType Directory -Force | Out-Null
    }
    $ControlPlaneScopeReasoningFile = Join-Path -Path $ControlPlaneScopeReasoningFolder -ChildPath "ScopeReasoning_ControlPlane.json"
    $ControlPlaneScopeReasoningPayload = [PSCustomObject]@{
        PrivilegedObjectClassificationSource = $PrivilegedObjectClassificationSource
        ClassificationParameterScope         = $ClassificationParameterScope
        AzureResourceGraphCriteria           = [PSCustomObject]@{
            SourceEnabled        = [bool]($PrivilegedObjectClassificationSource -eq "All" -or $PrivilegedObjectClassificationSource -contains "PrivilegedRolesFromAzGraph")
            HighPrivilegedRoles  = @($AzureHighPrivilegedRoles)
            HighPrivilegedScopes = @($AzureHighPrivilegedScopes)
            ScopeMatch           = "Exact assignment scope; child scopes are not included unless listed explicitly."
            WildcardScopeMatch   = "All assignment scopes"
        }
        # ObjectId breaks ties for objects sharing the same ObjectType/ObjectDisplayName (duplicate display names are allowed in Entra ID).
        PrivilegedObjects                    = @($PrivilegedObjects | Sort-Object ObjectType, ObjectDisplayName, ObjectId | ForEach-Object {
                [PSCustomObject]@{
                    ObjectId                      = $_.ObjectId
                    ObjectDisplayName             = $_.ObjectDisplayName
                    ObjectType                    = $_.ObjectType
                    ObjectSubType                 = $_.ObjectSubType
                    ClassificationSource          = @($_.Classification.ClassificationSource | Select-Object -Unique | Sort-Object)
                    ClassificationReason          = $_.Classification.ClassificationReason
                    RestrictedManagementByRAG     = [bool]$_.RestrictedManagementByRAG
                    RestrictedManagementByAadRole = [bool]$_.RestrictedManagementByAadRole
                    RestrictedManagementByRMAU    = [bool]$_.RestrictedManagementByRMAU
                }
            })
    }
    $ControlPlaneScopeReasoningPayload | ConvertTo-Json -Depth 6 | Out-File -FilePath $ControlPlaneScopeReasoningFile -Force
    Write-Host "  Control Plane scope reasoning file: $ControlPlaneScopeReasoningFile" -ForegroundColor Cyan
    Write-Host ""
    #endregion

    #region EntraID RBAC Classification Parameter Scope
    if ($ClassificationParameterScope -contains "EntraID") {
        Write-Host ""
        Write-Host "=========================================================" -ForegroundColor Cyan
        Write-Host " Entra ID RBAC - Scope Parameter Update" -ForegroundColor Cyan
        Write-Host "=========================================================" -ForegroundColor Cyan
        $EntraIdRoleClassification = Get-Content -Path $EntraIdClassificationParameterFile -Raw

        # Persist WHY each resolved scope (Administrative Unit or directory-level fallback) was added, mirroring
        # ScopeReasoning_DeviceManagement.json/ScopeReasoning_Azure.json/ScopeReasoning_IdentityGovernance.json -
        # otherwise the only record of "why is this AU in scope" is transient console output at generation time.
        $EntraIdScopeReasoning = [System.Collections.Generic.List[psobject]]::new()

        # Build one reasoning entry per unique Administrative Unit id found on a set of privileged objects
        # (Users/Groups share the same AssignedAdministrativeUnits/ObjectDisplayName shape).
        function New-EntraIdAuScopeReasoning {
            param([string]$ScopeCategory, [psobject[]]$ObjectsWithAU)
            $Entries = [System.Collections.Generic.List[psobject]]::new()
            $UniqueAUs = @($ObjectsWithAU.AssignedAdministrativeUnits | Where-Object { $null -ne $_.id } | Select-Object -Unique id, displayName)
            foreach ($AU in $UniqueAUs) {
                $MatchedObjects = @($ObjectsWithAU | Where-Object { $_.AssignedAdministrativeUnits.id -contains $AU.id })
                $Names = @($MatchedObjects | Select-Object -First 3 -ExpandProperty ObjectDisplayName)
                $Reason = "Administrative Unit assigned to $($MatchedObjects.Count) Control Plane object(s): $($Names -join ', ')"
                if ($MatchedObjects.Count -gt 3) { $Reason += " (+$($MatchedObjects.Count - 3) more)" }
                $Entries.Add([PSCustomObject]@{
                        ScopeCategory   = $ScopeCategory
                        ScopeId         = "/administrativeUnits/$($AU.id)"
                        ScopeName       = $AU.displayName
                        Reason          = $Reason
                        AffectedObjects = @($MatchedObjects | Sort-Object ObjectDisplayName, ObjectId | ForEach-Object {
                                [PSCustomObject]@{
                                    id          = "$($_.ObjectId)"
                                    displayName = "$($_.ObjectDisplayName)"
                                }
                            })
                    }) | Out-Null
            }
            return $Entries
        }

        # Build the reasoning entry for the directory-level ("/") fallback scope, driven by a set of
        # objects lacking RAG/Entra ID role/RMAU protection.
        function New-EntraIdDirectoryScopeReasoning {
            param([string]$ScopeCategory, [psobject[]]$UnprotectedObjects, [string]$ProtectionGap)
            $Names = @($UnprotectedObjects | Select-Object -First 3 -ExpandProperty ObjectDisplayName)
            $Reason = "$($UnprotectedObjects.Count) Control Plane object(s) $ProtectionGap require directory-level scope: $($Names -join ', ')"
            if ($UnprotectedObjects.Count -gt 3) { $Reason += " (+$($UnprotectedObjects.Count - 3) more)" }
            return [PSCustomObject]@{
                ScopeCategory   = $ScopeCategory
                ScopeId         = $DirectoryLevelAssignmentScope
                ScopeName       = "Directory (root)"
                Reason          = $Reason
                AffectedObjects = @($UnprotectedObjects | Sort-Object ObjectDisplayName, ObjectId | ForEach-Object {
                        [PSCustomObject]@{
                            id          = "$($_.ObjectId)"
                            displayName = "$($_.ObjectDisplayName)"
                        }
                    })
            }
        }

        #region Privileged User
        Write-Host "---------------------------------------------------------" -ForegroundColor DarkCyan
        Write-Host " Privileged Users" -ForegroundColor DarkCyan
        Write-Host "---------------------------------------------------------" -ForegroundColor DarkCyan
        $PrivilegedUsersAll = @($PrivilegedObjects | Where-Object { $_.ObjectType -eq "user" })
        # -ne $true rather than -eq $false: when a protection flag could not be resolved it is $null, and
        # "$null -eq $false" is FALSE - so an object of unknown protection state counted as protected and
        # was excluded here, suppressing the directory-level ("/") fallback scope that exists to cover
        # unprotected privileged objects. Unknown must be treated as unprotected (fail safe, wider Tier 0).
        $PrivilegedUsersWithoutProtection = @($PrivilegedUsersAll | Where-Object { $_.RestrictedManagementByRAG -ne $true -and $_.RestrictedManagementByAadRole -ne $true -and $_.RestrictedManagementByRMAU -ne $true })

        Write-Host "  Total users  : $($PrivilegedUsersAll.Count)" -ForegroundColor Gray
        Write-Host "  Unprotected  : $($PrivilegedUsersWithoutProtection.Count)" -ForegroundColor $(if ($PrivilegedUsersWithoutProtection.Count -gt 0) { 'Yellow' } else { 'DarkGreen' })

        # Include all Administrative Units because of Privileged Authentication Admin role assignment on (RM)AU level
        $PrivilegedUserWithAU = $PrivilegedObjects | Where-Object { $_.ObjectType -eq "user" -and $null -ne $_.AssignedAdministrativeUnits }
        # @() is required: a pipeline yielding a single scope unwraps to [string], which turns the
        # "+= $DirectoryLevelAssignmentScope" below into string concatenation instead of an append.
        $ScopeNamePrivilegedUsers = @($PrivilegedUserWithAU.AssignedAdministrativeUnits | Select-Object -Unique id | ForEach-Object { "/administrativeUnits/$($_.id)" })
        $EntraIdScopeReasoning.AddRange([psobject[]]@(New-EntraIdAuScopeReasoning -ScopeCategory "PrivilegedUsers" -ObjectsWithAU $PrivilegedUserWithAU))
        if ($PrivilegedUsersWithoutProtection.Count -gt 0) {
            Write-Warning "  Control Plane users without protection - directory scope required!"
            $WarningMessages.Add([PSCustomObject]@{ Type = "UnprotectedUsers"; Message = "$($PrivilegedUsersWithoutProtection.Count) Control Plane user(s) without protection - directory scope required" })
            $PrivilegedUsersWithoutProtection | ForEach-Object {
                if ($IncludeObjectDetails) {
                    Write-Host "    [!] $($_.ObjectDisplayName) ($($_.ObjectId))" -ForegroundColor Yellow
                } else {
                    Write-Host "    [!] $($_.ObjectId)" -ForegroundColor Yellow
                }
            }
            $ScopeNamePrivilegedUsers += $DirectoryLevelAssignmentScope
            $EntraIdScopeReasoning.Add((New-EntraIdDirectoryScopeReasoning -ScopeCategory "PrivilegedUsers" -UnprotectedObjects $PrivilegedUsersWithoutProtection -ProtectionGap "without RAG/Entra ID role/RMAU protection")) | Out-Null
        }

        if (@($ScopeNamePrivilegedUsers).Count -gt 0) {
            $ScopeNamePrivilegedUsers = @($ScopeNamePrivilegedUsers | Sort-Object -Unique)
            Write-Host "  Scope entries added:" -ForegroundColor Gray
            $ScopeNamePrivilegedUsers | ForEach-Object { Write-Host "    $_" -ForegroundColor DarkGreen }
            $ScopeNamePrivilegedUsersJSON = $ScopeNamePrivilegedUsers | ConvertTo-Json
            $ScopeNamePrivilegedUsersJSON = $ScopeNamePrivilegedUsersJSON.Replace('[', '').Replace(']', '')
            $ScopeNamePrivilegedUsersJSON = $ScopeNamePrivilegedUsersJSON -creplace '\s+', ' '
            $EntraIdRoleClassification = $EntraIdRoleClassification.replace('<ScopeNamePrivilegedUsers>', $ScopeNamePrivilegedUsersJSON)
            $ScopeSummary.Add([PSCustomObject]@{ Placeholder = 'ScopeNamePrivilegedUsers'; Entries = $ScopeNamePrivilegedUsers.Count; IncludesDirectory = ($ScopeNamePrivilegedUsers -contains '/'); Status = 'Updated' })
        } else {
            Write-Warning "  No privileged users require scope - placeholder cleared."
            $WarningMessages.Add([PSCustomObject]@{ Type = "EmptyScope"; Message = "No privileged users require scope - ScopeNamePrivilegedUsers placeholder cleared" })
            $EntraIdRoleClassification = $EntraIdRoleClassification.replace('<ScopeNamePrivilegedUsers>', '')
            $ScopeSummary.Add([PSCustomObject]@{ Placeholder = 'ScopeNamePrivilegedUsers'; Entries = 0; IncludesDirectory = $false; Status = 'Cleared' })
        }
        Write-Host ""
        #endregion

        #region Privileged Devices
        Write-Host "---------------------------------------------------------" -ForegroundColor DarkCyan
        Write-Host " Privileged Devices" -ForegroundColor DarkCyan
        Write-Host "---------------------------------------------------------" -ForegroundColor DarkCyan
        Write-Host "  Home tenant for device/RMAU evaluation: $HomeTenantId" -ForegroundColor Gray
        $PrivilegedDeviceOwners = @($PrivilegedObjects | Where-Object { $_.ObjectType -eq "user" })
        # Computed once and reused below so the "was a home tenant found" decision for
        # excluding foreign-tenant owners and for the owner filter stays a single condition.
        $HasHomeTenantId = -not [string]::IsNullOrWhiteSpace($HomeTenantId)
        if (-not $HasHomeTenantId) {
            Write-Warning "  Home tenant ID is unavailable; device owners will not be filtered by tenant."
            $WarningMessages.Add([PSCustomObject]@{ Type = "MissingHomeTenantId"; Message = "Home tenant ID is unavailable; device owners were not filtered by tenant" })
            $ForeignTenantDeviceOwners = @()
        } else {
            $ForeignTenantDeviceOwners = @($PrivilegedDeviceOwners | Where-Object {
                    -not [string]::IsNullOrEmpty($_.ObjectTenantId) -and $_.ObjectTenantId -ne $HomeTenantId
                })
        }
        if ($ForeignTenantDeviceOwners.Count -gt 0) {
            Write-Warning "  Excluded devices for $($ForeignTenantDeviceOwners.Count) privileged user(s) not owned by home tenant $HomeTenantId."
            $WarningMessages.Add([PSCustomObject]@{ Type = "ForeignTenantDeviceOwner"; Message = "Excluded devices for $($ForeignTenantDeviceOwners.Count) privileged user(s) not owned by home tenant $HomeTenantId" })
            foreach ($ForeignTenantDeviceOwner in $ForeignTenantDeviceOwners) {
                $EntraIdScopeReasoning.Add([PSCustomObject]@{
                        ScopeCategory = "ExcludedCrossTenantDevices"
                        ScopeId       = $ForeignTenantDeviceOwner.ObjectId
                        ScopeName     = $ForeignTenantDeviceOwner.ObjectDisplayName
                        Reason        = "Devices excluded from RMAU scope evaluation because their privileged user owner belongs to tenant $($ForeignTenantDeviceOwner.ObjectTenantId), not home tenant $HomeTenantId"
                    }) | Out-Null
            }
        }
        if ($HasHomeTenantId) {
            $PrivilegedDeviceOwners = @($PrivilegedDeviceOwners | Where-Object {
                    [string]::IsNullOrEmpty($_.ObjectTenantId) -or $_.ObjectTenantId -eq $HomeTenantId
                })
        }
        $PrivilegedUsersOwnedDevices = @($PrivilegedDeviceOwners | Where-Object { $null -ne $_.OwnedDevices } | Select-Object -ExpandProperty OwnedDevices)
        $PrivilegedUsersPawDevices = @($PrivilegedDeviceOwners | Where-Object { $null -ne $_.AssociatedPawDevice } | Select-Object -ExpandProperty AssociatedPawDevice)
        $PrivilegedUsersWithDevices = @($PrivilegedUsersOwnedDevices + $PrivilegedUsersPawDevices | Select-Object -Unique)
        Write-Host "  Devices of tenant-local privileged users (OwnedDevices + AssociatedPawDevice): $(@($PrivilegedUsersWithDevices).Count)" -ForegroundColor Gray
        # Build per-device protection status. Devices not in any AU at all are unprotected but would be
        # invisible to a flat AU list - track HasRMAU per device to catch them.
        $PrivilegedDevicesProtection = @($PrivilegedUsersWithDevices | ForEach-Object {
                $DeviceId = $_
                # A device with zero administrativeUnit memberships is the common case, not an error -
                # suppress the noisy 404 warning this endpoint returns for that state.
                $DeviceAUs = @(Invoke-EntraOpsMsGraphQuery -Method Get -Uri "/beta/devices/$DeviceId/memberOf/microsoft.graph.administrativeUnit" -OutputType PSObject -SuppressNotFoundWarning | Where-Object { $null -ne $_.id } | Select-Object id, displayName, isMemberManagementRestricted)
                [PSCustomObject]@{
                    DeviceId = $DeviceId
                    AUs      = $DeviceAUs
                    HasRMAU  = ($DeviceAUs | Where-Object { $_.isMemberManagementRestricted -eq $True }).Count -gt 0
                }
            })
        $PrivilegedDevicesWithoutProtection = @($PrivilegedDevicesProtection | Where-Object { $_.HasRMAU -eq $False })
        # Outer @() is required: the Where-Object pipeline unwraps a single scope to [string], which turns
        # the "+= $DirectoryLevelAssignmentScope" below into string concatenation instead of an append.
        $ScopeNamePrivilegedDevices = @(@(
                # RMAU AUs from RMAU-protected devices
                ($PrivilegedDevicesProtection | Where-Object { $_.HasRMAU -eq $True } | ForEach-Object { $_.AUs } | Where-Object { $_.isMemberManagementRestricted -eq $True } | Select-Object -Unique id | ForEach-Object { "/administrativeUnits/$($_.id)" })
                # All AUs from unprotected devices (no RMAU)
                ($PrivilegedDevicesProtection | Where-Object { $_.HasRMAU -eq $False } | ForEach-Object { $_.AUs } | Where-Object { $null -ne $_.id } | Select-Object -Unique id | ForEach-Object { "/administrativeUnits/$($_.id)" })
            ) | Where-Object { $null -ne $_ })

        # Devices carry no ObjectDisplayName (only DeviceId) and their AUs come from a per-device Graph lookup
        # rather than AssignedAdministrativeUnits, so they get their own reasoning-entry logic instead of
        # New-EntraIdAuScopeReasoning.
        foreach ($AU in @($PrivilegedDevicesProtection.AUs | Where-Object { $null -ne $_.id } | Select-Object -Unique id, displayName)) {
            $MatchedDevices = @($PrivilegedDevicesProtection | Where-Object { $_.AUs.id -contains $AU.id })
            $Names = @($MatchedDevices | Select-Object -First 3 -ExpandProperty DeviceId)
            $Reason = "Administrative Unit assigned to $($MatchedDevices.Count) Control Plane device(s): $($Names -join ', ')"
            if ($MatchedDevices.Count -gt 3) { $Reason += " (+$($MatchedDevices.Count - 3) more)" }
            $EntraIdScopeReasoning.Add([PSCustomObject]@{
                    ScopeCategory = "PrivilegedDevices"
                    ScopeId       = "/administrativeUnits/$($AU.id)"
                    ScopeName     = $AU.displayName
                    Reason        = $Reason
                }) | Out-Null
        }

        Write-Host "  Unprotected  : $($PrivilegedDevicesWithoutProtection.Count)" -ForegroundColor $(if ($PrivilegedDevicesWithoutProtection.Count -gt 0) { 'Yellow' } else { 'DarkGreen' })
        if ($PrivilegedDevicesWithoutProtection.Count -gt 0) {
            Write-Warning "  Control Plane devices without RMAU protection - directory scope required!"
            $WarningMessages.Add([PSCustomObject]@{ Type = "UnprotectedDevices"; Message = "$($PrivilegedDevicesWithoutProtection.Count) Control Plane device(s) without RMAU protection - directory scope required" })
            $PrivilegedDevicesWithoutProtection | ForEach-Object {
                Write-Host "    [!] Device $($_.DeviceId)" -ForegroundColor Yellow
            }
            $ScopeNamePrivilegedDevices += $DirectoryLevelAssignmentScope
            $DeviceNames = @($PrivilegedDevicesWithoutProtection | Select-Object -First 3 -ExpandProperty DeviceId)
            $DeviceReason = "$($PrivilegedDevicesWithoutProtection.Count) Control Plane device(s) without RMAU protection require directory-level scope: $($DeviceNames -join ', ')"
            if ($PrivilegedDevicesWithoutProtection.Count -gt 3) { $DeviceReason += " (+$($PrivilegedDevicesWithoutProtection.Count - 3) more)" }
            $EntraIdScopeReasoning.Add([PSCustomObject]@{
                    ScopeCategory = "PrivilegedDevices"
                    ScopeId       = $DirectoryLevelAssignmentScope
                    ScopeName     = "Directory (root)"
                    Reason        = $DeviceReason
                }) | Out-Null
        }
        if (@($ScopeNamePrivilegedDevices).Count -gt 0) {
            $ScopeNamePrivilegedDevices = @($ScopeNamePrivilegedDevices | Sort-Object -Unique)
            Write-Host "  Scope entries added:" -ForegroundColor Gray
            $ScopeNamePrivilegedDevices | ForEach-Object { Write-Host "    $_" -ForegroundColor DarkGreen }
            $ScopeNamePrivilegedDevicesJSON = $ScopeNamePrivilegedDevices | ConvertTo-Json
            $ScopeNamePrivilegedDevicesJSON = $ScopeNamePrivilegedDevicesJSON.Replace('[', '').Replace(']', '')
            $ScopeNamePrivilegedDevicesJSON = $ScopeNamePrivilegedDevicesJSON -creplace '\s+', ' '
            $EntraIdRoleClassification = $EntraIdRoleClassification.replace('<ScopeNamePrivilegedDevices>', $ScopeNamePrivilegedDevicesJSON)
            $ScopeSummary.Add([PSCustomObject]@{ Placeholder = 'ScopeNamePrivilegedDevices'; Entries = $ScopeNamePrivilegedDevices.Count; IncludesDirectory = ($ScopeNamePrivilegedDevices -contains '/'); Status = 'Updated' })
        } else {
            Write-Warning "  No privileged devices found - placeholder cleared."
            $WarningMessages.Add([PSCustomObject]@{ Type = "EmptyScope"; Message = "No privileged devices found - ScopeNamePrivilegedDevices placeholder cleared" })
            $EntraIdRoleClassification = $EntraIdRoleClassification.replace('<ScopeNamePrivilegedDevices>', '')
            $ScopeSummary.Add([PSCustomObject]@{ Placeholder = 'ScopeNamePrivilegedDevices'; Entries = 0; IncludesDirectory = $false; Status = 'Cleared' })
        }
        Write-Host ""
        #endregion

        #region Privileged Groups
        Write-Host "---------------------------------------------------------" -ForegroundColor DarkCyan
        Write-Host " Privileged Groups" -ForegroundColor DarkCyan
        Write-Host "---------------------------------------------------------" -ForegroundColor DarkCyan
        $PrivilegedGroupsAll = @($PrivilegedObjects | Where-Object { $_.ObjectType -eq "group" })
        # See the equivalent user filter above: an unresolved ($null) protection flag must count as
        # unprotected, otherwise the group is silently excluded from the directory-level fallback scope.
        $PrivilegedGroupsWithoutProtection = @($PrivilegedGroupsAll | Where-Object { $_.RestrictedManagementByRAG -ne $true -and $_.RestrictedManagementByAadRole -ne $true -and $_.RestrictedManagementByRMAU -ne $true })
        $PrivilegedGroupWithRMAU = @($PrivilegedGroupsAll | Where-Object { $_.RestrictedManagementByRMAU -eq $True })

        Write-Host "  Total groups : $($PrivilegedGroupsAll.Count)" -ForegroundColor Gray
        Write-Host "  Protected(RMAU): $($PrivilegedGroupWithRMAU.Count)" -ForegroundColor DarkGreen
        Write-Host "  Unprotected  : $($PrivilegedGroupsWithoutProtection.Count)" -ForegroundColor $(if ($PrivilegedGroupsWithoutProtection.Count -gt 0) { 'Yellow' } else { 'DarkGreen' })

        # Outer @() is required: the Where-Object pipeline unwraps a single scope to [string], which turns
        # the "+= $DirectoryLevelAssignmentScope" below into string concatenation instead of an append.
        $ScopeNamePrivilegedGroups = @(@(
                # RMAU AUs from RMAU-protected groups
                ($PrivilegedGroupWithRMAU.AssignedAdministrativeUnits | Where-Object { $null -ne $_.id } | Select-Object -Unique id | ForEach-Object { "/administrativeUnits/$($_.id)" })
                # All AUs from unprotected groups (no RMAU)
                ($PrivilegedGroupsWithoutProtection.AssignedAdministrativeUnits | Where-Object { $null -ne $_.id } | Select-Object -Unique id | ForEach-Object { "/administrativeUnits/$($_.id)" })
            ) | Where-Object { $null -ne $_ })
        $EntraIdScopeReasoning.AddRange([psobject[]]@(New-EntraIdAuScopeReasoning -ScopeCategory "PrivilegedGroups" -ObjectsWithAU (@($PrivilegedGroupWithRMAU) + @($PrivilegedGroupsWithoutProtection))))
        if ($PrivilegedGroupsWithoutProtection.Count -gt 0) {
            Write-Warning "  Control Plane groups without RMAU protection - directory scope required!"
            $WarningMessages.Add([PSCustomObject]@{ Type = "UnprotectedGroups"; Message = "$($PrivilegedGroupsWithoutProtection.Count) Control Plane group(s) without RMAU protection - directory scope required" })
            $PrivilegedGroupsWithoutProtection | ForEach-Object {
                if ($IncludeObjectDetails) {
                    Write-Host "    [!] $($_.ObjectDisplayName) ($($_.ObjectId))" -ForegroundColor Yellow
                } else {
                    Write-Host "    [!] $($_.ObjectId)" -ForegroundColor Yellow
                }
            }
            $ScopeNamePrivilegedGroups += $DirectoryLevelAssignmentScope
            $EntraIdScopeReasoning.Add((New-EntraIdDirectoryScopeReasoning -ScopeCategory "PrivilegedGroups" -UnprotectedObjects $PrivilegedGroupsWithoutProtection -ProtectionGap "without RMAU protection")) | Out-Null
        }
        if (@($ScopeNamePrivilegedGroups).Count -gt 0) {
            $ScopeNamePrivilegedGroups = @($ScopeNamePrivilegedGroups | Sort-Object -Unique)
            Write-Host "  Scope entries added:" -ForegroundColor Gray
            $ScopeNamePrivilegedGroups | ForEach-Object { Write-Host "    $_" -ForegroundColor DarkGreen }
            $ScopeNamePrivilegedGroupsJSON = $ScopeNamePrivilegedGroups | ConvertTo-Json
            $ScopeNamePrivilegedGroupsJSON = $ScopeNamePrivilegedGroupsJSON.Replace('[', '').Replace(']', '')
            $ScopeNamePrivilegedGroupsJSON = $ScopeNamePrivilegedGroupsJSON -creplace '\s+', ' '
            $EntraIdRoleClassification = $EntraIdRoleClassification.replace('<ScopeNamePrivilegedGroups>', $ScopeNamePrivilegedGroupsJSON)
            $ScopeSummary.Add([PSCustomObject]@{ Placeholder = 'ScopeNamePrivilegedGroups'; Entries = $ScopeNamePrivilegedGroups.Count; IncludesDirectory = ($ScopeNamePrivilegedGroups -contains '/'); Status = 'Updated' })
        } else {
            Write-Warning "  No privileged groups require scope - placeholder cleared."
            $WarningMessages.Add([PSCustomObject]@{ Type = "EmptyScope"; Message = "No privileged groups require scope - ScopeNamePrivilegedGroups placeholder cleared" })
            $EntraIdRoleClassification = $EntraIdRoleClassification.replace('<ScopeNamePrivilegedGroups>', '')
            $ScopeSummary.Add([PSCustomObject]@{ Placeholder = 'ScopeNamePrivilegedGroups'; Entries = 0; IncludesDirectory = $false; Status = 'Cleared' })
        }
        Write-Host ""
        #endregion

        #region Privileged Service Principals
        Write-Host "---------------------------------------------------------" -ForegroundColor DarkCyan
        Write-Host " Privileged Service Principals & Applications" -ForegroundColor DarkCyan
        Write-Host "---------------------------------------------------------" -ForegroundColor DarkCyan
        $PrivilegedServicePrincipals = @($PrivilegedObjects | Where-Object { $_.ObjectType -eq "servicePrincipal" })
        $PrivilegedApplicationObjects = @($PrivilegedObjects | Where-Object { $_.ObjectType -eq "application" })
        Write-Host "  Service Principals : $($PrivilegedServicePrincipals.Count)" -ForegroundColor Gray
        Write-Host "  Direct application objects: $($PrivilegedApplicationObjects.Count) (application objects of single-tenant service principals are resolved below)" -ForegroundColor Gray
        # Initialized here (not just inside the branch below) so the "@(...).Count -gt 0"
        # guard further down stays false - not $null, whose @($null).Count is 1 - when no
        # privileged service principals/applications were found.
        $ScopeNamePrivilegedServicePrincipals = @()
    
        if ($PrivilegedServicePrincipals.Count -gt 0 -or $PrivilegedApplicationObjects.Count -gt 0) {
            # Get list of object-level role assignment scope which includes Control Plane Service Principals
            # @() is required: a single service principal would unwrap to [string] and make the
            # array concatenation building $ScopeNamePrivilegedServicePrincipals a string join instead.
            $ScopeNameServicePrincipalObject = @($PrivilegedServicePrincipals | ForEach-Object { "/$($_.ObjectId)" })

            # Get current tenant ID to identify single-tenant apps
            $CurrentTenantId = (Get-AzContext).Tenant.Id

            # Initialize array for application object scopes
            $ScopeNameApplicationObject = @()

            # Process direct application objects from EntraOps
            if ($PrivilegedApplicationObjects.Count -gt 0) {
                Write-Host "  Processing $($PrivilegedApplicationObjects.Count) direct application objects from EntraOps..." -ForegroundColor Gray
                foreach ($AppObj in $PrivilegedApplicationObjects) {
                    $ScopeNameApplicationObject += "/$($AppObj.ObjectId)"
                    if ($IncludeObjectDetails) {
                        Write-Host "  [+] Direct app object: $($AppObj.ObjectDisplayName) -> /$($AppObj.ObjectId)" -ForegroundColor DarkGreen
                    } else {
                        Write-Host "  [+] Direct app object: $($AppObj.ObjectId)" -ForegroundColor DarkGreen
                    }
                }
            }

            # Filter for applications only (exclude managed identities and other types)
            $PrivilegedApplications = $PrivilegedServicePrincipals | Where-Object { $_.ObjectSubType -eq "Application" }
        
            # Get unique service principal object IDs for batch lookup
            $SpObjectIds = $PrivilegedApplications.ObjectId | Select-Object -Unique
        
            # Batch fetch service principal details for all at once to check appOwnerOrganizationId
            # This is much more efficient than individual requests
            $AppOwnershipInfo = @{}
            if ($SpObjectIds.Count -gt 0) {
                Write-Verbose "Fetching ownership information for $($SpObjectIds.Count) service principals..."
                foreach ($SpId in $SpObjectIds) {
                    $Uri = "/v1.0/servicePrincipals/$($SpId)?`$select=id,appId,appOwnerOrganizationId,servicePrincipalType"
                    try {
                        $SpDetails = Invoke-EntraOpsMsGraphQuery -Method Get -Uri $Uri -OutputType PSObject
                        if ($null -ne $SpDetails) {
                            $AppOwnershipInfo[$SpId] = $SpDetails
                            Write-Verbose "Fetched service principal details for: $SpId"
                        }
                    } catch {
                        Write-Warning "Failed to fetch service principal details for $SpId : $_"
                    }
                }
            }

            # Get application object IDs only for single-tenant apps owned by current tenant
            # Managed identities and multi-tenant apps are automatically excluded
            foreach ($App in $PrivilegedApplications) {
                $SpDetails = $AppOwnershipInfo[$App.ObjectId]
            
                # Only process if we have details and it's owned by current tenant (single-tenant app)
                if ($null -ne $SpDetails -and 
                    $SpDetails.servicePrincipalType -ne "ManagedIdentity" -and 
                    $SpDetails.appOwnerOrganizationId -eq $CurrentTenantId) {
                
                    try {
                        $AppUri = "/v1.0/applications?`$filter=appId eq '$($SpDetails.appId)'&`$select=id,appId"
                        $AppObjects = Invoke-EntraOpsMsGraphQuery -Method Get -Uri $AppUri -OutputType PSObject
                    
                        if ($null -ne $AppObjects) {
                            # Handle both single object and collection responses
                            $AppObjectList = if ($AppObjects -is [System.Collections.IEnumerable] -and $AppObjects -isnot [string]) { $AppObjects } else { @($AppObjects) }
                        
                            foreach ($AppObject in $AppObjectList) {
                                if ($null -ne $AppObject.id) {
                                    $ScopeNameApplicationObject += "/$($AppObject.id)"
                                    if ($IncludeObjectDetails) {
                                        Write-Host "  [+] App object resolved: $($App.ObjectDisplayName) ($($SpDetails.appId)) -> /$($AppObject.id)" -ForegroundColor DarkGreen
                                    } else {
                                        Write-Host "  [+] App object resolved: $($AppObject.id)" -ForegroundColor DarkGreen
                                    }
                                }
                            }
                        }
                    } catch {
                        Write-Warning "  [!] Failed to fetch application object for appId $($SpDetails.appId): $_"
                        $WarningMessages.Add([PSCustomObject]@{ Type = "ApiError"; Message = "Failed to fetch application object for appId $($SpDetails.appId): $_" })
                    }
                } else {
                    if ($null -ne $SpDetails) {
                        if ($IncludeObjectDetails) {
                            Write-Host "  [~] Skipped: $($App.ObjectDisplayName) - Type: $($SpDetails.servicePrincipalType), Owner: $(if ($SpDetails.appOwnerOrganizationId -ne $CurrentTenantId) { 'External tenant' } else { $SpDetails.appOwnerOrganizationId })" -ForegroundColor DarkGray
                        } else {
                            Write-Host "  [~] Skipped object: $($App.ObjectId)" -ForegroundColor DarkGray
                        }
                    }
                }
            }

            $PrivilegedServicePrincipalObjectsWithAU = $PrivilegedObjects | Where-Object { $_.ObjectType -eq "servicePrincipal" -and $null -ne $_.AssignedAdministrativeUnits.id }
            $PrivilegedServicePrincipalWithAU = @($PrivilegedServicePrincipalObjectsWithAU.AssignedAdministrativeUnits | Select-Object -Unique id | ForEach-Object { "/administrativeUnits/$($_.id)" })

            # Always add also directory level assignment scope because of missing protection of service principal by RAG, AAD Role or RMAU assignment
            $ScopeNamePrivilegedServicePrincipals = $ScopeNameServicePrincipalObject + $ScopeNameApplicationObject + $DirectoryLevelAssignmentScope + $PrivilegedServicePrincipalWithAU

            Write-Host "  Scope entries added:" -ForegroundColor Gray
            $ScopeNamePrivilegedServicePrincipals | Sort-Object -Unique | ForEach-Object { Write-Host "    $_" -ForegroundColor DarkGreen }

            # Object-level scopes (one entry per SP/app object, already unambiguous - no aggregation needed)
            foreach ($SpEntry in $PrivilegedServicePrincipals) {
                $EntraIdScopeReasoning.Add([PSCustomObject]@{
                        ScopeCategory = "PrivilegedServicePrincipals"
                        ScopeId       = "/$($SpEntry.ObjectId)"
                        ScopeName     = $SpEntry.ObjectDisplayName
                        Reason        = "Object-level role assignment scope for Control Plane service principal '$($SpEntry.ObjectDisplayName)'"
                    }) | Out-Null
            }
            foreach ($AppScope in $ScopeNameApplicationObject) {
                $EntraIdScopeReasoning.Add([PSCustomObject]@{
                        ScopeCategory = "PrivilegedServicePrincipals"
                        ScopeId       = $AppScope
                        ScopeName     = $null
                        Reason        = "Object-level role assignment scope for the application object of a Control Plane single-tenant app/direct application object"
                    }) | Out-Null
            }
            $EntraIdScopeReasoning.Add([PSCustomObject]@{
                    ScopeCategory = "PrivilegedServicePrincipals"
                    ScopeId       = $DirectoryLevelAssignmentScope
                    ScopeName     = "Directory (root)"
                    Reason        = "Always included: service principals are not protected by RAG/Entra ID role/RMAU assignment"
                }) | Out-Null
            $EntraIdScopeReasoning.AddRange([psobject[]]@(New-EntraIdAuScopeReasoning -ScopeCategory "PrivilegedServicePrincipals" -ObjectsWithAU $PrivilegedServicePrincipalObjectsWithAU))
        } else {
            Write-Warning "  No privileged applications found - defaulting to directory scope '/'"
            $WarningMessages.Add([PSCustomObject]@{ Type = "EmptyScope"; Message = "No privileged applications found - ScopeNamePrivilegedServicePrincipals defaulting to directory scope '/'" })
            $EntraIdRoleClassification = $EntraIdRoleClassification.replace('<ScopeNamePrivilegedServicePrincipals>', '"/"')
            $ScopeSummary.Add([PSCustomObject]@{ Placeholder = 'ScopeNamePrivilegedServicePrincipals'; Entries = 1; IncludesDirectory = $true; Status = 'Default(/)' })
        }

        if (@($ScopeNamePrivilegedServicePrincipals).Count -gt 0) {
            $ScopeNamePrivilegedServicePrincipals = @($ScopeNamePrivilegedServicePrincipals | Sort-Object -Unique)
            $ScopeNamePrivilegedServicePrincipalsJSON = $ScopeNamePrivilegedServicePrincipals | ConvertTo-Json
            $ScopeNamePrivilegedServicePrincipalsJSON = $ScopeNamePrivilegedServicePrincipalsJSON.Replace('[', '').Replace(']', '')
            $ScopeNamePrivilegedServicePrincipalsJSON = $ScopeNamePrivilegedServicePrincipalsJSON -creplace '\s+', ' '
            $EntraIdRoleClassification = $EntraIdRoleClassification.replace('<ScopeNamePrivilegedServicePrincipals>', $ScopeNamePrivilegedServicePrincipalsJSON)
            $ScopeSummary.Add([PSCustomObject]@{ Placeholder = 'ScopeNamePrivilegedServicePrincipals'; Entries = $ScopeNamePrivilegedServicePrincipals.Count; IncludesDirectory = ($ScopeNamePrivilegedServicePrincipals -contains '/'); Status = 'Updated' })
        }
        Write-Host ""
        #endregion

        # Apply role action overwrites (down-/upgrade of individual role actions) to the generated classification
        $EntraIdRoleClassificationDefinition = @($EntraIdRoleClassification | ConvertFrom-Json -Depth 10)
        $EntraIdRoleActionOverwrites = @((Import-EntraOpsClassificationOverwrites -RbacSystem "EntraID").RoleActionOverwrites)
        if ($EntraIdRoleActionOverwrites.Count -gt 0) {
            Write-Host "  Applying $($EntraIdRoleActionOverwrites.Count) role action overwrite(s) from $((@($EntraIdRoleActionOverwrites.SourceFile) | Sort-Object -Unique) -join ', ')..." -ForegroundColor Yellow
            $EntraIdRoleClassificationDefinition = Invoke-EntraOpsClassificationActionOverwrite -ClassificationDefinition $EntraIdRoleClassificationDefinition -RoleActionOverwrites $EntraIdRoleActionOverwrites
        }
        $EntraIdRoleClassificationDefinition | ConvertTo-Json -Depth 10 | Out-File -FilePath $EntraIdCustomizedClassificationFile -Force
        Write-Host "  Output file: $EntraIdCustomizedClassificationFile" -ForegroundColor Cyan

        #region Persist WHY each resolved EntraID scope (Administrative Unit or directory-level fallback) got its tier
        # Mirrors ScopeReasoning_DeviceManagement.json/ScopeReasoning_Azure.json/ScopeReasoning_IdentityGovernance.json.
        $EntraIdScopeReasoningFile = Join-Path (Split-Path $EntraIdCustomizedClassificationFile -Parent) "ScopeReasoning_EntraID.json"
        $EntraIdScopeReasoningPayload = [PSCustomObject]@{
            ScopeDetails = @($EntraIdScopeReasoning | Sort-Object ScopeCategory, ScopeName, ScopeId)
        }
        $EntraIdScopeReasoningPayload | ConvertTo-Json -Depth 5 | Out-File -FilePath $EntraIdScopeReasoningFile -Force
        Write-Host "  Scope reasoning file: $EntraIdScopeReasoningFile" -ForegroundColor Cyan
        #endregion

    } # end if EntraID
    #endregion

    #region DeviceManagement (Intune) RBAC Classification Parameter Scope
    if ($ClassificationParameterScope -contains "DeviceManagement") {
        Write-Host ""
        Write-Host "=========================================================" -ForegroundColor Cyan
        Write-Host " DeviceManagement (Intune) RBAC - Scope Parameter Update" -ForegroundColor Cyan
        Write-Host "=========================================================" -ForegroundColor Cyan

        $DeviceMgmtRoleClassification = Get-Content -Path $DeviceMgmtClassificationParameterFile -Raw

        #region Collect privileged devices from Control Plane and Management Plane
        Write-Host ""
        Write-Host "---------------------------------------------------------" -ForegroundColor DarkCyan
        Write-Host " Privileged Devices for Intune Group Classification" -ForegroundColor DarkCyan
        Write-Host "---------------------------------------------------------" -ForegroundColor DarkCyan

        # Collect all ControlPlane (Tier 0) and ManagementPlane (Tier 1) objects from EntraOps data
        $EntraOpsAllPrivilegedForDeviceMgmt = foreach ($Scope in $EntraOpsScopes) {
            try {
                Get-Content -Path (Join-Path -Path $EntraOpsEamFolder -ChildPath $Scope -AdditionalChildPath "$($Scope).json") -ErrorAction Stop | ConvertFrom-Json -Depth 10
            } catch {
                Write-Verbose "No data for ${Scope}: $_"
            }
        }

        # Tier 0 - ControlPlane devices: devices owned by or associated (PAW) with ControlPlane users
        $Tier0Users = @($EntraOpsAllPrivilegedForDeviceMgmt | Where-Object { $_.ObjectAdminTierLevelName -eq "ControlPlane" -and $_.ObjectType -eq "user" } | Select-Object -Unique ObjectId, ObjectDisplayName, OwnedDevices, AssociatedPawDevice)
        $Tier0OwnedDeviceIds = @($Tier0Users | Where-Object { $null -ne $_.OwnedDevices } | Select-Object -ExpandProperty OwnedDevices)
        $Tier0PawDeviceIds = @($Tier0Users | Where-Object { $null -ne $_.AssociatedPawDevice } | Select-Object -ExpandProperty AssociatedPawDevice)
        $Tier0DeviceIds = @($Tier0OwnedDeviceIds + $Tier0PawDeviceIds | Select-Object -Unique)

        # Tier 1 - ManagementPlane devices: devices owned by or associated (PAW) with ManagementPlane users (only for ControlPlaneAndManagementPlane scope)
        if ($DeviceMgmtPrivilegedTierScope -eq "ControlPlaneAndManagementPlane") {
            $Tier1Users = @($EntraOpsAllPrivilegedForDeviceMgmt | Where-Object { $_.ObjectAdminTierLevelName -eq "ManagementPlane" -and $_.ObjectType -eq "user" } | Select-Object -Unique ObjectId, ObjectDisplayName, OwnedDevices, AssociatedPawDevice)
            $Tier1OwnedDeviceIds = @($Tier1Users | Where-Object { $null -ne $_.OwnedDevices } | Select-Object -ExpandProperty OwnedDevices)
            $Tier1PawDeviceIds = @($Tier1Users | Where-Object { $null -ne $_.AssociatedPawDevice } | Select-Object -ExpandProperty AssociatedPawDevice)
            $Tier1DeviceIds = @($Tier1OwnedDeviceIds + $Tier1PawDeviceIds | Select-Object -Unique)
            # Remove Tier 0 devices from Tier 1 to avoid double classification (Tier 0 takes precedence)
            $Tier1DeviceIds = @($Tier1DeviceIds | Where-Object { $_ -notin $Tier0DeviceIds })
        } else {
            $Tier1Users = @()
            $Tier1DeviceIds = @()
        }

        # Device selection uses designated users only. Report devices of role-derived Control Plane users that no selected
        # user contributes, so a missing designation does not silently shrink the scope.
        $SelectedDeviceIds = @($Tier0DeviceIds) + @($Tier1DeviceIds)
        $DeviceSelectionGaps = @(Get-EntraOpsIntuneDeviceScopeSelectionGap -PrivilegedObjects $PrivilegedObjects -Tier0Users $Tier0Users -Tier1Users $Tier1Users -SelectedDeviceIds $SelectedDeviceIds -HomeTenantId $HomeTenantId)
        if ($DeviceSelectionGaps.Count -gt 0) {
            $UnselectedDeviceCount = @($DeviceSelectionGaps | ForEach-Object { $_.UnselectedDeviceIds }).Count
            Write-Warning "  $($DeviceSelectionGaps.Count) Control Plane user(s) have $UnselectedDeviceCount owned or PAW device(s) not selected for privileged Intune scope generation in mode $DeviceMgmtPrivilegedTierScope. Review the designated tier (ObjectAdminTierLevelName) of these users."
            foreach ($DeviceSelectionGap in $DeviceSelectionGaps) {
                $WarningMessages.Add([PSCustomObject]@{ Type = $DeviceSelectionGap.Type; Message = $DeviceSelectionGap.Message })
            }
        }

        Write-Host "  Scope mode               : $DeviceMgmtPrivilegedTierScope" -ForegroundColor Cyan
        Write-Host "  Tier 0 (ControlPlane)   : $($Tier0Users.Count) user(s), $($Tier0DeviceIds.Count) device(s)" -ForegroundColor Gray
        Write-Host "  Tier 1 (ManagementPlane): $($Tier1Users.Count) user(s), $($Tier1DeviceIds.Count) device(s)" -ForegroundColor $(if ($DeviceMgmtPrivilegedTierScope -eq "ControlPlaneDevicesOnly") { 'DarkGray' } else { 'Gray' })

        # Verbose: per-user device detail (OwnedDevices + AssociatedPawDevice)
        Write-Verbose "  Tier 0 device associations:"
        $Tier0Users | ForEach-Object {
            $UserOwnedDevs = @(if ($null -ne $_.OwnedDevices) { $_.OwnedDevices } else { @() })
            $UserPawDevs = @(if ($null -ne $_.AssociatedPawDevice) { $_.AssociatedPawDevice } else { @() })
            $AllDevs = @($UserOwnedDevs + $UserPawDevs | Select-Object -Unique)
            if ($AllDevs.Count -gt 0) {
                $OwnedLabel = if ($UserOwnedDevs.Count -gt 0) { "Owned: $($UserOwnedDevs -join ', ')" } else { $null }
                $PawLabel = if ($UserPawDevs.Count -gt 0) { "PAW: $($UserPawDevs -join ', ')" } else { $null }
                $DetailLabel = @($OwnedLabel, $PawLabel) | Where-Object { $null -ne $_ }
                Write-Verbose "    $($_.ObjectDisplayName) ($($_.ObjectId)) -> $($DetailLabel -join ' | ')"
            }
        }
        if ($Tier0DeviceIds.Count -eq 0) { Write-Verbose "    (none)" }

        Write-Verbose "  Tier 1 device associations:"
        $Tier1Users | ForEach-Object {
            $UserOwnedDevs = @(if ($null -ne $_.OwnedDevices) { $_.OwnedDevices } else { @() })
            $UserPawDevs = @(if ($null -ne $_.AssociatedPawDevice) { $_.AssociatedPawDevice } else { @() })
            $AllDevs = @($UserOwnedDevs + $UserPawDevs | Select-Object -Unique | Where-Object { $_ -notin $Tier0DeviceIds })
            if ($AllDevs.Count -gt 0) {
                $OwnedLabel = if ($UserOwnedDevs.Count -gt 0) { "Owned: $($UserOwnedDevs -join ', ')" } else { $null }
                $PawLabel = if ($UserPawDevs.Count -gt 0) { "PAW: $($UserPawDevs -join ', ')" } else { $null }
                $DetailLabel = @($OwnedLabel, $PawLabel) | Where-Object { $null -ne $_ }
                Write-Verbose "    $($_.ObjectDisplayName) ($($_.ObjectId)) -> $($DetailLabel -join ' | ')"
            }
        }
        if ($Tier1DeviceIds.Count -eq 0) { Write-Verbose "    (none)" }
        #endregion

        #region Resolve transitive group memberships for privileged devices and users
        Write-Host ""
        Write-Host "---------------------------------------------------------" -ForegroundColor DarkCyan
        Write-Host " Resolving Transitive Group Memberships for Devices" -ForegroundColor DarkCyan
        Write-Host "---------------------------------------------------------" -ForegroundColor DarkCyan

        # Helper: Get all groups a directory object belongs to (including nested/transitive membership)
        function Get-TransitiveGroupMembership {
            param(
                [string]$ObjectId,
                [ValidateSet("devices", "users")]
                [string]$ObjectType = "devices"
            )
            $Groups = @()
            try {
                # A device/user with zero group memberships is the common case, not an error -
                # suppress the noisy 404 warning this endpoint returns for that state.
                $MemberOf = Invoke-EntraOpsMsGraphQuery -Method Get -Uri "/beta/$ObjectType/$ObjectId/transitiveMemberOf/microsoft.graph.group?`$select=id,displayName" -OutputType PSObject -SuppressNotFoundWarning
                if ($null -ne $MemberOf) {
                    $Groups = @($MemberOf | Where-Object { $null -ne $_.id } | Select-Object id, displayName)
                }
            } catch {
                Write-Warning "  Failed to resolve group membership for $ObjectType $ObjectId : $_"
            }
            return $Groups
        }

        # Resolve Tier 0 device groups
        $Tier0DeviceGroups = @{}
        foreach ($DeviceId in $Tier0DeviceIds) {
            $Groups = Get-TransitiveGroupMembership -ObjectId $DeviceId -ObjectType "devices"
            if ($Groups.Count -gt 0) {
                $Tier0DeviceGroups[$DeviceId] = $Groups
            }
        }
        $Tier0DeviceUniqueGroupIds = @($Tier0DeviceGroups.Values | ForEach-Object { $_ } | Select-Object -Unique id | ForEach-Object { $_.id })

        # Resolve Tier 1 device groups
        $Tier1DeviceGroups = @{}
        foreach ($DeviceId in $Tier1DeviceIds) {
            $Groups = Get-TransitiveGroupMembership -ObjectId $DeviceId -ObjectType "devices"
            if ($Groups.Count -gt 0) {
                $Tier1DeviceGroups[$DeviceId] = $Groups
            }
        }
        $Tier1DeviceUniqueGroupIds = @($Tier1DeviceGroups.Values | ForEach-Object { $_ } | Select-Object -Unique id | ForEach-Object { $_.id })

        Write-Verbose "  Tier 0 unique device groups: $($Tier0DeviceUniqueGroupIds.Count)"
        Write-Verbose "  Tier 1 unique device groups: $($Tier1DeviceUniqueGroupIds.Count)"

        # Initialize user group collections - populated below only when scope includes user group memberships
        $Tier0UserGroups = @{}
        $Tier0UserUniqueGroupIds = @()
        $Tier1UserGroups = @{}
        $Tier1UserUniqueGroupIds = @()

        #region Resolve transitive group memberships for privileged users
        if ($DeviceMgmtPrivilegedTierScope -eq "ControlPlaneAndManagementPlane") {
            Write-Host ""
            Write-Host "---------------------------------------------------------" -ForegroundColor DarkCyan
            Write-Host " Resolving Transitive Group Memberships for Users" -ForegroundColor DarkCyan
            Write-Host "---------------------------------------------------------" -ForegroundColor DarkCyan

            # Resolve Tier 0 user groups
            foreach ($User in $Tier0Users) {
                $Groups = Get-TransitiveGroupMembership -ObjectId $User.ObjectId -ObjectType "users"
                if ($Groups.Count -gt 0) {
                    $Tier0UserGroups[$User.ObjectId] = $Groups
                }
            }
            $Tier0UserUniqueGroupIds = @($Tier0UserGroups.Values | ForEach-Object { $_ } | Select-Object -Unique id | ForEach-Object { $_.id })

            # Resolve Tier 1 user groups (exclude groups already in Tier 0)
            $Tier1UserGroups = @{}
            foreach ($User in $Tier1Users) {
                $Groups = Get-TransitiveGroupMembership -ObjectId $User.ObjectId -ObjectType "users"
                if ($Groups.Count -gt 0) {
                    $Tier1UserGroups[$User.ObjectId] = $Groups
                }
            }
            $Tier1UserUniqueGroupIds = @($Tier1UserGroups.Values | ForEach-Object { $_ } | Select-Object -Unique id | ForEach-Object { $_.id })

            Write-Verbose "  Tier 0 unique user groups: $($Tier0UserUniqueGroupIds.Count)"
            Write-Verbose "  Tier 1 unique user groups: $($Tier1UserUniqueGroupIds.Count)"

            # Verbose: per-user group detail
            Write-Verbose "  Tier 0 user group memberships:"
            foreach ($UserId in $Tier0UserGroups.Keys) {
                $UserName = ($Tier0Users | Where-Object { $_.ObjectId -eq $UserId }).ObjectDisplayName
                $UserGroupNames = @($Tier0UserGroups[$UserId] | ForEach-Object { $_.displayName }) -join ', '
                Write-Verbose "    $UserName ($UserId) -> Groups: $UserGroupNames"
            }
            if ($Tier0UserGroups.Count -eq 0) { Write-Verbose "    (none)" }

            Write-Verbose "  Tier 1 user group memberships:"
            foreach ($UserId in $Tier1UserGroups.Keys) {
                $UserName = ($Tier1Users | Where-Object { $_.ObjectId -eq $UserId }).ObjectDisplayName
                $UserGroupNames = @($Tier1UserGroups[$UserId] | ForEach-Object { $_.displayName }) -join ', '
                Write-Verbose "    $UserName ($UserId) -> Groups: $UserGroupNames"
            }
            if ($Tier1UserGroups.Count -eq 0) { Write-Verbose "    (none)" }

        } # end if ControlPlaneAndManagementPlane (user groups)
        #endregion

        # Merge device and user groups into combined unique group IDs per tier
        if ($DeviceMgmtPrivilegedTierScope -eq "ControlPlaneDevicesOnly") {
            $Tier0UniqueGroupIds = @($Tier0DeviceUniqueGroupIds | Select-Object -Unique)
            $Tier1UniqueGroupIds = @()
        } else {
            $Tier0UniqueGroupIds = @($Tier0DeviceUniqueGroupIds + $Tier0UserUniqueGroupIds | Select-Object -Unique)
            $Tier1UniqueGroupIds = @($Tier1DeviceUniqueGroupIds + $Tier1UserUniqueGroupIds | Select-Object -Unique)
            # Groups containing members from both tiers intentionally appear in both lists
            # so they are included in both <Tier0IncludedGroupIds> and <Tier1IncludedGroupIds>
        }

        Write-Host ""
        Write-Host "  Combined unique groups (devices + users):" -ForegroundColor White
        Write-Host "  Tier 0 (ControlPlane)   : $($Tier0UniqueGroupIds.Count) group(s) total (devices: $($Tier0DeviceUniqueGroupIds.Count), users: $($Tier0UserUniqueGroupIds.Count))" -ForegroundColor Gray
        Write-Host "  Tier 1 (ManagementPlane): $($Tier1UniqueGroupIds.Count) group(s) total (devices: $($Tier1DeviceUniqueGroupIds.Count), users: $($Tier1UserUniqueGroupIds.Count))" -ForegroundColor Gray
        #endregion

        #region Map groups to Intune scope tags
        Write-Host ""
        Write-Host "---------------------------------------------------------" -ForegroundColor DarkCyan
        Write-Host " Filtering Groups by Intune Scope Tag Assignments" -ForegroundColor DarkCyan
        Write-Host "---------------------------------------------------------" -ForegroundColor DarkCyan

        # Fetch scope tag display names for reporting
        $IntuneScopeTags = Invoke-EntraOpsMsGraphQuery -Method GET -Uri "/beta/deviceManagement/roleScopeTags" -OutputType PSObject
        $ScopeTagNameLookup = @{}
        foreach ($ScopeTag in $IntuneScopeTags) {
            $ScopeTagNameLookup["$($ScopeTag.Id)"] = $ScopeTag.DisplayName
        }

        # Use roleManagement/deviceManagement/roleAssignments to get all groups (directoryScopeIds)
        # mapped to scope tags (appScopeIds). The roleScopeTags/{id}/assignments API does not return
        # all group IDs, whereas directoryScopeIds from roleAssignments provides the complete set.
        $DeviceMgmtRoleAssignments = Invoke-EntraOpsMsGraphQuery -Method GET -Uri "/beta/roleManagement/deviceManagement/roleAssignments" -OutputType PSObject
        $IntuneScopeTagAssignments = foreach ($RoleAssignment in $DeviceMgmtRoleAssignments) {
            if ($null -eq $RoleAssignment.appScopeIds -or $RoleAssignment.appScopeIds.Count -eq 0) { continue }
            # directoryScopeIds contains the group IDs in scope for this role assignment
            $GroupIds = @($RoleAssignment.directoryScopeIds | Where-Object { $_ -ne "/" -and -not [string]::IsNullOrEmpty($_) })
            if ($GroupIds.Count -eq 0) { continue }
            foreach ($AppScopeId in $RoleAssignment.appScopeIds) {
                $ScopeTagName = $ScopeTagNameLookup["$AppScopeId"]
                if ([string]::IsNullOrEmpty($ScopeTagName)) { $ScopeTagName = "ScopeTag-$AppScopeId" }
                foreach ($GroupId in $GroupIds) {
                    Write-Verbose "  ScopeTag '$ScopeTagName' (ID: $AppScopeId) -> GroupId: $GroupId (from roleAssignment $($RoleAssignment.Id))"
                    [PSCustomObject]@{
                        ScopeTagName = $ScopeTagName
                        ScopeTagId   = $AppScopeId
                        GroupId      = $GroupId
                    }
                }
            }
        }

        # Build set of all group IDs that are in scope of any Intune role assignment with a scope tag
        $AllScopeTagGroupIds = @($IntuneScopeTagAssignments | Select-Object -Unique GroupId | ForEach-Object { $_.GroupId })
        Write-Verbose "  Total unique groups in scope of Intune role assignments: $($AllScopeTagGroupIds.Count)"

        # Build a unified group-name lookup across devices and users for both tiers
        $AllGroupNameLookup = @{}
        foreach ($Groups in (@($Tier0DeviceGroups.Values) + @($Tier0UserGroups.Values) + @($Tier1DeviceGroups.Values) + @($Tier1UserGroups.Values))) {
            foreach ($Grp in $Groups) {
                if ($null -ne $Grp.id -and -not $AllGroupNameLookup.ContainsKey($Grp.id)) {
                    $AllGroupNameLookup[$Grp.id] = $Grp.displayName
                }
            }
        }

        # Filter Tier 0 groups: only keep groups that are assigned to at least one Intune scope tag
        $Tier0FilteredGroupIds = @()
        $Tier0FilteredGroupDetails = @()
        foreach ($GroupId in $Tier0UniqueGroupIds) {
            if ($GroupId -in $AllScopeTagGroupIds) {
                $Tier0FilteredGroupIds += $GroupId
                $GroupName = $AllGroupNameLookup[$GroupId]
                $MatchedTags = @($IntuneScopeTagAssignments | Where-Object { $_.GroupId -eq $GroupId })
                $EamTier = if ($Tier0DeviceUniqueGroupIds -contains $GroupId) { 'ControlPlane (device)' } else { 'ControlPlane (user)' }
                $Tier0FilteredGroupDetails += [PSCustomObject]@{
                    GroupId          = $GroupId
                    GroupName        = $GroupName
                    EAMTierLevelName = $EamTier
                    ScopeTagNames    = ($MatchedTags | Select-Object -Unique ScopeTagName | ForEach-Object { $_.ScopeTagName }) -join ', '
                }
            }
        }

        # Filter Tier 1 groups: only keep groups that are assigned to at least one Intune scope tag
        $Tier1FilteredGroupIds = @()
        $Tier1FilteredGroupDetails = @()
        foreach ($GroupId in $Tier1UniqueGroupIds) {
            if ($GroupId -in $AllScopeTagGroupIds) {
                $Tier1FilteredGroupIds += $GroupId
                $GroupName = $AllGroupNameLookup[$GroupId]
                $MatchedTags = @($IntuneScopeTagAssignments | Where-Object { $_.GroupId -eq $GroupId })
                $EamTier = if ($Tier1DeviceUniqueGroupIds -contains $GroupId) { 'ManagementPlane (device)' } else { 'ManagementPlane (user)' }
                $Tier1FilteredGroupDetails += [PSCustomObject]@{
                    GroupId          = $GroupId
                    GroupName        = $GroupName
                    EAMTierLevelName = $EamTier
                    ScopeTagNames    = ($MatchedTags | Select-Object -Unique ScopeTagName | ForEach-Object { $_.ScopeTagName }) -join ', '
                }
            }
        }

        # Display Tier 0 groups filtered by scope tag presence
        Write-Host ""
        Write-Host "  Tier 0 (ControlPlane) groups with scope tag assignments:" -ForegroundColor White
        if ($Tier0FilteredGroupDetails.Count -gt 0) {
            $Tier0FilteredGroupDetails | Sort-Object GroupName | ForEach-Object {
                if ($IncludeObjectDetails) {
                    Write-Host "    $($_.GroupName) ($($_.GroupId)) [EAMTierLevelName: $($_.EAMTierLevelName)] -> ScopeTag(s): $($_.ScopeTagNames)" -ForegroundColor DarkGreen
                } else {
                    Write-Host "    $($_.GroupId)" -ForegroundColor DarkGreen
                }
            }
        } else {
            Write-Host "    (none - no Tier 0 groups are assigned to any Intune scope tags)" -ForegroundColor Yellow
            $WarningMessages.Add([PSCustomObject]@{ Type = "DeviceMgmtScope"; Message = "No Tier 0 (ControlPlane) groups are assigned to any Intune scope tags" })
        }
        $Tier0SkippedGroups = @($Tier0UniqueGroupIds | Where-Object { $_ -notin $Tier0FilteredGroupIds })
        if ($Tier0SkippedGroups.Count -gt 0) {
            Write-Verbose "  Tier 0 groups skipped (no scope tag assignment):"
            foreach ($SkippedId in $Tier0SkippedGroups) {
                Write-Verbose "    $($AllGroupNameLookup[$SkippedId]) ($SkippedId)"
            }
        }

        # Display Tier 1 groups filtered by scope tag presence
        Write-Host "  Tier 1 (ManagementPlane) groups with scope tag assignments:" -ForegroundColor White
        if ($Tier1FilteredGroupDetails.Count -gt 0) {
            $Tier1FilteredGroupDetails | Sort-Object GroupName | ForEach-Object {
                if ($IncludeObjectDetails) {
                    Write-Host "    $($_.GroupName) ($($_.GroupId)) [EAMTierLevelName: $($_.EAMTierLevelName)] -> ScopeTag(s): $($_.ScopeTagNames)" -ForegroundColor DarkGreen
                } else {
                    Write-Host "    $($_.GroupId)" -ForegroundColor DarkGreen
                }
            }
        } else {
            Write-Host "    (none - no Tier 1 groups are assigned to any Intune scope tags)" -ForegroundColor Yellow
            $WarningMessages.Add([PSCustomObject]@{ Type = "DeviceMgmtScope"; Message = "No Tier 1 (ManagementPlane) groups are assigned to any Intune scope tags" })
        }
        $Tier1SkippedGroups = @($Tier1UniqueGroupIds | Where-Object { $_ -notin $Tier1FilteredGroupIds })
        if ($Tier1SkippedGroups.Count -gt 0) {
            Write-Verbose "  Tier 1 groups skipped (no scope tag assignment):"
            foreach ($SkippedId in $Tier1SkippedGroups) {
                Write-Verbose "    $($AllGroupNameLookup[$SkippedId]) ($SkippedId)"
            }
        }
        #endregion

        #region Replace placeholders in DeviceManagement classification parameter file
        Write-Host ""
        Write-Host "---------------------------------------------------------" -ForegroundColor DarkCyan
        Write-Host " Replacing DeviceManagement Scope Placeholders (GroupIds)" -ForegroundColor DarkCyan
        Write-Host "---------------------------------------------------------" -ForegroundColor DarkCyan

        # Replace <Tier0IncludedGroupIds> with Tier 0 group IDs (filtered by scope tag presence)
        if ($Tier0FilteredGroupIds.Count -gt 0) {
            $Tier0GroupIdsJSON = ($Tier0FilteredGroupIds | Sort-Object -Unique | ForEach-Object { "`"$_`"" }) -join ', '
            $DeviceMgmtRoleClassification = $DeviceMgmtRoleClassification.replace('"<Tier0IncludedGroupIds>"', $Tier0GroupIdsJSON)
            $DeviceMgmtRoleClassification = $DeviceMgmtRoleClassification.replace('<Tier0IncludedGroupIds>', $Tier0GroupIdsJSON)
            Write-Host "  <Tier0IncludedGroupIds> -> $Tier0GroupIdsJSON" -ForegroundColor DarkGreen
            $ScopeSummary.Add([PSCustomObject]@{ Placeholder = 'Tier0IncludedGroupIds'; Entries = $Tier0FilteredGroupIds.Count; IncludesDirectory = $false; Status = 'Updated (GroupIds)' })
        } else {
            Write-Warning "  No Tier 0 groups with scope tag assignments found - placeholder cleared."
            $WarningMessages.Add([PSCustomObject]@{ Type = "EmptyScope"; Message = "No Tier 0 groups with scope tag assignments found - Tier0IncludedGroupIds placeholder cleared" })
            $DeviceMgmtRoleClassification = $DeviceMgmtRoleClassification.replace('"<Tier0IncludedGroupIds>",', '')
            $DeviceMgmtRoleClassification = $DeviceMgmtRoleClassification.replace('"<Tier0IncludedGroupIds>"', '')
            $DeviceMgmtRoleClassification = $DeviceMgmtRoleClassification.replace('<Tier0IncludedGroupIds>,', '')
            $DeviceMgmtRoleClassification = $DeviceMgmtRoleClassification.replace('<Tier0IncludedGroupIds>', '')
            $ScopeSummary.Add([PSCustomObject]@{ Placeholder = 'Tier0IncludedGroupIds'; Entries = 0; IncludesDirectory = $false; Status = 'Cleared' })
        }

        # Replace <Tier1IncludedGroupIds> with Tier 1 group IDs (filtered by scope tag presence)
        if ($Tier1FilteredGroupIds.Count -gt 0) {
            $Tier1GroupIdsJSON = ($Tier1FilteredGroupIds | Sort-Object -Unique | ForEach-Object { "`"$_`"" }) -join ', '
            $DeviceMgmtRoleClassification = $DeviceMgmtRoleClassification.replace('"<Tier1IncludedGroupIds>"', $Tier1GroupIdsJSON)
            $DeviceMgmtRoleClassification = $DeviceMgmtRoleClassification.replace('<Tier1IncludedGroupIds>', $Tier1GroupIdsJSON)
            Write-Host "  <Tier1IncludedGroupIds> -> $Tier1GroupIdsJSON" -ForegroundColor DarkGreen
            $ScopeSummary.Add([PSCustomObject]@{ Placeholder = 'Tier1IncludedGroupIds'; Entries = $Tier1FilteredGroupIds.Count; IncludesDirectory = $false; Status = 'Updated (GroupIds)' })
        } else {
            Write-Warning "  No Tier 1 groups with scope tag assignments found - placeholder cleared."
            $WarningMessages.Add([PSCustomObject]@{ Type = "EmptyScope"; Message = "No Tier 1 groups with scope tag assignments found - Tier1IncludedGroupIds placeholder cleared" })
            $DeviceMgmtRoleClassification = $DeviceMgmtRoleClassification.replace('"<Tier1IncludedGroupIds>",', '')
            $DeviceMgmtRoleClassification = $DeviceMgmtRoleClassification.replace('"<Tier1IncludedGroupIds>"', '')
            $DeviceMgmtRoleClassification = $DeviceMgmtRoleClassification.replace('<Tier1IncludedGroupIds>,', '')
            $DeviceMgmtRoleClassification = $DeviceMgmtRoleClassification.replace('<Tier1IncludedGroupIds>', '')
            $ScopeSummary.Add([PSCustomObject]@{ Placeholder = 'Tier1IncludedGroupIds'; Entries = 0; IncludesDirectory = $false; Status = 'Cleared' })
        }

        # Tier2EnterpriseDeviceScopeTagId is no longer needed - ManagementPlane uses "/*" wildcard
        # with ExcludedRoleAssignmentScopeName to cover all scopes not in Tier 0/1

        # Apply role action overwrites (down-/upgrade of individual role actions) to the generated classification
        $DeviceMgmtRoleClassificationDefinition = @($DeviceMgmtRoleClassification | ConvertFrom-Json -Depth 10)
        $DeviceMgmtRoleActionOverwrites = @((Import-EntraOpsClassificationOverwrites -RbacSystem "DeviceManagement").RoleActionOverwrites)
        if ($DeviceMgmtRoleActionOverwrites.Count -gt 0) {
            Write-Host "  Applying $($DeviceMgmtRoleActionOverwrites.Count) role action overwrite(s) from $((@($DeviceMgmtRoleActionOverwrites.SourceFile) | Sort-Object -Unique) -join ', ')..." -ForegroundColor Yellow
            $DeviceMgmtRoleClassificationDefinition = Invoke-EntraOpsClassificationActionOverwrite -ClassificationDefinition $DeviceMgmtRoleClassificationDefinition -RoleActionOverwrites $DeviceMgmtRoleActionOverwrites
        }
        $DeviceMgmtRoleClassificationDefinition | ConvertTo-Json -Depth 10 | Out-File -FilePath $DeviceMgmtCustomizedClassificationFile -Force
        Write-Host "  Output file: $DeviceMgmtCustomizedClassificationFile" -ForegroundColor Cyan
        #endregion

        #region DeviceManagement Summary: Groups and Devices
        Write-Host ""
        Write-Host "---------------------------------------------------------" -ForegroundColor DarkCyan
        Write-Host " DeviceManagement Classification Summary" -ForegroundColor DarkCyan
        Write-Host "---------------------------------------------------------" -ForegroundColor DarkCyan

        # Summary: all unique groups in scope with their EAMTierLevelName reason
        $AllTierGroupSummary = @()
        $AllTierGroupSummary += $Tier0DeviceGroups.Values | ForEach-Object { $_ } | Select-Object -Unique id, displayName | ForEach-Object {
            [PSCustomObject]@{ GroupName = $_.displayName; GroupId = $_.id; EAMTierLevelName = 'ControlPlane'; ObjectType = 'device' }
        }
        $AllTierGroupSummary += $Tier0UserGroups.Values | ForEach-Object { $_ } | Select-Object -Unique id, displayName | ForEach-Object {
            [PSCustomObject]@{ GroupName = $_.displayName; GroupId = $_.id; EAMTierLevelName = 'ControlPlane'; ObjectType = 'user' }
        }
        $AllTierGroupSummary += $Tier1DeviceGroups.Values | ForEach-Object { $_ } | Select-Object -Unique id, displayName | ForEach-Object {
            [PSCustomObject]@{ GroupName = $_.displayName; GroupId = $_.id; EAMTierLevelName = 'ManagementPlane'; ObjectType = 'device' }
        }
        $AllTierGroupSummary += $Tier1UserGroups.Values | ForEach-Object { $_ } | Select-Object -Unique id, displayName | ForEach-Object {
            [PSCustomObject]@{ GroupName = $_.displayName; GroupId = $_.id; EAMTierLevelName = 'ManagementPlane'; ObjectType = 'user' }
        }

        Write-Host ""
        Write-Host "  Groups in scope (reason = EAMTierLevelName of members):" -ForegroundColor White
        if ($AllTierGroupSummary.Count -gt 0) {
            $AllTierGroupSummary | Where-Object { $null -ne $_ } | Group-Object GroupId | Sort-Object { ($_.Group | Select-Object -First 1).EAMTierLevelName }, { ($_.Group | Select-Object -First 1).GroupName } | ForEach-Object {
                $EamLabels = ($_.Group | Select-Object -Unique EAMTierLevelName, ObjectType | ForEach-Object { "$($_.EAMTierLevelName) ($($_.ObjectType))" }) -join ', '
                $GroupEntry = $_.Group[0]
                if ($IncludeObjectDetails) {
                    Write-Host "    $($GroupEntry.GroupName) ($($GroupEntry.GroupId)) [EAMTierLevelName: $EamLabels]" -ForegroundColor DarkGreen
                } else {
                    Write-Host "    $($GroupEntry.GroupId)" -ForegroundColor DarkGreen
                }
            }
        } else {
            Write-Host "    (none)" -ForegroundColor DarkGray
        }

        # Verbose: per-device and per-user detail
        Write-Verbose "  Tier 0 (ControlPlane) device groups in scope:"
        if ($Tier0DeviceUniqueGroupIds.Count -gt 0) {
            $Tier0AllDeviceGroupDetails = $Tier0DeviceGroups.Values | ForEach-Object { $_ } | Select-Object -Unique id, displayName | Sort-Object displayName
            foreach ($Grp in $Tier0AllDeviceGroupDetails) {
                $DevicesInGroup = @($Tier0DeviceGroups.GetEnumerator() | Where-Object { $_.Value.id -contains $Grp.id } | ForEach-Object { $_.Key })
                Write-Verbose "    $($Grp.displayName) ($($Grp.id)) <- Devices: $($DevicesInGroup -join ', ')"
            }
        } else { Write-Verbose "    (none)" }

        Write-Verbose "  Tier 0 (ControlPlane) user groups in scope:"
        if ($Tier0UserUniqueGroupIds.Count -gt 0) {
            $Tier0AllUserGroupDetails = $Tier0UserGroups.Values | ForEach-Object { $_ } | Select-Object -Unique id, displayName | Sort-Object displayName
            foreach ($Grp in $Tier0AllUserGroupDetails) {
                $UsersInGroup = @($Tier0UserGroups.GetEnumerator() | Where-Object { $_.Value.id -contains $Grp.id } | ForEach-Object { $_.Key })
                Write-Verbose "    $($Grp.displayName) ($($Grp.id)) <- Users: $($UsersInGroup -join ', ')"
            }
        } else { Write-Verbose "    (none)" }

        Write-Verbose "  Tier 1 (ManagementPlane) device groups in scope:"
        if ($Tier1DeviceUniqueGroupIds.Count -gt 0) {
            $Tier1AllDeviceGroupDetails = $Tier1DeviceGroups.Values | ForEach-Object { $_ } | Select-Object -Unique id, displayName | Sort-Object displayName
            foreach ($Grp in $Tier1AllDeviceGroupDetails) {
                $DevicesInGroup = @($Tier1DeviceGroups.GetEnumerator() | Where-Object { $_.Value.id -contains $Grp.id } | ForEach-Object { $_.Key })
                Write-Verbose "    $($Grp.displayName) ($($Grp.id)) <- Devices: $($DevicesInGroup -join ', ')"
            }
        } else { Write-Verbose "    (none)" }

        Write-Verbose "  Tier 1 (ManagementPlane) user groups in scope:"
        if ($Tier1UserUniqueGroupIds.Count -gt 0) {
            $Tier1AllUserGroupDetails = $Tier1UserGroups.Values | ForEach-Object { $_ } | Select-Object -Unique id, displayName | Sort-Object displayName
            foreach ($Grp in $Tier1AllUserGroupDetails) {
                $UsersInGroup = @($Tier1UserGroups.GetEnumerator() | Where-Object { $_.Value.id -contains $Grp.id } | ForEach-Object { $_.Key })
                Write-Verbose "    $($Grp.displayName) ($($Grp.id)) <- Users: $($UsersInGroup -join ', ')"
            }
        } else { Write-Verbose "    (none)" }

        Write-Verbose "  Devices that led to classification (OwnedDevices + AssociatedPawDevice):"
        Write-Verbose "    Tier 0 (ControlPlane):"
        foreach ($User in $Tier0Users) {
            $UserOwnedDevs = @(if ($null -ne $User.OwnedDevices) { $User.OwnedDevices } else { @() })
            $UserPawDevs = @(if ($null -ne $User.AssociatedPawDevice) { $User.AssociatedPawDevice } else { @() })
            $AllUserDevs = @($UserOwnedDevs + $UserPawDevs | Select-Object -Unique)
            foreach ($DevId in $AllUserDevs) {
                $Source = @()
                if ($DevId -in $UserOwnedDevs) { $Source += 'Owned' }
                if ($DevId -in $UserPawDevs) { $Source += 'PAW' }
                $GroupNames = @($Tier0DeviceGroups[$DevId] | ForEach-Object { $_.displayName }) -join ', '
                $GroupLabel = if ($GroupNames) { " -> Groups: $GroupNames" } else { " -> (no group memberships found)" }
                Write-Verbose "      Device $DevId [$($Source -join ',')] (User: $($User.ObjectDisplayName))$GroupLabel"
            }
        }
        if ($Tier0DeviceIds.Count -eq 0) { Write-Verbose "      (none)" }

        Write-Verbose "    Tier 1 (ManagementPlane):"
        foreach ($User in $Tier1Users) {
            $UserOwnedDevs = @(if ($null -ne $User.OwnedDevices) { $User.OwnedDevices } else { @() })
            $UserPawDevs = @(if ($null -ne $User.AssociatedPawDevice) { $User.AssociatedPawDevice } else { @() })
            $AllUserDevs = @($UserOwnedDevs + $UserPawDevs | Select-Object -Unique | Where-Object { $_ -notin $Tier0DeviceIds })
            foreach ($DevId in $AllUserDevs) {
                $Source = @()
                if ($DevId -in $UserOwnedDevs) { $Source += 'Owned' }
                if ($DevId -in $UserPawDevs) { $Source += 'PAW' }
                $GroupNames = @($Tier1DeviceGroups[$DevId] | ForEach-Object { $_.displayName }) -join ', '
                $GroupLabel = if ($GroupNames) { " -> Groups: $GroupNames" } else { " -> (no group memberships found)" }
                Write-Verbose "      Device $DevId [$($Source -join ',')] (User: $($User.ObjectDisplayName))$GroupLabel"
            }
        }
        if ($Tier1DeviceIds.Count -eq 0) { Write-Verbose "      (none)" }
        Write-Host ""
        #endregion

        #region Persist group → device member mapping for BloodHound export
        Write-Host "---------------------------------------------------------" -ForegroundColor DarkCyan
        Write-Host " Persisting Group → Device Member Mapping" -ForegroundColor DarkCyan
        Write-Host "---------------------------------------------------------" -ForegroundColor DarkCyan

        # Collect all classified device IDs (Tier0 + Tier1)
        $AllClassifiedDeviceIds = @($Tier0DeviceIds + $Tier1DeviceIds | Select-Object -Unique)

        # Batch-resolve device display names
        $DeviceNameCache = @{}
        if ($AllClassifiedDeviceIds.Count -gt 0) {
            try {
                $Body = @{ ids = @($AllClassifiedDeviceIds); types = @("device") } | ConvertTo-Json -Depth 3
                $DeviceObjects = Invoke-EntraOpsMsGraphQuery -Method POST -Uri "https://graph.microsoft.com/beta/directoryObjects/getByIds" -Body $Body -OutputType PSObject
                foreach ($DevObj in $DeviceObjects) {
                    $DeviceNameCache[$DevObj.id] = $DevObj.displayName
                }
            } catch {
                Write-Warning "Failed to batch-resolve device display names: $($_.Exception.Message)"
            }
            # Fallback for unresolved IDs
            foreach ($DevId in $AllClassifiedDeviceIds) {
                if (-not $DeviceNameCache.ContainsKey($DevId)) {
                    $DeviceNameCache[$DevId] = $DevId
                }
            }
        }

        # Build reverse mapping: groupId → device members
        $GroupDeviceMembers = @{}
        foreach ($DeviceGroupsMap in @($Tier0DeviceGroups, $Tier1DeviceGroups)) {
            foreach ($entry in $DeviceGroupsMap.GetEnumerator()) {
                $deviceId = $entry.Key
                $deviceName = $DeviceNameCache[$deviceId] ?? $deviceId
                foreach ($grp in $entry.Value) {
                    $grpId = $grp.id
                    if (-not $GroupDeviceMembers.ContainsKey($grpId)) {
                        $GroupDeviceMembers[$grpId] = [PSCustomObject]@{
                            displayName   = $grp.displayName
                            deviceMembers = [System.Collections.Generic.List[PSCustomObject]]::new()
                        }
                    }
                    # Avoid duplicate devices in the same group
                    if (-not ($GroupDeviceMembers[$grpId].deviceMembers | Where-Object { $_.id -eq $deviceId })) {
                        $GroupDeviceMembers[$grpId].deviceMembers.Add([PSCustomObject]@{
                                id          = $deviceId
                                displayName = $deviceName
                            })
                    }
                }
            }
        }

        # Build allClassifiedDevices flat list (sorted by id for deterministic output - see note below)
        $AllClassifiedDevices = @($AllClassifiedDeviceIds | Sort-Object | ForEach-Object {
                [PSCustomObject]@{
                    id          = $_
                    displayName = $DeviceNameCache[$_] ?? $_
                }
            })

        # Serialize groupDeviceMembers with a stable (sorted) key/member order. PowerShell Hashtable
        # enumeration order for string keys is randomized per process (.NET string-hash-randomization
        # security hardening), so iterating $GroupDeviceMembers (or the $Tier0DeviceGroups/
        # $Tier1DeviceGroups hashtables used to build it) directly would reorder the JSON output on
        # every run even when the underlying group/device membership is unchanged - producing a
        # spurious diff (and an unnecessary commit) in the Pull-EntraOpsPrivilegedEAM workflow every
        # time it runs. Sort explicitly here so the output is stable across runs when the actual data
        # is unchanged.
        $OrderedGroupDeviceMembers = [ordered]@{}
        foreach ($grpId in ($GroupDeviceMembers.Keys | Sort-Object)) {
            $GroupEntry = $GroupDeviceMembers[$grpId]
            $OrderedGroupDeviceMembers[$grpId] = [PSCustomObject]@{
                displayName   = $GroupEntry.displayName
                deviceMembers = @($GroupEntry.deviceMembers | Sort-Object id)
            }
        }

        # Save to JSON alongside the classification file
        $DeviceMembersOutputFile = Join-Path (Split-Path $DeviceMgmtCustomizedClassificationFile -Parent) "DeviceManagement_ScopeGroupDeviceMembers.json"
        $DeviceMembersPayload = [PSCustomObject]@{
            groupDeviceMembers   = $OrderedGroupDeviceMembers
            allClassifiedDevices = $AllClassifiedDevices
        }
        $DeviceMembersPayload | ConvertTo-Json -Depth 5 | Out-File -FilePath $DeviceMembersOutputFile -Force
        Write-Host "  Persisted group → device mapping: $($GroupDeviceMembers.Count) group(s), $($AllClassifiedDevices.Count) device(s)" -ForegroundColor Green
        Write-Host "  Output file: $DeviceMembersOutputFile" -ForegroundColor Cyan
        Write-Host ""
        #endregion

        #region Persist WHY each group is Tier0/Tier1 and whether it matched an Intune scope tag
        # Mirrors the "Groups in scope" / "groups with scope tag assignments" console summaries above, so this
        # is available for later auditing instead of only being visible in the console/job log at generation time.
        $ScopeTagLookup = @{}
        foreach ($Detail in (@($Tier0FilteredGroupDetails) + @($Tier1FilteredGroupDetails))) {
            if ($null -eq $Detail) { continue }
            $ScopeTagLookup[$Detail.GroupId] = $Detail.ScopeTagNames
        }
        # GroupId breaks ties for groups sharing the same EAMTierLevelName/GroupName (duplicate group names are allowed in Entra ID).
        $DeviceMgmtGroupReasoning = @($AllTierGroupSummary | Where-Object { $null -ne $_ } | Group-Object GroupId | Sort-Object { ($_.Group | Select-Object -First 1).EAMTierLevelName }, { ($_.Group | Select-Object -First 1).GroupName }, Name | ForEach-Object {
                $GroupEntry = $_.Group[0]
                [PSCustomObject]@{
                    GroupId                  = $GroupEntry.GroupId
                    GroupName                = $GroupEntry.GroupName
                    EAMTierLevelName         = @($_.Group | Select-Object -Unique EAMTierLevelName, ObjectType | ForEach-Object { "$($_.EAMTierLevelName) ($($_.ObjectType))" })
                    IncludedInScopeTagFilter = $ScopeTagLookup.ContainsKey($GroupEntry.GroupId)
                    MatchedIntuneScopeTags   = if ($ScopeTagLookup.ContainsKey($GroupEntry.GroupId)) { $ScopeTagLookup[$GroupEntry.GroupId] } else { $null }
                }
            })
        $DeviceMgmtGroupReasoningFile = Join-Path (Split-Path $DeviceMgmtCustomizedClassificationFile -Parent) "ScopeReasoning_DeviceManagement.json"
        $DeviceMgmtGroupReasoningPayload = [PSCustomObject]@{
            Groups = $DeviceMgmtGroupReasoning
        }
        $DeviceMgmtGroupReasoningPayload | ConvertTo-Json -Depth 5 | Out-File -FilePath $DeviceMgmtGroupReasoningFile -Force
        Write-Host "  Group scope reasoning file: $DeviceMgmtGroupReasoningFile" -ForegroundColor Cyan
        Write-Host ""
        #endregion

    } # end if DeviceManagement
    #endregion

    #region Template-based RBAC systems without scope placeholders (ResourceApps)
    # These RBAC systems have no *.Param.json parameter files. A tenant-specific classification file is only
    # generated from the shipped template when overwrites for the RBAC system exist in the tenant-specific
    # classification folder. Without overwrites, the classification cmdlets keep using the shipped template via
    # their default path resolution.
    # Uses the shared EAMTierLevelName/TierLevelDefinition[] schema (same as Azure/Defender/DeviceManagement/
    # AadResources - ResourceApps entries additionally carry ResourceAppId/ResourceScope), handled by
    # Invoke-EntraOpsClassificationActionOverwrite. ResourceApps (API permissions) is customized via the
    # schema-aligned Classification_ApiPermissionOverwrites.json (matches Classification_ApiPermissions.json's own
    # PermissionValue/PermissionType/TargetAppId/Category shape instead of the RoleDefinitionActions/scope-pattern
    # shape). IdentityGovernance moved to its own scope parameterization region below (per-catalog/access package
    # tier scoping), with a template-only fallback when Classification_IdentityGovernance.Param.json is missing.
    $TemplateOnlyParameterScopes = @(
        [PSCustomObject]@{ RbacSystem = 'ResourceApps'; TemplateFile = $ResourceAppsClassificationTemplateFile; OutputFile = $ResourceAppsCustomizedClassificationFile; OverwriteProperty = 'ApiPermissionOverwrites' }
    )
    foreach ($TemplateParameterScope in $TemplateOnlyParameterScopes) {
        if ($ClassificationParameterScope -notcontains $TemplateParameterScope.RbacSystem) { continue }
        $TemplateOverwrites = @((Import-EntraOpsClassificationOverwrites -RbacSystem $TemplateParameterScope.RbacSystem).($TemplateParameterScope.OverwriteProperty))
        if ($TemplateOverwrites.Count -eq 0) {
            Write-Verbose "No overwrites for $($TemplateParameterScope.RbacSystem) - tenant-specific classification file will not be generated."
            continue
        }
        Write-Host ""
        Write-Host "=========================================================" -ForegroundColor Cyan
        Write-Host " $($TemplateParameterScope.RbacSystem) RBAC - Classification Overwrite Update" -ForegroundColor Cyan
        Write-Host "=========================================================" -ForegroundColor Cyan
        if (-not (Test-Path -Path $TemplateParameterScope.TemplateFile)) {
            Write-Warning "  Classification template file not found: $($TemplateParameterScope.TemplateFile)"
            $WarningMessages.Add([PSCustomObject]@{ Type = "MissingTemplateFile"; Message = "Classification template file for $($TemplateParameterScope.RbacSystem) not found: $($TemplateParameterScope.TemplateFile)" })
            continue
        }
        $TemplateClassificationDefinition = @(Get-Content -Path $TemplateParameterScope.TemplateFile -Raw | ConvertFrom-Json -Depth 10)
        Write-Host "  Applying $($TemplateOverwrites.Count) classification overwrite(s)..." -ForegroundColor Yellow
        $TemplateClassificationDefinition = Invoke-EntraOpsClassificationActionOverwrite -ClassificationDefinition $TemplateClassificationDefinition -RoleActionOverwrites $TemplateOverwrites
        $TemplateClassificationDefinition | ConvertTo-Json -Depth 10 | Out-File -FilePath $TemplateParameterScope.OutputFile -Force
        Write-Host "  Output file: $($TemplateParameterScope.OutputFile)" -ForegroundColor Cyan
    }
    #endregion

    #region Shared Azure Resource/Subscription Scope (reused by Defender, Azure and IdentityGovernance RBAC parameterization)
    # Computed once so that Defender, Azure and IdentityGovernance RBAC parameterization below reuse the same
    # Exposure Management and Azure Resource Graph managed-identity discovery, instead of issuing duplicate queries.
    # IdentityGovernance needs the Tier0/Tier1 resource scope buckets to classify Azure resources (subscriptions,
    # resource groups, ...) that have been onboarded to access package catalogs.
    $SharedAzureResourceScope = $null
    if ($ClassificationParameterScope -contains "Defender" -or $ClassificationParameterScope -contains "Azure" -or $ClassificationParameterScope -contains "IdentityGovernance") {
        Write-Host ""
        Write-Host "=========================================================" -ForegroundColor Cyan
        Write-Host " Resolving Shared Azure Resource/Subscription Scope" -ForegroundColor Cyan
        Write-Host " (reused by Defender and Azure RBAC parameterization)" -ForegroundColor Cyan
        Write-Host "=========================================================" -ForegroundColor Cyan
        $SharedAzureResourceScope = Get-EntraOpsClassificationAzureResourceScope -EntraOpsEamFolder $EntraOpsEamFolder -EntraOpsScopes $EntraOpsScopes -ExposureCriticalityLevel $ExposureCriticalityLevel -WarningMessages $WarningMessages
        Write-Host "  Tier 0 (ControlPlane) resources    : $($SharedAzureResourceScope.Tier0ResourceScope.Count) scope path(s)" -ForegroundColor Gray
        Write-Host "  Tier 1 (ManagementPlane) resources : $($SharedAzureResourceScope.Tier1ResourceScope.Count) scope path(s)" -ForegroundColor Gray
        Write-Host "  All subscriptions                  : $($SharedAzureResourceScope.AllSubscriptionScope.Count)" -ForegroundColor Gray
        Write-Host ""
    }
    #endregion

    #region IdentityGovernance RBAC Classification Parameter Scope
    if ($ClassificationParameterScope -contains "IdentityGovernance") {
        Write-Host ""
        Write-Host "=========================================================" -ForegroundColor Cyan
        Write-Host " Identity Governance RBAC - Scope Parameter Update" -ForegroundColor Cyan
        Write-Host "=========================================================" -ForegroundColor Cyan

        if (-not (Test-Path -Path $IdGovClassificationParameterFile)) {
            # Fallback to the previous template-only behavior: a tenant-specific classification file is only
            # generated from the shipped template when role action overwrites exist.
            Write-Warning "  Identity Governance classification parameter file not found: $IdGovClassificationParameterFile - falling back to template-only overwrite handling (no per-catalog scope tiering)."
            $WarningMessages.Add([PSCustomObject]@{ Type = "MissingTemplateFile"; Message = "Identity Governance classification parameter file not found: $IdGovClassificationParameterFile - fell back to template-only overwrite handling" })
            $IdGovTemplateOverwrites = @((Import-EntraOpsClassificationOverwrites -RbacSystem "IdentityGovernance").RoleActionOverwrites)
            if ($IdGovTemplateOverwrites.Count -gt 0 -and (Test-Path -Path $IdGovClassificationTemplateFile)) {
                $IdGovTemplateDefinition = @(Get-Content -Path $IdGovClassificationTemplateFile -Raw | ConvertFrom-Json -Depth 10)
                Write-Host "  Applying $($IdGovTemplateOverwrites.Count) classification overwrite(s)..." -ForegroundColor Yellow
                $IdGovTemplateDefinition = Invoke-EntraOpsClassificationActionOverwrite -ClassificationDefinition $IdGovTemplateDefinition -RoleActionOverwrites $IdGovTemplateOverwrites
                $IdGovTemplateDefinition | ConvertTo-Json -Depth 10 | Out-File -FilePath $IdGovCustomizedClassificationFile -Force
                Write-Host "  Output file: $IdGovCustomizedClassificationFile" -ForegroundColor Cyan
            }
        } else {
            $IdGovRoleClassification = Get-Content -Path $IdGovClassificationParameterFile -Raw

            # Reuse the shared Azure resource/subscription scope resolved earlier (needed to classify Azure
            # resources onboarded to catalogs); resolve it lazily if the shared block did not run.
            if ($null -eq $SharedAzureResourceScope) {
                $SharedAzureResourceScope = Get-EntraOpsClassificationAzureResourceScope -EntraOpsEamFolder $EntraOpsEamFolder -EntraOpsScopes $EntraOpsScopes -ExposureCriticalityLevel $ExposureCriticalityLevel -WarningMessages $WarningMessages
            }

            Write-Host "---------------------------------------------------------" -ForegroundColor DarkCyan
            Write-Host " Classifying Access Package Catalogs and Access Packages" -ForegroundColor DarkCyan
            Write-Host "---------------------------------------------------------" -ForegroundColor DarkCyan
            Write-Host "  Each catalog/access package scope is tiered by the most privileged resource assigned to it" -ForegroundColor Gray
            Write-Host "  (groups by their EntraOps classification, directory roles by EntraID/default classification," -ForegroundColor Gray
            Write-Host "  API permissions from access packages, Azure resources by Tier0/Tier1 resource scope)." -ForegroundColor Gray
            Write-Host "  Unclassifiable scopes stay Tier0 (ControlPlane) - conservative default." -ForegroundColor Gray

            $IdGovScopeClassifications = @(Get-EntraOpsIdGovScopeClassification -EntraOpsEamFolder $EntraOpsEamFolder -FolderClassification $DefaultFolderClassification -AzureResourceTierScope $SharedAzureResourceScope -WarningMessages $WarningMessages)

            $Tier0IdGovScope = @($IdGovScopeClassifications | Where-Object { $_.ResultingScope -eq "Tier0" } | Select-Object -ExpandProperty ScopeId | Sort-Object -Unique)
            $Tier1IdGovScope = @($IdGovScopeClassifications | Where-Object { $_.ResultingScope -eq "Tier1" } | Select-Object -ExpandProperty ScopeId | Sort-Object -Unique)
            $Tier2IdGovScope = @($IdGovScopeClassifications | Where-Object { $_.ResultingScope -eq "Tier2" } | Select-Object -ExpandProperty ScopeId | Sort-Object -Unique)
            # ControlPlane keeps matching every catalog/access package by wildcard (conservative default for
            # unknown/new scopes between classification runs) - only scopes affirmatively classified as Tier1 or
            # Tier2 are excluded from it and served by their own tier entries instead.
            $Tier0ExcludedIdGovScope = @($Tier1IdGovScope + $Tier2IdGovScope | Sort-Object -Unique)

            Write-Host ""
            Write-Host "  Tier0 (ControlPlane) scopes     : $($Tier0IdGovScope.Count) (matched by wildcard, no exclusion)" -ForegroundColor Gray
            Write-Host "  Tier1 (ManagementPlane) scopes  : $($Tier1IdGovScope.Count)" -ForegroundColor Gray
            Write-Host "  Tier2 (UserAccess) scopes       : $($Tier2IdGovScope.Count)" -ForegroundColor Gray

            #region Replace placeholders in IdentityGovernance classification parameter file
            $Tier0ExcludedIdGovScopeJSON = ($Tier0ExcludedIdGovScope | ForEach-Object { "`"$_`"" }) -join ", "
            $Tier1IdGovScopeJSON = ($Tier1IdGovScope | ForEach-Object { "`"$_`"" }) -join ", "
            $Tier2IdGovScopeJSON = ($Tier2IdGovScope | ForEach-Object { "`"$_`"" }) -join ", "
            $IdGovRoleClassification = $IdGovRoleClassification.replace('<Tier0ExcludedIdGovScope>', $Tier0ExcludedIdGovScopeJSON)
            $IdGovRoleClassification = $IdGovRoleClassification.replace('<Tier1IncludedIdGovScope>', $Tier1IdGovScopeJSON)
            $IdGovRoleClassification = $IdGovRoleClassification.replace('<Tier2IncludedIdGovScope>', $Tier2IdGovScopeJSON)
            $ScopeSummary.Add([PSCustomObject]@{ Placeholder = 'IdGov:Tier0ExcludedIdGovScope'; Entries = $Tier0ExcludedIdGovScope.Count; IncludesDirectory = $false; Status = 'Updated' })
            $ScopeSummary.Add([PSCustomObject]@{ Placeholder = 'IdGov:Tier1IncludedIdGovScope'; Entries = $Tier1IdGovScope.Count; IncludesDirectory = $false; Status = 'Updated' })
            $ScopeSummary.Add([PSCustomObject]@{ Placeholder = 'IdGov:Tier2IncludedIdGovScope'; Entries = $Tier2IdGovScope.Count; IncludesDirectory = $false; Status = 'Updated' })

            $IdGovClassificationDefinition = @($IdGovRoleClassification | ConvertFrom-Json -Depth 10)

            # Apply role action overwrites (down-/upgrade of individual role actions) to the generated
            # classification. Applied AFTER placeholder substitution, so overwrites match against the actual
            # resolved catalog/access package scope IDs, not the raw placeholder tokens. The same placeholder
            # tokens are also resolved inside overwrite scope entries (mirrors the Azure parameterization).
            $IdGovRoleActionOverwrites = @((Import-EntraOpsClassificationOverwrites -RbacSystem "IdentityGovernance").RoleActionOverwrites)
            if ($IdGovRoleActionOverwrites.Count -gt 0) {
                foreach ($Overwrite in $IdGovRoleActionOverwrites) {
                    $ResolvedScopes = [System.Collections.Generic.List[string]]::new()
                    foreach ($ScopeEntry in @($Overwrite.RoleAssignmentScopeName)) {
                        switch ($ScopeEntry) {
                            '<Tier0ExcludedIdGovScope>' { foreach ($Path in $Tier0ExcludedIdGovScope) { $ResolvedScopes.Add($Path) | Out-Null } }
                            '<Tier1IncludedIdGovScope>' { foreach ($Path in $Tier1IdGovScope) { $ResolvedScopes.Add($Path) | Out-Null } }
                            '<Tier2IncludedIdGovScope>' { foreach ($Path in $Tier2IdGovScope) { $ResolvedScopes.Add($Path) | Out-Null } }
                            default { $ResolvedScopes.Add($ScopeEntry) | Out-Null }
                        }
                    }
                    $Overwrite.RoleAssignmentScopeName = @($ResolvedScopes | Select-Object -Unique)
                }
                Write-Host "  Applying $($IdGovRoleActionOverwrites.Count) role action overwrite(s) from $((@($IdGovRoleActionOverwrites.SourceFile) | Sort-Object -Unique) -join ', ')..." -ForegroundColor Yellow
                $IdGovClassificationDefinition = Invoke-EntraOpsClassificationActionOverwrite -ClassificationDefinition $IdGovClassificationDefinition -RoleActionOverwrites $IdGovRoleActionOverwrites
            }

            # Ensure output directory exists
            $IdGovOutputDir = Split-Path $IdGovCustomizedClassificationFile -Parent
            if (-not (Test-Path -Path $IdGovOutputDir)) {
                New-Item -Path $IdGovOutputDir -ItemType Directory -Force | Out-Null
            }
            $IdGovClassificationDefinition | ConvertTo-Json -Depth 10 | Out-File -FilePath $IdGovCustomizedClassificationFile -Force
            Write-Host "  Output file: $IdGovCustomizedClassificationFile" -ForegroundColor Cyan

            # Persist WHY each catalog/access package scope was classified as Control, Management or User Access
            # (ScopeName/ScopeId/Source/EAMTier/ResultingScope/Reason - same structure as ScopeReasoning_Azure.json,
            # with ScopeName/ScopeId instead of ResourceName/ResourceId), so this is available for later auditing
            # instead of only being visible in the console/job log at generation time.
            $IdGovScopeReasoningFile = Join-Path -Path $IdGovOutputDir -ChildPath "ScopeReasoning_IdentityGovernance.json"
            $IdGovScopeReasoningPayload = [PSCustomObject]@{
                Tier0Scope   = $Tier0IdGovScope
                Tier1Scope   = $Tier1IdGovScope
                Tier2Scope   = $Tier2IdGovScope
                # ScopeId breaks ties for scopes sharing the same ScopeType/ScopeName (e.g. two access packages with an identical name in different catalogs).
                ScopeDetails = @($IdGovScopeClassifications | Sort-Object ScopeType, ScopeName, ScopeId | ForEach-Object {
                        [PSCustomObject]@{
                            ScopeName           = $_.ScopeName
                            ScopeId             = $_.ScopeId
                            ScopeType           = $_.ScopeType
                            CatalogDisplayName  = $_.CatalogDisplayName
                            Source              = $_.Source
                            EAMTier             = $_.EAMTier
                            ResultingScope      = $_.ResultingScope
                            Reason              = $_.Reason
                            ClassifiedResources = @($_.ClassifiedResources)
                        }
                    })
            }
            $IdGovScopeReasoningPayload | ConvertTo-Json -Depth 6 | Out-File -FilePath $IdGovScopeReasoningFile -Force
            Write-Host "  Scope reasoning file: $IdGovScopeReasoningFile" -ForegroundColor Cyan
            #endregion

            #region IdentityGovernance RBAC Classification Summary
            Write-Host ""
            Write-Host "---------------------------------------------------------" -ForegroundColor DarkCyan
            Write-Host " Identity Governance RBAC Classification Summary" -ForegroundColor DarkCyan
            Write-Host "---------------------------------------------------------" -ForegroundColor DarkCyan
            if ($IdGovScopeClassifications.Count -gt 0) {
                $IdGovScopeClassifications | Group-Object ScopeType | Sort-Object Name | ForEach-Object {
                    Write-Host "  [$($_.Name)] ($($_.Count) scope(s))" -ForegroundColor DarkCyan
                    $_.Group | Sort-Object ResultingScope, ScopeName | ForEach-Object {
                        if ($IncludeObjectDetails) {
                            $Color = switch ($_.ResultingScope) { "Tier0" { 'DarkGreen' } "Tier1" { 'Yellow' } default { 'Gray' } }
                            Write-Host "    $($_.ScopeName) [EAM: $($_.EAMTier) -> $($_.ResultingScope) scope]" -ForegroundColor $Color
                            Write-Host "      Reason : $($_.Reason)" -ForegroundColor DarkGray
                            Write-Host "      ScopeId: $($_.ScopeId)" -ForegroundColor DarkGray
                        } else {
                            Write-Host "    $($_.ScopeId)" -ForegroundColor DarkGray
                        }
                    }
                }
            } else {
                Write-Host "  (no catalogs/access packages identified - ControlPlane wildcard default remains in effect)" -ForegroundColor Yellow
            }
            Write-Host ""
            #endregion
        }
    } # end if IdentityGovernance
    #endregion

    #region Defender RBAC Classification Parameter Scope
    if ($ClassificationParameterScope -contains "Defender") {
        Write-Host ""
        Write-Host "=========================================================" -ForegroundColor Cyan
        Write-Host " Microsoft Defender RBAC - Scope Parameter Update" -ForegroundColor Cyan
        Write-Host "=========================================================" -ForegroundColor Cyan

        if (-not (Test-Path -Path $DefenderClassificationParameterFile)) {
            Write-Warning "  Defender classification parameter file not found: $DefenderClassificationParameterFile"
            $WarningMessages.Add([PSCustomObject]@{ Type = "MissingTemplateFile"; Message = "Defender classification parameter file not found: $DefenderClassificationParameterFile" })
        } else {
            $DefenderRoleClassification = Get-Content -Path $DefenderClassificationParameterFile -Raw

            Write-Host "---------------------------------------------------------" -ForegroundColor DarkCyan
            Write-Host " Resolving Defender for Cloud Resource/Subscription Scope" -ForegroundColor DarkCyan
            Write-Host "---------------------------------------------------------" -ForegroundColor DarkCyan
            Write-Host "  Only Security posture / Posture management actions (microsoft.xdr/securityposture/*) are" -ForegroundColor Gray
            Write-Host "  genuinely scopable per Defender for Cloud subscription/resource-group/resource; tenant-wide" -ForegroundColor Gray
            Write-Host "  configuration/authorization/dataops actions remain governed at directory scope '/' only." -ForegroundColor Gray

            $Tier0IncludedResourceScope = $SharedAzureResourceScope.Tier0ResourceScope
            $Tier1IncludedResourceScope = $SharedAzureResourceScope.Tier1ResourceScope

            Write-Host "  Tier 0 (ControlPlane) resource scope    : $($Tier0IncludedResourceScope.Count) entrie(s)" -ForegroundColor Gray
            Write-Host "  Tier 1 (ManagementPlane) resource scope : $($Tier1IncludedResourceScope.Count) entrie(s)" -ForegroundColor Gray

            $Tier0ScopeJSON = ($Tier0IncludedResourceScope | ForEach-Object { "`"$_`"" }) -join ", "
            $DefenderRoleClassification = $DefenderRoleClassification.replace('<Tier0IncludedResourceScope>', $Tier0ScopeJSON)
            $ScopeSummary.Add([PSCustomObject]@{ Placeholder = 'Defender:Tier0IncludedResourceScope'; Entries = $Tier0IncludedResourceScope.Count; IncludesDirectory = ($Tier0IncludedResourceScope -contains '/'); Status = 'Updated' })

            if ($Tier1IncludedResourceScope.Count -gt 0) {
                $Tier1ScopeJSON = ($Tier1IncludedResourceScope | ForEach-Object { "`"$_`"" }) -join ", "
                $DefenderRoleClassification = $DefenderRoleClassification.replace('<Tier1IncludedResourceScope>', $Tier1ScopeJSON)
                $ScopeSummary.Add([PSCustomObject]@{ Placeholder = 'Defender:Tier1IncludedResourceScope'; Entries = $Tier1IncludedResourceScope.Count; IncludesDirectory = $false; Status = 'Updated' })
            } else {
                Write-Warning "  No Tier 1 (ManagementPlane) resources found for Defender scope - placeholder cleared."
                $WarningMessages.Add([PSCustomObject]@{ Type = "EmptyScope"; Message = "No Tier 1 (ManagementPlane) resources found - Defender Tier1IncludedResourceScope placeholder cleared" })
                # Remove the placeholder along with a preceding comma (e.g. after Tier0IncludedResourceScope) or a
                # following comma, so the surrounding JSON array is never left with a dangling/leading comma.
                $DefenderRoleClassification = $DefenderRoleClassification -replace '\s*,\s*"?<Tier1IncludedResourceScope>"?', ''
                $DefenderRoleClassification = $DefenderRoleClassification -replace '"?<Tier1IncludedResourceScope>"?\s*,\s*', ''
                $DefenderRoleClassification = $DefenderRoleClassification -replace '"?<Tier1IncludedResourceScope>"?', ''
                $ScopeSummary.Add([PSCustomObject]@{ Placeholder = 'Defender:Tier1IncludedResourceScope'; Entries = 0; IncludesDirectory = $false; Status = 'Cleared' })
            }

            # Apply role action overwrites (down-/upgrade of individual role actions) to the generated classification
            $DefenderRoleClassificationDefinition = @($DefenderRoleClassification | ConvertFrom-Json -Depth 10)
            $DefenderRoleActionOverwrites = @((Import-EntraOpsClassificationOverwrites -RbacSystem "Defender").RoleActionOverwrites)
            if ($DefenderRoleActionOverwrites.Count -gt 0) {
                Write-Host "  Applying $($DefenderRoleActionOverwrites.Count) role action overwrite(s) from $((@($DefenderRoleActionOverwrites.SourceFile) | Sort-Object -Unique) -join ', ')..." -ForegroundColor Yellow
                $DefenderRoleClassificationDefinition = Invoke-EntraOpsClassificationActionOverwrite -ClassificationDefinition $DefenderRoleClassificationDefinition -RoleActionOverwrites $DefenderRoleActionOverwrites
            }

            # Ensure output directory exists
            $DefenderOutputDir = Split-Path $DefenderCustomizedClassificationFile -Parent
            if (-not (Test-Path -Path $DefenderOutputDir)) {
                New-Item -Path $DefenderOutputDir -ItemType Directory -Force | Out-Null
            }
            $DefenderRoleClassificationDefinition | ConvertTo-Json -Depth 10 | Out-File -FilePath $DefenderCustomizedClassificationFile -Force
            Write-Host "  Output file: $DefenderCustomizedClassificationFile" -ForegroundColor Cyan

            $DefenderCloudSetAssignments = [System.Collections.Generic.List[psobject]]::new()
            $DefenderEamFile = Join-Path -Path (Join-Path -Path $EntraOpsEamFolder -ChildPath 'Defender') -ChildPath 'Defender.json'
            if (Test-Path -LiteralPath $DefenderEamFile) {
                try {
                    $DefenderEamObjects = @(Get-Content -LiteralPath $DefenderEamFile -Raw | ConvertFrom-Json -Depth 10)
                    foreach ($DefenderEamObject in $DefenderEamObjects) {
                        foreach ($RoleAssignment in @($DefenderEamObject.RoleAssignments)) {
                            if ("$($RoleAssignment.RoleAssignmentScopeId)" -notmatch '(?i)^/cloudset/') { continue }
                            $SubscriptionScopes = if ($RoleAssignment.PSObject.Properties.Name -contains 'CloudSetSubscriptionScopes') { @($RoleAssignment.CloudSetSubscriptionScopes | Where-Object { -not [string]::IsNullOrWhiteSpace("$_") }) } else { @() }
                            $ResolutionStatus = if ($RoleAssignment.PSObject.Properties.Name -contains 'ScopeResolutionStatus') { "$($RoleAssignment.ScopeResolutionStatus)" } else { 'Unresolved' }
                            $DefenderCloudSetAssignments.Add([PSCustomObject]@{
                                    CloudSetId         = "$($RoleAssignment.RoleAssignmentScopeId)"
                                    CloudSetName       = "$($RoleAssignment.RoleAssignmentScopeName)"
                                    SubscriptionScopes = $SubscriptionScopes
                                    ResolutionStatus   = $ResolutionStatus
                                }) | Out-Null
                        }
                    }
                } catch {
                    $WarningMessage = "Failed to read Defender CloudSet assignments from '$DefenderEamFile': $($_.Exception.Message)"
                    Write-Warning $WarningMessage
                    $WarningMessages.Add([PSCustomObject]@{ Type = 'CloudSetReasoningReadError'; Message = $WarningMessage })
                }
            }

            $CloudSetReasoning = @($DefenderCloudSetAssignments | Group-Object CloudSetId | Sort-Object Name | ForEach-Object {
                    $CloudSetAssignments = @($_.Group)
                    $SubscriptionScopes = @($CloudSetAssignments.SubscriptionScopes | Sort-Object -Unique)
                    $Tier0SubscriptionScopes = @($SubscriptionScopes | Where-Object { $Tier0IncludedResourceScope -contains $_ })
                    $Tier1SubscriptionScopes = @($SubscriptionScopes | Where-Object { $_ -notin $Tier0SubscriptionScopes -and $Tier1IncludedResourceScope -contains $_ })
                    $ResolutionStatus = if ($SubscriptionScopes.Count -gt 0) { 'Resolved' } else { @($CloudSetAssignments.ResolutionStatus | Where-Object { $_ -eq 'Unresolved' } | Select-Object -First 1) ?? 'Unresolved' }
                    $ResultingScope = if ($Tier0SubscriptionScopes.Count -gt 0) { 'Tier0' } elseif ($Tier1SubscriptionScopes.Count -gt 0) { 'Tier1' } elseif ($ResolutionStatus -eq 'Resolved') { 'Unclassified' } else { 'UnknownBoundedScope' }
                    $AzureScopeEvidence = foreach ($SubscriptionScope in $SubscriptionScopes) {
                        $ResourceEvidence = @($SharedAzureResourceScope.ResourceScopeDetails | Where-Object { @($_.ExpandedScopePaths) -contains $SubscriptionScope } | Sort-Object Source, ResourceName, ResourceId)
                        [PSCustomObject]@{
                            SubscriptionScope = $SubscriptionScope
                            ResultingScope    = if ($Tier0SubscriptionScopes -contains $SubscriptionScope) { 'Tier0' } elseif ($Tier1SubscriptionScopes -contains $SubscriptionScope) { 'Tier1' } else { 'Unclassified' }
                            ScopeDetails      = @($ResourceEvidence | ForEach-Object {
                                    [PSCustomObject]@{
                                        ScopeId = $_.ResourceId
                                        Source  = $_.Source
                                        EAMTier = $_.EAMTier
                                        Reason  = $_.Reason
                                    }
                                })
                        }
                    }
                    [PSCustomObject]@{
                        CloudSetId              = $_.Name
                        CloudSetName            = @($CloudSetAssignments.CloudSetName | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Sort-Object -Unique | Select-Object -First 1)
                        ResolutionStatus        = $ResolutionStatus
                        SubscriptionScopes      = $SubscriptionScopes
                        Tier0SubscriptionScopes = $Tier0SubscriptionScopes
                        Tier1SubscriptionScopes = $Tier1SubscriptionScopes
                        ResultingScope          = $ResultingScope
                        Reason                  = "CloudSet contains $($SubscriptionScopes.Count) subscription(s); $($Tier0SubscriptionScopes.Count) map to Tier0 Azure reasoning and $($Tier1SubscriptionScopes.Count) map only to Tier1 Azure reasoning."
                        AzureScopeEvidence      = @($AzureScopeEvidence)
                    }
                })
            $DefenderScopeReasoningFile = Join-Path -Path $DefenderOutputDir -ChildPath 'ScopeReasoning_Defender.json'
            [PSCustomObject]@{
                CloudSetDetails     = $CloudSetReasoning
                UnresolvedCloudSets = @($CloudSetReasoning | Where-Object { $_.ResolutionStatus -eq 'Unresolved' })
            } | ConvertTo-Json -Depth 8 | Out-File -FilePath $DefenderScopeReasoningFile -Force
            Write-Host "  CloudSet scope reasoning file: $DefenderScopeReasoningFile" -ForegroundColor Cyan
        }
        Write-Host ""
    } # end if Defender
    #endregion

    #region Azure RBAC Classification Parameter Scope
    if ($ClassificationParameterScope -contains "Azure") {
        Write-Host ""
        Write-Host "=========================================================" -ForegroundColor Cyan
        Write-Host " Azure RBAC - Scope Parameter Update" -ForegroundColor Cyan
        Write-Host "=========================================================" -ForegroundColor Cyan

        $AzureRoleClassification = Get-Content -Path $AzureClassificationParameterFile -Raw

        # Identify which Service categories are actually driven by <Tier0/Tier1IncludedResourceScope> in the
        # template (rather than a hardcoded list), so it stays in sync if the template is customized. Probe by
        # substituting the placeholders with unique sentinel values (keeping the result valid JSON) and collecting
        # the Service of every entry whose RoleAssignmentScopeName/ExcludedRoleAssignmentScopeName references them.
        $DynamicScopeServices = [System.Collections.Generic.List[string]]::new()
        try {
            $Tier0Sentinel = "__EntraOpsTier0Placeholder__"
            $Tier1Sentinel = "__EntraOpsTier1Placeholder__"
            $ProbeText = (Get-Content -Path $AzureClassificationParameterFile -Raw).
            Replace('<Tier0IncludedResourceScope>', "`"$Tier0Sentinel`"").
            Replace('<Tier1IncludedResourceScope>', "`"$Tier1Sentinel`"")
            $ProbeDefinition = @($ProbeText | ConvertFrom-Json -Depth 10)
            foreach ($Tier in $ProbeDefinition) {
                foreach ($Definition in @($Tier.TierLevelDefinition)) {
                    $AllScopes = @($Definition.RoleAssignmentScopeName) + @($Definition.ExcludedRoleAssignmentScopeName)
                    if (($AllScopes -contains $Tier0Sentinel -or $AllScopes -contains $Tier1Sentinel) -and ($DynamicScopeServices -notcontains $Definition.Service)) {
                        $DynamicScopeServices.Add($Definition.Service) | Out-Null
                    }
                }
            }
        } catch {
            Write-Warning "Failed to probe Classification_Azure.Param.json for dynamically-scoped categories: $_"
        }

        # Reuse the shared Azure resource/subscription scope resolved earlier (avoids duplicate Exposure
        # Management / Azure Resource Graph queries when Defender parameterization also ran in this invocation).
        if ($null -eq $SharedAzureResourceScope) {
            $SharedAzureResourceScope = Get-EntraOpsClassificationAzureResourceScope -EntraOpsEamFolder $EntraOpsEamFolder -EntraOpsScopes $EntraOpsScopes -ExposureCriticalityLevel $ExposureCriticalityLevel -WarningMessages $WarningMessages
        }
        $AzureResourceScopeDetails = $SharedAzureResourceScope.ResourceScopeDetails

        #region Keep Tier0/Tier1 resource scopes split by the hosted managed identity's own effective tier
        Write-Host ""
        Write-Host "---------------------------------------------------------" -ForegroundColor DarkCyan
        Write-Host " Azure RBAC Tier0/Tier1 Resource Scope (from shared resource scope)" -ForegroundColor DarkCyan
        Write-Host "---------------------------------------------------------" -ForegroundColor DarkCyan
        Write-Host "  Azure RBAC scope now follows the hosted managed identity's own effective tier: a resource" -ForegroundColor Gray
        Write-Host "  hosting a ControlPlane-tier MI is Tier0, a resource hosting a ManagementPlane-tier MI is" -ForegroundColor Gray
        Write-Host "  Tier1 (managing/assigning that identity is bounded by the identity's own granted privileges)." -ForegroundColor Gray

        # Tier0/Tier1 resource scope is kept exactly as resolved per-MI-tier by Get-EntraOpsClassificationAzureResourceScope
        # (no longer merged): a resource hosting a ControlPlane-tier managed identity is Tier0, a resource hosting
        # a ManagementPlane-tier managed identity is Tier1. Managing/assigning a managed identity is only as
        # privileged as what that identity itself was granted, so the RBAC scope for the "Managed Identity"
        # category (and any other category reusing these placeholders) should reflect the identity's own tier.
        $Tier0ResourceScope = @($SharedAzureResourceScope.Tier0ResourceScope | Select-Object -Unique | Sort-Object)
        $Tier1ResourceScope = @($SharedAzureResourceScope.Tier1ResourceScope | Select-Object -Unique | Sort-Object)
        Write-Host "  Total expanded ARM scope paths (Tier0): $($Tier0ResourceScope.Count)" -ForegroundColor Gray
        if ($Tier0ResourceScope.Count -gt 0) {
            Write-Host ""
            Write-Host "  Tier0 ARM scope hierarchy (resource → subscription → management groups):" -ForegroundColor White
            $Tier0ResourceScope | ForEach-Object { Write-Host "    $_" -ForegroundColor DarkGreen }
        }
        Write-Host "  Total expanded ARM scope paths (Tier1): $($Tier1ResourceScope.Count)" -ForegroundColor Gray
        if ($Tier1ResourceScope.Count -gt 0) {
            Write-Host ""
            Write-Host "  Tier1 ARM scope hierarchy (resource → subscription → management groups):" -ForegroundColor White
            $Tier1ResourceScope | ForEach-Object { Write-Host "    $_" -ForegroundColor Yellow }
        }
        #endregion

        #region Replace placeholders in Azure classification parameter file
        Write-Host ""
        Write-Host "---------------------------------------------------------" -ForegroundColor DarkCyan
        Write-Host " Replacing Azure RBAC Scope Placeholders" -ForegroundColor DarkCyan
        Write-Host "---------------------------------------------------------" -ForegroundColor DarkCyan

        $Tier0ScopeJSON = ($Tier0ResourceScope | ForEach-Object { "`"$_`"" }) -join ", "
        $AzureRoleClassification = $AzureRoleClassification.replace('<Tier0IncludedResourceScope>', $Tier0ScopeJSON)
        Write-Host "  <Tier0IncludedResourceScope> -> $($Tier0ResourceScope.Count) scope path(s)" -ForegroundColor DarkGreen
        $ScopeSummary.Add([PSCustomObject]@{ Placeholder = 'Tier0IncludedResourceScope'; Entries = $Tier0ResourceScope.Count; IncludesDirectory = $false; Status = 'Updated' })

        # Tier 1: strictly the resources hosting a ManagementPlane-tier managed identity (may be empty if none exist)
        $Tier1ScopeJSON = ($Tier1ResourceScope | ForEach-Object { "`"$_`"" }) -join ", "
        $AzureRoleClassification = $AzureRoleClassification.replace('<Tier1IncludedResourceScope>', $Tier1ScopeJSON)
        Write-Host "  <Tier1IncludedResourceScope> -> $($Tier1ResourceScope.Count) scope path(s)" -ForegroundColor DarkGreen
        if ($Tier1ResourceScope.Count -eq 0) {
            Write-Host "    (empty - no resource currently hosts a ManagementPlane-tier managed identity)" -ForegroundColor Yellow
        }
        $ScopeSummary.Add([PSCustomObject]@{ Placeholder = 'Tier1IncludedResourceScope'; Entries = $Tier1ResourceScope.Count; IncludesDirectory = $false; Status = 'Updated' })

        $AzureClassificationDefinition = @($AzureRoleClassification | ConvertFrom-Json -Depth 10)

        # Apply role action overwrites (down-/upgrade of individual role actions) to the generated classification.
        # Applied AFTER Tier0/Tier1 placeholder substitution, so overwrites match against the actual resolved
        # ARM scope paths, not the raw <Tier0/Tier1IncludedResourceScope> placeholder tokens.
        $AzureRoleActionOverwrites = @((Import-EntraOpsClassificationOverwrites -RbacSystem "Azure").RoleActionOverwrites)
        if ($AzureRoleActionOverwrites.Count -gt 0) {
            # Classification_RoleActionOverwrites.json is a separate file from Classification_Azure.Param.json and
            # is NOT covered by the template's raw-text <Tier0/Tier1IncludedResourceScope> substitution above, so
            # resolve the same placeholder tokens here (as literal single-element RoleAssignmentScopeName array
            # entries, e.g. ["<Tier0IncludedResourceScope>"]) to the actual resolved ARM scope paths.
            foreach ($Overwrite in $AzureRoleActionOverwrites) {
                $ResolvedScopes = [System.Collections.Generic.List[string]]::new()
                foreach ($ScopeEntry in @($Overwrite.RoleAssignmentScopeName)) {
                    if ($ScopeEntry -eq '<Tier0IncludedResourceScope>') {
                        foreach ($Path in $Tier0ResourceScope) { $ResolvedScopes.Add($Path) | Out-Null }
                    } elseif ($ScopeEntry -eq '<Tier1IncludedResourceScope>') {
                        foreach ($Path in $Tier1ResourceScope) { $ResolvedScopes.Add($Path) | Out-Null }
                    } else {
                        $ResolvedScopes.Add($ScopeEntry) | Out-Null
                    }
                }
                $Overwrite.RoleAssignmentScopeName = @($ResolvedScopes | Select-Object -Unique)
            }

            Write-Host "  Applying $($AzureRoleActionOverwrites.Count) role action overwrite(s) from $((@($AzureRoleActionOverwrites.SourceFile) | Sort-Object -Unique) -join ', ')..." -ForegroundColor Yellow

            # Warn when an overwritten action currently lives in one of the categories whose scope is driven by
            # the hosted managed identity's own tier (<Tier0/Tier1IncludedResourceScope>, identified above from
            # the template) - the overwrite will remove the action from that dynamically-scoped entry and
            # re-add it under the overwrite's own (often broader) scope, bypassing the per-MI-tier resource
            # scoping for that action.
            foreach ($Overwrite in $AzureRoleActionOverwrites) {
                foreach ($Action in @($Overwrite.RoleDefinitionActions)) {
                    foreach ($Tier in $AzureClassificationDefinition) {
                        foreach ($Definition in @($Tier.TierLevelDefinition)) {
                            if ($DynamicScopeServices -notcontains $Definition.Service) { continue }
                            if (@($Definition.RoleDefinitionActions) -contains $Action) {
                                Write-Host "  ⚠ Overwrite for '$Action' will remove it from dynamically-scoped '$($Definition.Service)' ($($Tier.EAMTierLevelName)) - it will no longer be limited to MI-hosting resources of that tier." -ForegroundColor DarkYellow
                            }
                        }
                    }
                }
            }

            $AzureClassificationDefinition = Invoke-EntraOpsClassificationActionOverwrite -ClassificationDefinition $AzureClassificationDefinition -RoleActionOverwrites $AzureRoleActionOverwrites
        }

        # Ensure output directory exists
        $AzureOutputDir = Split-Path $AzureCustomizedClassificationFile -Parent
        if (-not (Test-Path -Path $AzureOutputDir)) {
            New-Item -Path $AzureOutputDir -ItemType Directory -Force | Out-Null
        }
        $AzureClassificationDefinition | ConvertTo-Json -Depth 10 | Out-File -FilePath $AzureCustomizedClassificationFile -Force
        Write-Host "  Output file: $AzureCustomizedClassificationFile" -ForegroundColor Cyan

        # Persist WHY each resource was included in Tier0/Tier1 scope (Source/EAMTier/Reason/ScopeId), so this
        # is available for later auditing instead of only being visible in the console/job log at generation time.
        # Structure is aligned with ScopeReasoning_IdentityGovernance.json (Tier0/Tier1Scope and ScopeDetails
        # with ScopeName/ScopeId).
        $AzureResourceScopeReasoningFile = Join-Path -Path $AzureOutputDir -ChildPath "ScopeReasoning_Azure.json"
        $AzureResourceScopeReasoningPayload = [PSCustomObject]@{
            Tier0Scope   = $Tier0ResourceScope
            Tier1Scope   = $Tier1ResourceScope
            # ResourceId/Reason break ties for resources with multiple reasons (e.g. a VM using several
            # UAMIs) since Source+ResourceName alone can be identical and ARG doesn't guarantee row order.
            ScopeDetails = @($AzureResourceScopeDetails | Sort-Object Source, ResourceName, ResourceId, Reason | ForEach-Object {
                    $ScopeDetail = [ordered]@{
                        ScopeName      = $_.ResourceName
                        ScopeId        = $_.ResourceId
                        Source         = $_.Source
                        EAMTier        = $_.EAMTier
                        # Same bucketing fallback as Get-EntraOpsClassificationAzureResourceScope: only
                        # empty/"Unknown" defaults to Tier0; "Unclassified" (evaluated, nothing privileged found)
                        # intentionally lands in Tier1.
                        ResultingScope = if ($_.EAMTier -eq "ControlPlane" -or [string]::IsNullOrEmpty($_.EAMTier) -or $_.EAMTier -eq "Unknown") { "Tier0" } else { "Tier1" }
                        Reason         = $_.Reason
                    }
                    if ($_.PSObject.Properties.Name -contains 'CriticalityLevel') {
                        $ScopeDetail['CriticalityLevel'] = $_.CriticalityLevel
                    }
                    if ($_.PSObject.Properties.Name -contains 'CriticalityRules') {
                        $ScopeDetail['CriticalityRules'] = $_.CriticalityRules
                    }
                    if ($_.PSObject.Properties.Name -contains 'TierSource') {
                        $ScopeDetail['TierSource'] = $_.TierSource
                    }
                    if ($_.PSObject.Properties.Name -contains 'TierEvidence') {
                        $ScopeDetail['TierEvidence'] = @($_.TierEvidence)
                    }
                    if ($_.PSObject.Properties.Name -contains 'ManagedIdentityObjectId') {
                        $ScopeDetail['ManagedIdentityObjectId'] = $_.ManagedIdentityObjectId
                    }
                    if ($_.PSObject.Properties.Name -contains 'ExpandedScopePaths') {
                        $ScopeDetail['ExpandedScopePaths'] = @($_.ExpandedScopePaths)
                    }
                    [PSCustomObject]$ScopeDetail
                })
        }
        $AzureResourceScopeReasoningPayload | ConvertTo-Json -Depth 5 | Out-File -FilePath $AzureResourceScopeReasoningFile -Force
        Write-Host "  Resource scope reasoning file: $AzureResourceScopeReasoningFile" -ForegroundColor Cyan
        #endregion

        #region Azure RBAC Classification Summary
        Write-Host ""
        Write-Host "---------------------------------------------------------" -ForegroundColor DarkCyan
        Write-Host " Azure RBAC Classification Summary" -ForegroundColor DarkCyan
        Write-Host "---------------------------------------------------------" -ForegroundColor DarkCyan

        Write-Host ""
        Write-Host "  Resource scope details (grouped by source) - EAMTier is the hosted/used/consumed managed" -ForegroundColor White
        Write-Host "  identity's own effective tier: only 'ControlPlane' (or truly unknown/unclassified) -> Tier0 scope," -ForegroundColor White
        Write-Host "  everything else genuinely classified (ManagementPlane, UserAccess, etc.) -> Tier1 scope:" -ForegroundColor White
        if ($AzureResourceScopeDetails.Count -gt 0) {
            $AzureResourceScopeDetails | Group-Object Source | Sort-Object Name | ForEach-Object {
                Write-Host "  [$($_.Name)] ($($_.Count) resource(s))" -ForegroundColor DarkCyan
                $_.Group | Sort-Object ResourceName | ForEach-Object {
                    if ($IncludeObjectDetails) {
                        $IsTier0 = $_.EAMTier -eq "ControlPlane" -or [string]::IsNullOrEmpty($_.EAMTier) -or $_.EAMTier -eq "Unknown"
                        $ResultingScope = if ($IsTier0) { "Tier0" } else { "Tier1" }
                        $Color = if ($_.EAMTier -eq "ControlPlane") { 'DarkGreen' } elseif ($IsTier0) { 'Gray' } else { 'Yellow' }
                        Write-Host "    $($_.ResourceName) [EAM: $($_.EAMTier) -> $ResultingScope scope]" -ForegroundColor $Color
                        Write-Host "      Reason    : $($_.Reason)" -ForegroundColor DarkGray
                        Write-Host "      ResourceId: $($_.ResourceId)" -ForegroundColor DarkGray
                    } else {
                        Write-Host "    $($_.ResourceId)" -ForegroundColor DarkGray
                    }
                }
            }
        } else {
            Write-Host "  (no resources identified for Tier0/Tier1 scope)" -ForegroundColor Yellow
        }
        Write-Host ""
        #endregion

    } # end if Azure
    #endregion

    # Final summary
    Write-Host "=========================================================" -ForegroundColor Cyan
    Write-Host " Classification Update Complete" -ForegroundColor Cyan
    Write-Host " RBAC Scope: $($ClassificationParameterScope -join ', ')" -ForegroundColor Cyan
    Write-Host "=========================================================" -ForegroundColor Cyan
    Write-Host ""
    Show-EntraOpsWarningSummary -WarningMessages $WarningMessages -IncludeObjectDetails $IncludeObjectDetails
    $ScopeSummary | Format-Table -AutoSize -Property Placeholder,
    @{Name = 'ScopeEntries'; Expression = { $_.Entries }; Align = 'Right' },
    @{Name = 'Dir(/)'; Expression = { if ($_.IncludesDirectory) { 'YES' } else { 'no' } }; Align = 'Center' },
    Status
}