<#
.SYNOPSIS
    Update classification definition file for Microsoft Entra ID with fine-granular scope of Control Plane permissions based on privileged objects.

.DESCRIPTION
    Classification of Control Plane needs to consider the scope of sensitive permissions. For example, managing group membership of security groups should be managed as Control Plane by default.
    But this enforces to manage service-specific roles (e.g., Knowledge Administrator) as Control Plane. Protection of privileged objects by using Role-assignable groups (PRG), Entra ID Roles or Restricted Management Administrative Units (RMAU) allows to protect them by lower privileged roles with those permissions on directory-level.
    This function checks if privileged objects are protected by the previous mentoined methods and RMAUs with assigned privileged objects.
    A parameter file will be used to generate an updated classification definition file for Microsoft Entra ID and exclude directory roles without impact to privileged objects from Control Plane. All other assignments will be still managed as Control Plane.

.PARAMETER PrivilegedObjectClassificationSource
    Source of privileged objects to identify the scope of privileged objects and update the classification definition file for Microsoft Entra ID.
    Possible values are "All", "EntraOps", "PrivilegedObjectIds", "PrivilegedRolesFromAzGraph" and "PrivilegedEdgesFromExposureManagement".

.PARAMETER EntraIdClassificationParameterFile
    Path to the classification parameter file for Microsoft Entra ID. Default is ./Classification/Templates/Classification_AadResources.Param.json.

.PARAMETER EntraIdCustomizedClassificationFile
    Path to the customized classification file for Microsoft Entra ID. Default is ./Classification/<TenantName>/Classification_AadResources.json.
    The file path will be recognized by the tenant name in the context of EntraOps and used for the classification.

.PARAMETER EntraOpsEamFolder
    Path to the folder where the EntraOps classification definition files are stored. Default is ./Classification.

.PARAMETER EntraOpsScopes
    Array of EntraOps scopes which should be considered for the analysis. Default selection are all available scopes: Azure, AzureBilling, EntraID, IdentityGovernance, DeviceManagement and ResourceApps.

.PARAMETER AzureHighPrivilegedRoles
    Array of high privileged roles in Azure RBAC which should be considered for the analysis. Default selection are high-privileged roles: Owner, Role Based Access Control Administrator and User Access Administrator.

.PARAMETER AzureHighPrivilegedScopes
    Scope of high privileged roles in Azure RBAC which should be considered for the analysis. Default selection is all scopes including management groups.

.PARAMETER ExposureCriticalityLevel
    Criticality level of assets in Exposure Management which should be considered for the analysis. Default selection is criticality level <1.

.PARAMETER PrivilegedObjectIds
    Manual list of privileged object IDs to identify the scope of privileged objects and update the classification definition file for Microsoft Entra ID.

.EXAMPLE
    Get privileged objects from various Microsoft Entra RBACs and Microsoft Azure roles to identify the scope of privileged objects and update the classification definition file for Microsoft Entra ID.
    Update-EntraOpsClassificationControlPlaneScope -PrivilegedObjectClassificationSource "EntraOps" -RBACSystems ("Azure","EntraID","IdentityGovernance","DeviceManagement","ResourceApps")

.EXAMPLE
    Get exposure graph edges from Microsoft Security Exposure Management with relation of "has permissions to", "can authenticate as", "has role on", "has credentials of" or "affecting" to assets with criticality level <1.
    This identitfies objects with direct/indirect permissions which leads in attack/access paths to high sensitive assets which can be identified as Control Plane.
    Update-EntraOpsClassificationControlPlaneScope -PrivilegedObjectClassificationSource "PrivilegedEdgesFromExposureManagement" -ExposureCriticalityLevel = "<1"

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

#>

function Update-EntraOpsClassificationControlPlaneScope {

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $False)]
        [ValidateSet("All", "EntraOps", "PrivilegedObjectIds", "PrivilegedRolesFromAzGraph", "PrivilegedEdgesFromExposureManagement")]
        [object]$PrivilegedObjectClassificationSource = "All"
        ,
        [Parameter(Mandatory = $false)]
        [System.String]$EntraIdClassificationParameterFile = "$DefaultFolderClassification\Templates\Classification_AadResources.Param.json"
        ,
        [Parameter(Mandatory = $false)]
        [System.String]$EntraIdCustomizedClassificationFile = "$DefaultFolderClassification\$($TenantNameContext)\Classification_AadResources.json"
        ,
        [Parameter(Mandatory = $false)]
        [ValidateScript({ Test-Path $_ })]
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

    $PrivilegedObjects = Get-EntraOpsClassificationControlPlaneObjects @Parameters

    #region Get classification file and filter for unique privileged objects
    $DirectoryLevelAssignmentScope = @("/")
    $EntraIdRoleClassification = Get-Content -Path $EntraIdClassificationParameterFile
    $PrivilegedObjects = $PrivilegedObjects | sort-object ObjectType, ObjectDisplayName | Select-Object -Unique *

    Write-Host ""
    Write-Host "=========================================================" -ForegroundColor Cyan
    Write-Host " EntraOps - Control Plane Scope Classification Update" -ForegroundColor Cyan
    Write-Host " Source : $PrivilegedObjectClassificationSource" -ForegroundColor Cyan
    Write-Host " Objects identified: $(@($PrivilegedObjects).Count)" -ForegroundColor Cyan
    Write-Host "=========================================================" -ForegroundColor Cyan
    Write-Host ""

    # Summary table: unique objects with all contributing sources listed per object
    Write-Host " Identified privileged objects by source:" -ForegroundColor White
    Write-Host "---------------------------------------------------------" -ForegroundColor DarkCyan
    $PrivilegedObjects | Sort-Object ObjectType, ObjectDisplayName | Group-Object -Property ObjectType | Sort-Object Name | ForEach-Object {
        Write-Host "  [$($_.Name)] ($($_.Count) object(s))" -ForegroundColor DarkCyan
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
    }
    Write-Host "---------------------------------------------------------" -ForegroundColor DarkCyan
    Write-Host ""

    # Track scope changes for final summary
    $ScopeSummary = [System.Collections.Generic.List[psobject]]::new()
    $WarningMessages = New-Object -TypeName "System.Collections.Generic.List[psobject]"
    #endregion   


    #region Privileged User
    Write-Host "---------------------------------------------------------" -ForegroundColor DarkCyan
    Write-Host " Privileged Users" -ForegroundColor DarkCyan
    Write-Host "---------------------------------------------------------" -ForegroundColor DarkCyan
    $PrivilegedUsersAll = @($PrivilegedObjects | Where-Object { $_.ObjectType -eq "user" })
    $PrivilegedUsersWithoutProtection = @($PrivilegedUsersAll | Where-Object { $_.RestrictedManagementByRAG -eq $false -and $_.RestrictedManagementByAadRole -eq $False -and $_.RestrictedManagementByRMAU -eq $False })

    Write-Host "  Total users  : $($PrivilegedUsersAll.Count)" -ForegroundColor Gray
    Write-Host "  Unprotected  : $($PrivilegedUsersWithoutProtection.Count)" -ForegroundColor $(if ($PrivilegedUsersWithoutProtection.Count -gt 0) { 'Yellow' } else { 'DarkGreen' })

    # Include all Administrative Units because of Privileged Authentication Admin role assignment on (RM)AU level
    $PrivilegedUserWithAU = $PrivilegedObjects | Where-Object { $_.ObjectType -eq "user" -and $null -ne $_.AssignedAdministrativeUnits }
    $ScopeNamePrivilegedUsers = $PrivilegedUserWithAU.AssignedAdministrativeUnits | Select-Object -Unique id | ForEach-Object { "/administrativeUnits/$($_.id)" }
    if ($PrivilegedUsersWithoutProtection.Count -gt 0) {
        Write-Warning "  Control Plane users without protection - directory scope required!"
        $WarningMessages.Add([PSCustomObject]@{ Type = "UnprotectedUsers"; Message = "$($PrivilegedUsersWithoutProtection.Count) Control Plane user(s) without protection - directory scope required" })
        $PrivilegedUsersWithoutProtection | ForEach-Object {
            Write-Host "    [!] $($_.ObjectDisplayName) ($($_.ObjectId))" -ForegroundColor Yellow
        }
        $ScopeNamePrivilegedUsers += $DirectoryLevelAssignmentScope
    }

    if ($null -ne $ScopeNamePrivilegedUsers) {
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
    $PrivilegedUsersWithDevices = ($PrivilegedObjects | Where-Object { $_.ObjectType -eq "user" -and $null -ne $_.OwnedDevices }) | Select-Object -ExpandProperty OwnedDevices | Select-Object -Unique
    Write-Host "  Devices owned by privileged users: $(@($PrivilegedUsersWithDevices).Count)" -ForegroundColor Gray
    # Build per-device protection status. Devices not in any AU at all are unprotected but would be
    # invisible to a flat AU list - track HasRMAU per device to catch them.
    $PrivilegedDevicesProtection = @($PrivilegedUsersWithDevices | ForEach-Object {
            $DeviceId = $_
            $DeviceAUs = @(Invoke-EntraOpsMsGraphQuery -Method Get -Uri "/beta/devices/$DeviceId/memberOf/microsoft.graph.administrativeUnit" -OutputType PSObject | Where-Object { $null -ne $_.id } | Select-Object id, displayName, isMemberManagementRestricted)
            [PSCustomObject]@{
                DeviceId = $DeviceId
                AUs      = $DeviceAUs
                HasRMAU  = ($DeviceAUs | Where-Object { $_.isMemberManagementRestricted -eq $True }).Count -gt 0
            }
        })
    $PrivilegedDevicesWithoutProtection = @($PrivilegedDevicesProtection | Where-Object { $_.HasRMAU -eq $False })
    $ScopeNamePrivilegedDevices = $PrivilegedDevicesProtection | Where-Object { $_.HasRMAU -eq $True } | ForEach-Object { $_.AUs } | Where-Object { $_.isMemberManagementRestricted -eq $True } | Select-Object -Unique id | ForEach-Object { "/administrativeUnits/$($_.id)" }

    Write-Host "  Unprotected  : $($PrivilegedDevicesWithoutProtection.Count)" -ForegroundColor $(if ($PrivilegedDevicesWithoutProtection.Count -gt 0) { 'Yellow' } else { 'DarkGreen' })
    if ($PrivilegedDevicesWithoutProtection.Count -gt 0) {
        Write-Warning "  Control Plane devices without RMAU protection - directory scope required!"
        $WarningMessages.Add([PSCustomObject]@{ Type = "UnprotectedDevices"; Message = "$($PrivilegedDevicesWithoutProtection.Count) Control Plane device(s) without RMAU protection - directory scope required" })
        $PrivilegedDevicesWithoutProtection | ForEach-Object {
            Write-Host "    [!] Device $($_.DeviceId)" -ForegroundColor Yellow
        }
        $ScopeNamePrivilegedDevices += $DirectoryLevelAssignmentScope
    }
    if ($null -ne $ScopeNamePrivilegedDevices) {
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
    $PrivilegedGroupsWithoutProtection = @($PrivilegedGroupsAll | Where-Object { $_.RestrictedManagementByRAG -eq $false -and $_.RestrictedManagementByAadRole -eq $False -and $_.RestrictedManagementByRMAU -eq $False })
    $PrivilegedGroupWithRMAU = @($PrivilegedGroupsAll | Where-Object { $_.RestrictedManagementByRMAU -eq $True })

    Write-Host "  Total groups : $($PrivilegedGroupsAll.Count)" -ForegroundColor Gray
    Write-Host "  Protected(RMAU): $($PrivilegedGroupWithRMAU.Count)" -ForegroundColor DarkGreen
    Write-Host "  Unprotected  : $($PrivilegedGroupsWithoutProtection.Count)" -ForegroundColor $(if ($PrivilegedGroupsWithoutProtection.Count -gt 0) { 'Yellow' } else { 'DarkGreen' })

    $ScopeNamePrivilegedGroups = $PrivilegedGroupWithRMAU.AssignedAdministrativeUnits | Select-Object -Unique id | ForEach-Object { "/administrativeUnits/$($_.id)" }
    if ($PrivilegedGroupsWithoutProtection.Count -gt 0) {
        Write-Warning "  Control Plane groups without RMAU protection - directory scope required!"
        $WarningMessages.Add([PSCustomObject]@{ Type = "UnprotectedGroups"; Message = "$($PrivilegedGroupsWithoutProtection.Count) Control Plane group(s) without RMAU protection - directory scope required" })
        $PrivilegedGroupsWithoutProtection | ForEach-Object {
            Write-Host "    [!] $($_.ObjectDisplayName) ($($_.ObjectId))" -ForegroundColor Yellow
        }
        $ScopeNamePrivilegedGroups += $DirectoryLevelAssignmentScope
    }
    if ($null -ne $ScopeNamePrivilegedGroups) {
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
    Write-Host "  Application objects: $($PrivilegedApplicationObjects.Count)" -ForegroundColor Gray
    
    if ($PrivilegedServicePrincipals.Count -gt 0 -or $PrivilegedApplicationObjects.Count -gt 0) {
        # Get list of object-level role assignment scope which includes Control Plane Service Principals
        $ScopeNameServicePrincipalObject = $PrivilegedServicePrincipals | ForEach-Object { "/$($_.ObjectId)" }

        # Get current tenant ID to identify single-tenant apps
        $CurrentTenantId = (Get-AzContext).Tenant.Id

        # Initialize array for application object scopes
        $ScopeNameApplicationObject = @()

        # Process direct application objects from EntraOps
        if ($PrivilegedApplicationObjects.Count -gt 0) {
            Write-Host "  Processing $($PrivilegedApplicationObjects.Count) direct application objects from EntraOps..." -ForegroundColor Gray
            foreach ($AppObj in $PrivilegedApplicationObjects) {
                $ScopeNameApplicationObject += "/$($AppObj.ObjectId)"
                Write-Host "  [+] Direct app object: $($AppObj.ObjectDisplayName) -> /$($AppObj.ObjectId)" -ForegroundColor DarkGreen
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
                                Write-Host "  [+] App object resolved: $($App.ObjectDisplayName) ($($SpDetails.appId)) -> /$($AppObject.id)" -ForegroundColor DarkGreen
                            }
                        }
                    }
                } catch {
                    Write-Warning "  [!] Failed to fetch application object for appId $($SpDetails.appId): $_"
                    $WarningMessages.Add([PSCustomObject]@{ Type = "ApiError"; Message = "Failed to fetch application object for appId $($SpDetails.appId): $_" })
                }
            } else {
                if ($null -ne $SpDetails) {
                    Write-Host "  [~] Skipped: $($App.ObjectDisplayName) - Type: $($SpDetails.servicePrincipalType), Owner: $(if ($SpDetails.appOwnerOrganizationId -ne $CurrentTenantId) { 'External tenant' } else { $SpDetails.appOwnerOrganizationId })" -ForegroundColor DarkGray
                }
            }
        }

        $PrivilegedServicePrincipalWithAU = $PrivilegedObjects | Where-Object { $_.ObjectType -eq "servicePrincipal" -and $null -ne $_.AssignedAdministrativeUnits.id }
        $PrivilegedServicePrincipalWithAU = $PrivilegedServicePrincipalWithAU.AssignedAdministrativeUnits | Select-Object -Unique id | ForEach-Object { "/administrativeUnits/$($_.id)" }

        # Always add also directory level assignment scope because of missing protection of service principal by RAG, AAD Role or RMAU assignment
        $ScopeNamePrivilegedServicePrincipals = $ScopeNameServicePrincipalObject + $ScopeNameApplicationObject + $DirectoryLevelAssignmentScope + $PrivilegedServicePrincipalWithAU

        Write-Host "  Scope entries added:" -ForegroundColor Gray
        $ScopeNamePrivilegedServicePrincipals | Sort-Object -Unique | ForEach-Object { Write-Host "    $_" -ForegroundColor DarkGreen }
    } else {
        Write-Warning "  No privileged applications found - defaulting to directory scope '/'"
        $WarningMessages.Add([PSCustomObject]@{ Type = "EmptyScope"; Message = "No privileged applications found - ScopeNamePrivilegedServicePrincipals defaulting to directory scope '/'" })
        $EntraIdRoleClassification = $EntraIdRoleClassification.replace('<ScopeNamePrivilegedServicePrincipals>', '"/"')
        $ScopeSummary.Add([PSCustomObject]@{ Placeholder = 'ScopeNamePrivilegedServicePrincipals'; Entries = 1; IncludesDirectory = $true; Status = 'Default(/)' })
    }

    if ($null -ne $ScopeNamePrivilegedServicePrincipals) {
        $ScopeNamePrivilegedServicePrincipals = @($ScopeNamePrivilegedServicePrincipals | Sort-Object -Unique)
        $ScopeNamePrivilegedServicePrincipalsJSON = $ScopeNamePrivilegedServicePrincipals | ConvertTo-Json
        $ScopeNamePrivilegedServicePrincipalsJSON = $ScopeNamePrivilegedServicePrincipalsJSON.Replace('[', '').Replace(']', '')
        $ScopeNamePrivilegedServicePrincipalsJSON = $ScopeNamePrivilegedServicePrincipalsJSON -creplace '\s+', ' '
        $EntraIdRoleClassification = $EntraIdRoleClassification.replace('<ScopeNamePrivilegedServicePrincipals>', $ScopeNamePrivilegedServicePrincipalsJSON)
        $ScopeSummary.Add([PSCustomObject]@{ Placeholder = 'ScopeNamePrivilegedServicePrincipals'; Entries = $ScopeNamePrivilegedServicePrincipals.Count; IncludesDirectory = ($ScopeNamePrivilegedServicePrincipals -contains '/'); Status = 'Updated' })
    }
    Write-Host ""
    #endregion

    $EntraIdRoleClassification = $EntraIdRoleClassification | ConvertFrom-Json -Depth 10 | ConvertTo-Json -Depth 10 | Out-File -FilePath $EntraIdCustomizedClassificationFile -Force

    # Final summary
    Write-Host "=========================================================" -ForegroundColor Cyan
    Write-Host " Classification Update Complete" -ForegroundColor Cyan
    Write-Host " Output file: $EntraIdCustomizedClassificationFile" -ForegroundColor Cyan
    Write-Host "=========================================================" -ForegroundColor Cyan
    Write-Host ""
    Show-EntraOpsWarningSummary -WarningMessages $WarningMessages
    $ScopeSummary | Format-Table -AutoSize -Property Placeholder,
    @{Name = 'ScopeEntries'; Expression = { $_.Entries }; Align = 'Right' },
    @{Name = 'Dir(/)'; Expression = { if ($_.IncludesDirectory) { 'YES' } else { 'no' } }; Align = 'Center' },
    Status
}
