<#
.SYNOPSIS
    Create a custom role "Privileged Application Administrator" based on "Application Administrator" role and assign it to a Delegated Admin Group for managing Control Plane Applications which are assigned to Restricted Management Administrative Units (RMAUs).
.DESCRIPTION
    Creates a custom role "Privileged Application Administrator" based on the built-in "Application Administrator" role, excluding specific resource actions that are not needed for managing Control Plane Applications. The custom role is then assigned to a specified Delegated Admin Group for each Restricted Management Administrative Unit (RMAU) provided.
.PARAMETER RoleName
    The name of the custom role to be created. Default is "Privileged Application Administrator".
.PARAMETER TemplateRoleName
    The name of the built-in role to use as a template for the custom role. Default is "Application Administrator".
.PARAMETER AdministrativeUnitIds
    An array of Administrative Unit IDs representing the RMAUs where the custom role will be assigned. Default retrieves all RMAUs which includes "ResourceApps" in their display name.
.PARAMETER DelegatedAdminGroupName
    The name of the Delegated Admin Group to which the custom role will be assigned.
.PARAMETER ExcludedResourceActionsFromTemplate
    An array of resource actions to exclude from the template role when creating the custom role. Defaults to a predefined list of actions which can not be scoped to RMAUs.
.PARAMETER EligibleRoleAssignment
    If true, the role assignment will be created as an eligible assignment in PIM instead of a direct assignment.
.EXAMPLE
    Create a Privileged Application Administrator role and assign it to the "Tier0-DelegatedAdmins" group for specified RMAUs.
    New-EntraOpsPrivilegedApplicationAdminDelegation -DelegatedAdminGroupName "Tier0-DelegatedAdmins" -AdministrativeUnitIds @("admin-unit-id-1","admin-unit-id-2")
#>

function New-EntraOpsPrivilegedApplicationAdminDelegation {
    param (
        [Parameter(Mandatory = $False)]
        [string]$RoleName = "Privileged Application Administrator"
        ,
        [Parameter(Mandatory = $False)]
        [string]$TemplateRoleName = "Application Administrator"
        ,        
        [Parameter(Mandatory = $false)]
        [Object]$AdministrativeUnitIds
        ,
        [Parameter(Mandatory = $true)]
        [string]$DelegatedAdminGroupName
        ,        
        [Parameter(Mandatory = $false)]
        [Object]$ExcludedResourceActionsFromTemplate = @(
            "microsoft.directory/adminConsentRequestPolicy/allProperties/allTasks",
            "microsoft.directory/appConsent/appConsentRequests/allProperties/read",
            "microsoft.azure.supportTickets/allEntities/allTasks",
            "microsoft.azure.serviceHealth/allEntities/allTasks",
            "microsoft.office365.serviceHealth/allEntities/allTasks",
            "microsoft.office365.supportTickets/allEntities/allTasks",
            "microsoft.office365.webPortal/allEntities/standard/read",
            "microsoft.directory/applications/policies/update",
            "microsoft.directory/applications/verification/update",
            "microsoft.directory/customAuthenticationExtensions/allProperties/allTasks",
            "microsoft.directory/oAuth2PermissionGrants/allProperties/allTasks"
        )
        ,
        [Parameter(Mandatory = $false)]
        [boolean]$EligibleRoleAssignment = $true
    )

    # Set Error Action
    $ErrorActionPreference = "Stop"

    if (-not $AdministrativeUnitIds) {
        $AdministrativeUnitIds = Get-MgDirectoryAdministrativeUnit -Filter "isMemberManagementRestricted eq true" | where-object {$_.DisplayName -like "*ResourceApps"} | Select-Object -ExpandProperty Id
    }

    #region Create Custom Role to manage members of RMAU
    $CustomRoleName = $RoleName
    $RestrictedAdminRole = Get-MgRoleManagementDirectoryRoleDefinition -Filter "(displayName eq '$($CustomRoleName)')"

    try {
        if ($RestrictedAdminRole) {
            Write-Verbose "Custom Role '$($CustomRoleName)' already exists. Skipping creation."
        } else {
            $RestrictedAdminRoleTemplate = Get-MgRoleManagementDirectoryRoleDefinition -Filter "(displayName eq '$($TemplateRoleName)')"
            $AllowedResourceActions = $RestrictedAdminRoleTemplate.RolePermissions.AllowedResourceActions | where-Object { $_ -notin $ExcludedResourceActionsFromTemplate } | foreach-object { $_ }
            $CustomRoleParameters = @{
                DisplayName = $CustomRoleName
                Description = "Users in this custom role can manage, and configure essential settings (including credential) of enterprise applications and app registrations. This role can be used for assignments on Restricted management administrative unit (RMAU)-level."
                IsEnabled = $true
                TemplateId = (New-Guid).Guid
                RolePermissions = @{
                    "allowedResourceActions" = $AllowedResourceActions
                    "ExcludedResourceActions" = $RestrictedAdminRoleTemplate.RolePermissions.ExcludedResourceActions
                    "Condition" = $RestrictedAdminRoleTemplate.RolePermissions.Condition
                }
            }

            $RestrictedAdminRole = New-MgRoleManagementDirectoryRoleDefinition @CustomRoleParameters
            if (-not $RestrictedAdminRole) {
                throw "Failed to create custom role '$($CustomRoleName)'."
            } else {
                Write-Verbose "Custom Role '$($CustomRoleName)' created successfully."                
            }
            
        }
    } catch {
        Write-Error "Error creating custom role '$($CustomRoleName)': $_"
        return
    }
    #endregion

    #region Assign Custom Role to Administrative Unit
    foreach ($AdminUnitId in $AdministrativeUnitIds) {
        $AdminUnit = Get-MgDirectoryAdministrativeUnit -AdministrativeUnitId $AdminUnitId
        if (-not $AdminUnit) {
            Write-Error "Administrative Unit with ID '$($AdminUnitId)' not found."
            continue
        } else {
            Write-Verbose "Processing Administrative Unit: '$($AdminUnit.DisplayName)'"

            $DelegatedAdminGroup = Get-MgGroup -Filter "displayName eq '$($DelegatedAdminGroupName)'"
            if (-not $DelegatedAdminGroup) {
                Write-Error "Delegated Admin Group '$($DelegatedAdminGroupName)' not found."
                continue
            } else {
                Write-Verbose "Found Delegated Admin Group: '$($DelegatedAdminGroup.Id)'"
            }

            if ($EligibleRoleAssignment) {
                $PimParameters = @{
                    Action = "adminAssign"
                    Justification = "Assigned via EntraOpsPrivilegedApplicationAdminDelegation"
                    DirectoryScopeId = "/administrativeUnits/$($AdminUnit.Id)"
                    PrincipalId = $DelegatedAdminGroup.Id
                    RoleDefinitionId = $RestrictedAdminRole.Id
                    ScheduleInfo = @{
                        StartDateTime = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
                        Expiration = @{
                            Type = "noExpiration"
                        }
                    }
                }

                $RetryEndTime = (Get-Date).AddMinutes(5)
                $Success = $false
                do {
                    try {
                        New-MgRoleManagementDirectoryRoleEligibilityScheduleRequest -BodyParameter $PimParameters
                        $Success = $true
                    } catch {
                        if ($_.Exception.Message -like "*The role is not found*") {
                            if ((Get-Date) -gt $RetryEndTime) {
                                Write-Error "Timeout waiting for role propagation."
                                throw $_
                            }
                            Write-Verbose "Role not found yet. Waiting 20 seconds for propagation..."
                            Start-Sleep -Seconds 20
                        } else {
                            throw $_
                        }
                    }
                } until ($Success)
            } else {
                $RmauRoleAssignmentParameters = @{
                    "@odata.type"      = "#microsoft.graph.unifiedRoleAssignment"
                    roleDefinitionId   = $RestrictedAdminRole.Id
                    principalId        = $DelegatedAdminGroup.Id
                    directoryScopeId   = "/administrativeUnits/$($AdminUnit.Id)"
                }
                New-MgRoleManagementDirectoryRoleAssignment -BodyParameter $RmauRoleAssignmentParameters
            }
        }
    }
    #endregion
}
