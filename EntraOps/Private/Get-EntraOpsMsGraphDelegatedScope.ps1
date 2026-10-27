<#
.SYNOPSIS
    Returns the delegated Microsoft Graph scopes requested by Connect-EntraOps.

.DESCRIPTION
    "Report" requests the read scopes only. "ServiceEM" and "ApplyProtection" add write scopes; some are only added
    when the feature is enabled in the EntraOpsConfig.json read before sign-in:

    - ServiceEM: AdministrativeUnit.ReadWrite.All when ServiceEM.AdministrativeUnits.WorkloadPlane or .UserAccess is set.
    - ApplyProtection: always AdministrativeUnit.ReadWrite.All and Group.ReadWrite.All; EntitlementManagement.ReadWrite.All
      only when AutomatedElmCatalogProtection.ApplyPrivilegedElmCatalogProtection is true.

.PARAMETER Scope
    Report, ServiceEM or ApplyProtection.

.PARAMETER Config
    EntraOpsConfig.json content, or $null when no configuration is used.
#>
function Get-EntraOpsMsGraphDelegatedScope {
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('Report', 'ServiceEM', 'ApplyProtection')]
        [string]$Scope,

        [AllowNull()]
        [psobject]$Config
    )

    $scopes = [System.Collections.Generic.List[string]]@(
        'AdministrativeUnit.Read.All',
        'Application.Read.All',
        'CustomSecAttributeAssignment.Read.All',
        'DeviceManagementConfiguration.Read.All',
        'DeviceManagementManagedDevices.Read.All',
        'DeviceManagementRBAC.Read.All',
        'DeviceManagementServiceConfig.Read.All',
        'Directory.Read.All',
        'DirectoryRecommendations.Read.All',
        'EntitlementManagement.Read.All',
        'Group.Read.All',
        'PrivilegedAccess.Read.AzureADGroup',
        'PrivilegedEligibilitySchedule.Read.AzureADGroup',
        'Policy.Read.All',
        'RemoteTenantGroups.Read.All',
        'RoleManagement.Read.All',
        'TenantGovernance-Relationship.Read.All',
        'ThreatHunting.Read.All',
        'User.Read.All',
        'Zone.Read.All'
    )

    if ($Scope -eq 'ServiceEM') {
        $scopes.AddRange([string[]]@(
                'Directory.AccessAsUser.All',
                'EntitlementManagement.ReadWrite.All',
                'RoleManagementPolicy.ReadWrite.AzureADGroup',
                'RoleManagementPolicy.ReadWrite.Directory',
                'RoleManagement.ReadWrite.Directory',
                'PrivilegedEligibilitySchedule.ReadWrite.AzureADGroup',
                'PrivilegedAccess.ReadWrite.AzureADGroup'
            ))
        $administrativeUnits = $Config.ServiceEM.AdministrativeUnits
        if (-not [string]::IsNullOrWhiteSpace($administrativeUnits.WorkloadPlane) -or -not [string]::IsNullOrWhiteSpace($administrativeUnits.UserAccess)) {
            $scopes.Add('AdministrativeUnit.ReadWrite.All')
        }
    } elseif ($Scope -eq 'ApplyProtection') {
        $scopes.AddRange([string[]]@('AdministrativeUnit.ReadWrite.All', 'Group.ReadWrite.All'))
        if ($Config.AutomatedElmCatalogProtection.ApplyPrivilegedElmCatalogProtection -eq $true) {
            $scopes.Add('EntitlementManagement.ReadWrite.All')
        }
    }

    return [string[]]$scopes
}
