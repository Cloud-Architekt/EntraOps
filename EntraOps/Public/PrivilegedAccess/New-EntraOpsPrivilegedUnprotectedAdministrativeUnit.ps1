<#
.SYNOPSIS
    Create Restricted Management AU for users and groups without any protection (by role-assignable groups, assigned directory role or existing RMAU membership) to avoid delegated management by lower privileged user.

.DESCRIPTION
    Create Restricted Management AU for users and groups without any protection (by role-assignable groups, assigned directory role or existing RMAU membership) to avoid delegated management by lower privileged user.

.PARAMETER ApplyToAccessTierLevel
    Array of Access Tier Levels to be processed. Default is ControlPlane, ManagementPlane.

.PARAMETER FilterObjectType
    Array of object types to be processed. Default is User, Group. Service Principal and application objects are not supported to be protected by RMAU.

.PARAMETER RbacSystems
    Array of RBAC systems to be processed. Default is Azure, AzureBilling, EntraID, IdentityGovernance, DeviceManagement, ResourceApps.

.EXAMPLE
    Create RMAU for privileged users without any protection but privileges in RBAC Systems "IdentityGovernance".
    New-EntraOpsPrivilegedUnprotectedAdministrativeUnit -RbacSystems ("EntraID", "IdentityGovernance")
#>
function New-EntraOpsPrivilegedUnprotectedAdministrativeUnit {

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $False)]
        [ValidateSet("ControlPlane", "ManagementPlane")]
        [Array]$ApplyToAccessTierLevel = ("ControlPlane", "ManagementPlane")
        ,
        [Parameter(Mandatory = $False)]
        [ValidateSet("User", "Group")]
        [Array]$FilterObjectType = ("User", "Group")
        ,
        [Parameter(Mandatory = $False)]
        [ValidateSet("EntraID", "IdentityGovernance", "ResourceApps", "DeviceManagement", "Defender")]
        [Array]$RbacSystems = ("EntraID", "IdentityGovernance", "ResourceApps", "DeviceManagement", "Defender")
    )

    # Get Tier Levels with unprotected privileged EAM objects
    $PrivilegedEamTierLevels = foreach ($RbacSystem in $RbacSystems) {
        # Get all privileged EAM objects
        $PrivilegedEamObjects = Get-Content "$DefaultFolderClassifiedEam/$RbacSystem/$($RbacSystem).json" | ConvertFrom-Json

        # Get all privileged EAM objects without any restricted management and their tier levels
        $UnprotectedPrivilegedUser = $PrivilegedEamObjects | Where-Object { $_.RestrictedManagementByRAG -ne $True -and $_.RestrictedManagementByAadRole -ne $True -and $_.RestrictedManagementByRMAU -ne $True -and $_.ObjectType -in $FilterObjectType }
        $UnprotectedPrivilegedUser.Classification | select-object -unique AdminTierLevelName, AdminTierLevel
    }

    # Get all unique AdminTierLevels which needs to be iterated for assigning objects to Conditional Access Target Groups
    $PrivilegedEamTierLevels = Get-ChildItem -Path "$($DefaultFolderClassification)/Templates" -File -Recurse -Exclude *.Param.json | foreach-object { Get-Content $_.FullName -Filter "*.json" | ConvertFrom-Json }
    $SelectedPrivilegedEamTierLevels = $PrivilegedEamTierLevels | where-object { $_.EAMTierLevelName -in $ApplyToAccessTierLevel } | select-object -unique @{Name = 'AdminTierLevel'; Expression = 'EAMTierLevelTagValue' }, @{Name = 'AdminTierLevelName'; Expression = 'EAMTierLevelName' }
    #endregion

    # Create Administrative Units for each Tier Level
    foreach ($TierLevel in $SelectedPrivilegedEamTierLevels) {
        $Name = "Tier" + $TierLevel.AdminTierLevel + "-" + $TierLevel.AdminTierLevelName + ".UnprotectedObjects"
        $AdministrativeUnit = (Invoke-EntraOpsMsGraphQuery -Method "GET" -Uri "/beta/administrativeUnits?`$filter=DisplayName eq '$Name'" -OutputType PSObject -DisableCache)

        if (-not $AdministrativeUnit.id) {
            Write-Host "Creating Administrative Unit $($Name)"

            $AuParams = @{
                DisplayName = $Name
                Description = "This administrative unit contains assets of " + $($TierLevel.AdminTierLevelName) + " without any restricted management"
            }

            $AuParams.IsMemberManagementRestricted = $true
            $Body = $AuParams | ConvertTo-Json -Depth 10

            try {
                $CreatedAuObject = Invoke-EntraOpsMsGraphQuery -Method "POST" -Body $Body -Uri "/beta/administrativeUnits"
            }
            catch {
                Write-Warning "Can not create Administrative Unit $($AuParams.DisplayName)! Error: $_"
            }

            # Check if AU has been created successfully, wait for delay and retry if not available yet
            Try {
                Do { Start-Sleep -Seconds 1 }
                Until ($AdministrativeUnit = (Invoke-EntraOpsMsGraphQuery -Method "GET" -Body $Body -Uri "/beta/administrativeUnits/$($CreatedAuObject.id)" -DisableCache))
                Write-Host "$($AdministrativeUnit.displayName) has been created successfully" -f Green
            }
            Catch {
                Write-Warning "$($AuParams.DisplayName) not available yet"
            }
        }
        else {
            Write-Host "Administrativer Unit $($AdministrativeUnit.displayName) already exists"
        }
    }
    #endregion
}