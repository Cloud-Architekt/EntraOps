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

.PARAMETER IncludeUnprotectedDevices
    Also ensure AUs exist for devices owned by/associated to privileged users (OwnedDevices, AssociatedPawDevice), not only for unprotected users/groups.

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
        [ValidateSet("Azure", "EntraID", "IdentityGovernance", "ResourceApps", "DeviceManagement", "Defender")]
        [Array]$RbacSystems = ("Azure", "EntraID", "IdentityGovernance", "ResourceApps", "DeviceManagement", "Defender")
        ,
        [Parameter(Mandatory = $False)]
        [switch]$IncludeUnprotectedDevices
        ,
        [Parameter(Mandatory = $False)]
        [boolean]$ApplyRmauAssignmentsForUnprotectedObjects = $false
        ,
        [Parameter(Mandatory = $False)]
        [ValidateRange(0, 1)]
        [double]$RemovalSafetyThreshold = 0.5
    )

    # Get Tier Levels with unprotected privileged EAM objects
    $UnprotectedPrivilegedEamTierLevels = foreach ($RbacSystem in $RbacSystems) {
        # Get all privileged EAM objects
        $PrivilegedEamObjects = Get-Content "$DefaultFolderClassifiedEam/$RbacSystem/$($RbacSystem).json" | ConvertFrom-Json

        # Get all privileged EAM objects without any restricted management and their tier levels
        $UnprotectedPrivilegedUser = $PrivilegedEamObjects | Where-Object { $_.RestrictedManagementByRAG -ne $True -and $_.RestrictedManagementByAadRole -ne $True -and $_.RestrictedManagementByRMAU -ne $True -and $_.ObjectType -in $FilterObjectType }
        $UnprotectedPrivilegedUser.Classification | select-object -unique AdminTierLevelName, AdminTierLevel
    }

    # Get all unique AdminTierLevels which needs to be iterated for creating Administrative Units
    $PrivilegedEamTierLevels = Get-ChildItem -Path "$($DefaultFolderClassification)/Templates" -File -Recurse -Exclude *.Param.json | foreach-object { Get-Content $_.FullName -Filter "*.json" | ConvertFrom-Json }
    $SelectedPrivilegedEamTierLevels = $PrivilegedEamTierLevels | where-object { $_.EAMTierLevelName -in $ApplyToAccessTierLevel } | select-object -unique @{Name = 'AdminTierLevel'; Expression = 'EAMTierLevelTagValue' }, @{Name = 'AdminTierLevelName'; Expression = 'EAMTierLevelName' }
    $RequiredTierLevelNames = @($UnprotectedPrivilegedEamTierLevels.AdminTierLevelName)
    if ($IncludeUnprotectedDevices) {
        $DeviceTierLevelNames = foreach ($RbacSystem in $RbacSystems) {
            $PrivilegedEamObjects = Get-Content "$DefaultFolderClassifiedEam/$RbacSystem/$($RbacSystem).json" | ConvertFrom-Json
            $PrivilegedEamObjects | Where-Object {
                $_.ObjectType -eq "user" -and
                (@($_.OwnedDevices).Count -gt 0 -or @(Get-EntraOpsPawDeviceObjectId -Object $_).Count -gt 0)
            } | ForEach-Object { $_.Classification.AdminTierLevelName }
        }
        $RequiredTierLevelNames += $DeviceTierLevelNames
    }
    $SelectedPrivilegedEamTierLevels = $SelectedPrivilegedEamTierLevels | Where-Object { $_.AdminTierLevelName -in @($RequiredTierLevelNames | Select-Object -Unique) }
    #endregion

    # Create Administrative Units for each Tier Level
    foreach ($TierLevel in $SelectedPrivilegedEamTierLevels) {
        $Name = "Tier" + $TierLevel.AdminTierLevel + "-" + $TierLevel.AdminTierLevelName + ".UnprotectedObjects"
        $AdministrativeUnits = @(Invoke-EntraOpsMsGraphQuery -Method "GET" -Uri "/beta/administrativeUnits?`$filter=DisplayName eq '$(ConvertTo-EntraOpsODataStringLiteral -Value $Name)'" -OutputType PSObject -DisableCache)
        $AdministrativeUnit = Select-EntraOpsUniqueGraphObject -InputObject $AdministrativeUnits -ObjectDescription "administrative unit '$Name'" -AllowNotFound

        if (-not $AdministrativeUnit.id) {
            Write-Host "Creating Administrative Unit $($Name)"
            $CreatedAuObject = $null

            $AuParams = @{
                DisplayName = $Name
                Description = "This administrative unit contains assets of " + $($TierLevel.AdminTierLevelName) + " without any restricted management"
            }

            $AuParams.IsMemberManagementRestricted = $true
            $Body = $AuParams | ConvertTo-Json -Depth 10

            try {
                $CreatedAuObject = Invoke-EntraOpsMsGraphQuery -Method "POST" -Body $Body -Uri "/beta/administrativeUnits" -ThrowOnFailure
            } catch {
                Write-Warning "Can not create Administrative Unit $($AuParams.DisplayName)! Error: $_"
            }

            # Poll only after Administrative Unit creation returns an object ID.
            if ($CreatedAuObject.id) {
                $AdministrativeUnit = $null
                $MaxPollSeconds = 60
                for ($i = 0; $i -lt $MaxPollSeconds -and -not $AdministrativeUnit; $i++) {
                    $AdministrativeUnit = Invoke-EntraOpsMsGraphQuery -Method "GET" -Uri "/beta/administrativeUnits/$($CreatedAuObject.id)" -DisableCache -SuppressNotFoundWarning
                    if (-not $AdministrativeUnit) { Start-Sleep -Seconds 1 }
                }
                if ($AdministrativeUnit) {
                    Write-Host "$($AdministrativeUnit.displayName) has been created successfully" -ForegroundColor Green
                } else {
                    Write-Warning "$($AuParams.DisplayName) not available after $MaxPollSeconds second(s)."
                }
            }
        } else {
            Write-Host "Administrative Unit $($AdministrativeUnit.displayName) already exists"
        }
    }
    #endregion
}