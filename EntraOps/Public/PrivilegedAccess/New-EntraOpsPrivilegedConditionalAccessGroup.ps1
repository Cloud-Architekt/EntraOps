<#
.SYNOPSIS
    Create security groups based on EntraOps classification which can be used for targeting Conditional Access policies.

.DESCRIPTION
    Security Groups for the different Enterprise Access Levels will be created based on the classification of EntraOps.
    This security groups can be used for targeting Conditional Access policies.

.PARAMETER ApplyToAccessTierLevel
    Array of Access Tier Levels to be processed. Default is ControlPlane, ManagementPlane.

.PARAMETER FilterObjectType
    Array of object types to be processed. Default is User, Group.

.PARAMETER GroupPrefix
    String to define the prefix of the Conditional Access Inclusion Groups. Default is "sug_Entra.CA.IncludeUsers.PrivilegedAccounts."

.PARAMETER RbacSystems
    Array of RBAC systems to be processed. Default is Azure, AzureBilling, EntraID, IdentityGovernance, DeviceManagement, ResourceApps.

.PARAMETER AdminUnitName
    Name of the Administrative Unit which should be used by creating security groups. By default, groups will be created on directory-level and not assigned to an administrative unit.

.EXAMPLE
    Create Conditional Access Target Groups for EntraID, IdentityGovernance and ResourceApps RBAC systems on scope of the existing RMAU "Tier0-ControlPlane.0.ZTPolicy".
    New-EntraOpsPrivilegedConditionalAccessGroup -GroupPrefix "sug_Entra.CA.IncludeUsers.PrivilegedAccounts." -RbacSystems ("EntraID", "IdentityGovernance") -AdminUnitName "Tier0-ControlPlane.0.ZTPolicy"
#>

function New-EntraOpsPrivilegedConditionalAccessGroup {

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
        [string]$GroupPrefix = "sug_Entra.CA.IncludeUsers.PrivilegedAccounts."
        ,
        [Parameter(Mandatory = $False)]
        [ValidateSet("EntraID", "IdentityGovernance", "ResourceApps", "DeviceManagement", "Defender")]
        [Array]$RbacSystems = ("EntraID", "IdentityGovernance", "ResourceApps", "DeviceManagement", "Defender")
        ,
        [Parameter(Mandatory = $true)]
        [String]$AdminUnitName
    )

    foreach ($RbacSystem in $RbacSystems) {

        $Classification = "$DefaultFolderClassifiedEam/$RbacSystem/$($RbacSystem).json"

        #region Get principals from EAM classification files and filter out objects without classification and objects not related to the RBAC system or object type filter
        $PrivilegedEam = @()
        $PrivilegedEam += Get-ChildItem -Path $Classification | foreach-object { Get-Content $_.FullName -Filter "*.json" | ConvertFrom-Json }
        $PrivilegedEam = $PrivilegedEam | Where-Object { $_.ObjectType -in $FilterObjectType }
        $PrivilegedEamCount = ($PrivilegedEam | Where-Object { $null -eq $_.Classification }).count
        if ($PrivilegedEamCount -gt 0) { Write-Warning "Numbers of objects without classification: $PrivilegedEamCount" }
        $PrivilegedEamClassifiedObjects = $PrivilegedEam | where-object { $_.Classification.AdminTierLevel -notcontains $null -and $_.RoleSystem -eq $RbacSystem }

        # Get all unique AdminTierLevels which needs to be iterated for assigning objects to Conditional Access Target Groups
        $PrivilegedEamClassificationTierLevels = $PrivilegedEamClassifiedObjects | ForEach-Object {
            $Classification = $_.Classification
            $Classification | where-object { $_.AdminTierLevelName -in $ApplyToAccessTierLevel } | select-object -unique AdminTierLevel, AdminTierLevelName
        }
        $PrivilegedEamClassificationTierLevels = $PrivilegedEamClassificationTierLevels | select-object -unique AdminTierLevel, AdminTierLevelName
        #endregion

        #region Create Conditional Access Target Groups
        foreach ($TierLevel in $PrivilegedEamClassificationTierLevels) {

            Write-Verbose "Create CA target group for $($RbacSystem) - $($TierLevel.AdminTierLevelName)"

            $Name = "$GroupPrefix" + $TierLevel.AdminTierLevelName + "." + $($RbacSystem)
            $Group = (Invoke-EntraOpsMsGraphQuery -Method "GET" -Body $Body -Uri "/v1.0/groups?`$filter=DisplayName eq '$Name'" -OutputType PSObject -DisableCache)
            if (-not $Group.id) {

                $GroupParams = @{
                    "@odata.type"   = "#Microsoft.Graph.Group"
                    DisplayName     = $Name
                    SecurityEnabled = $True
                    MailEnabled     = $False
                    MailNickname    = "NotSet"
                    Description     = "This Conditional Access target groups contains assets of " + $TierLevel.AdminTierLevelName
                }
                $GroupParams = $GroupParams | ConvertTo-Json -Depth 10

                Write-Host "Creating Conditional Access Target Group $($Name)"
                if ($AdminUnitName) {
                    try {
                        $AdminUnitId = (Invoke-EntraOpsMsGraphQuery -Method "GET" -Body $Body -Uri "/beta/administrativeUnits?`$filter=DisplayName eq '$($AdminUnitName)'" -DisableCache).id
                        $CreatedGroupObject = Invoke-MgGraphRequest -Method "POST" -Body $GroupParams -Uri "https://graph.microsoft.com/beta/administrativeUnits/$($AdminUnitId)/members/" -ErrorAction Stop
                    }
                    catch {
                        Write-Error "Can not create Group $($GroupParams.Name)! Error: $_"
                    }
                }
                else {
                    try {
                        $CreatedGroupObject = Invoke-EntraOpsMsGraphQuery -Method "POST" -Body $GroupParams -Uri "/beta/groups"
                    }
                    catch {
                        Write-Error "Can not create Group $($GroupParams.Name)! Error: $_"
                    }
                }

                # Check if Security Group has been created successfully, wait for delay and retry if not available yet
                Try {
                    Do { Start-Sleep -Seconds 1 }
                    Until ($Group = (Invoke-EntraOpsMsGraphQuery -Method "GET" -Body $Body -Uri "/beta/groups/$($CreatedGroupObject.id)" -DisableCache))
                    Write-Host "$($Group.DisplayName) has been created successfully" -f Green
                }
                Catch {
                    Write-Warning "$($GroupParams.DisplayName) not available yet"
                }
            }
            else {
                Write-Host "Security group $($Group.displayName) already exists"
            }
        }
        #endregion
    }
}