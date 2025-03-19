<#
.SYNOPSIS
    Established connection to required PowerShell modules and requests access tokens for EntraOps PowerShell Module

.DESCRIPTION
    Connection to Azure Resourec Management and Microsoft Graph API by using Connect-AzAccount and Connect-MgGraph.

.PARAMETER AuthenticationType
    Type of authentication to be used for Azure and Microsoft Graph. Default is "AlreadyAuthenticated".
    .NOTES

.EXAMPLE
    Using Interactive Sign-In of User with double authentication to Az PowerShell (Connect-AzAccount) and Microsoft Graph SDK (Connect-MgGraph)
    Connect-EntraOps -AuthenticationType "UserInteractive" -TenantName "cloudlab.onmicrosoft.com"

.EXAMPLE
    Using authenticated session to Az PowerShell (Connect-AzAccount) in GitHub workflow or any other workload identity environment to request access token for Microsoft Graph SDK (by Get-AzAccessToken) without any further initial authentication.
    Connect-EntraOps -AuthenticationType "AlreadyAuthenticated" -TenantName "cloudlab.onmicrosoft.com"

.EXAMPLE
    Using System-assigned Managed Identity to get Service Principal of Contoso Tenant from Azure KeyVault (Multi-Tenant Use Case) in CloudLab Tenant
    Connect-EntraOps -AuthenticationType "ServicePrincipal" -TenantName "contoso.onmicrosoft.com" -KeyVaultTenantName "cloudlab.onmicrosoft.com" -KeyVaultName "entraops-kva" -PrefixSecretName "AADOps-"

.EXAMPLE
    Using Managed Identity (User Assigned) to sign-in to Azure and Microsoft Graph
    Connect-EntraOps -AuthenticationType "UserAssignedMSI" -AccountId "b8c2f9d2-9886-4981-b9c2-e8e3726a871d" -TenantName "cloudlab.onmicrosoft.com"
#>
function Connect-EntraOps {
    [cmdletbinding()]
    param (
        [Parameter(Mandatory = $False)]
        [ValidateSet('UserInteractive', 'SystemAssignedMSI', 'UserAssignedMSI', 'FederatedCredentials', 'AlreadyAuthenticated', 'DeviceAuthentication')]
        [System.String]$AuthenticationType = "AlreadyAuthenticated"
        ,
        [Parameter(Mandatory = $False)]
        [ValidateSet("beta", "v1.0")]
        [System.String]$GraphApiVersion = "beta"
        ,
        [Parameter(Mandatory = $False)]
        [System.String]$AccountId
        ,
        [Parameter(Mandatory = $True)]
        [System.String]$TenantName
        ,
        [Parameter(Mandatory = $False)]
        [System.String]$TenantId
        ,
        [Parameter(Mandatory = $False)]
        [boolean]$MultiTenantRepo = $false
        ,
        [Parameter(Mandatory = $False)]
        [boolean]$UseAzPwshOnly = $false
        ,
        [Parameter(Mandatory = $False)]
        [System.String]$AzArmAccessToken
        ,
        [Parameter(Mandatory = $False)]
        [System.String]$MsGraphAccessToken
        ,
        [Parameter(Mandatory = $False)]
        [ValidateScript({ Test-Path $_ })]
        [System.String]$ConfigFilePath
    )

    Process {

        $ErrorActionPreference = "Stop"

        #region Switch between Microsoft Graph SDK (Invoke-MgGraphRequest) and Azure PowerShell only in combination with Invoke-RestMethod
        if ($UseAzPwshOnly -eq $true) {
            New-Variable -Name UseAzPwshOnly -Value $True -Scope Global -Force
        } else {
            New-Variable -Name UseAzPwshOnly -Value $False -Scope Global -Force

            $RequiredCoreModules = @{
                ModuleName    = 'Microsoft.Graph.Authentication'
                ModuleVersion = '2.0.0'
            }
            $RequiredCoreModules | ForEach-Object { Install-EntraOpsRequiredModule -ModuleName $_.ModuleName -MinimalVersion $_.ModuleVersion }

            $Scopes = @(
                "AdministrativeUnit.Read.All",
                "Application.Read.All",
                "CustomSecAttributeAssignment.Read.All",
                "DeviceManagementConfiguration.Read.All",
                "DeviceManagementManagedDevices.Read.All",
                "DeviceManagementRBAC.Read.All",
                "DeviceManagementServiceConfig.Read.All",
                "Directory.Read.All",
                "DirectoryRecommendations.Read.All",
                "EntitlementManagement.Read.All",
                "Group.Read.All",
                "PrivilegedAccess.Read.AzureADGroup",
                "PrivilegedEligibilitySchedule.Read.AzureADGroup",
                "Policy.Read.All",
                "RoleManagement.Read.All",
                "ThreatHunting.Read.All",
                "User.Read.All"
            )
        }
        #endregion

        #region Switch to choose authentication method for Azure and Microsoft Graph
        switch ( $AuthenticationType ) {
            UserInteractive {
                try {
                    Write-Output "Logging in to Azure..."
                    Connect-AzAccount -Tenant $TenantName -ErrorAction Stop | Out-Null
                    if ($TenantId -ne (Get-AzContext).Tenant.Id -or $null -eq $TenantId) {
                        $TenantId = (Get-AzContext).Tenant.Id
                    }
                    Write-Output "Succesfully logged in to Azure"
                    Write-Output "Logging in to Microsoft Graph..."
                    Connect-MgGraph -TenantId $TenantId -NoWelcome -ErrorAction Stop -Scopes $Scopes
                    Write-Output "Succesfully logged in to Microsoft Graph"
                } catch {
                    Write-Error -Message $_.Exception
                    throw $_.Exception
                }
            }
            DeviceAuthentication {
                try {
                    Write-Output "Logging in to Azure..."
                    Connect-AzAccount -Tenant $TenantName -ErrorAction Stop -UseDeviceAuthentication | Out-Null
                    if ($TenantId -ne (Get-AzContext).Tenant.Id -or $null -eq $TenantId) {
                        $TenantId = (Get-AzContext).Tenant.Id
                    }
                    Write-Output "Succesfully logged in to Azure"
                    Write-Output "Logging in to Microsoft Graph..."
                    Connect-MgGraph -TenantId $TenantId -NoWelcome -ErrorAction Stop -Scopes $Scopes -UseDeviceAuthentication
                    Write-Output "Succesfully logged in to Microsoft Graph"
                } catch {
                    Write-Error -Message $_.Exception
                    throw $_.Exception
                }
            }
            SystemAssignedMSI {
                try {
                    Write-Output "Logging in to Azure..."
                    Connect-AzAccount -Identity -ErrorAction Stop
                    Write-Output "Succesfully logged in to Azure"
                    Write-Output "Logging in to Microsoft Graph..."
                    Connect-MgGraph -Identity -ErrorAction Stop -NoWelcome
                    Write-Output "Succesfully logged in to Microsoft Graph"
                } catch {
                    Write-Error -Message $_.Exception
                    throw $_.Exception
                }
            }
            UserAssignedMSI {
                try {
                    Write-Output "Logging in to Azure..."
                    Connect-AzAccount -Identity -AccountId $AccountId -ErrorAction Stop
                    Write-Output "Succesfully logged in to Azure"
                    Write-Output "Logging in to Microsoft Graph..."
                    Connect-MgGraph -Identity -ClientId $AccountId -NoWelcome -ErrorAction Stop
                    Write-Output "Succesfully logged in to Microsoft Graph"
                } catch {
                    Write-Error -Message $_.Exception
                    throw $_.Exception
                }
            }
            FederatedCredentials {
                if ($Null -eq (Get-AzContext).Tenant.Id) {
                    throw "Federated environment is not already authenticated"
                }
                try {
                    $SecureAccessToken = (Get-AzAccessToken -ResourceTypeName "MSGraph" -AsSecureString).Token
                    Connect-MgGraph -AccessToken $SecureAccessToken -ErrorAction Stop -NoWelcome
                } catch {
                    throw $_.Exception
                }
            }
            AlreadyAuthenticated {
                if ($AccountId -and $MsGraphAccessToken -and $AzArmAccessToken) {
                    Connect-AzAccount -AccountId $AccountId -AccessToken $AzArmAccessToken -Tenant $TenantName

                    if ($UseAzPwshOnly -eq $true) {
                        New-Variable -Name MsGraphAccessToken -Value $MsGraphAccessToken -Scope Script -Force
                    } else {
                        $SecureMsGraphAccessToken = $MsGraphAccessToken | ConvertTo-SecureString -AsPlainText -Force
                        Connect-MgGraph -AccessToken $SecureMsGraphAccessToken -NoWelcome
                    }
                } elseif ($Null -ne (Get-AzContext).Tenant.Id) {
                    try {
                        $SecureAccessToken = (Get-AzAccessToken -ResourceTypeName "MSGraph" -AsSecureString).Token
                        Connect-MgGraph -AccessToken $SecureAccessToken -ErrorAction Stop -NoWelcome
                    } catch {
                        throw $_.Exception
                    }
                } else {
                    Write-Error -Message 'User or workload is not already authenticated. This authentication method is the default for EntraOps. Check "Get-Help Connect-EntraOps" to review the various options. Authenticated Azure PowerShell session is required for using "AlreadyAuthenticated" mode.'
                }
            }
        }
        #endregion

        #region Summary of established connection to ARM and Microsoft Graph API
        if ($UseAzPwshOnly -eq $true) {
            Write-Verbose -Message "Connected to Azure Management"
            $AzContext = Get-AzContext | Select-Object Account, Tenant, TokenCache
            Write-Verbose $($AzContext)
        } else {
            Write-Verbose -Message "Connected to Azure Management"
            $AzContext = Get-AzContext | Select-Object Account, Tenant, TokenCache
            Write-Verbose $($AzContext)

            Write-Verbose -Message "Connected to Microsoft Graph"
            $MgContext = Get-MgContext | Select-Object ClientId, TenantId, AppName, ContextScope
            Write-Verbose -Message $($MgContext)

            Write-Verbose "Scoped permissions in Microsoft Graph"
            $MgScopes = (Get-MgContext).Scopes
            Write-Verbose -Message $($MgScopes | Out-String)
        }
        #endregion

        #region Import Environment variables if exists
        if ($ConfigFilePath) {
            try {
                $EntraOpsConfig = Get-Content -Path $ConfigFilePath | ConvertFrom-Json -Depth 10 -AsHashtable
            } catch {
                Write-Error "Issue to import config file $($ConfigFilePath)! Check if the file exists and is in JSON format."
            }
            # Remove Ingest or Apply* parameters from config file and show configuration
            $EntraOpsConfig.AutomatedClassificationUpdate.Remove("ApplyAutomatedClassificationUpdate")
            $EntraOpsConfig.AutomatedControlPlaneScopeUpdate.Remove("ApplyAutomatedControlPlaneScopeUpdate")
            if ($EntraOpsConfig.LogAnalytics) { $EntraOpsConfig.LogAnalytics.Remove("IngestToLogAnalytics") }
            if ($EntraOpsConfig.SentinelWatchLists) { $EntraOpsConfig.SentinelWatchLists.Remove("IngestToWatchLists") }
            if ($EntraOpsConfig.AutomatedAdministrativeUnitManagement) { $EntraOpsConfig.AutomatedAdministrativeUnitManagement.Remove("ApplyAdministrativeUnitAssignments") }
            if ($EntraOpsConfig.AutomatedConditionalAccessTargetGroups) { $EntraOpsConfig.AutomatedConditionalAccessTargetGroups.Remove("ApplyConditionalAccessTargetGroups") }
            if ($EntraOpsConfig.AutomatedRmauAssignmentsForUnprotectedObjects) { $EntraOpsConfig.AutomatedRmauAssignmentsForUnprotectedObjects.Remove("ApplyRmauAssignmentsForUnprotectedObjects") }

            New-Variable -Name EntraOpsConfig -Value $EntraOpsConfig -Scope Global -Force
            Write-Verbose -Message "Config file $($ConfigFilePath) imported"
        }
        #endregion

        #region Set global variables
        New-Variable -Name TenantIdContext -Value $TenantId -Scope Global -Force
        New-Variable -Name TenantNameContext -Value $TenantName -Scope Global -Force
        if ($MultiTenantRepo -eq $true) {
            New-Variable -Name DefaultFolderClassification -Value "$EntraOpsBaseFolder/Classification/$($TenantName)/" -Scope Global -Force
            New-Variable -Name DefaultFolderClassifiedEam -Value "$EntraOpsBaseFolder/PrivilegedEAM/$($TenantName)/" -Scope Global -Force
            Write-Verbose -Message "Multi Tenant in Repository"
        } else {
            New-Variable -Name DefaultFolderClassification -Value "$EntraOpsBaseFolder/Classification/" -Scope Global -Force
            New-Variable -Name DefaultFolderClassifiedEam -Value "$EntraOpsBaseFolder/PrivilegedEAM/" -Scope Global -Force
            Write-Verbose -Message "Single Tenant in Repository"
        }
        #endregion
    }
}