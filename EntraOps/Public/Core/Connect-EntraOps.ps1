<#
.SYNOPSIS
    Established connection to required PowerShell modules and requests access tokens for EntraOps PowerShell Module

.DESCRIPTION
    Connection to Azure Resource Management and Microsoft Graph API by using Connect-AzAccount and Connect-MgGraph.

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
        [ValidatePattern('^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$')]
        [System.String]$TenantName
        ,
        [Parameter(Mandatory = $False)]
        [System.String]$TenantId
        ,
        [Parameter(Mandatory = $False)]
        [boolean]$MultiTenantRepo = $false
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
        ,
        [Parameter(Mandatory = $False)]
        [switch]$NoWelcome
        ,
        [Parameter(Mandatory = $False)]
        [switch]$UseInvokeRestMethodOnly       
    )

    Process {

        $ErrorActionPreference = "Stop"

        # Display welcome banner unless suppressed
        if (-not $NoWelcome) {
            # Robustly resolve module manifest path
            $ManifestPath = if ($MyInvocation.MyCommand.Module.ModuleBase) {
                Join-Path $MyInvocation.MyCommand.Module.ModuleBase "EntraOps.psd1"
            } else {
                # Fallback to relative path if module context is missing (e.g. running script directly)
                "$PSScriptRoot/../../EntraOps.psd1"
            }
            
            if (Test-Path $ManifestPath) {
                $ModuleManifest = Import-PowerShellDataFile $ManifestPath
                $ModuleVersion = $($ModuleManifest.ModuleVersion)
            } else {
                $ModuleVersion = "Unknown"
            }

            $PSEnvironment = "PowerShell " + ($PSVersionTable.PSEdition) + " " + ($PSVersionTable.PSVersion.ToString())

            $Splash = @"
 ______       _              ____
|  ____|     | |            / __ \
| |__   _ __ | |_ _ __ __ _| |  | |_ __  ___
|  __| | '_ \| __| '__/ _`  | |  | | '_ \/ __|
| |____| | | | |_| | | (_| | |__| | |_) \__ \
|______|_| |_|\__|_|  \__,_|\____/| .__/|___/
                                  | |
                                  |_|

Version $($ModuleVersion) on $($PSEnvironment)
Community Project by Thomas Naunheim - www.entraops.com
"@

            Write-Host $Splash -ForegroundColor Blue
        }
        #region Switch between Microsoft Graph SDK (Invoke-MgGraphRequest) and Azure PowerShell only in combination with Invoke-RestMethod
        if ($UseInvokeRestMethodOnly -eq $true) {
            New-Variable -Name UseInvokeRestMethodOnly -Value $True -Scope Global -Force
        } else {
            New-Variable -Name UseInvokeRestMethodOnly -Value $False -Scope Global -Force        

            $RequiredCoreModules = @{
                ModuleName    = 'Microsoft.Graph.Authentication'
                ModuleVersion = '2.0.0'
            }
            # Recommendation 1: Validate module availability before installation check
            $RequiredCoreModules | ForEach-Object {
                if (-not (Get-Module -Name $_.ModuleName)) {
                    Install-EntraOpsRequiredModule -ModuleName $_.ModuleName -MinimalVersion $_.ModuleVersion
                }
            }

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
                # Recommendation 2: Optimize context retrieval to avoid redundant cmdlet calls
                $CurrentAzContext = Get-AzContext
                $CurrentMgContext = Get-MgContext

                if ($AccountId -and $MsGraphAccessToken -and $AzArmAccessToken) {
                    Connect-AzAccount -AccountId $AccountId -AccessToken $AzArmAccessToken -Tenant $TenantName

                    $SecureMsGraphAccessToken = $MsGraphAccessToken | ConvertTo-SecureString -AsPlainText -Force
                    Connect-MgGraph -AccessToken $SecureMsGraphAccessToken -NoWelcome
                    
                } elseif ($Null -ne $CurrentAzContext.Tenant.Id -and $Null -ne $CurrentMgContext.TenantId) {
                    try {
                        $SecureAccessToken = (Get-AzAccessToken -ResourceTypeName "MSGraph" -AsSecureString).Token
                        Connect-MgGraph -AccessToken $SecureAccessToken -ErrorAction Stop -NoWelcome
                    } catch {
                        $ErrorMessage = if ($null -ne $_.Exception.Message) { $_.Exception.Message } else { $_.ToString() }
                        throw "Failed to connect to Microsoft Graph using Azure access token: $ErrorMessage"
                    }                    
                } elseif ($Null -ne $CurrentAzContext.Tenant.Id) {
                    try {
                        $SecureAccessToken = (Get-AzAccessToken -ResourceTypeName "MSGraph" -AsSecureString).Token
                        Connect-MgGraph -AccessToken $SecureAccessToken -ErrorAction Stop -NoWelcome
                    } catch {
                        $ErrorMessage = if ($null -ne $_.Exception.Message) { $_.Exception.Message } else { $_.ToString() }
                        throw "Failed to connect to Microsoft Graph using Azure access token: $ErrorMessage"
                    }
                } else {
                    Write-Error -Message 'User or workload is not already authenticated. This authentication method is the default for EntraOps. Check "Get-Help Connect-EntraOps" to review the various options. Authenticated Azure PowerShell session is required for using "AlreadyAuthenticated" mode.'
                }
            }
        }
        #endregion

        #region Summary of established connection to ARM and Microsoft Graph API
        # Recommendation 3: Optimize context retrieval and verbose output generation
        Write-Verbose -Message "Connected to Azure Management"
        $AzContext = Get-AzContext | Select-Object Account, Tenant, TokenCache
        Write-Verbose ($AzContext | Out-String)

        # Retrieve MG context once
        $MgContextRaw = Get-MgContext
        
        Write-Verbose -Message "Connected to Microsoft Graph"
        $MgContext = $MgContextRaw | Select-Object ClientId, TenantId, AppName, ContextScope
        Write-Verbose -Message ($MgContext | Out-String)

        Write-Verbose "Scoped permissions in Microsoft Graph"
        $MgScopes = $MgContextRaw.Scopes
        Write-Verbose -Message ($MgScopes | Out-String)
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
        New-Variable -Name XdrAvdHuntingAccess -Value ((Get-MgContext).Scopes -contains "ThreatHunting.Read.All") -Scope Global -Force
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

        if (-not $NoWelcome) {
            #region Display connection summary
            Write-Host ""
            Write-Host "═══════════════════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
            Write-Host "  🔐 Connection Summary" -ForegroundColor Cyan
            Write-Host "═══════════════════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
            
            Write-Host "  Authentication Type : $AuthenticationType" -ForegroundColor White

            # Get Azure context
            $AzContext = Get-AzContext -ErrorAction SilentlyContinue
            if ($AzContext) {
                Write-Host "  Azure Account       : $($AzContext.Account.Id)" -ForegroundColor Green
                Write-Host "  Azure Tenant        : $($AzContext.Tenant.Id)" -ForegroundColor White
                Write-Host "  Azure Subscription  : $($AzContext.Subscription.Name)" -ForegroundColor White
            } else {
                Write-Host "  Azure Account       : Not connected" -ForegroundColor Gray
            }
            
            # Get Microsoft Graph context
            $MgContext = Get-MgContext
            if ($MgContext) {
                Write-Host "  Graph Account       : $($MgContext.Account)" -ForegroundColor Green
                Write-Host "  Graph Tenant        : $($MgContext.TenantId)" -ForegroundColor White
                Write-Host "  Graph Auth Type     : $($MgContext.AuthType)" -ForegroundColor White
                
                # Display scopes (truncate if too many)
                $Scopes = $MgContext.Scopes
                if ($Scopes.Count -gt 0) {
                    $ScopeDisplay = if ($Scopes.Count -le 5) {
                        $Scopes -join ", "
                    } else {
                        ($Scopes | Select-Object -First 5) -join ", " + " (+$($Scopes.Count - 5) more)"
                    }
                    Write-Host "  Graph Scopes        : $ScopeDisplay" -ForegroundColor White
                }
            } else {
                Write-Host "  Graph Account       : Not connected" -ForegroundColor Gray
            }
            
            Write-Host "═══════════════════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
            Write-Host ""
            #endregion
            
            #region Display cache information
            Write-Host "═══════════════════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
            Write-Host "  📦 Cache Configuration" -ForegroundColor Cyan
            Write-Host "═══════════════════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
            
            # Cache location
            Write-Host "  Cache Location      : $($__EntraOpsSession.PersistentCachePath)" -ForegroundColor White
            
            # Memory cache
            $MemoryCacheCount = $__EntraOpsSession.GraphCache.Count
            Write-Host "  Memory Cache        : $MemoryCacheCount entries" -ForegroundColor $(if ($MemoryCacheCount -gt 0) { "Green" } else { "Gray" })
            
            # Persistent cache statistics
            if (Test-Path $__EntraOpsSession.PersistentCachePath) {
                $PersistentFiles = Get-ChildItem -Path $__EntraOpsSession.PersistentCachePath -Filter "*.json" -ErrorAction SilentlyContinue
                $PersistentCount = $PersistentFiles.Count
                
                if ($PersistentCount -gt 0) {
                    $PersistentSizeMB = [Math]::Round(($PersistentFiles | Measure-Object -Property Length -Sum).Sum / 1MB, 2)
                    Write-Host "  Persistent Cache    : $PersistentCount files ($PersistentSizeMB MB)" -ForegroundColor Green
                    
                    # Show newest cache file
                    $NewestCache = $PersistentFiles | Sort-Object LastWriteTime -Descending | Select-Object -First 1
                    if ($NewestCache) {
                        $CacheAge = [Math]::Round(((Get-Date) - $NewestCache.LastWriteTime).TotalHours, 1)
                        Write-Host "  Latest Cache Update : $CacheAge hours ago" -ForegroundColor $(if ($CacheAge -lt 1) { "Green" } elseif ($CacheAge -lt 24) { "Yellow" } else { "Gray" })
                    }
                } else {
                    Write-Host "  Persistent Cache    : Empty (will populate on first API call)" -ForegroundColor Gray
                }
            } else {
                Write-Host "  Persistent Cache    : Directory will be created on first use" -ForegroundColor Gray
            }
            
            # Cache TTL settings
            Write-Host "  Default TTL         : $([Math]::Round($__EntraOpsSession.DefaultCacheTTL / 3600, 1)) hours" -ForegroundColor White
            Write-Host "  Static Data TTL     : $([Math]::Round($__EntraOpsSession.StaticDataCacheTTL / 3600, 1)) hours" -ForegroundColor White
            
            Write-Host "═══════════════════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
            Write-Host ""
            
            # Warning to disconnect when finished
            Write-Host "⚠️  REMINDER: Run 'Disconnect-EntraOps' when finished to:" -ForegroundColor Yellow
            Write-Host "   • Clear persistent cache on disk with results from your session and free memory" -ForegroundColor Yellow
            Write-Host "   • Disconnect from Azure Resource Management" -ForegroundColor Yellow
            Write-Host "   • Disconnect from Microsoft Graph API" -ForegroundColor Yellow
            Write-Host ""
            #endregion
        }
    }
}