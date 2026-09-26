<#
.SYNOPSIS
    Establishes connections to required PowerShell modules and requests EntraOps access tokens.

.DESCRIPTION
    Connection to Azure Resource Management and Microsoft Graph API by using Connect-AzAccount and Connect-MgGraph.

.PARAMETER AuthenticationType
    Type of authentication to be used for Azure and Microsoft Graph. Default is "AlreadyAuthenticated".

.PARAMETER UseInvokeRestMethodOnly
    Use Invoke-RestMethod instead of the Microsoft Graph SDK (Invoke-MgGraphRequest) for all
    Invoke-EntraOps*Query cmdlets in this session. The Microsoft Graph SDK is neither required nor
    installed in this mode; tokens are provided via -MsGraphAccessToken or acquired with
    Get-AzAccessToken from the Az PowerShell context. Can also be set through the config file
    (top-level setting "UseInvokeRestMethodOnly"); an explicit parameter wins over the config file.
    Note: parallel object resolution requires the Graph SDK and falls back to sequential processing
    in this mode. Connect-EntraOps itself also skips Connect-MgGraph for service-principal/managed-
    identity AuthenticationType values (SystemAssignedMSI, UserAssignedMSI, FederatedCredentials,
    AlreadyAuthenticated) in this mode - their Graph tokens come from Get-AzAccessToken instead, since
    application permissions are fully contained in a client-credentials token without needing
    per-request scopes. UserInteractive and DeviceAuthentication still call Connect-MgGraph (and thus
    still require Microsoft.Graph.Authentication) even with this switch enabled, because only
    Connect-MgGraph -Scopes can trigger the interactive/incremental consent prompt that delegated
    Graph scopes require; a warning is emitted when this fallback applies.

.EXAMPLE
    Using Interactive Sign-In of User with double authentication to Az PowerShell (Connect-AzAccount) and Microsoft Graph SDK (Connect-MgGraph)
    Connect-EntraOps -AuthenticationType "UserInteractive" -TenantName "contoso.onmicrosoft.com"

.EXAMPLE
    Using authenticated session to Az PowerShell (Connect-AzAccount) in GitHub workflow or any other workload identity environment to request access token for Microsoft Graph SDK (by Get-AzAccessToken) without any further initial authentication.
    Connect-EntraOps -AuthenticationType "AlreadyAuthenticated" -TenantName "contoso.onmicrosoft.com"

.EXAMPLE
    Using Managed Identity (User Assigned) to sign-in to Azure and Microsoft Graph
    Connect-EntraOps -AuthenticationType "UserAssignedMSI" -AccountId "00000000-0000-0000-0000-000000000000" -TenantName "contoso.onmicrosoft.com"
#>
function Connect-EntraOps {
    # -MsGraphAccessToken is a plaintext [string] by public contract (populated from workflow
    # secrets/federated tokens in CI pipelines); Connect-MgGraph -AccessToken requires a
    # SecureString, so the one-time in-memory conversion below is unavoidable without a breaking
    # change to the parameter type.
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingConvertToSecureStringWithPlainText', '', Justification = 'MsGraphAccessToken is an existing public string parameter fed by external pipeline secrets; converting it in memory for Connect-MgGraph -AccessToken does not expose a new plaintext secret, and changing the parameter to SecureString would break the public API.')]
    [cmdletbinding()]
    param (
        [Parameter(Mandatory = $False)]
        [ValidateSet('UserInteractive', 'SystemAssignedMSI', 'UserAssignedMSI', 'FederatedCredentials', 'AlreadyAuthenticated', 'DeviceAuthentication')]
        [System.String]$AuthenticationType = "AlreadyAuthenticated"
        ,
        [Parameter(Mandatory = $False)]
        [ValidateSet("Report", "ServiceEM")]
        [System.String]$Scope = "Report"
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
        [ValidatePattern('^$|^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$')]
        [System.String]$TenantId
        ,
        [Parameter(Mandatory = $False)]
        [ValidatePattern('^$|^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$')]
        [System.String]$ManagingTenantId
        ,
        [Parameter(Mandatory = $False)]
        [System.String]$ManagingTenantName
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

        #region Load tenant and managing tenant settings from config file if not provided as parameters
        if ($ConfigFilePath -and (Test-Path $ConfigFilePath)) {
            $EarlyConfig = Get-Content -Path $ConfigFilePath | ConvertFrom-Json
            if ([string]::IsNullOrEmpty($TenantId) -and -not [string]::IsNullOrEmpty($EarlyConfig.TenantId)) {
                $TenantId = $EarlyConfig.TenantId
            }
            if ([string]::IsNullOrEmpty($ManagingTenantId) -and -not [string]::IsNullOrEmpty($EarlyConfig.ManagingTenantId)) {
                $ManagingTenantId = $EarlyConfig.ManagingTenantId
            }
            if ([string]::IsNullOrEmpty($ManagingTenantName) -and -not [string]::IsNullOrEmpty($EarlyConfig.ManagingTenantName)) {
                $ManagingTenantName = $EarlyConfig.ManagingTenantName
            }
        }
        #endregion

        #region Switch between Microsoft Graph SDK (Invoke-MgGraphRequest) and Azure PowerShell only in combination with Invoke-RestMethod
        # Resolve the effective mode: explicit parameter > config file setting > default ($false)
        if (-not $PSBoundParameters.ContainsKey('UseInvokeRestMethodOnly') -and $null -ne $EarlyConfig.UseInvokeRestMethodOnly) {
            $UseInvokeRestMethodOnly = [bool]$EarlyConfig.UseInvokeRestMethodOnly
            Write-Verbose "UseInvokeRestMethodOnly set from config file: $UseInvokeRestMethodOnly"
        }

        # The module-private session store is the authoritative home of the mode - all
        # Invoke-EntraOps*Query cmdlets read it from there (a user-set global variable is
        # only honored as legacy fallback when the session store has no value)
        $__EntraOpsSession['UseInvokeRestMethodOnly'] = [bool]$UseInvokeRestMethodOnly

        # Clean up the flag persisted as global variable by previous module versions
        Remove-Variable -Name UseInvokeRestMethodOnly -Scope Global -Force -ErrorAction SilentlyContinue

        # Start each connection with fresh token state: cached tokens from a previous connection may
        # belong to another tenant and would otherwise be re-used until they expire. Tenant-keyed ARM
        # token entries stay valid; only the context-dependent 'default' entry must go.
        $__EntraOpsSession.MsGraphTokenCache.Clear()
        $__EntraOpsSession.ArmTokenCache.Remove('default')

        # Persist an explicitly provided Microsoft Graph access token in the module-private session
        # store so the Invoke-RestMethod path of Invoke-EntraOpsMsGraphQuery can use it (required for
        # token-based authentication where the Az context cannot mint new Graph tokens itself).
        # Deliberately not a global variable: module scope keeps the token out of the user-visible
        # session state (Get-Variable, transcripts, diagnostic dumps).
        if (-not [string]::IsNullOrEmpty($MsGraphAccessToken)) {
            # Read the real expiry from the JWT exp claim; fall back to a conservative default
            $ProvidedTokenExpiry = [DateTime]::UtcNow.AddMinutes(50)
            try {
                $PayloadPart = ($MsGraphAccessToken -split '\.')[1].Replace('-', '+').Replace('_', '/')
                switch ($PayloadPart.Length % 4) { 2 { $PayloadPart += '==' } 3 { $PayloadPart += '=' } }
                $TokenPayload = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($PayloadPart)) | ConvertFrom-Json
                if ($TokenPayload.exp) { $ProvidedTokenExpiry = [DateTimeOffset]::FromUnixTimeSeconds($TokenPayload.exp).UtcDateTime }
            } catch {
                Write-Verbose "Could not parse expiry from provided Microsoft Graph access token: $($_.Exception.Message)"
            }

            $__EntraOpsSession.MsGraphTokenCache['provided'] = @{ Token = $MsGraphAccessToken; Expiry = $ProvidedTokenExpiry }

            # Clean up a token persisted as global variable by previous module versions
            Remove-Variable -Name MsGraphAccessToken -Scope Global -Force -ErrorAction SilentlyContinue
        }

        # Azure authentication and ARM access are required in every connection mode.
        @(
            @{ ModuleName = 'Az.Accounts'; ModuleVersion = '2.19.0' }
            @{ ModuleName = 'Az.Resources'; ModuleVersion = '6.16.2' }
        ) | ForEach-Object {
            Install-EntraOpsRequiredModule -ModuleName $_.ModuleName -MinimalVersion $_.ModuleVersion
        }

        # The Microsoft Graph SDK is only required (and installed) when it is actually used
        if (-not $__EntraOpsSession['UseInvokeRestMethodOnly']) {
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
                "RemoteTenantGroups.Read.All",
                "RoleManagement.Read.All",
                "TenantGovernance-Relationship.Read.All",
                "ThreatHunting.Read.All",
                "User.Read.All",
                "Zone.Read.All"
            )

            if ($Scope -eq "ServiceEM") {
                $MgGraphScopesServiceEM = @(
                    "Directory.AccessAsUser.All",
                    "EntitlementManagement.ReadWrite.All",
                    "RoleManagementPolicy.ReadWrite.AzureADGroup",
                    "RoleManagementPolicy.ReadWrite.Directory",
                    "RoleManagement.ReadWrite.Directory",
                    "PrivilegedEligibilitySchedule.ReadWrite.AzureADGroup",
                    "PrivilegedAccess.ReadWrite.AzureADGroup"
                )
                $Scopes += $MgGraphScopesServiceEM
            }
        }
        #endregion

        # In UseInvokeRestMethodOnly mode, Invoke-EntraOps*Query cmdlets acquire and cache their own
        # Microsoft Graph token via Get-AzAccessToken, so Connect-MgGraph is unnecessary for the
        # service-principal/managed-identity authentication types below: their Graph permissions are
        # Application permissions already admin-consented to the app, and a client-credentials token
        # always contains every granted app role (no per-request scope negotiation needed).
        # UserInteractive/DeviceAuthentication are the exception: Get-AzAccessToken cannot trigger the
        # interactive/incremental consent prompt that delegated Graph scopes require, so those two
        # authentication types still fall back to Connect-MgGraph (and therefore still require
        # Microsoft.Graph.Authentication to be installed) even when UseInvokeRestMethodOnly is enabled.
        $SkipGraphSdkAuth = [bool]$__EntraOpsSession['UseInvokeRestMethodOnly'] -and ($AuthenticationType -notin @('UserInteractive', 'DeviceAuthentication'))
        if ($__EntraOpsSession['UseInvokeRestMethodOnly'] -and $AuthenticationType -in @('UserInteractive', 'DeviceAuthentication')) {
            Write-Warning "UseInvokeRestMethodOnly is enabled, but AuthenticationType '$AuthenticationType' still requires Connect-MgGraph (Microsoft.Graph.Authentication module) as a fallback: Get-AzAccessToken cannot trigger the interactive/incremental admin-consent prompt needed for delegated Microsoft Graph scopes, only Connect-MgGraph -Scopes can. Use a service-principal-based AuthenticationType (SystemAssignedMSI, UserAssignedMSI, FederatedCredentials or AlreadyAuthenticated) to avoid this Graph SDK dependency, or provide an already-consented -MsGraphAccessToken."
        }

        #region Switch to choose authentication method for Azure and Microsoft Graph
        switch ( $AuthenticationType ) {
            UserInteractive {
                try {
                    # Pre-authenticate to managing tenant for cross-tenant access
                    if (-not [string]::IsNullOrEmpty($ManagingTenantId)) {
                        Write-Output "Pre-authenticating to managing tenant (Azure)..."
                        Connect-AzAccount -Tenant $ManagingTenantId -ErrorAction Stop | Out-Null
                        Write-Output "Pre-authenticating to managing tenant (Microsoft Graph) using Az token..."
                        $SecureManagingAccessToken = (Get-AzAccessToken -ResourceTypeName "MSGraph" -TenantId $ManagingTenantId -AsSecureString -ErrorAction Stop).Token
                        Connect-MgGraph -AccessToken $SecureManagingAccessToken -NoWelcome -ErrorAction Stop
                        Write-Output "Successfully pre-authenticated to managing tenant $ManagingTenantId"
                    }

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
                    # Pre-authenticate to managing tenant for cross-tenant access
                    if (-not [string]::IsNullOrEmpty($ManagingTenantId)) {
                        Write-Output "Pre-authenticating to managing tenant (Azure)..."
                        Connect-AzAccount -Tenant $ManagingTenantId -ErrorAction Stop -UseDeviceAuthentication | Out-Null
                        Write-Output "Pre-authenticating to managing tenant (Microsoft Graph) using Az token..."
                        $SecureManagingAccessToken = (Get-AzAccessToken -ResourceTypeName "MSGraph" -TenantId $ManagingTenantId -AsSecureString -ErrorAction Stop).Token
                        Connect-MgGraph -AccessToken $SecureManagingAccessToken -NoWelcome -ErrorAction Stop
                        Write-Output "Successfully pre-authenticated to managing tenant $ManagingTenantId"
                    }

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
                    if (-not $SkipGraphSdkAuth) {
                        Write-Output "Logging in to Microsoft Graph..."
                        Connect-MgGraph -Identity -ErrorAction Stop -NoWelcome
                        Write-Output "Succesfully logged in to Microsoft Graph"
                    } else {
                        Write-Verbose "UseInvokeRestMethodOnly is enabled: skipping Connect-MgGraph, Microsoft Graph tokens will be acquired via Get-AzAccessToken when needed."
                    }
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
                    if (-not $SkipGraphSdkAuth) {
                        Write-Output "Logging in to Microsoft Graph..."
                        Connect-MgGraph -Identity -ClientId $AccountId -NoWelcome -ErrorAction Stop
                        Write-Output "Succesfully logged in to Microsoft Graph"
                    } else {
                        Write-Verbose "UseInvokeRestMethodOnly is enabled: skipping Connect-MgGraph, Microsoft Graph tokens will be acquired via Get-AzAccessToken when needed."
                    }
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
                    # Pre-authenticate to managing tenant for cross-tenant access
                    if (-not [string]::IsNullOrEmpty($ManagingTenantId)) {
                        $SecureManagingAccessToken = (Get-AzAccessToken -ResourceTypeName "MSGraph" -TenantId $ManagingTenantId -AsSecureString).Token
                        if (-not $SkipGraphSdkAuth) {
                            Write-Output "Pre-authenticating to managing tenant (Microsoft Graph)..."
                            Connect-MgGraph -AccessToken $SecureManagingAccessToken -ErrorAction Stop -NoWelcome
                            Write-Output "Successfully pre-authenticated to managing tenant $ManagingTenantId"
                        }
                    }

                    # Connect to target tenant
                    if (-not [string]::IsNullOrEmpty($TenantId)) {
                        $SecureAccessToken = (Get-AzAccessToken -ResourceTypeName "MSGraph" -TenantId $TenantId -AsSecureString).Token
                    } else {
                        $SecureAccessToken = (Get-AzAccessToken -ResourceTypeName "MSGraph" -AsSecureString).Token
                    }
                    if (-not $SkipGraphSdkAuth) {
                        Connect-MgGraph -AccessToken $SecureAccessToken -ErrorAction Stop -NoWelcome
                    } else {
                        Write-Verbose "UseInvokeRestMethodOnly is enabled: skipping Connect-MgGraph, Microsoft Graph tokens will be acquired via Get-AzAccessToken when needed."
                    }

                    # Pre-warm an ARM access token too (same pattern as above), while the GitHub OIDC
                    # federated assertion behind this Az context is still fresh (it's only valid for a
                    # few minutes). Az.Accounts caches acquired tokens per resource/tenant across the
                    # job's remaining steps, so a later step's first-ever ARM request (e.g. Azure RBAC
                    # collection) is served from this cached token instead of needing a new assertion
                    # exchange once it has expired. Non-fatal: callers that never touch Azure RBAC
                    # should not fail Connect-EntraOps over this optimization.
                    try {
                        if (-not [string]::IsNullOrEmpty($TenantId)) {
                            $SecureArmAccessToken = (Get-AzAccessToken -ResourceUrl "https://management.azure.com/" -TenantId $TenantId -AsSecureString).Token
                        } else {
                            $SecureArmAccessToken = (Get-AzAccessToken -ResourceUrl "https://management.azure.com/" -AsSecureString).Token
                        }
                    } catch {
                        Write-Verbose "Could not pre-warm an Azure Resource Manager access token: $($_.Exception.Message)"
                    }
                } catch {
                    throw $_.Exception
                }
            }
            AlreadyAuthenticated {
                # Recommendation 2: Optimize context retrieval to avoid redundant cmdlet calls
                $CurrentAzContext = Get-AzContext
                $CurrentMgContext = if (-not $SkipGraphSdkAuth) { Get-MgContext } else { $null }

                # Pre-authenticate to managing tenant for cross-tenant access
                if (-not [string]::IsNullOrEmpty($ManagingTenantId) -and $Null -ne $CurrentAzContext.Tenant.Id) {
                    try {
                        $SecureManagingAccessToken = (Get-AzAccessToken -ResourceTypeName "MSGraph" -TenantId $ManagingTenantId -AsSecureString).Token
                        if (-not $SkipGraphSdkAuth) {
                            Write-Output "Pre-authenticating to managing tenant (Microsoft Graph)..."
                            Connect-MgGraph -AccessToken $SecureManagingAccessToken -ErrorAction Stop -NoWelcome
                            Write-Output "Successfully pre-authenticated to managing tenant $ManagingTenantId"
                        }
                    } catch {
                        Write-Warning "Failed to pre-authenticate to managing tenant: $($_.Exception.Message)"
                    }
                }

                if ($AccountId -and $MsGraphAccessToken -and $AzArmAccessToken) {
                    Connect-AzAccount -AccountId $AccountId -AccessToken $AzArmAccessToken -Tenant $TenantName

                    if (-not $SkipGraphSdkAuth) {
                        $SecureMsGraphAccessToken = $MsGraphAccessToken | ConvertTo-SecureString -AsPlainText -Force
                        Connect-MgGraph -AccessToken $SecureMsGraphAccessToken -NoWelcome
                    }

                } elseif ($Null -ne $CurrentAzContext.Tenant.Id -and $Null -ne $CurrentMgContext.TenantId) {
                    try {
                        $SecureAccessToken = (Get-AzAccessToken -ResourceTypeName "MSGraph" -AsSecureString).Token
                        Connect-MgGraph -AccessToken $SecureAccessToken -ErrorAction Stop -NoWelcome
                    } catch {
                        $ErrorMessage = if ($null -ne $_.Exception.Message) { $_.Exception.Message } else { $_.ToString() }
                        throw "Failed to connect to Microsoft Graph using Azure access token: $ErrorMessage"
                    }                    
                } elseif ($Null -ne $CurrentAzContext.Tenant.Id) {
                    if ($SkipGraphSdkAuth) {
                        Write-Verbose "UseInvokeRestMethodOnly is enabled: skipping Connect-MgGraph, Microsoft Graph tokens will be acquired via Get-AzAccessToken when needed."
                    } else {
                        try {
                            $SecureAccessToken = (Get-AzAccessToken -ResourceTypeName "MSGraph" -AsSecureString).Token
                            Connect-MgGraph -AccessToken $SecureAccessToken -ErrorAction Stop -NoWelcome
                        } catch {
                            $ErrorMessage = if ($null -ne $_.Exception.Message) { $_.Exception.Message } else { $_.ToString() }
                            throw "Failed to connect to Microsoft Graph using Azure access token: $ErrorMessage"
                        }
                    }
                } else {
                    Write-Error -Message 'User or workload is not already authenticated. This authentication method is the default for EntraOps. Check "Get-Help Connect-EntraOps" to review the various options. Authenticated Azure PowerShell session is required for using "AlreadyAuthenticated" mode.'
                }
            }
        }
        #endregion

        #region Verify connection to target tenant
        if (-not [string]::IsNullOrEmpty($TenantId)) {
            $VerifyAzContext = Get-AzContext
            if ($VerifyAzContext -and $VerifyAzContext.Tenant.Id -ne $TenantId) {
                Write-Output "Azure context is on tenant $($VerifyAzContext.Tenant.Id), switching to target tenant $TenantId..."
                Set-AzContext -TenantId $TenantId -ErrorAction Stop | Out-Null
                Write-Output "Successfully switched Azure context to target tenant"
            }

            $VerifyMgContext = if (-not $SkipGraphSdkAuth) { Get-MgContext } else { $null }
            if ($VerifyMgContext -and $VerifyMgContext.TenantId -ne $TenantId) {
                Write-Output "Microsoft Graph is connected to $($VerifyMgContext.TenantId), reconnecting to target tenant $TenantId..."
                try {
                    $SecureTargetAccessToken = (Get-AzAccessToken -ResourceTypeName "MSGraph" -TenantId $TenantId -AsSecureString).Token
                    Connect-MgGraph -AccessToken $SecureTargetAccessToken -ErrorAction Stop -NoWelcome
                    Write-Output "Successfully reconnected Microsoft Graph to target tenant"
                } catch {
                    Write-Warning "Could not reconnect Microsoft Graph to target tenant ${TenantId}: $($_.Exception.Message)"
                }
            }
        }
        #endregion

        #region Summary of established connection to ARM and Microsoft Graph API
        # Recommendation 3: Optimize context retrieval and verbose output generation
        Write-Verbose -Message "Connected to Azure Management"
        $AzContextRaw = Get-AzContext
        $AzContext = $AzContextRaw | Select-Object Account, Tenant, TokenCache
        Write-Verbose ($AzContext | Out-String)

        # Retrieve MG context once (skipped when Connect-MgGraph was itself skipped in REST-only mode)
        $MgContextRaw = if (-not $SkipGraphSdkAuth) { Get-MgContext } else { $null }

        if ($MgContextRaw) {
            Write-Verbose -Message "Connected to Microsoft Graph"
        } else {
            Write-Verbose -Message "Not connected via Microsoft Graph SDK (UseInvokeRestMethodOnly mode: tokens are acquired via Get-AzAccessToken as needed)"
        }
        $MgContext = $MgContextRaw | Select-Object ClientId, TenantId, AppName, ContextScope
        Write-Verbose -Message ($MgContext | Out-String)

        Write-Verbose "Scoped permissions in Microsoft Graph"
        $MgScopes = $MgContextRaw.Scopes
        Write-Verbose -Message ($MgScopes | Out-String)
        #endregion

        #region Validate baseline Graph scopes for already-authenticated user sessions
        if ($AuthenticationType -eq 'AlreadyAuthenticated' -and $AzContextRaw.Account.Type -eq 'User' -and $MgContextRaw) {
            $MissingScopes = @($Scopes | Where-Object { $_ -notin $MgContextRaw.Scopes })
            $TenantGovernanceRelationshipScope = 'TenantGovernance-Relationship.Read.All'
            $MissingBaselineScopes = @($MissingScopes | Where-Object { $_ -ne $TenantGovernanceRelationshipScope })
            if ($MissingBaselineScopes.Count -gt 0) {
                Write-Warning "The already-authenticated user session is missing $($MissingBaselineScopes.Count) baseline EntraOps delegated scope(s): $($MissingBaselineScopes -join ', '). Dependent collection steps may fail with 403 Forbidden. Reconnect with the missing scopes consented."
            }
            if ($MissingScopes -contains $TenantGovernanceRelationshipScope) {
                $HasManagingTenantConfiguration = -not [string]::IsNullOrWhiteSpace($ManagingTenantId) -or -not [string]::IsNullOrWhiteSpace($ManagingTenantName)
                if ($HasManagingTenantConfiguration) {
                    Write-Warning "The already-authenticated user session is missing '$TenantGovernanceRelationshipScope'. Tenant Governance delegated-administration relationships may not be discovered or analyzed. Reconnect with this delegated scope consented."
                } else {
                    Write-Warning "The already-authenticated user session is missing '$TenantGovernanceRelationshipScope'. No ManagingTenantId or ManagingTenantName is configured, so this may be acceptable only if you have verified that no Tenant Governance delegated-administration relationships exist. Without this scope, unknown relationships cannot be discovered or analyzed."
                }
            }
        }
        #endregion

        #region Import Environment variables if exists
        $IncludeObjectDetails = $false
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
            if ($EntraOpsConfig.AutomatedElmCatalogProtection) { $EntraOpsConfig.AutomatedElmCatalogProtection.Remove("ApplyPrivilegedElmCatalogProtection") }
            if ($EntraOpsConfig.ConsoleOutput -and $null -ne $EntraOpsConfig.ConsoleOutput.IncludeObjectDetails) {
                $IncludeObjectDetails = [bool]$EntraOpsConfig.ConsoleOutput.IncludeObjectDetails
            }

            New-Variable -Name EntraOpsConfig -Value $EntraOpsConfig -Scope Global -Force
            Write-Verbose -Message "Config file $($ConfigFilePath) imported"
        }
        #endregion

        #region Set global variables
        New-Variable -Name TenantIdContext -Value $TenantId -Scope Global -Force
        New-Variable -Name TenantNameContext -Value $TenantName -Scope Global -Force
        New-Variable -Name ManagingTenantIdContext -Value $ManagingTenantId -Scope Global -Force
        New-Variable -Name ManagingTenantNameContext -Value $ManagingTenantName -Scope Global -Force
        New-Variable -Name EntraOpsIncludeObjectDetails -Value $IncludeObjectDetails -Scope Global -Force
        New-Variable -Name XdrAvdHuntingAccess -Value (-not $SkipGraphSdkAuth -and (Get-MgContext).Scopes -contains "ThreatHunting.Read.All") -Scope Global -Force
        $__EntraOpsSession['AuthenticationType'] = $AuthenticationType
        # $DefaultFolderClassification is always the Classification/ root; consumers append
        # $TenantNameContext or Templates/ themselves (Resolve-EntraOpsClassificationPath,
        # Import-EntraOpsClassificationOverwrites, Update-EntraOpsClassificationControlPlaneScope, ...).
        New-Variable -Name DefaultFolderClassification -Value "$EntraOpsBaseFolder/Classification/" -Scope Global -Force
        if ($MultiTenantRepo -eq $true) {
            New-Variable -Name DefaultFolderClassifiedEam -Value "$EntraOpsBaseFolder/PrivilegedEAM/$($TenantName)/" -Scope Global -Force
            Write-Verbose -Message "Multi Tenant in Repository"
        } else {
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

            # Display managing tenant info if configured
            if (-not [string]::IsNullOrEmpty($ManagingTenantId)) {
                Write-Host "  Managing Tenant ID  : $ManagingTenantId" -ForegroundColor White
                Write-Host "  Managing Tenant Name: $ManagingTenantName" -ForegroundColor White
            }

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
            $MgContext = if (-not $SkipGraphSdkAuth) { Get-MgContext } else { $null }
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
            } elseif ($SkipGraphSdkAuth) {
                Write-Host "  Graph Account       : Not connected (UseInvokeRestMethodOnly - tokens acquired via Get-AzAccessToken as needed)" -ForegroundColor Gray
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