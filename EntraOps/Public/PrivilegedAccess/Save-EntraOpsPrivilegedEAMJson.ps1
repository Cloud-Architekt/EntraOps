<#
.SYNOPSIS
    Export and save EntraOps Privileged EAM data to JSON files.

.DESCRIPTION
    Get information from EntraOps about classification based on Enterprise Access Model and save them as JSON to folder.

.PARAMETER ExportFolder
    Folder where the JSON files should be stored. Default is ./PrivilegedEAM.

.PARAMETER RbacSystems
    Array of RBAC systems to be processed. Default is Azure, AzureBilling, EntraID, IdentityGovernance, DeviceManagement, ResourceApps.

.EXAMPLE
    Export and save JSON files of EntraOps to default folder
    Save-EntraOpsPrivilegedEAMJson
#>

function Save-EntraOpsPrivilegedEAMJson {

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [System.String]$ExportFolder = $DefaultFolderClassifiedEam
        ,
        [Parameter(Mandatory = $False)]
        [ValidateSet("EntraID", "IdentityGovernance", "DeviceManagement", "ResourceApps", "Defender")]
        [Array]$RbacSystems = ("EntraID", "IdentityGovernance", "DeviceManagement", "ResourceApps", "Defender")
    )

    #region Initialize and Clear Cache
    Write-Output "Clearing cache before analyzing RBAC and classification data"
    Clear-EntraOpsCache
    #endregion

    #region Parallel Processing: Entra ID and Resource Apps
    # These two RBAC systems can be processed in parallel as they are independent
    Write-Host "Starting parallel processing of EntraID and ResourceApps..."
    
    $ParallelJobs = @()
    
    # Determine which jobs to run
    if ($RbacSystems -contains "EntraID") {
        $ParallelJobs += "EntraID"
    }
    
    if ($RbacSystems -contains "ResourceApps") {
        $ParallelJobs += "ResourceApps"
    }
    
    # Execute parallel jobs if any exist
    if ($ParallelJobs.Count -gt 0) {
        Write-Verbose "Preparing to launch $($ParallelJobs.Count) parallel jobs: $($ParallelJobs -join ', ')"
        
        # Capture authentication context from parent session
        $AzContext = Get-AzContext
        
        # Get Microsoft Graph connection parameters (set by Connect-EntraOps)
        # This preserves the original authentication scope from Connect-EntraOps
        if ($null -eq $MgGraphConnectionInfo) {
            throw "Microsoft Graph connection info not found. Please ensure Connect-EntraOps has been called with proper authentication."
        }
        
        # Create a local copy to work with
        $MgConnectionInfo = $MgGraphConnectionInfo
        
        # Convert SecureString token to plaintext only when needed for job serialization
        # This is unavoidable as Start-Job ArgumentList requires serializable types
        if ($MgConnectionInfo.SecureAccessToken) {
            $MgConnectionInfo.AccessToken = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto(
                [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($MgConnectionInfo.SecureAccessToken)
            )
            # Remove SecureString from hashtable to avoid serialization issues
            $MgConnectionInfo.Remove('SecureAccessToken')
        }
        
        # Get Azure ARM token as plain string (required by Connect-AzAccount)
        $AzArmTokenObj = Get-AzAccessToken -ResourceUrl "https://management.azure.com/"
        
        # Ensure we have a plain string token
        if ($AzArmTokenObj.Token -is [SecureString]) {
            $AzArmAccessToken = $AzArmTokenObj.Token | ConvertFrom-SecureString -AsPlainText
        } elseif ($AzArmTokenObj.Token -is [string]) {
            $AzArmAccessToken = $AzArmTokenObj.Token
        } else {
            $AzArmAccessToken = $AzArmTokenObj.Token.ToString()
        }
        
        # Validate token format (should be a JWT starting with "eyJ")
        if (-not $AzArmAccessToken.StartsWith("eyJ")) {
            throw "Azure ARM access token does not appear to be in valid JWT format"
        }
        
        $AccountId = $AzContext.Account.Id
        $TenantId = $AzContext.Tenant.Id
        
        Write-Verbose "Authentication context captured for Account: $AccountId, Tenant: $TenantId"
        Write-Verbose "ARM Token length: $($AzArmAccessToken.Length)"
        Write-Verbose "Microsoft Graph Auth Type: $($MgConnectionInfo.AuthType)"
        
        # Resolve module path
        $ModulePath = "$EntraOpsBaseFolder/EntraOps/EntraOps.psm1"
        Write-Verbose "Module path: $ModulePath"
        
        # Capture global variables needed by jobs
        $GlobalVars = @{
            DefaultFolderClassification = $DefaultFolderClassification
            DefaultFolderClassifiedEam  = $DefaultFolderClassifiedEam
            TenantIdContext             = $TenantIdContext
            TenantNameContext           = $TenantNameContext
            EntraOpsBaseFolder          = $EntraOpsBaseFolder
            ModulePath                  = $ModulePath
        }
        
        Write-Verbose "Global variables captured: $($GlobalVars.Keys -join ', ')"
        
        # Create a clean copy of connection info for jobs (without SecureString)
        $MgConnectionInfoForJobs = $MgConnectionInfo.Clone()
        
        # Use Start-Job for true process isolation (avoids assembly loading conflicts)
        Write-Verbose "Creating background jobs with Start-Job..."
        $Jobs = $ParallelJobs | ForEach-Object {
            $JobName = $_
            Write-Verbose "Launching job: $JobName"
            
            Start-Job -Name $JobName -ScriptBlock {
                param($JobName, $ExportFolder, $GlobalVars, $AccountId, $TenantId, $MgConnectionInfo, $AzArmAccessToken)
                
                try {
                    Write-Output "[$JobName] Starting processing..."
                    
                    # Set global variables
                    $GlobalVars.GetEnumerator() | ForEach-Object {
                        New-Variable -Name $_.Key -Value $_.Value -Scope Global -Force
                    }
                    
                    Write-Verbose "[$JobName] Global variables set"
                    Write-Output "[$JobName] ARM Token received (length: $($AzArmAccessToken.Length))"
                    
                    # Import EntraOps module (skip installation check in child jobs)
                    Write-Verbose "[$JobName] Importing EntraOps module..."
                    $env:ENTRAOPS_SKIP_MODULE_INSTALL = "true"
                    Import-Module $GlobalVars.ModulePath -Force -WarningAction SilentlyContinue -ErrorAction Stop
                    Write-Output "[$JobName] Module imported successfully"
                    
                    # Authenticate to Azure using token from parent session
                    Write-Verbose "[$JobName] Authenticating to Azure with token..."
                    Write-Verbose "[$JobName] Token starts with: $($AzArmAccessToken.Substring(0, [Math]::Min(10, $AzArmAccessToken.Length)))"
                    
                    $ConnectParams = @{
                        AccessToken = $AzArmAccessToken
                        AccountId   = $AccountId
                        Tenant      = $TenantId
                        ErrorAction = 'Stop'
                    }
                    Connect-AzAccount @ConnectParams | Out-Null
                    
                    # Authenticate to Microsoft Graph using connection parameters from parent session
                    Write-Verbose "[$JobName] Authenticating to Microsoft Graph..."
                    Write-Verbose "[$JobName] Auth Type: $($MgConnectionInfo.AuthType)"
                    
                    switch ($MgConnectionInfo.AuthType) {
                        'Identity' {
                            Connect-MgGraph -Identity -NoWelcome -ErrorAction Stop | Out-Null
                        }
                        'UserAssignedIdentity' {
                            Connect-MgGraph -Identity -ClientId $MgConnectionInfo.ClientId -NoWelcome -ErrorAction Stop | Out-Null
                        }
                        { $_ -in @('FederatedToken', 'ExplicitToken', 'FromAzContext') } {
                            $SecureToken = ConvertTo-SecureString -String $MgConnectionInfo.AccessToken -AsPlainText -Force
                            Connect-MgGraph -AccessToken $SecureToken -NoWelcome -ErrorAction Stop | Out-Null
                        }
                        default {
                            # For interactive/device auth modes with scopes
                            if ($MgConnectionInfo.Scopes) {
                                Connect-MgGraph -Scopes $MgConnectionInfo.Scopes -TenantId $MgConnectionInfo.TenantId -NoWelcome -ErrorAction Stop | Out-Null
                            } else {
                                throw "Unsupported authentication type: $($MgConnectionInfo.AuthType)"
                            }
                        }
                    }
                    
                    Write-Output "[$JobName] Authentication completed successfully"
                    
                    # Process based on RBAC system type
                    switch ($JobName) {
                        'EntraID' {
                            $SystemExportFolder = "$ExportFolder/EntraID"
                            
                            # Prepare export folder
                            if (Test-Path $SystemExportFolder) {
                                Remove-Item $SystemExportFolder -Force -Recurse
                            }
                            New-Item $SystemExportFolder -ItemType Directory -Force | Out-Null
                            
                            Write-Output "[$JobName] Retrieving privileged EAM data..."
                            $EamData = Get-EntraOpsPrivilegedEamEntraId
                            
                            Write-Output "[$JobName] Exporting $($EamData.Count) objects..."
                            $EamData | ConvertTo-Json -Depth 10 | Out-File -Path "$SystemExportFolder/EntraID.json" -Force
                            
                            # Create subdirectories and write individual files
                            $EamData | Group-Object ObjectType | ForEach-Object {
                                $Dir = "$SystemExportFolder/$($_.Name)"
                                if (!(Test-Path $Dir)) { 
                                    New-Item -ItemType Directory -Force -Path $Dir | Out-Null 
                                }
                            }
                            
                            foreach ($Obj in $EamData) {
                                $Path = "$SystemExportFolder/$($Obj.ObjectType)/$($Obj.ObjectId).json"
                                $Obj | ConvertTo-Json -Depth 10 | Out-File -Path $Path -Force
                            }
                            
                            Write-Output "[$JobName] Successfully exported $($EamData.Count) objects"
                        }
                        
                        'ResourceApps' {
                            $SystemExportFolder = "$ExportFolder/ResourceApps"
                            
                            # Prepare export folder
                            if (Test-Path $SystemExportFolder) {
                                Remove-Item $SystemExportFolder -Force -Recurse
                            }
                            New-Item $SystemExportFolder -ItemType Directory -Force | Out-Null
                            
                            Write-Output "[$JobName] Retrieving privileged EAM data..."
                            $EamData = Get-EntraOpsPrivilegedEamResourceApps
                            
                            Write-Output "[$JobName] Exporting $($EamData.Count) objects..."
                            $EamData | ConvertTo-Json -Depth 10 | Out-File -Path "$SystemExportFolder/ResourceApps.json" -Force
                            
                            # Create subdirectories and write individual files
                            $EamData | Group-Object ObjectType | ForEach-Object {
                                $Dir = "$SystemExportFolder/$($_.Name)"
                                if (!(Test-Path $Dir)) { 
                                    New-Item -ItemType Directory -Force -Path $Dir | Out-Null 
                                }
                            }
                            
                            foreach ($Obj in $EamData) {
                                $Path = "$SystemExportFolder/$($Obj.ObjectType)/$($Obj.ObjectId).json"
                                $Obj | ConvertTo-Json -Depth 10 | Out-File -Path $Path -Force
                            }
                            
                            Write-Output "[$JobName] Successfully exported $($EamData.Count) objects"
                        }
                    }
                } catch {
                    Write-Error "[$JobName] Error: $_"
                    throw
                }
            } -ArgumentList $JobName, $DefaultFolderClassifiedEam, $GlobalVars, $AccountId, $TenantId, $MgConnectionInfoForJobs, $AzArmAccessToken
        }
        
        # Clear sensitive data from parent session after jobs are launched
        if ($MgConnectionInfo.AccessToken) {
            $MgConnectionInfo.AccessToken = $null
        }
        if ($MgConnectionInfoForJobs.AccessToken) {
            $MgConnectionInfoForJobs.AccessToken = $null
        }
        
        Write-Verbose "All jobs launched. Job IDs: $($Jobs.Id -join ', ')"
        Write-Host "Jobs executing. Monitoring progress..."
        
        # Monitor job progress with real-time output streaming
        $CompletedJobs = @()
        while ($CompletedJobs.Count -lt $Jobs.Count) {
            foreach ($Job in $Jobs) {
                if ($Job.Id -notin $CompletedJobs) {
                    $JobState = (Get-Job -Id $Job.Id).State
                    
                    # Stream any available output
                    $Output = Receive-Job -Id $Job.Id
                    if ($Output) {
                        $Output | ForEach-Object { Write-Host "[$($Job.Name)] $_" }
                    }
                    
                    # Mark as completed if finished
                    if ($JobState -in @('Completed', 'Failed', 'Stopped')) {
                        Write-Verbose "Job $($Job.Name) state: $JobState"
                        $CompletedJobs += $Job.Id
                    }
                }
            }
            
            if ($CompletedJobs.Count -lt $Jobs.Count) {
                Start-Sleep -Milliseconds 500
            }
        }
        
        Write-Verbose "All jobs completed. Collecting final results..."
        
        # Collect final results and clean up
        $Jobs | ForEach-Object {
            Write-Host "`n--- Final output from $($_.Name) ---"
            $FinalOutput = Receive-Job -Job $_
            if ($FinalOutput) {
                $FinalOutput | ForEach-Object { Write-Host $_ }
            }
            
            # Check job state
            if ($_.State -eq 'Failed') {
                Write-Warning "Job $($_.Name) failed"
            }
            
            Remove-Job -Job $_
        }
        
        Write-Host "`nParallel processing completed.`n"
    }
    #endregion

    #region Sequential Processing: Device Management
    # Must be processed sequentially after parallel jobs
    if ($RbacSystems -contains "DeviceManagement") {
        Write-Host "Processing DeviceManagement RBAC system..."
        $DevMgmtExportFolder = "$($DefaultFolderClassifiedEam)/DeviceManagement"
        $EamDeviceMgmt = Get-EntraOpsPrivilegedEAMIntune

        if ((Test-Path -path "$($DevMgmtExportFolder)")) {
            Remove-Item "$($DevMgmtExportFolder)" -Force -Recurse
            New-Item "$($DevMgmtExportFolder)" -ItemType Directory -Force | Out-Null
        } else {
            New-Item "$($DevMgmtExportFolder)" -ItemType Directory -Force | Out-Null
        }
        $EamDeviceMgmt | Convertto-Json -Depth 10 | Out-File -Path "$($DevMgmtExportFolder)/DeviceManagement.json" -Force
        
        # Create directories first
        $EamDeviceMgmt | Group-Object ObjectType | ForEach-Object {
            $Dir = "$($DevMgmtExportFolder)/$($_.Name)"
            if (!(Test-Path $Dir)) { New-Item -ItemType Directory -Force -Path $Dir | Out-Null }
        }

        # Parallel File Write
        $EamDeviceMgmt | ForEach-Object -Parallel {
            $Obj = $_
            $Path = "$using:DevMgmtExportFolder/$($Obj.ObjectType)/$($Obj.ObjectId).json"
            $Obj | Convertto-Json -Depth 10 | Out-File -Path $Path -Force
        } -ThrottleLimit 50
        
        Write-Host "Completed DeviceManagement processing: $($EamDeviceMgmt.Count) objects exported"
    }
    #endregion

    #region Sequential Processing: Identity Governance
    # Must be processed sequentially in defined order
    if ($RbacSystems -contains "IdentityGovernance") {
        Write-Host "Processing IdentityGovernance RBAC system..."
        $IdGovExportFolder = "$($DefaultFolderClassifiedEam)/IdentityGovernance"

        $EamIdGov = Get-EntraOpsPrivilegedEAMIdGov
        $EamIdGov | Measure-Object

        if ((Test-Path -path "$($IdGovExportFolder)")) {
            Remove-Item "$($IdGovExportFolder)" -Force -Recurse
            New-Item "$($IdGovExportFolder)" -ItemType Directory -Force | Out-Null
        } else {
            New-Item "$($IdGovExportFolder)" -ItemType Directory -Force | Out-Null
        }
        $EamIdGov | Convertto-Json -Depth 10 | Out-File -Path "$($IdGovExportFolder)/IdentityGovernance.json" -Force
        
        # Create directories first
        $EamIdGov | Group-Object ObjectType | ForEach-Object {
            $Dir = "$($IdGovExportFolder)/$($_.Name)"
            if (!(Test-Path $Dir)) { New-Item -ItemType Directory -Force -Path $Dir | Out-Null }
        }

        # Parallel File Write
        $EamIdGov | ForEach-Object -Parallel {
            $Obj = $_
            $Path = "$using:IdGovExportFolder/$($Obj.ObjectType)/$($Obj.ObjectId).json"
            $Obj | Convertto-Json -Depth 10 | Out-File -Path $Path -Force
        } -ThrottleLimit 50
        
        Write-Host "Completed IdentityGovernance processing: $($EamIdGov.Count) objects exported"
    }
    #endregion

    #region Sequential Processing: Defender
    # Must be processed sequentially in defined order
    if ($RbacSystems -contains "Defender") {
        Write-Host "Processing Defender RBAC system..."
        $DefenderExportFolder = "$($DefaultFolderClassifiedEam)/Defender"

        $EamDefender = Get-EntraOpsPrivilegedEAMDefender
        $EamDefender | Measure-Object

        if ((Test-Path -path "$($DefenderExportFolder)")) {
            Remove-Item "$($DefenderExportFolder)" -Force -Recurse
            New-Item "$($DefenderExportFolder)" -ItemType Directory -Force | Out-Null
        } else {
            New-Item "$($DefenderExportFolder)" -ItemType Directory -Force | Out-Null
        }
        $EamDefender | Convertto-Json -Depth 10 | Out-File -Path "$($DefenderExportFolder)/Defender.json" -Force
        
        # Create directories first
        $EamDefender | Group-Object ObjectType | ForEach-Object {
            $Dir = "$($DefenderExportFolder)/$($_.Name)"
            if (!(Test-Path $Dir)) { New-Item -ItemType Directory -Force -Path $Dir | Out-Null }
        }

        # Parallel File Write
        $EamDefender | ForEach-Object -Parallel {
            $Obj = $_
            $Path = "$using:DefenderExportFolder/$($Obj.ObjectType)/$($Obj.ObjectId).json"
            $Obj | Convertto-Json -Depth 10 | Out-File -Path $Path -Force
        } -ThrottleLimit 50
        
        Write-Host "Completed Defender processing: $($EamDefender.Count) objects exported"
    }
    #endregion
    
    Write-Host "`nAll RBAC systems processing completed successfully!"
}