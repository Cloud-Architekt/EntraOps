<#
.SYNOPSIS
    Wrapper function to save data of EntraOps Privileged EAM insights to custom table in Log Analytics or Sentinel Workspace.

.DESCRIPTION
    Wrapper function to save data of EntraOps Privileged EAM insights to custom table in Log Analytics or Sentinel Workspace.

.PARAMETER ImportPath
    Folder where the classification files should be stored. Default is ./PrivilegedEAM.

.PARAMETER DataCollectionRuleName
    Name of the data collection rule in Log Analytics or Sentinel Workspace.

.PARAMETER DataCollectionResourceGroupName
    Resource group name of the Log Analytics or Sentinel Workspace.

.PARAMETER DataCollectionRuleSubscriptionId
    Subscription ID of the Log Analytics or Sentinel Workspace. Default is the current subscription.

.PARAMETER TenantId
    Tenant ID of the Microsoft Entra ID tenant. Default is the current tenant ID.

.PARAMETER TableName
    Name of the custom table in Log Analytics or Sentinel Workspace. Default is PrivilegedEAM_CL.

.PARAMETER PrincipalTypeFilter
    Filter for principal type. Default is User, Group, ServicePrincipal. Possible values are User, Group, ServicePrincipal.

.PARAMETER RbacSystems
    Array of RBAC systems to be processed. Default is Azure, AzureBilling, EntraID, IdentityGovernance, DeviceManagement, ResourceApps.

.EXAMPLE
    Save data of EntraOps Privileged EAM insights to custom table in Log Analytics or Sentinel Workspace defined in parameter.
    Save-EntraOpsPrivilegedEAMInsightsCustomTable -DataCollectionRuleName "EntraOpsDataCollectionRule" -DataCollectionResourceGroupName "EntraOpsResourceGroup" -DataCollectionRuleSubscriptionId "3f72a077-c32a-423c-8503-41b93d3b0737"

.EXAMPLE
    Save data of EntraOps Privileged EAM insights to custom table in Log Analytics or Sentinel Workspace defined in config file and available in global variable.
    $LogAnalyticsParam = $EntraOpsConfig.LogAnalytics
    Save-EntraOpsPrivilegedEAMInsightsCustomTable @LogAnalyticsParam
#>

function Save-EntraOpsPrivilegedEAMInsightsCustomTable {

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $False)]
        [System.String]$ImportPath = $DefaultFolderClassifiedEam
        ,
        [Parameter(Mandatory = $True)]
        [System.String]$DataCollectionRuleName
        ,
        [Parameter(Mandatory = $True)]
        [System.String]$DataCollectionResourceGroupName
        ,
        [Parameter(Mandatory = $false)]
        [System.String]$DataCollectionRuleSubscriptionId = (Get-AzContext).Subscription.Id
        ,
        [Parameter(Mandatory = $false)]
        [System.String]$TenantId = (Get-AzContext).Tenant.Id
        ,
        [Parameter(Mandatory = $False)]
        [System.String]$TableName = "PrivilegedEAM_CL"
        ,
        [Parameter(Mandatory = $false)]
        [object]$PrincipalTypeFilter = ("User", "Group", "ServicePrincipal").toLower()
        ,
        [Parameter(Mandatory = $false)]
        [ValidateSet("Azure", "AzureBilling", "EntraID", "IdentityGovernance", "DeviceManagement", "ResourceApps", "Defender")]
        [object]$RbacSystems = ("Azure", "AzureBilling", "EntraID", "IdentityGovernance", "DeviceManagement", "ResourceApps", "Defender")
    )

    Set-AzContext -SubscriptionId $DataCollectionRuleSubscriptionId

    foreach ($RbacSystem in $RbacSystems) {
        Write-Host "Upload data for $($RbacSystem)"
        foreach ($ObjectType in $PrincipalTypeFilter) {

            try {
                $EamFiles = (Get-ChildItem -Path "$($ImportPath)\$($RbacSystem)\$($ObjectType)" -Filter "*.json").FullName
            } catch {
                Write-Warning "No $($RbacSystem).json found!"
            }

            if ($EamFiles.Count -gt 0) {
                Write-Host "Upload classification data for object type: $($ObjectType)"
            
                # Loop through files in batches of 50 to avoid errors hitting the 1Mb file limit for DCRs
                for ($i = 0; $i -lt $EamFiles.Count; $i += 50) {
                    # Select the current batch of 50 files
                    $Batch = $EamFiles[$i..([math]::Min($i + 49, $EamFiles.Count - 1))]
                
                    # Process the batch
                    $EamSummary = @()
                    $EamSummary += $Batch | ForEach-Object {
                        # Check that each item is indeed a file before processing
                        if (Test-Path $_ -PathType Leaf) {
                            Get-Content $_ | ConvertFrom-Json -Depth 10
                        } else {
                            Write-Warning "Skipped non-file item: $_"
                        }
                    }

                    if ($EamSummary.Count -ne 0) {
                        $Json = $EamSummary | ConvertTo-Json -Depth 10
                
                        # Send the batch to the API
                        Push-EntraOpsLogsIngestionAPI -TableName $TableName -JsonContent $json -DataCollectionRuleName $DataCollectionRuleName -DataCollectionResourceGroupName $DataCollectionResourceGroupName -DataCollectionRuleSubscriptionId $DataCollectionRuleSubscriptionId                
                    }
                    
                    Write-Host "Processed batch of $($EamSummary.Count) files starting at index $i."
                }
            }
        }
    }
}