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

            # Reset to prevent stale data from a previous iteration leaking through
            # when Get-ChildItem throws (e.g. directory does not exist).
            # Join-Path is required: the upstream literal "$ImportPath\$RbacSystem\$ObjectType" uses
            # backslashes, which are not path separators on the Linux CI runners this runs on.
            $EamFiles = @()
            $ObjectTypePath = Join-Path -Path $ImportPath -ChildPath "$RbacSystem/$ObjectType"

            if (Test-Path -Path $ObjectTypePath -PathType Container) {
                $EamFiles = @((Get-ChildItem -Path $ObjectTypePath -Filter "*.json" -File).FullName)
            }

            if ($EamFiles.Count -gt 0) {
                Write-Host "Upload classification data for object type: $($ObjectType)"
                $MaxPayloadBytes = 1000000  # Stay under the 1MB (1,048,576) DCR limit with margin
                $BatchSize = 25
                $BatchNumber = 0

                for ($i = 0; $i -lt $EamFiles.Count; $i += $BatchSize) {
                    $EndIndex = [Math]::Min($i + $BatchSize - 1, $EamFiles.Count - 1)
                    $Batch = $EamFiles[$i..$EndIndex]

                    $EamSummary = @()
                    $EamSummary += $Batch | ForEach-Object {
                        Get-Content $_ | ConvertFrom-Json -Depth 10
                    }

                    if ($EamSummary.Count -eq 0) { continue }

                    # -AsArray is required: piping a single-element collection to ConvertTo-Json emits a
                    # bare object, and the Logs Ingestion API rejects the payload with
                    # "Received data is not a valid JSON array." This bites any batch of exactly one
                    # record - a trailing batch, or an object-type folder holding a single file.
                    $Json = $EamSummary | ConvertTo-Json -Depth 10 -AsArray
                    $PayloadBytes = [System.Text.Encoding]::UTF8.GetByteCount($Json)

                    if ($PayloadBytes -gt $MaxPayloadBytes -and $EamSummary.Count -gt 1) {
                        # Split into individual uploads when batch exceeds limit
                        Write-Host "Batch at index $i ($PayloadBytes bytes) exceeds limit, uploading individually"
                        foreach ($Item in $EamSummary) {
                            # Always a single-element array here, so -AsArray is mandatory - without it
                            # every oversized record was silently rejected at ingestion.
                            $SingleJson = @($Item) | ConvertTo-Json -Depth 10 -AsArray
                            Push-EntraOpsLogsIngestionAPI -TableName $TableName -JsonContent $SingleJson -DataCollectionRuleName $DataCollectionRuleName -DataCollectionResourceGroupName $DataCollectionResourceGroupName -DataCollectionRuleSubscriptionId $DataCollectionRuleSubscriptionId
                        }
                    } else {
                        Push-EntraOpsLogsIngestionAPI -TableName $TableName -JsonContent $Json -DataCollectionRuleName $DataCollectionRuleName -DataCollectionResourceGroupName $DataCollectionResourceGroupName -DataCollectionRuleSubscriptionId $DataCollectionRuleSubscriptionId
                    }

                    $BatchNumber++
                    Write-Host "Processed batch ${BatchNumber}: $($EamSummary.Count) files (starting at index $i, $PayloadBytes bytes)"
                }
            }
        }
    }
}