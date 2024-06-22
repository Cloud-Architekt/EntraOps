<#
.SYNOPSIS
    Ingest EntraOps data to Log Analytics workspace using Ingest API.

.DESCRIPTION
    Ingesting data to Log Analytics workspace using Data Collection Rule and Data Collection Endpoint via Ingest API.

.PARAMETER JsonContent
    JSON content as plaintext to be ingested to Log Analytics workspace.

.PARAMETER DataCollectionRuleName
    Name of the Data Collection Rule in Azure Resource Manager.

.PARAMETER DataCollectionResourceGroupName
    Resource Group Name of the Data Collection Rule in Azure Resource Manager. Default is 'aadops-rg'.

.PARAMETER DataCollectionRuleSubscriptionId
    Subscription Id of the Data Collection Rule in Azure Resource Manager.

.PARAMETER TableName
    Custom Log Table name in Log Analytics workspace. Default is 'PrivilegedEAM_CL'.

.PARAMETER SampleDataOnly
    If set to $true, the function will return the JSON content with added timestamp. Default is $false.

.PARAMETER ApiVersion
    API version to be used for the ARM API request. Default is '2022-06-01'.

.EXAMPLE
    Ingest JSON data to Log Analytics Custom Log Table 'PrivilegedEAM_CL' in Log Analytics Workspace
    Push-EntraOpsLogIngestionAPI -JsonContent <VariableWithPlainJson> -DataCollectionRuleName "entraops-dcr" -DataCollectionResourceGroupName "entraops-rg" -DataCollectionRuleSubscriptionId "00000000-0000-0000-0000-000000000000"

.EXAMPLE
    Get schema to update data collection transformation rule
    Push-EntraOpsLogIngestionAPI -JsonContent <VariableWithPlainJson> -SampleDataOnly $true -DataCollectionRuleName "entraops-dcr" -DataCollectionResourceGroupName "entraops-rg" -DataCollectionRuleSubscriptionId "00000000-0000-0000-0000-000000000000"
 #>

function Push-EntraOpsLogsIngestionAPI {

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $True)]
        [object]$JsonContent
        ,
        [Parameter(Mandatory = $true)]
        [string]$DataCollectionRuleName
        ,
        [Parameter(Mandatory = $false)]
        [System.String]$DataCollectionResourceGroupName = "aadops-rg"
        ,
        [Parameter(Mandatory = $true)]
        [System.String]$DataCollectionRuleSubscriptionId
        ,
        [Parameter(Mandatory = $false)]
        [System.String]$TableName = "PrivilegedEAM_CL"
        ,
        [Parameter(Mandatory = $false)]
        [System.Boolean]$SampleDataOnly = $false
        ,
        [Parameter(Mandatory = $false)]
        [System.String]$ApiVersion = "2022-06-01"
    )

    $ErrorActionPreference = "Stop"

    Set-AzContext -SubscriptionId $DataCollectionRuleSubscriptionId | Out-Null

    Write-Verbose "Ingesting to Log Analytics Custom Log Table '$($TableName)'"
    Write-Verbose " DataCollectionRuleSubscriptionId '$($DataCollectionRuleSubscriptionId)'"
    Write-Verbose " DataCollectionRuleResourceGroup '$($DataCollectionRuleResourceGroup)'"
    Write-Verbose " DataCollectionRuleName: '$($DataCollectionRuleName)'"
    Write-Verbose " LogAnalyticsCustomLogTableName: '$($TableName)'"
    Write-Verbose " ThrottleLimitMonitor: '$($ThrottleLimitMonitor)'"

    # Authentication
    $AccessToken = (Get-AzAccessToken -ResourceUrl "https://monitor.azure.com/").Token
    $headers = @{"Authorization" = "Bearer $AccessToken"; "Content-Type" = "application/json" }

    # Add Timestamp to JSON data
    try {
        $json = $JsonContent | ConvertFrom-Json -Depth 10
        $json | ForEach-Object {
            $_ | Add-Member -NotePropertyName TimeGenerated -NotePropertyValue (Get-Date).ToUniversalTime().ToString("o") -Force
        }
        $json = $json | ConvertTo-Json -Depth 10
    }
    catch {
        Write-Error "Cannot convert JSON content to JSON object"
        throw $_
    }

    if ($SampleDataOnly -eq $false) {

        # Get Data Collection Rule details and Uri
        $DcrArmUri = "https://management.azure.com/subscriptions/$($DataCollectionRuleSubscriptionId)/resourceGroups/$($DataCollectionResourceGroupName)/providers/Microsoft.Insights/dataCollectionRules/$($DataCollectionRuleName)?api-version=$($ApiVersion)"
        $Dcr = ((Invoke-AzRestMethod -Method "Get" -Uri $DcrArmUri).Content | ConvertFrom-Json)
        if ($Dcr.properties.dataflows.outputStream -notcontains "Custom-$($TableName)") {
            Write-Error "Custom table $($TableName) does not match with data flow in data collection rule $($DataCollectionRuleName)!"
        }

        # Get Data Collection Endpoint details and Uri
        $DceEndpointId = $Dcr.properties.dataCollectionEndpointId
        $DceArmUri = "https://management.azure.com$($DceEndpointId)?api-version=$($ApiVersion)"
        $Dce = ((Invoke-AzRestMethod -Method "Get" -Uri $DceArmUri).Content | ConvertFrom-Json)
        $DceIngestEndpointUrl = $Dce.properties.logsIngestion.endpoint

        if ($null -eq $DceIngestEndpointUrl) {
            Write-Error "No Data Collection endpoint found!"
        }

        # Get Ingest API Uri
        $PostUri = "$DceIngestEndpointUrl/dataCollectionRules/$($Dcr.properties.immutableId)/streams/Custom-$($TableName)?api-version=2023-01-01"

        # Ingest data to Log Analytics
        Invoke-RestMethod -Uri $PostUri -Method "Post" -Body $json -Headers $headers -Verbose

    }
    else {
        return $json
    }
}