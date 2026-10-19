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

.PARAMETER TimeGenerated
    Timestamp written as TimeGenerated to every record. Pass the same value for all calls of one ingestion
    run, so the records of a run can be told apart from earlier runs. Default is the current time per call.

.EXAMPLE
    Ingest JSON data to Log Analytics Custom Log Table 'PrivilegedEAM_CL' in Log Analytics Workspace
    Push-EntraOpsLogsIngestionAPI -JsonContent <VariableWithPlainJson> -DataCollectionRuleName "entraops-dcr" -DataCollectionResourceGroupName "entraops-rg" -DataCollectionRuleSubscriptionId "00000000-0000-0000-0000-000000000000"

.EXAMPLE
    Get schema to update data collection transformation rule
    Push-EntraOpsLogsIngestionAPI -JsonContent <VariableWithPlainJson> -SampleDataOnly $true -DataCollectionRuleName "entraops-dcr" -DataCollectionResourceGroupName "entraops-rg" -DataCollectionRuleSubscriptionId "00000000-0000-0000-0000-000000000000"
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
        ,
        [Parameter(Mandatory = $false)]
        [Nullable[DateTime]]$TimeGenerated
    )

    $ErrorActionPreference = "Stop"

    Write-Verbose "Ingesting to Log Analytics Custom Log Table '$($TableName)'"
    Write-Verbose " DataCollectionRuleSubscriptionId '$($DataCollectionRuleSubscriptionId)'"
    Write-Verbose " DataCollectionRuleResourceGroup '$($DataCollectionResourceGroupName)'"
    Write-Verbose " DataCollectionRuleName: '$($DataCollectionRuleName)'"
    Write-Verbose " LogAnalyticsCustomLogTableName: '$($TableName)'"

    # Add Timestamp to JSON data
    try {
        $Records = @($JsonContent | ConvertFrom-Json -Depth 10)
        $RecordTimeGenerated = if ($null -ne $TimeGenerated) { $TimeGenerated.ToUniversalTime().ToString("o") } else { (Get-Date).ToUniversalTime().ToString("o") }
        $Records | ForEach-Object {
            $_ | Add-Member -NotePropertyName TimeGenerated -NotePropertyValue $RecordTimeGenerated -Force
        }
        $json = $Records | ConvertTo-Json -Depth 10 -AsArray
    } catch {
        Write-Error "Cannot convert JSON content to JSON object"
        throw $_
    }

    if ($SampleDataOnly -eq $false) {
        $OriginalAzContext = Get-AzContext
        try {
            Set-AzContext -SubscriptionId $DataCollectionRuleSubscriptionId | Out-Null

            # Authentication
            $AccessToken = (Get-AzAccessToken -ResourceUrl "https://monitor.azure.com/" -AsSecureString).Token
            $PlainAccessToken = ConvertFrom-SecureString -SecureString $AccessToken -AsPlainText
            $headers = @{"Authorization" = "Bearer $PlainAccessToken"; "Content-Type" = "application/json" }

            $DcrArmUri = "https://management.azure.com/subscriptions/$($DataCollectionRuleSubscriptionId)/resourceGroups/$($DataCollectionResourceGroupName)/providers/Microsoft.Insights/dataCollectionRules/$($DataCollectionRuleName)?api-version=$($ApiVersion)"
            $Dcr = ((Invoke-AzRestMethod -Method "Get" -Uri $DcrArmUri).Content | ConvertFrom-Json)
            if ($Dcr.properties.dataflows.outputStream -notcontains "Custom-$($TableName)") {
                Write-Error "Custom table $($TableName) does not match with data flow in data collection rule $($DataCollectionRuleName)!"
            }

            $DceEndpointId = $Dcr.properties.dataCollectionEndpointId
            $DceArmUri = "https://management.azure.com$($DceEndpointId)?api-version=$($ApiVersion)"
            $Dce = ((Invoke-AzRestMethod -Method "Get" -Uri $DceArmUri).Content | ConvertFrom-Json)
            $DceIngestEndpointUrl = $Dce.properties.logsIngestion.endpoint

            if ($null -eq $DceIngestEndpointUrl) {
                Write-Error "No Data Collection endpoint found!"
            }

            $PostUri = "$DceIngestEndpointUrl/dataCollectionRules/$($Dcr.properties.immutableId)/streams/Custom-$($TableName)?api-version=2023-01-01"

            # Logs Ingestion API allows a maximum of 1 MB (1048576 bytes) per request.
            # Split records into chunks below the limit (with buffer for JSON array overhead).
            $MaxRequestBytes = 1000000
            $ChunkIndex = 0

            # Measure the serialized UTF-8 body and split batches that exceed the request limit.
            function Send-EntraOpsLogsIngestionChunk {
                param(
                    [Parameter(Mandatory = $true)]
                    [System.Collections.Generic.List[object]]$RecordsSubset
                )

                $Body = $RecordsSubset | ConvertTo-Json -Depth 10 -AsArray -Compress
                $BodySize = [System.Text.Encoding]::UTF8.GetByteCount($Body)

                if ($BodySize -gt $MaxRequestBytes -and $RecordsSubset.Count -gt 1) {
                    $SplitIndex = [Math]::Ceiling($RecordsSubset.Count / 2)
                    $FirstHalf = [System.Collections.Generic.List[object]]::new($RecordsSubset.GetRange(0, $SplitIndex))
                    $SecondHalf = [System.Collections.Generic.List[object]]::new($RecordsSubset.GetRange($SplitIndex, $RecordsSubset.Count - $SplitIndex))
                    Send-EntraOpsLogsIngestionChunk -RecordsSubset $FirstHalf
                    Send-EntraOpsLogsIngestionChunk -RecordsSubset $SecondHalf
                    return
                }

                if ($BodySize -gt $MaxRequestBytes) {
                    throw "Single record exceeds the 1 MB Logs Ingestion API request limit ($BodySize bytes). The record cannot be split safely."
                }

                $script:ChunkIndex++
                Write-Verbose "Sending chunk $($script:ChunkIndex) with $($RecordsSubset.Count) record(s) and body size $BodySize bytes to Logs Ingestion API"
                Invoke-RestMethod -Uri $PostUri -Method "Post" -Body $Body -Headers $headers -Verbose
            }

            # Estimate batch sizes first to avoid serializing the entire dataset at once.
            $Batches = [System.Collections.Generic.List[object]]::new()
            $CurrentBatch = [System.Collections.Generic.List[object]]::new()
            $CurrentSize = 0

            foreach ($Record in $Records) {
                $RecordSize = [System.Text.Encoding]::UTF8.GetByteCount(($Record | ConvertTo-Json -Depth 10 -Compress)) + 1
                if ($CurrentBatch.Count -gt 0 -and ($CurrentSize + $RecordSize) -gt $MaxRequestBytes) {
                    $Batches.Add($CurrentBatch)
                    $CurrentBatch = [System.Collections.Generic.List[object]]::new()
                    $CurrentSize = 0
                }
                $CurrentBatch.Add($Record)
                $CurrentSize += $RecordSize
            }
            if ($CurrentBatch.Count -gt 0) { $Batches.Add($CurrentBatch) }

            foreach ($Batch in $Batches) {
                Send-EntraOpsLogsIngestionChunk -RecordsSubset $Batch
            }
        } finally {
            if ($null -ne $OriginalAzContext) {
                Set-AzContext -Context $OriginalAzContext | Out-Null
            }
        }
    } else {
        return $json
    }
}