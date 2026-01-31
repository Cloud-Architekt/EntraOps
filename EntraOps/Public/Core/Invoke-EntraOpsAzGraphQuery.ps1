<#
.SYNOPSIS
    Executing KQL Query on Azure Resource Graph API

.DESCRIPTION
    Request to Azure Resource Graph API to execute KQL Query with pagination support to fetch all resources.

.PARAMETER KqlQuery
    KQL Query to be executed on Azure Resource Graph API

.PARAMETER BatchSize
    Number of records to be fetched in a single request. Default is 1000.

.PARAMETER SkipResult^
    Number of records to be skipped in the result. Default is 0.

.EXAMPLE
    Execute Azure Resource Graph query to fetch all resources with AdminTierLevel Tag
    Invoke-EntraOpsAzGraphQuery -KqlQuery 'resources | where isnotempty(tags.$AdminTierTagName) | project name, id, type, resourceGroup, tags, subscriptionId, location, tenantId, identity'
#>

function Invoke-EntraOpsAzGraphQuery {

  param (
    [parameter(Mandatory = $true)]
    [string]$KqlQuery
    ,
    [parameter(Mandatory = $false)]
    [string]$BatchSize = "1000"
  )

  $SkipResult = "0"

  while ($true) {
    if ($SkipResult -gt 0) {
      $GraphResult = Search-AzGraph -Query $kqlQuery -First $BatchSize -SkipToken $GraphResult.SkipToken -UseTenantScope
    }
    else {
      $GraphResult = Search-AzGraph -Query $kqlQuery -First $BatchSize -UseTenantScope
    }

    $Result += $GraphResult.data

    if ($GraphResult.data.Count -lt $BatchSize) {
      break;
    }
    $SkipResult += $SkipResult + $BatchSize
  }
  return $Result
}