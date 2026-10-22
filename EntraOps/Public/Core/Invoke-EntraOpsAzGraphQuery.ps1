<#
.SYNOPSIS
    Executing KQL Query on Azure Resource Graph API

.DESCRIPTION
    Request to Azure Resource Graph API to execute KQL Query with pagination support to fetch all resources.
    Uses the Azure Resource Graph REST API directly through Invoke-RestMethod and the current Az PowerShell
    context's ARM access token. This avoids an Az.ResourceGraph module dependency while retaining tenant-wide
    query scope, $skipToken pagination, and adaptive throttling retries.

.PARAMETER KqlQuery
    KQL Query to be executed on Azure Resource Graph API

.PARAMETER BatchSize
    Number of records to be fetched in a single request. Default is 1000.

.PARAMETER UseInvokeRestMethodOnly
  Retained for backward compatibility. Azure Resource Graph queries always use Invoke-RestMethod.

.PARAMETER MaxRetries
    Maximum number of retry attempts for throttling (429) or transient errors on the REST path. Default is 5.

.PARAMETER InitialRetryDelay
    Initial delay in seconds before the first retry on the REST path. Default is 2 seconds.

.PARAMETER ThrowOnFailure
    Throw a terminating error instead of writing a non-terminating error and returning the (possibly partial)
    result collected so far. Use this from callers whose output must never be built from an incomplete result
    set - most importantly classification scope discovery, where an empty or partial result silently narrows
    the Control Plane scope instead of failing the run.

.EXAMPLE
    Execute Azure Resource Graph query to fetch all resources with AdminTierLevel Tag
    Invoke-EntraOpsAzGraphQuery -KqlQuery 'resources | where isnotempty(tags.$AdminTierTagName) | project name, id, type, resourceGroup, tags, subscriptionId, location, tenantId, identity'
#>

function Invoke-EntraOpsAzGraphQuery {
  [CmdletBinding()]
  param (
    [parameter(Mandatory = $true)]
    [string]$KqlQuery
    ,
    [parameter(Mandatory = $false)]
    [int]$BatchSize = 1000
    ,
    [parameter(Mandatory = $false)]
    [switch]$UseInvokeRestMethodOnly
    ,
    [parameter(Mandatory = $false)]
    [int]$MaxRetries = 5
    ,
    [parameter(Mandatory = $false)]
    [int]$InitialRetryDelay = 2
    ,
    [parameter(Mandatory = $false)]
    [switch]$ThrowOnFailure
  )

  $Result = [System.Collections.Generic.List[object]]::new()

  #region REST path - direct call to the Azure Resource Graph REST API
  Write-Verbose "Using Invoke-RestMethod against the Azure Resource Graph REST API"

  function Get-EntraOpsArgAccessToken {
    $Now = [DateTime]::UtcNow
    $Cached = $__EntraOpsSession.ArmTokenCache['default']
    # Re-use a cached token while it is valid for at least another 5 minutes
    if ($null -ne $Cached -and $Cached.Expiry -gt $Now.AddMinutes(5)) {
      return $Cached.Token
    }

    $TokenResponse = Get-AzAccessToken -ResourceTypeName Arm -AsSecureString -ErrorAction Stop
    $PlainToken = $TokenResponse.Token | ConvertFrom-SecureString -AsPlainText
    $Expiry = if ($TokenResponse.ExpiresOn) { $TokenResponse.ExpiresOn.UtcDateTime } else { $Now.AddMinutes(30) }
    $__EntraOpsSession.ArmTokenCache['default'] = @{ Token = $PlainToken; Expiry = $Expiry }
    return $PlainToken
  }

  $ArgEndpoint = "https://management.azure.com/providers/Microsoft.ResourceGraph/resources?api-version=2022-10-01"
  $SkipToken = $null

  do {
    # No subscriptions/managementGroups in the request body queries every resource the caller can access.
    $Options = [ordered]@{ '$top' = $BatchSize; resultFormat = 'objectArray' }
    if (-not [string]::IsNullOrEmpty($SkipToken)) { $Options['$skipToken'] = $SkipToken }
    $Body = @{ query = $KqlQuery; options = $Options } | ConvertTo-Json -Depth 10 -Compress

    $GraphResponse = $null
    $RetryCount = 0
    while ($true) {
      try {
        $HeaderParams = @{ Authorization = "Bearer $(Get-EntraOpsArgAccessToken)" }
        $GraphResponse = Invoke-RestMethod -Method POST -Uri $ArgEndpoint -Headers $HeaderParams -ContentType "application/json" -Body $Body -ErrorAction Stop
        break
      } catch {
        $StatusCode = $null
        if ($_.Exception.Response) { $StatusCode = $_.Exception.Response.StatusCode.value__ }

        # An expired token will be re-acquired on the next attempt; drop it from cache now
        if ($StatusCode -eq 401) { $__EntraOpsSession.ArmTokenCache.Remove('default') }

        if ($StatusCode -in @(401, 429, 500, 502, 503, 504) -and $RetryCount -lt $MaxRetries) {
          $RetryCount++

          # Prefer the Retry-After header, otherwise adaptive exponential backoff capped at 60s
          $RetryAfter = $null
          try {
            if ($_.Exception.Response.Headers -and $_.Exception.Response.Headers.Contains('Retry-After')) {
              $RetryAfter = [int]($_.Exception.Response.Headers.GetValues('Retry-After') | Select-Object -First 1)
            }
          } catch { Write-Verbose "Ignoring unreadable Retry-After header, using exponential backoff: $($_.Exception.Message)" }

          if ($null -ne $RetryAfter -and $RetryAfter -gt 0) {
            $RetryDelay = $RetryAfter
          } else {
            $RetryDelay = [Math]::Min($InitialRetryDelay * [Math]::Pow(2, $RetryCount - 1), 60)
          }

          Write-Verbose "Azure Resource Graph request throttled/transient (HTTP $StatusCode). Retry $RetryCount/$MaxRetries in $([Math]::Round($RetryDelay, 1))s"
          Start-Sleep -Seconds $RetryDelay
        } else {
          # Surface the Resource Graph error message from the response body when available
          $ErrorMessage = $_.Exception.Message
          if ($_.ErrorDetails.Message) {
            try { $ErrorMessage = ($_.ErrorDetails.Message | ConvertFrom-Json -ErrorAction Stop).error.message } catch { Write-Verbose "Resource Graph error body is not valid JSON, using the exception message: $($_.Exception.Message)" }
          }
          # Note this can be reached mid-pagination ($skipToken loop), so $Result may already hold
          # earlier pages - returning it yields a partial result the caller cannot distinguish
          # from a complete one.
          if ($ThrowOnFailure) {
            throw "Azure Resource Graph query failed after $($Result.Count) record(s): $ErrorMessage"
          }
          Write-Error "Azure Resource Graph query failed: $ErrorMessage"
          return $Result
        }
      }
    }

    if ($null -ne $GraphResponse.data) {
      $Result.AddRange(@($GraphResponse.data))
    }
    $SkipToken = $GraphResponse.'$skipToken'
  } while (-not [string]::IsNullOrEmpty($SkipToken))

  return $Result
  #endregion
}
