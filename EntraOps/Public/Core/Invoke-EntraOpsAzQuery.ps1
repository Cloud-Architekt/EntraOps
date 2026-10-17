<#
.SYNOPSIS
    Executing optimized queries against the Azure Resource Manager (ARM) REST API.

.DESCRIPTION
    Wrapper to call the Azure Resource Manager API (https://management.azure.com) with automatic
    pagination (nextLink), adaptive throttling/retry handling and result caching. The design borrows
    proven performance patterns from AzAPICall (https://github.com/JulianHayward/AzAPICall):

    - Throttling: honors the Retry-After header, reacts to the x-ms-ratelimit-remaining-* headers to
      proactively back off before ARM starts returning 429, and retries the transient status codes
      (429/500/502/503/504) as well as ARM error codes that indicate a retryable condition
      (e.g. ExpiredAuthenticationToken, ServerTimeout, GatewayTimeout, ResourceRequestsThrottled).
    - Paging: follows nextLink (and @odata.nextLink) until the full result set is collected.
    - Batching: bundles many requests into the ARM $batch endpoint (max 20 processed concurrently),
      which is what makes tenant-wide collection (all subscriptions and all management groups) fast.

    Pass a single relative/absolute Uri for one resource/list call, or pass an array of relative URIs
    (or request hashtables) to -BatchRequest to fan out many calls through the ARM batch endpoint. The
    batch path is the recommended way to collect RBAC role assignments across the entire tenant.

.PARAMETER Method
    HTTP Method to be used for the request. Default is GET.

.PARAMETER Uri
    Relative ARM Uri (starting with /subscriptions, /providers, /tenants, ...) or an absolute
    https://management.azure.com/... Uri. If -ApiVersion is supplied and the Uri has no api-version
    query parameter, it is appended automatically.

.PARAMETER BatchRequest
    One or more requests to send through the ARM $batch endpoint. Each item can be either a relative
    Uri string or a hashtable @{ Method = 'GET'; Uri = '/subscriptions/.../...?api-version=2022-04-01' }.
    Requests are chunked into -BatchSize (default 20) and each batched response is paged independently.

.PARAMETER Body
    Body of the request (objects are converted to JSON automatically, strings are sent as-is).

.PARAMETER ApiVersion
    Default api-version appended to URIs that do not already specify one. Default is 2022-04-01
    (the GA Microsoft.Authorization version used for role assignments).

.PARAMETER BatchSize
    Number of requests bundled into a single ARM $batch call. ARM processes a maximum of 20 requests
    concurrently per batch, which is the default and recommended value.

.PARAMETER OutputType
    Type of output to be returned. Default is PSObject. Other options are HashTable and Json.

.PARAMETER TenantId
    Optional tenant id to acquire the ARM access token for (cross-tenant scenarios). Defaults to the
    tenant of the current Az PowerShell context.

.PARAMETER DisableCache
    Disable the module-internal cache mechanism for the request.

.PARAMETER UseInvokeRestMethodOnly
    Accepted for consistency with the other Invoke-EntraOps*Query cmdlets. This wrapper is natively
    implemented with Invoke-RestMethod (token via Get-AzAccessToken, no Az.Resources/Invoke-AzRestMethod
    dependency), so batching, paging and retry behavior are identical with or without this switch.

.PARAMETER MaxRetries
    Maximum number of retry attempts for throttling (429) or transient errors. Default is 5.

.PARAMETER InitialRetryDelay
    Initial delay in seconds before the first retry. Default is 2 seconds. Adaptive backoff combined
    with the Retry-After header is used for subsequent attempts.

.EXAMPLE
    # List all role assignments of a single subscription (paged automatically)
    Invoke-EntraOpsAzQuery -Uri "/subscriptions/$SubscriptionId/providers/Microsoft.Authorization/roleAssignments"

.EXAMPLE
    # Get all role assignments tenant-wide (every subscription AND every management group) in batches.
    # Discover scopes first, then fan out through the ARM $batch endpoint for maximum throughput.
    $Subscriptions = (Invoke-EntraOpsAzQuery -Uri "/subscriptions" -ApiVersion "2020-01-01").subscriptionId
    $MgmtGroups    = (Invoke-EntraOpsAzQuery -Uri "/providers/Microsoft.Management/managementGroups" -ApiVersion "2020-05-01").name

    $RbacRequests  = @()
    $RbacRequests += $Subscriptions | ForEach-Object { "/subscriptions/$_/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01" }
    $RbacRequests += $MgmtGroups    | ForEach-Object { "/providers/Microsoft.Management/managementGroups/$_/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01" }

    $AllRoleAssignments = Invoke-EntraOpsAzQuery -BatchRequest $RbacRequests

.EXAMPLE
    # Filter role assignments to those at the exact scope (atScope) for a subscription
    Invoke-EntraOpsAzQuery -Uri "/subscriptions/$SubscriptionId/providers/Microsoft.Authorization/roleAssignments?`$filter=atScope()"
#>

function Invoke-EntraOpsAzQuery {
    [CmdletBinding(DefaultParameterSetName = 'Single')]
    param (
        [Parameter(Mandatory = $false, ParameterSetName = 'Single')]
        [string]$Method = 'GET',

        [Parameter(Mandatory = $true, ParameterSetName = 'Single')]
        [string]$Uri,

        [Parameter(Mandatory = $true, ParameterSetName = 'Batch')]
        [object[]]$BatchRequest,

        [Parameter(Mandatory = $false, ParameterSetName = 'Single')]
        [object]$Body,

        [Parameter(Mandatory = $false)]
        [string]$ApiVersion = '2022-04-01',

        [Parameter(Mandatory = $false, ParameterSetName = 'Batch')]
        [ValidateRange(1, 20)]
        [int]$BatchSize = 20,

        [Parameter(Mandatory = $false)]
        [ValidateSet("PSObject", "HashTable", "Json")]
        [string]$OutputType = "PSObject",

        [Parameter(Mandatory = $false)]
        [string]$TenantId,

        [Parameter(Mandatory = $false)]
        [switch]$DisableCache,

        [Parameter(Mandatory = $false)]
        [switch]$UseInvokeRestMethodOnly,

        [Parameter(Mandatory = $false)]
        [int]$MaxRetries = 5,

        [Parameter(Mandatory = $false)]
        [int]$InitialRetryDelay = 2
    )

    $ArmBaseUri = "https://management.azure.com"

    # This wrapper is natively implemented with Invoke-RestMethod, so the switch is a no-op
    # and only exists so all Invoke-EntraOps*Query cmdlets share the same parameter surface
    if ($UseInvokeRestMethodOnly) {
        Write-Verbose "UseInvokeRestMethodOnly requested - Invoke-EntraOpsAzQuery always uses Invoke-RestMethod."
    }

    #region Helper - Acquire (and cache) the ARM bearer token
    function Get-EntraOpsArmAccessToken {
        param ([string]$ForTenantId)

        $TokenKey = if ([string]::IsNullOrEmpty($ForTenantId)) { "default" } else { $ForTenantId }
        $Now = [DateTime]::UtcNow

        $Cached = $__EntraOpsSession.ArmTokenCache[$TokenKey]
        # Re-use a cached token while it is valid for at least another 5 minutes
        if ($null -ne $Cached -and $Cached.Expiry -gt $Now.AddMinutes(5)) {
            return $Cached.Token
        }

        $TokenParams = @{
            ResourceTypeName = 'Arm'
            AsSecureString   = $true
            ErrorAction      = 'Stop'
        }
        if (-not [string]::IsNullOrEmpty($ForTenantId)) { $TokenParams.TenantId = $ForTenantId }

        $TokenResponse = Get-AzAccessToken @TokenParams
        $PlainToken = $TokenResponse.Token | ConvertFrom-SecureString -AsPlainText
        $Expiry = if ($TokenResponse.ExpiresOn) { $TokenResponse.ExpiresOn.UtcDateTime } else { $Now.AddMinutes(30) }

        $__EntraOpsSession.ArmTokenCache[$TokenKey] = @{ Token = $PlainToken; Expiry = $Expiry }
        return $PlainToken
    }
    #endregion

    #region Helper - Tenant discriminator for response cache keys
    # Many ARM URIs are tenant agnostic ("/subscriptions", "/providers/Microsoft.Management/managementGroups",
    # "/providers/Microsoft.Authorization/roleAssignments?$filter=atScope()"), so a URI-only cache key lets a
    # response collected for tenant A be served to tenant B in a multi-tenant or worker-reuse run.
    # The tenant is derived from the "tid" claim of the ARM bearer token actually used for the request, which
    # is authoritative - unlike ambient context, it cannot silently fall back to the same value in both tenants.
    function Get-EntraOpsArmCacheTenantId {
        param ([string]$ForTenantId)

        if (-not [string]::IsNullOrEmpty($ForTenantId)) { return $ForTenantId }

        try {
            $Token = Get-EntraOpsArmAccessToken -ForTenantId $ForTenantId
            $Payload = ($Token -split '\.')[1]
            if ([string]::IsNullOrEmpty($Payload)) { return 'unknown-tenant' }
            $Payload = $Payload.Replace('-', '+').Replace('_', '/')
            $Payload = $Payload.PadRight([int][Math]::Ceiling($Payload.Length / 4) * 4, '=')
            $Claims = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($Payload)) | ConvertFrom-Json
            if (-not [string]::IsNullOrEmpty($Claims.tid)) { return $Claims.tid }
        } catch {
            Write-Verbose "Unable to determine ARM tenant context for cache scoping: $_"
        }
        # Deliberately NOT "default": an unresolvable tenant must not share a cache namespace with a resolved one.
        return 'unknown-tenant'
    }
    #endregion

    #region Helper - Normalize a relative/absolute ARM Uri and ensure api-version
    function Resolve-EntraOpsArmUri {
        param ([string]$RawUri)

        if ($RawUri -like "$ArmBaseUri/*") {
            $Resolved = $RawUri
        } elseif ($RawUri -like "/*") {
            $Resolved = "$ArmBaseUri$RawUri"
        } else {
            throw "Invalid Azure Resource Manager URI: $($RawUri)! Use a relative path (e.g. /subscriptions/...) or an absolute $ArmBaseUri/... URI."
        }

        if ($Resolved -notmatch "[?&]api-version=") {
            $Separator = if ($Resolved.Contains('?')) { '&' } else { '?' }
            $Resolved = "$Resolved$($Separator)api-version=$ApiVersion"
        }
        return $Resolved
    }
    #endregion

    #region Helper - Proactively back off based on the remaining rate-limit budget
    function Invoke-EntraOpsArmRateLimitBackoff {
        param ($ResponseHeaders)

        if ($null -eq $ResponseHeaders) { return }

        # ARM exposes several x-ms-ratelimit-remaining-* counters; back off when the lowest gets close to 0
        $RemainingValues = foreach ($HeaderName in $ResponseHeaders.Keys) {
            if ($HeaderName -like 'x-ms-ratelimit-remaining-*') {
                $RawValue = $ResponseHeaders[$HeaderName]
                if ($RawValue -is [array]) { $RawValue = $RawValue[0] }
                $Parsed = 0
                if ([int]::TryParse("$RawValue", [ref]$Parsed)) { $Parsed }
            }
        }

        if ($RemainingValues) {
            $Lowest = ($RemainingValues | Measure-Object -Minimum).Minimum
            if ($Lowest -le 10) {
                Write-Verbose "ARM rate-limit budget low (remaining: $Lowest). Backing off 5s to avoid throttling."
                Start-Sleep -Seconds 5
            } elseif ($Lowest -le 50) {
                Write-Verbose "ARM rate-limit budget getting low (remaining: $Lowest). Backing off 1s."
                Start-Sleep -Seconds 1
            }
        }
    }
    #endregion

    #region Helper - Execute a single ARM request with adaptive retry/throttle handling
    # Returns a hashtable: @{ Success = [bool]; Data = <parsed object>; ErrorCode = <string>; StatusCode = <int> }
    function Invoke-EntraOpsArmRequest {
        param (
            [string]$RequestMethod,
            [string]$RequestUri,
            [object]$RequestBody
        )

        # Retryable ARM/HTTP signals adopted from AzAPICall's rule set
        $RetryableStatusCodes = @(429, 500, 502, 503, 504)
        $RetryableErrorCodes = @(
            'ExpiredAuthenticationToken', 'InvalidAuthenticationToken', 'Authentication_ExpiredToken', 'TokenExpired',
            'GatewayTimeout', 'BadGateway', 'InvalidGatewayHost', 'ServerTimeout', 'ServiceUnavailable',
            'RequestTimeout', 'InternalServerError', 'UnknownError', 'MultipleErrorsOccurred',
            'ResourceRequestsThrottled', 'RateLimiting', 'TooManyRequests', 'OperationNotAllowed'
        )

        $BodyJson = $null
        if ($null -ne $RequestBody) {
            $BodyJson = if ($RequestBody -is [string]) { $RequestBody } else { $RequestBody | ConvertTo-Json -Depth 20 -Compress }
        }

        $RetryCount = 0
        while ($RetryCount -le $MaxRetries) {
            $ResponseHeaders = $null

            try {
                # Acquire/refresh token on every attempt (cached) so an expired-token retry gets a fresh one.
                # Kept inside the try so a transient credential/OIDC failure (e.g. ClientAssertionCredential)
                # is retried like any other transient error instead of crashing the whole run.
                $HeaderParams = @{ Authorization = "Bearer $(Get-EntraOpsArmAccessToken -ForTenantId $TenantId)" }

                $InvokeParams = @{
                    Headers                 = $HeaderParams
                    Uri                     = $RequestUri
                    Method                  = $RequestMethod
                    ContentType             = "application/json"
                    ResponseHeadersVariable = 'ResponseHeaders'
                    ErrorAction             = 'Stop'
                }
                if ($null -ne $BodyJson) { $InvokeParams.Body = $BodyJson }

                $RequestResult = Invoke-RestMethod @InvokeParams

                # Honor the remaining rate-limit budget before the caller fires the next request
                Invoke-EntraOpsArmRateLimitBackoff -ResponseHeaders $ResponseHeaders

                return @{ Success = $true; Data = $RequestResult; ErrorCode = $null; StatusCode = 200 }

            } catch {
                $StatusCode = $null
                if ($_.Exception.Response) { $StatusCode = $_.Exception.Response.StatusCode.value__ }

                # Extract the ARM error code from the response body (best effort)
                $ErrorCode = $null
                if ($_.ErrorDetails.Message) {
                    try { $ErrorCode = ($_.ErrorDetails.Message | ConvertFrom-Json -ErrorAction Stop).error.code } catch { Write-Verbose "ARM error body is not valid JSON, continuing without an error code: $($_.Exception.Message)" }
                }

                $IsNetworkError = ($null -eq $StatusCode -and $_.Exception.Message -match 'An error occurred while sending the request|operation has timed out|Unable to connect|Connection reset')

                # Token acquisition/credential failures (e.g. a transient OIDC/federated-credential exchange
                # hiccup surfaced by Get-AzAccessToken as "ClientAssertionCredential authentication failed")
                # have no HTTP response at all, so they must be detected from the exception message.
                $IsAuthError = ($null -eq $StatusCode -and $_.Exception.Message -match 'ClientAssertionCredential authentication failed|ManagedIdentityCredential authentication failed|Failed to acquire token|AADSTS')

                # Non-retryable, expected conditions: report and skip without burning retries
                if ($ErrorCode -in @('ResponseTooLarge')) {
                    Write-Warning "ARM returned '$ErrorCode' for $RequestUri. Result skipped - narrow the scope or use the ARM `$batch endpoint per sub-scope."
                    return @{ Success = $false; Data = $null; ErrorCode = $ErrorCode; StatusCode = $StatusCode }
                }

                $IsRetryable = ($StatusCode -in $RetryableStatusCodes) -or ($ErrorCode -in $RetryableErrorCodes) -or $IsNetworkError -or $IsAuthError

                if ($IsRetryable -and $RetryCount -lt $MaxRetries) {
                    $RetryCount++

                    # An expired or unusable token will be re-acquired on the next loop; drop it from cache now
                    if ($IsAuthError -or $ErrorCode -in @('ExpiredAuthenticationToken', 'InvalidAuthenticationToken', 'Authentication_ExpiredToken', 'TokenExpired')) {
                        $TokenKey = if ([string]::IsNullOrEmpty($TenantId)) { "default" } else { $TenantId }
                        $__EntraOpsSession.ArmTokenCache.Remove($TokenKey)
                    }

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

                    # Add jitter (±20%) to prevent a thundering herd of synchronized retries
                    $Jitter = $RetryDelay * 0.2 * (Get-Random -Minimum -1.0 -Maximum 1.0)
                    $RetryDelay = [Math]::Max(1, $RetryDelay + $Jitter)

                    Add-EntraOpsRetryStatistic -Name TotalRetries
                    Add-EntraOpsRetryStatistic -Name ThrottledRequests
                    Write-Verbose "ARM request throttled/transient (HTTP $StatusCode / $ErrorCode). Retry $RetryCount/$MaxRetries in $([Math]::Round($RetryDelay, 1))s for: $RequestUri"

                    Start-Sleep -Seconds $RetryDelay
                } else {
                    if ($RetryCount -ge $MaxRetries) {
                        Add-EntraOpsRetryStatistic -Name FailedRequests
                        $__EntraOpsSession.RetryStatistics.FailedRequestDetails.Add([pscustomobject]@{ Timestamp = (Get-Date); Uri = $RequestUri; StatusCode = $StatusCode; ErrorMessage = "$($_.Exception.Message)$(if ($ErrorCode) { " ($ErrorCode)" })" })
                        Write-Error "ARM request to $RequestUri failed after $MaxRetries retry attempts. Error: $($_.Exception.Message)"
                    } else {
                        Add-EntraOpsRetryStatistic -Name NonRetryableRequests
                        $__EntraOpsSession.RetryStatistics.NonRetryableRequestDetails.Add([pscustomobject]@{ Timestamp = (Get-Date); Uri = $RequestUri; StatusCode = $StatusCode; ErrorMessage = "$($_.Exception.Message)$(if ($ErrorCode) { " ($ErrorCode)" })" })
                        Write-Warning "ARM request to $RequestUri failed (non-retryable HTTP $StatusCode / $ErrorCode). Error: $($_.Exception.Message)"
                    }
                    return @{ Success = $false; Data = $null; ErrorCode = $ErrorCode; StatusCode = $StatusCode }
                }
            }
        }

        Add-EntraOpsRetryStatistic -Name FailedRequests
        $__EntraOpsSession.RetryStatistics.FailedRequestDetails.Add([pscustomobject]@{ Timestamp = (Get-Date); Uri = $RequestUri; StatusCode = 429; ErrorMessage = "Persistent throttling after $MaxRetries retry attempts" })
        Write-Error "ARM request to $RequestUri failed after $MaxRetries retry attempts due to persistent throttling."
        return @{ Success = $false; Data = $null; ErrorCode = 'MaxRetriesExceeded'; StatusCode = 429 }
    }
    #endregion

    #region Helper - Follow nextLink pagination for an ARM list payload
    function Get-EntraOpsArmPagedResult {
        param ([object]$FirstPage)

        $Collected = New-Object System.Collections.Generic.List[Object]

        $Page = $FirstPage
        while ($true) {
            if ($null -ne $Page.value) {
                $Collected.AddRange(@($Page.value))
            } elseif ($null -ne $Page) {
                $Collected.Add($Page)
            }

            $NextLink = $Page.nextLink
            if ([string]::IsNullOrEmpty($NextLink)) { $NextLink = $Page.'@odata.nextLink' }
            if ([string]::IsNullOrEmpty($NextLink)) { break }

            $NextResult = Invoke-EntraOpsArmRequest -RequestMethod 'GET' -RequestUri $NextLink -RequestBody $null
            if (-not $NextResult.Success) {
                # Returning what was collected so far makes a truncated result indistinguishable from a
                # complete one: the run reports success and the missing privileged principals look like
                # legitimate remediation in the committed diff. Fail loudly instead - the empty/failed-result
                # guard in Save-EntraOpsEAMRbacSystemJson then preserves the previous good export.
                throw "ARM pagination failed after $($Collected.Count) item(s) while following '$NextLink'. Refusing to return a partial result set."
            }
            $Page = $NextResult.Data
        }

        return $Collected
    }
    #endregion

    $Result = New-Object System.Collections.Generic.List[Object]

    if ($PSCmdlet.ParameterSetName -eq 'Batch') {
        #region Batch mode - fan out through the ARM $batch endpoint (max 20 concurrent per call)
        $BatchEndpoint = "$ArmBaseUri/batch?api-version=2020-06-01"

        # Normalize each request to @{ httpMethod; url } with a resolved Uri + api-version
        $NormalizedRequests = foreach ($Request in $BatchRequest) {
            if ($Request -is [hashtable]) {
                @{ httpMethod = ($Request.Method ?? 'GET'); url = (Resolve-EntraOpsArmUri -RawUri $Request.Uri) }
            } else {
                @{ httpMethod = 'GET'; url = (Resolve-EntraOpsArmUri -RawUri "$Request") }
            }
        }

        $TotalRequests = @($NormalizedRequests).Count
        Write-Verbose "Dispatching $TotalRequests ARM request(s) through the `$batch endpoint in chunks of $BatchSize."

        # Retain failed batch items so incomplete responses cannot be exported as complete snapshots.
        $FailedBatchItems = [System.Collections.Generic.List[string]]::new()

        for ($Offset = 0; $Offset -lt $TotalRequests; $Offset += $BatchSize) {
            $Chunk = @($NormalizedRequests)[$Offset..([Math]::Min($Offset + $BatchSize - 1, $TotalRequests - 1))]

            # ARM requires a unique name per request to correlate responses
            $ChunkRequests = @()
            for ($i = 0; $i -lt $Chunk.Count; $i++) {
                $ChunkRequests += @{ httpMethod = $Chunk[$i].httpMethod; name = "$($Offset + $i)"; url = $Chunk[$i].url }
            }

            $BatchBody = @{ requests = $ChunkRequests }
            $BatchResult = Invoke-EntraOpsArmRequest -RequestMethod 'POST' -RequestUri $BatchEndpoint -RequestBody $BatchBody
            if (-not $BatchResult.Success) {
                # Retry the whole chunk once (Invoke-EntraOpsArmRequest already applies its own
                # per-request retry/backoff internally). Silently continuing here would drop up to
                # $BatchSize scopes from the result while the run still reports success.
                Write-Warning "ARM `$batch chunk (offset $Offset, $($ChunkRequests.Count) request(s)) failed - retrying chunk once."
                $BatchResult = Invoke-EntraOpsArmRequest -RequestMethod 'POST' -RequestUri $BatchEndpoint -RequestBody $BatchBody
                if (-not $BatchResult.Success) {
                    $FailedScopes = @($Chunk | ForEach-Object { $_.url }) -join ', '
                    throw "ARM `$batch chunk (offset $Offset) failed after retry. Refusing to return a truncated result set. Failed scope request(s): $FailedScopes"
                }
            }

            foreach ($Response in $BatchResult.Data.responses) {
                $ItemStatus = $Response.httpStatusCode

                if ($ItemStatus -ge 200 -and $ItemStatus -lt 300) {
                    # Page each successful response independently (nextLink follows go direct, not via batch)
                    $Result.AddRange(@(Get-EntraOpsArmPagedResult -FirstPage $Response.content))
                } elseif ($ItemStatus -in @(429, 500, 502, 503, 504)) {
                    # Per-item throttling/transient error: retry that single request on its own
                    $RetryReq = @($NormalizedRequests)[[int]$Response.name]
                    Write-Verbose "Batch item '$($Response.name)' returned HTTP $ItemStatus, retrying individually: $($RetryReq.url)"
                    $ItemResult = Invoke-EntraOpsArmRequest -RequestMethod $RetryReq.httpMethod -RequestUri $RetryReq.url -RequestBody $null
                    if ($ItemResult.Success) {
                        $Result.AddRange(@(Get-EntraOpsArmPagedResult -FirstPage $ItemResult.Data))
                    } else {
                        $FailedBatchItems.Add("$($RetryReq.url) (HTTP $ItemStatus, individual retry failed)")
                    }
                } else {
                    $ItemCode = $Response.content.error.code
                    $ItemUrl = (@($NormalizedRequests)[[int]$Response.name]).url
                    Add-EntraOpsRetryStatistic -Name NonRetryableRequests
                    $__EntraOpsSession.RetryStatistics.NonRetryableRequestDetails.Add([pscustomobject]@{ Timestamp = (Get-Date); Uri = $ItemUrl; StatusCode = $ItemStatus; ErrorMessage = "Batch item failed ($ItemCode)" })
                    Write-Warning "Batch item '$($Response.name)' failed (HTTP $ItemStatus / $ItemCode): $ItemUrl"
                    $FailedBatchItems.Add("$ItemUrl (HTTP $ItemStatus / $ItemCode)")
                }
            }
        }

        if ($FailedBatchItems.Count -gt 0) {
            throw "$($FailedBatchItems.Count) ARM `$batch item(s) failed. Refusing to return a truncated result set. Failed request(s): $($FailedBatchItems -join '; ')"
        }
        #endregion
    } else {
        #region Single mode - one resource/list call with caching + pagination
        $ResolvedUri = Resolve-EntraOpsArmUri -RawUri $Uri
        $IsCacheable = ($Method -eq 'GET' -and -not $DisableCache)
        # Tenant-scoped cache key (matches the "<tenant>#<uri>" convention of Invoke-EntraOpsMsGraphQuery).
        # CacheMetadata keeps the raw Uri as a field so verbose/telemetry output stays readable.
        $CacheKey = if ($IsCacheable) { "$(Get-EntraOpsArmCacheTenantId -ForTenantId $TenantId)#$ResolvedUri" } else { $ResolvedUri }

        $QueryResult = $null
        if ($IsCacheable -and $__EntraOpsSession.GraphCache.ContainsKey($CacheKey)) {
            if ($__EntraOpsSession.CacheMetadata.ContainsKey($CacheKey)) {
                $CacheEntry = $__EntraOpsSession.CacheMetadata[$CacheKey]
                if ([DateTime]::UtcNow -lt $CacheEntry.ExpiryTime) {
                    Write-Verbose "Using valid ARM cache: $ResolvedUri"
                    $QueryResult = $__EntraOpsSession.GraphCache[$CacheKey]
                } else {
                    $__EntraOpsSession.GraphCache.Remove($CacheKey)
                    $__EntraOpsSession.CacheMetadata.Remove($CacheKey)
                }
            } else {
                $QueryResult = $__EntraOpsSession.GraphCache[$CacheKey]
            }
        }

        if ($null -eq $QueryResult) {
            $FirstResult = Invoke-EntraOpsArmRequest -RequestMethod $Method -RequestUri $ResolvedUri -RequestBody $Body
            if (-not $FirstResult.Success) { return $null }

            $QueryResult = Get-EntraOpsArmPagedResult -FirstPage $FirstResult.Data

            # Cache GET results with TTL metadata (reuses the shared session cache + TTL settings)
            if ($IsCacheable) {
                $CurrentTime = [DateTime]::UtcNow
                $CacheMetadataEntry = @{
                    Uri         = $ResolvedUri
                    CachedTime  = $CurrentTime
                    ExpiryTime  = $CurrentTime.AddSeconds($__EntraOpsSession.DefaultCacheTTL)
                    TTLSeconds  = $__EntraOpsSession.DefaultCacheTTL
                    ResultCount = $QueryResult.Count
                }
                $__EntraOpsSession.GraphCache[$CacheKey] = $QueryResult
                $__EntraOpsSession.CacheMetadata[$CacheKey] = $CacheMetadataEntry
                Write-Verbose "Cached ARM result for $ResolvedUri (TTL: $($__EntraOpsSession.DefaultCacheTTL)s, Count: $($QueryResult.Count))"
            }
        }

        $Result.AddRange(@($QueryResult))
        #endregion
    }

    switch ($OutputType) {
        Json     { return ($Result | ConvertTo-Json -Depth 20) }
        # Case-insensitive conversion so property access with different casing (e.g. .Id vs "id")
        # behaves like the rest of the module (ConvertFrom-Json -AsHashtable is case-sensitive)
        HashTable { return @($Result | ForEach-Object { ConvertTo-EntraOpsCaseInsensitiveHashtable -InputObject $_ }) }
        default  { return $Result }
    }
}
