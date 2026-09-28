<#
.SYNOPSIS
    Executing Query on Microsoft Graph API.

.DESCRIPTION
    Wrapper to call Microsoft Graph API with pagination support to fetch all data and set default values.

.PARAMETER Method
    HTTP Method to be used for the request. Default is GET.

.PARAMETER Uri
    URI of the Microsoft Graph API to be called. Format of the URI should be /beta/ or /v1.0/ followed by the endpoint.

.PARAMETER Body
    Body of the request to be sent to the Microsoft Graph API.

.PARAMETER ConsistencyLevel
    Consistency level to be used for the request.

.PARAMETER OutputType
    Type of output to be returned. Default is HashTable.
    Other options are PSObject, HttpResponseMessage, and JSON.

.PARAMETER DisableCache
    Disable module-internal cache mechanism for the request.

.PARAMETER UseInvokeRestMethodOnly
    Use Invoke-RestMethod instead of Invoke-MgGraphRequest (Microsoft Graph SDK) for the request.
    The access token is taken from the module-private session store (set by Connect-EntraOps
    -MsGraphAccessToken) or acquired via Get-AzAccessToken from the current Az PowerShell context.
    Output, pagination, batching ($batch), caching and retry behavior are identical to the SDK path.
    If not set explicitly, the module-wide setting from Connect-EntraOps -UseInvokeRestMethodOnly applies.

.PARAMETER MaxRetries
    Maximum number of retry attempts for rate limiting (429) or transient errors (503, 504). Default is 5.

.PARAMETER InitialRetryDelay
    Initial delay in seconds before first retry. Default is 2 seconds. Uses adaptive backoff with Retry-After header.

.PARAMETER SuppressNotFoundWarning
    Downgrade the non-retryable-error warning to Write-Verbose specifically for HTTP 404 (NotFound)
    responses. Use for "probe for absence" lookups where a 404 is an expected, common outcome rather
    than a genuine failure.

.PARAMETER SuppressBadRequestWarning
    Downgrade the non-retryable-error warning to Write-Verbose specifically for HTTP 400 (BadRequest)
    responses. Use for capability probes where a 400 is an expected outcome (e.g. PIM for Groups
    eligibilitySchedules queries against groups that are not PIM-capable) rather than a genuine failure.

.PARAMETER SuppressForbiddenWarning
    Downgrade the non-retryable-error warning to Write-Verbose specifically for HTTP 403 (Forbidden)
    responses. Use together with -ThrowOnFailure at call sites that catch the error and emit their
    own, more actionable warning (e.g. naming the missing Graph permission), so the same failure is
    not reported twice.

.EXAMPLE
    Get list of all transitive role assignments for a principal in Microsoft Entra ID by principalId and using ConsistencyLevel.
    Invoke-EntraOpsMsGraphQuery -Uri "/beta/roleManagement/directory/transitiveRoleAssignments?`$count=true&`$filter=principalId eq '$Principal'" -ConsistencyLevel "eventual"

.EXAMPLE
    Get list of all role definitions in Microsoft Entra ID.
    Invoke-EntraOpsMsGraphQuery -Uri "/beta/roleManagement/directory/roleDefinitions"

.EXAMPLE
    Query with custom retry settings for high-traffic scenarios.
    Invoke-EntraOpsMsGraphQuery -Uri "/beta/users" -MaxRetries 7 -InitialRetryDelay 10
#>

function Invoke-EntraOpsMsGraphQuery {
    [CmdletBinding()]
    param (
        [parameter(Mandatory = $false)]
        [string]$Method = 'GET',

        [parameter(Mandatory = $true)]
        [string]$Uri,

        [parameter(Mandatory = $false)]
        [string]$Body,

        [parameter(Mandatory = $false)]
        [string]$ConsistencyLevel,

        [parameter(Mandatory = $false)]
        [ValidateSet("HashTable", "PSObject", "HttpResponseMessage", "Json")]
        [string]$OutputType = "HashTable",

        [Parameter(Mandatory = $false)]
        [switch]$DisableCache,

        [Parameter(Mandatory = $false)]
        [switch]$UseInvokeRestMethodOnly,

        [Parameter(Mandatory = $false)]
        [int]$MaxRetries = 5,

        [Parameter(Mandatory = $false)]
        [int]$InitialRetryDelay = 2,

        # Throw a terminating error instead of writing a non-terminating error and returning $null.
        # Use from callers whose output must never be built from a failed/incomplete result set - a
        # returned $null is indistinguishable from "no results", which silently narrows classification.
        [switch]$ThrowOnFailure,

        # Downgrade the non-retryable-error warning to Write-Verbose specifically for HTTP 404
        # (NotFound) responses. Use at "probe for absence" call sites where a 404 is an expected,
        # common outcome (e.g. checking whether an object has zero administrativeUnit memberships)
        # rather than a genuine failure - avoids alarming warning spam for normal states. Has no
        # effect on any other status code, and does not affect -ThrowOnFailure.
        [switch]$SuppressNotFoundWarning,

        # Same as SuppressNotFoundWarning but for HTTP 400 (BadRequest) - for capability probes
        # where Graph answers 400 for a normal state (e.g. eligibilitySchedules on a group that
        # is not PIM-capable).
        [switch]$SuppressBadRequestWarning,

        # Same as SuppressNotFoundWarning but for HTTP 403 (Forbidden) - for call sites that pair
        # it with -ThrowOnFailure and surface their own permission-specific warning instead.
        [switch]$SuppressForbiddenWarning,

        # Fetch only the first page and do not follow @odata.nextLink. Use for intentional
        # "sample the first N items" queries (e.g. $top probes) where full pagination is unwanted.
        [switch]$FirstPageOnly
    )

    # Fall back to the module-wide setting when not set explicitly: session store from
    # Connect-EntraOps -UseInvokeRestMethodOnly is authoritative, a user-set global variable
    # is honored as legacy fallback
    if (-not $PSBoundParameters.ContainsKey('UseInvokeRestMethodOnly')) {
        if ($__EntraOpsSession.ContainsKey('UseInvokeRestMethodOnly')) {
            $UseInvokeRestMethodOnly = [bool]$__EntraOpsSession['UseInvokeRestMethodOnly']
        } else {
            $UseInvokeRestMethodOnly = [bool]$Global:UseInvokeRestMethodOnly
        }
    }

    #region Helper - Graph error code/message from the response body (the raw body also contains all response headers)
    function Get-EntraOpsMsGraphErrorSummary {
        param($ErrorRecord)
        $Body = [string]$ErrorRecord.ErrorDetails.Message
        if ($Body -match '(?s)(\{\s*"error".*\})\s*$') {
            try {
                $GraphError = ($Matches[1] | ConvertFrom-Json -ErrorAction Stop).error
                if ($GraphError.code) { return " ($($GraphError.code): $($GraphError.message))" }
            } catch { }
        }
        return ''
    }
    #endregion

    #region Helper - Acquire (and cache) a Microsoft Graph bearer token for the Invoke-RestMethod path
    function Get-EntraOpsMsGraphAccessToken {
        $Now = [DateTime]::UtcNow

        # Cross-tenant work (e.g. managing tenant group expansion/object resolution) sets
        # CurrentGraphTenantId in the session - the REST path must then use a token for THAT
        # tenant, mirroring what Connect-MgGraph context switching does for the SDK path
        $TargetTenantId = $__EntraOpsSession['CurrentGraphTenantId']
        $TokenKey = if ([string]::IsNullOrEmpty($TargetTenantId)) { 'default' } else { $TargetTenantId }

        if ($TokenKey -eq 'default') {
            # Prefer a token explicitly provided to Connect-EntraOps -MsGraphAccessToken (module-private
            # session store), e.g. workload identity scenarios where the Az context cannot mint new Graph
            # tokens itself. Falls through to Get-AzAccessToken once the provided token has expired.
            # Only valid for the home/target tenant - never for cross-tenant requests.
            $Provided = $__EntraOpsSession.MsGraphTokenCache['provided']
            if ($null -ne $Provided -and $Provided.Expiry -gt $Now) {
                return $Provided.Token
            }

            # Legacy fallback: global variable set by callers before the module-private store existed
            if (-not [string]::IsNullOrEmpty($Global:MsGraphAccessToken)) {
                # Deprecated - warn once per module load, keep working for backward compatibility
                if (-not $Script:MsGraphGlobalTokenFallbackWarned) {
                    Write-Warning "Reading the Microsoft Graph access token from `$Global:MsGraphAccessToken is deprecated and will be removed in a future release. Pass the token via Connect-EntraOps -MsGraphAccessToken instead."
                    $Script:MsGraphGlobalTokenFallbackWarned = $true
                }
                return $Global:MsGraphAccessToken
            }
        }

        $Cached = $__EntraOpsSession.MsGraphTokenCache[$TokenKey]
        # Re-use a cached token while it is valid for at least another 5 minutes
        if ($null -ne $Cached -and $Cached.Expiry -gt $Now.AddMinutes(5)) {
            return $Cached.Token
        }

        $TokenParams = @{ ResourceTypeName = 'MSGraph'; AsSecureString = $true; ErrorAction = 'Stop' }
        if ($TokenKey -ne 'default') { $TokenParams.TenantId = $TargetTenantId }
        $TokenResponse = Get-AzAccessToken @TokenParams
        $PlainToken = $TokenResponse.Token | ConvertFrom-SecureString -AsPlainText
        $Expiry = if ($TokenResponse.ExpiresOn) { $TokenResponse.ExpiresOn.UtcDateTime } else { $Now.AddMinutes(30) }
        $__EntraOpsSession.MsGraphTokenCache[$TokenKey] = @{ Token = $PlainToken; Expiry = $Expiry }
        return $PlainToken
    }
    #endregion

    $HeaderParams = @{}

    # Check if the Uri is valid.
    if ($Uri -like "/beta/*" -or $Uri -like "/v1.0/*") {
        $Uri = "https://graph.microsoft.com$Uri"
    } elseif ($Uri -like "https://graph.microsoft.com/*") {
    } else {
        throw "Invalid Graph URI: $($Uri)!"
    }

    # Add ConsistencyLevel if provided in parameter
    if ($null -ne $ConsistencyLevel) {
        $HeaderParams.Add('ConsistencyLevel', "$ConsistencyLevel")
    }

    # Check cache property for the Uri
    $isBatch = $Uri.EndsWith('$batch')
    $isMethodGet = $Method -eq 'GET'
    $isCacheablePost = ($Method -eq 'POST' -and ($Uri -like "*/getByIds*" -or $Uri -like "*/validateProperties"))

    # Cache keys must be scoped per tenant: $__EntraOpsSession is a single module-scope
    # hashtable shared across the whole process, so without a tenant discriminator, a
    # Graph URI (e.g. role definitions) queried for Tenant A would be served back for
    # Tenant B if both are processed in the same session/runspace (sequential loops,
    # or worker-process/runspace reuse in Azure Functions). Prefer the actual
    # authenticated Graph context's TenantId (reflects the token actually used for the
    # call); fall back to the Connect-EntraOps global context if unavailable.
    # A cross-tenant override set by managing-tenant code paths takes precedence: in REST-only
    # mode Get-MgContext does not reflect the tenant actually queried by Invoke-RestMethod
    $CacheTenantId = $__EntraOpsSession['CurrentGraphTenantId']
    if ([string]::IsNullOrEmpty($CacheTenantId)) {
        try {
            $CacheTenantId = (Get-MgContext -ErrorAction Stop).TenantId
        } catch {
            Write-Verbose "Unable to determine current Graph tenant context for cache scoping: $_"
        }
    }
    if ([string]::IsNullOrEmpty($CacheTenantId)) {
        $CacheTenantId = $Global:TenantIdContext
    }
    if ([string]::IsNullOrEmpty($CacheTenantId)) {
        $CacheTenantId = "default"
    }

    if ($isCacheablePost -and $null -ne $Body) {
        # Create hash of body to ensure unique cache key for POST requests
        $BodyBytes = [System.Text.Encoding]::UTF8.GetBytes($Body)
        $Sha256 = [System.Security.Cryptography.SHA256]::Create()
        try {
            $BodyHash = [BitConverter]::ToString($Sha256.ComputeHash($BodyBytes)).Replace("-", "")
        } finally {
            $Sha256.Dispose()
        }
        $cacheKey = "$CacheTenantId#$Uri#$BodyHash"
    } else {
        $cacheKey = "$CacheTenantId#$Uri"
    }

    try {
        $isInCache = $__EntraOpsSession.GraphCache.ContainsKey($cacheKey)
    } catch {
        Write-Verbose "Cache is empty"
    }
    
    # Determine if this is static reference data (longer TTL)
    $IsStaticData = $Uri -match "roleDefinitions|directoryRoleTemplates|permissionGrants|appRoles|publishedPermissionScopes"
    $CacheTTLSeconds = if ($IsStaticData) { $__EntraOpsSession.StaticDataCacheTTL } else { $__EntraOpsSession.DefaultCacheTTL }

    # Check if Cache can be used and data is available in cache
    # Enhanced logic with TTL support for improved cache management
    $CacheIsValid = $false
    if (!$DisableCache -and !$isBatch -and $isInCache -and ($isMethodGet -or $isCacheablePost)) {
        # Check if cache entry has expired
        if ($__EntraOpsSession.CacheMetadata.ContainsKey($cacheKey)) {
            $CacheEntry = $__EntraOpsSession.CacheMetadata[$cacheKey]
            $CurrentTime = [DateTime]::UtcNow
            
            if ($CurrentTime -lt $CacheEntry.ExpiryTime) {
                $CacheIsValid = $true
                $TimeRemaining = ($CacheEntry.ExpiryTime - $CurrentTime).TotalSeconds
                Write-Verbose ("Using valid graph cache: $($cacheKey) (expires in $([Math]::Round($TimeRemaining, 0))s)")
                $QueryResult = $__EntraOpsSession.GraphCache[$cacheKey]
            } else {
                Write-Verbose ("Cache expired for: $($cacheKey), fetching fresh data")
                $__EntraOpsSession.GraphCache.Remove($cacheKey)
                $__EntraOpsSession.CacheMetadata.Remove($cacheKey)
                $isInCache = $false
            }
        } else {
            # Legacy cache entry without metadata, use it but stamp metadata so it expires after the regular TTL
            Write-Verbose ("Using legacy graph cache (no TTL): $($cacheKey), stamping TTL metadata ($($CacheTTLSeconds)s)")
            $CacheIsValid = $true
            $QueryResult = $__EntraOpsSession.GraphCache[$cacheKey]
            $LegacyCachedTime = [DateTime]::UtcNow
            $__EntraOpsSession.CacheMetadata[$cacheKey] = @{
                Uri          = $Uri
                CachedTime   = $LegacyCachedTime
                ExpiryTime   = $LegacyCachedTime.AddSeconds($CacheTTLSeconds)
                TTLSeconds   = $CacheTTLSeconds
                IsStaticData = $IsStaticData
                ResultCount  = if ($QueryResult -is [System.Collections.ICollection]) { $QueryResult.Count } else { 1 }
            }
        }
    }

    if (!$QueryResult) {
        # Create empty arrays to store the results
        $QueryRequest = @()
        $QueryResult = New-Object System.Collections.Generic.List[Object]

        if ($UseInvokeRestMethodOnly) {
            Write-Verbose -Message "Using Invoke-RestMethod Cmdlet"
            try {
                $HeaderParams['Authorization'] = "Bearer $(Get-EntraOpsMsGraphAccessToken)"
            } catch {
                throw "UseInvokeRestMethodOnly is enabled but no Microsoft Graph access token could be acquired. Provide -MsGraphAccessToken to Connect-EntraOps or authenticate with Az PowerShell (Connect-AzAccount). Error: $($_.Exception.Message)"
            }

            $RetryCount = 0
            $Success = $false
            
            while (-not $Success -and $RetryCount -le $MaxRetries) {
                try {
                    # A retry restarts from the first page, so anything collected by the failed attempt must be
                    # discarded first. Without this, a mid-pagination failure retried at this level re-appends
                    # the pages already collected and silently duplicates results.
                    $QueryResult.Clear()

                    # Run the initial query to Graph API
                    if ($Method -eq 'GET') {
                        $QueryRequest = Invoke-RestMethod -Headers $HeaderParams -Uri $Uri -Method $Method -ContentType "application/json" -ResponseHeadersVariable 'ResponseMessage'
                    } else {
                        $QueryRequest = Invoke-RestMethod -Headers $HeaderParams -Uri $Uri -Method $Method -ContentType "application/json" -Body $Body -ResponseHeadersVariable 'ResponseMessage'
                    }

                    # Add the initial query result to the result array
                    if ($null -ne $QueryRequest.value) {
                        $QueryResult.AddRange(@($QueryRequest.value))
                    } else {
                        $QueryResult.Add($QueryRequest)
                    }

                    # Run another query to fetch data until there are no pages left
                    if (-not $FirstPageOnly) {
                        while ($QueryRequest.'@odata.nextLink') {
                            # Pagination retry logic
                            $PageRetryCount = 0
                            $PageSuccess = $false
                            
                            while (-not $PageSuccess -and $PageRetryCount -le 3) {
                                try {
                                    $QueryRequest = Invoke-RestMethod -Headers $HeaderParams -Uri $QueryRequest.'@odata.nextLink' -Method $Method -ContentType "application/json" -ResponseHeadersVariable 'ResponseMessage'
                                    $QueryResult.AddRange(@($QueryRequest.value))
                                    $PageSuccess = $true
                                } catch {
                                    $PageStatusCode = $_.Exception.Response.StatusCode.value__
                                    
                                    if ($PageStatusCode -in @(429, 503, 504) -and $PageRetryCount -lt 3) {
                                        $PageRetryCount++
                                        
                                        # Try to extract Retry-After from pagination response
                                        $PageRetryAfter = $null
                                        try {
                                            if ($_.Exception.Response.Headers -and $_.Exception.Response.Headers['Retry-After']) {
                                                $PageRetryAfter = [int]$_.Exception.Response.Headers['Retry-After']
                                            }
                                        } catch { }
                                        
                                        if ($null -ne $PageRetryAfter -and $PageRetryAfter -gt 0) {
                                            $PageDelay = $PageRetryAfter
                                        } else {
                                            $PageDelay = $InitialRetryDelay * [Math]::Pow(2, $PageRetryCount - 1)
                                            $PageDelay = [Math]::Min($PageDelay, 30)
                                        }
                                        
                                        # Add jitter for pagination
                                        $PageJitter = $PageDelay * 0.2 * (Get-Random -Minimum -1.0 -Maximum 1.0)
                                        $PageDelay = [Math]::Max(1, $PageDelay + $PageJitter)
                                        
                                        # Track pagination retry (silent)
                                        Add-EntraOpsRetryStatistic -Name TotalRetries
                                        Add-EntraOpsRetryStatistic -Name ThrottledRequests
                                        
                                        Write-Verbose "Pagination hit rate limit (HTTP $PageStatusCode). Retry $PageRetryCount/3 in $([Math]::Round($PageDelay, 1))s"
                                        Start-Sleep -Seconds $PageDelay
                                    } else {
                                        throw
                                    }
                                }
                            }
                            
                            if (-not $PageSuccess) {
                                throw "Failed to retrieve paginated results after $PageRetryCount retries"
                            }
                        }
                    }

                    switch ($OutputType) {
                        # Case-insensitive conversion for parity with Invoke-MgGraphRequest hashtables
                        # (ConvertFrom-Json -AsHashtable would create case-SENSITIVE keys and break
                        # consumers accessing properties with different casing, e.g. .Id vs "id")
                        HashTable { $QueryResult = @($QueryResult | ForEach-Object { ConvertTo-EntraOpsCaseInsensitiveHashtable -InputObject $_ }) }
                        JSON { $QueryResult = $QueryResult | ConvertTo-Json -Depth 10 }
                        PSObject { $QueryResult = $QueryResult }
                        HttpResponseMessage { $QueryResult = $ResponseMessage }
                    }
                    
                    $Success = $true
                    $QueryResult
                    
                } catch {
                    $StatusCode = $_.Exception.Response.StatusCode.value__
                    $IsNetworkError = $false

                    # Detect network/connection errors that should be retried
                    if ($null -eq $StatusCode -and $_.Exception.Message -match 'An error occurred while sending the request|The operation has timed out|Unable to connect|Connection reset') {
                        $IsNetworkError = $true
                    }

                    # An expired token (401) is retryable when the token came from Get-AzAccessToken
                    # (session cache can be refreshed); a statically provided token (Connect-EntraOps
                    # -MsGraphAccessToken or legacy global variable) cannot be renewed. Static tokens
                    # only ever serve default-tenant requests - cross-tenant tokens always refresh.
                    $RefreshTenantId = $__EntraOpsSession['CurrentGraphTenantId']
                    $RefreshTokenKey = if ([string]::IsNullOrEmpty($RefreshTenantId)) { 'default' } else { $RefreshTenantId }
                    $ProvidedToken = $__EntraOpsSession.MsGraphTokenCache['provided']
                    $HasStaticToken = ($RefreshTokenKey -eq 'default') -and (($null -ne $ProvidedToken -and $ProvidedToken.Expiry -gt [DateTime]::UtcNow) -or (-not [string]::IsNullOrEmpty($Global:MsGraphAccessToken)))
                    $IsTokenRefreshable = ($StatusCode -eq 401 -and -not $HasStaticToken)

                    # Retry logic for rate limiting, transient errors, and network errors
                    if (($StatusCode -in @(429, 503, 504) -or $IsNetworkError -or $IsTokenRefreshable) -and $RetryCount -lt $MaxRetries) {
                        $RetryCount++

                        if ($IsTokenRefreshable) {
                            $__EntraOpsSession.MsGraphTokenCache.Remove($RefreshTokenKey)
                            try {
                                $HeaderParams['Authorization'] = "Bearer $(Get-EntraOpsMsGraphAccessToken)"
                                Write-Verbose "Graph access token expired (HTTP 401), acquired a fresh token for retry"
                            } catch {
                                Write-Verbose "Failed to refresh Graph access token: $($_.Exception.Message)"
                            }
                        }

                        # Try to extract Retry-After header from response
                        $RetryAfter = $null
                        try {
                            if ($_.Exception.Response.Headers -and $_.Exception.Response.Headers['Retry-After']) {
                                $RetryAfter = [int]$_.Exception.Response.Headers['Retry-After']
                                Write-Verbose "Graph API provided Retry-After: ${RetryAfter}s"
                            }
                        } catch {
                            Write-Verbose "Could not extract Retry-After header: $_"
                        }
                        
                        # Use Retry-After if available, otherwise adaptive exponential backoff
                        if ($null -ne $RetryAfter -and $RetryAfter -gt 0) {
                            $RetryDelay = $RetryAfter
                        } else {
                            $RetryDelay = $InitialRetryDelay * [Math]::Pow(2, $RetryCount - 1)
                            $RetryDelay = [Math]::Min($RetryDelay, 60)
                        }
                        
                        # Add jitter (±20%) to prevent thundering herd
                        $Jitter = $RetryDelay * 0.2 * (Get-Random -Minimum -1.0 -Maximum 1.0)
                        $RetryDelay = [Math]::Max(1, $RetryDelay + $Jitter)
                        
                        # Track retry statistics (silent - no warning spam)
                        Add-EntraOpsRetryStatistic -Name TotalRetries
                        if ($IsNetworkError) {
                            Add-EntraOpsRetryStatistic -Name ThrottledRequests
                            Write-Verbose "Network error. Retry $RetryCount/$MaxRetries in $([Math]::Round($RetryDelay, 1))s for: $Uri"
                        } else {
                            Add-EntraOpsRetryStatistic -Name ThrottledRequests
                            Write-Verbose "Graph API throttled (HTTP $StatusCode). Retry $RetryCount/$MaxRetries in $([Math]::Round($RetryDelay, 1))s for: $Uri"
                        }
                        Write-Verbose "Error details: $($_.Exception.Message)"
                        
                        Start-Sleep -Seconds $RetryDelay
                    } else {
                        if ($RetryCount -ge $MaxRetries) {
                            Add-EntraOpsRetryStatistic -Name FailedRequests
                            $__EntraOpsSession.RetryStatistics.FailedRequestDetails.Add([pscustomobject]@{ Timestamp = (Get-Date); Uri = $Uri; StatusCode = $StatusCode; ErrorMessage = "$($_.Exception.Message) (after $MaxRetries retry attempts)" })
                            # Intended non-terminating (followed by return $null below); -ErrorAction Continue keeps
                            # it non-terminating despite the module-wide $ErrorActionPreference = "Stop"
                            Write-Error "Failed to execute $Uri after $MaxRetries retry attempts. Error: $($_.Exception.Message)" -ErrorAction Continue
                        } else {
                            Add-EntraOpsRetryStatistic -Name NonRetryableRequests
                            $__EntraOpsSession.RetryStatistics.NonRetryableRequestDetails.Add([pscustomobject]@{ Timestamp = (Get-Date); Uri = $Uri; StatusCode = $StatusCode; ErrorMessage = $_.Exception.Message })
                            if (($SuppressNotFoundWarning -and $StatusCode -eq 404) -or ($SuppressBadRequestWarning -and $StatusCode -eq 400) -or ($SuppressForbiddenWarning -and $StatusCode -eq 403)) {
                                Write-Verbose "Failed to execute $Uri (expected $StatusCode, warning suppressed). Error: $($_.Exception.Message)"
                            } else {
                                Write-Warning "Failed to execute $Uri (non-retryable error). Error: $($_.Exception.Message)$(Get-EntraOpsMsGraphErrorSummary -ErrorRecord $_)"
                            }
                        }
                        if ($ThrowOnFailure) {
                            $GraphException = [System.InvalidOperationException]::new("Microsoft Graph query '$Uri' failed: $($_.Exception.Message)", $_.Exception)
                            $GraphException.Data['StatusCode'] = $StatusCode
                            $GraphException.Data['Uri'] = $Uri
                            throw $GraphException
                        }
                        return $null
                    }
                }
            }

            if (-not $Success) {
                Add-EntraOpsRetryStatistic -Name FailedRequests
                $__EntraOpsSession.RetryStatistics.FailedRequestDetails.Add([pscustomobject]@{ Timestamp = (Get-Date); Uri = $Uri; StatusCode = $null; ErrorMessage = "Persistent rate limiting" })
                if ($ThrowOnFailure) { throw "Microsoft Graph query '$Uri' failed after $MaxRetries retry attempts due to persistent rate limiting." }
                # Intended non-terminating (followed by return $null); -ErrorAction Continue keeps it
                # non-terminating despite the module-wide $ErrorActionPreference = "Stop"
                Write-Error "Failed to execute $Uri after $MaxRetries retry attempts due to persistent rate limiting." -ErrorAction Continue
                return $null
            }
        } else {
            Write-Verbose -Message "Using Invoke-MgGraphRequest Cmdlet"

            $RetryCount = 0
            $Success = $false
            
            while (-not $Success -and $RetryCount -le $MaxRetries) {
                try {
                    # A retry restarts from the first page, so anything collected by the failed attempt must be
                    # discarded first. Without this, a mid-pagination failure retried at this level re-appends
                    # the pages already collected and silently duplicates results.
                    $QueryResult.Clear()

                    # Run the initial query to Graph API
                    if ($Method -eq 'GET') {
                        $QueryRequest = Invoke-MgGraphRequest -Headers $HeaderParams -Uri $Uri -Method $Method -ContentType "application/json" -OutputType $OutputType
                    } else {
                        $QueryRequest = Invoke-MgGraphRequest -Headers $HeaderParams -Uri $Uri -Method $Method -ContentType "application/json" -Body $Body -OutputType $OutputType
                    }

                    # Add the initial query result to the result array
                    if ($null -ne $QueryRequest.value) {
                        $QueryResult.AddRange(@($QueryRequest.value))
                    } else {
                        $QueryResult.Add($QueryRequest)
                    }

                    # Run another query to fetch data until there are no pages left
                    if (-not $FirstPageOnly) {
                        while ($QueryRequest.'@odata.nextLink') {
                            # Pagination can also hit rate limits, wrap in retry logic
                            $PageRetryCount = 0
                            $PageSuccess = $false
                            
                            while (-not $PageSuccess -and $PageRetryCount -le 3) {
                                try {
                                    $QueryRequest = Invoke-MgGraphRequest -Headers $HeaderParams -Uri $QueryRequest.'@odata.nextLink' -Method $Method -ContentType "application/json" -OutputType $OutputType
                                    $QueryResult.AddRange(@($QueryRequest.value))
                                    $PageSuccess = $true
                                } catch {
                                    $PageStatusCode = $null
                                    if ($_.Exception.Response) {
                                        $PageStatusCode = $_.Exception.Response.StatusCode.value__
                                    } elseif ($_.Exception.Message -match 'TooManyRequests|429') {
                                        $PageStatusCode = 429
                                    }
                                    
                                    if ($PageStatusCode -in @(429, 503, 504) -and $PageRetryCount -lt 3) {
                                        $PageRetryCount++
                                        
                                        # Try to extract Retry-After from pagination response
                                        $PageRetryAfter = $null
                                        try {
                                            if ($_.Exception.Response.Headers -and $_.Exception.Response.Headers['Retry-After']) {
                                                $PageRetryAfter = [int]$_.Exception.Response.Headers['Retry-After']
                                            }
                                        } catch { }
                                        
                                        if ($null -ne $PageRetryAfter -and $PageRetryAfter -gt 0) {
                                            $PageDelay = $PageRetryAfter
                                        } else {
                                            $PageDelay = $InitialRetryDelay * [Math]::Pow(2, $PageRetryCount - 1)
                                            $PageDelay = [Math]::Min($PageDelay, 30)
                                        }
                                        
                                        # Add jitter for pagination
                                        $PageJitter = $PageDelay * 0.2 * (Get-Random -Minimum -1.0 -Maximum 1.0)
                                        $PageDelay = [Math]::Max(1, $PageDelay + $PageJitter)
                                        
                                        # Track pagination retry (silent)
                                        Add-EntraOpsRetryStatistic -Name TotalRetries
                                        Add-EntraOpsRetryStatistic -Name ThrottledRequests
                                        
                                        Write-Verbose "Pagination hit rate limit (HTTP $PageStatusCode). Retry $PageRetryCount/3 in $([Math]::Round($PageDelay, 1))s"
                                        Start-Sleep -Seconds $PageDelay
                                    } else {
                                        throw
                                    }
                                }
                            }
                            
                            if (-not $PageSuccess) {
                                throw "Failed to retrieve paginated results after $PageRetryCount retries"
                            }
                        }
                    }
                    
                    $Success = $true
                    $QueryResult
                    
                } catch {
                    # Extract status code from exception
                    $StatusCode = $null
                    $IsNetworkError = $false
                    
                    if ($_.Exception.Response) {
                        $StatusCode = $_.Exception.Response.StatusCode.value__
                    } elseif ($_.Exception.Message -match 'TooManyRequests|429') {
                        $StatusCode = 429
                    } elseif ($_.Exception.Message -match 'ServiceUnavailable|503') {
                        $StatusCode = 503
                    } elseif ($_.Exception.Message -match 'GatewayTimeout|504') {
                        $StatusCode = 504
                    } elseif ($_.Exception.Message -match 'An error occurred while sending the request|The operation has timed out|Unable to connect|Connection reset') {
                        $IsNetworkError = $true
                    }
                    
                    # Retry logic for rate limiting, transient errors, and network errors
                    if (($StatusCode -in @(429, 503, 504) -or $IsNetworkError) -and $RetryCount -lt $MaxRetries) {
                        $RetryCount++
                        
                        # Try to extract Retry-After header from response
                        $RetryAfter = $null
                        try {
                            if ($_.Exception.Response.Headers -and $_.Exception.Response.Headers['Retry-After']) {
                                $RetryAfter = [int]$_.Exception.Response.Headers['Retry-After']
                                Write-Verbose "Graph API provided Retry-After: ${RetryAfter}s"
                            }
                        } catch {
                            Write-Verbose "Could not extract Retry-After header: $_"
                        }
                        
                        # Use Retry-After if available, otherwise adaptive exponential backoff
                        if ($null -ne $RetryAfter -and $RetryAfter -gt 0) {
                            $RetryDelay = $RetryAfter
                        } else {
                            # Adaptive backoff: 2s, 4s, 8s, 16s, 32s
                            $RetryDelay = $InitialRetryDelay * [Math]::Pow(2, $RetryCount - 1)
                            # Cap at 60 seconds (Graph API rarely needs more)
                            $RetryDelay = [Math]::Min($RetryDelay, 60)
                        }
                        
                        # Add jitter (±20%) to prevent thundering herd
                        $Jitter = $RetryDelay * 0.2 * (Get-Random -Minimum -1.0 -Maximum 1.0)
                        $RetryDelay = [Math]::Max(1, $RetryDelay + $Jitter)
                        
                        # Track retry statistics (silent - no warning spam)
                        Add-EntraOpsRetryStatistic -Name TotalRetries
                        if ($IsNetworkError) {
                            Add-EntraOpsRetryStatistic -Name ThrottledRequests
                            Write-Verbose "Network error. Retry $RetryCount/$MaxRetries in $([Math]::Round($RetryDelay, 1))s for: $Uri"
                        } else {
                            Add-EntraOpsRetryStatistic -Name ThrottledRequests
                            Write-Verbose "Graph API throttled (HTTP $StatusCode). Retry $RetryCount/$MaxRetries in $([Math]::Round($RetryDelay, 1))s for: $Uri"
                        }
                        Write-Verbose "Error details: $($_.Exception.Message)"
                        
                        Start-Sleep -Seconds $RetryDelay
                    } else {
                        # Non-retryable error or max retries exceeded
                        if ($RetryCount -ge $MaxRetries) {
                            Add-EntraOpsRetryStatistic -Name FailedRequests
                            $__EntraOpsSession.RetryStatistics.FailedRequestDetails.Add([pscustomobject]@{ Timestamp = (Get-Date); Uri = $Uri; StatusCode = $StatusCode; ErrorMessage = "$($_.Exception.Message) (after $MaxRetries retry attempts)" })
                            # Intended non-terminating (followed by return $null below); -ErrorAction Continue keeps
                            # it non-terminating despite the module-wide $ErrorActionPreference = "Stop"
                            Write-Error "Failed to execute $Uri after $MaxRetries retry attempts. Error: $($_.Exception.Message)" -ErrorAction Continue
                        } else {
                            Add-EntraOpsRetryStatistic -Name NonRetryableRequests
                            $__EntraOpsSession.RetryStatistics.NonRetryableRequestDetails.Add([pscustomobject]@{ Timestamp = (Get-Date); Uri = $Uri; StatusCode = $StatusCode; ErrorMessage = $_.Exception.Message })
                            if (($SuppressNotFoundWarning -and $StatusCode -eq 404) -or ($SuppressBadRequestWarning -and $StatusCode -eq 400) -or ($SuppressForbiddenWarning -and $StatusCode -eq 403)) {
                                Write-Verbose "Failed to execute $Uri (expected $StatusCode, warning suppressed). Error: $($_.Exception.Message)"
                            } else {
                                Write-Warning "Failed to execute $Uri (non-retryable error). Error: $($_.Exception.Message)$(Get-EntraOpsMsGraphErrorSummary -ErrorRecord $_)"
                            }
                        }
                        if ($ThrowOnFailure) {
                            $GraphException = [System.InvalidOperationException]::new("Microsoft Graph query '$Uri' failed: $($_.Exception.Message)", $_.Exception)
                            $GraphException.Data['StatusCode'] = $StatusCode
                            $GraphException.Data['Uri'] = $Uri
                            throw $GraphException
                        }

                        # Return empty result instead of throwing to allow function to continue
                        return $null
                    }
                }
            }
            
            if (-not $Success) {
                Add-EntraOpsRetryStatistic -Name FailedRequests
                $__EntraOpsSession.RetryStatistics.FailedRequestDetails.Add([pscustomobject]@{ Timestamp = (Get-Date); Uri = $Uri; StatusCode = $null; ErrorMessage = "Persistent rate limiting" })
                if ($ThrowOnFailure) { throw "Microsoft Graph query '$Uri' failed after $MaxRetries retry attempts due to persistent rate limiting." }
                # Intended non-terminating (followed by return $null); -ErrorAction Continue keeps it
                # non-terminating despite the module-wide $ErrorActionPreference = "Stop"
                Write-Error "Failed to execute $Uri after $MaxRetries retry attempts due to persistent rate limiting." -ErrorAction Continue
                return $null
            }
        }
        # Updating cache with TTL metadata
        if ($QueryResult -and !$isBatch -and ($isMethodGet -or $isCacheablePost)) {
            $CurrentTime = [DateTime]::UtcNow
            $ExpiryTime = $CurrentTime.AddSeconds($CacheTTLSeconds)
            
            # Assignment is idempotent when parallel requests populate the same key.
            $__EntraOpsSession.GraphCache[$cacheKey] = $QueryResult
            
            # Update or add cache metadata with TTL
            $CacheMetadataEntry = @{
                Uri          = $Uri
                CachedTime   = $CurrentTime
                ExpiryTime   = $ExpiryTime
                TTLSeconds   = $CacheTTLSeconds
                IsStaticData = $IsStaticData
                ResultCount  = if ($QueryResult -is [System.Collections.ICollection]) { $QueryResult.Count } else { 1 }
            }
            
            $__EntraOpsSession.CacheMetadata[$cacheKey] = $CacheMetadataEntry
            
            Write-Verbose "Cached result for $($cacheKey) (TTL: $($CacheTTLSeconds)s, Count: $($CacheMetadataEntry.ResultCount))"
            
            # Optionally persist static data to disk for cross-session caching
            if ($IsStaticData -and (Test-Path $__EntraOpsSession.PersistentCachePath)) {
                try {
                    $CacheFileName = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($cacheKey)) + ".json"
                    $CacheFilePath = Join-Path $__EntraOpsSession.PersistentCachePath $CacheFileName
                    
                    $PersistentCacheObject = @{
                        Uri        = $Uri
                        CachedTime = $CurrentTime.ToString("o")
                        ExpiryTime = $ExpiryTime.ToString("o")
                        Data       = $QueryResult
                    }
                    
                    $PersistentCacheObject | ConvertTo-Json -Depth 10 -Compress | Out-File -FilePath $CacheFilePath -Force
                    Write-Verbose "Persisted static data cache to: $CacheFileName"
                } catch {
                    Write-Verbose "Failed to persist cache to disk: $_"
                }
            }
        }
    } else {
        $QueryResult
    }
}