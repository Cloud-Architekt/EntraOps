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

.PARAMETER MaxRetries
    Maximum number of retry attempts for rate limiting (429) or transient errors (503, 504). Default is 5.

.PARAMETER InitialRetryDelay
    Initial delay in seconds before first retry. Default is 2 seconds. Uses adaptive backoff with Retry-After header.

.EXAMPLE
    Get list of all transitive role assignments for a principal in Microsoft Entra ID by principalId and using ConsistencyLevel.
    Invoke-EntraOpsMsGraphQuery -Uri "/beta/roleManagement/directory/transitiveRoleAssignments?$count=true&`$filter=principalId eq '$Principal'" -ConsistencyLevel "eventual"

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
        [int]$MaxRetries = 5,

        [Parameter(Mandatory = $false)]
        [int]$InitialRetryDelay = 2
    )

    $HeaderParams = @{}

    # Initialize retry statistics tracking in session if not present
    if (-not $__EntraOpsSession.ContainsKey('RetryStatistics')) {
        $__EntraOpsSession.RetryStatistics = @{
            TotalRetries      = 0
            ThrottledRequests = 0
            FailedRequests    = 0
        }
    }

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
    
    if ($isCacheablePost -and $null -ne $Body) {
        # Create hash of body to ensure unique cache key for POST requests
        $BodyBytes = [System.Text.Encoding]::UTF8.GetBytes($Body)
        $BodyHash = [BitConverter]::ToString(([System.Security.Cryptography.SHA256]::Create()).ComputeHash($BodyBytes)).Replace("-", "")
        $cacheKey = "$Uri#$BodyHash"
    } else {
        $cacheKey = $Uri
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
            # Legacy cache entry without metadata, use it but add metadata
            Write-Verbose ("Using legacy graph cache (no TTL): $($cacheKey)")
            $CacheIsValid = $true
            $QueryResult = $__EntraOpsSession.GraphCache[$cacheKey]
        }
    }

    if (!$QueryResult) {
        # Create empty arrays to store the results
        $QueryRequest = @()
        $QueryResult = New-Object System.Collections.Generic.List[Object]

        if ($UseAzPwshOnly -eq $True -and $null -ne $MsGraphAccessToken) {
            Write-Verbose -Message "Using Invoke-RestMethod Cmdlet"
            $AccessToken = $MsGraphAccessToken
            $HeaderParams.Add('Authorization', "Bearer $($AccessToken)")

            $RetryCount = 0
            $Success = $false
            
            while (-not $Success -and $RetryCount -le $MaxRetries) {
                try {
                    # Run the initial query to Graph API
                    if ($Method -eq 'GET') {
                        $QueryRequest = Invoke-RestMethod -Headers $HeaderParams -Uri $Uri -Method $Method -ContentType "application/json" -ResponseHeadersVariable $ResponseMessage
                    } else {
                        $QueryRequest = Invoke-RestMethod -Headers $HeaderParams -Uri $Uri -Method $Method -ContentType "application/json" -Body $Body -ResponseHeadersVariable $ResponseMessage
                    }

                    # Add the initial query result to the result array
                    if ($QueryRequest.value) {
                        $QueryResult.AddRange($QueryRequest.value)
                    } else {
                        $QueryResult.Add($QueryRequest)
                    }

                    # Run another query to fetch data until there are no pages left
                    if ($Uri -notlike "*`$top*") {
                        while ($QueryRequest.'@odata.nextLink') {
                            # Pagination retry logic
                            $PageRetryCount = 0
                            $PageSuccess = $false
                            
                            while (-not $PageSuccess -and $PageRetryCount -le 3) {
                                try {
                                    $QueryRequest = Invoke-RestMethod -Headers $HeaderParams -Uri $QueryRequest.'@odata.nextLink' -Method $Method -ContentType "application/json" -ResponseHeadersVariable $ResponseMessage
                                    $QueryResult.AddRange($QueryRequest.value)
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
                                        $__EntraOpsSession.RetryStatistics.TotalRetries++
                                        $__EntraOpsSession.RetryStatistics.ThrottledRequests++
                                        
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
                        HashTable { $QueryResult = $QueryResult | ConvertTo-Json -Depth 10 | ConvertFrom-Json -Depth 10 -AsHashtable }
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
                            $RetryDelay = $InitialRetryDelay * [Math]::Pow(2, $RetryCount - 1)
                            $RetryDelay = [Math]::Min($RetryDelay, 60)
                        }
                        
                        # Add jitter (±20%) to prevent thundering herd
                        $Jitter = $RetryDelay * 0.2 * (Get-Random -Minimum -1.0 -Maximum 1.0)
                        $RetryDelay = [Math]::Max(1, $RetryDelay + $Jitter)
                        
                        # Track retry statistics (silent - no warning spam)
                        $__EntraOpsSession.RetryStatistics.TotalRetries++
                        if ($IsNetworkError) {
                            $__EntraOpsSession.RetryStatistics.ThrottledRequests++
                            Write-Verbose "Network error. Retry $RetryCount/$MaxRetries in $([Math]::Round($RetryDelay, 1))s for: $Uri"
                        } else {
                            $__EntraOpsSession.RetryStatistics.ThrottledRequests++
                            Write-Verbose "Graph API throttled (HTTP $StatusCode). Retry $RetryCount/$MaxRetries in $([Math]::Round($RetryDelay, 1))s for: $Uri"
                        }
                        Write-Verbose "Error details: $($_.Exception.Message)"
                        
                        Start-Sleep -Seconds $RetryDelay
                    } else {
                        if ($RetryCount -ge $MaxRetries) {
                            $__EntraOpsSession.RetryStatistics.FailedRequests++
                            Write-Error "Failed to execute $Uri after $MaxRetries retry attempts. Error: $($_.Exception.Message)"
                        } else {
                            $__EntraOpsSession.RetryStatistics.FailedRequests++
                            Write-Warning "Failed to execute $Uri (non-retryable error). Error: $($_.Exception.Message)"
                        }
                        return $null
                    }
                }
            }
            
            if (-not $Success) {
                $__EntraOpsSession.RetryStatistics.FailedRequests++
                Write-Error "Failed to execute $Uri after $MaxRetries retry attempts due to persistent rate limiting."
                return $null
            }
        } else {
            Write-Verbose -Message "Using Invoke-MgGraphRequest Cmdlet"

            $RetryCount = 0
            $Success = $false
            
            while (-not $Success -and $RetryCount -le $MaxRetries) {
                try {
                    # Run the initial query to Graph API
                    if ($Method -eq 'GET') {
                        $QueryRequest = Invoke-MgGraphRequest -Headers $HeaderParams -Uri $Uri -Method $Method -ContentType "application/json" -OutputType $OutputType
                    } else {
                        $QueryRequest = Invoke-MgGraphRequest -Headers $HeaderParams -Uri $Uri -Method $Method -ContentType "application/json" -Body $Body -OutputType $OutputType
                    }

                    # Add the initial query result to the result array
                    if ($QueryRequest.value) {
                        $QueryResult.AddRange($QueryRequest.value)
                    } else {
                        $QueryResult.Add($QueryRequest)
                    }

                    # Run another query to fetch data until there are no pages left
                    if ($Uri -notlike "*`$top*") {
                        while ($QueryRequest.'@odata.nextLink') {
                            # Pagination can also hit rate limits, wrap in retry logic
                            $PageRetryCount = 0
                            $PageSuccess = $false
                            
                            while (-not $PageSuccess -and $PageRetryCount -le 3) {
                                try {
                                    $QueryRequest = Invoke-MgGraphRequest -Headers $HeaderParams -Uri $QueryRequest.'@odata.nextLink' -Method $Method -ContentType "application/json" -OutputType $OutputType
                                    $QueryResult.AddRange($QueryRequest.value)
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
                                        $__EntraOpsSession.RetryStatistics.TotalRetries++
                                        $__EntraOpsSession.RetryStatistics.ThrottledRequests++
                                        
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
                        $__EntraOpsSession.RetryStatistics.TotalRetries++
                        if ($IsNetworkError) {
                            $__EntraOpsSession.RetryStatistics.ThrottledRequests++
                            Write-Verbose "Network error. Retry $RetryCount/$MaxRetries in $([Math]::Round($RetryDelay, 1))s for: $Uri"
                        } else {
                            $__EntraOpsSession.RetryStatistics.ThrottledRequests++
                            Write-Verbose "Graph API throttled (HTTP $StatusCode). Retry $RetryCount/$MaxRetries in $([Math]::Round($RetryDelay, 1))s for: $Uri"
                        }
                        Write-Verbose "Error details: $($_.Exception.Message)"
                        
                        Start-Sleep -Seconds $RetryDelay
                    } else {
                        # Non-retryable error or max retries exceeded
                        if ($RetryCount -ge $MaxRetries) {
                            $__EntraOpsSession.RetryStatistics.FailedRequests++
                            Write-Error "Failed to execute $Uri after $MaxRetries retry attempts. Error: $($_.Exception.Message)"
                        } else {
                            $__EntraOpsSession.RetryStatistics.FailedRequests++
                            Write-Warning "Failed to execute $Uri (non-retryable error). Error: $($_.Exception.Message)"
                        }
                        # Return empty result instead of throwing to allow function to continue
                        return $null
                    }
                }
            }
            
            if (-not $Success) {
                $__EntraOpsSession.RetryStatistics.FailedRequests++
                Write-Error "Failed to execute $Uri after $MaxRetries retry attempts due to persistent rate limiting."
                return $null
            }
        }
        # Updating cache with TTL metadata
        if ($QueryResult -and !$isBatch -and ($isMethodGet -or $isCacheablePost)) {
            $CurrentTime = [DateTime]::UtcNow
            $ExpiryTime = $CurrentTime.AddSeconds($CacheTTLSeconds)
            
            # Update cache
            if ($isInCache) {
                $__EntraOpsSession.GraphCache[$cacheKey] = $QueryResult
            } else {
                $__EntraOpsSession.GraphCache.Add($cacheKey, $QueryResult)
            }
            
            # Update or add cache metadata with TTL
            $CacheMetadataEntry = @{
                Uri          = $Uri
                CachedTime   = $CurrentTime
                ExpiryTime   = $ExpiryTime
                TTLSeconds   = $CacheTTLSeconds
                IsStaticData = $IsStaticData
                ResultCount  = if ($QueryResult -is [System.Collections.ICollection]) { $QueryResult.Count } else { 1 }
            }
            
            if ($__EntraOpsSession.CacheMetadata.ContainsKey($cacheKey)) {
                $__EntraOpsSession.CacheMetadata[$cacheKey] = $CacheMetadataEntry
            } else {
                $__EntraOpsSession.CacheMetadata.Add($cacheKey, $CacheMetadataEntry)
            }
            
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