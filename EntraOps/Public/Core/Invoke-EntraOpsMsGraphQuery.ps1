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

.EXAMPLE
    Get list of all transitive role assignments for a principal in Microsoft Entra ID by principalId and using ConsistencyLevel.
    Invoke-EntraOpsMsGraphQuery -Uri "/beta/roleManagement/directory/transitiveRoleAssignments?$count=true&`$filter=principalId eq '$Principal'" -ConsistencyLevel "eventual"

.EXAMPLE
    Get list of all role definitions in Microsoft Entra ID.
    Invoke-EntraOpsMsGraphQuery -Uri "/beta/roleManagement/directory/roleDefinitions"
#>

function Invoke-EntraOpsMsGraphQuery {

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
        [switch]$DisableCache
    )

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
    try {
        $isInCache = $__EntraOpsSession.GraphCache.ContainsKey($Uri)
    } catch {
        Write-Verbose "Cache is empty"
    }

    $isBatch = $Uri.EndsWith('$batch')
    $cacheKey = $Uri
    $isMethodGet = $Method -eq 'GET'
    
    # Determine if this is static reference data (longer TTL)
    $IsStaticData = $Uri -match "roleDefinitions|directoryRoleTemplates|permissionGrants|appRoles|publishedPermissionScopes"
    $CacheTTLSeconds = if ($IsStaticData) { $__EntraOpsSession.StaticDataCacheTTL } else { $__EntraOpsSession.DefaultCacheTTL }

    # Check if Cache can be used and data is available in cache
    # Enhanced logic with TTL support for improved cache management
    $CacheIsValid = $false
    if (!$DisableCache -and !$isBatch -and $isInCache -and $isMethodGet) {
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
                        $QueryRequest = Invoke-RestMethod -Headers $HeaderParams -Uri $QueryRequest.'@odata.nextLink' -Method $Method -ContentType "application/json" -ResponseHeadersVariable $ResponseMessage
                        $QueryResult.AddRange($QueryRequest.value)
                    }
                }

                switch ($OutputType) {
                    HashTable { $QueryResult = $QueryResult | ConvertTo-Json -Depth 10 | ConvertFrom-Json -Depth 10 -AsHashtable }
                    JSON { $QueryResult = $QueryResult | ConvertTo-Json -Depth 10 }
                    PSObject { $QueryResult = $QueryResult }
                    HttpResponseMessage { $QueryResult = $ResponseMessage }
                }
                $QueryResult
            } catch {
                Write-Warning "Failed to execute $($URI). Error: $($_.Exception.Message)"
            }
        } else {
            Write-Verbose -Message "Using Invoke-MgGraphRequest Cmdlet"

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
                        $QueryRequest = Invoke-MgGraphRequest -Headers $HeaderParams -Uri $QueryRequest.'@odata.nextLink' -Method $Method -ContentType "application/json" -OutputType $OutputType
                        $QueryResult.AddRange($QueryRequest.value)
                    }
                }
                $QueryResult
            } catch {
                Write-Warning "Failed to execute $($URI). Error: $($_.Exception.Message)"
            }
        }
        # Updating cache with TTL metadata
        if ($QueryResult -and !$isBatch -and $isMethodGet) {
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
                Uri = $Uri
                CachedTime = $CurrentTime
                ExpiryTime = $ExpiryTime
                TTLSeconds = $CacheTTLSeconds
                IsStaticData = $IsStaticData
                ResultCount = if ($QueryResult -is [System.Collections.ICollection]) { $QueryResult.Count } else { 1 }
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
                        Uri = $Uri
                        CachedTime = $CurrentTime.ToString("o")
                        ExpiryTime = $ExpiryTime.ToString("o")
                        Data = $QueryResult
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