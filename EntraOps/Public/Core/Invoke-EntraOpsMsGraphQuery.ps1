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
    }
    elseif ($Uri -like "https://graph.microsoft.com/*") {
    }
    else {
        throw "Invalid Graph URI: $($Uri)!"
    }

    # Add ConsistencyLevel if provided in parameter
    if ($null -ne $ConsistencyLevel) {
        $HeaderParams.Add('ConsistencyLevel', "$ConsistencyLevel")
    }

    # Check cache property for the Uri
    try {
        $isInCache = $__EntraOpsSession.GraphCache.ContainsKey($Uri)
    }
    catch {
        Write-Verbose "Cache is empty"
    }

    $isBatch = $Uri.EndsWith('$batch')
    $cacheKey = $Uri
    $isMethodGet = $Method -eq 'GET'

    # Check if Cache can be used and data is available in cache
    # Logic of caching Graph requests by Merill (Maester Framework)
    if (!$DisableCache -and !$isBatch -and $isInCache -and $isMethodGet) {
        # Don't read from cache for batch requests.
        Write-Verbose ("Using graph cache: $($cacheKey)")
        $QueryResult = $__EntraOpsSession.GraphCache[$cacheKey]
    }

    if (!$QueryResult) {
        # Create empty arrays to store the results
        $QueryRequest = @()
        $QueryResult = @()

        if ($UseAzPwshOnly -eq $True -and $null -ne $MsGraphAccessToken) {
            Write-Verbose -Message "Using Invoke-RestMethod Cmdlet"
            $AccessToken = $MsGraphAccessToken
            $HeaderParams.Add('Authorization', "Bearer $($AccessToken)")

            try {
                # Run the initial query to Graph API
                if ($Method -eq 'GET') {
                    $QueryRequest = Invoke-RestMethod -Headers $HeaderParams -Uri $Uri -Method $Method -ContentType "application/json" -ResponseHeadersVariable $ResponseMessage
                }
                else {
                    $QueryRequest = Invoke-RestMethod -Headers $HeaderParams -Uri $Uri -Method $Method -ContentType "application/json" -Body $Body -ResponseHeadersVariable $ResponseMessage
                }

                # Add the initial query result to the result array
                if ($QueryRequest.value) {
                    $QueryResult += $QueryRequest.value
                }
                else {
                    $QueryResult += $QueryRequest
                }

                # Run another query to fetch data until there are no pages left
                if ($Uri -notlike "*`$top*") {
                    while ($QueryRequest.'@odata.nextLink') {
                        $QueryRequest = Invoke-RestMethod -Headers $HeaderParams -Uri $QueryRequest.'@odata.nextLink' -Method $Method -ContentType "application/json" -ResponseHeadersVariable $ResponseMessage
                        $QueryResult += $QueryRequest.value
                    }
                }

                switch ($OutputType) {
                    HashTable { $QueryResult = $QueryResult | ConvertTo-Json -Depth 10 | ConvertFrom-Json -Depth 10 -AsHashtable }
                    JSON { $QueryResult = $QueryResult | ConvertTo-Json -Depth 10 }
                    PSObject { $QueryResult = $QueryResult }
                    HttpResponseMessage { $QueryResult = $ResponseMessage }
                }
                $QueryResult
            }
            catch {
                Write-Warning "Failed to execute $($URI). Error: $($_.Exception.Message)"
            }
        }
        else {
            Write-Verbose -Message "Using Invoke-MgGraphRequest Cmdlet"

            try {
                # Run the initial query to Graph API
                if ($Method -eq 'GET') {
                    $QueryRequest = Invoke-MgGraphRequest -Headers $HeaderParams -Uri $Uri -Method $Method -ContentType "application/json" -OutputType $OutputType
                }
                else {
                    $QueryRequest = Invoke-MgGraphRequest -Headers $HeaderParams -Uri $Uri -Method $Method -ContentType "application/json" -Body $Body -OutputType $OutputType
                }

                # Add the initial query result to the result array
                if ($QueryRequest.value) {
                    $QueryResult += $QueryRequest.value
                }
                else {
                    $QueryResult += $QueryRequest
                }

                # Run another query to fetch data until there are no pages left
                if ($Uri -notlike "*`$top*") {
                    while ($QueryRequest.'@odata.nextLink') {
                        $QueryRequest = Invoke-MgGraphRequest -Headers $HeaderParams -Uri $QueryRequest.'@odata.nextLink' -Method $Method -ContentType "application/json" -OutputType $OutputType
                        $QueryResult += $QueryRequest.value
                    }
                }
                $QueryResult
            }
            catch {
                Write-Warning "Failed to execute $($URI). Error: $($_.Exception.Message)"
            }
        }
        # Updating cache
        if ($QueryResult -and !$isBatch -and $isMethodGet) {
            # Update cache
            if ($isInCache) {
                $__EntraOpsSession.GraphCache[$cacheKey] = $QueryResult
            }
            else {
                $__EntraOpsSession.GraphCache.Add($cacheKey, $QueryResult)
            }
        }
    }
    else {
        $QueryResult
    }
}