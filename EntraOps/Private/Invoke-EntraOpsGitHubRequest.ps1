function Invoke-EntraOpsGitHubRequest {
    <#
    .SYNOPSIS
        Sends a GET request to GitHub with authentication and retries for rate limits and transient errors.

    .DESCRIPTION
        Unauthenticated requests to api.github.com share a limit of 60 requests per hour per IP address,
        which hosted CI runners exhaust quickly. The request is authenticated with -Token, otherwise with the
        environment variable GITHUB_TOKEN or GH_TOKEN (ENTRAOPS_PAT is meant for the Insiders repository and is
        only sent when the caller passes it as -Token). The token is only sent to GitHub hosts. A token that GitHub rejects (401) is not needed for public repositories: the request is
        repeated once without it. The same applies to 403 and 404 for files and archives of the public
        Cloud-Architekt/EntraOps repository (raw.githubusercontent.com, codeload.github.com, github.com): a token
        without access to the organization, for example GITHUB_TOKEN of a workflow in another organization, gets
        these answers. Requests to the private Insiders repository are never repeated without the token.

        Rate limits (403/429 with Retry-After or x-ratelimit-remaining 0), server errors (5xx) and network
        errors are retried up to -MaxRetries times. The wait follows Retry-After or x-ratelimit-reset; when it
        is longer than -MaxRetryWaitInSeconds, the request fails at once with the time the limit resets.

    .PARAMETER Uri
        The GitHub URL (api.github.com, raw.githubusercontent.com, codeload.github.com or github.com).

    .PARAMETER OutFile
        Saves the response body to this file instead of returning it.

    .PARAMETER Token
        The GitHub token. Without it, GITHUB_TOKEN or GH_TOKEN of the environment is used.

    .PARAMETER Headers
        Additional request headers.

    .PARAMETER MaxRetries
        Number of retries after the first attempt. Default is 3.

    .PARAMETER MaxRetryWaitInSeconds
        Longest wait for one retry. Default is 120 seconds.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Uri,

        [Parameter(Mandatory = $false)]
        [string]$OutFile,

        [Parameter(Mandatory = $false)]
        [string]$Token,

        [Parameter(Mandatory = $false)]
        [hashtable]$Headers = @{},

        [Parameter(Mandatory = $false)]
        [ValidateRange(0, 10)]
        [int]$MaxRetries = 3,

        [Parameter(Mandatory = $false)]
        [ValidateRange(0, 3600)]
        [int]$MaxRetryWaitInSeconds = 120
    )

    $GitHubHosts = @('api.github.com', 'raw.githubusercontent.com', 'codeload.github.com', 'github.com', 'objects.githubusercontent.com')
    $RequestHost = ([uri]$Uri).Host
    if ([string]::IsNullOrWhiteSpace($Token)) {
        $Token = @($env:GITHUB_TOKEN, $env:GH_TOKEN) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -First 1
    }
    $UseToken = -not [string]::IsNullOrWhiteSpace($Token) -and $RequestHost -in $GitHubHosts
    # Files and archives of the public repository need no token (the trailing slash excludes EntraOps-Insiders).
    $IsPublicRepositoryContent = $RequestHost -in @('raw.githubusercontent.com', 'codeload.github.com', 'github.com') -and ([uri]$Uri).AbsolutePath -match '^/Cloud-Architekt/EntraOps/'

    # Reads a response header from HttpResponseHeaders (Invoke-RestMethod) or a dictionary.
    $GetHeader = {
        param($Response, [string]$Name)
        $ResponseHeaders = $Response.Headers
        if ($null -eq $ResponseHeaders) { return $null }
        if ($ResponseHeaders -is [System.Net.Http.Headers.HttpHeaders]) {
            $Values = $null
            if ($ResponseHeaders.TryGetValues($Name, [ref]$Values)) { return @($Values)[0] }
            return $null
        }
        if ($ResponseHeaders -is [System.Collections.IDictionary]) {
            foreach ($Key in $ResponseHeaders.Keys) {
                if ("$Key" -eq $Name) { return @($ResponseHeaders[$Key])[0] }
            }
        }
        return $null
    }

    $Attempt = 0
    while ($true) {
        $RequestHeaders = @{ 'User-Agent' = 'EntraOps'; 'Accept' = 'application/vnd.github+json' }
        foreach ($Key in $Headers.Keys) { $RequestHeaders[$Key] = $Headers[$Key] }
        if ($UseToken) { $RequestHeaders['Authorization'] = "Bearer $Token" }
        $RequestParameters = @{ Method = 'GET'; Uri = $Uri; Headers = $RequestHeaders; ErrorAction = 'Stop' }
        if ($OutFile) { $RequestParameters.OutFile = $OutFile }

        try {
            return Invoke-RestMethod @RequestParameters
        } catch {
            $ErrorRecord = $_
            $Response = $ErrorRecord.Exception.Response
            $StatusCode = if ($null -ne $Response -and $null -ne $Response.StatusCode) { [int]$Response.StatusCode } else { $null }

            $RateLimitRemaining = & $GetHeader $Response 'x-ratelimit-remaining'
            $RetryAfter = Get-EntraOpsRetryAfterSeconds -Response $Response
            $IsRateLimited = $StatusCode -eq 429 -or ($StatusCode -eq 403 -and ("$RateLimitRemaining" -eq '0' -or $null -ne $RetryAfter -or "$($ErrorRecord.ErrorDetails.Message)" -match 'rate limit'))

            if ($UseToken -and ($StatusCode -eq 401 -or ($IsPublicRepositoryContent -and ($StatusCode -eq 404 -or ($StatusCode -eq 403 -and -not $IsRateLimited))))) {
                # 404 is also the answer for a ref that doesn't exist (for example a release tag that is probed), so only 401 warns.
                $Message = "GitHub $(if ($StatusCode -eq 401) { 'rejected the token' } else { "answered $StatusCode with the token" }) for $Uri. Repeating the request without it."
                if ($StatusCode -eq 401) { Write-Warning $Message } else { Write-Verbose $Message }
                $UseToken = $false
                continue
            }

            $IsTransient = $null -eq $StatusCode -or $StatusCode -ge 500
            if (-not ($IsRateLimited -or $IsTransient) -or $Attempt -ge $MaxRetries) {
                if ($IsRateLimited) {
                    throw "GitHub rate limit exceeded for $Uri$(if (-not $UseToken) { ' (unauthenticated requests share 60 requests per hour per IP address; set GITHUB_TOKEN or GH_TOKEN)' }): $($ErrorRecord.Exception.Message)"
                }
                throw $ErrorRecord
            }

            $WaitInSeconds = if ($null -ne $RetryAfter) {
                $RetryAfter
            } elseif ($IsRateLimited -and "$RateLimitRemaining" -eq '0' -and "$(& $GetHeader $Response 'x-ratelimit-reset')" -match '^\d+$') {
                [int][Math]::Max(1, [DateTimeOffset]::FromUnixTimeSeconds([long](& $GetHeader $Response 'x-ratelimit-reset')).Subtract([DateTimeOffset]::UtcNow).TotalSeconds + 1)
            } else {
                [int][Math]::Pow(2, $Attempt + 1)
            }
            if ($WaitInSeconds -gt $MaxRetryWaitInSeconds) {
                $ResetAt = [DateTimeOffset]::UtcNow.AddSeconds($WaitInSeconds).ToString('u')
                throw "GitHub rate limit exceeded for $Uri until $ResetAt (longer than the retry wait of $MaxRetryWaitInSeconds seconds)$(if (-not $UseToken) { '. Unauthenticated requests share 60 requests per hour per IP address; set GITHUB_TOKEN or GH_TOKEN' })."
            }

            $Attempt++
            $Reason = if ($IsRateLimited) { 'rate limited' } elseif ($null -eq $StatusCode) { 'network error' } else { "HTTP $StatusCode" }
            Write-Verbose "GitHub request to $Uri failed ($Reason). Retry $Attempt of $MaxRetries in $WaitInSeconds second(s)."
            Start-Sleep -Seconds $WaitInSeconds
        }
    }
}
