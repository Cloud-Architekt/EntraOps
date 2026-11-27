#Requires -Modules Pester

BeforeAll {
    $script:TestRepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
    . "$script:TestRepositoryRoot/EntraOps/Private/Get-EntraOpsRetryAfterSeconds.ps1"
    . "$script:TestRepositoryRoot/EntraOps/Private/Invoke-EntraOpsGitHubRequest.ps1"

    # The exception Invoke-RestMethod throws for an unsuccessful status code.
    function New-GitHubHttpError {
        param([int]$StatusCode, [hashtable]$Headers = @{}, [Nullable[int]]$RetryAfterSeconds)
        $Response = [System.Net.Http.HttpResponseMessage]::new([System.Net.HttpStatusCode]$StatusCode)
        foreach ($Key in $Headers.Keys) { $null = $Response.Headers.TryAddWithoutValidation($Key, [string]$Headers[$Key]) }
        if ($null -ne $RetryAfterSeconds) { $Response.Headers.RetryAfter = [System.Net.Http.Headers.RetryConditionHeaderValue]::new([timespan]::FromSeconds($RetryAfterSeconds)) }
        [Microsoft.PowerShell.Commands.HttpResponseException]::new("Response status code does not indicate success: $StatusCode.", $Response)
    }
}

Describe 'Invoke-EntraOpsGitHubRequest' {
    BeforeEach {
        $script:SavedTokens = @{ GITHUB_TOKEN = $env:GITHUB_TOKEN; GH_TOKEN = $env:GH_TOKEN; ENTRAOPS_PAT = $env:ENTRAOPS_PAT }
        $env:GITHUB_TOKEN = $null; $env:GH_TOKEN = $null; $env:ENTRAOPS_PAT = $null
        $script:Requests = [System.Collections.Generic.List[hashtable]]::new()
        Mock Start-Sleep {}
    }

    AfterEach {
        foreach ($Name in $script:SavedTokens.Keys) { Set-Item -Path "Env:$Name" -Value $script:SavedTokens[$Name] -ErrorAction SilentlyContinue }
    }

    It 'authenticates GitHub requests with GITHUB_TOKEN of the environment' {
        $env:GITHUB_TOKEN = 'ghs_test'
        Mock Invoke-RestMethod { $script:Requests.Add($Headers); 'ok' }

        Invoke-EntraOpsGitHubRequest -Uri 'https://api.github.com/repos/Cloud-Architekt/AzurePrivilegedIAM/contents/x' | Should -Be 'ok'

        $script:Requests[0]['Authorization'] | Should -Be 'Bearer ghs_test'
        $script:Requests[0]['User-Agent'] | Should -Be 'EntraOps'
    }

    It 'does not send ENTRAOPS_PAT, which is meant for the Insiders repository' {
        $env:ENTRAOPS_PAT = 'insiders-pat'
        Mock Invoke-RestMethod { $script:Requests.Add($Headers) }

        Invoke-EntraOpsGitHubRequest -Uri 'https://api.github.com/x'

        $script:Requests[0].ContainsKey('Authorization') | Should -BeFalse
    }

    It 'never sends the token to another host' {
        $env:GITHUB_TOKEN = 'ghs_test'
        Mock Invoke-RestMethod { $script:Requests.Add($Headers) }

        Invoke-EntraOpsGitHubRequest -Uri 'https://example.test/file.json'

        $script:Requests[0].ContainsKey('Authorization') | Should -BeFalse
    }

    It 'waits until the rate limit resets and retries' {
        $script:Calls = 0
        $Reset = [DateTimeOffset]::UtcNow.AddSeconds(5).ToUnixTimeSeconds()
        Mock Invoke-RestMethod {
            $script:Calls++
            if ($script:Calls -eq 1) { throw (New-GitHubHttpError -StatusCode 403 -Headers @{ 'x-ratelimit-remaining' = '0'; 'x-ratelimit-reset' = "$Reset" }) }
            'ok'
        }

        Invoke-EntraOpsGitHubRequest -Uri 'https://api.github.com/x' | Should -Be 'ok'

        $script:Calls | Should -Be 2
        Should -Invoke Start-Sleep -Times 1 -Exactly -ParameterFilter { $Seconds -ge 4 -and $Seconds -le 7 }
    }

    It 'follows Retry-After of a secondary rate limit' {
        $script:Calls = 0
        Mock Invoke-RestMethod {
            $script:Calls++
            if ($script:Calls -eq 1) { throw (New-GitHubHttpError -StatusCode 429 -RetryAfterSeconds 3) }
            'ok'
        }

        Invoke-EntraOpsGitHubRequest -Uri 'https://api.github.com/x' | Should -Be 'ok'

        Should -Invoke Start-Sleep -Times 1 -Exactly -ParameterFilter { $Seconds -eq 3 }
    }

    It 'fails at once when the rate limit resets later than the retry wait and names the token variables' {
        $Reset = [DateTimeOffset]::UtcNow.AddMinutes(40).ToUnixTimeSeconds()
        Mock Invoke-RestMethod { throw (New-GitHubHttpError -StatusCode 403 -Headers @{ 'x-ratelimit-remaining' = '0'; 'x-ratelimit-reset' = "$Reset" }) }

        { Invoke-EntraOpsGitHubRequest -Uri 'https://api.github.com/x' } | Should -Throw '*rate limit exceeded*until*set GITHUB_TOKEN or GH_TOKEN*'

        Should -Invoke Invoke-RestMethod -Times 1 -Exactly
        Should -Invoke Start-Sleep -Times 0
    }

    It 'retries server errors with backoff and gives up after MaxRetries' {
        Mock Invoke-RestMethod { throw (New-GitHubHttpError -StatusCode 502) }

        { Invoke-EntraOpsGitHubRequest -Uri 'https://api.github.com/x' -MaxRetries 2 } | Should -Throw '*502*'

        Should -Invoke Invoke-RestMethod -Times 3 -Exactly
        Should -Invoke Start-Sleep -Times 2 -Exactly
    }

    It 'does not retry a request that is not found' {
        Mock Invoke-RestMethod { throw (New-GitHubHttpError -StatusCode 404) }

        { Invoke-EntraOpsGitHubRequest -Uri 'https://api.github.com/x' } | Should -Throw '*404*'

        Should -Invoke Invoke-RestMethod -Times 1 -Exactly
    }

    It 'repeats the request without a token that GitHub rejects' {
        Mock Invoke-RestMethod {
            $script:Requests.Add($Headers)
            if ($Headers.ContainsKey('Authorization')) { throw (New-GitHubHttpError -StatusCode 401) }
            'ok'
        }

        Invoke-EntraOpsGitHubRequest -Uri 'https://api.github.com/x' -Token 'expired' -WarningAction SilentlyContinue | Should -Be 'ok'

        $script:Requests.Count | Should -Be 2
        $script:Requests[1].ContainsKey('Authorization') | Should -BeFalse
    }

    It 'repeats a request for the public repository without a token that has no access (<StatusCode>, <Uri>)' -ForEach @(
        @{ StatusCode = 404; Uri = 'https://raw.githubusercontent.com/Cloud-Architekt/EntraOps/main/EntraOps/EntraOps.psd1' }
        @{ StatusCode = 403; Uri = 'https://raw.githubusercontent.com/Cloud-Architekt/EntraOps/v1.2.0/EntraOps/EntraOps.psd1' }
        @{ StatusCode = 404; Uri = 'https://codeload.github.com/Cloud-Architekt/EntraOps/zip/main' }
        @{ StatusCode = 404; Uri = 'https://github.com/Cloud-Architekt/EntraOps/archive/main.zip' }
    ) {
        $env:GITHUB_TOKEN = 'ghs_other_org'
        $script:Status = $StatusCode
        Mock Invoke-RestMethod {
            $script:Requests.Add($Headers)
            if ($Headers.ContainsKey('Authorization')) { throw (New-GitHubHttpError -StatusCode $script:Status) }
            'ok'
        }

        Invoke-EntraOpsGitHubRequest -Uri $Uri -WarningVariable Warnings | Should -Be 'ok'

        $script:Requests.Count | Should -Be 2
        $script:Requests[1].ContainsKey('Authorization') | Should -BeFalse
        # A 404 is also the answer for a tag that doesn't exist: no warning for it.
        $Warnings | Should -BeNullOrEmpty
    }

    It 'never repeats a request for <Case> without the token' -ForEach @(
        @{ Case = 'the private Insiders repository'; Uri = 'https://raw.githubusercontent.com/Cloud-Architekt/EntraOps-Insiders/main/EntraOps/EntraOps.psd1'; StatusCode = 404 }
        @{ Case = 'the Insiders archive through the API'; Uri = 'https://api.github.com/repos/Cloud-Architekt/EntraOps-Insiders/zipball/main'; StatusCode = 404 }
        @{ Case = 'the GitHub API'; Uri = 'https://api.github.com/repos/Cloud-Architekt/EntraOps/commits'; StatusCode = 403 }
    ) {
        $script:Status = $StatusCode
        Mock Invoke-RestMethod { $script:Requests.Add($Headers); throw (New-GitHubHttpError -StatusCode $script:Status) }

        { Invoke-EntraOpsGitHubRequest -Uri $Uri -Token 'insiders-pat' } | Should -Throw "*$StatusCode*"

        $script:Requests.Count | Should -Be 1
        $script:Requests[0]['Authorization'] | Should -Be 'Bearer insiders-pat'
    }

    It 'treats a rate limit of the public repository as rate limit, not as missing access' {
        $env:GITHUB_TOKEN = 'ghs_test'
        $script:Calls = 0
        Mock Invoke-RestMethod {
            $script:Requests.Add($Headers)
            $script:Calls++
            if ($script:Calls -eq 1) { throw (New-GitHubHttpError -StatusCode 403 -RetryAfterSeconds 2) }
            'ok'
        }

        Invoke-EntraOpsGitHubRequest -Uri 'https://raw.githubusercontent.com/Cloud-Architekt/EntraOps/main/EntraOps/EntraOps.psd1' | Should -Be 'ok'

        $script:Requests[1]['Authorization'] | Should -Be 'Bearer ghs_test'
        Should -Invoke Start-Sleep -Times 1 -Exactly
    }
}
