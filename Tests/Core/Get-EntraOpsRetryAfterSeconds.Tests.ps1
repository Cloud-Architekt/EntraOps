#Requires -Modules Pester

BeforeAll {
    $script:TestRepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
    . "$script:TestRepositoryRoot/EntraOps/Private/Get-EntraOpsRetryAfterSeconds.ps1"

    function New-TestThrottledResponse {
        param([string]$RetryAfter)
        $Response = [System.Net.Http.HttpResponseMessage]::new([System.Net.HttpStatusCode]::TooManyRequests)
        if ($RetryAfter) { $null = $Response.Headers.TryAddWithoutValidation('Retry-After', $RetryAfter) }
        $Response
    }
}

Describe 'Get-EntraOpsRetryAfterSeconds' {
    It 'reads the delta seconds of an HttpResponseMessage' {
        # A string index on HttpResponseHeaders returns nothing, which previously disabled Retry-After entirely.
        Get-EntraOpsRetryAfterSeconds -Response (New-TestThrottledResponse -RetryAfter '120') | Should -Be 120
    }

    It 'reads the HTTP date form of an HttpResponseMessage' {
        $Date = [DateTimeOffset]::UtcNow.AddSeconds(90).ToString('r')
        $Seconds = Get-EntraOpsRetryAfterSeconds -Response (New-TestThrottledResponse -RetryAfter $Date)
        $Seconds | Should -BeGreaterOrEqual 85
        $Seconds | Should -BeLessOrEqual 91
    }

    It 'reads dictionary-shaped headers' {
        Get-EntraOpsRetryAfterSeconds -Response ([pscustomobject]@{ Headers = @{ 'Retry-After' = @('30') } }) | Should -Be 30
    }

    It 'returns nothing without a Retry-After header' {
        Get-EntraOpsRetryAfterSeconds -Response (New-TestThrottledResponse) | Should -BeNullOrEmpty
        Get-EntraOpsRetryAfterSeconds -Response $null | Should -BeNullOrEmpty
    }
}
