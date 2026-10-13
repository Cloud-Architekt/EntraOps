#Requires -Modules Pester

BeforeAll {
    $script:TestRepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
    Import-Module (Join-Path $script:TestRepositoryRoot 'EntraOps') -Force
    $script:Session = & (Get-Module EntraOps) { $__EntraOpsSession }
    $script:PreviousRestMode = $script:Session['UseInvokeRestMethodOnly']

    function New-TestGraphError {
        param([int]$StatusCode, [string]$ErrorCode)
        $response = [System.Net.Http.HttpResponseMessage]::new([System.Net.HttpStatusCode]$StatusCode)
        $exception = [Microsoft.PowerShell.Commands.HttpResponseException]::new("Response status code does not indicate success: $StatusCode.", $response)
        $record = [System.Management.Automation.ErrorRecord]::new($exception, 'WebCmdletWebResponseException', 'InvalidOperation', $null)
        $record.ErrorDetails = [System.Management.Automation.ErrorDetails]::new("{`"error`":{`"code`":`"$ErrorCode`",`"message`":`"test`"}}")
        $record
    }
}

AfterAll {
    $script:Session['UseInvokeRestMethodOnly'] = $script:PreviousRestMode
    $script:Session.MsGraphTokenCache.Remove('provided')
    $script:Session.GraphCache.Clear()
    $script:Session.CacheMetadata.Clear()
}

Describe 'Invoke-EntraOpsMsGraphQuery error details and cache' {
    BeforeEach {
        $script:Session['UseInvokeRestMethodOnly'] = $true
        $script:Session.MsGraphTokenCache['provided'] = @{ Token = 'token'; Expiry = [DateTime]::UtcNow.AddHours(1) }
        $script:Session.GraphCache.Clear()
        $script:Session.CacheMetadata.Clear()
        $script:Calls = 0
        Mock Invoke-RestMethod -ModuleName EntraOps { $script:Calls++; [pscustomobject]@{ id = "result-$script:Calls" } }
    }

    It 'adds the Graph error code to the thrown exception' {
        Mock Invoke-RestMethod -ModuleName EntraOps { throw (New-TestGraphError -StatusCode 400 -ErrorCode 'ResourceNotFoundInOriginSystem') }

        $caught = $null
        try {
            Invoke-EntraOpsMsGraphQuery -Method POST -Uri '/v1.0/identityGovernance/entitlementManagement/resourceRequests' -Body '{}' -ThrowOnFailure -SuppressBadRequestWarning
        } catch { $caught = $_ }

        $caught.Exception.Data['StatusCode'] | Should -Be 400
        $caught.Exception.Data['ErrorCode'] | Should -Be 'ResourceNotFoundInOriginSystem'
    }

    It 'neither reads nor stores the cache with DisableCache' {
        Invoke-EntraOpsMsGraphQuery -Method GET -Uri '/v1.0/groups/a' -DisableCache | Out-Null
        Invoke-EntraOpsMsGraphQuery -Method GET -Uri '/v1.0/groups/a' | Out-Null
        Invoke-EntraOpsMsGraphQuery -Method GET -Uri '/v1.0/groups/a' | Out-Null

        $script:Calls | Should -Be 2
    }

    It 'replaces an older cache entry with a fresh DisableCache result' {
        Invoke-EntraOpsMsGraphQuery -Method GET -Uri '/v1.0/groups/b' | Out-Null
        Invoke-EntraOpsMsGraphQuery -Method GET -Uri '/v1.0/groups/b' -DisableCache | Out-Null
        $result = Invoke-EntraOpsMsGraphQuery -Method GET -Uri '/v1.0/groups/b'

        $script:Calls | Should -Be 3
        $result.id | Should -Be 'result-3'
    }
}
