#Requires -Modules Pester

BeforeAll {
    $script:TestRepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
    . "$script:TestRepositoryRoot/EntraOps/Private/Invoke-EntraOpsParallelObjectResolution.ps1"

    # Stubs for the module commands the tests mock
    function Invoke-EntraOpsMsGraphQuery { param($Method, $Uri, $Body, $OutputType) }
    function Get-EntraOpsPrivilegedEntraObject { param($AadObjectId, $TenantId) }
    function Get-MgContext { param() }
}

Describe 'Invoke-EntraOpsParallelObjectResolution' {
    BeforeEach {
        $script:__EntraOpsSession = @{ GraphCache = @{}; CacheMetadata = @{}; DefaultCacheTTL = 3600; UseInvokeRestMethodOnly = $false }
        $Global:TenantIdContext = 'tenant'
        Mock Get-MgContext { $null }
        Mock Write-Progress {}
        # getByIds returns each object once, whatever the number of times its ID was requested
        Mock Invoke-EntraOpsMsGraphQuery {
            @(($Body | ConvertFrom-Json).ids | Sort-Object -Unique | Where-Object { $_ -ne '33333333-3333-3333-3333-333333333333' } | ForEach-Object { [pscustomobject]@{ id = $_ } })
        }
        Mock Get-EntraOpsPrivilegedEntraObject { [pscustomobject]@{ ObjectId = $AadObjectId; ObjectType = 'user' } }
    }

    AfterAll {
        Remove-Variable -Name TenantIdContext -Scope Global -ErrorAction SilentlyContinue
    }

    It 'resolves each object ID once and counts unique IDs in its output' {
        $Objects = @(
            [pscustomobject]@{ ObjectId = '11111111-1111-1111-1111-111111111111'; ObjectType = 'User' }
            [pscustomobject]@{ ObjectId = '11111111-1111-1111-1111-111111111111'; ObjectType = 'ServicePrincipal' }
            [pscustomobject]@{ ObjectId = '22222222-2222-2222-2222-222222222222'; ObjectType = 'Group' }
            [pscustomobject]@{ ObjectId = '33333333-3333-3333-3333-333333333333'; ObjectType = 'User' }
        )

        $Output = @(Invoke-EntraOpsParallelObjectResolution -UniqueObjects $Objects -TenantId 'tenant' -EnableParallelProcessing $false 6>&1)
        $Cache = $Output | Where-Object { $_ -is [hashtable] }
        $Messages = ($Output | Where-Object { $_ -isnot [hashtable] }) -join "`n"

        Should -Invoke Get-EntraOpsPrivilegedEntraObject -Times 3 -Exactly
        $Cache.Keys.Count | Should -Be 3
        $Messages | Should -Match 'Pre-fetch complete: 2 of 3 object\(s\) cached, 0 in failed batches\.'
        $Messages | Should -Match 'Resolving details for 3 unique objects'
    }
}
