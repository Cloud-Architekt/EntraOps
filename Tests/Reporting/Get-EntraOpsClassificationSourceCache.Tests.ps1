#Requires -Modules Pester

BeforeAll {
    $script:TestRepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
    . "$script:TestRepositoryRoot/EntraOps/Private/Get-EntraOpsClassificationSourceCache.ps1"
    $script:FileName = 'Classification_EntraIdDirectoryRoles.json'
}

Describe 'Get-EntraOpsClassificationSourceCache' {
    BeforeEach {
        $script:CachePath = Join-Path $TestDrive ([guid]::NewGuid().ToString())
        Mock Invoke-WebRequest { Set-Content -LiteralPath $OutFile -Value '[{"RoleId":"1"}]' -Encoding UTF8 }
    }

    It 'downloads the file into the cache and returns a root that keeps the Classification sub-path' {
        $Root = Get-EntraOpsClassificationSourceCache -FileName $script:FileName -CachePath $script:CachePath

        Join-Path $Root "Classification/$script:FileName" | Should -Exist
        Should -Invoke Invoke-WebRequest -Times 1 -Exactly -ParameterFilter {
            $Uri -eq "https://raw.githubusercontent.com/Cloud-Architekt/AzurePrivilegedIAM/main/Classification/$script:FileName"
        }
    }

    It 'does not download again while the cached file is fresh' {
        Get-EntraOpsClassificationSourceCache -FileName $script:FileName -CachePath $script:CachePath | Out-Null
        Get-EntraOpsClassificationSourceCache -FileName $script:FileName -CachePath $script:CachePath | Out-Null

        Should -Invoke Invoke-WebRequest -Times 1 -Exactly
    }

    It 'downloads again when the cached file is older than MaxAgeHours' {
        $Root = Get-EntraOpsClassificationSourceCache -FileName $script:FileName -CachePath $script:CachePath
        (Get-Item (Join-Path $Root "Classification/$script:FileName")).LastWriteTimeUtc = [datetime]::UtcNow.AddHours(-48)

        Get-EntraOpsClassificationSourceCache -FileName $script:FileName -CachePath $script:CachePath -MaxAgeHours 24 | Out-Null

        Should -Invoke Invoke-WebRequest -Times 2 -Exactly
    }

    It 'keeps a stale cached copy and warns when the refresh fails' {
        $Root = Get-EntraOpsClassificationSourceCache -FileName $script:FileName -CachePath $script:CachePath
        $Cached = Join-Path $Root "Classification/$script:FileName"
        (Get-Item $Cached).LastWriteTimeUtc = [datetime]::UtcNow.AddHours(-48)
        Mock Invoke-WebRequest { throw 'offline' }

        $Result = Get-EntraOpsClassificationSourceCache -FileName $script:FileName -CachePath $script:CachePath -WarningVariable Warnings -WarningAction SilentlyContinue

        $Result | Should -Be $Root
        "$Warnings" | Should -Match 'cached copy'
        Get-Content -LiteralPath $Cached -Raw | Should -Match 'RoleId'
    }

    It 'returns null and leaves no file when the download fails and nothing is cached' {
        Mock Invoke-WebRequest { throw 'offline' }

        $Result = Get-EntraOpsClassificationSourceCache -FileName $script:FileName -CachePath $script:CachePath -WarningAction SilentlyContinue

        $Result | Should -BeNullOrEmpty
        Get-ChildItem -LiteralPath $script:CachePath -Recurse -File -ErrorAction SilentlyContinue | Should -BeNullOrEmpty
    }

    It 'does not replace a good copy with a non-JSON response' {
        $Root = Get-EntraOpsClassificationSourceCache -FileName $script:FileName -CachePath $script:CachePath
        $Cached = Join-Path $Root "Classification/$script:FileName"
        (Get-Item $Cached).LastWriteTimeUtc = [datetime]::UtcNow.AddHours(-48)
        Mock Invoke-WebRequest { Set-Content -LiteralPath $OutFile -Value '<html>rate limited</html>' }

        Get-EntraOpsClassificationSourceCache -FileName $script:FileName -CachePath $script:CachePath -WarningAction SilentlyContinue | Out-Null

        Get-Content -LiteralPath $Cached -Raw | Should -Match 'RoleId'
    }

    It 'rejects refs with path traversal and unexpected file names' {
        { Get-EntraOpsClassificationSourceCache -CachePath $script:CachePath -Ref 'a/../b' } | Should -Throw
        { Get-EntraOpsClassificationSourceCache -CachePath $script:CachePath -FileName '../x.json' } | Should -Throw
    }
}
