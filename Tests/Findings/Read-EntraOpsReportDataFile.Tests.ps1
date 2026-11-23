#Requires -Modules Pester

Describe 'Read-EntraOpsReportDataFile' {
    BeforeAll {
        $script:TestRepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
        Import-Module (Join-Path $script:TestRepositoryRoot 'EntraOps/EntraOps.psd1') -Force -WarningAction SilentlyContinue
    }

    It 'reads the data after a header comment that contains an equals sign' {
        $Path = Join-Path $TestDrive 'data.js'
        Set-Content -LiteralPath $Path -Value "// Auto-generated: tier = most privileged`nwindow.ENTRAOPS_TEST = {`"a`":1,`"b`":`"x=y`"};"
        $Result = & (Get-Module EntraOps) { param($Path) Read-EntraOpsReportDataFile -Path $Path } $Path
        $Result.Data['a'] | Should -Be 1
        $Result.Data['b'] | Should -Be 'x=y'
    }

    It 'returns nothing for a missing file and throws for a file without data' {
        & (Get-Module EntraOps) { param($Path) Read-EntraOpsReportDataFile -Path $Path } (Join-Path $TestDrive 'missing.js') | Should -BeNullOrEmpty
        $Path = Join-Path $TestDrive 'empty.js'
        Set-Content -LiteralPath $Path -Value '// nothing'
        { & (Get-Module EntraOps) { param($Path) Read-EntraOpsReportDataFile -Path $Path } $Path } | Should -Throw '*is not a*'
    }
}
