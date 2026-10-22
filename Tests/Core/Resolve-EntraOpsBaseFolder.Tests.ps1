#Requires -Modules Pester

Describe 'Resolve-EntraOpsBaseFolder' {
    BeforeAll {
        $script:TestRepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
        . "$script:TestRepositoryRoot/EntraOps/Private/Test-EntraOpsRepositoryCheckout.ps1"
        . "$script:TestRepositoryRoot/EntraOps/Private/Resolve-EntraOpsBaseFolder.ps1"
    }

    BeforeEach {
        $script:Root = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
        $script:Repository = Join-Path $script:Root 'repo'
        $script:GalleryModule = Join-Path $script:Root 'Modules/EntraOps/1.1.0'
        $script:WorkFolder = Join-Path $script:Root 'work'
        $script:UserHome = Join-Path $script:Root 'home'
        New-Item -ItemType Directory -Path "$script:Repository/EntraOps", $script:GalleryModule, $script:WorkFolder, $script:UserHome -Force | Out-Null
    }

    It 'keeps the repository checkout for GitHub, Azure DevOps and local clones (update contract)' {
        Set-Content -LiteralPath "$script:Repository/EntraOpsUpdateContract.json" -Value '{}'
        Set-Content -LiteralPath "$script:WorkFolder/EntraOpsConfig.json" -Value '{}'

        $Result = Resolve-EntraOpsBaseFolder -ModuleRoot "$script:Repository/EntraOps" -EnvironmentRoot '' -CurrentPath $script:WorkFolder -UserHome $script:UserHome

        $Result.Path | Should -Be $script:Repository
        $Result.Source | Should -Be 'RepositoryCheckout'
    }

    It 'keeps the repository checkout when only the Classification folder is present' {
        New-Item -ItemType Directory -Path "$script:Repository/Classification" | Out-Null

        $Result = Resolve-EntraOpsBaseFolder -ModuleRoot "$script:Repository/EntraOps" -EnvironmentRoot '' -CurrentPath $script:WorkFolder -UserHome $script:UserHome

        $Result.Source | Should -Be 'RepositoryCheckout'
    }

    It 'lets ENTRAOPS_ROOT win over every other source' {
        Set-Content -LiteralPath "$script:Repository/EntraOpsUpdateContract.json" -Value '{}'

        $Result = Resolve-EntraOpsBaseFolder -ModuleRoot "$script:Repository/EntraOps" -EnvironmentRoot "$script:WorkFolder/" -CurrentPath $script:WorkFolder -UserHome $script:UserHome

        $Result.Path | Should -Be $script:WorkFolder
        $Result.Source | Should -Be 'EnvironmentVariable'
    }

    It 'uses the current folder with EntraOpsConfig.json for a module-only install' {
        Set-Content -LiteralPath "$script:WorkFolder/EntraOpsConfig.json" -Value '{}'

        $Result = Resolve-EntraOpsBaseFolder -ModuleRoot $script:GalleryModule -EnvironmentRoot '' -CurrentPath $script:WorkFolder -UserHome $script:UserHome

        $Result.Path | Should -Be $script:WorkFolder
        $Result.Source | Should -Be 'CurrentFolder'
    }

    It 'falls back to <home>/EntraOps and never to the module install folder' {
        $Result = Resolve-EntraOpsBaseFolder -ModuleRoot $script:GalleryModule -EnvironmentRoot '' -CurrentPath $script:WorkFolder -UserHome $script:UserHome

        $Result.Path | Should -Be (Join-Path $script:UserHome 'EntraOps')
        $Result.Source | Should -Be 'UserFolder'
    }
}
