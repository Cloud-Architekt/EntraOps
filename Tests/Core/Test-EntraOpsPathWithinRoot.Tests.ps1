#Requires -Modules Pester

BeforeDiscovery {
    $script:TestRepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
}

BeforeAll {
    $script:TestRepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
    . "$script:TestRepositoryRoot/EntraOps/Private/Test-EntraOpsPathWithinRoot.ps1"

    function New-TestDirectoryLink {
        param (
            [Parameter(Mandatory = $true)]
            [string]$Path,

            [Parameter(Mandatory = $true)]
            [string]$Target
        )

        $ItemType = if ($IsWindows) { 'Junction' } else { 'SymbolicLink' }
        New-Item -ItemType $ItemType -Path $Path -Target $Target -ErrorAction Stop | Out-Null
    }
}

Describe 'Test-EntraOpsPathWithinRoot' {
    BeforeAll {
    $script:TestRepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
        $Root = Join-Path $TestDrive 'EntraOps'
    }

    It 'accepts a direct child' {
        Test-EntraOpsPathWithinRoot -Path (Join-Path $Root 'PrivilegedEAM') -Root $Root | Should -BeTrue
    }

    It 'accepts a nested descendant' {
        Test-EntraOpsPathWithinRoot -Path (Join-Path $Root 'PrivilegedEAM/EntraID/user.json') -Root $Root | Should -BeTrue
    }

    It 'rejects a sibling that shares the root as a text prefix' {
        Test-EntraOpsPathWithinRoot -Path (Join-Path $TestDrive 'EntraOps-escape') -Root $Root | Should -BeFalse
    }

    It 'rejects traversal that leaves the root' {
        Test-EntraOpsPathWithinRoot -Path (Join-Path $Root '../EntraOps-escape/PrivilegedEAM') -Root $Root | Should -BeFalse
    }

    It 'accepts traversal that returns into the root' {
        Test-EntraOpsPathWithinRoot -Path (Join-Path $Root '../EntraOps/PrivilegedEAM') -Root $Root | Should -BeTrue
    }

    It 'rejects the root itself by default' {
        Test-EntraOpsPathWithinRoot -Path $Root -Root $Root | Should -BeFalse
    }

    It 'accepts the root only with -AllowRoot' {
        Test-EntraOpsPathWithinRoot -Path $Root -Root $Root -AllowRoot | Should -BeTrue
    }

    It 'rejects a parent of the root' {
        Test-EntraOpsPathWithinRoot -Path $TestDrive -Root $Root | Should -BeFalse
    }

    It 'ignores a trailing directory separator on the root' {
        $RootWithSeparator = $Root + [System.IO.Path]::DirectorySeparatorChar
        Test-EntraOpsPathWithinRoot -Path (Join-Path $Root 'PrivilegedEAM') -Root $RootWithSeparator | Should -BeTrue
        Test-EntraOpsPathWithinRoot -Path $Root -Root $RootWithSeparator | Should -BeFalse
    }

    It 'fails closed for a path-case variant on every platform' {
        $CaseVariant = Join-Path $TestDrive 'entraops/PrivilegedEAM'
        Test-EntraOpsPathWithinRoot -Path $CaseVariant -Root $Root | Should -BeFalse
    }

    It 'rejects a descendant reached through a filesystem link to outside the root' {
        $OutsideRoot = Join-Path $TestDrive 'Outside'
        $OutsideChild = Join-Path $OutsideRoot 'PrivilegedEAM'
        New-Item -ItemType Directory -Path $Root, $OutsideChild -Force | Out-Null
        New-TestDirectoryLink -Path (Join-Path $Root 'linked-outside') -Target $OutsideRoot

        Test-EntraOpsPathWithinRoot -Path (Join-Path $Root 'linked-outside/PrivilegedEAM') -Root $Root |
            Should -BeFalse
    }

    It 'accepts a descendant reached through a filesystem link that stays inside the root' {
        $InsideTarget = Join-Path $Root 'actual/PrivilegedEAM'
        New-Item -ItemType Directory -Path $InsideTarget -Force | Out-Null
        New-TestDirectoryLink -Path (Join-Path $Root 'linked-inside') -Target (Join-Path $Root 'actual')

        Test-EntraOpsPathWithinRoot -Path (Join-Path $Root 'linked-inside/PrivilegedEAM') -Root $Root |
            Should -BeTrue
    }

    It 'rejects a nonexistent descendant below a filesystem link to outside the root' {
        $OutsideRoot = Join-Path $TestDrive 'OutsideForNewPath'
        New-Item -ItemType Directory -Path $Root, $OutsideRoot -Force | Out-Null
        New-TestDirectoryLink -Path (Join-Path $Root 'linked-new-outside') -Target $OutsideRoot

        Test-EntraOpsPathWithinRoot -Path (Join-Path $Root 'linked-new-outside/not-created-yet') -Root $Root |
            Should -BeFalse
    }

    It 'resolves traversal relative to a filesystem link target' {
        $OutsideRoot = Join-Path $TestDrive 'OutsideForTraversal'
        $LinkTarget = Join-Path $OutsideRoot 'target'
        New-Item -ItemType Directory -Path $Root, $LinkTarget -Force | Out-Null
        New-TestDirectoryLink -Path (Join-Path $Root 'linked-traversal') -Target $LinkTarget

        Test-EntraOpsPathWithinRoot -Path (Join-Path $Root 'linked-traversal/../escaped') -Root $Root |
            Should -BeFalse
    }
}

Describe 'Save-EntraOpsEAMRbacSystemJson path guard' {
    BeforeAll {
    $script:TestRepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
        . "$script:TestRepositoryRoot/EntraOps/Private/Save-EntraOpsEAMRbacSystemJson.ps1"

        $script:EntraOpsBaseFolder = Join-Path $TestDrive 'EntraOps'
        New-Item -ItemType Directory -Path $script:EntraOpsBaseFolder -Force | Out-Null

        $script:SiblingFolder = Join-Path $TestDrive 'EntraOps-escape'
        New-Item -ItemType Directory -Path $script:SiblingFolder -Force | Out-Null

        $script:SampleEamData = @(
            [pscustomobject]@{ ObjectType = 'user'; ObjectId = '11111111-1111-1111-1111-111111111111' }
        )
    }

    It 'refuses a sibling export folder and deletes nothing' {
        Mock Remove-Item {}

        {
            Save-EntraOpsEAMRbacSystemJson -ExportFolder $script:SiblingFolder -RbacSystemName 'EntraID' `
                -EamData $script:SampleEamData -AggregateFileName 'EntraID.json'
        } | Should -Throw '*not under the expected base directory*'

        Should -Not -Invoke Remove-Item
    }

    It 'refuses the base folder itself and deletes nothing' {
        Mock Remove-Item {}

        {
            Save-EntraOpsEAMRbacSystemJson -ExportFolder $script:EntraOpsBaseFolder -RbacSystemName 'EntraID' `
                -EamData $script:SampleEamData -AggregateFileName 'EntraID.json'
        } | Should -Throw '*not under the expected base directory*'

        Should -Not -Invoke Remove-Item
    }

    It 'refuses an export folder reached through a filesystem link and deletes nothing' {
        $OutsideRoot = Join-Path $TestDrive 'OutsideExport'
        $OutsideExport = Join-Path $OutsideRoot 'EntraID'
        New-Item -ItemType Directory -Path $OutsideExport -Force | Out-Null
        New-TestDirectoryLink -Path (Join-Path $script:EntraOpsBaseFolder 'linked-outside') -Target $OutsideRoot
        Mock Remove-Item {}

        {
            Save-EntraOpsEAMRbacSystemJson `
                -ExportFolder (Join-Path $script:EntraOpsBaseFolder 'linked-outside/EntraID') `
                -RbacSystemName 'EntraID' `
                -EamData $script:SampleEamData `
                -AggregateFileName 'EntraID.json'
        } | Should -Throw '*not under the expected base directory*'

        Should -Not -Invoke Remove-Item
    }
}

