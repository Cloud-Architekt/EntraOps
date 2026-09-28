#Requires -Modules Pester

BeforeDiscovery {
    $script:TestRepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
}

BeforeAll {
    $script:TestRepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
    . "$script:TestRepositoryRoot/EntraOps/Private/Resolve-EntraOpsClassificationPath.ps1"
}

Describe "Resolve-EntraOpsClassificationPath" {
    BeforeEach {
        $script:PreviousTenantNameContext = Get-Variable -Name TenantNameContext -Scope Global -ValueOnly -ErrorAction SilentlyContinue
        $global:TenantNameContext = "contoso.onmicrosoft.com"

        $script:ClassificationRoot = Join-Path $TestDrive "Classification"
        # Recreate the tree from scratch: TestDrive contents from BeforeEach persist across
        # tests, so a tenant file created by one test must not leak into the next.
        if (Test-Path $script:ClassificationRoot) { Remove-Item -Path $script:ClassificationRoot -Recurse -Force }
        New-Item -ItemType Directory -Path (Join-Path $script:ClassificationRoot "Templates") -Force | Out-Null
        New-Item -ItemType Directory -Path (Join-Path $script:ClassificationRoot $global:TenantNameContext) -Force | Out-Null

        # Parameterized system: template + .Param.json variant
        Set-Content -Path (Join-Path $script:ClassificationRoot "Templates/Classification_Azure.json") -Value "[]"
        Set-Content -Path (Join-Path $script:ClassificationRoot "Templates/Classification_Azure.Param.json") -Value "[]"
        # Template-only system: template without .Param.json variant
        Set-Content -Path (Join-Path $script:ClassificationRoot "Templates/Classification_ApiPermissions.json") -Value "[]"
    }

    AfterEach {
        if ($null -ne $script:PreviousTenantNameContext) {
            $global:TenantNameContext = $script:PreviousTenantNameContext
        } else {
            Remove-Variable -Name TenantNameContext -Scope Global -ErrorAction SilentlyContinue
        }
    }

    It "prefers the tenant-specific file without a warning" {
        $TenantFile = Join-Path $script:ClassificationRoot "$global:TenantNameContext/Classification_Azure.json"
        Set-Content -Path $TenantFile -Value "[]"

        $Warnings = @()
        $Resolved = Resolve-EntraOpsClassificationPath -ClassificationFileName "Classification_Azure.json" -FolderClassification $script:ClassificationRoot -WarningVariable Warnings -WarningAction SilentlyContinue
        $Resolved | Should -Be $TenantFile
        $Warnings | Should -BeNullOrEmpty
    }

    It "warns on template fallback for a parameterized system" {
        $Warnings = @()
        $Resolved = Resolve-EntraOpsClassificationPath -ClassificationFileName "Classification_Azure.json" -FolderClassification $script:ClassificationRoot -WarningVariable Warnings -WarningAction SilentlyContinue
        $Resolved | Should -Be (Join-Path $script:ClassificationRoot "Templates/Classification_Azure.json")
        @($Warnings).Count | Should -Be 1
        "$($Warnings[0])" | Should -BeLike "*tenant-scoped placeholders*"
    }

    It "does not warn on template fallback for a template-only system" {
        $Warnings = @()
        $Resolved = Resolve-EntraOpsClassificationPath -ClassificationFileName "Classification_ApiPermissions.json" -FolderClassification $script:ClassificationRoot -WarningVariable Warnings -WarningAction SilentlyContinue
        $Resolved | Should -Be (Join-Path $script:ClassificationRoot "Templates/Classification_ApiPermissions.json")
        $Warnings | Should -BeNullOrEmpty
    }

    It "still uses a tenant-specific file for a template-only system when overwrite generation produced one" {
        $TenantFile = Join-Path $script:ClassificationRoot "$global:TenantNameContext/Classification_ApiPermissions.json"
        Set-Content -Path $TenantFile -Value "[]"

        Resolve-EntraOpsClassificationPath -ClassificationFileName "Classification_ApiPermissions.json" -FolderClassification $script:ClassificationRoot | Should -Be $TenantFile
    }
}

