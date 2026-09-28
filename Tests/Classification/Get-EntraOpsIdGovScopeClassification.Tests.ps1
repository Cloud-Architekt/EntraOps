#Requires -Modules Pester

BeforeDiscovery {
    $script:TestRepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
}

BeforeAll {
    $script:TestRepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
    . "$script:TestRepositoryRoot/EntraOps/Private/Get-EntraOpsAadApplicationClassification.ps1"
    . "$script:TestRepositoryRoot/EntraOps/Private/Resolve-EntraOpsSharePointOnlineRoleTier.ps1"
    . "$script:TestRepositoryRoot/EntraOps/Private/Get-EntraOpsIdGovScopeClassification.ps1"

    # Stub for the Graph helper so Pester can mock it (the module is not imported here).
    function Invoke-EntraOpsMsGraphQuery {
        param($Uri, $Method, $Body, $OutputType, $ConsistencyLevel)
        throw "Graph query not mocked in this test: $Uri"
    }

    $script:KnownSpId = "11111111-1111-1111-1111-111111111111"
    $script:UnknownSpId = "22222222-2222-2222-2222-222222222222"
    $script:SiteUrl = "https://contoso.sharepoint.com/sites/give"
}

Describe "Get-EntraOpsIdGovScopeClassification AadApplication and SharePointOnline origins" {
    BeforeEach {
        # EAM export folder: only ResourceApps data is needed for these origins.
        $script:EamFolder = Join-Path $TestDrive "PrivilegedEAM"
        if (Test-Path $script:EamFolder) { Remove-Item -Path $script:EamFolder -Recurse -Force }
        New-Item -ItemType Directory -Path (Join-Path $script:EamFolder "ResourceApps") -Force | Out-Null
        @(
            [pscustomobject]@{
                ObjectId       = $script:KnownSpId
                ObjectDisplayName = "Known App"
                Classification = @(
                    [pscustomobject]@{ AdminTierLevel = "0"; AdminTierLevelName = "ControlPlane"; Service = "Authentication" }
                )
            }
        ) | ConvertTo-Json -Depth 5 -AsArray | Set-Content -Path (Join-Path $script:EamFolder "ResourceApps/ResourceApps.json")

        # Empty classification folder: API-permission templates absent -> warning only.
        $script:ClassificationFolder = Join-Path $TestDrive "Classification"
        New-Item -ItemType Directory -Path $script:ClassificationFolder -Force | Out-Null

        Mock Invoke-EntraOpsMsGraphQuery -ParameterFilter { $Uri -like "*accessPackageCatalogs?*" } -MockWith {
            @([pscustomobject]@{ id = "cat1"; displayName = "Test Catalog" })
        }
        Mock Invoke-EntraOpsMsGraphQuery -ParameterFilter { $Uri -like "*accessPackageCatalogs/cat1/accessPackageResources*" } -MockWith {
            @(
                [pscustomobject]@{ originSystem = "AadApplication"; originId = $script:KnownSpId; displayName = "Known App" }
                [pscustomobject]@{ originSystem = "SharePointOnline"; originId = $script:SiteUrl; displayName = "Give" }
            )
        }
        Mock Invoke-EntraOpsMsGraphQuery -ParameterFilter { $Uri -like "*accessPackageCatalogs('cat1')*" } -MockWith {
            [pscustomobject]@{
                id             = "cat1"
                displayName    = "Test Catalog"
                accessPackages = @(
                    [pscustomobject]@{ id = "ap-sharepoint"; displayName = "SharePoint Visitors Package" }
                    [pscustomobject]@{ id = "ap-unresolved-app"; displayName = "Unresolved App Package" }
                )
            }
        }
        Mock Invoke-EntraOpsMsGraphQuery -ParameterFilter { $Uri -like "*accessPackages/ap-sharepoint?*" } -MockWith {
            [pscustomobject]@{
                id                              = "ap-sharepoint"
                displayName                     = "SharePoint Visitors Package"
                accessPackageResourceRoleScopes = @(
                    [pscustomobject]@{
                        accessPackageResourceRole  = [pscustomobject]@{ displayName = "Besucher von Give"; originId = "4" }
                        accessPackageResourceScope = [pscustomobject]@{ originSystem = "SharePointOnline"; originId = $script:SiteUrl; displayName = "Give" }
                    }
                )
            }
        }
        Mock Invoke-EntraOpsMsGraphQuery -ParameterFilter { $Uri -like "*accessPackages/ap-unresolved-app?*" } -MockWith {
            [pscustomobject]@{
                id                              = "ap-unresolved-app"
                displayName                     = "Unresolved App Package"
                accessPackageResourceRoleScopes = @(
                    [pscustomobject]@{
                        accessPackageResourceRole  = [pscustomobject]@{ displayName = "Default Access"; originId = "role-guid" }
                        accessPackageResourceScope = [pscustomobject]@{ originSystem = "AadApplication"; originId = $script:UnknownSpId; displayName = "Mystery App" }
                    }
                )
            }
        }

        $script:Warnings = [System.Collections.Generic.List[psobject]]::new()
        $script:Result = @(Get-EntraOpsIdGovScopeClassification -EntraOpsEamFolder $script:EamFolder -FilterClassifiedRbacs @("Azure") -FolderClassification $script:ClassificationFolder -WarningMessages $script:Warnings)
    }

    It "classifies a localized SharePoint visitor role as UserAccess via its default group originId" {
        $ApScope = $script:Result | Where-Object { $_.ScopeId -eq "/AccessPackage/ap-sharepoint" }
        $ApScope.EAMTier | Should -Be "UserAccess"
        $SpDetail = @($ApScope.ClassifiedResources | Where-Object { $_.OriginSystem -eq "SharePointOnline" })[0]
        $SpDetail.EAMTier | Should -Be "UserAccess"
        $SpDetail.Reason | Should -BeLike "*Besucher von Give*"
    }

    It "classifies a known AadApplication from its ResourceApps classification" {
        $CatalogScope = $script:Result | Where-Object { $_.ScopeType -eq "AccessPackageCatalog" }
        $AppDetail = @($CatalogScope.ClassifiedResources | Where-Object { $_.OriginSystem -eq "AadApplication" -and $_.ResourceId -eq $script:KnownSpId })[0]
        $AppDetail.EAMTier | Should -Be "ControlPlane"
        $AppDetail.Reason | Should -BeLike "*ResourceApps*"
    }

    It "fails closed to ControlPlane for an unresolved AadApplication and records a warning" {
        $ApScope = $script:Result | Where-Object { $_.ScopeId -eq "/AccessPackage/ap-unresolved-app" }
        $ApScope.EAMTier | Should -Be "ControlPlane"
        @($script:Warnings | Where-Object { $_.Type -eq "Unresolved AadApplication" }).Count | Should -Be 1
    }

    It "treats the catalog-level SharePoint resource as ManagementPlane without an unknown-role warning" {
        $CatalogScope = $script:Result | Where-Object { $_.ScopeType -eq "AccessPackageCatalog" }
        $SpDetail = @($CatalogScope.ClassifiedResources | Where-Object { $_.OriginSystem -eq "SharePointOnline" })[0]
        $SpDetail.EAMTier | Should -Be "ManagementPlane"
        $SpDetail.Reason | Should -BeLike "*catalog level*"
        @($script:Warnings | Where-Object { $_.Type -eq "UnknownSharePointRole" }).Count | Should -Be 0
    }
}

