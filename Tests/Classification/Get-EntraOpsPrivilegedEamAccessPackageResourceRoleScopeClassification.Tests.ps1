#Requires -Modules Pester

BeforeDiscovery {
    $script:TestRepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
}

BeforeAll {
    $script:TestRepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
    . "$script:TestRepositoryRoot/EntraOps/Private/Find-EntraOpsAzureScopeContainmentMatch.ps1"
    . "$script:TestRepositoryRoot/EntraOps/Private/Resolve-EntraOpsAzureScopeReasoningTier.ps1"
    . "$script:TestRepositoryRoot/EntraOps/Private/Get-EntraOpsAadApplicationClassification.ps1"
    . "$script:TestRepositoryRoot/EntraOps/Private/Resolve-EntraOpsSharePointOnlineRoleTier.ps1"
    . "$script:TestRepositoryRoot/EntraOps/Private/Get-EntraOpsPrivilegedEamAccessPackageResourceRoleScopeClassification.ps1"
}

Describe "Get-EntraOpsPrivilegedEamAccessPackageResourceRoleScopeClassification" {
    Context "AzureResources scope with unresolved Azure scope reasoning" {
        BeforeAll {
    $script:TestRepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
            $AzureResourceScope = [PSCustomObject]@{
                accessPackageResourceRole  = [PSCustomObject]@{ displayName = "Contributor" }
                accessPackageResourceScope = [PSCustomObject]@{
                    originSystem = "AzureResources"
                    originId     = "/subscriptions/aaaa-1111"
                    displayName  = "Test Subscription"
                }
            }
            $WarningMessages = [System.Collections.Generic.List[psobject]]::new()

            $Result = Get-EntraOpsPrivilegedEamAccessPackageResourceRoleScopeClassification `
                -ResourceRoleScopes @($AzureResourceScope) `
                -FilterClassifiedRbacs @("Azure") `
                -ClassificationCache @{} `
                -ApiPermissionsClassLookup @{} `
                -AzureScopeReasoning $null `
                -ContextLabel "access package aaaaaaaa-0000-0000-0000-000000000000" `
                -WarningMessages $WarningMessages
        }

        It "fails closed to the canonical ControlPlane tier pair instead of Unclassified" {
            $Result.Count | Should -Be 1
            $Result[0].AdminTierLevel | Should -Be "0"
            $Result[0].AdminTierLevelName | Should -Be "ControlPlane"
        }

        It "records a warning explaining the scope could not be evaluated" {
            $WarningMessages.Count | Should -Be 1
            $WarningMessages[0].Type | Should -Be "Unresolved Azure Scope"
            $WarningMessages[0].Message | Should -Match "could not be evaluated"
            $WarningMessages[0].Message | Should -Match "ControlPlane"
        }

        It "fails closed to ControlPlane when Azure scope reasoning is unavailable" {
            # Keep unresolved Azure resource scopes consistent across Identity Governance classifiers.
            $Result[0].AdminTierLevelName | Should -Be "ControlPlane"
        }
    }

    Context "AzureResources scope with resolved Azure scope reasoning (regression guard)" {
        It "still classifies normally by containment when scope reasoning is available" {
            $Reasoning = [PSCustomObject]@{
                Tier0Scope = @("/subscriptions/aaaa-1111")
                Tier1Scope = @()
            }
            $AzureResourceScope = [PSCustomObject]@{
                accessPackageResourceRole  = [PSCustomObject]@{ displayName = "Contributor" }
                accessPackageResourceScope = [PSCustomObject]@{
                    originSystem = "AzureResources"
                    originId     = "/subscriptions/aaaa-1111"
                    displayName  = "Test Subscription"
                }
            }
            $WarningMessages = [System.Collections.Generic.List[psobject]]::new()

            $Result = Get-EntraOpsPrivilegedEamAccessPackageResourceRoleScopeClassification `
                -ResourceRoleScopes @($AzureResourceScope) `
                -FilterClassifiedRbacs @("Azure") `
                -ClassificationCache @{} `
                -ApiPermissionsClassLookup @{} `
                -AzureScopeReasoning $Reasoning `
                -ContextLabel "access package aaaaaaaa-0000-0000-0000-000000000000" `
                -WarningMessages $WarningMessages

            $Result[0].AdminTierLevelName | Should -Be "ControlPlane"
            $WarningMessages.Count | Should -Be 0
        }
    }

    Context "AadApplication scope classified from ResourceApps" {
        BeforeEach {
            $script:ApplicationScope = [pscustomobject]@{
                accessPackageResourceRole  = [pscustomobject]@{ displayName = "Default Access" }
                accessPackageResourceScope = [pscustomobject]@{
                    originSystem = "AadApplication"
                    originId     = "service-principal-id"
                    displayName  = "Graph Explorer"
                }
            }
            $script:WarningMessages = [System.Collections.Generic.List[psobject]]::new()
        }

        It "inherits the application's most privileged ResourceApps classification" {
            $Cache = @{
                "ResourceApps:ByObjectId" = @{
                    "service-principal-id" = @([pscustomobject]@{
                            Classification = @(
                                [pscustomobject]@{ AdminTierLevel = "0"; AdminTierLevelName = "ControlPlane"; Service = "Application and Workload Identity" }
                                [pscustomobject]@{ AdminTierLevel = "1"; AdminTierLevelName = "ManagementPlane"; Service = "Reporting" }
                            )
                        })
                }
            }

            $Result = @(Get-EntraOpsPrivilegedEamAccessPackageResourceRoleScopeClassification -ResourceRoleScopes @($script:ApplicationScope) -FilterClassifiedRbacs @("Azure") -ClassificationCache $Cache -ApiPermissionsClassLookup @{} -ContextLabel "test package" -WarningMessages $script:WarningMessages)

            $Result.AdminTierLevelName | Should -Contain "ControlPlane"
            $Result.TaggedByRoleSystem | Should -Contain "ResourceApps"
            $script:WarningMessages.Count | Should -Be 0
        }

        It "classifies a known application without privileged ResourceApps entries as UserAccess" {
            $Cache = @{ "ResourceApps:ByObjectId" = @{ "service-principal-id" = @([pscustomobject]@{ Classification = @() }) } }

            $Result = @(Get-EntraOpsPrivilegedEamAccessPackageResourceRoleScopeClassification -ResourceRoleScopes @($script:ApplicationScope) -FilterClassifiedRbacs @("Azure") -ClassificationCache $Cache -ApiPermissionsClassLookup @{} -ContextLabel "test package" -WarningMessages $script:WarningMessages)

            $Result.Count | Should -Be 1
            $Result[0].AdminTierLevelName | Should -Be "UserAccess"
        }

        It "fails closed when the service principal is absent from ResourceApps" {
            $Result = @(Get-EntraOpsPrivilegedEamAccessPackageResourceRoleScopeClassification -ResourceRoleScopes @($script:ApplicationScope) -FilterClassifiedRbacs @("Azure") -ClassificationCache @{} -ApiPermissionsClassLookup @{} -ContextLabel "test package" -WarningMessages $script:WarningMessages)

            $Result[0].AdminTierLevelName | Should -Be "ControlPlane"
            $script:WarningMessages[0].Type | Should -Be "Unresolved AadApplication"
        }

        It "classifies an application with exclusively Unclassified entries as UserAccess" {
            # Real ResourceApps exports carry explicit Unclassified entries; an app with ONLY those
            # is a known app without privileged classifications and must not surface as Unclassified.
            $Cache = @{
                "ResourceApps:ByObjectId" = @{
                    "service-principal-id" = @([pscustomobject]@{
                            Classification = @(
                                [pscustomobject]@{ AdminTierLevel = "3"; AdminTierLevelName = "Unclassified"; Service = "Unclassified" }
                            )
                        })
                }
            }

            $Result = @(Get-EntraOpsPrivilegedEamAccessPackageResourceRoleScopeClassification -ResourceRoleScopes @($script:ApplicationScope) -FilterClassifiedRbacs @("Azure") -ClassificationCache $Cache -ApiPermissionsClassLookup @{} -ContextLabel "test package" -WarningMessages $script:WarningMessages)

            $Result.Count | Should -Be 1
            $Result[0].AdminTierLevelName | Should -Be "UserAccess"
            $script:WarningMessages.Count | Should -Be 0
        }

        It "drops Unclassified entries but keeps real classifications for mixed exports" {
            $Cache = @{
                "ResourceApps:ByObjectId" = @{
                    "service-principal-id" = @([pscustomobject]@{
                            Classification = @(
                                [pscustomobject]@{ AdminTierLevel = "3"; AdminTierLevelName = "Unclassified"; Service = "Unclassified" }
                                [pscustomobject]@{ AdminTierLevel = "2"; AdminTierLevelName = "UserAccess"; Service = "Collaboration" }
                            )
                        })
                }
            }

            $Result = @(Get-EntraOpsPrivilegedEamAccessPackageResourceRoleScopeClassification -ResourceRoleScopes @($script:ApplicationScope) -FilterClassifiedRbacs @("Azure") -ClassificationCache $Cache -ApiPermissionsClassLookup @{} -ContextLabel "test package" -WarningMessages $script:WarningMessages)

            $Result.AdminTierLevelName | Should -Not -Contain "Unclassified"
            $Result.AdminTierLevelName | Should -Contain "UserAccess"
        }
    }

    Context "SharePointOnline role classification" {
        It "maps <RoleName> (originId <RoleOriginId>) to <ExpectedTier>" -TestCases @(
            @{ RoleName = "Give Site Visitors"; RoleOriginId = "4"; ExpectedTier = "UserAccess" }
            @{ RoleName = "Site Members"; RoleOriginId = "5"; ExpectedTier = "UserAccess" }
            @{ RoleName = "Site Owners"; RoleOriginId = "3"; ExpectedTier = "ManagementPlane" }
            @{ RoleName = "Full Control"; RoleOriginId = ""; ExpectedTier = "ManagementPlane" }
            @{ RoleName = "Custom Role"; RoleOriginId = "17"; ExpectedTier = "ManagementPlane" }
            # Localized default groups resolve via the locale-independent site group IDs
            @{ RoleName = "Besucher von Give"; RoleOriginId = "4"; ExpectedTier = "UserAccess" }
            @{ RoleName = "Besitzer von Give"; RoleOriginId = "3"; ExpectedTier = "ManagementPlane" }
        ) {
            $Scope = [pscustomobject]@{
                accessPackageResourceRole  = [pscustomobject]@{ displayName = $RoleName; originId = $RoleOriginId }
                accessPackageResourceScope = [pscustomobject]@{
                    originSystem = "SharePointOnline"
                    originId     = "https://contoso.sharepoint.com/sites/give"
                    displayName  = "Give"
                }
            }
            $Warnings = [System.Collections.Generic.List[psobject]]::new()

            $Result = @(Get-EntraOpsPrivilegedEamAccessPackageResourceRoleScopeClassification -ResourceRoleScopes @($Scope) -FilterClassifiedRbacs @("Azure") -ClassificationCache @{} -ApiPermissionsClassLookup @{} -ContextLabel "test package" -WarningMessages $Warnings)

            $Result.Count | Should -Be 1
            $Result[0].AdminTierLevelName | Should -Be $ExpectedTier
            if ($RoleName -eq "Custom Role") {
                $Warnings[0].Type | Should -Be "Unknown SharePoint Role"
            } else {
                $Warnings.Count | Should -Be 0
            }
        }
    }
}

