#Requires -Modules Pester

BeforeDiscovery {
    $script:TestRepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
}

BeforeAll {
    $script:TestRepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
    function Invoke-RestMethod { param($Uri) throw "Invoke-RestMethod must be mocked" }
    function Get-AzContext { throw "Get-AzContext must be mocked" }
    function Connect-AzAccount { param($TenantId) throw "Connect-AzAccount must not be called" }
    function Get-AzTenant { param($TenantId) throw "Get-AzTenant must be mocked" }

    . "$script:TestRepositoryRoot/EntraOps/Private/Get-EntraOpsTenantGovernanceResourceDefinition.ps1"
    . "$script:TestRepositoryRoot/EntraOps/Public/Configuration/New-EntraOpsConfigFile.ps1"
    . "$script:TestRepositoryRoot/EntraOps/Public/PrivilegedAccess/New-EntraOpsPrivilegedAdministrativeUnit.ps1"
    . "$script:TestRepositoryRoot/EntraOps/Public/PrivilegedAccess/Update-EntraOpsPrivilegedAdministrativeUnit.ps1"
    . "$script:TestRepositoryRoot/EntraOps/Public/PrivilegedAccess/New-EntraOpsPrivilegedConditionalAccessGroup.ps1"
    . "$script:TestRepositoryRoot/EntraOps/Public/PrivilegedAccess/Update-EntraOpsPrivilegedConditionalAccessGroup.ps1"
    . "$script:TestRepositoryRoot/EntraOps/Public/PrivilegedAccess/New-EntraOpsPrivilegedUnprotectedAdministrativeUnit.ps1"
    . "$script:TestRepositoryRoot/EntraOps/Public/PrivilegedAccess/Update-EntraOpsPrivilegedUnprotectedAdministrativeUnit.ps1"
    . "$script:TestRepositoryRoot/EntraOps/Public/PrivilegedAccess/Update-EntraOpsPrivilegedUnprotectedElmCatalog.ps1"
}

Describe "Mutation configuration workflow splatting" {
    BeforeEach {
        $script:TenantId = '11111111-1111-1111-1111-111111111111'
        Mock Invoke-RestMethod {
            [pscustomobject]@{ token_endpoint = "https://login.windows.net/$script:TenantId/oauth2/token" }
        }
        Mock Get-AzContext { [pscustomobject]@{ Tenant = [pscustomobject]@{ Id = $script:TenantId } } }
        Mock Get-AzTenant { [pscustomobject]@{ Domains = @('contoso.onmicrosoft.com') } }
    }

    It "keeps every generated mutation section compatible with all workflow receivers" {
        $ConfigPath = Join-Path $TestDrive 'EntraOpsConfig.json'
        New-EntraOpsConfigFile -TenantName 'contoso.onmicrosoft.com' -ConfigFilePath $ConfigPath | Out-Null
        $Config = [System.IO.File]::ReadAllText($ConfigPath) | ConvertFrom-Json

        $SectionReceivers = [ordered]@{
            AutomatedAdministrativeUnitManagement         = @(
                'New-EntraOpsPrivilegedAdministrativeUnit'
                'Update-EntraOpsPrivilegedAdministrativeUnit'
            )
            AutomatedConditionalAccessTargetGroups        = @(
                'New-EntraOpsPrivilegedConditionalAccessGroup'
                'Update-EntraOpsPrivilegedConditionalAccessGroup'
            )
            AutomatedRmauAssignmentsForUnprotectedObjects = @(
                'New-EntraOpsPrivilegedUnprotectedAdministrativeUnit'
                'Update-EntraOpsPrivilegedUnprotectedAdministrativeUnit'
            )
            AutomatedElmCatalogProtection                 = @(
                'Update-EntraOpsPrivilegedUnprotectedElmCatalog'
            )
        }

        foreach ($SectionName in $SectionReceivers.Keys) {
            $SectionKeys = @($Config.$SectionName.PSObject.Properties.Name)
            foreach ($CommandName in $SectionReceivers[$SectionName]) {
                $Command = Get-Command $CommandName
                $UnsupportedKeys = @($SectionKeys | Where-Object { -not $Command.Parameters.ContainsKey($_) })
                $UnsupportedKeys | Should -BeNullOrEmpty -Because "$SectionName is splatted directly onto $CommandName by Push-EntraOpsPrivilegedEAM"
            }
        }
    }

    It "disables descriptive console object details in generated configuration by default" {
        $ConfigPath = Join-Path $TestDrive 'EntraOpsConfig.json'
        New-EntraOpsConfigFile -TenantName 'contoso.onmicrosoft.com' -ConfigFilePath $ConfigPath | Out-Null
        $Config = [System.IO.File]::ReadAllText($ConfigPath) | ConvertFrom-Json

        $Config.ConsoleOutput.IncludeObjectDetails | Should -BeFalse
    }

    It "generates safe automated-update validation defaults" {
        $ConfigPath = Join-Path $TestDrive 'EntraOpsConfig.json'
        New-EntraOpsConfigFile -TenantName 'contoso.onmicrosoft.com' -ConfigFilePath $ConfigPath | Out-Null
        $Config = [System.IO.File]::ReadAllText($ConfigPath) | ConvertFrom-Json

        $Config.AutomatedEntraOpsUpdate.ValidationFrequency | Should -Be 'OnChange'
        $Config.AutomatedEntraOpsUpdate.RunBrowserTests | Should -BeTrue
        @($Config.AutomatedEntraOpsUpdate.TargetUpdateFolders) | Should -Not -Contain './.github/workflows'
        $Config.ClassificationExplorer.GenerateChangeHistory | Should -BeFalse
    }

    It "generates Azure DevOps update targets and publication defaults" {
        $ConfigPath = Join-Path $TestDrive 'EntraOps-AzureDevOps.json'
        New-EntraOpsConfigFile -TenantName 'contoso.onmicrosoft.com' -DevOpsPlatform AzureDevOps -ConfigFilePath $ConfigPath | Out-Null
        $Config = [System.IO.File]::ReadAllText($ConfigPath) | ConvertFrom-Json

        $Config.DevOpsPlatform | Should -Be 'AzureDevOps'
        $Config.AutomatedEntraOpsUpdate.PublicationMode | Should -Be 'DirectPush'
        @($Config.AutomatedEntraOpsUpdate.TargetUpdateFolders) | Should -Contain './.azure-pipelines'
        @($Config.AutomatedEntraOpsUpdate.TargetUpdateFolders) | Should -Not -Contain './.github/actions'
    }

    It "writes explicitly selected automated-update validation options" {
        $ConfigPath = Join-Path $TestDrive 'EntraOpsConfig.json'
        New-EntraOpsConfigFile -TenantName 'contoso.onmicrosoft.com' -ConfigFilePath $ConfigPath `
            -ValidationFrequency Always -RunBrowserTests $false | Out-Null
        $Config = [System.IO.File]::ReadAllText($ConfigPath) | ConvertFrom-Json

        $Config.AutomatedEntraOpsUpdate.ValidationFrequency | Should -Be 'Always'
        $Config.AutomatedEntraOpsUpdate.RunBrowserTests | Should -BeFalse
    }

    It "writes an explicitly enabled Classification Explorer history setting" {
        $ConfigPath = Join-Path $TestDrive 'EntraOpsConfig.json'
        New-EntraOpsConfigFile -TenantName 'contoso.onmicrosoft.com' -ConfigFilePath $ConfigPath `
            -ClassificationExplorerGenerateChangeHistory $true | Out-Null
        $Config = [System.IO.File]::ReadAllText($ConfigPath) | ConvertFrom-Json

        $Config.ClassificationExplorer.GenerateChangeHistory | Should -BeTrue
    }

    It "keeps automated EntraOps scopes aligned with the selected RBAC systems" {
        $ConfigPath = Join-Path $TestDrive 'EntraOpsConfig.json'
        New-EntraOpsConfigFile -TenantName 'contoso.onmicrosoft.com' -ConfigFilePath $ConfigPath `
            -RbacSystems @('Azure', 'EntraID') | Out-Null
        $Config = [System.IO.File]::ReadAllText($ConfigPath) | ConvertFrom-Json

        @($Config.RbacSystems) | Should -Be @('Azure', 'EntraID')
        @($Config.AutomatedControlPlaneScopeUpdate.EntraOpsScopes) | Should -Be @('Azure', 'EntraID')
    }

    It "enables the Tenant Governance schedule only with the master feature switch" {
        $DisabledConfigPath = Join-Path $TestDrive 'TenantGovernanceDisabled.json'
        New-EntraOpsConfigFile -TenantName 'contoso.onmicrosoft.com' -ConfigFilePath $DisabledConfigPath | Out-Null
        $DisabledConfig = [System.IO.File]::ReadAllText($DisabledConfigPath) | ConvertFrom-Json

        $DisabledConfig.TenantGovernanceSnapshot.EnableTenantGovernanceSnapshot | Should -BeFalse
        $DisabledConfig.TenantGovernanceSnapshot.SnapshotScheduledTrigger | Should -BeFalse

        $EnabledConfigPath = Join-Path $TestDrive 'TenantGovernanceEnabled.json'
        New-EntraOpsConfigFile -TenantName 'contoso.onmicrosoft.com' -ConfigFilePath $EnabledConfigPath `
            -EnableTenantGovernanceSnapshot $true | Out-Null
        $EnabledConfig = [System.IO.File]::ReadAllText($EnabledConfigPath) | ConvertFrom-Json

        $EnabledConfig.TenantGovernanceSnapshot.EnableTenantGovernanceSnapshot | Should -BeTrue
        $EnabledConfig.TenantGovernanceSnapshot.SnapshotScheduledTrigger | Should -BeTrue
    }
}

