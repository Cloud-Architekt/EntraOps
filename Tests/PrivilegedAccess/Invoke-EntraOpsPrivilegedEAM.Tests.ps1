#Requires -Modules Pester

Describe 'Invoke-EntraOpsPrivilegedEAM session working folder' {
    BeforeAll {
        $script:TestRepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
        $script:OriginalEntraOpsRoot = $env:ENTRAOPS_ROOT
        $script:SessionVariableNames = @(
            'EntraOpsBaseFolder', 'TenantIdContext', 'TenantNameContext',
            'DefaultFolderClassification', 'DefaultFolderClassifiedEam', 'XdrAvdHuntingAccess',
            'ManagingTenantIdContext', 'ManagingTenantNameContext', 'EntraOpsConfig', 'EntraOpsIncludeObjectDetails'
        )
        $script:OriginalVariables = @{}
        foreach ($Name in $script:SessionVariableNames) {
            $Variable = Get-Variable -Name $Name -Scope Global -ErrorAction SilentlyContinue
            if ($Variable) { $script:OriginalVariables[$Name] = $Variable.Value }
        }

        # Separator-agnostic path comparison: the module builds '<base>/Classification/' while Join-Path emits '\' on Windows.
        function ConvertTo-ComparablePath {
            param ([string]$Path)
            [System.IO.Path]::GetFullPath($Path).TrimEnd([char[]]@('/', '\'))
        }

        $script:ImportFolder = Join-Path $TestDrive 'import-folder'
        $env:ENTRAOPS_ROOT = $script:ImportFolder
        Import-Module (Join-Path $script:TestRepositoryRoot 'EntraOps/EntraOps.psd1') -Force -WarningAction SilentlyContinue

        # Mock needs an existing command; CI runners do not always have the Az/Microsoft Graph modules installed.
        $script:CommandStubs = @(foreach ($CommandName in 'Get-AzContext', 'Get-AzTenant', 'Get-MgContext') {
                if (-not (Get-Command -Name $CommandName -ErrorAction SilentlyContinue)) {
                    Set-Item -Path "Function:\global:$CommandName" -Value { throw "$($MyInvocation.MyCommand.Name) must be mocked" }
                    $CommandName
                }
            })
    }

    AfterAll {
        foreach ($CommandName in $script:CommandStubs) {
            Remove-Item -Path "Function:\$CommandName" -ErrorAction SilentlyContinue
        }
        $env:ENTRAOPS_ROOT = $script:OriginalEntraOpsRoot
        foreach ($Name in $script:SessionVariableNames) {
            if ($script:OriginalVariables.ContainsKey($Name)) {
                Set-Variable -Name $Name -Value $script:OriginalVariables[$Name] -Scope Global
            } else {
                Remove-Variable -Name $Name -Scope Global -ErrorAction SilentlyContinue
            }
        }
        Remove-Module EntraOps -Force
    }

    BeforeEach {
        foreach ($Name in $script:SessionVariableNames | Where-Object { $_ -ne 'EntraOpsBaseFolder' }) {
            Remove-Variable -Name $Name -Scope Global -ErrorAction SilentlyContinue
        }
        & (Get-Module EntraOps) { $__EntraOpsSession.Remove('ConfigFilePath'); $__EntraOpsSession.Remove('UseInvokeRestMethodOnly') }
        $script:Workspace = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
        $Global:EntraOpsBaseFolder = $script:ImportFolder
        $script:ArchiveFolder = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path "$script:ArchiveFolder/source/Reports" -Force | Out-Null
        Set-Content -LiteralPath "$script:ArchiveFolder/source/Reports/index.html" -Value 'report'

        Mock -ModuleName EntraOps Get-EntraOpsSourceArchive {
            [pscustomobject]@{ SourceRoot = "$script:ArchiveFolder/source"; TemporaryFolder = $script:ArchiveFolder; Repository = 'EntraOps' }
        }
        Mock -ModuleName EntraOps Get-AzContext {
            [pscustomobject]@{ Account = @{ Id = 'test@example.com' }; Tenant = @{ Id = '00000000-0000-0000-0000-000000000001' } }
        }
        Mock -ModuleName EntraOps Get-MgContext {
            [pscustomobject]@{ Account = 'test@example.com'; TenantId = '00000000-0000-0000-0000-000000000001'; Scopes = @() }
        }
        Mock -ModuleName EntraOps Get-AzTenant { [pscustomobject]@{ Domains = @('contoso.onmicrosoft.com') } }
        Mock -ModuleName EntraOps Update-EntraOpsClassificationFiles {
            $Path = Join-Path $FolderClassification 'Classification_AadResources.json'
            if (-not $SkipExisting -or -not (Test-Path -LiteralPath $Path)) { Set-Content -LiteralPath $Path -Value '{}' }
        }
        Mock -ModuleName EntraOps Update-EntraOpsClassificationControlPlaneScope {
            $Names = @{ EntraID = 'AadResources'; Azure = 'Azure'; DeviceManagement = 'DeviceManagement'; Defender = 'Defender'; IdentityGovernance = 'IdentityGovernance'; ResourceApps = 'ApiPermissions' }
            foreach ($Scope in $ClassificationParameterScope) {
                Set-Content -LiteralPath (Join-Path $Global:DefaultFolderClassification "contoso.onmicrosoft.com/Classification_$($Names[$Scope]).json") -Value '{}'
                Set-Content -LiteralPath (Join-Path $Global:DefaultFolderClassification "contoso.onmicrosoft.com/ScopeReasoning_$Scope.json") -Value '{"refreshed":true}'
            }
        }
        Mock -ModuleName EntraOps Save-EntraOpsPrivilegedEAMJson {
            New-Item -ItemType Directory -Path (Join-Path $ExportFolder 'EntraID') -Force | Out-Null
            Set-Content -LiteralPath (Join-Path $ExportFolder 'EntraID/EntraID.json') -Value '[]'
        }
        Mock -ModuleName EntraOps Disconnect-EntraOps {}
        Mock -ModuleName EntraOps Start-Sleep {}
        Mock -ModuleName EntraOps Write-Host {}
        Mock -ModuleName EntraOps Read-Host { 'R' }

        Initialize-EntraOpsWorkspace -Path $script:Workspace -Content Reports | Out-Null
        Push-Location $script:Workspace
        $script:Config = @{
            TenantId = '00000000-0000-0000-0000-000000000001'
            TenantName = 'contoso.onmicrosoft.com'
            RbacSystems = @('EntraID', 'Defender')
            AzureRbacClassification = @{ UnresolvedRoleDefinitionFallbackTier = 'ControlPlane' }
            AutomatedClassificationUpdate = @{ Classifications = @('AadResources', 'Defender') }
            AutomatedControlPlaneScopeUpdate = @{
                ClassificationParameterScope = @('EntraID', 'Defender')
                PrivilegedObjectClassificationSource = @('EntraOps', 'PrivilegedRolesFromAzGraph')
                AzureHighPrivilegedRoles = @('Owner')
                AzureHighPrivilegedScopes = @('/subscriptions/test')
                ExposureCriticalityLevel = '<2'
                DeviceMgmtPrivilegedTierScope = 'ControlPlaneDevicesOnly'
            }
        }
    }

    AfterEach { Pop-Location }

    It 'keeps exports and classification files in the workspace selected after module import' {
        Invoke-EntraOpsPrivilegedEAM -KeepClassificationFiles -RbacSystems 'EntraID'

        Test-Path -LiteralPath "$script:Workspace/PrivilegedEAM/EntraID/EntraID.json" | Should -BeTrue
        Test-Path -LiteralPath "$script:Workspace/Classification/Templates/Classification_AadResources.json" | Should -BeTrue
        Test-Path -LiteralPath "$script:Workspace/Classification/contoso.onmicrosoft.com/Classification_AadResources.json" | Should -BeTrue
        Test-Path -LiteralPath $script:ImportFolder | Should -BeFalse
        ConvertTo-ComparablePath $Global:DefaultFolderClassifiedEam | Should -Be (ConvertTo-ComparablePath (Join-Path $script:Workspace 'PrivilegedEAM'))
        ConvertTo-ComparablePath $Global:DefaultFolderClassification | Should -Be (ConvertTo-ComparablePath (Join-Path $script:Workspace 'Classification'))
    }

    It 'honors an explicit export folder while keeping classification in the selected workspace' {
        $ExportPath = Join-Path $TestDrive 'custom-export'
        Invoke-EntraOpsPrivilegedEAM -KeepClassificationFiles -RbacSystems 'EntraID' -ExportFolder $ExportPath

        Test-Path -LiteralPath "$ExportPath/EntraID/EntraID.json" | Should -BeTrue
        Test-Path -LiteralPath "$script:Workspace/Classification/Templates/Classification_AadResources.json" | Should -BeTrue
        Test-Path -LiteralPath "$script:Workspace/Classification/contoso.onmicrosoft.com/Classification_AadResources.json" | Should -BeTrue
        Test-Path -LiteralPath "$script:Workspace/PrivilegedEAM" | Should -BeFalse
        Test-Path -LiteralPath $script:ImportFolder | Should -BeFalse
        ConvertTo-ComparablePath $Global:DefaultFolderClassifiedEam | Should -Be (ConvertTo-ComparablePath $ExportPath)
    }

    It 'uses zero-config defaults when no configuration is present' {
        Invoke-EntraOpsPrivilegedEAM -RbacSystems EntraID

        Should -Invoke Write-Host -ModuleName EntraOps -Times 1 -Exactly -ParameterFilter { "$Object" -match 'Zero-Config Run' }
        $Global:EntraOpsConfig.AzureRbacClassification.UnresolvedRoleDefinitionFallbackTier | Should -Be 'Unclassified'
        Test-Path "$script:Workspace/Classification" | Should -BeFalse
        Should -Invoke Read-Host -ModuleName EntraOps -Times 0 -Exactly
    }

    It 'detects the working folder configuration and reports the full path in yellow' {
        $script:ConfigPath = Join-Path $script:Workspace 'EntraOpsConfig.json'
        $script:Config | ConvertTo-Json -Depth 10 | Set-Content $script:ConfigPath

        Invoke-EntraOpsPrivilegedEAM -KeepClassificationFiles

        $Global:EntraOpsConfig.AzureRbacClassification.UnresolvedRoleDefinitionFallbackTier | Should -Be 'ControlPlane'
        Should -Invoke Write-Host -ModuleName EntraOps -Times 1 -Exactly -ParameterFilter { "$Object" -match 'Config File' -and "$Object" -like "*$script:ConfigPath*" -and $ForegroundColor -eq 'Yellow' }
        Should -Invoke Write-Host -ModuleName EntraOps -Times 0 -Exactly -ParameterFilter { "$Object" -match 'Zero-Config Run' }
        Should -Invoke Save-EntraOpsPrivilegedEAMJson -ModuleName EntraOps -Times 2 -Exactly -ParameterFilter { @($RbacSystems).Count -eq 2 -and 'Defender' -in $RbacSystems }
        Should -Invoke Update-EntraOpsClassificationControlPlaneScope -ModuleName EntraOps -Times 2 -Exactly -ParameterFilter {
            @($PrivilegedObjectClassificationSource).Count -eq 2 -and $AzureHighPrivilegedRoles -eq 'Owner' -and
            $AzureHighPrivilegedScopes -eq '/subscriptions/test' -and $ExposureCriticalityLevel -eq '<2' -and
            $DeviceMgmtPrivilegedTierScope -eq 'ControlPlaneDevicesOnly' -and 'Defender' -in $ClassificationParameterScope
        }
        Should -Invoke Update-EntraOpsClassificationFiles -ModuleName EntraOps -Times 1 -Exactly -ParameterFilter { -not $SkipExisting -and @($Classifications).Count -eq 2 -and 'Defender' -in $Classifications }
    }

    It 'prefers the configuration loaded by Connect-EntraOps and preserves session folders' {
        $script:ConfigPath = Join-Path $TestDrive 'connected-config.json'
        $Global:EntraOpsConfig = $script:Config
        & (Get-Module EntraOps) { param($Path) $__EntraOpsSession['ConfigFilePath'] = $Path } $script:ConfigPath
        $Global:DefaultFolderClassifiedEam = Join-Path $script:Workspace 'PrivilegedEAM/contoso.onmicrosoft.com'
        $Global:DefaultFolderClassification = Join-Path $script:Workspace 'custom-classification'
        '{ "TenantId": "another-tenant" }' | Set-Content (Join-Path $script:Workspace 'EntraOpsConfig.json')

        Invoke-EntraOpsPrivilegedEAM -KeepClassificationFiles

        [object]::ReferenceEquals($Global:EntraOpsConfig, $script:Config) | Should -BeTrue
        Test-Path "$script:Workspace/PrivilegedEAM/contoso.onmicrosoft.com/EntraID/EntraID.json" | Should -BeTrue
        Test-Path "$script:Workspace/custom-classification/contoso.onmicrosoft.com/Classification_AadResources.json" | Should -BeTrue
        Should -Invoke Write-Host -ModuleName EntraOps -Times 1 -Exactly -ParameterFilter { "$Object" -like "*Config File*$script:ConfigPath*" -and $ForegroundColor -eq 'Yellow' }
    }

    It 'uses the configuration and absolute source path initialized by Connect-EntraOps' {
        Mock -ModuleName EntraOps Install-EntraOpsRequiredModule {}
        $script:ConfigPath = Join-Path $script:Workspace 'EntraOpsConfig.json'
        $script:Config | ConvertTo-Json -Depth 10 | Set-Content $script:ConfigPath
        Connect-EntraOps -AuthenticationType AlreadyAuthenticated -TenantName contoso.onmicrosoft.com -ConfigFilePath './EntraOpsConfig.json' -UseInvokeRestMethodOnly -NoWelcome
        # Reuse the initialized configuration rather than silently reloading an edited file.
        '{"TenantId":"another-tenant"}' | Set-Content $script:ConfigPath

        Invoke-EntraOpsPrivilegedEAM -KeepClassificationFiles

        $Global:EntraOpsConfig.AzureRbacClassification.UnresolvedRoleDefinitionFallbackTier | Should -Be 'ControlPlane'
        Should -Invoke Write-Host -ModuleName EntraOps -Times 1 -Exactly -ParameterFilter { "$Object" -like "*Config File*$script:ConfigPath*" -and $ForegroundColor -eq 'Yellow' }
        Should -Invoke Save-EntraOpsPrivilegedEAMJson -ModuleName EntraOps -Times 2 -Exactly -ParameterFilter { @($RbacSystems).Count -eq 2 -and 'Defender' -in $RbacSystems }
    }

    It 'lets explicit parameters override configuration values' {
        $Global:EntraOpsConfig = $script:Config
        $ExportPath = Join-Path $TestDrive 'override-export'

        Invoke-EntraOpsPrivilegedEAM -KeepClassificationFiles -RbacSystems Azure -ClassificationParameterScope Azure -PrivilegedObjectClassificationSource PrivilegedRolesFromAzGraph -ExportFolder $ExportPath

        Should -Invoke Save-EntraOpsPrivilegedEAMJson -ModuleName EntraOps -Times 2 -Exactly -ParameterFilter { @($RbacSystems).Count -eq 1 -and $RbacSystems -contains 'Azure' -and $ExportFolder -eq $ExportPath }
        Should -Invoke Update-EntraOpsClassificationControlPlaneScope -ModuleName EntraOps -Times 2 -Exactly -ParameterFilter { @($ClassificationParameterScope).Count -eq 1 -and $ClassificationParameterScope -contains 'Azure' -and @($PrivilegedObjectClassificationSource).Count -eq 1 -and $PrivilegedObjectClassificationSource -contains 'PrivilegedRolesFromAzGraph' }
    }

    It 'lets an explicit config file override a loaded configuration' {
        $Global:EntraOpsConfig = @{ TenantId = 'another-tenant' }
        $ConfigPath = Join-Path $TestDrive 'explicit.json'
        $script:Config | ConvertTo-Json -Depth 10 | Set-Content $ConfigPath

        Invoke-EntraOpsPrivilegedEAM -ConfigFilePath $ConfigPath -KeepClassificationFiles

        $Global:EntraOpsConfig.TenantId | Should -Be $script:Config.TenantId
    }

    It 'falls back to the base folder when the current folder has no config' {
        $script:Config | ConvertTo-Json -Depth 10 | Set-Content (Join-Path $script:Workspace 'EntraOpsConfig.json')
        $OtherFolder = Join-Path $TestDrive 'other-folder'
        New-Item -ItemType Directory -Path $OtherFolder -Force | Out-Null
        Push-Location $OtherFolder
        try { Invoke-EntraOpsPrivilegedEAM -KeepClassificationFiles } finally { Pop-Location }

        $Global:EntraOpsConfig.RbacSystems | Should -Contain 'Defender'
    }

    It 'rejects a config for another tenant before changing classification files' {
        $script:Config.TenantId = 'another-tenant'
        $script:Config | ConvertTo-Json -Depth 10 | Set-Content (Join-Path $script:Workspace 'EntraOpsConfig.json')

        { Invoke-EntraOpsPrivilegedEAM } | Should -Throw '*does not match the active Azure tenant*'

        Should -Invoke Update-EntraOpsClassificationFiles -ModuleName EntraOps -Times 0 -Exactly
        Should -Invoke Save-EntraOpsPrivilegedEAMJson -ModuleName EntraOps -Times 0 -Exactly
    }

    It 'rejects a configuration with a foreign tenant name and no tenant ID' {
        $script:Config.Remove('TenantId')
        $script:Config.TenantName = 'fabrikam.onmicrosoft.com'
        $script:Config | ConvertTo-Json -Depth 10 | Set-Content (Join-Path $script:Workspace 'EntraOpsConfig.json')

        { Invoke-EntraOpsPrivilegedEAM -KeepClassificationFiles } | Should -Throw '*TenantName*does not match*'

        Should -Invoke Update-EntraOpsClassificationFiles -ModuleName EntraOps -Times 0 -Exactly
    }

    It 'rejects mismatched Azure and Graph contexts in a configured run' {
        $Global:EntraOpsConfig = $script:Config
        Mock -ModuleName EntraOps Get-MgContext { [pscustomobject]@{ TenantId = 'another-tenant' } }

        { Invoke-EntraOpsPrivilegedEAM -KeepClassificationFiles } | Should -Throw '*Microsoft Graph tenant*does not match*'

        Should -Invoke Save-EntraOpsPrivilegedEAMJson -ModuleName EntraOps -Times 0 -Exactly
    }

    It 'rejects mismatched Azure and Graph contexts in a zero-config run' {
        Mock -ModuleName EntraOps Get-MgContext { [pscustomobject]@{ TenantId = 'another-tenant' } }

        { Invoke-EntraOpsPrivilegedEAM -RbacSystems EntraID } | Should -Throw '*Microsoft Graph tenant*does not match*'

        Should -Invoke Write-Host -ModuleName EntraOps -Times 1 -Exactly -ParameterFilter { "$Object" -match 'Zero-Config Run' }
        Should -Invoke Update-EntraOpsClassificationFiles -ModuleName EntraOps -Times 0 -Exactly
        Should -Invoke Save-EntraOpsPrivilegedEAMJson -ModuleName EntraOps -Times 0 -Exactly
    }

    It 'warns before running filter expressions from an automatically found configuration' {
        $script:Config.AlternateObjectTierLevelAttributes = @{ User = @{ Enabled = $true; ControlPlane = '$Object.ObjectDisplayName -eq "admin"' } }
        $script:ConfigPath = Join-Path $script:Workspace 'EntraOpsConfig.json'
        $script:Config | ConvertTo-Json -Depth 10 | Set-Content $script:ConfigPath
        $script:Events = [System.Collections.Generic.List[string]]::new()
        Mock -ModuleName EntraOps Write-Warning { $script:Events.Add("warning:$Message") }
        Mock -ModuleName EntraOps Save-EntraOpsPrivilegedEAMJson { $script:Events.Add('export') }

        Invoke-EntraOpsPrivilegedEAM -KeepClassificationFiles -ExistingClassificationAction Reuse

        $FilterWarnings = @($script:Events | Where-Object { $_ -like 'warning:*AlternateObjectTierLevelAttributes*' })
        $FilterWarnings.Count | Should -Be 1
        $FilterWarnings[0] | Should -BeLike "*$script:ConfigPath*"
        $FilterWarnings[0] | Should -BeLike '*executed as PowerShell code*'
        $FilterWarnings[0] | Should -BeLike '*-ConfigFilePath*'
        $script:Events.IndexOf($FilterWarnings[0]) | Should -BeLessThan $script:Events.IndexOf('export')
        Should -Invoke Write-Warning -ModuleName EntraOps -Times 1 -Exactly -ParameterFilter { $Message -like '*AlternateObjectTierLevelAttributes*' }
    }

    It 'does not warn about filter expressions when the configuration is <Source>' -ForEach @(@{ Source = 'passed with -ConfigFilePath' }, @{ Source = 'loaded by Connect-EntraOps' }, @{ Source = 'found automatically without enabled filters' }) {
        $Filters = @{ User = @{ Enabled = $true; ControlPlane = '$true' } }
        if ($Source -like 'found*') { $Filters.User.Enabled = $false }
        $script:Config.AlternateObjectTierLevelAttributes = $Filters
        $ConfigPath = Join-Path $script:Workspace 'EntraOpsConfig.json'
        $script:Config | ConvertTo-Json -Depth 10 | Set-Content $ConfigPath
        Mock -ModuleName EntraOps Write-Warning {}

        switch -Wildcard ($Source) {
            'passed*' { Invoke-EntraOpsPrivilegedEAM -ConfigFilePath $ConfigPath -KeepClassificationFiles -ExistingClassificationAction Reuse }
            'loaded*' {
                $Global:EntraOpsConfig = $script:Config
                Invoke-EntraOpsPrivilegedEAM -KeepClassificationFiles -ExistingClassificationAction Reuse
            }
            default { Invoke-EntraOpsPrivilegedEAM -KeepClassificationFiles -ExistingClassificationAction Reuse }
        }

        Should -Invoke Write-Warning -ModuleName EntraOps -Times 0 -Exactly -ParameterFilter { $Message -like '*AlternateObjectTierLevelAttributes*' }
    }

    It 'fails without downloading or exporting when an explicit config file is missing' {
        { Invoke-EntraOpsPrivilegedEAM -ConfigFilePath './missing.json' } | Should -Throw

        Should -Invoke Update-EntraOpsClassificationFiles -ModuleName EntraOps -Times 0 -Exactly
        Should -Invoke Save-EntraOpsPrivilegedEAMJson -ModuleName EntraOps -Times 0 -Exactly
    }

    It 'rejects invalid JSON rather than falling back to defaults' {
        '{invalid' | Set-Content (Join-Path $script:Workspace 'EntraOpsConfig.json')

        { Invoke-EntraOpsPrivilegedEAM } | Should -Throw

        Should -Invoke Update-EntraOpsClassificationFiles -ModuleName EntraOps -Times 0 -Exactly
        Should -Invoke Save-EntraOpsPrivilegedEAMJson -ModuleName EntraOps -Times 0 -Exactly
    }

    It 'honors an empty configured classification parameter scope' {
        $script:Config.AutomatedControlPlaneScopeUpdate.ClassificationParameterScope = @()
        $Global:EntraOpsConfig = $script:Config

        Invoke-EntraOpsPrivilegedEAM -KeepClassificationFiles

        Should -Invoke Update-EntraOpsClassificationControlPlaneScope -ModuleName EntraOps -Times 0 -Exactly
        Should -Invoke Save-EntraOpsPrivilegedEAMJson -ModuleName EntraOps -Times 1 -Exactly
    }

    It 'reuses templates and preserves overwrite files while refreshing tenant classification and reasoning (Keep: <Keep>)' -ForEach @(@{ Keep = $true }, @{ Keep = $false }) {
        $TenantFolder = Join-Path $script:Workspace 'Classification/contoso.onmicrosoft.com'
        New-Item -ItemType Directory -Path "$TenantFolder/Archive", "$script:Workspace/Classification/Templates" -Force | Out-Null
        $ExistingPaths = @(
            "$TenantFolder/Classification_RoleActionOverwrites.json", "$TenantFolder/Classification_RoleDefinitionOverwrites.json",
            "$TenantFolder/Archive/Classification_AadResources.json", "$script:Workspace/Classification/Templates/Classification_AadResources.json",
            "$script:Workspace/Classification/Templates/Classification_RoleDefinitionOverwrites.json"
        )
        foreach ($Path in $ExistingPaths) { Set-Content -LiteralPath $Path -Value '[{"custom":"preserve"}]' }
        Set-Content "$TenantFolder/Classification_AadResources.json" -Value '[{"old":true}]'
        Set-Content "$TenantFolder/ScopeReasoning_EntraID.json" -Value '{"old":true}'
        Mock -ModuleName EntraOps Save-EntraOpsPrivilegedEAMJson {
            $Resolved = & (Get-Module EntraOps) { Resolve-EntraOpsClassificationPath -ClassificationFileName 'Classification_AadResources.json' }
            Get-Content -LiteralPath $Resolved -Raw | Should -Match '^\{\}\s*$'
        }

        Invoke-EntraOpsPrivilegedEAM -KeepClassificationFiles:$Keep -RbacSystems EntraID

        foreach ($Path in $ExistingPaths) { Get-Content -LiteralPath $Path -Raw | Should -Be "[{`"custom`":`"preserve`"}]$([Environment]::NewLine)" }
        Get-Content "$TenantFolder/Classification_AadResources.json" -Raw | Should -Match '^\{\}\s*$'
        Get-Content "$TenantFolder/ScopeReasoning_EntraID.json" -Raw | Should -Match 'refreshed'
        Should -Invoke Update-EntraOpsClassificationControlPlaneScope -ModuleName EntraOps -Times 2 -Exactly -ParameterFilter { @($ClassificationParameterScope).Count -eq 1 -and $ClassificationParameterScope -contains 'EntraID' }
        Should -Invoke Save-EntraOpsPrivilegedEAMJson -ModuleName EntraOps -Times 2 -Exactly
        Should -Invoke Read-Host -ModuleName EntraOps -Times 1 -Exactly
    }

    It 'refreshes existing and generates missing tenant classifications on both bootstrap passes' {
        $TenantFolder = Join-Path $script:Workspace 'Classification/contoso.onmicrosoft.com'
        New-Item -ItemType Directory -Path $TenantFolder -Force | Out-Null
        Set-Content -LiteralPath "$TenantFolder/Classification_Azure.json" -Value '[{"custom":"preserve"}]'

        Invoke-EntraOpsPrivilegedEAM -KeepClassificationFiles -RbacSystems Azure, DeviceManagement

        Get-Content "$TenantFolder/Classification_Azure.json" -Raw | Should -Match '^\{\}\s*$'
        Test-Path "$TenantFolder/Classification_DeviceManagement.json" | Should -BeTrue
        Should -Invoke Update-EntraOpsClassificationControlPlaneScope -ModuleName EntraOps -Times 2 -Exactly -ParameterFilter { @($ClassificationParameterScope).Count -eq 2 -and $ClassificationParameterScope -contains 'DeviceManagement' -and $ClassificationParameterScope -contains 'Azure' }
    }

    It 'refreshes the selected existing classifications once when all prior EAM exports exist' {
        $TenantFolder = Join-Path $script:Workspace 'Classification/contoso.onmicrosoft.com'
        New-Item -ItemType Directory -Path $TenantFolder -Force | Out-Null
        Set-Content "$TenantFolder/Classification_AadResources.json" -Value '[{"old":true}]'
        Set-Content "$TenantFolder/Classification_Azure.json" -Value '[{"outsideSelectedScope":true}]'
        foreach ($System in 'EntraID', 'Azure') {
            New-Item -ItemType Directory -Path "$script:Workspace/PrivilegedEAM/$System" -Force | Out-Null
            Set-Content "$script:Workspace/PrivilegedEAM/$System/$System.json" -Value '[]'
        }

        Invoke-EntraOpsPrivilegedEAM -ExistingClassificationAction Reuse -RbacSystems EntraID, Azure -ClassificationParameterScope EntraID

        Get-Content "$TenantFolder/Classification_AadResources.json" -Raw | Should -Match '^\{\}\s*$'
        Get-Content "$TenantFolder/ScopeReasoning_EntraID.json" -Raw | Should -Match 'refreshed'
        Get-Content "$TenantFolder/Classification_Azure.json" -Raw | Should -Match 'outsideSelectedScope'
        Should -Invoke Update-EntraOpsClassificationControlPlaneScope -ModuleName EntraOps -Times 1 -Exactly -ParameterFilter { @($ClassificationParameterScope).Count -eq 1 -and $ClassificationParameterScope -contains 'EntraID' }
        Should -Invoke Save-EntraOpsPrivilegedEAMJson -ModuleName EntraOps -Times 1 -Exactly
    }

    It 'preserves reused templates, tenant overwrite files and refreshed definitions after export fails (Keep: <Keep>)' -ForEach @(@{ Keep = $true }, @{ Keep = $false }) {
        $TenantFolder = Join-Path $script:Workspace 'Classification/contoso.onmicrosoft.com'
        New-Item -ItemType Directory -Path $TenantFolder, "$script:Workspace/Classification/Templates" -Force | Out-Null
        Set-Content "$TenantFolder/Classification_AadResources.json" -Value '[{"old":true}]'
        Set-Content "$TenantFolder/Classification_RoleActionOverwrites.json" -Value '[{"custom":"preserve"}]'
        Set-Content "$TenantFolder/Classification_RoleDefinitionOverwrites.json" -Value '[{"custom":"preserve"}]'
        Set-Content "$script:Workspace/Classification/Templates/Classification_AadResources.json" -Value '[{"custom":"preserve"}]'
        Mock -ModuleName EntraOps Save-EntraOpsPrivilegedEAMJson { throw 'Export failed' }

        { Invoke-EntraOpsPrivilegedEAM -KeepClassificationFiles:$Keep -RbacSystems EntraID } | Should -Throw '*Export failed*'

        Get-Content "$TenantFolder/Classification_AadResources.json" -Raw | Should -Match '^\{\}\s*$'
        Get-Content "$TenantFolder/Classification_RoleActionOverwrites.json" -Raw | Should -Match 'preserve'
        Get-Content "$TenantFolder/Classification_RoleDefinitionOverwrites.json" -Raw | Should -Match 'preserve'
        Get-Content "$script:Workspace/Classification/Templates/Classification_AadResources.json" -Raw | Should -Match 'preserve'
    }

    It 'defaults to reuse when the prompt is accepted with Enter (Keep: <Keep>)' -ForEach @(@{ Keep = $true }, @{ Keep = $false }) {
        $TenantFolder = Join-Path $script:Workspace 'Classification/contoso.onmicrosoft.com'
        New-Item -ItemType Directory -Path $TenantFolder -Force | Out-Null
        Set-Content "$TenantFolder/Classification_AadResources.json" -Value '[{"custom":"preserve"}]'
        Mock -ModuleName EntraOps Read-Host { '' }

        Invoke-EntraOpsPrivilegedEAM -KeepClassificationFiles:$Keep -RbacSystems EntraID

        Get-Content "$TenantFolder/Classification_AadResources.json" -Raw | Should -Match '^\{\}\s*$'
        Should -Invoke Read-Host -ModuleName EntraOps -Times 1 -Exactly -ParameterFilter { $Prompt -match '\[R\] Reuse \(default\).*\[G\] Regenerate' }
        Should -Invoke Update-EntraOpsClassificationFiles -ModuleName EntraOps -Times 1 -Exactly -ParameterFilter { $SkipExisting }
        Should -Invoke Update-EntraOpsClassificationControlPlaneScope -ModuleName EntraOps -Times 2 -Exactly
    }

    It 'refreshes existing templates and tenant definitions when regeneration is selected (Keep: <Keep>)' -ForEach @(@{ Keep = $true }, @{ Keep = $false }) {
        $TenantFolder = Join-Path $script:Workspace 'Classification/contoso.onmicrosoft.com'
        New-Item -ItemType Directory -Path $TenantFolder, "$script:Workspace/Classification/Templates" -Force | Out-Null
        Set-Content "$TenantFolder/Classification_AadResources.json" -Value '[{"custom":"old"}]'
        Set-Content "$script:Workspace/Classification/Templates/Classification_AadResources.json" -Value '[{"custom":"old"}]'
        Mock -ModuleName EntraOps Read-Host { 'G' }

        Invoke-EntraOpsPrivilegedEAM -KeepClassificationFiles:$Keep -RbacSystems EntraID

        Get-Content "$TenantFolder/Classification_AadResources.json" -Raw | Should -Match '^\{\}\s*$'
        Get-Content "$script:Workspace/Classification/Templates/Classification_AadResources.json" -Raw | Should -Match '^\{\}\s*$'
        Should -Invoke Read-Host -ModuleName EntraOps -Times 1 -Exactly
        Should -Invoke Update-EntraOpsClassificationFiles -ModuleName EntraOps -Times 1 -Exactly -ParameterFilter { -not $SkipExisting }
        Should -Invoke Update-EntraOpsClassificationControlPlaneScope -ModuleName EntraOps -Times 2 -Exactly
    }

    It 'allows explicit reuse without prompting (Keep: <Keep>)' -ForEach @(@{ Keep = $true }, @{ Keep = $false }) {
        $TenantFolder = Join-Path $script:Workspace 'Classification/contoso.onmicrosoft.com'
        New-Item -ItemType Directory -Path $TenantFolder -Force | Out-Null
        Set-Content "$TenantFolder/Classification_AadResources.json" -Value '[{"custom":"preserve"}]'

        Invoke-EntraOpsPrivilegedEAM -KeepClassificationFiles:$Keep -ExistingClassificationAction Reuse -RbacSystems EntraID

        Get-Content "$TenantFolder/Classification_AadResources.json" -Raw | Should -Match '^\{\}\s*$'
        Should -Invoke Read-Host -ModuleName EntraOps -Times 0 -Exactly
        Should -Invoke Update-EntraOpsClassificationFiles -ModuleName EntraOps -Times 1 -Exactly -ParameterFilter { $SkipExisting }
        Should -Invoke Update-EntraOpsClassificationControlPlaneScope -ModuleName EntraOps -Times 2 -Exactly
    }

    It 'allows explicit regeneration without prompting (Keep: <Keep>)' -ForEach @(@{ Keep = $true }, @{ Keep = $false }) {
        $TenantFolder = Join-Path $script:Workspace 'Classification/contoso.onmicrosoft.com'
        New-Item -ItemType Directory -Path $TenantFolder -Force | Out-Null
        Set-Content "$TenantFolder/Classification_AadResources.json" -Value '[{"custom":"old"}]'

        Invoke-EntraOpsPrivilegedEAM -KeepClassificationFiles:$Keep -ExistingClassificationAction Regenerate -RbacSystems EntraID

        Get-Content "$TenantFolder/Classification_AadResources.json" -Raw | Should -Match '^\{\}\s*$'
        Should -Invoke Read-Host -ModuleName EntraOps -Times 0 -Exactly
        Should -Invoke Update-EntraOpsClassificationFiles -ModuleName EntraOps -Times 1 -Exactly -ParameterFilter { -not $SkipExisting }
        Should -Invoke Update-EntraOpsClassificationControlPlaneScope -ModuleName EntraOps -Times 2 -Exactly
    }

    It 'asks again after an invalid response' {
        $TenantFolder = Join-Path $script:Workspace 'Classification/contoso.onmicrosoft.com'
        New-Item -ItemType Directory -Path $TenantFolder -Force | Out-Null
        Set-Content "$TenantFolder/Classification_AadResources.json" -Value '[]'
        $script:PromptResponses = [System.Collections.Generic.Queue[string]]::new()
        $script:PromptResponses.Enqueue('invalid')
        $script:PromptResponses.Enqueue(' reuse ')
        Mock -ModuleName EntraOps Read-Host { $script:PromptResponses.Dequeue() }

        Invoke-EntraOpsPrivilegedEAM -RbacSystems EntraID

        Should -Invoke Read-Host -ModuleName EntraOps -Times 2 -Exactly
        Should -Invoke Update-EntraOpsClassificationControlPlaneScope -ModuleName EntraOps -Times 2 -Exactly
    }

    It 'does not prompt for classification files belonging to another tenant or an archive' {
        $Root = Join-Path $script:Workspace 'Classification'
        New-Item -ItemType Directory -Path "$Root/fabrikam.onmicrosoft.com", "$Root/contoso.onmicrosoft.com/Archive" -Force | Out-Null
        Set-Content "$Root/fabrikam.onmicrosoft.com/Classification_AadResources.json" -Value '[]'
        Set-Content "$Root/contoso.onmicrosoft.com/Archive/Classification_AadResources.json" -Value '[]'

        Invoke-EntraOpsPrivilegedEAM -KeepClassificationFiles -RbacSystems EntraID

        Should -Invoke Read-Host -ModuleName EntraOps -Times 0 -Exactly
        Should -Invoke Update-EntraOpsClassificationControlPlaneScope -ModuleName EntraOps -Times 2 -Exactly
    }

    It 'fails before updating files if the host cannot prompt' {
        $TenantFolder = Join-Path $script:Workspace 'Classification/contoso.onmicrosoft.com'
        New-Item -ItemType Directory -Path $TenantFolder -Force | Out-Null
        Set-Content "$TenantFolder/Classification_AadResources.json" -Value '[{"custom":"preserve"}]'
        Mock -ModuleName EntraOps Read-Host { throw 'PowerShell is in NonInteractive mode.' }

        { Invoke-EntraOpsPrivilegedEAM -KeepClassificationFiles -RbacSystems EntraID } | Should -Throw '*ExistingClassificationAction Reuse or Regenerate*'

        Get-Content "$TenantFolder/Classification_AadResources.json" -Raw | Should -Match 'preserve'
        Should -Invoke Update-EntraOpsClassificationFiles -ModuleName EntraOps -Times 0 -Exactly
        Should -Invoke Save-EntraOpsPrivilegedEAMJson -ModuleName EntraOps -Times 0 -Exactly
    }
}
