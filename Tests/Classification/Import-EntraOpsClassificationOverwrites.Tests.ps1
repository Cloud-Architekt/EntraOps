#Requires -Modules Pester

BeforeAll {
    $script:TestRepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
    Import-Module (Join-Path $script:TestRepositoryRoot 'EntraOps/EntraOps.psd1') -Force -WarningAction SilentlyContinue

    function New-OverwriteFile {
        param([string]$Path, [object[]]$Entries)
        New-Item -ItemType Directory -Path (Split-Path -Parent $Path) -Force | Out-Null
        ConvertTo-Json -InputObject @($Entries) -Depth 5 | Set-Content -LiteralPath $Path -Encoding UTF8
    }
}

Describe 'Get-EntraOpsClassificationOverwriteFile' {
    It 'returns the base file first and the tagged variants by name with the text after the last underscore as tag' {
        $Folder = Join-Path $TestDrive 'files'
        foreach ($Name in 'Classification_RoleDefinitionOverwrites_Zeta.json', 'Classification_RoleDefinitionOverwrites.json',
            'Classification_RoleDefinitionOverwrites_Tier0_PAW.json', 'Classification_RoleDefinitionOverwrites_.json',
            'Classification_RoleActionOverwrites_PAW.json', 'Classification_RoleDefinitionOverwritesPAW.json') {
            New-OverwriteFile -Path (Join-Path $Folder $Name) -Entries @()
        }

        $Files = InModuleScope EntraOps -Parameters @{ Folder = $Folder } {
            Get-EntraOpsClassificationOverwriteFile -Folder $Folder -BaseName 'Classification_RoleDefinitionOverwrites.json'
        }

        @($Files.Name) | Should -Be @('Classification_RoleDefinitionOverwrites.json', 'Classification_RoleDefinitionOverwrites_Tier0_PAW.json', 'Classification_RoleDefinitionOverwrites_Zeta.json')
        $Files[0].Tag | Should -BeNullOrEmpty
        @($Files[1..2].Tag) | Should -Be @('PAW', 'Zeta')
    }

    It 'recognizes base and tagged overwrite files of every type for preservation' {
        InModuleScope EntraOps {
            Test-EntraOpsClassificationOverwriteFileName -Name 'Classification_RoleActionOverwrites.json' | Should -BeTrue
            Test-EntraOpsClassificationOverwriteFileName -Name 'Classification_RoleDefinitionOverwrites_PAW.json' | Should -BeTrue
            Test-EntraOpsClassificationOverwriteFileName -Name 'Classification_ApiPermissionOverwrites_Graph.json' | Should -BeTrue
            Test-EntraOpsClassificationOverwriteFileName -Name 'Classification_AadResources.json' | Should -BeFalse
            Test-EntraOpsClassificationOverwriteFileName -Name 'Classification_RoleDefinitionOverwrites.json.bak' | Should -BeFalse
        }
    }
}

Describe 'Import-EntraOpsClassificationOverwrites with tagged files' {
    BeforeEach {
        $script:Root = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
        $script:Tenant = Join-Path $script:Root 'contoso.onmicrosoft.com'
        $script:Templates = Join-Path $script:Root 'Templates'
    }

    It 'loads the tenant base and tagged role action files in order and keeps their source file' {
        New-OverwriteFile -Path (Join-Path $script:Tenant 'Classification_RoleActionOverwrites.json') -Entries @(
            @{ RbacSystem = 'EntraID'; RoleDefinitionActions = @('microsoft.directory/a/read'); EAMTierLevelName = 'UserAccess'; Justification = 'base' })
        New-OverwriteFile -Path (Join-Path $script:Tenant 'Classification_RoleActionOverwrites_PAW.json') -Entries @(
            @{ RbacSystem = 'EntraID'; RoleDefinitionActions = @('microsoft.directory/a/read'); EAMTierLevelName = 'ControlPlane'; Justification = 'paw' })

        $Result = InModuleScope EntraOps -Parameters @{ Root = $script:Root } {
            $TenantNameContext = 'contoso.onmicrosoft.com'
            Import-EntraOpsClassificationOverwrites -RbacSystem 'EntraID' -FolderClassification $Root
        }

        @($Result.RoleActionOverwrites.SourceFile) | Should -Be @('Classification_RoleActionOverwrites.json', 'Classification_RoleActionOverwrites_PAW.json')
        # Applied in this order, so the tagged file's entry for the same action takes precedence
        $Result.RoleActionOverwrites[-1].EAMTierLevelName | Should -Be 'ControlPlane'
    }

    It 'loads tagged API permission files without a base file' {
        New-OverwriteFile -Path (Join-Path $script:Tenant 'Classification_ApiPermissionOverwrites_Graph.json') -Entries @(
            @{ PermissionValue = 'Mail.Read'; EAMTierLevelName = 'ManagementPlane'; Justification = 'graph' })

        $Result = InModuleScope EntraOps -Parameters @{ Root = $script:Root } {
            $TenantNameContext = 'contoso.onmicrosoft.com'
            Import-EntraOpsClassificationOverwrites -RbacSystem 'ResourceApps' -FolderClassification $Root
        }

        @($Result.ApiPermissionOverwrites).Count | Should -Be 1
        $Result.ApiPermissionOverwrites[0].SourceFile | Should -Be 'Classification_ApiPermissionOverwrites_Graph.json'
    }

    It 'adds tenant tagged role definition files to the Templates base file when the tenant has no base file' {
        New-OverwriteFile -Path (Join-Path $script:Templates 'Classification_RoleDefinitionOverwrites.json') -Entries @(
            @{ RbacSystem = 'EntraID'; RoleDefinitionName = 'Template Role'; EAMTierLevelName = 'ControlPlane'; Justification = 'template' })
        New-OverwriteFile -Path (Join-Path $script:Tenant 'Classification_RoleDefinitionOverwrites_PAW.json') -Entries @(
            @{ RbacSystem = 'EntraID'; RoleDefinitionName = 'PAW Role'; EAMTierLevelName = 'ControlPlane'; Justification = 'paw' })

        $Result = InModuleScope EntraOps -Parameters @{ Root = $script:Root } {
            $TenantNameContext = 'contoso.onmicrosoft.com'
            Import-EntraOpsClassificationOverwrites -RbacSystem 'EntraID' -FolderClassification $Root
        }

        @($Result.RoleDefinitionOverwrites.RoleDefinitionName) | Should -Be @('Template Role', 'PAW Role')
    }

    It 'prefers the tenant base role definition file over the template and still adds tagged files' {
        New-OverwriteFile -Path (Join-Path $script:Templates 'Classification_RoleDefinitionOverwrites.json') -Entries @(
            @{ RbacSystem = 'EntraID'; RoleDefinitionName = 'Template Role'; EAMTierLevelName = 'ControlPlane'; Justification = 'template' })
        New-OverwriteFile -Path (Join-Path $script:Tenant 'Classification_RoleDefinitionOverwrites.json') -Entries @(
            @{ RbacSystem = 'EntraID'; RoleDefinitionName = 'Tenant Role'; EAMTierLevelName = 'ManagementPlane'; Justification = 'tenant' })
        New-OverwriteFile -Path (Join-Path $script:Tenant 'Classification_RoleDefinitionOverwrites_PAW.json') -Entries @(
            @{ RbacSystem = 'EntraID'; RoleDefinitionName = 'PAW Role'; EAMTierLevelName = 'ControlPlane'; Justification = 'paw' })

        $Result = InModuleScope EntraOps -Parameters @{ Root = $script:Root } {
            $TenantNameContext = 'contoso.onmicrosoft.com'
            Import-EntraOpsClassificationOverwrites -RbacSystem 'EntraID' -FolderClassification $Root
        }

        @($Result.RoleDefinitionOverwrites.RoleDefinitionName) | Should -Be @('Tenant Role', 'PAW Role')
    }

    It 'applies the role definition precedence rules across files to the resulting classification' {
        $RoleId = '62e90394-69f5-4237-9190-012177145e10'
        # Base: whole-role pin by ID. Tagged: a name-only pin (ignored: an ID match exists) and a
        # service-specific entry (replaced: the whole-role entry is applied last).
        New-OverwriteFile -Path (Join-Path $script:Tenant 'Classification_RoleDefinitionOverwrites.json') -Entries @(
            @{ RbacSystem = 'EntraID'; RoleDefinitionId = $RoleId; EAMTierLevelName = 'ControlPlane'; Justification = 'base whole role' },
            @{ RbacSystem = 'EntraID'; RoleDefinitionName = 'Helpdesk Administrator'; Service = 'Helpdesk'; EAMTierLevelName = 'ControlPlane'; Justification = 'base helpdesk' })
        New-OverwriteFile -Path (Join-Path $script:Tenant 'Classification_RoleDefinitionOverwrites_PAW.json') -Entries @(
            @{ RbacSystem = 'EntraID'; RoleDefinitionName = 'Global Administrator'; EAMTierLevelName = 'UserAccess'; Justification = 'paw name only' },
            @{ RbacSystem = 'EntraID'; RoleDefinitionId = $RoleId; Service = 'Global'; EAMTierLevelName = 'ManagementPlane'; Justification = 'paw service' })
        # Same kind in both files (service-specific by name for another role): the later file wins
        New-OverwriteFile -Path (Join-Path $script:Tenant 'Classification_RoleDefinitionOverwrites_Zeta.json') -Entries @(
            @{ RbacSystem = 'EntraID'; RoleDefinitionName = 'Helpdesk Administrator'; Service = 'Helpdesk'; EAMTierLevelName = 'UserAccess'; Justification = 'zeta' })

        $Assignments = InModuleScope EntraOps -Parameters @{ Root = $script:Root; RoleId = $RoleId } {
            $TenantNameContext = 'contoso.onmicrosoft.com'
            $Overwrites = (Import-EntraOpsClassificationOverwrites -RbacSystem 'EntraID' -FolderClassification $Root 6>$null).RoleDefinitionOverwrites
            $Classified = @(
                [pscustomobject]@{ RoleDefinitionId = $RoleId; RoleDefinitionName = 'Global Administrator'; Classification = @([pscustomobject]@{ AdminTierLevel = '0'; AdminTierLevelName = 'ControlPlane'; Service = 'Global' }) },
                [pscustomobject]@{ RoleDefinitionId = 'helpdesk-id'; RoleDefinitionName = 'Helpdesk Administrator'; Classification = @([pscustomobject]@{ AdminTierLevel = '1'; AdminTierLevelName = 'ManagementPlane'; Service = 'Helpdesk' }) }
            )
            Invoke-EntraOpsClassificationRoleOverwrite -RbacClassifications $Classified -RoleDefinitionOverwrites $Overwrites -RoleSystem 'EntraID' 6>$null
        }

        $GlobalAdmin = $Assignments | Where-Object RoleDefinitionName -eq 'Global Administrator'
        @($GlobalAdmin.Classification).Count | Should -Be 1
        $GlobalAdmin.Classification[0].AdminTierLevelName | Should -Be 'ControlPlane'
        $Helpdesk = $Assignments | Where-Object RoleDefinitionName -eq 'Helpdesk Administrator'
        @($Helpdesk.Classification | Where-Object Service -eq 'Helpdesk').AdminTierLevelName | Should -Be 'UserAccess'
    }

    It 'lists entries of different files for the same item' {
        New-OverwriteFile -Path (Join-Path $script:Tenant 'Classification_RoleActionOverwrites.json') -Entries @(
            @{ RbacSystem = 'EntraID'; RoleDefinitionActions = @('microsoft.directory/a/read'); EAMTierLevelName = 'UserAccess'; Justification = 'base' })
        New-OverwriteFile -Path (Join-Path $script:Tenant 'Classification_RoleActionOverwrites_PAW.json') -Entries @(
            @{ RbacSystem = 'EntraID'; RoleDefinitionActions = @('microsoft.directory/a/read'); EAMTierLevelName = 'ControlPlane'; Justification = 'paw' })

        $Output = InModuleScope EntraOps -Parameters @{ Root = $script:Root } {
            $TenantNameContext = 'contoso.onmicrosoft.com'
            Import-EntraOpsClassificationOverwrites -RbacSystem 'EntraID' -FolderClassification $Root 6>&1 |
                Where-Object { $_ -is [System.Management.Automation.InformationRecord] } | ForEach-Object { "$_" }
        }
        ($Output -join "`n") | Should -Match "overlap \(EntraID\): role action 'microsoft.directory/a/read' on '/\*' is defined in Classification_RoleActionOverwrites.json, Classification_RoleActionOverwrites_PAW.json"
    }

    It 'lists an overlap once per entry and once per session for an unchanged file set' {
        $Role = @{ RbacSystem = 'EntraID'; RoleDefinitionId = '62e90394-69f5-4237-9190-012177145e10'; RoleDefinitionName = 'Global Administrator'; EAMTierLevelName = 'ControlPlane'; Justification = 'test' }
        New-OverwriteFile -Path (Join-Path $script:Tenant 'Classification_RoleDefinitionOverwrites.json') -Entries @($Role)
        New-OverwriteFile -Path (Join-Path $script:Tenant 'Classification_RoleDefinitionOverwrites_PAW.json') -Entries @($Role)

        $Output = InModuleScope EntraOps -Parameters @{ Root = $script:Root } {
            $TenantNameContext = 'contoso.onmicrosoft.com'
            foreach ($Run in 1..3) {
                Import-EntraOpsClassificationOverwrites -RbacSystem 'EntraID' -FolderClassification $Root 6>&1 |
                    Where-Object { $_ -is [System.Management.Automation.InformationRecord] } | ForEach-Object { "$_" }
            }
        }
        @($Output | Where-Object { $_ -like "*overlap (EntraID): role definition 'Global Administrator'*" }).Count | Should -Be 1
    }

    It 'ignores tagged files in the Templates folder' {
        New-OverwriteFile -Path (Join-Path $script:Templates 'Classification_RoleDefinitionOverwrites_PAW.json') -Entries @(
            @{ RbacSystem = 'EntraID'; RoleDefinitionName = 'PAW Role'; EAMTierLevelName = 'ControlPlane'; Justification = 'paw' })

        $Result = InModuleScope EntraOps -Parameters @{ Root = $script:Root } {
            $TenantNameContext = 'contoso.onmicrosoft.com'
            Import-EntraOpsClassificationOverwrites -RbacSystem 'EntraID' -FolderClassification $Root
        }

        @($Result.RoleDefinitionOverwrites).Count | Should -Be 0
    }
}
