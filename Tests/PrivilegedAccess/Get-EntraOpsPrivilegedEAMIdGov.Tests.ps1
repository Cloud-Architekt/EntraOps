#Requires -Modules Pester

Describe 'Get-EntraOpsPrivilegedEAMIdGov classification sources' {
    BeforeAll {
        $script:TestRepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
        Import-Module (Join-Path $script:TestRepositoryRoot 'EntraOps/EntraOps.psd1') -Force -WarningAction SilentlyContinue
        $script:PreviousTenantNameContext = $Global:TenantNameContext
    }

    AfterAll {
        $Global:TenantNameContext = $script:PreviousTenantNameContext
        Remove-Module EntraOps -Force -ErrorAction SilentlyContinue
    }

    BeforeEach {
        $Global:TenantNameContext = 'contoso.onmicrosoft.com'
        $script:ClassificationFolder = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path (Join-Path $script:ClassificationFolder 'Templates') -Force | Out-Null
        '[]' | Set-Content -Path (Join-Path $script:ClassificationFolder 'Templates/Classification_ApiPermissions.json')
        $script:CapturedWarnings = $null

        Mock -ModuleName EntraOps Resolve-EntraOpsClassificationPath { 'Classification_IdentityGovernance.json' }
        Mock -ModuleName EntraOps Invoke-RestMethod { @() }
        Mock -ModuleName EntraOps Import-EntraOpsGlobalExclusions { @() }
        Mock -ModuleName EntraOps Get-EntraOpsPrivilegedIdGovRoles {
            @([pscustomobject]@{
                    RoleAssignmentId      = 'assignment-1'
                    RoleAssignmentScopeId = '/'
                    RoleDefinitionId      = 'role-1'
                    RoleDefinitionName    = 'Catalog creator'
                    ObjectId              = '11111111-1111-1111-1111-111111111111'
                    ObjectType            = 'user'
                })
        }
        Mock -ModuleName EntraOps Invoke-EntraOpsMsGraphQuery { @() }
        Mock -ModuleName EntraOps Expand-EntraOpsPrivilegedEAMJsonFile { @() }
        Mock -ModuleName EntraOps Import-EntraOpsClassificationOverwrites { [pscustomobject]@{ RoleDefinitionOverwrites = @() } }
        Mock -ModuleName EntraOps Invoke-EntraOpsParallelObjectResolution { @{} }
        Mock -ModuleName EntraOps Invoke-EntraOpsEAMClassificationAggregation { @() }
        Mock -ModuleName EntraOps Show-EntraOpsWarningSummary { $script:CapturedWarnings = @($WarningMessages) }
    }

    It 'loads the RBAC system exports from an EAM folder without trailing separator' {
        # Connect-EntraOps and Invoke-EntraOpsPrivilegedEAM set DefaultFolderClassifiedEam without a trailing separator
        $EamFolder = Join-Path $TestDrive "PrivilegedEAM$([guid]::NewGuid().ToString('N'))"
        foreach ($RbacSystem in 'Azure', 'EntraID', 'DeviceManagement') {
            New-Item -ItemType Directory -Path (Join-Path $EamFolder $RbacSystem) -Force | Out-Null
            '[{"ObjectId":"22222222-2222-2222-2222-222222222222","RoleAssignments":[]}]' | Set-Content -Path (Join-Path $EamFolder "$RbacSystem/$RbacSystem.json")
        }

        $null = Get-EntraOpsPrivilegedEamIdGov -TenantId '99999999-9999-9999-9999-999999999999' -FolderClassification $script:ClassificationFolder -FolderClassifiedObjects $EamFolder.TrimEnd('/', '\') -GlobalExclusion $false -EnableParallelProcessing $false 6>$null

        @($script:CapturedWarnings | Where-Object { $_.Type -in 'Classification Source Missing', 'Classification Source Empty' -and $_.Target -ne 'ResourceApps' }).Target | Should -BeNullOrEmpty
    }
}
