#Requires -Modules Pester

Describe 'Get-EntraOpsPrivilegedEAMDefender CloudSet warnings' {
    BeforeAll {
        $script:TestRepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
        Import-Module (Join-Path $script:TestRepositoryRoot 'EntraOps/EntraOps.psd1') -Force -WarningAction SilentlyContinue
        $script:PreviousTenantNameContext = $Global:TenantNameContext

        function New-DefenderAssignment {
            param([string]$ScopeId, [object[]]$SubscriptionScopes, [string]$Status, [string]$RoleDefinitionId = 'role-1')
            [pscustomobject]@{
                RoleAssignmentId           = [guid]::NewGuid().ToString()
                RoleAssignmentScopeId      = $ScopeId
                RoleAssignmentScopeName    = 'CloudSet'
                CloudSetSubscriptionScopes = $SubscriptionScopes
                ScopeResolutionStatus      = $Status
                RoleDefinitionId           = $RoleDefinitionId
                ObjectId                   = '11111111-1111-1111-1111-111111111111'
                ObjectType                 = 'user'
            }
        }
    }

    AfterAll {
        $Global:TenantNameContext = $script:PreviousTenantNameContext
        Remove-Module EntraOps -Force -ErrorAction SilentlyContinue
    }

    BeforeEach {
        $Global:TenantNameContext = 'contoso.onmicrosoft.com'
        $script:ClassificationFolder = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path (Join-Path $script:ClassificationFolder $Global:TenantNameContext) -Force | Out-Null
        $script:CapturedWarnings = $null

        Mock -ModuleName EntraOps Resolve-EntraOpsClassificationPath { 'Classification_Defender.json' }
        Mock -ModuleName EntraOps Import-EntraOpsGlobalExclusions { @() }
        Mock -ModuleName EntraOps Invoke-EntraOpsMsGraphQuery { @([pscustomobject]@{ Id = 'role-1'; rolePermissions = @() }) }
        Mock -ModuleName EntraOps Expand-EntraOpsPrivilegedEAMJsonFile { @() }
        Mock -ModuleName EntraOps Import-EntraOpsClassificationOverwrites { [pscustomobject]@{ RoleDefinitionOverwrites = @() } }
        Mock -ModuleName EntraOps Invoke-EntraOpsParallelObjectResolution { @{} }
        Mock -ModuleName EntraOps Invoke-EntraOpsEAMClassificationAggregation { @() }
        Mock -ModuleName EntraOps Show-EntraOpsWarningSummary { $script:CapturedWarnings = @($WarningMessages) }
    }

    It 'warns once per resolved CloudSet that contains no Azure subscription' {
        Mock -ModuleName EntraOps Get-EntraOpsPrivilegedDefenderRoles {
            @(
                New-DefenderAssignment -ScopeId '/CloudSet/empty' -SubscriptionScopes $null -Status 'Resolved'
                New-DefenderAssignment -ScopeId '/CloudSet/empty' -SubscriptionScopes $null -Status 'Resolved' -RoleDefinitionId 'role-2'
                New-DefenderAssignment -ScopeId '/CloudSet/unresolved' -SubscriptionScopes @() -Status 'Unresolved'
                New-DefenderAssignment -ScopeId '/' -SubscriptionScopes @() -Status 'DirectoryScope'
            )
        }

        $null = Get-EntraOpsPrivilegedEAMDefender -TenantId '99999999-9999-9999-9999-999999999999' -FolderClassification $script:ClassificationFolder -GlobalExclusion $false -EnableParallelProcessing $false 6>$null

        $EmptyCloudSetWarnings = @($script:CapturedWarnings | Where-Object { $_.Type -eq 'CloudSetWithoutSubscriptionScope' })
        $EmptyCloudSetWarnings.Count | Should -Be 1
        $EmptyCloudSetWarnings[0].ObjectId | Should -BeExactly '/CloudSet/empty'
        $EmptyCloudSetWarnings[0].Message | Should -Match '0 Azure subscription scope'
    }

    It 'does not warn about CloudSets with resolved subscriptions' {
        Mock -ModuleName EntraOps Get-EntraOpsPrivilegedDefenderRoles {
            @(New-DefenderAssignment -ScopeId '/CloudSet/full' -SubscriptionScopes @('/subscriptions/00000000-0000-0000-0000-000000000000') -Status 'Resolved')
        }

        $null = Get-EntraOpsPrivilegedEAMDefender -TenantId '99999999-9999-9999-9999-999999999999' -FolderClassification $script:ClassificationFolder -GlobalExclusion $false -EnableParallelProcessing $false 6>$null

        @($script:CapturedWarnings | Where-Object { $_.Type -eq 'CloudSetWithoutSubscriptionScope' }).Count | Should -Be 0
    }
}
