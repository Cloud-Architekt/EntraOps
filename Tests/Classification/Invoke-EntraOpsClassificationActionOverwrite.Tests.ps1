#Requires -Modules Pester

BeforeDiscovery {
    $script:TestRepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
}

BeforeAll {
    $script:TestRepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
    . "$script:TestRepositoryRoot/EntraOps/Private/Invoke-EntraOpsClassificationActionOverwrite.ps1"

    function New-ClassificationDefinition {
        # Two tiers, each with one service entry, scoped to all subscriptions.
        return @(
            [PSCustomObject]@{
                EAMTierLevelName     = 'ControlPlane'
                EAMTierLevelTagValue = '0'
                TierLevelDefinition  = @(
                    [PSCustomObject]@{
                        Category                = 'Azure'
                        Service                 = 'Authorization'
                        RoleAssignmentScopeName = @('/subscriptions/*')
                        RoleDefinitionActions   = @('Microsoft.Authorization/roleAssignments/write')
                    }
                )
            }
            [PSCustomObject]@{
                EAMTierLevelName     = 'ManagementPlane'
                EAMTierLevelTagValue = '1'
                TierLevelDefinition  = @(
                    [PSCustomObject]@{
                        Category                = 'Azure'
                        Service                 = 'Compute'
                        RoleAssignmentScopeName = @('/subscriptions/*')
                        RoleDefinitionActions   = @('Microsoft.Compute/virtualMachines/write', 'Microsoft.Compute/virtualMachines/restart/action')
                    }
                )
            }
        )
    }

    function New-Overwrite {
        param (
            [string]$TierLevelName = 'ControlPlane',
            [string[]]$Actions = @('Microsoft.Compute/virtualMachines/write'),
            [string[]]$Scopes = @('/subscriptions/*'),
            [string]$Service,
            [string]$ActionType = 'Action'
        )

        $Overwrite = [ordered]@{
            EAMTierLevelName        = $TierLevelName
            RoleDefinitionActions   = $Actions
            RoleAssignmentScopeName = $Scopes
            ActionType              = $ActionType
        }
        if ($PSBoundParameters.ContainsKey('Service')) { $Overwrite['Service'] = $Service }

        return @([PSCustomObject]$Overwrite)
    }

    function Get-TierActions {
        param ([array]$Definition, [string]$TierLevelName)

        $Tier = $Definition | Where-Object { $_.EAMTierLevelName -eq $TierLevelName }
        return @($Tier.TierLevelDefinition.RoleDefinitionActions)
    }
}

Describe 'Invoke-EntraOpsClassificationActionOverwrite' {

    Context 'Moving an action between tiers' {
        It 'removes the action from the source tier and adds it to the target tier' {
            $Definition = New-ClassificationDefinition

            $Result = Invoke-EntraOpsClassificationActionOverwrite -ClassificationDefinition $Definition -RoleActionOverwrites (New-Overwrite)

            Get-TierActions -Definition $Result -TierLevelName 'ControlPlane' | Should -Contain 'Microsoft.Compute/virtualMachines/write'
            Get-TierActions -Definition $Result -TierLevelName 'ManagementPlane' | Should -Not -Contain 'Microsoft.Compute/virtualMachines/write'
        }

        It 'leaves other actions of the source entry untouched' {
            $Definition = New-ClassificationDefinition

            $Result = Invoke-EntraOpsClassificationActionOverwrite -ClassificationDefinition $Definition -RoleActionOverwrites (New-Overwrite)

            Get-TierActions -Definition $Result -TierLevelName 'ManagementPlane' | Should -Contain 'Microsoft.Compute/virtualMachines/restart/action'
        }

        It 'uses an explicit Service on the overwrite for the target entry' {
            $Definition = New-ClassificationDefinition

            $Result = Invoke-EntraOpsClassificationActionOverwrite -ClassificationDefinition $Definition -RoleActionOverwrites (New-Overwrite -Service 'Custom Compute')

            $ControlPlane = $Result | Where-Object { $_.EAMTierLevelName -eq 'ControlPlane' }
            $Target = @($ControlPlane.TierLevelDefinition | Where-Object { @($_.RoleDefinitionActions) -contains 'Microsoft.Compute/virtualMachines/write' })
            $Target.Count | Should -Be 1
            $Target[0].Service | Should -Be 'Custom Compute'
        }
    }

    Context 'Fail-safe behaviour' {
        It 'leaves the classification unchanged when the target tier does not exist' {
            $Definition = New-ClassificationDefinition

            $Result = Invoke-EntraOpsClassificationActionOverwrite -ClassificationDefinition $Definition `
                -RoleActionOverwrites (New-Overwrite -TierLevelName 'TypoPlane') -WarningAction SilentlyContinue

            # The action must not be removed from its current tier when it cannot be re-added anywhere.
            Get-TierActions -Definition $Result -TierLevelName 'ManagementPlane' | Should -Contain 'Microsoft.Compute/virtualMachines/write'
        }

        It 'warns when the target tier does not exist' {
            $Definition = New-ClassificationDefinition

            $Warnings = @()
            Invoke-EntraOpsClassificationActionOverwrite -ClassificationDefinition $Definition `
                -RoleActionOverwrites (New-Overwrite -TierLevelName 'TypoPlane') -WarningVariable Warnings -WarningAction SilentlyContinue | Out-Null

            $Warnings.Count | Should -BeGreaterThan 0
            "$Warnings" | Should -Match 'TypoPlane'
        }

        It 'returns the classification unchanged when no overwrites are supplied' {
            $Definition = New-ClassificationDefinition

            $Result = Invoke-EntraOpsClassificationActionOverwrite -ClassificationDefinition $Definition -RoleActionOverwrites @()

            Get-TierActions -Definition $Result -TierLevelName 'ManagementPlane' | Should -Contain 'Microsoft.Compute/virtualMachines/write'
            Get-TierActions -Definition $Result -TierLevelName 'ControlPlane' | Should -Not -Contain 'Microsoft.Compute/virtualMachines/write'
        }

        It 'warns when a wildcard pattern in another tier still covers the overwritten action' {
            $Definition = New-ClassificationDefinition
            $ManagementPlane = $Definition | Where-Object { $_.EAMTierLevelName -eq 'ManagementPlane' }
            $ManagementPlane.TierLevelDefinition = @(
                [PSCustomObject]@{
                    Category                = 'Azure'
                    Service                 = 'Compute'
                    RoleAssignmentScopeName = @('/subscriptions/*')
                    RoleDefinitionActions   = @('Microsoft.Compute/*')
                }
            )

            $Warnings = @()
            Invoke-EntraOpsClassificationActionOverwrite -ClassificationDefinition $Definition `
                -RoleActionOverwrites (New-Overwrite) -WarningVariable Warnings -WarningAction SilentlyContinue | Out-Null

            "$Warnings" | Should -Match 'wildcard'
        }
    }

    Context 'Actions and DataActions are isolated' {
        It 'does not remove a management-plane action for a DataAction overwrite' {
            $Definition = New-ClassificationDefinition

            $Result = Invoke-EntraOpsClassificationActionOverwrite -ClassificationDefinition $Definition `
                -RoleActionOverwrites (New-Overwrite -ActionType 'DataAction')

            # The source entry has no ActionType and therefore defaults to "Action"; a DataAction overwrite must not touch it.
            Get-TierActions -Definition $Result -TierLevelName 'ManagementPlane' | Should -Contain 'Microsoft.Compute/virtualMachines/write'
        }

        It 'creates the target entry with the overwritten ActionType' {
            $Definition = New-ClassificationDefinition
            $ManagementPlane = $Definition | Where-Object { $_.EAMTierLevelName -eq 'ManagementPlane' }
            $ManagementPlane.TierLevelDefinition = @(
                [PSCustomObject]@{
                    Category                = 'Azure'
                    Service                 = 'Storage'
                    ActionType              = 'DataAction'
                    RoleAssignmentScopeName = @('/subscriptions/*')
                    RoleDefinitionActions   = @('Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read')
                }
            )

            $Result = Invoke-EntraOpsClassificationActionOverwrite -ClassificationDefinition $Definition `
                -RoleActionOverwrites (New-Overwrite -Actions @('Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read') -ActionType 'DataAction')

            Get-TierActions -Definition $Result -TierLevelName 'ManagementPlane' | Should -Not -Contain 'Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read'
            $ControlPlane = $Result | Where-Object { $_.EAMTierLevelName -eq 'ControlPlane' }
            $Target = @($ControlPlane.TierLevelDefinition | Where-Object { @($_.RoleDefinitionActions) -contains 'Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read' })
            $Target.Count | Should -Be 1
            $Target[0].ActionType | Should -Be 'DataAction'
        }
    }

    Context 'Scope precedence' {
        It 'excludes only the overwritten scope when the overwrite is narrower than the entry' {
            $Definition = New-ClassificationDefinition
            $NarrowScope = '/subscriptions/00000000-0000-0000-0000-000000000001'

            $Result = Invoke-EntraOpsClassificationActionOverwrite -ClassificationDefinition $Definition `
                -RoleActionOverwrites (New-Overwrite -Scopes @($NarrowScope))

            $ManagementPlane = $Result | Where-Object { $_.EAMTierLevelName -eq 'ManagementPlane' }
            $SourceEntry = @($ManagementPlane.TierLevelDefinition)[0]
            # The action stays classified for every other subscription, with the overwritten scope excluded.
            $SourceEntry.RoleDefinitionActions | Should -Contain 'Microsoft.Compute/virtualMachines/write'
            $SourceEntry.ExcludedRoleAssignmentScopeName | Should -Contain $NarrowScope
        }

        It 'does not touch an entry whose scope does not overlap the overwrite' {
            $Definition = New-ClassificationDefinition

            $Result = Invoke-EntraOpsClassificationActionOverwrite -ClassificationDefinition $Definition `
                -RoleActionOverwrites (New-Overwrite -Scopes @('/providers/Microsoft.Management/managementGroups/*'))

            $ManagementPlane = $Result | Where-Object { $_.EAMTierLevelName -eq 'ManagementPlane' }
            $SourceEntry = @($ManagementPlane.TierLevelDefinition)[0]
            $SourceEntry.RoleDefinitionActions | Should -Contain 'Microsoft.Compute/virtualMachines/write'
            @($SourceEntry.ExcludedRoleAssignmentScopeName) | Should -Not -Contain '/providers/Microsoft.Management/managementGroups/*'
        }
    }
}


Describe 'API permission overwrites of one permission type' {
    BeforeAll {
        . "$script:TestRepositoryRoot/EntraOps/Public/PrivilegedAccess/Expand-EntraOpsPrivilegedEamJsonFile.ps1"
        . "$script:TestRepositoryRoot/EntraOps/Private/Resolve-EntraOpsAppRoleAssignmentClassification.ps1"
        $script:AppId = '00000003-0000-0ff1-ce00-000000000000'

        # Classification_ApiPermissions.json: the permission for both types (ResourceScope All) in the Control Plane.
        function New-ApiPermissionClassification {
            param([array]$ExtraControlPlaneDefinitions = @())
            @(
                [PSCustomObject]@{
                    EAMTierLevelName     = 'ControlPlane'
                    EAMTierLevelTagValue = '0'
                    TierLevelDefinition  = @(
                        [PSCustomObject]@{ Category = 'Microsoft.Graph'; Service = 'SharePoint'; ResourceAppId = $script:AppId; ResourceScope = 'All'; RoleAssignmentScopeName = @('/'); RoleDefinitionActions = @('Sites.FullControl.All') }
                    ) + $ExtraControlPlaneDefinitions
                }
                [PSCustomObject]@{ EAMTierLevelName = 'ManagementPlane'; EAMTierLevelTagValue = '1'; TierLevelDefinition = @() }
            )
        }

        # The tier of each permission type at run time, after the overwrite was saved and loaded like a tenant file.
        function Get-RuntimeTier {
            param([array]$Classification)
            $File = Join-Path $TestDrive "classification-$([guid]::NewGuid().ToString('N')).json"
            $Classification | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $File
            $Definitions = Expand-EntraOpsPrivilegedEAMJsonFile -FilePath $File
            $Tiers = @{}
            foreach ($RoleType in 'Application', 'Delegated') {
                $Assignment = [PSCustomObject]@{ RoleDefinitionId = 'r1'; RoleAssignmentScopeId = 's1'; RoleDefinitionName = 'Sites.FullControl.All'; RoleType = $RoleType; ResourceAppId = $script:AppId }
                $Tiers[$RoleType] = @((Resolve-EntraOpsAppRoleAssignmentClassification -AppRoleAssignments @($Assignment) -ClassificationDefinitions $Definitions).Classification.AdminTierLevelName)
            }
            $Tiers
        }
    }

    It 'keeps the other permission type at its tier for an overwrite of the <Overwritten> permission' -ForEach @(
        @{ Overwritten = 'Application'; ResourceScope = 'Application'; Kept = 'Delegated' }
        @{ Overwritten = 'Delegated'; ResourceScope = 'Delegation'; Kept = 'Application' }
    ) {
        $Overwrite = [PSCustomObject]@{ EAMTierLevelName = 'ManagementPlane'; RoleDefinitionActions = @('Sites.FullControl.All'); ResourceAppId = $script:AppId; ResourceScope = $ResourceScope; RoleAssignmentScopeName = @('/') }

        $Result = Invoke-EntraOpsClassificationActionOverwrite -ClassificationDefinition (New-ApiPermissionClassification) -RoleActionOverwrites @($Overwrite) 6>$null

        $Tiers = Get-RuntimeTier -Classification $Result
        $Tiers[$Overwritten] | Should -Be @('ManagementPlane')
        $Tiers[$Kept] | Should -Be @('ControlPlane')
        # The classification values of the permission types, not the RoleType of the assignment ("Delegated").
        @($Result.TierLevelDefinition.ResourceScope | Where-Object { $_ }) | Should -Not -Contain 'Delegated'
    }

    It 'adds the kept delegated permission to an existing Delegation entry of the service' {
        $Existing = [PSCustomObject]@{ Category = 'Microsoft.Graph'; Service = 'SharePoint'; ResourceAppId = $script:AppId; ResourceScope = 'Delegation'; RoleAssignmentScopeName = @('/'); RoleDefinitionActions = @('Sites.Manage.All') }
        $Overwrite = [PSCustomObject]@{ EAMTierLevelName = 'ManagementPlane'; RoleDefinitionActions = @('Sites.FullControl.All'); ResourceAppId = $script:AppId; ResourceScope = 'Application'; RoleAssignmentScopeName = @('/') }

        $Result = Invoke-EntraOpsClassificationActionOverwrite -ClassificationDefinition (New-ApiPermissionClassification -ExtraControlPlaneDefinitions @($Existing)) -RoleActionOverwrites @($Overwrite) 6>$null

        $DelegationEntries = @(($Result | Where-Object EAMTierLevelName -eq 'ControlPlane').TierLevelDefinition | Where-Object ResourceScope -eq 'Delegation')
        $DelegationEntries.Count | Should -Be 1
        @($DelegationEntries[0].RoleDefinitionActions) | Should -Be @('Sites.Manage.All', 'Sites.FullControl.All')
    }
}
