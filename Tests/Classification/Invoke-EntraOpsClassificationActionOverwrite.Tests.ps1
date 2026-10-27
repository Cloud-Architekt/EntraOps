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

