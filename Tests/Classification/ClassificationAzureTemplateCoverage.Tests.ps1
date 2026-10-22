#Requires -Modules Pester

BeforeDiscovery {
    $script:TestRepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
}

# The base Classification_Azure.json and the parameterized Classification_Azure.Param.json are not
# action-for-action identical by design: the parameterized template adds Control Plane services that
# are bound to <Tier0IncludedResourceScope> and therefore cannot exist in the non-parameterized base.
#
# What has to hold is the outcome: at an ordinary (non-Tier 0) scope both templates must still classify
# the privileged Azure actions below at Management Plane, either through an explicit entry or through a
# service/wildcard entry. This guards the base template that is used as fallback whenever no
# tenant-specific classification file exists.

BeforeAll {
    $script:TestRepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
    . "$script:TestRepositoryRoot/EntraOps/Private/Test-EntraOpsClassificationActionMatch.ps1"

    $script:OrdinaryScope = '/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-test'

    function Get-AzureClassification {
        param([Parameter(Mandatory = $true)][string]$Name)

        $Raw = [System.IO.File]::ReadAllText((Resolve-Path "$script:TestRepositoryRoot/Classification/Templates/$Name"))
        if ($Name -like '*.Param.json') {
            # A tenant without Tier 0 resources at this scope resolves every placeholder to an empty list.
            $Raw = $Raw -replace ',\s*<[A-Za-z0-9_]+>', ''
            $Raw = $Raw -replace '<[A-Za-z0-9_]+>\s*,\s*', ''
            $Raw = $Raw -replace '<[A-Za-z0-9_]+>', ''
        }
        return ($Raw | ConvertFrom-Json -Depth 10)
    }

    # Mirrors the scope and action matching of Get-EntraOpsAzureActionClassification.
    function Resolve-AzureActionTier {
        param(
            [Parameter(Mandatory = $true)]$Classification,
            [Parameter(Mandatory = $true)][string]$Action,
            [Parameter(Mandatory = $true)][ValidateSet('Action', 'DataAction')][string]$ActionType,
            [Parameter(Mandatory = $true)][string]$Scope
        )

        foreach ($Tier in $Classification) {
            foreach ($Definition in @($Tier.TierLevelDefinition)) {
                $DefinitionType = if ($Definition.ActionType -eq 'DataAction') { 'DataAction' } else { 'Action' }
                if ($DefinitionType -ne $ActionType) { continue }
                if (-not ((@($Definition.RoleAssignmentScopeName) -contains $Scope) -or (@($Definition.RoleAssignmentScopeName) -contains '/*'))) { continue }
                if (@($Definition.ExcludedRoleAssignmentScopeName) -contains $Scope) { continue }
                if (Test-EntraOpsClassificationActionMatch -ClassificationActions @($Definition.ExcludedRoleDefinitionActions) -Action $Action) { continue }
                if (Test-EntraOpsClassificationActionMatch -ClassificationActions @($Definition.RoleDefinitionActions) -Action $Action) {
                    return $Tier.EAMTierLevelName
                }
            }
        }
        return 'Unclassified'
    }
}

Describe 'Classification_Azure template coverage at ordinary scopes' {
    It 'classifies <Action> at Management Plane in <Template>' -TestCases @(
        foreach ($Template in @('Classification_Azure.json', 'Classification_Azure.Param.json')) {
            @{ Template = $Template; Action = 'Microsoft.KeyVault/vaults/secrets/setSecret/action'; ActionType = 'DataAction' }
            @{ Template = $Template; Action = 'Microsoft.KeyVault/vaults/keys/wrap/action'; ActionType = 'DataAction' }
            @{ Template = $Template; Action = 'Microsoft.Compute/virtualMachineScaleSets/runCommand/action'; ActionType = 'Action' }
            @{ Template = $Template; Action = 'Microsoft.GuestConfiguration/guestConfigurationAssignments/write'; ActionType = 'Action' }
            @{ Template = $Template; Action = 'Microsoft.GuestConfiguration/guestConfigurationAssignments/delete'; ActionType = 'Action' }
            @{ Template = $Template; Action = 'Microsoft.Web/sites/write'; ActionType = 'Action' }
            @{ Template = $Template; Action = 'Microsoft.Automation/automationAccounts/compilationjobs/write'; ActionType = 'Action' }
            @{ Template = $Template; Action = 'Microsoft.Automation/automationAccounts/nodeConfigurations/write'; ActionType = 'Action' }
            @{ Template = $Template; Action = 'Microsoft.Automation/automationAccounts/hybridRunbookWorkerGroups/write'; ActionType = 'Action' }
        }
    ) {
        $Classification = Get-AzureClassification -Name $Template
        Resolve-AzureActionTier -Classification $Classification -Action $Action -ActionType $ActionType -Scope $script:OrdinaryScope |
            Should -Be 'ManagementPlane'
    }
}

