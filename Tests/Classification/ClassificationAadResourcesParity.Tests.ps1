#Requires -Modules Pester

BeforeDiscovery {
    $script:TestRepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
}

BeforeAll {
    $script:TestRepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
    $script:TemplateDir = "$script:TestRepositoryRoot/Classification/Templates"

    function Get-AadClassificationActions {
        param([Parameter(Mandatory = $true)][string]$Name)

        $Raw = [System.IO.File]::ReadAllText((Resolve-Path (Join-Path $script:TemplateDir $Name)))
        if ($Name -like '*.Param.json') {
            # Scope placeholders do not affect the role-action catalog. Remove them so the
            # parameterized template can be parsed and compared with the base template.
            $Raw = $Raw -replace ',\s*<[A-Za-z0-9_]+>', ''
            $Raw = $Raw -replace '<[A-Za-z0-9_]+>\s*,\s*', ''
            $Raw = $Raw -replace '<[A-Za-z0-9_]+>', ''
        }

        $Classification = $Raw | ConvertFrom-Json
        return @($Classification.TierLevelDefinition.RoleDefinitionActions |
            ForEach-Object { @($_) } |
            Sort-Object -Unique)
    }
}

Describe 'Classification_AadResources template parity' {
    It 'keeps the base and parameterized role-action catalogs synchronized' {
        $BaseActions = Get-AadClassificationActions -Name 'Classification_AadResources.json'
        $ParameterizedActions = Get-AadClassificationActions -Name 'Classification_AadResources.Param.json'

        Compare-Object -ReferenceObject $BaseActions -DifferenceObject $ParameterizedActions | Should -BeNullOrEmpty
    }
}

