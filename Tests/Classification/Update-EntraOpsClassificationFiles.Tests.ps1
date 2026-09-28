#Requires -Modules Pester

BeforeDiscovery {
    $script:TestRepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
}

BeforeAll {
    $script:TestRepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
    $RepositoryRoot = $script:TestRepositoryRoot

    # Mirrors the validation Update-EntraOpsClassificationFiles applies to a downloaded template.
    function ConvertTo-ValidatableTemplate {
        param (
            [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Content,
            [Parameter(Mandatory = $true)][string]$FileName
        )

        if ($FileName -like '*.Param.json') {
            return ($Content -replace '"<[A-Za-z0-9_]+>"', '"placeholder"') -replace '<[A-Za-z0-9_]+>', '"placeholder"'
        }
        return $Content
    }
}

Describe 'Classification template download validation' {
    It 'accepts every shipped classification template' {
        $Templates = @(Get-ChildItem (Join-Path $RepositoryRoot 'Classification/Templates') -Filter 'Classification_*.json')
        $Templates.Count | Should -BeGreaterThan 0

        foreach ($Template in $Templates) {
            $Content = Get-Content -LiteralPath $Template.FullName -Raw
            $Validatable = ConvertTo-ValidatableTemplate -Content $Content -FileName $Template.Name
            { $Validatable | ConvertFrom-Json -Depth 10 } | Should -Not -Throw -Because "$($Template.Name) must pass download validation"
        }
    }

    It 'accepts a Param template with bare placeholders' {
        # Placeholders are unquoted in the templates and only substituted later, so the raw text is not JSON.
        $Content = '[{"EAMTierLevelName":"ControlPlane","TierLevelDefinition":[{"RoleAssignmentScopeName":[<Tier0IncludedResourceScope>]}]}]'

        { $Content | ConvertFrom-Json -Depth 10 } | Should -Throw
        { (ConvertTo-ValidatableTemplate -Content $Content -FileName 'Classification_Azure.Param.json') | ConvertFrom-Json -Depth 10 } | Should -Not -Throw
    }

    It 'still rejects an HTML error page' {
        $Content = '<!DOCTYPE html><html><body>404 Not Found</body></html>'

        { (ConvertTo-ValidatableTemplate -Content $Content -FileName 'Classification_Azure.Param.json') | ConvertFrom-Json -Depth 10 } | Should -Throw
    }

    It 'still rejects a truncated download' {
        $Content = '[{"Category":"Microsoft.AzureAD",'

        { (ConvertTo-ValidatableTemplate -Content $Content -FileName 'Classification_AadResources.Param.json') | ConvertFrom-Json -Depth 10 } | Should -Throw
    }

    It 'does not relax validation for non-Param templates' {
        $Content = '[{"RoleAssignmentScopeName":[<Tier0IncludedResourceScope>]}]'

        { (ConvertTo-ValidatableTemplate -Content $Content -FileName 'Classification_Azure.json') | ConvertFrom-Json -Depth 10 } | Should -Throw
    }
}

