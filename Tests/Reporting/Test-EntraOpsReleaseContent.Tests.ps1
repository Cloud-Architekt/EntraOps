#Requires -Modules Pester

BeforeDiscovery {
    $script:TestRepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
}

BeforeAll {
    $script:TestRepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
    $ValidatorPath = Join-Path $script:TestRepositoryRoot '.github/scripts/Test-EntraOpsReleaseContent.ps1'
    $RepositoryRoot = $script:TestRepositoryRoot

    function New-TestContent {
        param (
            [Parameter(Mandatory = $true)]
            [string]$Root,

            [Parameter(Mandatory = $true)]
            [string]$RelativePath,

            [Parameter(Mandatory = $true)]
            [string]$Content
        )

        $FilePath = Join-Path $Root $RelativePath
        New-Item -Path (Split-Path $FilePath -Parent) -ItemType Directory -Force | Out-Null
        Set-Content -LiteralPath $FilePath -Value $Content -Encoding UTF8
    }
}

# Evaluated at discovery: Tests/ is synced into deployment repositories, but .github/ can lag behind
# it, and a configured deployment is expected to hold the tenant data this validator rejects.
$ValidatorScript = Join-Path $script:TestRepositoryRoot '.github/scripts/Test-EntraOpsReleaseContent.ps1'
$IsConfiguredDeployment = Test-Path -LiteralPath (Join-Path $script:TestRepositoryRoot 'EntraOpsConfig.json')

Describe 'Test-EntraOpsReleaseContent' -Skip:(-not (Test-Path -LiteralPath $ValidatorScript)) {
    BeforeEach {
        # Each case needs an empty tree; TestDrive itself is shared for the whole container.
        $TestRoot = Join-Path $TestDrive ([guid]::NewGuid().ToString())
        New-Item -Path $TestRoot -ItemType Directory -Force | Out-Null
    }

    It 'accepts the shipped repository content' -Skip:$IsConfiguredDeployment {
        & $ValidatorPath -RepositoryRoot $RepositoryRoot | Should -Match 'Release content validation passed'
    }

    It 'rejects a tenant initial domain that is not a documented placeholder' {
        New-TestContent -Root $TestRoot -RelativePath 'Samples/sample.json' -Content '{ "TenantName": "realcustomer.onmicrosoft.com" }'

        # The validator emits GitHub workflow commands for real findings. Suppress the information
        # stream here so an intentionally invalid fixture does not become a false CI annotation.
        { & $ValidatorPath -RepositoryRoot $TestRoot 6>$null } | Should -Throw '*validation failed*'
    }

    It 'accepts the documented placeholder tenants' {
        New-TestContent -Root $TestRoot -RelativePath 'Samples/sample.json' -Content '{ "TenantName": "contoso.onmicrosoft.com", "ManagingTenantName": "fabrikam.onmicrosoft.com" }'

        & $ValidatorPath -RepositoryRoot $TestRoot | Should -Match 'Release content validation passed'
    }

    It 'rejects a mail address outside the placeholder domains' {
        New-TestContent -Root $TestRoot -RelativePath 'Samples/sample.json' -Content '{ "ObjectMailAddress": "someone@realcorp.net" }'

        { & $ValidatorPath -RepositoryRoot $TestRoot 6>$null } | Should -Throw '*validation failed*'
    }

    It 'rejects a subscription resource path with a real subscription id' {
        New-TestContent -Root $TestRoot -RelativePath 'Workbooks/sample.json' -Content '{ "value": "/subscriptions/4d3e5b65-8a52-4b2f-b5cd-1670c700136b/resourceGroups/rg" }'

        { & $ValidatorPath -RepositoryRoot $TestRoot 6>$null } | Should -Throw '*validation failed*'
    }

    It 'accepts the zeroed placeholder subscription id' {
        New-TestContent -Root $TestRoot -RelativePath 'Workbooks/sample.json' -Content '{ "value": "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg" }'

        & $ValidatorPath -RepositoryRoot $TestRoot | Should -Match 'Release content validation passed'
    }

    It 'accepts a repeated-digit placeholder subscription id' {
        New-TestContent -Root $TestRoot -RelativePath 'Workbooks/sample.json' -Content '{ "value": "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/rg" }'

        & $ValidatorPath -RepositoryRoot $TestRoot | Should -Match 'Release content validation passed'
    }

    It 'rejects a non-empty shipped global principal exclusion list' {
        New-TestContent -Root $TestRoot -RelativePath 'Classification/Global.json' -Content '[ { "ExcludedPrincipalId": [ "11111111-1111-1111-1111-111111111111" ] } ]'

        { & $ValidatorPath -RepositoryRoot $TestRoot 6>$null } | Should -Throw '*ExcludedPrincipalId*'
    }

    It 'accepts an empty shipped global principal exclusion list' {
        New-TestContent -Root $TestRoot -RelativePath 'Classification/Global.json' -Content '[ { "ExcludedPrincipalId": [] } ]'

        & $ValidatorPath -RepositoryRoot $TestRoot | Should -Match 'Release content validation passed'
    }

    It 'ignores operator-generated output paths' {
        New-TestContent -Root $TestRoot -RelativePath 'PrivilegedEAM/EntraID/EntraID.json' -Content '{ "ObjectSignInName": "admin@realcustomer.onmicrosoft.com" }'
        New-TestContent -Root $TestRoot -RelativePath 'TenantGovernance/Snapshots/policy.json' -Content '{ "mail": "someone@realcorp.net" }'
        New-TestContent -Root $TestRoot -RelativePath 'EntraOpsConfig.json' -Content '{ "TenantName": "realcustomer.onmicrosoft.com" }'

        & $ValidatorPath -RepositoryRoot $TestRoot | Should -Match 'Release content validation passed'
    }

    It 'ignores the tenant-specific classification folder committed by the pull workflow' {
        # Pull-EntraOpsPrivilegedEAM commits Classification/<TenantName>/ into the operator's own repository.
        New-TestContent -Root $TestRoot -RelativePath 'Classification/realcustomer.onmicrosoft.com/ScopeReasoning_Azure.json' `
            -Content '{ "Tier0Scope": ["/subscriptions/4d3e5b65-8a52-4b2f-b5cd-1670c700136b"] }'

        & $ValidatorPath -RepositoryRoot $TestRoot | Should -Match 'Release content validation passed'
    }

    It 'still scans the shipped classification templates' {
        New-TestContent -Root $TestRoot -RelativePath 'Classification/Templates/Classification_Azure.json' `
            -Content '{ "Tier0Scope": ["/subscriptions/4d3e5b65-8a52-4b2f-b5cd-1670c700136b"] }'

        { & $ValidatorPath -RepositoryRoot $TestRoot 6>$null } | Should -Throw '*validation failed*'
    }

    It 'scans content inside dot-directories such as .github' {
        New-TestContent -Root $TestRoot -RelativePath '.github/workflows/test.yaml' -Content 'env:
  TenantName: realcustomer.onmicrosoft.com'

        { & $ValidatorPath -RepositoryRoot $TestRoot 6>$null } | Should -Throw '*validation failed*'
    }
}

