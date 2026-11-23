#Requires -Modules Pester

BeforeDiscovery {
    $script:TestRepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
}

Describe 'Classification template reuse' {
    BeforeAll {
        . (Join-Path $script:TestRepositoryRoot 'EntraOps/Public/Configuration/Update-EntraOpsClassificationFiles.ps1')
        . (Join-Path $script:TestRepositoryRoot 'EntraOps/Private/Invoke-EntraOpsGitHubRequest.ps1')
        . (Join-Path $script:TestRepositoryRoot 'EntraOps/Private/Get-EntraOpsRetryAfterSeconds.ps1')
    }

    BeforeEach {
        $script:TemplateFolder = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $script:TemplateFolder | Out-Null
        Set-Content "$script:TemplateFolder/Classification_Azure.json" -Value '[{"custom":"preserve"}]'
        Mock Invoke-RestMethod {
            @(
                @{ Name = 'Classification_Azure.json'; download_url = 'https://example.test/Azure.json' }
                @{ Name = 'Classification_Azure.Param.json'; download_url = 'https://example.test/Azure.Param.json' }
                @{ Name = 'Classification_RoleDefinitionOverwrites.json'; download_url = 'https://example.test/overwrites.json' }
            )
        } -ParameterFilter { -not $OutFile }
        Mock Invoke-RestMethod { Set-Content -LiteralPath $OutFile -Value '[{"downloaded":true}]' } -ParameterFilter { $OutFile }
    }

    It 'reuses existing templates while downloading missing parameter and overwrite templates' {
        Update-EntraOpsClassificationFiles -FolderClassification $script:TemplateFolder -Classifications Azure -SkipExisting

        Get-Content "$script:TemplateFolder/Classification_Azure.json" -Raw | Should -Match 'preserve'
        Test-Path "$script:TemplateFolder/Classification_Azure.Param.json" | Should -BeTrue
        Test-Path "$script:TemplateFolder/Classification_RoleDefinitionOverwrites.json" | Should -BeTrue
        Should -Invoke Invoke-RestMethod -Times 0 -Exactly -ParameterFilter { $Uri -eq 'https://example.test/Azure.json' }
        Should -Invoke Invoke-RestMethod -Times 2 -Exactly -ParameterFilter { $OutFile }
    }

    It 'preserves existing parameter and role definition overwrite templates with SkipExisting' {
        Set-Content "$script:TemplateFolder/Classification_Azure.Param.json" -Value '[{"custom":"preserve"}]'
        Set-Content "$script:TemplateFolder/Classification_RoleDefinitionOverwrites.json" -Value '[{"custom":"preserve"}]'

        Update-EntraOpsClassificationFiles -FolderClassification $script:TemplateFolder -Classifications Azure -SkipExisting

        foreach ($Name in 'Azure', 'Azure.Param', 'RoleDefinitionOverwrites') {
            Get-Content "$script:TemplateFolder/Classification_$Name.json" -Raw | Should -Match 'preserve'
        }
        Should -Invoke Invoke-RestMethod -Times 0 -Exactly -ParameterFilter { $OutFile }
    }

    It 'overwrites every selected existing template when SkipExisting is <Mode>' -ForEach @(
        @{ Mode = 'omitted'; Arguments = @{} }
        @{ Mode = 'false'; Arguments = @{ SkipExisting = $false } }
    ) {
        Set-Content "$script:TemplateFolder/Classification_Azure.Param.json" -Value '[{"custom":"preserve"}]'
        Set-Content "$script:TemplateFolder/Classification_RoleDefinitionOverwrites.json" -Value '[{"custom":"preserve"}]'

        Update-EntraOpsClassificationFiles -FolderClassification $script:TemplateFolder -Classifications Azure @Arguments

        foreach ($Name in 'Azure', 'Azure.Param', 'RoleDefinitionOverwrites') {
            Get-Content "$script:TemplateFolder/Classification_$Name.json" -Raw | Should -Match 'downloaded'
        }
        Should -Invoke Invoke-RestMethod -Times 3 -Exactly -ParameterFilter { $OutFile }
    }

    It 'skips deprecated upstream templates when Classifications is All' {
        Mock Invoke-RestMethod {
            @(
                @{ Name = 'Classification_Azure.json'; download_url = 'https://example.test/Azure.json' }
                @{ Name = 'Classification_AzBilling.json'; download_url = 'https://example.test/AzBilling.json' }
                @{ Name = 'Classification_AzResources.json'; download_url = 'https://example.test/AzResources.json' }
                @{ Name = 'Classification_AzResourcesByAzTags.json'; download_url = 'https://example.test/AzResourcesByAzTags.json' }
            )
        } -ParameterFilter { -not $OutFile }

        $Verbose = Update-EntraOpsClassificationFiles -FolderClassification $script:TemplateFolder -Classifications All -IncludeOverwrites:$false -Verbose 4>&1 |
            Where-Object { $_ -is [System.Management.Automation.VerboseRecord] } | ForEach-Object { $_.Message }

        Get-Content "$script:TemplateFolder/Classification_Azure.json" -Raw | Should -Match 'downloaded'
        foreach ($Name in 'AzBilling', 'AzResources', 'AzResourcesByAzTags') {
            Test-Path "$script:TemplateFolder/Classification_$Name.json" | Should -BeFalse
            @($Verbose | Where-Object { $_ -match "Classification_$Name\.json\] Skipped: deprecated" }).Count | Should -Be 1
        }
        Should -Invoke Invoke-RestMethod -Times 1 -Exactly -ParameterFilter { $OutFile }
    }
}

Describe 'Classification template listing unavailable' {
    BeforeAll {
        . (Join-Path $script:TestRepositoryRoot 'EntraOps/Public/Configuration/Update-EntraOpsClassificationFiles.ps1')
        . (Join-Path $script:TestRepositoryRoot 'EntraOps/Private/Invoke-EntraOpsGitHubRequest.ps1')
    }

    BeforeEach {
        $script:TemplateFolder = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $script:TemplateFolder | Out-Null
        Set-Content "$script:TemplateFolder/Classification_Azure.json" -Value '[{"custom":"preserve"}]'
        Mock Invoke-EntraOpsGitHubRequest { throw 'GitHub rate limit exceeded for https://api.github.com/repos/Cloud-Architekt/AzurePrivilegedIAM/contents/EntraOps_Classification?ref=main' }
    }

    It 'keeps and uses the local templates when every requested template exists' {
        Update-EntraOpsClassificationFiles -FolderClassification $script:TemplateFolder -Classifications Azure -WarningVariable Warnings -WarningAction SilentlyContinue

        Get-Content "$script:TemplateFolder/Classification_Azure.json" -Raw | Should -Match 'preserve'
        ($Warnings -join ' ') | Should -Match 'rate limit exceeded.*existing templates .* are kept and used'
        Should -Invoke Invoke-EntraOpsGitHubRequest -Times 1 -Exactly
    }

    It 'keeps any local template set for All' {
        { Update-EntraOpsClassificationFiles -FolderClassification $script:TemplateFolder -Classifications All -WarningAction SilentlyContinue } | Should -Not -Throw
    }

    It 'fails when a requested template is missing locally' {
        { Update-EntraOpsClassificationFiles -FolderClassification $script:TemplateFolder -Classifications Azure, AadResources } |
            Should -Throw '*could not be listed*requested templates don''t exist*'
    }

    It 'fails with FailOnUnavailableRepository' {
        { Update-EntraOpsClassificationFiles -FolderClassification $script:TemplateFolder -Classifications Azure -FailOnUnavailableRepository } |
            Should -Throw '*could not be listed*rate limit exceeded*'
    }
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

