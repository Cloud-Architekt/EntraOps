#Requires -Modules Pester

BeforeDiscovery {
    $script:TestRepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
}

Describe 'Convert-EntraOpsExportToSampleData' {
    BeforeAll {
    $script:TestRepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
        $ImplementationPath = Join-Path $script:TestRepositoryRoot 'EntraOps/Public/Reportings/Convert-EntraOpsExportToSampleData.ps1'
        Import-Module (Join-Path $script:TestRepositoryRoot 'EntraOps/EntraOps.psd1') -Force
        $OriginalGuid = '11111111-2222-3333-4444-555555555555'
        $OriginalUpn = 'secret_person_example.com#EXT#@fabrikam.onmicrosoft.com'
        $OriginalResourceId = "/subscriptions/$OriginalGuid/resourceGroups/domaincontroller-rg/providers/Microsoft.Storage/storageAccounts/blobstorage"
    }

    BeforeEach {
        $TestRoot = Join-Path $TestDrive ([guid]::NewGuid().Guid)
        $SourcePath = Join-Path $TestRoot 'source'
        $DestinationPath = Join-Path $TestRoot 'destination'
        $ClassificationPath = Join-Path $SourcePath 'Classification/fabrikam.onmicrosoft.com'
        $PrivilegedEamPath = Join-Path $SourcePath 'PrivilegedEAM/EntraID/user'
        $TenantGovernancePath = Join-Path $SourcePath 'TenantGovernance/Snapshots/example'
        $null = New-Item -ItemType Directory -Path $ClassificationPath, $PrivilegedEamPath, $TenantGovernancePath

        $Identity = [ordered]@{
            ObjectId                = $OriginalGuid
            ObjectTenantId          = $OriginalGuid
            ObjectType              = 'user'
            ObjectDisplayName       = 'Secret Person'
            ObjectUserPrincipalName = $OriginalUpn
            RoleAssignmentScopeId   = $OriginalResourceId
            CompositeId             = "prefix_$($OriginalGuid)_suffix"
            TenantName              = 'fabrikam'
        }
        $Identity | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $ClassificationPath 'classification.json')
        $Identity | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $PrivilegedEamPath "$OriginalGuid.json")

        [ordered]@{
            id               = $OriginalGuid
            principal        = 'Secret Person'
            ownerDisplayName = 'Second Person'
            reason           = "Users 'Secret Person' and 'Second Person' have access in fabrikam"
            users            = @($OriginalUpn)
            resourceId       = $OriginalResourceId
        } | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $TenantGovernancePath 'snapshot.json')

        [ordered]@{
            scope = '/providers/Microsoft.Management/managementGroups/fabrikam'
        } | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $ClassificationPath 'management-group.json')
    }

    It 'exports Convert-EntraOpsExportToSampleData from the EntraOps module' {
        $Command = Get-Command Convert-EntraOpsExportToSampleData -Module EntraOps

        $Command.CommandType | Should -Be 'Function'
        $Command.Parameters.Keys | Should -Contain 'SourcePath'
        $Command.Parameters.Keys | Should -Contain 'DestinationPath'
        $Command.Parameters.Keys | Should -Contain 'GenerateReports'
    }

    It 'anonymizes all export areas with one relationship-preserving mapping' {
        $Result = Convert-EntraOpsExportToSampleData -SourcePath $SourcePath -DestinationPath $DestinationPath `
            -SourceTenantName 'fabrikam' -Seed 'pester-seed'

        $Classification = Get-Content -LiteralPath (Join-Path $DestinationPath 'Classification/contoso.onmicrosoft.com/classification.json') -Raw | ConvertFrom-Json
        $PrivilegedFile = Get-ChildItem -LiteralPath (Join-Path $DestinationPath 'PrivilegedEAM/EntraID/user') -Filter '*.json' -File | Select-Object -First 1
        $Privileged = Get-Content -LiteralPath $PrivilegedFile.FullName -Raw | ConvertFrom-Json
        $Governance = Get-Content -LiteralPath (Join-Path $DestinationPath 'TenantGovernance/Snapshots/example/snapshot.json') -Raw | ConvertFrom-Json
        $OutputText = Get-ChildItem -LiteralPath $DestinationPath -Recurse -File -Filter '*.json' | Get-Content -Raw | Out-String

        $Result.SourceFiles | Should -Be 4
        $Classification.ObjectId | Should -Not -Be $OriginalGuid
        $Classification.ObjectId | Should -Be $Privileged.ObjectId
        $Classification.ObjectId | Should -Be $Governance.id
        $PrivilegedFile.BaseName | Should -Be $Classification.ObjectId
        $Classification.ObjectDisplayName | Should -Be 'user01'
        $Classification.CompositeId | Should -Be "prefix_$($Classification.ObjectId)_suffix"
        $Privileged.ObjectDisplayName | Should -Be 'user01'
        $Governance.principal | Should -Be 'user01'
        $Governance.ownerDisplayName | Should -Be 'object01'
        $Governance.reason | Should -Be "Users 'user01' and 'object01' have access in contoso"
        $Classification.ObjectUserPrincipalName | Should -Be 'user01#EXT#@contoso.onmicrosoft.com'
        $Classification.RoleAssignmentScopeId | Should -Match '/resourceGroups/resourcegroup01/providers/Microsoft.Storage/storageAccounts/storage01$'
        $Classification.RoleAssignmentScopeId | Should -Match "^/subscriptions/$([regex]::Escape($Classification.ObjectId))/"
        $Classification.RoleAssignmentScopeId | Should -Be $Governance.resourceId
        $Classification.TenantName | Should -Be 'contoso'
        $OutputText | Should -Not -Match ([regex]::Escape($OriginalGuid))
        $OutputText | Should -Not -Match 'fabrikam|Secret Person|secret_person'

        (Get-Content -LiteralPath (Join-Path $PrivilegedEamPath "$OriginalGuid.json") -Raw) | Should -Match ([regex]::Escape($OriginalGuid))
    }

    It 'uses TenantName for the Classification folder despite a matching management group name' {
        $CustomDestination = Join-Path $TestDrive 'destination-custom-tenant'
        $null = Convert-EntraOpsExportToSampleData -SourcePath $SourcePath -DestinationPath $CustomDestination `
            -SourceTenantName 'fabrikam' -TenantName 'adatum' -Seed 'pester-seed' `
            -ProgressAction SilentlyContinue

        Test-Path -LiteralPath (Join-Path $CustomDestination 'Classification/adatum.onmicrosoft.com') | Should -BeTrue
        Test-Path -LiteralPath (Join-Path $CustomDestination 'Classification/managementgroup01.onmicrosoft.com') | Should -BeFalse
        $ManagementGroup = Get-Content -LiteralPath (Join-Path $CustomDestination 'Classification/adatum.onmicrosoft.com/management-group.json') -Raw | ConvertFrom-Json
        $ManagementGroup.scope | Should -Be '/providers/Microsoft.Management/managementGroups/managementgroup01'
    }

    It 'generates offline reports from the anonymized PrivilegedEAM data' {
        $ReportDestination = Join-Path $DestinationPath 'StaticReports'
        $Identity | ConvertTo-Json | Set-Content -LiteralPath (Join-Path (Split-Path -Parent $PrivilegedEamPath) 'EntraID.json')
        $Result = Convert-EntraOpsExportToSampleData -SourcePath $SourcePath -DestinationPath $DestinationPath `
            -SourceTenantName 'fabrikam' -Seed 'pester-seed' -GenerateReports `
            -ReportDestinationPath $ReportDestination -ProgressAction SilentlyContinue

        $Result.ReportPath | Should -Be $ReportDestination
        $Result.GeneratedReports | Should -Be @('EamDashboard', 'TierBreachAnalyzer', 'AccessPathMap')
        Test-Path -LiteralPath (Join-Path $ReportDestination 'index.html') | Should -BeTrue
        Test-Path -LiteralPath (Join-Path $ReportDestination 'EamDashboard/data/eam-dashboard-data.js') | Should -BeTrue
        Test-Path -LiteralPath (Join-Path $ReportDestination 'TierBreachAnalyzer/data/tier-breach-data.js') | Should -BeTrue
        Test-Path -LiteralPath (Join-Path $ReportDestination 'AccessPathMap/data/access-path-map-data.js') | Should -BeTrue

        $Manifest = Get-Content -LiteralPath (Join-Path $DestinationPath 'anonymization-manifest.json') -Raw | ConvertFrom-Json
        $Manifest.reportPath | Should -Be 'StaticReports'
        $Manifest.generatedReports | Should -Be @('EamDashboard', 'TierBreachAnalyzer', 'AccessPathMap')

        $ReportText = Get-ChildItem -LiteralPath $ReportDestination -Recurse -File -Filter '*.js' |
        Get-Content -Raw | Out-String
        $ReportText | Should -Not -Match ([regex]::Escape($OriginalGuid))
        $ReportText | Should -Not -Match 'fabrikam|Secret Person|secret_person'
    }

    It 'reports each processing phase in verbose mode' {
        $VerboseDestination = Join-Path $TestDrive 'destination-verbose'
        $Output = @(Convert-EntraOpsExportToSampleData -SourcePath $SourcePath -DestinationPath $VerboseDestination `
                -SourceTenantName 'fabrikam' -Seed 'pester-seed' -Verbose `
                -ProgressAction SilentlyContinue 4>&1)
        $VerboseText = $Output |
        Where-Object { $_ -is [System.Management.Automation.VerboseRecord] } |
        Out-String

        $VerboseText | Should -Match ([regex]::Escape('[1/3]'))
        $VerboseText | Should -Match ([regex]::Escape('[2/3]'))
        $VerboseText | Should -Match ([regex]::Escape('[3/3]'))
        $VerboseText | Should -Match 'Anonymization complete'
    }

    It 'displays progress by default and completes the progress activity' {
        $ScriptContent = [System.IO.File]::ReadAllText($ImplementationPath)

        $ScriptContent | Should -Match ([regex]::Escape("-PhaseNumber 1"))
        $ScriptContent | Should -Match ([regex]::Escape("-PhaseNumber 2"))
        $ScriptContent | Should -Match ([regex]::Escape("-PhaseNumber 3"))
        $ScriptContent | Should -Match 'Write-Progress.+-Completed'
    }
}
