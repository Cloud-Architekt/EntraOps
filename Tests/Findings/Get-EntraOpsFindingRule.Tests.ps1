#Requires -Modules Pester

Describe 'Get-EntraOpsFindingRule' {
    BeforeAll {
        $script:TestRepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
        Import-Module (Join-Path $script:TestRepositoryRoot 'EntraOps/EntraOps.psd1') -Force -WarningAction SilentlyContinue
        $script:Rules = @(Get-EntraOpsFindingRule)
        $script:CategoryNumber = [ordered]@{ TierBoundaries = 1; Classification = 2; JustInTimeAccess = 3; AccountProtection = 4; WorkloadIdentities = 5; AccessGovernance = 6; OwnershipAndDelegation = 7; Drift = 8 }

        # Keys of the risk flags of the deprecated exclusion parameters of New-EntraOpsConfigFile (EntraOps 1.1.0).
        $ConfigCommand = Get-Command New-EntraOpsConfigFile
        $script:ConfigExclusionKeys = @{}
        foreach ($Name in 'PimRequestFlowExcludedRiskFlags', 'AccessPackageFlowExcludedRiskFlags') {
            $script:ConfigExclusionKeys[$Name] = @($ConfigCommand.Parameters[$Name].Attributes | Where-Object { $_ -is [System.Management.Automation.ValidateSetAttribute] } | ForEach-Object { $_.ValidValues })
        }
    }

    It 'returns all rules of the catalog' {
        $script:Rules.Count | Should -Be 59
        ($script:Rules | Where-Object Area -eq 'PrivilegedAssets').Count | Should -Be 12
        ($script:Rules | Where-Object Area -eq 'TierBreach').Count | Should -Be 2
        ($script:Rules | Where-Object Area -eq 'PrivilegedEAM').Count | Should -Be 18
        ($script:Rules | Where-Object Area -eq 'PimRequestFlow').Count | Should -Be 9
        ($script:Rules | Where-Object Area -eq 'AccessPackageFlow').Count | Should -Be 7
        ($script:Rules | Where-Object Area -eq 'TenantGovernance').Count | Should -Be 8
        ($script:Rules | Where-Object Area -eq 'PrivilegeHistory').Count | Should -Be 3
    }

    It 'keeps the released rule IDs and numbers new rules consecutively per category' {
        $Lock = Get-Content -LiteralPath (Join-Path $script:TestRepositoryRoot 'EntraOps/Private/Findings/FindingRules.lock.json') -Raw | ConvertFrom-Json
        $Problems = & (Get-Module EntraOps) { param($Rule, $Released) Test-EntraOpsFindingRuleCatalog -Rule $Rule -ReleasedRule $Released } $script:Rules @($Lock.rules)
        @($Problems) | Should -BeNullOrEmpty -Because 'Maester test IDs never change once released (run Build-EntraOpsMaesterPack.ps1 to see the problems)'
        foreach ($Category in $script:CategoryNumber.Keys) {
            @($script:Rules | Where-Object Category -eq $Category)[0].CategoryNumber | Should -Be $script:CategoryNumber[$Category]
        }
    }

    It 'detects <Case>' -ForEach @(
        @{ Case = 'a changed key of a released rule'; Change = { param($Rules) $Rules[1].Key = 'renamed' }; Message = 'changed its Key' }
        @{ Case = 'a removed released rule'; Change = { param($Rules) $Rules.RemoveAt(1) }; Message = 'is missing' }
        @{ Case = 'a new rule inserted before released rules'; Change = { param($Rules) $Rules.Insert(0, [pscustomobject]@{ Id = 'EO.1001'; Area = 'A'; Key = 'new'; Category = 'TierBoundaries'; CategoryNumber = 1 }); $Rules[1].Id = 'EO.1002'; $Rules[2].Id = 'EO.1003' }; Message = 'changed its Key|must be appended' }
        @{ Case = 'a gap in the numbering'; Change = { param($Rules) $Rules[1].Id = 'EO.1003' }; Message = 'not numbered consecutively' }
        @{ Case = 'an ID of another category'; Change = { param($Rules) $Rules[1].Id = 'EO.2002' }; Message = 'must be numbered EO.1nnn' }
    ) {
        $Rules = [System.Collections.Generic.List[object]]::new()
        foreach ($Number in 1..2) { $Rules.Add([pscustomobject]@{ Id = "EO.100$Number"; Area = 'A'; Key = "k$Number"; Category = 'TierBoundaries'; CategoryNumber = 1 }) }
        $Released = @($Rules | ForEach-Object { [pscustomobject]@{ Id = $_.Id; Area = $_.Area; Key = $_.Key; Category = $_.Category } })
        & $Change $Rules
        $Problems = & (Get-Module EntraOps) { param($Rule, $Released) Test-EntraOpsFindingRuleCatalog -Rule $Rule -ReleasedRule $Released } @($Rules) $Released
        @($Problems) -join "`n" | Should -Match $Message
    }

    It 'accepts new rules appended after the released rules and deprecated released rules' {
        $Rules = @(
            [pscustomobject]@{ Id = 'EO.1001'; Area = 'A'; Key = 'k1'; Category = 'TierBoundaries'; CategoryNumber = 1; Lifecycle = 'Deprecated' }
            [pscustomobject]@{ Id = 'EO.1002'; Area = 'A'; Key = 'k2'; Category = 'TierBoundaries'; CategoryNumber = 1 }
        )
        $Released = @([pscustomobject]@{ Id = 'EO.1001'; Area = 'A'; Key = 'k1'; Category = 'TierBoundaries' })
        @(& (Get-Module EntraOps) { param($Rule, $Released) Test-EntraOpsFindingRuleCatalog -Rule $Rule -ReleasedRule $Released } $Rules $Released) | Should -BeNullOrEmpty
    }

    It 'uses unique IDs of a known category' {
        @($script:Rules.Id | Select-Object -Unique).Count | Should -Be $script:Rules.Count
        foreach ($Rule in $script:Rules) {
            $Rule.Id | Should -Match '^EO\.\d{4}$'
            $Rule.Category | Should -BeIn @($script:CategoryNumber.Keys)
        }
    }

    It 'uses unique keys within an area' {
        foreach ($Group in ($script:Rules | Group-Object Area)) {
            @($Group.Group.Key | Select-Object -Unique).Count | Should -Be $Group.Count -Because "keys of $($Group.Name) identify review states and exclusions"
        }
    }

    It 'has the metadata a Maester test needs' {
        foreach ($Rule in $script:Rules) {
            $Rule.Severity | Should -BeIn @('Critical', 'High', 'Medium', 'Low', 'Info') -Because $Rule.Id
            # Maester check titles state the expected state as a sentence, like the tests that ship with Maester.
            $Rule.CheckTitle | Should -Match '^[A-Z].+\.$' -Because "$($Rule.Id) needs a Maester check title"
            $Rule.CheckTitle | Should -Not -Be $Rule.Title
            foreach ($Field in 'Key', 'Title', 'Description', 'Remediation', 'ReportSeverity', 'Product', 'Feature', 'ResourceType', 'CategoryTitle', 'EffortDescription', 'UserImpactDescription') {
                $Rule.$Field | Should -Not -BeNullOrEmpty -Because "$($Rule.Id) needs $Field"
            }
            $Rule.Effort | Should -BeIn @('Low', 'Medium', 'High') -Because "$($Rule.Id) needs the implementation effort"
            $Rule.UserImpact | Should -BeIn @('Low', 'Medium', 'High') -Because "$($Rule.Id) needs the user impact"
            # Every rule links its resources (the reports and the Maester test descriptions show them).
            @($Rule.References).Count | Should -BeGreaterThan 0 -Because "$($Rule.Id) needs references"
            foreach ($Reference in $Rule.References) {
                $Reference.Title | Should -Not -BeNullOrEmpty -Because "$($Rule.Id) references need a title"
                $Reference.Url | Should -Match '^https://' -Because "$($Rule.Id) references need an https URL"
                $Reference.Type | Should -BeIn @('Learn', 'Graph', 'EntraOps', 'Maester') -Because "$($Rule.Id) references need a known type"
            }
            @($Rule.References.Url | Select-Object -Unique).Count | Should -Be @($Rule.References).Count -Because "$($Rule.Id) references are unique"
            # Maester Pack test IDs: MP.<Code>.<n>, code of 2-10 letters or digits starting with a letter.
            $Rule.MaesterTestId | Should -Match '^MP\.[A-Za-z][A-Za-z0-9]{1,9}\.\d{4}$'
            $Rule.MaesterTestId | Should -Be ('MP.EOPS.' + $Rule.Id.Substring(3))
        }
    }

    It 'filters by area, ID and key' {
        @(Get-EntraOpsFindingRule -Area TierBreach).Id | Should -Be @('EO.1001', 'EO.1003')
        @(Get-EntraOpsFindingRule -Id 'EO.300*').Count | Should -Be 9
        @(Get-EntraOpsFindingRule -Category Drift).Key | Should -Be @('newControlPlaneAccess', 'tierBreachIncrease', 'newDelegatedPrivilegedPermission')
        @(Get-EntraOpsFindingRule -Category AccessGovernance).Key | Should -Be @('noApproval', 'broadRequestor', 'unauthorizedAccess', 'missingAccess', 'accessPackageExpiration', 'accessPackageAccessReview')
        @(Get-EntraOpsFindingRule -Key 'approverLowerTier').Area | Should -Be @('PimRequestFlow', 'AccessPackageFlow')
        @(Get-EntraOpsFindingRule -Key 'approverLowerTier').Category | Should -Be @('TierBoundaries', 'TierBoundaries')
    }

    It 'covers the findings of the Privileged Assets report' {
        # The What-if rules of the report (Reports/PrivilegedAssets/js/findings.js) name their rule key and ID.
        $FindingsJs = Get-Content -LiteralPath (Join-Path $script:TestRepositoryRoot 'Reports/PrivilegedAssets/js/findings.js') -Raw
        $ReportKeys = @([regex]::Matches($FindingsJs, '\{\s*key:\s*"(\w+)",\s*id:\s*"EO\.\d{4}"') | ForEach-Object { $_.Groups[1].Value })
        $ReportKeys.Count | Should -BeGreaterThan 0
        @($script:Rules | Where-Object Area -eq 'PrivilegedAssets').Key | Sort-Object | Should -Be ($ReportKeys | Sort-Object)
    }

    It 'matches the catalog in the fallback rules of the Privileged Assets report' {
        # Used for data generated without findings (What-if); id, title, severity and category must match the catalog.
        $FindingsJs = Get-Content -LiteralPath (Join-Path $script:TestRepositoryRoot 'Reports/PrivilegedAssets/js/findings.js') -Raw
        $Entries = [regex]::Matches($FindingsJs, '\{\s*key:\s*"(?<key>\w+)",\s*id:\s*"(?<id>EO\.\d{4})",\s*title:\s*"(?<title>[^"]+)",\s*severity:\s*"(?<severity>\w+)",\s*category:\s*"(?<category>\w+)"')
        $Entries.Count | Should -Be @($script:Rules | Where-Object Area -eq 'PrivilegedAssets').Count
        foreach ($Entry in $Entries) {
            $Rule = $script:Rules | Where-Object { $_.Area -eq 'PrivilegedAssets' -and $_.Key -eq $Entry.Groups['key'].Value }
            "$($Entry.Groups['key'].Value): $($Entry.Groups['id'].Value) $($Entry.Groups['title'].Value) $($Entry.Groups['severity'].Value) $($Entry.Groups['category'].Value)" |
                Should -Be "$($Rule.Key): $($Rule.Id) $($Rule.Title) $($Rule.Severity) $($Rule.Category)"
        }
    }

    It 'knows the risk flags that the <Report> report refers to' -ForEach @(
        @{ Report = 'PimRequestFlow'; Area = 'PimRequestFlow' }
        @{ Report = 'AccessPackageFlow'; Area = 'AccessPackageFlow' }
    ) {
        # The report shows the risk flags of New-EntraOpsReportFindingData; its metric tiles and counters
        # refer to some of them by key.
        $Source = (Get-Content -LiteralPath (Join-Path $script:TestRepositoryRoot "Reports/$Report/js/app.js") -Raw) + (Get-Content -LiteralPath (Join-Path $script:TestRepositoryRoot "Reports/$Report/index.html") -Raw)
        $ReportKeys = @([regex]::Matches($Source, 'data-(?:pim|ap)-metric="(\w+)"|fl\.id === "(\w+)"') | ForEach-Object { $_.Groups[1].Value + $_.Groups[2].Value } |
                Where-Object { $_ -notin 'all', 'anyRisk' } | Select-Object -Unique)
        $ReportKeys.Count | Should -BeGreaterThan 0
        $ReportKeys | Where-Object { $_ -notin @($script:Rules | Where-Object Area -eq $Area).Key } | Should -BeNullOrEmpty
    }

    It 'maps the deprecated <Setting> of EntraOps 1.1.0 to rules of <Area>' -ForEach @(
        @{ Setting = 'PimRequestFlowExcludedRiskFlags'; Area = 'PimRequestFlow' }
        @{ Setting = 'AccessPackageFlowExcludedRiskFlags'; Area = 'AccessPackageFlow' }
    ) {
        $AreaKeys = @($script:Rules | Where-Object Area -eq $Area).Key
        $script:ConfigExclusionKeys[$Setting].Count | Should -BeGreaterThan 0
        $script:ConfigExclusionKeys[$Setting] | Where-Object { $_ -cnotin $AreaKeys } | Should -BeNullOrEmpty -Because 'every deprecated risk flag is a rule key of its area'
    }

    It 'uses the severity Info for the rules that ask for a review (Investigate), and only for them' {
        foreach ($Rule in $script:Rules) {
            ($Rule.Severity -eq 'Info') | Should -Be ([bool]$Rule.Investigate) -Because "$($Rule.Id): a rule whose findings fail the check has a severity, a rule that asks for a review is Info"
        }
    }

    It 'derives the report severity: the breach type of Tier Breach, fail or warn for the flow reports, else the severity' {
        foreach ($Rule in $script:Rules) {
            $Expected = if ($Rule.Area -eq 'TierBreach') { $Rule.Key } elseif ($Rule.Area -in 'PimRequestFlow', 'AccessPackageFlow' -and $Rule.Severity -in 'Critical', 'High', 'Medium', 'Low') { @{ Critical = 'fail'; High = 'fail'; Medium = 'warn'; Low = 'warn' }[$Rule.Severity] } else { $Rule.Severity.ToLowerInvariant() }
            $Rule.ReportSeverity | Should -BeExactly $Expected -Because $Rule.Id
        }
        (Get-EntraOpsFindingRule -Id EO.1001).ReportSeverity | Should -BeExactly 'tier0Breach'
        (Get-EntraOpsFindingRule -Id EO.6001).ReportSeverity | Should -BeExactly 'fail'
        (Get-EntraOpsFindingRule -Id EO.4009).ReportSeverity | Should -BeExactly 'low'
        (Get-EntraOpsFindingRule -Id EO.4010).ReportSeverity | Should -BeExactly 'info'
        (Get-EntraOpsFindingRule -Id EO.4008).ReportSeverity | Should -BeExactly 'medium'
        # An informational flow rule: listed with the risk flags, not counted as one.
        (Get-EntraOpsFindingRule -Id EO.2005).ReportSeverity | Should -BeExactly 'info'
    }

    It 'has an evaluator and a context builder for every area of the catalog, and only for those' {
        $Module = Get-Module EntraOps
        $Areas = @(& $Module { (Get-EntraOpsFindingCatalog).Areas })
        @($script:Rules.Area | Select-Object -Unique) | Should -Be $Areas
        $Functions = @(& $Module { Get-Command -Module EntraOps -CommandType Function -ListImported -ErrorAction SilentlyContinue; Get-ChildItem function: }).Name | Select-Object -Unique
        foreach ($Area in $Areas) {
            $Functions | Should -Contain "Invoke-EntraOps$($Area)FindingRule"
            $Functions | Should -Contain "New-EntraOps$($Area)FindingContext"
        }
        foreach ($Name in @($Functions | Where-Object { $_ -match '^Invoke-EntraOps(\w+)FindingRule$' -and $_ -ne 'Invoke-EntraOpsFindingRuleSet' })) {
            $Matches[1] | Should -BeIn $Areas -Because "$Name evaluates an area of the catalog"
        }
        $Categories = @(& $Module { (Get-EntraOpsFindingCatalog).CategoryKeys })
        $script:Rules.Category | Select-Object -Unique | Where-Object { $_ -notin $Categories } | Should -BeNullOrEmpty
        foreach ($Category in $Categories) { @($script:Rules | Where-Object Category -eq $Category).Count | Should -BeGreaterThan 0 -Because "category $Category has rules" }
    }

    It 'completes the areas and categories of the catalog' {
        $Completion = TabExpansion2 -inputScript 'Get-EntraOpsFindingRule -Area Tier' -cursorColumn 'Get-EntraOpsFindingRule -Area Tier'.Length
        $Completion.CompletionMatches.CompletionText | Should -Be @('TierBreach')
        $Completion = TabExpansion2 -inputScript 'Invoke-EntraOpsFindingEvaluation -Category Dr' -cursorColumn 'Invoke-EntraOpsFindingEvaluation -Category Dr'.Length
        $Completion.CompletionMatches.CompletionText | Should -Be @('Drift')
    }
}
