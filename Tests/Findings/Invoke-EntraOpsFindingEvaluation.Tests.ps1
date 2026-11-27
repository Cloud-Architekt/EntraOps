#Requires -Modules Pester

Describe 'Invoke-EntraOpsFindingEvaluation' {
    BeforeAll {
        $script:TestRepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
        Import-Module (Join-Path $script:TestRepositoryRoot 'EntraOps/EntraOps.psd1') -Force -WarningAction SilentlyContinue

        function New-TestRoleAssignment {
            param([string]$Name, [string]$InstanceId, [object[]]$Classification, [string]$Scope = '/')
            [ordered]@{
                RoleDefinitionName = $Name; RoleIsPrivileged = $true; RoleAssignmentId = "ra-$InstanceId"; RoleAssignmentInstanceId = $InstanceId
                RoleAssignmentScopeId = $Scope; RoleAssignmentScopeName = 'Tenant'; RoleAssignmentType = 'Direct'; PIMAssignmentType = 'Eligible'
                Classification = $Classification
            }
        }
    }

    BeforeEach {
        $script:Root = Join-Path $TestDrive ([guid]::NewGuid())
        New-Item -ItemType Directory -Path "$script:Root/PrivilegedEAM/EntraID", "$script:Root/PrivilegedEAM/EntraID/user", "$script:Root/Reports/TierBreachAnalyzer" -Force | Out-Null
        @(
            # Control Plane user with a Control Plane role: no breach.
            [ordered]@{ ObjectId = 'cp-user'; ObjectType = 'user'; ObjectDisplayName = 'CP Admin'; ObjectAdminTierLevel = '0'
                RoleAssignments = @(New-TestRoleAssignment -Name 'Global Administrator' -InstanceId 'i1' -Classification @(@{ Service = 'Global'; AdminTierLevel = '0' }))
            }
            # Management Plane user reaching Tier 0 and Tier 1: Tier 0 breach on the Tier 0 path only (the breach rule
            # leaves out Control Plane services, and the Tier 1 path is within the object's own tier).
            [ordered]@{ ObjectId = 'mp-user'; ObjectType = 'user'; ObjectDisplayName = 'MP Admin'; ObjectAdminTierLevel = '1'
                RoleAssignments = @(New-TestRoleAssignment -Name 'Privileged Role Administrator' -InstanceId 'i2' -Classification @(@{ Service = 'Roles'; AdminTierLevel = '0' }, @{ Service = 'Groups'; AdminTierLevel = '1' }))
            }
            # Unclassified service principal (Tier 2) reaching Tier 1: counted apart by the breach rule, no Tier 0 breach.
            [ordered]@{ ObjectId = 'sp'; ObjectType = 'serviceprincipal'; ObjectDisplayName = 'App'; ObjectAdminTierLevel = 'Unclassified'
                RoleAssignments = @(New-TestRoleAssignment -Name 'Groups Administrator' -InstanceId 'i3' -Classification @(@{ Service = 'Groups'; AdminTierLevel = '1' }))
            }
            # User Access user reaching Tier 1: breach.
            [ordered]@{ ObjectId = 'ua-user'; ObjectType = 'user'; ObjectDisplayName = 'UA User'; ObjectAdminTierLevel = '2'
                RoleAssignments = @(New-TestRoleAssignment -Name 'User Administrator' -InstanceId 'i5' -Classification @(@{ Service = 'Users'; AdminTierLevel = '1' }))
            }
            # Groups are not evaluated.
            [ordered]@{ ObjectId = 'group'; ObjectType = 'group'; ObjectDisplayName = 'Group'; ObjectAdminTierLevel = '2'
                RoleAssignments = @(New-TestRoleAssignment -Name 'Global Administrator' -InstanceId 'i4' -Classification @(@{ Service = 'Global'; AdminTierLevel = '0' }))
            }
        ) | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath "$script:Root/PrivilegedEAM/EntraID/EntraID.json"
        # Per-object subfolders are not read.
        '[{"ObjectId":"ignored","ObjectType":"user","ObjectAdminTierLevel":"2","RoleAssignments":[{"RoleDefinitionName":"x","Classification":[{"Service":"Global","AdminTierLevel":"0"}]}]}]' |
            Set-Content -LiteralPath "$script:Root/PrivilegedEAM/EntraID/user/ignored.json"
    }

    It 'returns one result per Tier Breach rule with the failed paths' {
        $Results = @(Invoke-EntraOpsFindingEvaluation -Area TierBreach -ImportPath "$script:Root/PrivilegedEAM")

        # Sorted by rule ID: the Tier 0 breach (Critical) comes first in the Tier boundaries category.
        $Results.RuleId | Should -Be @('EO.1001', 'EO.1003')
        $Breach = $Results | Where-Object Key -eq 'breach'
        $Breach.Status | Should -Be 'Failed'
        # One instance per role assignment (cp-user, mp-user, sp, ua-user); groups are not evaluated.
        $Breach.EvaluatedCount | Should -Be 4
        $Breach.FailedCount | Should -Be 1
        $Breach.MaesterTestId | Should -Be 'MP.EOPS.1003'
        $Breach.Category | Should -Be 'TierBoundaries'
        @($Breach.Results.Instance.ObjectId) | Should -Be @('ua-user')
        $Breach.Results[0].Message | Should -Be "User Access object 'UA User' reaches the Management Plane service 'Users' through the role 'User Administrator' (EntraID) at 'Tenant'."
        # Unclassified objects are counted apart, not reported.
        $Breach.UnclassifiedCount | Should -Be 1
        @($Breach.UnclassifiedResults.Instance.ObjectId) | Should -Be @('sp')
        $Breach.UnclassifiedResults[0].Message | Should -Be "Unclassified object (counted as User Access) 'App' reaches the Management Plane service 'Groups' through the role 'Groups Administrator' (EntraID) at 'Tenant'."

        $Tier0 = $Results | Where-Object Key -eq 'tier0Breach'
        $Tier0.FailedCount | Should -Be 1
        $Tier0.UnclassifiedCount | Should -Be 0
        $Tier0.Results[0].Severity | Should -Be 'Critical'
        $Tier0.Results[0].Instance.ObjectId | Should -Be 'mp-user'
        $Tier0.Results[0].Instance.AdminTierLevel | Should -Be 1
        $Tier0.Results[0].Evidence.Service | Should -Be 'Roles'
        $Tier0.Results[0].Evidence.ServiceTierLevel | Should -Be 0
        $Tier0.Results[0].Message | Should -Be "Management Plane object 'MP Admin' reaches the Control Plane service 'Roles' through the role 'Privileged Role Administrator' (EntraID) at 'Tenant'."
    }

    It 'keeps unclassified objects as Tier 0 breaches, marks them in the evidence and notes how many there are' {
        @(
            [ordered]@{ ObjectId = 'mp-user'; ObjectType = 'user'; ObjectDisplayName = 'MP Admin'; ObjectAdminTierLevel = '1'
                RoleAssignments = @(New-TestRoleAssignment -Name 'Privileged Role Administrator' -InstanceId 'i2' -Classification @(@{ Service = 'Roles'; AdminTierLevel = '0' }))
            }
            [ordered]@{ ObjectId = 'sp'; ObjectType = 'serviceprincipal'; ObjectDisplayName = 'App'; ObjectAdminTierLevel = 'Unclassified'
                RoleAssignments = @(New-TestRoleAssignment -Name 'Application Administrator' -InstanceId 'i3' -Classification @(@{ Service = 'Apps'; AdminTierLevel = '0' }))
            }
        ) | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath "$script:Root/PrivilegedEAM/EntraID/EntraID.json"

        $Tier0 = @(Invoke-EntraOpsFindingEvaluation -Area TierBreach -ImportPath "$script:Root/PrivilegedEAM") | Where-Object Key -eq 'tier0Breach'
        $Tier0.FailedCount | Should -Be 2
        $Tier0.UnclassifiedCount | Should -Be 0
        ($Tier0.Results | Where-Object { $_.Instance.ObjectId -eq 'sp' }).Evidence.ObjectUnclassified | Should -BeTrue
        ($Tier0.Results | Where-Object { $_.Instance.ObjectId -eq 'mp-user' }).Evidence.ObjectUnclassified | Should -BeFalse
        $Tier0.ReasonCode | Should -Be 'Note'
        $Tier0.Reason | Should -BeLike '1 of 2 results are objects without a classification, counted as User Access*Classify these objects first (EO.2001)*'
    }

    It 'reports an assignment once with all services it reaches' {
        @(
            [ordered]@{ ObjectId = 'mp-user'; ObjectType = 'user'; ObjectDisplayName = 'MP Admin'; ObjectAdminTierLevel = '1'
                RoleAssignments = @(New-TestRoleAssignment -Name 'Global Administrator' -InstanceId 'i7' -Classification @(
                        @{ Service = 'Tenant'; AdminTierLevel = '0' }, @{ Service = 'Roles'; AdminTierLevel = '0' }, @{ Service = 'Users'; AdminTierLevel = '0' }, @{ Service = 'Apps'; AdminTierLevel = '0' }, @{ Service = 'Groups'; AdminTierLevel = '1' }))
            }
            # A User Access user whose assignment reaches Tier 0 and Tier 1: reported by the Tier 0 rule only.
            [ordered]@{ ObjectId = 'ua-user'; ObjectType = 'user'; ObjectDisplayName = 'UA User'; ObjectAdminTierLevel = '2'
                RoleAssignments = @(New-TestRoleAssignment -Name 'Mixed Role' -InstanceId 'i8' -Classification @(@{ Service = 'Roles'; AdminTierLevel = '0' }, @{ Service = 'Users'; AdminTierLevel = '1' }))
            }
        ) | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath "$script:Root/PrivilegedEAM/EntraID/EntraID.json"

        $Results = @(Invoke-EntraOpsFindingEvaluation -Area TierBreach -ImportPath "$script:Root/PrivilegedEAM")
        $Tier0 = $Results | Where-Object Key -eq 'tier0Breach'
        $Tier0.EvaluatedCount | Should -Be 2
        $Tier0.FailedCount | Should -Be 2
        $Admin = $Tier0.Results | Where-Object { $_.Instance.ObjectId -eq 'mp-user' }
        @($Admin.Evidence.Services) | Should -Be @('Apps', 'Roles', 'Tenant', 'Users')
        $Admin.Evidence.Service | Should -Be 'Apps'
        @($Admin.Evidence.PathIds).Count | Should -Be 4
        $Admin.Message | Should -Be "Management Plane object 'MP Admin' reaches 4 Control Plane services ('Apps', 'Roles', 'Tenant' and 1 more) through the role 'Global Administrator' (EntraID) at 'Tenant'."
        ($Results | Where-Object Key -eq 'breach').FailedCount | Should -Be 0
    }

    It 'leaves out delegated permissions and Microsoft first-party service principals, which the analyzer still flags' {
        $Delegated = New-TestRoleAssignment -Name 'Directory.ReadWrite.All' -InstanceId 'i9' -Classification @(@{ Service = 'Tenant'; AdminTierLevel = '0' })
        $Delegated.RoleType = 'Delegated'
        @(
            [ordered]@{ ObjectId = 'client'; ObjectType = 'serviceprincipal'; ObjectDisplayName = 'Client'; ObjectAdminTierLevel = '2'; RoleAssignments = @($Delegated) }
            [ordered]@{ ObjectId = 'ms-app'; ObjectType = 'serviceprincipal'; ObjectDisplayName = 'Microsoft App'; ObjectAdminTierLevel = '2'; OriginTenantId = 'f8cdef31-a31e-4b4a-93e4-5f571e91255a'
                RoleAssignments = @(New-TestRoleAssignment -Name 'Directory Writers' -InstanceId 'i10' -Classification @(@{ Service = 'Tenant'; AdminTierLevel = '0' }))
            }
        ) | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath "$script:Root/PrivilegedEAM/EntraID/EntraID.json"

        $Tier0 = Invoke-EntraOpsFindingEvaluation -Area TierBreach -ImportPath "$script:Root/PrivilegedEAM" | Where-Object Key -eq 'tier0Breach'
        $Tier0.EvaluatedCount | Should -Be 0
        $Tier0.FailedCount | Should -Be 0
        $Payload = New-EntraOpsTierBreachAnalyzerData -RepoRoot $script:Root -AppRoot "$script:Root/Reports/TierBreachAnalyzer" -ImportPath "$script:Root/PrivilegedEAM" -PassThru -WhatIf
        @($Payload.paths | Where-Object tier0Breach).Count | Should -Be 2
    }

    It 'uses stable path IDs that are valid Maester instance IDs' {
        $First = @((Invoke-EntraOpsFindingEvaluation -Area TierBreach -ImportPath "$script:Root/PrivilegedEAM" | Where-Object Key -eq 'breach').Results.Instance.Id)
        $Second = @((Invoke-EntraOpsFindingEvaluation -Area TierBreach -ImportPath "$script:Root/PrivilegedEAM" | Where-Object Key -eq 'breach').Results.Instance.Id)

        $Second | Should -Be $First
        @($First | Select-Object -Unique).Count | Should -Be $First.Count
        foreach ($Id in $First) { $Id | Should -Match '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$' }
    }

    It 'excludes rules by ID or by area and key' {
        $Results = @(Invoke-EntraOpsFindingEvaluation -Area TierBreach -ImportPath "$script:Root/PrivilegedEAM" -ExcludeRule 'EO.1003', 'TierBreach.tier0Breach')

        $Results.Status | Should -Be @('Excluded', 'Excluded')
        $Results.FailedCount | Should -Be @(0, 0)
    }

    It 'skips the breach rule with the reason to classify when only unclassified objects are affected' {
        @(
            [ordered]@{ ObjectId = 'sp'; ObjectType = 'serviceprincipal'; ObjectDisplayName = 'App'; ObjectAdminTierLevel = 'Unclassified'
                RoleAssignments = @(
                    New-TestRoleAssignment -Name 'Groups Administrator' -InstanceId 'i3' -Classification @(@{ Service = 'Groups'; AdminTierLevel = '1' })
                    New-TestRoleAssignment -Name 'User Administrator' -InstanceId 'i6' -Classification @(@{ Service = 'Users'; AdminTierLevel = '1' })
                )
            }
        ) | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath "$script:Root/PrivilegedEAM/EntraID/EntraID.json"

        $Breach = Invoke-EntraOpsFindingEvaluation -Area TierBreach -ImportPath "$script:Root/PrivilegedEAM" | Where-Object Key -eq 'breach'
        $Breach.Status | Should -Be 'Skipped'
        $Breach.FailedCount | Should -Be 0
        $Breach.EvaluatedCount | Should -Be 2
        $Breach.UnclassifiedCount | Should -Be 2
        $Breach.Reason | Should -Be 'Only unclassified objects are affected: 1 unclassified object(s) with 2 affected role assignments. Classify these objects (EO.2001) to evaluate this check: their tier is unknown, so they are not reported as findings.'

        # The unclassified results are saved for the reports, which list them on request.
        $Breach | Save-EntraOpsFindingJson -ExportFolder "$script:Root/Findings" -TenantId 't' -TenantName 't' 6> $null
        $Saved = (Get-Content -LiteralPath "$script:Root/Findings/findings.json" -Raw | ConvertFrom-Json).Rules[0]
        $Saved.Status | Should -Be 'Skipped'
        $Saved.UnclassifiedCount | Should -Be 2
        @($Saved.UnclassifiedResults.Instance.ObjectId | Select-Object -Unique) | Should -Be @('sp')
        @($Saved.Results).Count | Should -Be 0
    }

    It 'passes when no path breaches and skips when there is nothing to evaluate' {
        @(
            [ordered]@{ ObjectId = 'cp-user'; ObjectType = 'user'; ObjectDisplayName = 'CP Admin'; ObjectAdminTierLevel = '0'
                RoleAssignments = @(New-TestRoleAssignment -Name 'Global Administrator' -InstanceId 'i1' -Classification @(@{ Service = 'Global'; AdminTierLevel = '0' }))
            }
        ) | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath "$script:Root/PrivilegedEAM/EntraID/EntraID.json"
        @(Invoke-EntraOpsFindingEvaluation -Area TierBreach -ImportPath "$script:Root/PrivilegedEAM").Status | Should -Be @('Passed', 'Passed')

        Remove-Item -LiteralPath "$script:Root/PrivilegedEAM/EntraID/EntraID.json"
        $Skipped = @(Invoke-EntraOpsFindingEvaluation -Area TierBreach -ImportPath "$script:Root/PrivilegedEAM" -WarningAction SilentlyContinue)
        $Skipped.Status | Should -Be @('Skipped', 'Skipped')
        $Skipped[0].Reason | Should -Be 'No role assignments in the scope of this rule (0 evaluated).'
    }

    It 'skips the rules without export and names the cmdlets that create it' {
        $Results = @(Invoke-EntraOpsFindingEvaluation -Area TierBreach, PrivilegedAssets, PrivilegedEAM -ImportPath "$script:Root/missing")
        $Results.Status | Select-Object -Unique | Should -Be 'Skipped'
        $Results[0].Reason | Should -Match 'Run Invoke-EntraOpsPrivilegedEAM \(or Save-EntraOpsPrivilegedEAMJson\) first'
    }

    It 'returns the rules with status Error when the export cannot be read' {
        'not json' | Set-Content -LiteralPath "$script:Root/PrivilegedEAM/EntraID/EntraID.json"
        $Results = @(Invoke-EntraOpsFindingEvaluation -Area TierBreach, PrivilegedAssets -ImportPath "$script:Root/PrivilegedEAM" -WarningAction SilentlyContinue)
        $Results.Status | Select-Object -Unique | Should -Be 'Error'
        $Results[0].Reason | Should -Match 'Failed to read or parse Privileged EAM export file'

        # The status and its reason are saved for the reports and the EntraOps Maester Pack.
        $Results | Save-EntraOpsFindingJson -ExportFolder "$script:Root/Findings" -TenantId 't' -TenantName 't' 6> $null
        $Saved = Get-Content -LiteralPath "$script:Root/Findings/findings.json" -Raw | ConvertFrom-Json
        $Saved.Rules.Status | Select-Object -Unique | Should -Be 'Error'
        $Saved.Rules[0].Reason | Should -Be $Results[0].Reason
    }

    It 'returns a rule whose evaluator fails with status Error and evaluates the other rules' {
        $Results = & (Get-Module EntraOps) {
            # Inventory without the checks of the objects: the evaluator fails on the first object.
            $Context = [pscustomobject]@{ Area = 'PrivilegedAssets'; Objects = @([ordered]@{ objectId = 'o1' }); ObjectFindings = $null }
            @(Invoke-EntraOpsFindingRuleSet -Context $Context -WarningAction SilentlyContinue)
        }
        $Results.Status | Select-Object -Unique | Should -Be 'Error'
        $Results[0].Reason | Should -Match '^The rule could not be evaluated: '
    }

    It 'returns deprecated rules as Excluded without evaluating them' {
        $Results = & (Get-Module EntraOps) {
            $Context = New-EntraOpsTierBreachFindingContext -ImportPath $args[0]
            Mock Get-EntraOpsFindingRule -ModuleName EntraOps { $Rule = (& (Get-Command Get-EntraOpsFindingRule -CommandType Function) @PesterBoundParameters); foreach ($Item in $Rule) { if ($Item.Id -eq 'EO.1003') { $Item.Lifecycle = 'Deprecated' }; $Item } }
            @(Invoke-EntraOpsFindingRuleSet -Context $Context)
        } "$script:Root/PrivilegedEAM"
        ($Results | Where-Object RuleId -eq 'EO.1003').Status | Should -Be 'Excluded'
        ($Results | Where-Object RuleId -eq 'EO.1003').Reason | Should -Match '^Deprecated rule'
        ($Results | Where-Object RuleId -eq 'EO.1001').Status | Should -Be 'Failed'
    }

    It 'shows the rule results, rules and findings as tables' {
        $Results = @(Invoke-EntraOpsFindingEvaluation -Area TierBreach -ImportPath "$script:Root/PrivilegedEAM")
        $Results[0].PSObject.TypeNames | Should -Contain 'EntraOps.FindingRuleResult'
        $Results[0].Results[0].PSObject.TypeNames | Should -Contain 'EntraOps.Finding'
        $Results[0].Results[0].Instance | Should -BeOfType [pscustomobject]

        $Table = $Results | Out-String -Width 200
        $Table | Should -Match 'RuleId\s+Severity\s+Status\s+Failed/Evaluated\s+Title'
        $Table | Should -Match 'EO\.1003\s+High\s+Failed\s+1/4\s+Role assignment'
        ($Results[0].Results | Out-String -Width 200) | Should -Match 'RuleId\s+Severity\s+DisplayName\s+Message'
        (Get-EntraOpsFindingRule -Area TierBreach | Out-String -Width 200) | Should -Match 'Id\s+Area\s+Severity\s+Title'
    }

    It 'rejects an unknown area or category with the valid values' {
        { Invoke-EntraOpsFindingEvaluation -Area TierBreech -ImportPath "$script:Root/PrivilegedEAM" } | Should -Throw "Unknown finding rule area 'TierBreech'. Valid values: *TierBreach*"
        { Get-EntraOpsFindingRule -Category Drifts } | Should -Throw "Unknown finding rule category 'Drifts'. Valid values: TierBoundaries, *"
    }

    It 'flags the same paths in the Tier Breach Analyzer data as the finding rules' {
        $Payload = New-EntraOpsTierBreachAnalyzerData -RepoRoot $script:Root -AppRoot "$script:Root/Reports/TierBreachAnalyzer" -ImportPath "$script:Root/PrivilegedEAM" -PassThru -WhatIf
        $Results = @(Invoke-EntraOpsFindingEvaluation -Area TierBreach -ImportPath "$script:Root/PrivilegedEAM")

        # The analyzer's breach flag covers the paths of both rules (breach leaves out Control Plane services),
        # including the paths of unclassified objects that the breach rule counts apart.
        $Rules = @($Results | Where-Object Key -in 'breach', 'tier0Breach')
        @($Payload.paths | Where-Object breach | ForEach-Object pathId | Sort-Object) | Should -Be @(@($Rules.Results.Evidence.PathIds) + @($Rules.UnclassifiedResults.Evidence.PathIds) | Sort-Object)
        @($Payload.paths | Where-Object tier0Breach | ForEach-Object pathId) | Should -Be @(($Results | Where-Object Key -eq 'tier0Breach').Results.Evidence.PathIds)
        @($Payload.paths).Count | Should -Be 5
    }

    It 'accepts the results of finding exceptions and reports expired, stale and invalid exceptions' {
        $Config = "$script:Root/EntraOpsConfig.json"
        '{ "Findings": { "ExceptionMaxDays": 30 } }' | Set-Content -LiteralPath $Config
        $PathId = (Invoke-EntraOpsFindingEvaluation -Area TierBreach -ImportPath "$script:Root/PrivilegedEAM" -ConfigFilePath $Config | Where-Object Key -eq 'breach').Results[0].Instance.Id
        $Today = (Get-Date).ToUniversalTime().Date
        $Day = { param($Offset) $Today.AddDays($Offset).ToString('yyyy-MM-dd') }
        New-Item -ItemType Directory -Path "$script:Root/Classification" -Force | Out-Null
        @(
            # All Tier 0 breaches of the object: accepted until next week.
            [ordered]@{ RuleId = 'eo.1001'; ObjectId = 'MP-USER'; State = 'RiskAccepted'; Justification = 'Migration to a Tier 0 account'; AcceptedBy = 'admin@contoso.com'; AcceptedOn = (& $Day -1); ExpiresOn = (& $Day 7); Reference = 'CHG-1' }
            # Expired yesterday: the path is reported again.
            [ordered]@{ RuleId = 'EO.1003'; InstanceId = $PathId; ObjectId = 'ua-user'; State = 'Dismissed'; Justification = 'False positive'; ExpiresOn = (& $Day -1) }
            # The finding is gone.
            [ordered]@{ RuleId = 'EO.1003'; ObjectId = 'removed-user'; State = 'Dismissed'; Justification = 'Old' }
            # Longer than ExceptionMaxDays: shortened.
            [ordered]@{ RuleId = 'EO.1001'; InstanceId = 'other-path'; State = 'RiskAccepted'; Justification = 'Long'; AcceptedOn = (& $Day 0); ExpiresOn = (& $Day 100) }
            # Invalid entries.
            [ordered]@{ RuleId = 'EO.9999'; ObjectId = 'x'; State = 'Dismissed'; Justification = 'Unknown rule' }
            [ordered]@{ RuleId = 'EO.1001'; ObjectId = 'x'; State = 'Dismissed' }
            [ordered]@{ RuleId = 'EO.1001'; ObjectId = 'x'; State = 'RiskAccepted'; Justification = 'No dates' }
            [ordered]@{ RuleId = 'EO.1001'; ObjectId = 'mp-user'; State = 'Dismissed'; Justification = 'Repeated' }
        ) | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath "$script:Root/Classification/FindingExceptions.json"

        $Results = @(Invoke-EntraOpsFindingEvaluation -Area TierBreach -ImportPath "$script:Root/PrivilegedEAM" -ConfigFilePath $Config -WarningVariable Warnings -WarningAction SilentlyContinue)

        $Tier0 = $Results | Where-Object Key -eq 'tier0Breach'
        $Tier0.Status | Should -Be 'Passed'
        $Tier0.FailedCount | Should -Be 0
        $Tier0.AcceptedCount | Should -Be 1
        $Tier0.AcceptedResults[0].Instance.ObjectId | Should -Be 'mp-user'
        $Tier0.AcceptedResults[0].Status | Should -Be 'RiskAccepted'
        $Tier0.AcceptedResults[0].Exception.Justification | Should -Be 'Migration to a Tier 0 account'
        $Tier0.AcceptedResults[0].Exception.Reference | Should -Be 'CHG-1'
        @($Tier0.Exceptions | ForEach-Object { "$($_.RuleId) $($_.Status) $($_.MatchedCount)" }) | Should -Be @('EO.1001 Active 1', 'EO.1001 Stale 0')
        ($Tier0.Exceptions | Where-Object InstanceId -eq 'other-path').ExpiresOn | Should -Be (& $Day 30)

        $Breach = $Results | Where-Object Key -eq 'breach'
        $Breach.Status | Should -Be 'Failed'
        $Breach.FailedCount | Should -Be 1
        $Breach.AcceptedCount | Should -Be 0
        @($Breach.Exceptions | ForEach-Object { "$($_.Status) $($_.MatchedCount)" }) | Should -Be @('Expired 1', 'Stale 0')

        $Text = $Warnings -join "`n"
        $Text | Should -Match 'Skipped 4 invalid finding exception'
        $Text | Should -Match 'unknown rule'
        $Text | Should -Match 'Justification is required'
        $Text | Should -Match 'needs AcceptedOn and ExpiresOn'
        $Text | Should -Match 'repeats the exception for object mp-user'
        $Text | Should -Match 'more than 30 days'
        $Text | Should -Match "1 finding exception\(s\) in .+ expired"

        # Rules that are not evaluated don't make their exceptions stale.
        $Excluded = Invoke-EntraOpsFindingEvaluation -Area TierBreach -ImportPath "$script:Root/PrivilegedEAM" -ConfigFilePath $Config -ExcludeRule 'EO.1001' -WarningAction SilentlyContinue | Where-Object Key -eq 'tier0Breach'
        @($Excluded.Exceptions.Status | Select-Object -Unique) | Should -Be @('NotEvaluated')

        # The saved results keep the accepted results and the exceptions for the reports and the Maester Pack.
        $Results | Save-EntraOpsFindingJson -ExportFolder "$script:Root/Findings" -ConfigFilePath $Config -TenantId 'tenant-id' -TenantName 'contoso' 6>$null
        $Saved = Get-Content -LiteralPath "$script:Root/Findings/findings.json" -Raw | ConvertFrom-Json
        $Saved.ExceptionSettings.FilePath | Should -Be './Classification/FindingExceptions.json'
        $Saved.ExceptionSettings.MaxDays | Should -Be 30
        $SavedTier0 = $Saved.Rules | Where-Object RuleId -eq 'EO.1001'
        $SavedTier0.AcceptedCount | Should -Be 1
        $SavedTier0.AcceptedResults[0].Exception.State | Should -Be 'RiskAccepted'
        @($SavedTier0.Exceptions.Status) | Should -Be @('Active', 'Stale')
        $SavedTier0.Exceptions[0].Key | Should -Be 'eo.1001||mp-user'
    }

    It 'reads no finding exceptions outside the EntraOps folder' {
        $Config = "$script:Root/EntraOpsConfig.json"
        '{ "Findings": { "ExceptionsFilePath": "../outside.json" } }' | Set-Content -LiteralPath $Config
        '[{ "RuleId": "EO.1001", "ObjectId": "mp-user", "State": "Dismissed", "Justification": "x" }]' | Set-Content -LiteralPath (Join-Path (Split-Path $script:Root) 'outside.json')

        $Tier0 = Invoke-EntraOpsFindingEvaluation -Area TierBreach -ImportPath "$script:Root/PrivilegedEAM" -ConfigFilePath $Config -WarningVariable Warnings -WarningAction SilentlyContinue | Where-Object Key -eq 'tier0Breach'

        $Tier0.Status | Should -Be 'Failed'
        @($Tier0.Exceptions).Count | Should -Be 0
        ($Warnings -join "`n") | Should -Match 'outside the EntraOps folder'
    }

    It 'reports a breach of an activated eligible assignment once, by its eligible assignment' {
        $Export = Get-Content -LiteralPath "$script:Root/PrivilegedEAM/EntraID/EntraID.json" -Raw | ConvertFrom-Json
        $MpUser = $Export | Where-Object ObjectId -eq 'mp-user'
        $Activation = New-TestRoleAssignment -Name 'Privileged Role Administrator' -InstanceId 'i2-activated' -Classification @(@{ Service = 'Roles'; AdminTierLevel = '0' })
        $Activation.PIMAssignmentType = 'Activated'
        $MpUser.RoleAssignments = @($MpUser.RoleAssignments) + @([pscustomobject]$Activation)
        $Export | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath "$script:Root/PrivilegedEAM/EntraID/EntraID.json"

        $Tier0 = Invoke-EntraOpsFindingEvaluation -Area TierBreach -ImportPath "$script:Root/PrivilegedEAM" | Where-Object Key -eq 'tier0Breach'
        $Tier0.FailedCount | Should -Be 1
        @($Tier0.Results.Evidence.PimAssignmentType) | Should -Be @('Eligible')
    }

    It 'takes the tenant ID of EntraOpsConfig.json without a connection, and warns without one' {
        $OriginalTenant = Get-Variable -Name TenantIdContext -Scope Global -ValueOnly -ErrorAction SilentlyContinue
        try {
            $Global:TenantIdContext = $null
            $Config = Join-Path $TestDrive 'tenant-config.json'
            @{ TenantId = 'config-tenant' } | ConvertTo-Json | Set-Content -LiteralPath $Config
            Invoke-EntraOpsFindingEvaluation -Area TierBreach -ImportPath "$script:Root/PrivilegedEAM" |
                Save-EntraOpsFindingJson -ExportFolder "$script:Root/FindingsConfigTenant" -ConfigFilePath $Config -TenantName 'contoso' -WarningVariable Warnings -WarningAction SilentlyContinue
            (Get-Content -LiteralPath "$script:Root/FindingsConfigTenant/findings.json" -Raw | ConvertFrom-Json).TenantId | Should -Be 'config-tenant'
            @($Warnings | Where-Object { "$_" -like '*no tenant ID*' }).Count | Should -Be 0

            Invoke-EntraOpsFindingEvaluation -Area TierBreach -ImportPath "$script:Root/PrivilegedEAM" |
                Save-EntraOpsFindingJson -ExportFolder "$script:Root/FindingsNoTenant" -ConfigFilePath (Join-Path $TestDrive 'none.json') -TenantName 'contoso' -WarningVariable Warnings -WarningAction SilentlyContinue
            @($Warnings | Where-Object { "$_" -like 'The finding results have no tenant ID*' }).Count | Should -Be 1
        } finally {
            $Global:TenantIdContext = $OriginalTenant
        }
    }

    It 'saves the results with tenant and schema version' {
        Invoke-EntraOpsFindingEvaluation -Area TierBreach -ImportPath "$script:Root/PrivilegedEAM" |
            Save-EntraOpsFindingJson -ExportFolder "$script:Root/Findings" -TenantId 'tenant-id' -TenantName 'contoso.onmicrosoft.com'

        "$script:Root/Findings/findings.json.tmp" | Should -Not -Exist
        $Saved = Get-Content -LiteralPath "$script:Root/Findings/findings.json" -Raw | ConvertFrom-Json
        # The same results for the reports, which load their data as scripts.
        $Script = Get-Content -LiteralPath "$script:Root/Findings/findings.js" -Raw
        $Script | Should -Match '^// Auto-generated by Save-EntraOpsFindingJson'
        ($Script.Substring($Script.IndexOf('=') + 1).TrimEnd().TrimEnd(';') | ConvertFrom-Json).Rules.Count | Should -Be @($Saved.Rules).Count
        $Saved.SchemaVersion | Should -Be '1.0'
        $Saved.TenantId | Should -Be 'tenant-id'
        $Saved.TenantName | Should -Be 'contoso.onmicrosoft.com'
        $Saved.Generator.Name | Should -Be 'EntraOps'
        ([datetime]$Saved.GeneratedAt).ToUniversalTime() | Should -BeGreaterThan (Get-Date).ToUniversalTime().AddMinutes(-5)
        $Saved.Rules.RuleId | Should -Be @('EO.1001', 'EO.1003')
        $Saved.Rules[0].Category | Should -Be 'TierBoundaries'
        $Saved.Rules[0].CategoryTitle | Should -Be 'Tier boundaries'
        $Saved.Rules[0].CategoryNumber | Should -Be 1
        $Saved.Rules[0].CheckTitle | Should -Be 'No object below Control Plane has access to a Control Plane service.'
        $Saved.Rules[1].FailedCount | Should -Be 1
        @($Saved.Rules[1].Results).Count | Should -Be 1
        $Saved.Rules[0].Effort | Should -BeIn @('Low', 'Medium', 'High')
        $Saved.Rules[0].UserImpactDescription | Should -Not -BeNullOrEmpty
        $Saved.Rules[0].Results[0].Evidence.Role | Should -Be 'Privileged Role Administrator'
    }
}


Describe 'Finding rule details' {
    BeforeAll {
        $script:TestRepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
        Import-Module (Join-Path $script:TestRepositoryRoot 'EntraOps/EntraOps.psd1') -Force -WarningAction SilentlyContinue
    }

    It 'reports the Management Plane services of an assignment that also reaches a Control Plane service when EO.1001 is excluded' {
        $Results = & (Get-Module EntraOps) {
            $Path = { param($Service, $Tier) [ordered]@{ pathId = "p-$Service"; objectId = 'u1'; objectName = 'User'; objectType = 'user'; objectTier = 2; objectTierName = 'UserAccess'; system = 'EntraID'; role = 'Role'; roleType = 'BuiltInRole'; delegatedPermission = $false; microsoftFirstParty = $false; service = $Service; serviceTier = $Tier; assignmentInstanceId = 'ra1'; scopeName = 'Tenant' } }
            $Context = [pscustomobject]@{ Area = 'TierBreach'; Paths = @((& $Path 'Roles' 0), (& $Path 'Groups' 1)) }
            $Rule = Get-EntraOpsFindingRule -Id EO.1003
            foreach ($Excluded in @(@(), @('EO.1001'))) {
                $Rule | Add-Member -NotePropertyName ExcludedRules -NotePropertyValue $Excluded -Force
                , @(Invoke-EntraOpsTierBreachFindingRule -Context $Context -Rule $Rule | Where-Object Failed)
            }
        }
        # With EO.1001, the assignment is reported there; without it, EO.1003 reports its Management Plane service.
        $Results[0].Count | Should -Be 0
        $Results[1].Count | Should -Be 1
        $Results[1][0].Message | Should -Be "User Access object 'User' reaches the Management Plane service 'Groups' through the role 'Role' (EntraID) at 'Tenant'."
    }

    It 'reads the dates of finding exceptions without a time zone shift and warns about implausible dates' {
        $Root = Join-Path $TestDrive 'exception-dates'
        New-Item -ItemType Directory -Path $Root -Force | Out-Null
        $Future = (Get-Date).ToUniversalTime().AddDays(10).ToString('yyyy-MM-dd')
        @(
            [ordered]@{ RuleId = 'EO.1001'; ObjectId = 'a'; State = 'RiskAccepted'; Justification = 'Offset'; AcceptedOn = '2026-01-01'; ExpiresOn = '2099-06-30T00:00:00+14:00' }
            [ordered]@{ RuleId = 'EO.1001'; ObjectId = 'b'; State = 'RiskAccepted'; Justification = 'Before'; AcceptedOn = '2026-01-10'; ExpiresOn = '2026-01-05' }
            [ordered]@{ RuleId = 'EO.1001'; ObjectId = 'c'; State = 'Dismissed'; Justification = 'Future'; AcceptedOn = $Future }
        ) | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath "$Root/exceptions.json"
        $Exceptions = & (Get-Module EntraOps) { param($Root) Read-EntraOpsFindingExceptionFile -FilePath './exceptions.json' -RootFolder $Root -WarningVariable +Warnings -WarningAction SilentlyContinue; $script:ExceptionWarnings = $Warnings } $Root
        ($Exceptions | Where-Object ObjectId -eq 'a').ExpiresOn | Should -Be '2099-06-30'
        $Text = & (Get-Module EntraOps) { $script:ExceptionWarnings -join "`n" }
        $Text | Should -Match 'before it was accepted'
        $Text | Should -Match 'a date in the future'
    }

    It 'keeps the day of a finding exception as written when the JSON reader converts dates (PowerShell 7.4)' {
        $Root = Join-Path $TestDrive 'exception-dates-converted'
        New-Item -ItemType Directory -Path $Root -Force | Out-Null
        # In every time zone, the local day of at least one of the two ExpiresOn dates is not the day as written.
        @'
[
  { "RuleId": "EO.1001", "ObjectId": "a", "State": "RiskAccepted", "Justification": "East", "AcceptedOn": "2026-01-01T00:00:00+14:00", "ExpiresOn": "2099-06-30T00:00:00+14:00" },
  { "RuleId": "EO.1001", "ObjectId": "b", "State": "RiskAccepted", "Justification": "West", "AcceptedOn": "2026-01-01T23:59:59-12:00", "ExpiresOn": "2099-06-30T23:59:59-12:00" },
  "no object",
  { "RuleId": "EO.1001", "ObjectId": "c", "State": "Dismissed", "Justification": "Day only", "ExpiresOn": "2099-06-30" }
]
'@ | Set-Content -LiteralPath "$Root/exceptions.json"
        # PowerShell 7.4 has no ConvertFrom-Json -DateKind and returns such text as a date in the local time zone.
        Mock -ModuleName EntraOps Get-Command { [pscustomobject]@{ Parameters = @{} } } -ParameterFilter { "$Name" -eq 'ConvertFrom-Json' }
        $Exceptions = & (Get-Module EntraOps) { param($Root) Read-EntraOpsFindingExceptionFile -FilePath './exceptions.json' -RootFolder $Root -WarningAction SilentlyContinue } $Root
        Should -Invoke -ModuleName EntraOps Get-Command -Times 1 -Exactly
        @($Exceptions.ObjectId) | Should -Be @('a', 'b', 'c')
        @($Exceptions.AcceptedOn) | Should -Be @('2026-01-01', '2026-01-01', '')
        @($Exceptions.ExpiresOn) | Should -Be @('2099-06-30', '2099-06-30', '2099-06-30')

        # The dates are read as text, by entry; an entry that is no object keeps its place.
        $Texts = & (Get-Module EntraOps) { param($Path) , @(Get-EntraOpsFindingExceptionDateText -Json (Get-Content -LiteralPath $Path -Raw)) } "$Root/exceptions.json"
        $Texts.Count | Should -Be 4
        $Texts[1].ExpiresOn | Should -Be '2099-06-30T23:59:59-12:00'
        $Texts[2] | Should -BeNullOrEmpty
        $Texts[3].ExpiresOn | Should -Be '2099-06-30'
    }

    It 'limits a risk acceptance to ExceptionMaxDays from today when AcceptedOn is in the future' {
        $Root = Join-Path $TestDrive 'exception-future'
        New-Item -ItemType Directory -Path $Root -Force | Out-Null
        $Today = (Get-Date).ToUniversalTime().Date
        $Day = { param($Offset) $Today.AddDays($Offset).ToString('yyyy-MM-dd') }
        @(
            # Accepted in four years for 150 days: within 180 days of AcceptedOn, but not of today.
            [ordered]@{ RuleId = 'EO.1001'; ObjectId = 'a'; State = 'RiskAccepted'; Justification = 'Future'; AcceptedOn = (& $Day 1460); ExpiresOn = (& $Day 1610) }
            [ordered]@{ RuleId = 'EO.1001'; ObjectId = 'b'; State = 'RiskAccepted'; Justification = 'Past'; AcceptedOn = (& $Day -10); ExpiresOn = (& $Day 400) }
            [ordered]@{ RuleId = 'EO.1001'; ObjectId = 'c'; State = 'RiskAccepted'; Justification = 'Within'; AcceptedOn = (& $Day 5); ExpiresOn = (& $Day 180) }
        ) | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath "$Root/exceptions.json"
        $Exceptions = & (Get-Module EntraOps) { param($Root) Read-EntraOpsFindingExceptionFile -FilePath './exceptions.json' -RootFolder $Root -MaxDays 180 -WarningVariable +Warnings -WarningAction SilentlyContinue; $script:ExceptionWarnings = $Warnings } $Root
        @($Exceptions.ExpiresOn) | Should -Be @((& $Day 180), (& $Day 170), (& $Day 180))
        $Text = & (Get-Module EntraOps) { $script:ExceptionWarnings -join "`n" }
        $Text | Should -Match "entry 1 \(EO\.1001\) was accepted on $(& $Day 1460), a date in the future"
        $Text | Should -Match "entry 1 \(EO\.1001\) expires on $(& $Day 1610), more than 180 days \(Findings\.ExceptionMaxDays\) after today: it expires on $(& $Day 180)\."
        $Text | Should -Match "entry 2 \(EO\.1001\) expires on $(& $Day 400), more than 180 days \(Findings\.ExceptionMaxDays\) after AcceptedOn: it expires on $(& $Day 170)\."
        $Text | Should -Not -Match 'entry 3 \(EO\.1001\) expires'
    }
}
