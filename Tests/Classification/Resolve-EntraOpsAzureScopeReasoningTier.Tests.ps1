#Requires -Modules Pester

BeforeDiscovery {
    $script:TestRepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
}

BeforeAll {
    $script:TestRepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
    . "$script:TestRepositoryRoot/EntraOps/Private/Find-EntraOpsAzureScopeContainmentMatch.ps1"
    . "$script:TestRepositoryRoot/EntraOps/Private/Resolve-EntraOpsAzureScopeReasoningTier.ps1"
}

Describe "Resolve-EntraOpsAzureScopeReasoningTier" {
    BeforeAll {
    $script:TestRepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
        $Reasoning = [pscustomobject]@{
            Tier0Scope = @("/", "/subscriptions/aaaa-t0", "/subscriptions/shared/resourcegroups/rg-t0")
            Tier1Scope = @("/subscriptions/bbbb-t1")
        }
    }

    Context "Containment classification" {
        It "classifies an exact Tier0 scope as ControlPlane with the matched scope" {
            $Result = Resolve-EntraOpsAzureScopeReasoningTier -ArmScopeId "/subscriptions/aaaa-t0" -AzureScopeReasoning $Reasoning
            $Result.AdminTierLevelName | Should -Be "ControlPlane"
            $Result.AdminTierLevel | Should -Be "0"
            $Result.MatchedScope | Should -Be "/subscriptions/aaaa-t0"
        }

        It "classifies a scope beneath a Tier0 bucket as ControlPlane" {
            $Result = Resolve-EntraOpsAzureScopeReasoningTier -ArmScopeId "/subscriptions/aaaa-t0/resourceGroups/anything" -AzureScopeReasoning $Reasoning
            $Result.AdminTierLevelName | Should -Be "ControlPlane"
        }

        It "classifies a scope containing a Tier0 bucket beneath it as ControlPlane" {
            $Result = Resolve-EntraOpsAzureScopeReasoningTier -ArmScopeId "/subscriptions/shared" -AzureScopeReasoning $Reasoning
            $Result.AdminTierLevelName | Should -Be "ControlPlane"
            $Result.MatchedScope | Should -Be "/subscriptions/shared/resourcegroups/rg-t0"
        }

        It "classifies a Tier1 scope as ManagementPlane when no Tier0 bucket overlaps" {
            $Result = Resolve-EntraOpsAzureScopeReasoningTier -ArmScopeId "/subscriptions/bbbb-t1/resourceGroups/rg1" -AzureScopeReasoning $Reasoning
            $Result.AdminTierLevelName | Should -Be "ManagementPlane"
            $Result.AdminTierLevel | Should -Be "1"
        }

        It "classifies a scope without any bucket overlap as UserAccess" {
            $Result = Resolve-EntraOpsAzureScopeReasoningTier -ArmScopeId "/subscriptions/cccc-unrelated" -AzureScopeReasoning $Reasoning
            $Result.AdminTierLevelName | Should -Be "UserAccess"
            $Result.MatchedScope | Should -BeNullOrEmpty
        }

        It "does not let the directory root '/' in Tier0Scope force every scope to Tier0" {
            $Result = Resolve-EntraOpsAzureScopeReasoningTier -ArmScopeId "/subscriptions/cccc-unrelated" -AzureScopeReasoning $Reasoning
            $Result.AdminTierLevelName | Should -Be "UserAccess"
        }

        It "normalizes casing and trailing slashes before matching" {
            $Result = Resolve-EntraOpsAzureScopeReasoningTier -ArmScopeId "/Subscriptions/AAAA-T0/" -AzureScopeReasoning $Reasoning
            $Result.AdminTierLevelName | Should -Be "ControlPlane"
        }

        It "returns null without scope reasoning so callers keep their conservative fallback" {
            Resolve-EntraOpsAzureScopeReasoningTier -ArmScopeId "/subscriptions/aaaa-t0" -AzureScopeReasoning $null | Should -BeNullOrEmpty
        }

        It "returns null for a scope that normalizes to empty" {
            Resolve-EntraOpsAzureScopeReasoningTier -ArmScopeId "/" -AzureScopeReasoning $Reasoning | Should -BeNullOrEmpty
        }
    }

    Context "Memoization" {
        BeforeEach {
            # Each test gets fresh payload instances so the identity-keyed cache starts cold.
            $PayloadA = [pscustomobject]@{
                Tier0Scope = @("/subscriptions/aaaa-t0")
                Tier1Scope = @("/subscriptions/bbbb-t1")
            }
            $PayloadB = [pscustomobject]@{
                Tier0Scope = @("/subscriptions/aaaa-t0")
                Tier1Scope = @("/subscriptions/bbbb-t1")
            }
            Mock Find-EntraOpsAzureScopeContainmentMatch { $null }
        }

        It "runs the containment scan only once per distinct scope and payload" {
            1..5 | ForEach-Object {
                Resolve-EntraOpsAzureScopeReasoningTier -ArmScopeId "/subscriptions/cccc" -AzureScopeReasoning $PayloadA | Out-Null
            }
            # One Tier0 probe + one Tier1 probe for the first call; the other four calls are cache hits.
            Should -Invoke Find-EntraOpsAzureScopeContainmentMatch -Times 2 -Exactly
        }

        It "returns the identical cached result instance for a repeated scope" {
            $First = Resolve-EntraOpsAzureScopeReasoningTier -ArmScopeId "/subscriptions/cccc" -AzureScopeReasoning $PayloadA
            $Second = Resolve-EntraOpsAzureScopeReasoningTier -ArmScopeId "/subscriptions/cccc" -AzureScopeReasoning $PayloadA
            [object]::ReferenceEquals($First, $Second) | Should -BeTrue
        }

        It "scans again for a new scope against the same payload" {
            Resolve-EntraOpsAzureScopeReasoningTier -ArmScopeId "/subscriptions/cccc" -AzureScopeReasoning $PayloadA | Out-Null
            Resolve-EntraOpsAzureScopeReasoningTier -ArmScopeId "/subscriptions/dddd" -AzureScopeReasoning $PayloadA | Out-Null
            Should -Invoke Find-EntraOpsAzureScopeContainmentMatch -Times 4 -Exactly
        }

        It "invalidates the cache when a different payload instance is passed" {
            Resolve-EntraOpsAzureScopeReasoningTier -ArmScopeId "/subscriptions/cccc" -AzureScopeReasoning $PayloadA | Out-Null
            # Same content, different object: identity-keyed cache must not reuse PayloadA's results.
            Resolve-EntraOpsAzureScopeReasoningTier -ArmScopeId "/subscriptions/cccc" -AzureScopeReasoning $PayloadB | Out-Null
            Should -Invoke Find-EntraOpsAzureScopeContainmentMatch -Times 4 -Exactly
        }

        It "passes normalized buckets to the containment scan" {
            $MixedCasePayload = [pscustomobject]@{
                Tier0Scope = @("/Subscriptions/AAAA-T0/", "/")
                Tier1Scope = @()
            }
            Resolve-EntraOpsAzureScopeReasoningTier -ArmScopeId "/subscriptions/x" -AzureScopeReasoning $MixedCasePayload | Out-Null
            Should -Invoke Find-EntraOpsAzureScopeContainmentMatch -ParameterFilter {
                $Scope -eq "/subscriptions/x" -and @($BucketedScopes).Count -eq 1 -and @($BucketedScopes)[0] -eq "/subscriptions/aaaa-t0"
            } -Times 1
        }
    }

    Context "Memoized results still classify correctly end-to-end" {
        It "keeps tier answers stable across repeated mixed-scope resolution" {
            $Payload = [pscustomobject]@{
                Tier0Scope = @("/subscriptions/aaaa-t0")
                Tier1Scope = @("/subscriptions/bbbb-t1")
            }
            $Expected = @{
                "/subscriptions/aaaa-t0/vm1" = "ControlPlane"
                "/subscriptions/bbbb-t1"     = "ManagementPlane"
                "/subscriptions/other"       = "UserAccess"
            }
            foreach ($Round in 1..3) {
                foreach ($Scope in $Expected.Keys) {
                    (Resolve-EntraOpsAzureScopeReasoningTier -ArmScopeId $Scope -AzureScopeReasoning $Payload).AdminTierLevelName |
                        Should -Be $Expected[$Scope] -Because "round $Round, scope $Scope"
                }
            }
        }
    }
}

