#Requires -Modules Pester

BeforeDiscovery {
    $script:TestRepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
}

BeforeAll {
    $script:TestRepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
    . "$script:TestRepositoryRoot/EntraOps/Private/ConvertTo-EntraOpsODataStringLiteral.ps1"
    . "$script:TestRepositoryRoot/EntraOps/Private/Select-EntraOpsUniqueGraphObject.ps1"
}

Describe "Graph object lookup safety" {
    It "escapes and encodes apostrophes, ampersands, Unicode, and filter-like input" {
        $Quote = [char]39
        $Value = "O${Quote}Brien & 管理${Quote}) or id ne null or (${Quote}x${Quote}"

        [uri]::UnescapeDataString((ConvertTo-EntraOpsODataStringLiteral -Value $Value)) |
            Should -Be $Value.Replace("$Quote", "$Quote$Quote")
    }

    It "returns a unique object" {
        $Object = [pscustomobject]@{ Id = "one" }

        Select-EntraOpsUniqueGraphObject -InputObject @($Object) -ObjectDescription "test object" | Should -Be $Object
    }

    It "allows a missing object only when requested" {
        Select-EntraOpsUniqueGraphObject -InputObject @() -ObjectDescription "test object" -AllowNotFound | Should -BeNullOrEmpty
        { Select-EntraOpsUniqueGraphObject -InputObject @() -ObjectDescription "test object" } | Should -Throw "*No object matched*"
    }

    It "rejects ambiguous results" {
        $Objects = @([pscustomobject]@{ Id = "one" }, [pscustomobject]@{ Id = "two" })

        { Select-EntraOpsUniqueGraphObject -InputObject $Objects -ObjectDescription "test object" } | Should -Throw "*Multiple objects matched*"
    }

    Context "call sites with a not-found skip or create branch pass -AllowNotFound" {
        # These cmdlets deliberately handle a $null lookup result (NOT FOUND skip rows, or a
        # create-if-missing branch). Omitting -AllowNotFound turns that handling into dead code
        # and a mid-loop abort - this guard trips if the flag is ever dropped again.
        It "<File> passes -AllowNotFound on every Select-EntraOpsUniqueGraphObject call" -TestCases @(
            @{ File = "EntraOps/Public/Configuration/New-EntraOpsWorkloadIdentity.ps1" }
            @{ File = "EntraOps/Public/PrivilegedAccess/Update-EntraOpsPrivilegedConditionalAccessGroup.ps1" }
            @{ File = "EntraOps/Public/PrivilegedAccess/Update-EntraOpsPrivilegedAdministrativeUnit.ps1" }
            @{ File = "EntraOps/Public/PrivilegedAccess/Update-EntraOpsPrivilegedUnprotectedAdministrativeUnit.ps1" }
        ) {
            $Path = Join-Path $script:TestRepositoryRoot $File
            $Ast = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$null, [ref]$null)
            $Calls = @($Ast.FindAll({ param($Node) $Node -is [System.Management.Automation.Language.CommandAst] -and $Node.GetCommandName() -eq 'Select-EntraOpsUniqueGraphObject' }, $true))

            $Calls.Count | Should -BeGreaterThan 0
            foreach ($Call in $Calls) {
                @($Call.CommandElements | Where-Object { $_ -is [System.Management.Automation.Language.CommandParameterAst] -and $_.ParameterName -eq 'AllowNotFound' }).Count |
                    Should -Be 1 -Because "the call at line $($Call.Extent.StartLineNumber) must keep its not-found handling reachable"
            }
        }
    }

    Context "report tier badge maps cover every tier the generators emit" {
        It "<File> maps WorkloadPlane in its tierBadge implementation" -TestCases @(
            @{ File = "Reports/ConfigurationAnalyzer/js/app.js" }
            @{ File = "Reports/shared/object-inspector.js" }
        ) {
            $Content = Get-Content -Raw -LiteralPath (Join-Path $script:TestRepositoryRoot $File)
            $BadgeFunction = [regex]::Match($Content, 'function tierBadge[\s\S]*?\n    \}')
            $BadgeFunction.Success | Should -BeTrue
            foreach ($Tier in @('ControlPlane', 'ManagementPlane', 'WorkloadPlane', 'UserAccess')) {
                $BadgeFunction.Value | Should -BeLike "*$Tier*"
            }
        }
    }
}
