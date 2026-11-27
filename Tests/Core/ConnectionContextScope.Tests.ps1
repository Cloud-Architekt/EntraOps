#Requires -Modules Pester

# Every Microsoft Graph and Azure sign-in in the module is process-scoped, so a run never reads or
# writes the user's persisted contexts (~/.Azure, ~/.mg) and parallel pwsh processes cannot overwrite
# each other's tenant context. ForEach-Object -Parallel runspaces still share the process-wide context.
BeforeDiscovery {
    $RepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
    $script:ConnectCalls = foreach ($File in Get-ChildItem -Path (Join-Path $RepositoryRoot 'EntraOps') -Filter '*.ps1' -Recurse) {
        $Ast = [System.Management.Automation.Language.Parser]::ParseFile($File.FullName, [ref]$null, [ref]$null)
        $Commands = $Ast.FindAll({
                param($Node)
                $Node -is [System.Management.Automation.Language.CommandAst] -and
                $Node.GetCommandName() -in @('Connect-MgGraph', 'Connect-AzAccount')
            }, $true)
        foreach ($Command in $Commands) {
            $ParameterNames = @($Command.CommandElements |
                Where-Object { $_ -is [System.Management.Automation.Language.CommandParameterAst] } |
                ForEach-Object ParameterName)
            $SplattedNames = @($Command.CommandElements |
                Where-Object { $_ -is [System.Management.Automation.Language.VariableExpressionAst] -and $_.Splatted } |
                ForEach-Object { $_.VariablePath.UserPath })
            @{
                Location       = '{0}:{1}' -f $File.FullName.Substring($RepositoryRoot.Length + 1), $Command.Extent.StartLineNumber
                Command        = $Command.GetCommandName()
                ParameterNames = $ParameterNames
                SplattedNames  = $SplattedNames
                Text           = $Command.Extent.Text
            }
        }
    }
}

Describe 'Process-scoped connection context' {
    It 'finds Connect-MgGraph and Connect-AzAccount calls in the module' {
        @($script:ConnectCalls).Count | Should -BeGreaterThan 0
    }

    It '<Command> at <Location> is process-scoped' -ForEach $script:ConnectCalls {
        if ($Command -eq 'Connect-AzAccount') {
            $ParameterNames | Should -Contain 'Scope' -Because 'Connect-AzAccount must use -Scope Process'
            $Text | Should -Match '-Scope\s+Process\b'
        } elseif ($ParameterNames -contains 'AccessToken') {
            # The AccessToken parameter set has no -ContextScope; token-based sessions are always process-scoped.
            $ParameterNames | Should -Not -Contain 'ContextScope'
        } elseif ($SplattedNames.Count -gt 0) {
            $Text | Should -Match '@\w+' -Because 'splatted calls are checked by their own unit tests (e.g. Invoke-EntraOpsAssessment)'
        } else {
            $ParameterNames | Should -Contain 'ContextScope' -Because 'Connect-MgGraph must use -ContextScope Process'
            $Text | Should -Match '-ContextScope\s+Process\b'
        }
    }
}
