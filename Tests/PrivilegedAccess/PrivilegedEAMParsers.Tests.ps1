#Requires -Modules Pester

BeforeDiscovery {
    $script:ParserCases = @(
        @{ Name = 'WatchLists'; QueryProperty = 'Query' }
        @{ Name = 'CustomTable'; QueryProperty = 'query' }
    )
}

BeforeAll {
    $script:TestRepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path

    function Get-TestParserDefinition {
        param([string]$Name, [string]$QueryProperty)
        $YamlText = Get-Content -LiteralPath (Join-Path $script:TestRepositoryRoot "Parsers/PrivilegedEAM_$Name.yaml") -Raw
        $QueryBlock = ($YamlText -split "ParserQuery: \|\r?\n", 2)[1].TrimEnd()
        $Lines = $QueryBlock -split '\r?\n'
        $Indent = $Lines[0].Length - $Lines[0].TrimStart(' ').Length
        $YamlQuery = ($Lines | ForEach-Object { if ($_.Trim()) { $_.Substring($Indent) } else { '' } }) -join "`n"
        $YamlVersion = [regex]::Match($YamlText, '(?m)^\s+Version:\s*([\d.]+)').Groups[1].Value

        $Template = Get-Content -LiteralPath (Join-Path $script:TestRepositoryRoot "Parsers/PrivilegedEAM_$Name.json") -Raw | ConvertFrom-Json
        $Properties = $Template.resources[0].resources[0].properties
        [pscustomobject]@{
            YamlQuery    = $YamlQuery
            JsonQuery    = ($Properties.$QueryProperty -replace "`r`n", "`n").TrimEnd()
            YamlVersion  = $YamlVersion
            JsonVersion  = [string]$Properties.version
        }
    }
}

Describe 'PrivilegedEAM parser <Name>' -ForEach $script:ParserCases {
    BeforeAll {
        $script:Parser = Get-TestParserDefinition -Name $Name -QueryProperty $QueryProperty
    }

    It 'deploys the same query as the YAML source' {
        $script:Parser.JsonQuery | Should -BeExactly $script:Parser.YamlQuery
    }

    It 'keeps the template version in line with the YAML version' {
        $script:Parser.JsonVersion | Should -Be ($script:Parser.YamlVersion -split '\.')[-1]
    }

    It 'attributes every eligible group membership subtype to PIM' {
        foreach ($SubType in 'Eligible member', 'Nested Eligible member', 'Nested Eligible group member') {
            ([regex]::Matches($script:Parser.YamlQuery, [regex]::Escape("`"$SubType`""))).Count | Should -BeGreaterOrEqual 3 -Because "'$SubType' must be covered by the roles-and-groups case, the PIM for Groups case and TransitiveByPim"
        }
    }

    It 'checks the combined roles-and-groups case before the role-only case' {
        $script:Parser.YamlQuery.IndexOf('"PIM for Entra ID Roles and Groups"') | Should -BeLessThan $script:Parser.YamlQuery.IndexOf('"PIM for Entra ID Roles"')
    }
}

Describe 'PrivilegedEAM parser data selection' {
    It 'keeps watchlist role assignments without classification' {
        $Parser = Get-TestParserDefinition -Name 'WatchLists' -QueryProperty 'Query'
        $Parser.YamlQuery | Should -Match "join kind=leftouter \(\s*\n\s*_GetWatchlist\('EntraOps_RoleClassifications'\)"
    }

    It 'returns the latest completed custom table ingestion instead of a fixed one-day window' {
        $Parser = Get-TestParserDefinition -Name 'CustomTable' -QueryProperty 'query'
        $Parser.YamlQuery | Should -Not -Match 'ago\(1d\)'
        # Runs are selected by their completion marker, exactly by the run timestamp or between two markers.
        $Parser.YamlQuery | Should -Match 'LatestMarker = max\(MarkerTime\) by RoleSystem'
        $Parser.YamlQuery | Should -Match 'TimeGenerated == LatestMarker'
        $Parser.YamlQuery | Should -Match 'TimeGenerated > PreviousMarker and TimeGenerated <= LatestMarker'
        # Marker records are bookkeeping and never returned as objects.
        $Parser.YamlQuery | Should -Match 'where ObjectType != RunMarkerType'
    }

    It 'uses the completion marker type that Save-EntraOpsPrivilegedEAMInsightsCustomTable writes' {
        $Parser = Get-TestParserDefinition -Name 'CustomTable' -QueryProperty 'query'
        $Producer = Get-Content -LiteralPath (Join-Path $script:TestRepositoryRoot 'EntraOps/Public/PrivilegedAccess/Save-EntraOpsPrivilegedEAMInsightsCustomTable.ps1') -Raw

        $ParserMarker = [regex]::Match($Parser.YamlQuery, 'let RunMarkerType = "(?<Type>[^"]+)";').Groups['Type'].Value
        $ProducerMarker = [regex]::Match($Producer, 'ObjectType\s*=\s*"(?<Type>[^"]+)"').Groups['Type'].Value

        $ParserMarker | Should -Not -BeNullOrEmpty
        $ProducerMarker | Should -Be $ParserMarker
    }
}
