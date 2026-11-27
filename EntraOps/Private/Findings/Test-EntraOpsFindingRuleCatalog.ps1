function Test-EntraOpsFindingRuleCatalog {
    <#
    .SYNOPSIS
        Checks the IDs of the finding rule catalog against the released rules (FindingRules.lock.json).
    .DESCRIPTION
        Rule IDs become Maester test IDs (MP.EOPS.<n>), and Maester refuses an update of a pack whose tests
        change their meaning, so an ID never changes once it is released. Returns one message per problem:
          * IDs are EO.<category number><nnn>, unique and consecutive within their category (from 001).
          * Every released rule (lock file) still exists with the same ID, area, key and category. A released
            rule that is no longer needed is kept with Lifecycle Deprecated instead of being removed.
          * New rules are appended: their number is higher than every released number of their category.
        Used by Build-EntraOpsMaesterPack.ps1 and Tests/Findings/Get-EntraOpsFindingRule.Tests.ps1.
    .PARAMETER Rule
        The rules of the catalog (from Get-EntraOpsFindingRule).
    .PARAMETER ReleasedRule
        The released rules of the lock file (Id, Area, Key, Category).
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param (
        [Parameter(Mandatory = $true)]
        [object[]]$Rule,

        [Parameter(Mandatory = $false)]
        [AllowEmptyCollection()]
        [object[]]$ReleasedRule = @()
    )

    $ById = @{}
    foreach ($Item in $Rule) {
        if ($ById.ContainsKey($Item.Id)) { "Rule ID $($Item.Id) is used more than once." }
        $ById[$Item.Id] = $Item
        if ($Item.Id -notmatch '^EO\.(\d)(\d{3})$' -or [int]$Matches[1] -ne [int]$Item.CategoryNumber) {
            "Rule $($Item.Id) ($($Item.Area).$($Item.Key)) must be numbered EO.$($Item.CategoryNumber)nnn for its category $($Item.Category)."
        }
    }
    foreach ($Group in ($Rule | Group-Object Area, Key | Where-Object Count -GT 1)) { "The key $($Group.Name -replace ', ', '.') is used by more than one rule." }

    foreach ($Category in ($Rule | Group-Object Category)) {
        $Numbers = @($Category.Group | ForEach-Object { [int]$_.Id.Substring(4) } | Sort-Object)
        for ($Index = 0; $Index -lt $Numbers.Count; $Index++) {
            if ($Numbers[$Index] -ne $Index + 1) { "The rules of category $($Category.Name) are not numbered consecutively from 001: $(($Numbers | ForEach-Object { '{0:d3}' -f $_ }) -join ', ')."; break }
        }
    }

    foreach ($Released in $ReleasedRule) {
        $Current = $ById[$Released.Id]
        if ($null -eq $Current) { "Released rule $($Released.Id) ($($Released.Area).$($Released.Key)) is missing. Keep it with Lifecycle Deprecated instead."; continue }
        foreach ($Field in 'Area', 'Key', 'Category') {
            if ("$($Current.$Field)" -cne "$($Released.$Field)") { "Released rule $($Released.Id) changed its $Field from '$($Released.$Field)' to '$($Current.$Field)'. Released IDs never change; add a new rule instead." }
        }
    }

    $ReleasedIds = @($ReleasedRule.Id)
    foreach ($Category in ($Rule | Group-Object Category)) {
        $HighestReleased = @($Category.Group | Where-Object { $_.Id -in $ReleasedIds } | ForEach-Object { [int]$_.Id.Substring(4) } | Sort-Object)[-1]
        if ($null -eq $HighestReleased) { continue }
        foreach ($Item in @($Category.Group | Where-Object { $_.Id -notin $ReleasedIds -and [int]$_.Id.Substring(4) -lt $HighestReleased })) {
            "New rule $($Item.Id) ($($Item.Area).$($Item.Key)) must be appended after the released rules of category $($Item.Category)."
        }
    }
}
