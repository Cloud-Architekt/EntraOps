#Requires -Version 7.4
<#
.SYNOPSIS
    Generates the EntraOps Maester Pack from the EntraOps finding rule catalog.
.DESCRIPTION
    Writes the generated files of the EntraOps Maester Pack into the pack repository (Cloud-Architekt/EntraOps-MaesterPack):
    the manifest (maester-pack.json), the suite and one native Maester test per finding rule
    (tests/Test.MP.EOPS.<n>.ps1 with its description in tests/Test.MP.EOPS.<n>.md), the helpers
    (copied from Integrations/Maester/Template/helpers) and entraops-source.json with the EntraOps version and
    commit the pack was generated from. The [MaesterTest] attribute of a native test accepts only constants,
    so the tests are generated from the rule catalog (Get-EntraOpsFindingRule) instead of being read at run time.
    The files that the pack repository maintains itself (guide, banner, README, workflows) are not touched;
    the manifest names the guide and the banner when they exist.

    Each test reports the result of its rule from the findings.json that Save-EntraOpsFindingJson writes;
    the pack itself does not evaluate anything and needs no connection.

    The pack has the version of the EntraOps module. Re-run this script after changing the rule catalog
    (EntraOps/Private/Findings/FindingRules.json); the sync workflow of the pack repository runs it as well.

    Maester test IDs never change once they are released. The script checks the rule IDs first
    (Test-EntraOpsFindingRuleCatalog) and refuses to change or remove a test that exists in the pack
    repository. With -Release, it adds the rules that are not released yet to
    EntraOps/Private/Findings/FindingRules.lock.json, which fixes their IDs from then on.
.PARAMETER RepoRoot
    Path to the EntraOps repository root. Defaults to the grandparent of this script's folder (Integrations/Maester).
.PARAMETER OutputPath
    Root of the pack repository. Defaults to the folder named like the pack repository (-PackRepository, for
    example EntraOps-MaesterPack) next to the EntraOps repository.
.PARAMETER PackRepository
    GitHub repository that publishes the pack: its URL is the Homepage, Support and SecurityContact of the
    manifest and the base of the HelpUrl of every test. Defaults to https://github.com/Cloud-Architekt/EntraOps-MaesterPack.
    A staging repository (for example of a fork) publishes the same pack: the Id, Guid and Code of the
    manifest and the test IDs don't change, so Update-MtPack moves between staging and release builds.
.PARAMETER EntraOpsRepository
    GitHub repository of EntraOps that the description of every test links to (the finding rule catalog). Defaults
    to https://github.com/Cloud-Architekt/EntraOps; a staging pack can link to the repository it was built from.
.PARAMETER Version
    Version of the pack. Defaults to the version of the EntraOps module.
.PARAMETER Release
    Record the rules that are not released yet in FindingRules.lock.json (with this version as Since).
    Run it before the pack release of this version.
.EXAMPLE
    ./Integrations/Maester/Build-EntraOpsMaesterPack.ps1

    Generates the pack into ../EntraOps-MaesterPack.
.EXAMPLE
    ./Integrations/Maester/Build-EntraOpsMaesterPack.ps1 -OutputPath ./pack-repo -Release

    Generates the pack and records its rules as released.
.EXAMPLE
    ./Integrations/Maester/Build-EntraOpsMaesterPack.ps1 -PackRepository https://github.com/contoso/EntraOps-MaesterPack -EntraOpsRepository https://github.com/contoso/EntraOps -OutputPath ../contoso-EntraOps-MaesterPack

    Generates the same pack into the staging repository ../contoso-EntraOps-MaesterPack, with its help links
    and the rule catalog link of the fork.
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param (
    [Parameter(Mandatory = $false)]
    [string]$RepoRoot = (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)),

    [Parameter(Mandatory = $false)]
    [string]$OutputPath,

    [Parameter(Mandatory = $false)]
    [string]$Version,

    [Parameter(Mandatory = $false)]
    [switch]$Release,

    [Parameter(Mandatory = $false)]
    [ValidatePattern('^https://github\.com/[\w.-]+/[\w.-]+/?$')]
    [string]$PackRepository = 'https://github.com/Cloud-Architekt/EntraOps-MaesterPack',

    [Parameter(Mandatory = $false)]
    [ValidatePattern('^https://github\.com/[\w.-]+/[\w.-]+/?$')]
    [string]$EntraOpsRepository = 'https://github.com/Cloud-Architekt/EntraOps'
)

$ErrorActionPreference = 'Stop'
$PackRepository = $PackRepository.TrimEnd('/')
$EntraOpsRepository = $EntraOpsRepository.TrimEnd('/')
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $PackRepositoryName = ($PackRepository -split '/')[-2..-1] -join '/'
    $OutputPath = Join-Path (Split-Path -Parent $RepoRoot) ($PackRepository -split '/')[-1]
    if (-not (Test-Path -LiteralPath $OutputPath -PathType Container)) {
        throw "The pack repository was not found at $OutputPath. Clone $PackRepositoryName next to EntraOps, or pass -OutputPath."
    }
}
$OutputPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputPath)

$env:ENTRAOPS_NOWELCOME = '1'
$Module = Import-Module (Join-Path $RepoRoot 'EntraOps/EntraOps.psd1') -Force -PassThru -WarningAction SilentlyContinue
if ([string]::IsNullOrWhiteSpace($Version)) { $Version = $Module.Version.ToString() }
$Rules = @(Get-EntraOpsFindingRule)

# Released rule IDs never change (Maester test IDs): check the catalog before generating the pack.
$LockPath = Join-Path $RepoRoot 'EntraOps/Private/Findings/FindingRules.lock.json'
$Lock = Get-Content -LiteralPath $LockPath -Raw | ConvertFrom-Json
$Problems = @(& $Module { param($Rule, $ReleasedRule) Test-EntraOpsFindingRuleCatalog -Rule $Rule -ReleasedRule $ReleasedRule } $Rules @($Lock.rules))

# The tests in the pack repository were published (or are about to be): each must keep its rule.
$RulesById = @{}
foreach ($Rule in $Rules) { $RulesById[$Rule.Id] = $Rule }
$ExistingTests = @(if (Test-Path -LiteralPath (Join-Path $OutputPath 'tests') -PathType Container) { Get-ChildItem -LiteralPath (Join-Path $OutputPath 'tests') -File -Filter 'Test.MP.*.ps1' })
foreach ($Test in $ExistingTests) {
    $Match = [regex]::Match((Get-Content -LiteralPath $Test.FullName -Raw), 'EntraOps rule (EO\.\d{4}) \((\w+)\.(\w+)\)')
    if (-not $Match.Success) { $Problems += "$($Test.Name) in the pack repository is not an EntraOps rule test."; continue }
    $Rule = $RulesById[$Match.Groups[1].Value]
    if ($null -eq $Rule) { $Problems += "$($Test.Name) tests rule $($Match.Groups[1].Value), which is no longer in the catalog. Keep the rule with Lifecycle Deprecated instead." }
    elseif ($Rule.Area -cne $Match.Groups[2].Value -or $Rule.Key -cne $Match.Groups[3].Value -or $Test.Name -cne "Test.$($Rule.MaesterTestId).ps1") {
        $Problems += "$($Test.Name) tests $($Match.Groups[2].Value).$($Match.Groups[3].Value), but rule $($Rule.Id) is now $($Rule.Area).$($Rule.Key) ($($Rule.MaesterTestId)). Published test IDs never change; add a new rule instead."
    }
}
if ($Problems.Count -gt 0) { throw "The finding rule catalog is not valid:`n- $($Problems -join "`n- ")" }

# The links of the pack follow the repository that publishes it (-PackRepository); its identity does not.
# Never change Guid or Code once the pack is released: Update-MtPack refuses a release whose Guid or code changed.
$Manifest = [ordered]@{
    '$schema'        = 'https://maester.dev/schemas/maester-pack-1.0.json'
    Id               = 'cloud-architekt.entraops'
    Guid             = '01964975-3423-4c3e-a3a0-b2510e0d6e39'
    Name             = 'EntraOps'
    Description      = 'Reports the EntraOps findings on privileged access: Enterprise Access Model tier breaches, classification, standing access, account protection, workload identities, PIM, access packages and drift.'
    Version          = $Version
    Publisher        = 'Cloud-Architekt'
    License          = 'MIT'
    Homepage         = $PackRepository
    Support          = "$PackRepository/issues"
    SecurityContact  = "$PackRepository/security/policy"
    RequiresMaester  = '>=3.0'
    Code             = 'EOPS'
    Suites           = @('tests')
    Helpers          = @('helpers')
    Uses             = [ordered]@{
        Services     = @()
        GraphScopes  = @()
        TenantWrites = @()
        Network      = @()
        Modules      = @()
    }
    Categories       = @('Identity', 'Privileged access', 'Enterprise Access Model')
}
# Maintained in the pack repository: named in the manifest when they exist.
if (Test-Path -LiteralPath (Join-Path $OutputPath 'maester-pack.guide.json') -PathType Leaf) { $Manifest.Guide = 'maester-pack.guide.json' }
if (Test-Path -LiteralPath (Join-Path $OutputPath 'assets/banner.png') -PathType Leaf) { $Manifest.Banner = 'assets/banner.png' }

# The pack's menu in the Maester report (Maester 3.0.0-rc56 or later; older versions ignore it with a warning).
# The report shows the guide only when the menu has a guide page, so the set-up pages come with the guide.
$Navigation = [System.Collections.Generic.List[object]]::new()
$Navigation.Add([ordered]@{ Title = 'Overview'; View = 'pack' })
$Navigation.Add([ordered]@{
        Section = 'Findings'
        Items   = @(
            [ordered]@{ Title = 'All results'; Id = 'results'; View = 'tests' }
            [ordered]@{ Title = 'Not met'; Id = 'not-met'; View = 'tests'; Result = 'Failed' }
            [ordered]@{ Title = 'Not evaluated'; Id = 'not-evaluated'; View = 'tests'; Result = 'Skipped' }
        )
    })
if ($Manifest.Contains('Guide')) {
    $Navigation.Add([ordered]@{
            Section = 'Set up'
            Items   = @(
                [ordered]@{ Title = 'Get started'; Id = 'start'; View = 'guide'; Page = 'start' }
                [ordered]@{ Title = 'Connect'; Id = 'connect'; View = 'guide'; Page = 'connect' }
                [ordered]@{ Title = 'Run'; Id = 'run'; View = 'guide'; Page = 'run' }
            )
        })
}
$Navigation.Add([ordered]@{ Title = 'About this pack'; Id = 'about'; View = 'about' })
$Manifest.Report = [ordered]@{ Navigation = $Navigation.ToArray() }

$Suite = [ordered]@{
    Id              = 'EOPS.Findings'
    Name            = 'EntraOps findings'
    HelpUrlTemplate = "$PackRepository/blob/main/tests/Test.{Id}.md"
    Tags            = @('EntraOps')
}

# Constants for the [MaesterTest] attribute: single-quoted, with embedded quotes doubled.
function ConvertTo-AttributeString([string]$Value) { "'" + $Value.Replace("'", "''") + "'" }

# ResourceType of the [MaesterTest] attribute: a key of the Maester taxonomy (assets/MaesterTaxonomy.psd1 of
# Maester 3.0), so the report groups the pack's results with Maester's own tests. The catalog keeps the EntraOps
# resource types, which name the scope in the reasons of skipped rules. Role assignments, role definitions and
# administrative units (the scope of role assignments) are directory roles; privileged objects are mostly
# accounts, as in Maester's privileged-access tests. Azure role assignments point at their principals, as in
# Maester's MT.1056, and nested Control Plane groups at the groups.
$MaesterResourceTypes = @('Tenant', 'User', 'Group', 'Application', 'ServicePrincipal', 'Agent', 'Device', 'DirectoryRole', 'ConditionalAccessPolicy', 'Policy', 'AccessPackage', 'AzureResource', 'Permission')
$MaesterResourceTypeOf = @{ RoleAssignment = 'DirectoryRole'; RoleDefinition = 'DirectoryRole'; AdministrativeUnit = 'DirectoryRole'; PrivilegedObject = 'User' }
$MaesterResourceTypeOfRule = @{ 'PrivilegedEAM.nestedControlPlaneGroup' = 'Group' }
function Get-MaesterResourceType($Rule) {
    $Type = if ($MaesterResourceTypeOfRule.ContainsKey("$($Rule.Area).$($Rule.Key)")) { $MaesterResourceTypeOfRule["$($Rule.Area).$($Rule.Key)"] }
    elseif ($Rule.Product -eq 'azure' -and $Rule.ResourceType -eq 'RoleAssignment') { 'User' }
    elseif ($MaesterResourceTypeOf.ContainsKey($Rule.ResourceType)) { $MaesterResourceTypeOf[$Rule.ResourceType] }
    else { $Rule.ResourceType }
    if ($Type -cnotin $MaesterResourceTypes) { throw "Rule $($Rule.Id) has the resource type '$($Rule.ResourceType)', which has no Maester resource type. Map it in Build-EntraOpsMaesterPack.ps1." }
    $Type
}

# UserImpact and ImplementationCost of the attribute rate the remediation (Effort and UserImpact of the rule).
# Maester leaves them out for Info tests, which only ask for an investigation.
function Get-MaesterRemediationRating($Rule) {
    if ($Rule.Severity -eq 'Info') { return '' }
    "`n        UserImpact         = $(ConvertTo-AttributeString $Rule.UserImpact),`n        ImplementationCost = $(ConvertTo-AttributeString $Rule.Effort),"
}

# Test functions are named after what they check: Test-EntraOps<Subject><Key>, for example Test-EntraOpsObjectTierBreach.
$FunctionSubject = @{ PrivilegedAssets = 'Object'; TierBreach = 'AssignmentPath'; PrivilegedEAM = 'Privileged'; PimRequestFlow = 'PimRole'; AccessPackageFlow = 'AccessPackage'; TenantGovernance = 'Setting'; PrivilegeHistory = 'History' }

$Files = [ordered]@{
    'maester-pack.json' = ($Manifest | ConvertTo-Json -Depth 10)
    'tests/suite.json'  = ($Suite | ConvertTo-Json -Depth 5)
}
foreach ($Rule in $Rules) {
    $Name = "Test.$($Rule.MaesterTestId)"
    $FunctionName = 'Test-EntraOps' + $FunctionSubject[$Rule.Area] + $Rule.Key.Substring(0, 1).ToUpperInvariant() + $Rule.Key.Substring(1)
    $Files["tests/$Name.ps1"] = @"
function $FunctionName {
    <#
    .SYNOPSIS
    $($Rule.CheckTitle) EntraOps rule $($Rule.Id) ($($Rule.Area).$($Rule.Key)).

    .DESCRIPTION
    Generated by Build-EntraOpsMaesterPack.ps1 of $(($EntraOpsRepository -split '/')[-2..-1] -join '/') from the EntraOps finding rule catalog - do not edit by hand.
    #>
    [MaesterTest(
        Id                 = $(ConvertTo-AttributeString $Rule.MaesterTestId),
        Title              = $(ConvertTo-AttributeString $Rule.CheckTitle),
        Severity           = $(ConvertTo-AttributeString $Rule.Severity),$(Get-MaesterRemediationRating $Rule)
        Product            = $(ConvertTo-AttributeString $Rule.Product),
        Feature            = $(ConvertTo-AttributeString $Rule.Feature),
        Area               = 'privileged-access',
        ResourceType       = $(ConvertTo-AttributeString (Get-MaesterResourceType $Rule)),
        Service            = 'None',$(if ($Rule.Lifecycle -ne 'Stable') { "`n        Lifecycle          = $(ConvertTo-AttributeString $Rule.Lifecycle)," })
        Author             = 'Cloud-Architekt',
        HelpUrl            = $(ConvertTo-AttributeString "$PackRepository/blob/main/tests/$Name.md"),
        Tag                = ('EntraOps', $(ConvertTo-AttributeString $Rule.CategoryTitle))
    )]
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    Test-EntraOpsPackFinding -RuleId $(ConvertTo-AttributeString $Rule.Id)
}
"@
    # The description of a rule states its finding: the label says so, as Maester shows it with passed tests as well.
    $Files["tests/$Name.md"] = @"
**$(if ($Rule.Investigate) { 'Reported when' } else { 'Fails when' }):** $($Rule.Description)

EntraOps evaluates this rule as $($Rule.Id) ($($Rule.Area).$($Rule.Key)). The EntraOps reports show the same result as the finding '$($Rule.Title)'.$(if ($Rule.Investigate) { " The check asks for a review, not a fix: its findings are reported as Investigate, not as Failed." })

#### Remediation action

$($Rule.Remediation)

| Implementation effort | User impact |
| --- | --- |
| $($Rule.Effort): $($Rule.EffortDescription) | $($Rule.UserImpact): $($Rule.UserImpactDescription) |

#### Dismiss or accept a finding

A finding that is a false positive, or whose risk is accepted until a date, is an exception in the EntraOps Finding Exceptions File (``Findings.ExceptionsFilePath``, default ``./Classification/FindingExceptions.json``). The test doesn't fail for it: with dismissed findings only it passes, and with risk-accepted findings but no open one it is skipped with the accepted risks as the reason, because the control is not met. Add exceptions in the Findings view of the EntraOps Privileged Assets report (*Accept* at an affected object of $($Rule.Id)) and export the file to the EntraOps folder; the next EntraOps evaluation applies it.

#### Related links

$(@(@($Rule.References) | ForEach-Object { "- [$($_.Title)]($($_.Url))" }) -join "`n")
- [EntraOps findings and Maester Pack](https://www.entraops.com/docs/reportings/index.html#findings)
- [EntraOps finding exceptions](https://www.entraops.com/docs/reportings/index.html#finding-exceptions)
- [EntraOps finding rules]($EntraOpsRepository/blob/main/EntraOps/Private/Findings/FindingRules.json)

<!--- Results --->
%TestResult%
"@
}
foreach ($Helper in Get-ChildItem -LiteralPath (Join-Path $PSScriptRoot 'Template/helpers') -File -Filter '*.ps1') {
    $Files["helpers/$($Helper.Name)"] = Get-Content -LiteralPath $Helper.FullName -Raw
}

# The EntraOps source of this pack version; the helpers read findings.json files of schema version 1.x.
$Commit = git -C $RepoRoot rev-parse HEAD 2>$null
$HasGit = $LASTEXITCODE -eq 0 -and $Commit
# The GitHub repository of the commit (its origin remote): EntraOps, or the Insiders repository or a fork it was built from.
$Remote = if ($HasGit) { "$(git -C $RepoRoot remote get-url origin 2>$null)" } else { '' }
$SourceRepository = if ($Remote -match 'github\.com[:/]([\w.-]+)/([\w.-]+?)(?:\.git)?/?$') { "https://github.com/$($Matches[1])/$($Matches[2])" } else { 'https://github.com/Cloud-Architekt/EntraOps' }
$Files['entraops-source.json'] = [ordered]@{
    Repository     = $SourceRepository
    Version        = $Version
    Commit         = $(if ($HasGit) { "$Commit" } else { $null })
    LocalChanges   = $(if ($HasGit) { [bool](git -C $RepoRoot status --porcelain -- EntraOps/Private/Findings EntraOps/Public/Findings Integrations/Maester 2>$null) } else { $null })
    FindingsSchema = '1.x'
    Rules          = $Rules.Count
} | ConvertTo-Json -Depth 3

if ($PSCmdlet.ShouldProcess($OutputPath, 'Generate the EntraOps Maester Pack')) {
    foreach ($RelativePath in $Files.Keys) {
        $Target = Join-Path $OutputPath $RelativePath
        New-Item -ItemType Directory -Path (Split-Path -Parent $Target) -Force | Out-Null
        $Content = $Files[$RelativePath].Replace("`r`n", "`n").TrimEnd("`n") + "`n"
        [System.IO.File]::WriteAllText($Target, $Content, [System.Text.UTF8Encoding]::new($false))
    }
    Write-Host "Generated the EntraOps Maester Pack $Version with $($Rules.Count) tests in $OutputPath"
}

if ($Release -and $PSCmdlet.ShouldProcess($LockPath, 'Record the released finding rules')) {
    $Released = [System.Collections.Generic.List[object]]::new()
    foreach ($Entry in @($Lock.rules)) { $Released.Add($Entry) }
    foreach ($Rule in $Rules | Where-Object { $_.Id -notin @($Lock.rules.Id) }) {
        $Released.Add([ordered]@{ Id = $Rule.Id; Area = $Rule.Area; Key = $Rule.Key; Category = $Rule.Category; Since = $Version })
    }
    $Lock.rules = @($Released | Sort-Object { $_.Id })
    [System.IO.File]::WriteAllText($LockPath, ($Lock | ConvertTo-Json -Depth 5) + "`n", [System.Text.UTF8Encoding]::new($false))
    Write-Host "Recorded $($Released.Count) released finding rules in $LockPath"
}
