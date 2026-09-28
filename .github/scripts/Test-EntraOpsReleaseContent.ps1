<#
.SYNOPSIS
    Fails when content that ships to the public repository contains tenant-specific or personal data.

.DESCRIPTION
    EntraOps is published as a template that operators fork into their own private repository. Files
    that ship with the project (module source, documentation, samples, classification defaults,
    workbooks, parsers, queries and workflows) must therefore never contain data derived from a real
    tenant. Generated output produced by an operator's own deployment (PrivilegedEAM, tenant-specific
    Classification folders, TenantGovernance snapshots, generated report data, EntraOpsConfig.json)
    is expected to contain tenant data and is excluded from this scan.

    Checks:
      - initial domains (*.onmicrosoft.com) other than the documented placeholder tenants
      - e-mail addresses other than the documented placeholder and maintainer contact addresses
      - Azure subscription resource paths with a non-zero subscription GUID
      - a non-empty ExcludedPrincipalId list in the shipped Classification/Global.json

.PARAMETER RepositoryRoot
    Root of the repository to scan. Defaults to the repository containing this script.

.EXAMPLE
    ./.github/scripts/Test-EntraOpsReleaseContent.ps1
#>
[CmdletBinding()]
param (
    [Parameter(Mandatory = $false)]
    [string]$RepositoryRoot = (Join-Path $PSScriptRoot '../..')
)

$ResolvedRepositoryRoot = [System.IO.Path]::GetFullPath($RepositoryRoot)
if (-not (Test-Path -LiteralPath $ResolvedRepositoryRoot -PathType Container)) {
    throw "Repository root '$ResolvedRepositoryRoot' does not exist."
}

# Paths holding operator-generated output, which legitimately contains tenant data.
$ExcludedPathPatterns = @(
    '.git/'
    'PrivilegedEAM/'
    'TenantGovernance/'
    'Review/'
    'Reports/*/data/'
    'Docs/data/'
    'EntraOpsConfig.json'
    # This validator's own tests must contain the patterns it rejects.
    'Tests/Reporting/Test-EntraOpsReleaseContent.Tests.ps1'
)

# Tenant and identity placeholders that are intentionally used in examples and fixtures.
$AllowedTenantNames = @('contoso', 'fabrikam', 'adatum', 'tenant', 'tenantname', 'yourtenant', 'managementgroup01', 'm365x', 'example')
$AllowedMailDomains = @('contoso.com', 'fabrikam.com', 'adatum.com', 'example.com', 'example.org', 'example.net')
$AllowedMailAddresses = @(
    'security@entraops.com'
    'entraopsghactions@ghactions.com'
    'alex.wilber@outlook.com'
)

$Violations = [System.Collections.Generic.List[string]]::new()

# -Force is required so dot-directories such as .github are included; .git is pruned before recursion.
$RootEntries = Get-ChildItem -LiteralPath $ResolvedRepositoryRoot -Force | Where-Object { $_.Name -ne '.git' }
$Files = @(foreach ($RootEntry in $RootEntries) {
        if ($RootEntry.PSIsContainer) {
            Get-ChildItem -LiteralPath $RootEntry.FullName -Recurse -File -Force
        } else {
            $RootEntry
        }
    }) | Where-Object {
    $RelativePath = [System.IO.Path]::GetRelativePath($ResolvedRepositoryRoot, $_.FullName).Replace('\', '/')
    $IsExcluded = $false
    foreach ($Pattern in $ExcludedPathPatterns) {
        if ($RelativePath -like "$Pattern*" -or $RelativePath -like "*/$Pattern*" -or $RelativePath -like $Pattern) {
            $IsExcluded = $true
            break
        }
    }
    # Only Templates/ and Global.json ship with the project. Everything else under Classification/ is
    # tenant-specific output written into an operator's own repository and legitimately contains their
    # tenant name, subscription ids and scope paths.
    if (-not $IsExcluded -and $RelativePath -like 'Classification/*' -and
        $RelativePath -notlike 'Classification/Templates/*' -and $RelativePath -ne 'Classification/Global.json') {
        $IsExcluded = $true
    }
    -not $IsExcluded
}

foreach ($File in $Files) {
    $RelativePath = [System.IO.Path]::GetRelativePath($ResolvedRepositoryRoot, $File.FullName).Replace('\', '/')

    $Content = $null
    try {
        $Content = [System.IO.File]::ReadAllText($File.FullName)
    } catch {
        continue
    }
    # Skip binary content.
    if ($Content.Contains([char]0)) {
        continue
    }

    foreach ($Match in [regex]::Matches($Content, '(?<Tenant>[a-zA-Z0-9-]+)\.onmicrosoft\.com')) {
        $TenantName = $Match.Groups['Tenant'].Value.ToLowerInvariant()
        if ($TenantName -in $AllowedTenantNames -or $TenantName.StartsWith('<') -or $TenantName.StartsWith('your')) {
            continue
        }
        $Violations.Add("$RelativePath contains the initial domain '$($Match.Value)'. Use a placeholder tenant such as contoso.onmicrosoft.com.")
    }

    foreach ($Match in [regex]::Matches($Content, '(?<Mail>[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})')) {
        $MailAddress = $Match.Groups['Mail'].Value.ToLowerInvariant()
        if ($MailAddress -like '*@odata.bind') {
            continue
        }
        $MailDomain = $MailAddress.Split('@')[-1]
        if ($MailAddress -in $AllowedMailAddresses -or $MailDomain -in $AllowedMailDomains) {
            continue
        }
        $Violations.Add("$RelativePath contains the mail address '$($Match.Groups['Mail'].Value)'. Use a placeholder address such as AdeleV@contoso.com.")
    }

    foreach ($Match in [regex]::Matches($Content, '/subscriptions/(?<Subscription>[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})')) {
        $SubscriptionId = $Match.Groups['Subscription'].Value
        # Placeholders such as 00000000-0000-0000-0000-000000000001 or 11111111-1111-... are built from a
        # repeated digit; a real subscription id never has this little entropy.
        $Digits = $SubscriptionId -replace '-', ''
        if (@($Digits.ToCharArray() | Select-Object -Unique).Count -le 2) {
            continue
        }
        $Violations.Add("$RelativePath contains the subscription resource path '$($Match.Value)'. Replace it with a placeholder or remove the saved value.")
    }
}

$GlobalExclusionPath = Join-Path $ResolvedRepositoryRoot 'Classification/Global.json'
if (Test-Path -LiteralPath $GlobalExclusionPath) {
    $GlobalExclusions = @((Get-Content -LiteralPath $GlobalExclusionPath -Raw | ConvertFrom-Json).ExcludedPrincipalId | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    if ($GlobalExclusions.Count -gt 0) {
        $Violations.Add("Classification/Global.json ships a non-empty ExcludedPrincipalId list ($($GlobalExclusions -join ', ')). Principals excluded there are silently dropped from classification in every deployment; the shipped default must be empty.")
    }
}

if ($Violations.Count -gt 0) {
    $SortedViolations = @($Violations | Sort-Object -Unique)
    $SortedViolations | ForEach-Object { Write-Host "::error::$_" }
    throw "Release content validation failed with $($SortedViolations.Count) finding(s):`n$($SortedViolations -join "`n")"
}

Write-Output "Release content validation passed for $($Files.Count) file(s)."
