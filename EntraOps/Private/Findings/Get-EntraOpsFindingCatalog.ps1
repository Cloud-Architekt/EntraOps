function Get-EntraOpsFindingCatalog {
    <#
    .SYNOPSIS
        Returns the finding rule catalog (Private/Findings/FindingRules.json), read once per session.
    .DESCRIPTION
        The catalog is cached in the module scope on first use. Returns the parsed catalog (Catalog), the
        categories by key (Categories), the areas and categories in catalog order (Areas, CategoryKeys) and
        the names of the Findings settings of EntraOpsConfig.json (SettingNames: ExcludedRules, the
        Finding Exceptions File settings and the settings of the rule parameters). Parameters with Scope Root are
        settings of the whole EntraOpsConfig.json (for example ManagingTenantId), not Findings settings.
    #>
    [CmdletBinding()]
    param ()

    if ($null -ne $script:EntraOpsFindingCatalog) { return $script:EntraOpsFindingCatalog }

    $CatalogPath = Join-Path (Get-EntraOpsFindingRoot).ModuleRoot 'Private/Findings/FindingRules.json'
    if (-not (Test-Path -LiteralPath $CatalogPath -PathType Leaf)) {
        throw "EntraOps finding rule catalog not found: $CatalogPath"
    }
    try {
        $Catalog = Get-Content -LiteralPath $CatalogPath -Raw -Encoding UTF8 | ConvertFrom-Json
    } catch {
        throw "Failed to read the EntraOps finding rule catalog '$CatalogPath': $($_.Exception.Message)"
    }

    $Categories = [ordered]@{}
    foreach ($Entry in @($Catalog.categories)) { $Categories[$Entry.Key] = $Entry }
    $SettingNames = [System.Collections.Generic.List[string]]::new()
    $SettingNames.Add('ExcludedRules')
    $SettingNames.Add('ExceptionsFilePath')
    $SettingNames.Add('ExceptionMaxDays')
    foreach ($Parameter in @($Catalog.rules.Parameters | Where-Object { $_ -and "$($_.Scope)" -ne 'Root' })) { if (-not $SettingNames.Contains($Parameter.Setting)) { $SettingNames.Add($Parameter.Setting) } }

    $script:EntraOpsFindingCatalog = [pscustomobject]@{
        Path         = $CatalogPath
        Catalog      = $Catalog
        Categories   = $Categories
        CategoryKeys = @($Categories.Keys)
        Areas        = @($Catalog.rules.Area | Select-Object -Unique)
        SettingNames = @($SettingNames)
    }
    $script:EntraOpsFindingCatalog
}

function Assert-EntraOpsFindingCatalogValue {
    <#
    .SYNOPSIS
        Throws when a finding rule area or category is not in the catalog, listing the valid values.
    .DESCRIPTION
        The -Area and -Category parameters of the Findings cmdlets complete the values of the catalog
        (Get-EntraOpsFindingCatalogCompletion) and validate them with this function, so a new area or
        category of the catalog needs no change of the cmdlets.
    .PARAMETER Name
        Area or Category.
    .PARAMETER Value
        The values to check (compared case-insensitively).
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateSet('Area', 'Category')]
        [string]$Name,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [AllowEmptyCollection()]
        [string[]]$Value = @()
    )

    $Catalog = Get-EntraOpsFindingCatalog
    $Valid = if ($Name -eq 'Area') { $Catalog.Areas } else { $Catalog.CategoryKeys }
    $Unknown = @($Value | Where-Object { -not [string]::IsNullOrEmpty($_) -and $_ -notin $Valid })
    if ($Unknown.Count -gt 0) {
        throw "Unknown finding rule $($Name.ToLowerInvariant()) '$($Unknown -join "', '")'. Valid values: $($Valid -join ', ')."
    }
}

function Get-EntraOpsFindingCatalogCompletion {
    <#
    .SYNOPSIS
        Tab completion of the -Area and -Category parameters of the Findings cmdlets from the catalog.
    .PARAMETER Name
        Area or Category.
    .PARAMETER WordToComplete
        The text typed so far.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateSet('Area', 'Category')]
        [string]$Name,

        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string]$WordToComplete = ''
    )

    $Catalog = Get-EntraOpsFindingCatalog
    $Values = if ($Name -eq 'Area') { $Catalog.Areas } else { $Catalog.CategoryKeys }
    foreach ($Value in $Values) {
        if ($Value -like "$($WordToComplete.Trim('''', '"'))*") { [System.Management.Automation.CompletionResult]::new($Value, $Value, 'ParameterValue', $Value) }
    }
}
