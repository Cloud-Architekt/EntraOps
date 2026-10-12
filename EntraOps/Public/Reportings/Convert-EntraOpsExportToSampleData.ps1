#Requires -Version 7.2

function Convert-EntraOpsExportToSampleData {
    <#
.SYNOPSIS
Creates a relationship-preserving anonymized copy of EntraOps export data.

.DESCRIPTION
Processes the Classification, PrivilegedEAM, and TenantGovernance directories below
SourcePath. A single mapping is used for the complete run so identifiers and names
that occur in more than one export remain related.

GUID replacements are derived from Seed. Identity and Azure resource names use
stable aliases such as user01, group01, resourcegroup01, and storage01. The source
is never modified and the source-to-target mapping is not written to disk.

.PARAMETER TenantName
Target tenant prefix. Defaults to contoso. Unless TenantInitialDomain is supplied,
the target initial domain is derived as <TenantName>.onmicrosoft.com.

.PARAMETER TenantInitialDomain
Target tenant initial domain and Classification tenant folder name. Use this when
the initial domain is not <TenantName>.onmicrosoft.com.

.PARAMETER GenerateReports
Generate an offline EntraOps Reporting bundle from the anonymized data. The bundle
includes EAM Dashboard, Tier Breach Analyzer, Access Path Map, and Configuration
Analyzer when its snapshot prerequisites are available. Graph enrichment is disabled.
Report generation requires PowerShell 7.4 or later.

.PARAMETER ReportDestinationPath
Destination for the generated report bundle. Defaults to <DestinationPath>/Reports.

.EXAMPLE
Import-Module EntraOps
Convert-EntraOpsExportToSampleData `
    -SourcePath '/path/to/EntraOpsExport' `
    -DestinationPath '/path/to/EntraOpsExport-Anonymized' `
    -SourceTenantName 'fabrikam' `
    -Seed 'sample-data-v1' `
    -GenerateReports `
    -Verbose

.NOTES
Progress is displayed by default. Use -ProgressAction SilentlyContinue to hide
the progress display, for example in non-interactive automation.
#>

    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [ValidateScript({ Test-Path -LiteralPath $_ -PathType Container })]
        [string]$SourcePath,

        [Parameter(Mandatory)]
        [string]$DestinationPath,

        [string]$SourceTenantName,

        [ValidateNotNullOrEmpty()]
        [string]$TenantName = 'contoso',

        [ValidatePattern('^[a-zA-Z0-9.-]+$')]
        [string]$TenantInitialDomain,

        [ValidateNotNullOrEmpty()]
        [string]$Seed = ([guid]::NewGuid().Guid),

        [string[]]$AdditionalSensitivePropertyName = @(),

        [switch]$GenerateReports,

        [string]$ReportDestinationPath
    )

    Set-StrictMode -Version Latest
    $ErrorActionPreference = 'Stop'

    if ($GenerateReports -and $PSVersionTable.PSVersion -lt [version]'7.4') {
        throw '-GenerateReports requires PowerShell 7.4 or later because the EntraOps module requires that version.'
    }

    if ([string]::IsNullOrWhiteSpace($TenantInitialDomain)) {
        $TenantInitialDomain = "$TenantName.onmicrosoft.com"
    }

    $script:GuidAliases = [System.Collections.Generic.Dictionary[string, string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $script:LabelAliases = [System.Collections.Generic.Dictionary[string, string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $script:NameAliases = [System.Collections.Generic.Dictionary[string, string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $script:UserAliases = [System.Collections.Generic.Dictionary[string, string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $script:ResourceValueAliases = [System.Collections.Generic.Dictionary[string, string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $script:AliasCounters = [System.Collections.Generic.Dictionary[string, int]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $script:EmbeddedAliasPattern = $null
    $script:AnonymizedStringCache = [System.Collections.Generic.Dictionary[string, string]]::new([System.StringComparer]::Ordinal)
    $script:AnonymizedStringCacheResult = $null
    $script:GuidHmac = $null
    $script:GuidPattern = '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'
    $script:ResourceTypeAliases = @{
        automationaccounts     = 'automation'
        clusters               = 'cluster'
        databases              = 'database'
        factories              = 'datafactory'
        managedclusters        = 'cluster'
        managementgroups       = 'managementgroup'
        namespaces             = 'namespace'
        registries             = 'registry'
        servers                = 'server'
        sites                  = 'webapp'
        storageaccounts        = 'storage'
        userassignedidentities = 'managedidentity'
        vaults                 = 'keyvault'
        virtualmachines        = 'virtualmachine'
        virtualnetworks        = 'virtualnetwork'
        workflows              = 'logicapp'
    }

    function Get-AnonymizedGuid {
        param([Parameter(Mandatory)][string]$Value)

        if (-not $script:GuidAliases.ContainsKey($Value)) {
            if ($null -eq $script:GuidHmac) {
                $script:GuidHmac = [System.Security.Cryptography.HMACSHA256]::new([System.Text.Encoding]::UTF8.GetBytes($Seed))
            }
            $Hash = $script:GuidHmac.ComputeHash([System.Text.Encoding]::UTF8.GetBytes("guid:$($Value.ToLowerInvariant())"))

            $GuidBytes = [byte[]]::new(16)
            [System.Array]::Copy($Hash, $GuidBytes, 16)
            $script:GuidAliases[$Value] = ([guid]::new($GuidBytes)).Guid
        }

        return $script:GuidAliases[$Value]
    }

    function Get-AnonymizedLabel {
        param(
            [Parameter(Mandatory)][string]$Category,
            [Parameter(Mandatory)][string]$Value
        )

        $NormalizedCategory = ($Category.ToLowerInvariant() -replace '[^a-z0-9]', '')
        if ([string]::IsNullOrWhiteSpace($NormalizedCategory)) {
            $NormalizedCategory = 'object'
        }

        $AliasKey = "$NormalizedCategory`0$Value"
        if (-not $script:LabelAliases.ContainsKey($AliasKey)) {
            if (-not $script:AliasCounters.ContainsKey($NormalizedCategory)) {
                $script:AliasCounters[$NormalizedCategory] = 0
            }

            $script:AliasCounters[$NormalizedCategory]++
            $script:LabelAliases[$AliasKey] = '{0}{1:00}' -f $NormalizedCategory, $script:AliasCounters[$NormalizedCategory]
        }

        return $script:LabelAliases[$AliasKey]
    }

    function Get-IdentityCategory {
        param([AllowNull()][string]$ObjectType)

        switch -Regex ($ObjectType) {
            '^user$' { return 'user' }
            '^group$' { return 'group' }
            '^serviceprincipal$' { return 'serviceprincipal' }
            default { return 'object' }
        }
    }

    function Get-ResourceCategory {
        param([Parameter(Mandatory)][string]$ResourceType)

        $NormalizedType = ($ResourceType.ToLowerInvariant() -replace '[^a-z0-9]', '')
        if ($script:ResourceTypeAliases.ContainsKey($NormalizedType)) {
            return $script:ResourceTypeAliases[$NormalizedType]
        }

        if ($NormalizedType.EndsWith('ies')) {
            return $NormalizedType.Substring(0, $NormalizedType.Length - 3) + 'y'
        }
        if ($NormalizedType.EndsWith('s') -and -not $NormalizedType.EndsWith('ss')) {
            return $NormalizedType.Substring(0, $NormalizedType.Length - 1)
        }

        return $NormalizedType
    }

    function Get-AnonymizedResourceName {
        param(
            [Parameter(Mandatory)][string]$ResourceType,
            [Parameter(Mandatory)][string]$Value
        )

        if ($Value -match "(?i)^$($script:GuidPattern)`$") {
            return $Value
        }

        if ($Value -match '[*?]') {
            # Wildcard scope/role-action patterns (e.g. "*", "rg-prod*") are not resource
            # names; anonymizing them would corrupt every literal wildcard in the output.
            return $Value
        }

        $Category = Get-ResourceCategory -ResourceType $ResourceType
        $Alias = Get-AnonymizedLabel -Category $Category -Value $Value
        if (-not $script:ResourceValueAliases.ContainsKey($Value)) {
            $script:ResourceValueAliases[$Value] = $Alias
        }
        return $Alias
    }

    function Convert-AzureResourceId {
        param([Parameter(Mandatory)][string]$Value)

        if ($Value -notmatch '(?i)^/(subscriptions|providers|resourcegroups)/') {
            return $Value
        }

        $Segments = $Value.Split('/')
        for ($Index = 1; $Index -lt $Segments.Count; $Index++) {
            switch ($Segments[$Index].ToLowerInvariant()) {
                'subscriptions' {
                    if ($Index + 1 -lt $Segments.Count) {
                        $Index++
                    }
                }
                'resourcegroups' {
                    if ($Index + 1 -lt $Segments.Count) {
                        $Segments[$Index + 1] = Get-AnonymizedResourceName -ResourceType 'resourcegroups' -Value $Segments[$Index + 1]
                        $Index++
                    }
                }
                'providers' {
                    if ($Index + 1 -lt $Segments.Count) {
                        $Index += 2
                    }
                    while ($Index -lt $Segments.Count) {
                        $ResourceType = $Segments[$Index]
                        if ($Index + 1 -ge $Segments.Count) {
                            break
                        }
                        if ($ResourceType.ToLowerInvariant() -eq 'providers') {
                            # A nested provider namespace (e.g. a role assignment scoped to
                            # a resource under a second /providers/Microsoft.X/ segment):
                            # skip the namespace instead of anonymizing it as a resource value.
                            $Index += 2
                            continue
                        }
                        $Segments[$Index + 1] = Get-AnonymizedResourceName -ResourceType $ResourceType -Value $Segments[$Index + 1]
                        $Index += 2
                    }
                }
            }
        }

        return $Segments -join '/'
    }

    function Convert-GuidText {
        param([Parameter(Mandatory)][string]$Value)

        return [regex]::Replace(
            $Value,
            "(?i)(?<![0-9a-f])$($script:GuidPattern)(?![0-9a-f])",
            { param($Match) Get-AnonymizedGuid -Value $Match.Value }
        )
    }

    function Get-UserAlias {
        param([Parameter(Mandatory)][string]$Value)

        if ($script:UserAliases.ContainsKey($Value)) {
            return $script:UserAliases[$Value]
        }

        $Alias = Get-AnonymizedLabel -Category 'user' -Value $Value
        $script:UserAliases[$Value] = $Alias
        return $Alias
    }

    function Resolve-UserIdentityAlias {
        param([Parameter(Mandatory)][string]$Value)

        # Get-UserAlias already checks/populates $script:UserAliases itself; only the
        # NameAliases fallback (an identity registered by its display name, not its UPN) needs
        # to be checked ahead of it here.
        if ($script:NameAliases.ContainsKey($Value)) {
            return $script:NameAliases[$Value]
        }
        return Get-UserAlias -Value $Value
    }

    function Convert-UserIdentityText {
        param([Parameter(Mandatory)][string]$Value)

        $Converted = [regex]::Replace(
            $Value,
            '(?i)(?<identity>[a-z0-9.!#$%&''*+/=?^_`{|}~-]+)#EXT#@(?<domain>[a-z0-9.-]+)',
            {
                param($Match)
                $Alias = Resolve-UserIdentityAlias -Value $Match.Value
                return "$Alias#EXT#@$script:ConvertEntraOpsExportToSampleDataTenantInitialDomain"
            }
        )

        return [regex]::Replace(
            $Converted,
            '(?i)(?<local>[a-z0-9.!#$%&''*+/=?^_`{|}~-]+)@(?<domain>[a-z0-9.-]+\.[a-z]{2,})',
            {
                param($Match)
                if ($Match.Value -match '(?i)#EXT#@') {
                    return $Match.Value
                }
                $Alias = Resolve-UserIdentityAlias -Value $Match.Value
                $TargetDomain = if ($Match.Groups['domain'].Value.EndsWith('.onmicrosoft.com', [System.StringComparison]::OrdinalIgnoreCase)) {
                    $script:ConvertEntraOpsExportToSampleDataTenantInitialDomain
                } else {
                    "$script:ConvertEntraOpsExportToSampleDataTenantName.com"
                }
                return "$Alias@$TargetDomain"
            }
        )
    }

    function Convert-AnonymizedString {
        # Only called during phase 3, once all aliases/EmbeddedAliasPattern are final, so
        # results can be safely cached: export files repeat the same schema keys and
        # frequently-repeated values (tier labels, role names, ...) many times over.
        param([AllowEmptyString()][string]$Value)

        if ([string]::IsNullOrEmpty($Value)) {
            return $Value
        }

        if ($script:AnonymizedStringCache.TryGetValue($Value, [ref]$script:AnonymizedStringCacheResult)) {
            return $script:AnonymizedStringCacheResult
        }

        $Result = Convert-AnonymizedStringCore -Value $Value
        $script:AnonymizedStringCache[$Value] = $Result
        return $Result
    }

    function Convert-AnonymizedStringCore {
        param([AllowEmptyString()][string]$Value)

        if (-not [string]::IsNullOrWhiteSpace($script:ConvertEntraOpsExportToSampleDataSourceTenantName) -and
            $Value.Equals("$($script:ConvertEntraOpsExportToSampleDataSourceTenantName).onmicrosoft.com", [System.StringComparison]::OrdinalIgnoreCase)) {
            return $script:ConvertEntraOpsExportToSampleDataTenantInitialDomain
        }

        if (-not [string]::IsNullOrWhiteSpace($script:ConvertEntraOpsExportToSampleDataSourceTenantName) -and
            $Value -notmatch '[/@]') {
            # Use a MatchEvaluator (not a replacement string) so that "$0"/"$&"/"${name}"
            # tokens inside -TenantName are treated as literal text, not regex substitutions.
            $Value = [regex]::Replace(
                $Value,
                "(?i)$([regex]::Escape($script:ConvertEntraOpsExportToSampleDataSourceTenantName))",
                { $script:ConvertEntraOpsExportToSampleDataTenantName }
            )
        }

        if ($script:ResourceValueAliases.ContainsKey($Value)) {
            return $script:ResourceValueAliases[$Value]
        }
        if ($script:NameAliases.ContainsKey($Value) -and $Value -notmatch '(@|#EXT#)') {
            return $script:NameAliases[$Value]
        }

        $Converted = Convert-AzureResourceId -Value $Value
        $Converted = if ($null -ne $script:EmbeddedAliasPattern) {
            $script:EmbeddedAliasPattern.Replace(
                $Converted,
                {
                    param($Match)
                    if ($Match.Value -match '(@|#EXT#)') {
                        return $Match.Value
                    }
                    if ($script:ResourceValueAliases.ContainsKey($Match.Value)) {
                        return $script:ResourceValueAliases[$Match.Value]
                    }
                    return $script:NameAliases[$Match.Value]
                }
            )
        } else {
            $Converted
        }
        $Converted = Convert-UserIdentityText -Value $Converted
        $Converted = Convert-GuidText -Value $Converted

        return $Converted
    }

    function Register-PrimaryIdentityNames {
        param([AllowNull()]$Node)

        if ($null -eq $Node) {
            return
        }
        if ($Node -is [System.Collections.IDictionary]) {
            if ($Node.Contains('ObjectDisplayName') -and -not [string]::IsNullOrWhiteSpace([string]$Node['ObjectDisplayName'])) {
                $Category = Get-IdentityCategory -ObjectType ([string]$Node['ObjectType'])
                $IdentityKey = if ($Node.Contains('ObjectId') -and $Node['ObjectId']) { [string]$Node['ObjectId'] } else { [string]$Node['ObjectDisplayName'] }
                $Alias = Get-AnonymizedLabel -Category $Category -Value $IdentityKey
                if (-not $script:NameAliases.ContainsKey([string]$Node['ObjectDisplayName'])) {
                    $script:NameAliases[[string]$Node['ObjectDisplayName']] = $Alias
                }
                if ($Node.Contains('ObjectUserPrincipalName') -and [string]$Node['ObjectUserPrincipalName'] -match '(@|#EXT#)') {
                    $script:UserAliases[[string]$Node['ObjectUserPrincipalName']] = $Alias
                    $script:NameAliases[[string]$Node['ObjectUserPrincipalName']] = $Alias
                }
            }

            foreach ($Entry in $Node.GetEnumerator()) {
                Register-PrimaryIdentityNames -Node $Entry.Value
            }
            return
        }
        if ($Node -is [System.Collections.IEnumerable] -and $Node -isnot [string]) {
            foreach ($Item in $Node) {
                Register-PrimaryIdentityNames -Node $Item
            }
        }
    }

    function Register-RelatedNamesAndResources {
        param([AllowNull()]$Node)

        if ($null -eq $Node) {
            return
        }
        if ($Node -is [System.Collections.IDictionary]) {
            foreach ($Entry in $Node.GetEnumerator()) {
                # Matches both the EntraOps export's PascalCase names (ObjectDisplayName, ...)
                # and raw Graph/ARM camelCase names (displayName, userPrincipalName, ...),
                # since TenantGovernance snapshots persist unmodified Graph response objects.
                $IsSensitiveProperty = $Entry.Key -match '(?i)(DisplayName|DisplayNames|UserPrincipalName|ResourceName)$' -or
                $AdditionalSensitivePropertyName -contains [string]$Entry.Key
                if ($IsSensitiveProperty) {
                    $Values = if ($Entry.Value -is [System.Collections.IEnumerable] -and $Entry.Value -isnot [string]) { $Entry.Value } else { @($Entry.Value) }
                    foreach ($SensitiveValue in $Values) {
                        if ($SensitiveValue -is [string] -and -not [string]::IsNullOrWhiteSpace($SensitiveValue) -and -not $script:NameAliases.ContainsKey($SensitiveValue)) {
                            $script:NameAliases[$SensitiveValue] = Get-AnonymizedLabel -Category 'object' -Value $SensitiveValue
                        }
                    }
                }
                if ($Entry.Value -is [string] -and $Entry.Value -match '(?i)^/(subscriptions|providers|resourcegroups)/') {
                    $null = Convert-AzureResourceId -Value $Entry.Value
                }
                Register-RelatedNamesAndResources -Node $Entry.Value
            }
            return
        }
        if ($Node -is [System.Collections.IEnumerable] -and $Node -isnot [string]) {
            foreach ($Item in $Node) {
                Register-RelatedNamesAndResources -Node $Item
            }
        }
    }

    function Convert-AnonymizedNode {
        param([AllowNull()]$Node)

        if ($null -eq $Node) {
            return $null
        }
        if ($Node -is [string]) {
            return Convert-AnonymizedString -Value $Node
        }
        if ($Node -is [System.Collections.IDictionary]) {
            $ConvertedObject = [ordered]@{}
            foreach ($Entry in $Node.GetEnumerator()) {
                $ConvertedName = Convert-AnonymizedString -Value ([string]$Entry.Key)
                $ConvertedObject[$ConvertedName] = Convert-AnonymizedNode -Node $Entry.Value
            }
            return $ConvertedObject
        }
        if ($Node -is [System.Collections.IEnumerable]) {
            $ConvertedItems = @(
                foreach ($Item in $Node) {
                    Convert-AnonymizedNode -Node $Item
                }
            )
            return , $ConvertedItems
        }

        return $Node
    }

    function Read-JsonDocument {
        param([Parameter(Mandatory)][string]$Path)

        try {
            # -NoEnumerate keeps a top-level JSON array as a single array value instead of
            # unrolling it onto the pipeline, which would otherwise corrupt round-tripping
            # of empty ("[]" -> $null) and single-element ("[x]" -> x) arrays.
            return [System.IO.File]::ReadAllText($Path) | ConvertFrom-Json -AsHashtable -Depth 100 -NoEnumerate
        } catch {
            throw "Failed to parse export JSON '$Path': $($_.Exception.Message)"
        }
    }

    function Write-AnonymizationProgress {
        param(
            [Parameter(Mandatory)][string]$Phase,
            [Parameter(Mandatory)][int]$PhaseNumber,
            [Parameter(Mandatory)][int]$CurrentItem,
            [Parameter(Mandatory)][int]$TotalItems,
            [string]$CurrentFile
        )

        $TotalWorkItems = [Math]::Max(1, $TotalItems * 3)
        $CompletedWorkItems = (($PhaseNumber - 1) * $TotalItems) + $CurrentItem
        $PercentComplete = [Math]::Min(100, [Math]::Floor(($CompletedWorkItems / $TotalWorkItems) * 100))
        $Status = "Phase $PhaseNumber of 3: $Phase ($CurrentItem of $TotalItems)"

        Write-Progress -Id 1 -Activity 'Anonymizing EntraOps export' -Status $Status `
            -CurrentOperation $CurrentFile -PercentComplete $PercentComplete
    }

    function New-AnonymizedReportBundle {
        param(
            [Parameter(Mandatory)][string]$AnonymizedRoot,
            [Parameter(Mandatory)][string]$ReportRoot
        )

        # $PSScriptRoot is <module>/Public/Reportings in both repository clones and module-only installs.
        $ModuleRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
        $WorkingFolder = if (-not [string]::IsNullOrWhiteSpace($Global:EntraOpsBaseFolder)) { $Global:EntraOpsBaseFolder } else { Split-Path -Parent $ModuleRoot }
        $ReportTemplateRoot = Join-Path $WorkingFolder 'Reports'
        $ModuleManifest = Join-Path $ModuleRoot 'EntraOps.psd1'
        if (-not (Test-Path -LiteralPath $ReportTemplateRoot -PathType Container)) {
            throw "EntraOps report templates were not found: $ReportTemplateRoot. Run Initialize-EntraOpsWorkspace -Content Reports to install them."
        }
        if (-not (Test-Path -LiteralPath $ModuleManifest -PathType Leaf)) {
            throw "EntraOps module manifest was not found: $ModuleManifest"
        }
        if (Test-Path -LiteralPath $ReportRoot) {
            throw "ReportDestinationPath already exists: $ReportRoot"
        }

        Write-Progress -Id 2 -ParentId 1 -Activity 'Generating reports from anonymized data' `
            -Status 'Copying static report assets' -PercentComplete 10
        Write-Verbose "Copying report assets from $ReportTemplateRoot to $ReportRoot"
        $null = [System.IO.Directory]::CreateDirectory($ReportRoot)
        Get-ChildItem -LiteralPath $ReportTemplateRoot -Force |
        Where-Object Name -NotIn @('.DS_Store') |
        Copy-Item -Destination $ReportRoot -Recurse -Force

        # Copied report trees can contain ignored generated datasets from a previous run.
        # Remove all of them before generating from the anonymized export.
        Get-ChildItem -LiteralPath $ReportRoot -Recurse -Directory -Force |
        Where-Object Name -EQ 'data' |
        ForEach-Object {
            Get-ChildItem -LiteralPath $_.FullName -Force -ErrorAction SilentlyContinue |
            Remove-Item -Recurse -Force
        }

        Write-Progress -Id 2 -ParentId 1 -Activity 'Generating reports from anonymized data' `
            -Status 'Loading EntraOps reporting commands' -PercentComplete 20
        Import-Module $ModuleManifest -Force -ErrorAction Stop

        $GeneratedReports = [System.Collections.Generic.List[string]]::new()
        $PrivilegedEamPath = Join-Path $AnonymizedRoot 'PrivilegedEAM'
        if (Test-Path -LiteralPath $PrivilegedEamPath -PathType Container) {
            $ReportTasks = @(
                [ordered]@{
                    Name       = 'EamDashboard'
                    Percent    = 35
                    Command    = 'New-EntraOpsPrivilegedEamDashboardData'
                    Parameters = @{
                        RepoRoot                       = $AnonymizedRoot
                        ImportPath                     = $PrivilegedEamPath
                        AppRoot                        = Join-Path $ReportRoot 'EamDashboard'
                        ResolveLinkedIdentityObjectIds = $false
                    }
                },
                [ordered]@{
                    Name       = 'TierBreachAnalyzer'
                    Percent    = 50
                    Command    = 'New-EntraOpsTierBreachAnalyzerData'
                    Parameters = @{
                        RepoRoot   = $AnonymizedRoot
                        ImportPath = $PrivilegedEamPath
                        AppRoot    = Join-Path $ReportRoot 'TierBreachAnalyzer'
                    }
                },
                [ordered]@{
                    Name       = 'AccessPathMap'
                    Percent    = 65
                    Command    = 'New-EntraOpsAccessPathMapData'
                    Parameters = @{
                        RepoRoot                             = $AnonymizedRoot
                        ImportPath                           = $PrivilegedEamPath
                        AppRoot                              = Join-Path $ReportRoot 'AccessPathMap'
                        ResolveObjectIdsOutsidePrivilegedEAM = $false
                    }
                },
                [ordered]@{
                    Name       = 'PrivilegedAssets'
                    Percent    = 72
                    Command    = 'New-EntraOpsPrivilegedAssetsData'
                    Parameters = @{
                        RepoRoot                = $AnonymizedRoot
                        ImportPath              = $PrivilegedEamPath
                        AppRoot                 = Join-Path $ReportRoot 'PrivilegedAssets'
                        ConfigFilePath          = Join-Path $AnonymizedRoot 'EntraOpsConfig.json'
                        ResolveRelatedObjectIds = $false
                    }
                }
            )
            foreach ($ReportTask in $ReportTasks) {
                Write-Progress -Id 2 -ParentId 1 -Activity 'Generating reports from anonymized data' `
                    -Status "Generating $($ReportTask.Name)" -PercentComplete $ReportTask.Percent
                Write-Verbose "Generating $($ReportTask.Name) from $PrivilegedEamPath"
                $ReportParameters = $ReportTask.Parameters
                $ReportParameters['Verbose'] = $VerbosePreference -eq 'Continue'
                & $ReportTask.Command @ReportParameters
                $GeneratedReports.Add($ReportTask.Name)
            }
        } else {
            Write-Warning "PrivilegedEAM data was not found below $AnonymizedRoot; PrivilegedEAM reports were skipped."
        }

        $SnapshotPath = Join-Path $AnonymizedRoot 'TenantGovernance/Snapshots'
        $SnapshotManifestPath = Join-Path $SnapshotPath '.SnapshotManifest.json'
        if (Test-Path -LiteralPath $SnapshotManifestPath -PathType Leaf) {
            Write-Progress -Id 2 -ParentId 1 -Activity 'Generating reports from anonymized data' `
                -Status 'Generating ConfigurationAnalyzer' -PercentComplete 80
            Write-Verbose "Generating ConfigurationAnalyzer from $SnapshotPath"
            try {
                New-EntraOpsTenantGovernanceConfigurationAnalyzerData `
                    -RepoRoot $AnonymizedRoot `
                    -ImportPath $SnapshotPath `
                    -AppRoot (Join-Path $ReportRoot 'ConfigurationAnalyzer') `
                    -ResolveGroupMembersForPrivilegedAssets $false `
                    -AllowStaleSnapshot `
                    -Verbose:($VerbosePreference -eq 'Continue')
                $GeneratedReports.Add('ConfigurationAnalyzer')
            } catch {
                Write-Warning "Configuration Analyzer report was skipped: $($_.Exception.Message)"
            }
        } else {
            Write-Verbose "Configuration Analyzer skipped because no anonymized snapshot manifest exists at $SnapshotManifestPath"
        }

        Write-Progress -Id 2 -ParentId 1 -Activity 'Generating reports from anonymized data' `
            -Status 'Report bundle complete' -PercentComplete 100
        Write-Progress -Id 2 -ParentId 1 -Activity 'Generating reports from anonymized data' -Completed
        Write-Verbose "Generated report bundle at $ReportRoot with: $($GeneratedReports -join ', ')"
        return $GeneratedReports.ToArray()
    }

    $SourceRoot = [System.IO.Path]::GetFullPath((Resolve-Path -LiteralPath $SourcePath).Path)
    $DestinationRoot = [System.IO.Path]::GetFullPath($DestinationPath)
    if ([string]::IsNullOrWhiteSpace($ReportDestinationPath)) {
        $ReportDestinationPath = Join-Path $DestinationRoot 'Reports'
    }
    $ReportRoot = [System.IO.Path]::GetFullPath($ReportDestinationPath)
    if ($GenerateReports -and $ReportRoot.Equals($DestinationRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw 'ReportDestinationPath must not be the same as DestinationPath.'
    }
    Write-Verbose "Source export: $SourceRoot"
    Write-Verbose "Destination: $DestinationRoot"
    if ($GenerateReports) {
        Write-Verbose "Report destination: $ReportRoot"
    }
    $SourcePrefix = $SourceRoot.TrimEnd([System.IO.Path]::DirectorySeparatorChar) + [System.IO.Path]::DirectorySeparatorChar
    if ($DestinationRoot -eq $SourceRoot -or $DestinationRoot.StartsWith($SourcePrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw 'DestinationPath must be outside SourcePath.'
    }
    if ($GenerateReports) {
        $ReportPrefix = $ReportRoot.TrimEnd([System.IO.Path]::DirectorySeparatorChar) + [System.IO.Path]::DirectorySeparatorChar
        if ($ReportRoot.Equals($SourceRoot, [System.StringComparison]::OrdinalIgnoreCase) -or
            $ReportRoot.StartsWith($SourcePrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
            throw 'ReportDestinationPath must be outside SourcePath.'
        }
        if ($DestinationRoot.StartsWith($ReportPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
            throw 'ReportDestinationPath must not be a parent of DestinationPath.'
        }
        if ($ReportRoot.StartsWith($DestinationRoot + [System.IO.Path]::DirectorySeparatorChar, [System.StringComparison]::OrdinalIgnoreCase)) {
            $ReportRelativePath = [System.IO.Path]::GetRelativePath($DestinationRoot, $ReportRoot)
            $ReportTopLevelDirectory = $ReportRelativePath.Split([System.IO.Path]::DirectorySeparatorChar)[0]
            if ($ReportTopLevelDirectory -in @('Classification', 'PrivilegedEAM', 'TenantGovernance')) {
                throw 'ReportDestinationPath must not overlap an anonymized export directory.'
            }
        }
    }
    if (Test-Path -LiteralPath $DestinationRoot) {
        throw "DestinationPath already exists: $DestinationRoot"
    }
    if ($GenerateReports -and -not $ReportRoot.StartsWith($DestinationRoot + [System.IO.Path]::DirectorySeparatorChar, [System.StringComparison]::OrdinalIgnoreCase) -and
        (Test-Path -LiteralPath $ReportRoot)) {
        throw "ReportDestinationPath already exists: $ReportRoot"
    }

    $ExportDirectoryNames = @('Classification', 'PrivilegedEAM', 'TenantGovernance')
    $ExportDirectories = @(if ((Split-Path -Leaf $SourceRoot) -in $ExportDirectoryNames) {
            Get-Item -LiteralPath $SourceRoot
        } else {
            $ExportDirectoryNames | ForEach-Object {
                $Candidate = Join-Path $SourceRoot $_
                if (Test-Path -LiteralPath $Candidate -PathType Container) {
                    Get-Item -LiteralPath $Candidate
                }
            }
        })
    if ($ExportDirectories.Count -eq 0) {
        throw "No Classification, PrivilegedEAM, or TenantGovernance directories were found below $SourceRoot."
    }

    $JsonFiles = @($ExportDirectories | ForEach-Object {
            Get-ChildItem -LiteralPath $_.FullName -Recurse -File -Filter '*.json' |
            Where-Object FullName -NotMatch '[/\\]Templates[/\\]'
        } | Sort-Object -Property FullName -Unique)
    if ($JsonFiles.Count -eq 0) {
        throw 'No JSON export files were found.'
    }
    Write-Verbose "Discovered $($JsonFiles.Count) JSON export file(s) in: $($ExportDirectories.Name -join ', ')"

    if ([string]::IsNullOrWhiteSpace($SourceTenantName)) {
        # -SourcePath may point at the export root, or directly at one of its
        # Classification/PrivilegedEAM/TenantGovernance subdirectories (both are supported).
        $ClassificationRoot = if ((Split-Path -Leaf $SourceRoot) -eq 'Classification') {
            $SourceRoot
        } else {
            Join-Path $SourceRoot 'Classification'
        }
        $TenantDirectory = Get-ChildItem -LiteralPath $ClassificationRoot -Directory -ErrorAction SilentlyContinue |
        Where-Object Name -Like '*.onmicrosoft.com' |
        Select-Object -First 1
        if ($TenantDirectory) {
            $SourceTenantName = $TenantDirectory.Name -replace '(?i)\.onmicrosoft\.com$', ''
            Write-Verbose "Detected source tenant name '$SourceTenantName' from $($TenantDirectory.Name)."
        } else {
            Write-Warning 'Source tenant name could not be auto-detected (no Classification/<tenant>.onmicrosoft.com directory was found). The real source tenant name and initial domain may remain unredacted in the output unless -SourceTenantName is supplied.'
        }
    }
    $script:ConvertEntraOpsExportToSampleDataSourceTenantName = $SourceTenantName
    $script:ConvertEntraOpsExportToSampleDataTenantName = $TenantName
    $script:ConvertEntraOpsExportToSampleDataTenantInitialDomain = $TenantInitialDomain
    Write-Verbose "Target tenant: $TenantName ($TenantInitialDomain)"

    # Each export file is parsed from disk once here (phase 1) and the parsed document is
    # reused by phases 2 and 3 below, instead of being re-read and re-parsed on every phase.
    $FileNumber = 0
    $ParsedFiles = @(foreach ($JsonFile in $JsonFiles) {
            $FileNumber++
            $RelativePath = [System.IO.Path]::GetRelativePath($SourceRoot, $JsonFile.FullName)
            Write-AnonymizationProgress -Phase 'Discovering primary identities' -PhaseNumber 1 `
                -CurrentItem $FileNumber -TotalItems $JsonFiles.Count -CurrentFile $RelativePath
            Write-Verbose "[1/3] Reading primary identities from $RelativePath"
            $Document = Read-JsonDocument -Path $JsonFile.FullName
            Register-PrimaryIdentityNames -Node $Document
            [pscustomobject]@{
                RelativePath = $RelativePath
                Document     = $Document
            }
        })
    $FileNumber = 0
    foreach ($ParsedFile in $ParsedFiles) {
        $FileNumber++
        Write-AnonymizationProgress -Phase 'Discovering related names and resources' -PhaseNumber 2 `
            -CurrentItem $FileNumber -TotalItems $JsonFiles.Count -CurrentFile $ParsedFile.RelativePath
        Write-Verbose "[2/3] Discovering related names and resources from $($ParsedFile.RelativePath)"
        Register-RelatedNamesAndResources -Node $ParsedFile.Document
    }
    Write-Verbose "Mappings discovered: $($script:NameAliases.Count) names, $($script:ResourceValueAliases.Count) resources."
    $EmbeddedAliasValues = @(
        [System.Collections.Generic.HashSet[string]]::new(
            [string[]](@($script:NameAliases.Keys) + @($script:ResourceValueAliases.Keys) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }),
            [System.StringComparer]::OrdinalIgnoreCase
        ) | Sort-Object -Property Length -Descending
    )
    if ($EmbeddedAliasValues.Count -gt 0) {
        $EmbeddedAliasExpression = ($EmbeddedAliasValues | ForEach-Object {
                '(?<![a-z0-9])' + [regex]::Escape($_) + '(?![a-z0-9])'
            }) -join '|'
        $script:EmbeddedAliasPattern = [regex]::new(
            $EmbeddedAliasExpression,
            [System.Text.RegularExpressions.RegexOptions]::IgnoreCase -bor [System.Text.RegularExpressions.RegexOptions]::CultureInvariant
        )
    }

    $GeneratedReports = @()
    if ($PSCmdlet.ShouldProcess($DestinationRoot, "Create anonymized copy of $($JsonFiles.Count) JSON files")) {
        $FileNumber = 0
        foreach ($ParsedFile in $ParsedFiles) {
            $FileNumber++
            Write-AnonymizationProgress -Phase 'Writing anonymized export' -PhaseNumber 3 `
                -CurrentItem $FileNumber -TotalItems $JsonFiles.Count -CurrentFile $ParsedFile.RelativePath
            $ConvertedPathSegments = $ParsedFile.RelativePath.Split([System.IO.Path]::DirectorySeparatorChar) | ForEach-Object {
                Convert-AnonymizedString -Value $_
            }
            $TargetPath = Join-Path $DestinationRoot ($ConvertedPathSegments -join [System.IO.Path]::DirectorySeparatorChar)
            $RelativeTargetPath = [System.IO.Path]::GetRelativePath($DestinationRoot, $TargetPath)
            Write-Verbose "[3/3] Writing $($ParsedFile.RelativePath) -> $RelativeTargetPath"
            $TargetDirectory = Split-Path -Parent $TargetPath
            $null = [System.IO.Directory]::CreateDirectory($TargetDirectory)

            $ConvertedDocument = Convert-AnonymizedNode -Node $ParsedFile.Document
            # Bind via -InputObject (not the pipeline) so a top-level array is serialized
            # as an array of any length, matching the source file's shape.
            $Json = ConvertTo-Json -InputObject $ConvertedDocument -Depth 100
            [System.IO.File]::WriteAllText($TargetPath, $Json + [Environment]::NewLine, [System.Text.UTF8Encoding]::new($false))
        }

        if ($GenerateReports) {
            $GeneratedReports = @(New-AnonymizedReportBundle -AnonymizedRoot $DestinationRoot -ReportRoot $ReportRoot)
        }

        $ManifestReportPath = if ($GenerateReports -and
            $ReportRoot.StartsWith($DestinationRoot + [System.IO.Path]::DirectorySeparatorChar, [System.StringComparison]::OrdinalIgnoreCase)) {
            [System.IO.Path]::GetRelativePath($DestinationRoot, $ReportRoot)
        }

        $Manifest = [ordered]@{
            formatVersion       = 1
            generatedAtUtc      = [DateTime]::UtcNow.ToString('o')
            sourceFiles         = $JsonFiles.Count
            anonymizedGuids     = $script:GuidAliases.Count
            anonymizedNames     = $script:NameAliases.Count
            anonymizedResources = $script:ResourceValueAliases.Count
            tenantName          = $TenantName
            tenantInitialDomain = $TenantInitialDomain
            deterministic       = $PSBoundParameters.ContainsKey('Seed')
            reportPath          = $ManifestReportPath
            generatedReports    = $GeneratedReports
        }
        $ManifestPath = Join-Path $DestinationRoot 'anonymization-manifest.json'
        [System.IO.File]::WriteAllText($ManifestPath, ($Manifest | ConvertTo-Json) + [Environment]::NewLine, [System.Text.UTF8Encoding]::new($false))
        Write-Verbose "Wrote anonymization manifest to $ManifestPath"
    }

    if ($null -ne $script:GuidHmac) {
        $script:GuidHmac.Dispose()
    }
    Write-Progress -Id 1 -Activity 'Anonymizing EntraOps export' -Completed
    Write-Verbose "Anonymization complete: $($script:GuidAliases.Count) GUIDs, $($script:NameAliases.Count) names, and $($script:ResourceValueAliases.Count) resources anonymized."

    [pscustomobject]@{
        DestinationPath     = $DestinationRoot
        SourceFiles         = $JsonFiles.Count
        AnonymizedGuids     = $script:GuidAliases.Count
        AnonymizedNames     = $script:NameAliases.Count
        AnonymizedResources = $script:ResourceValueAliases.Count
        TenantName          = $TenantName
        TenantInitialDomain = $TenantInitialDomain
        ReportPath          = if ($GenerateReports) { $ReportRoot } else { $null }
        GeneratedReports    = @($GeneratedReports)
    }
}