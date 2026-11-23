function Get-EntraOpsFindingSetting {
    <#
    .SYNOPSIS
        Reads the settings of the finding rules from EntraOpsConfig.json.
    .DESCRIPTION
        Returns the rules to exclude and the setting values of the rule parameters (see the Parameters of
        Get-EntraOpsFindingRule) from the Findings section of EntraOpsConfig.json:
          * ExcludedRules: rule IDs (EO.4008) or <Area>.<Key> (PrivilegedAssets.pawMissing), the one place
            to exclude rules.
          * ControlPlaneActivationMaxHours, EligibleAssignmentMaxDays, EmergencyAccessAccounts: setting values.
        Rule parameters with Scope Root are read from the root of EntraOpsConfig.json instead (ManagingTenantId and
        ManagingTenantName of Tenant Governance, for EO.4010 and EO.4011); a parameter with Format Guid must be a
        GUID, else its rules get the status Error.
          * ExceptionsFilePath (default ./Classification/FindingExceptions.json, relative to the folder of
            EntraOpsConfig.json) and ExceptionMaxDays (default 180, 0 for no limit): the Finding Exceptions
            File with the dismissed and risk-accepted findings (Exceptions, see
            Read-EntraOpsFindingExceptionFile). It is read also without EntraOpsConfig.json.
        ConfigurationAnalyzer.PimRequestFlowExcludedRiskFlags and .AccessPackageFlowExcludedRiskFlags (EntraOps
        1.1.0) are deprecated aliases: their risk flags are excluded as PimRequestFlow.<Key> and
        AccessPackageFlow.<Key>.

        The settings are checked against the catalog, with a warning for each problem:
          * A setting value must have the type of the default of its parameter (a number, a list of values ...).
            An invalid value is not used: Errors holds its message, and the rules of the parameter get the
            status Error with this message.
          * Unknown Findings settings and excluded rules that match no rule are listed with the valid values.
        A missing or unreadable file returns no exclusions and no setting values, so the rules use their
        defaults.
    .PARAMETER ConfigFilePath
        Path to EntraOpsConfig.json.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string]$ConfigFilePath
    )

    $Setting = [pscustomobject]@{ ExcludedRules = @(); Values = @{}; Errors = @{}; ExceptionsFilePath = './Classification/FindingExceptions.json'; ExceptionMaxDays = 180; Exceptions = @() }
    if ([string]::IsNullOrWhiteSpace($ConfigFilePath)) { return $Setting }
    $Config = $null
    if (Test-Path -LiteralPath $ConfigFilePath -PathType Leaf) {
        try {
            $Config = Get-Content -LiteralPath $ConfigFilePath -Raw | ConvertFrom-Json
        } catch {
            Write-Warning "The finding settings of $ConfigFilePath could not be read, the rules use their defaults: $($_.Exception.Message)"
        }
    }
    if ($null -eq $Config) {
        Add-EntraOpsFindingException -Setting $Setting -ConfigFilePath $ConfigFilePath
        return $Setting
    }

    $Catalog = Get-EntraOpsFindingCatalog
    $Defaults = @{}
    $RootParameters = @($Catalog.Catalog.rules.Parameters | Where-Object { $_ -and "$($_.Scope)" -eq 'Root' })
    foreach ($Parameter in @($Catalog.Catalog.rules.Parameters | Where-Object { $_ -and "$($_.Scope)" -ne 'Root' })) { if (-not $Defaults.ContainsKey($Parameter.Setting)) { $Defaults[$Parameter.Setting] = $Parameter.Default } }

    $Excluded = [System.Collections.Generic.List[string]]::new()
    $Findings = $Config.PSObject.Properties['Findings']
    if ($null -ne $Findings -and $null -ne $Findings.Value) {
        $Rules = @(@($Findings.Value.ExcludedRules) | Where-Object { -not [string]::IsNullOrWhiteSpace("$_") } | ForEach-Object { "$_".Trim() })
        foreach ($Rule in (Resolve-EntraOpsFindingExclusion -ExcludeRule $Rules -Source 'Findings.ExcludedRules')) { $Excluded.Add($Rule) }

        $Unknown = [System.Collections.Generic.List[string]]::new()
        foreach ($Property in $Findings.Value.PSObject.Properties) {
            if ($Property.Name -eq 'ExcludedRules') { continue }
            if ($Property.Name -eq 'ExceptionsFilePath') {
                if ($Property.Value -is [string] -and -not [string]::IsNullOrWhiteSpace($Property.Value)) { $Setting.ExceptionsFilePath = $Property.Value.Trim() }
                elseif ($null -ne $Property.Value) { Write-Warning "Findings.ExceptionsFilePath must be a path, but is '$($Property.Value | ConvertTo-Json -Compress)'. The default $($Setting.ExceptionsFilePath) is used." }
                continue
            }
            if ($Property.Name -eq 'ExceptionMaxDays') {
                $Checked = ConvertTo-EntraOpsFindingSettingValue -Name $Property.Name -Value $Property.Value -Default 0
                if ($Checked.Error -or $Checked.Value -lt 0) { Write-Warning "Findings.ExceptionMaxDays must be a number of days (0 for no limit), but is '$($Property.Value)'. The default $($Setting.ExceptionMaxDays) is used." }
                else { $Setting.ExceptionMaxDays = [int]$Checked.Value }
                continue
            }
            if (-not $Defaults.ContainsKey($Property.Name)) { $Unknown.Add($Property.Name); continue }
            if ($null -eq $Property.Value) { continue }
            $Checked = ConvertTo-EntraOpsFindingSettingValue -Name $Property.Name -Value $Property.Value -Default $Defaults[$Property.Name]
            if ($Checked.Error) {
                Write-Warning "$($Checked.Error). The finding rules that use it are not evaluated (status Error)."
                $Setting.Errors[$Property.Name] = $Checked.Error
            } else {
                $Setting.Values[$Property.Name] = $Checked.Value
            }
        }
        if ($Unknown.Count -gt 0) {
            Write-Warning "Unknown Findings setting(s) in ${ConfigFilePath}: $($Unknown -join ', '). Valid settings: $($Catalog.SettingNames -join ', ')."
        }
    }

    # Deprecated (EntraOps 1.1.0): the risk flags of the flow reports, now Findings.ExcludedRules.
    $Analyzer = $Config.PSObject.Properties['ConfigurationAnalyzer']
    if ($null -ne $Analyzer -and $null -ne $Analyzer.Value) {
        foreach ($Alias in @(@{ Name = 'PimRequestFlowExcludedRiskFlags'; Area = 'PimRequestFlow' }, @{ Name = 'AccessPackageFlowExcludedRiskFlags'; Area = 'AccessPackageFlow' })) {
            $Rules = @(@($Analyzer.Value.($Alias.Name)) | Where-Object { $_ -is [string] -and $_ } | ForEach-Object { "$($Alias.Area).$_" })
            if ($Rules.Count -eq 0) { continue }
            Write-Warning "ConfigurationAnalyzer.$($Alias.Name) is deprecated. Exclude the rules in Findings.ExcludedRules instead: $($Rules -join ', ')."
            foreach ($Rule in (Resolve-EntraOpsFindingExclusion -ExcludeRule $Rules -Source "ConfigurationAnalyzer.$($Alias.Name)")) { $Excluded.Add($Rule) }
        }
    }
    # Settings of the whole EntraOpsConfig.json that rules use (Scope Root), for example ManagingTenantId.
    foreach ($Parameter in $RootParameters) {
        if ($Setting.Values.ContainsKey($Parameter.Setting) -or $Setting.Errors.ContainsKey($Parameter.Setting)) { continue }
        $Property = $Config.PSObject.Properties[$Parameter.Setting]
        if ($null -eq $Property -or $null -eq $Property.Value -or [string]::IsNullOrWhiteSpace("$($Property.Value)")) { continue }
        if ($Property.Value -isnot [string]) {
            $Setting.Errors[$Parameter.Setting] = "$($Parameter.Setting) of EntraOpsConfig.json must be text, but is '$($Property.Value | ConvertTo-Json -Compress)'"
            Write-Warning "$($Setting.Errors[$Parameter.Setting]). The finding rules that use it are not evaluated (status Error)."
            continue
        }
        $Value = $Property.Value.Trim()
        $Parsed = [guid]::Empty
        if ("$($Parameter.Format)" -eq 'Guid' -and -not [guid]::TryParse($Value, [ref]$Parsed)) {
            $Setting.Errors[$Parameter.Setting] = "$($Parameter.Setting) of EntraOpsConfig.json must be a tenant ID (GUID), but is '$Value'"
            Write-Warning "$($Setting.Errors[$Parameter.Setting]). The finding rules that use it are not evaluated (status Error)."
            continue
        }
        $Setting.Values[$Parameter.Setting] = $Value
    }
    $Setting.ExcludedRules = @($Excluded | Select-Object -Unique)
    Add-EntraOpsFindingException -Setting $Setting -ConfigFilePath $ConfigFilePath
    $Setting
}

function Add-EntraOpsFindingException {
    <#
    .SYNOPSIS
        Reads the Finding Exceptions File of the settings, relative to the folder of EntraOpsConfig.json.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [object]$Setting,

        [Parameter(Mandatory = $true)]
        [string]$ConfigFilePath
    )

    $RootFolder = Split-Path -Parent $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($ConfigFilePath)
    $Setting.Exceptions = @(Read-EntraOpsFindingExceptionFile -FilePath $Setting.ExceptionsFilePath -RootFolder $RootFolder -MaxDays $Setting.ExceptionMaxDays)
}

function ConvertTo-EntraOpsFindingSettingValue {
    <#
    .SYNOPSIS
        Checks a Findings setting value against the type of the default of its rule parameter.
    .DESCRIPTION
        Returns the value to use (Value) or the problem (Error):
          * Number default: a number, or a text that is a number.
          * List default: a list of texts, or a single text.
          * Text or true/false default: a value of the same type.
    .PARAMETER Name
        Name of the setting (Findings.<Name>).
    .PARAMETER Value
        The value of EntraOpsConfig.json.
    .PARAMETER Default
        The default of the rule parameter.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]$Value,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]$Default
    )

    $IsNumber = { param($Item) $Item -is [int] -or $Item -is [long] -or $Item -is [double] -or $Item -is [decimal] }
    $Text = if ($Value -is [array]) { "[$(@($Value) -join ', ')]" } else { "$Value" }
    if (& $IsNumber $Default) {
        if (& $IsNumber $Value) { return [pscustomobject]@{ Value = $Value; Error = $null } }
        $Number = 0.0
        if ($Value -is [string] -and [double]::TryParse($Value, [System.Globalization.NumberStyles]::Float, [cultureinfo]::InvariantCulture, [ref]$Number)) {
            return [pscustomobject]@{ Value = $(if ($Number -eq [Math]::Floor($Number) -and [Math]::Abs($Number) -le [int]::MaxValue) { [int]$Number } else { $Number }); Error = $null }
        }
        return [pscustomobject]@{ Value = $null; Error = "Findings.$Name must be a number, but is '$Text'" }
    }
    if ($Default -is [array]) {
        $Items = @($Value)
        if (@($Items | Where-Object { $null -ne $_ -and $_ -isnot [string] -and -not (& $IsNumber $_) }).Count -eq 0) { return [pscustomobject]@{ Value = @($Items | Where-Object { $null -ne $_ } | ForEach-Object { "$_" }); Error = $null } }
        return [pscustomobject]@{ Value = $null; Error = "Findings.$Name must be a list of values, but is '$Text'" }
    }
    if ($Default -is [bool]) {
        if ($Value -is [bool]) { return [pscustomobject]@{ Value = $Value; Error = $null } }
        return [pscustomobject]@{ Value = $null; Error = "Findings.$Name must be true or false, but is '$Text'" }
    }
    if ($Default -is [string] -and $Value -isnot [string]) {
        return [pscustomobject]@{ Value = $null; Error = "Findings.$Name must be a text, but is '$Text'" }
    }
    [pscustomobject]@{ Value = $Value; Error = $null }
}

function Resolve-EntraOpsFindingExclusion {
    <#
    .SYNOPSIS
        Returns the rules to exclude and warns about entries that match no finding rule.
    .DESCRIPTION
        An entry is a rule ID (EO.4008) or <Area>.<Key> (PrivilegedAssets.pawMissing), compared
        case-insensitively like the exclusion itself (Invoke-EntraOpsFindingRuleSet). Entries that match no
        rule are returned as well (they exclude nothing), with a warning that lists the valid rule IDs.
    .PARAMETER ExcludeRule
        The entries.
    .PARAMETER Source
        Where the entries come from, for the warning (for example Findings.ExcludedRules).
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param (
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [AllowEmptyCollection()]
        [string[]]$ExcludeRule = @(),

        [Parameter(Mandatory = $true)]
        [string]$Source
    )

    $Entries = @($ExcludeRule | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    if ($Entries.Count -eq 0) { return }
    $Rules = @(Get-EntraOpsFindingRule)
    $Known = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($Rule in $Rules) { $null = $Known.Add($Rule.Id); $null = $Known.Add("$($Rule.Area).$($Rule.Key)") }
    $Unknown = @($Entries | Where-Object { -not $Known.Contains($_) })
    if ($Unknown.Count -gt 0) {
        Write-Warning "$Source`: '$($Unknown -join "', '")' matches no finding rule and excludes nothing. Valid values are the rule IDs ($($Rules.Id -join ', ')) or <Area>.<Key> (for example PrivilegedAssets.pawMissing); see Get-EntraOpsFindingRule."
    }
    $Entries
}
