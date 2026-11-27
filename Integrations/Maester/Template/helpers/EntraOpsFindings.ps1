function Skip-EntraOpsPackTest {
    <#
    .SYNOPSIS
    Skips the calling test because the EntraOps finding results cannot be used, and tells it once per run in the console as well.

    .DESCRIPTION
    All tests of the pack skip for the same reason: the console of Invoke-Maester shows it once (a warning), the
    report shows it with each test.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string] $Reason
    )

    Write-EntraOpsPackWarning "All tests of the EntraOps Maester Pack are skipped: $Reason"
    Add-MtTestResultDetail -SkippedBecause Custom -SkippedCustomReason $Reason
}

function Write-EntraOpsPackWarning {
    <#
    .SYNOPSIS
    Writes a warning once per run of Maester (the tests of a pack share the module of the pack).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string] $Message
    )

    if ($null -eq $script:EntraOpsPackWarnings) { $script:EntraOpsPackWarnings = [System.Collections.Generic.HashSet[string]]::new() }
    if ($script:EntraOpsPackWarnings.Add($Message)) { Write-Warning $Message }
}

function Resolve-EntraOpsPackPath {
    <#
    .SYNOPSIS
    The full path of a path from maester-config.json: ~ is the home folder, a relative path is relative to the current folder.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [string] $Path
    )

    $value = $Path.Trim()
    if ($value -match '^~(?=$|[\\/])' -and $HOME) { $value = $HOME + $value.Substring(1) }
    [System.IO.Path]::GetFullPath($value, (Get-Location -PSProvider FileSystem).ProviderPath)
}

function Get-EntraOpsPackNotFoundAdvice {
    <#
    .SYNOPSIS
    An install hint, appended to the guidance when no findings.json is found, if the EntraOps module is not installed on this machine; otherwise nothing.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param()

    if ($null -eq $script:EntraOpsPackHasModule) {
        $script:EntraOpsPackHasModule = [bool](Get-Module -ListAvailable -Name 'EntraOps' | Select-Object -First 1)
    }
    if ($script:EntraOpsPackHasModule) { return '' }
    ' The EntraOps module is not installed on this machine: install it with Install-PSResource -Name EntraOps -Repository PSGallery -Scope CurrentUser, then run Invoke-EntraOpsAssessment (it saves findings.json to <home>/EntraOps/Reports/Findings/data, where the pack finds it without a setting).'
}

function Get-EntraOpsPackFindingSet {
    <#
    .SYNOPSIS
    Reads the EntraOps finding results (findings.json) that the tests of this pack report.

    .DESCRIPTION
    The results are written by EntraOps (Invoke-EntraOpsAssessment or New-EntraOpsReportingData) to
    Reports/Findings/data of the EntraOps working folder, which the EntraOps reporting pipelines publish in
    the EntraOps-Reporting artifact (Findings/data). The setting EntraOps.FindingsPath points to
    findings.json or to the folder that holds it (~ is the home folder, a relative path is relative to the
    current folder). Without the setting, the first of these folders that has findings.json is used:
    <ENTRAOPS_ROOT>/Reports/Findings/data, <home>/EntraOps/Reports/Findings/data (the working folder of a
    module-only installation) and ./Reports/Findings/data. The file is read once and reused by all tests of the
    run while it does not change.

    Skips the calling test, with the reason and what to do, when the file is missing, cannot be read (for example
    cut off), is no EntraOps finding results file, has an unknown schema, belongs to another tenant than the
    Microsoft Graph connection, is older than EntraOps.MaxFindingsAgeDays (default 7 days, 0 turns the check
    off) or has no readable date to check its age, and when that setting is not a number of days. The console of Invoke-Maester shows the reason once.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param()

    $howTo = 'run Invoke-EntraOpsAssessment (without EntraOps in place) or New-EntraOpsReportingData (in your EntraOps repository), which save findings.json to Reports/Findings/data of the EntraOps working folder'
    $setting = [string](Get-MtSetting -Name 'EntraOps.FindingsPath' -Default '')
    if ([string]::IsNullOrWhiteSpace($setting)) {
        # The default locations of EntraOps: its working folder (ENTRAOPS_ROOT, or <home>/EntraOps for a module-only
        # installation) and the current folder (a clone of the EntraOps repository).
        $defaultFolders = @(
            if (-not [string]::IsNullOrWhiteSpace($env:ENTRAOPS_ROOT)) { Join-Path -Path $env:ENTRAOPS_ROOT -ChildPath 'Reports/Findings/data' }
            if (-not [string]::IsNullOrWhiteSpace($HOME)) { Join-Path -Path $HOME -ChildPath 'EntraOps/Reports/Findings/data' }
            Join-Path -Path (Get-Location -PSProvider FileSystem).ProviderPath -ChildPath 'Reports/Findings/data'
        )
        $folder = @($defaultFolders | Where-Object { Test-Path -LiteralPath (Join-Path -Path $_ -ChildPath 'findings.json') -PathType Leaf }) | Select-Object -First 1
        if (-not $folder) {
            Skip-EntraOpsPackTest "No EntraOps finding results (findings.json) were found in $($defaultFolders -join ', '). To create them, $howTo. For results in another folder, for example the Findings/data folder of the EntraOps-Reporting artifact, set EntraOps.FindingsPath in the GlobalSettings of maester-config.json to that folder.$(Get-EntraOpsPackNotFoundAdvice)"
            return
        }
        $path = Join-Path -Path $folder -ChildPath 'findings.json'
        $where = $path
    } else {
        $path = Resolve-EntraOpsPackPath $setting
        # The setting as it is written, when it is not the full path (relative, or with ~).
        $origin = if ($setting.Trim() -ne $path) { " (EntraOps.FindingsPath '$($setting.Trim())', from the current folder $((Get-Location -PSProvider FileSystem).ProviderPath))" } else { ' (EntraOps.FindingsPath)' }
        $where = "$path$origin"
        if (Test-Path -LiteralPath $path -PathType Container) {
            $folder = $path
            $path = Join-Path -Path $folder -ChildPath 'findings.json'
            $where = "$path$origin"
            if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
                Skip-EntraOpsPackTest "No EntraOps finding results were found in $($folder)$($origin): the folder has no findings.json. Set EntraOps.FindingsPath in maester-config.json to the Reports/Findings/data folder of the EntraOps working folder or the Findings/data folder of the EntraOps-Reporting artifact, or $howTo."
                return
            }
        } elseif (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            Skip-EntraOpsPackTest "No EntraOps finding results were found at $($where): the path does not exist. Correct EntraOps.FindingsPath in maester-config.json (findings.json or its folder), or $howTo."
            return
        }
    }

    $file = Get-Item -LiteralPath $path
    $cacheKey = '{0}|{1}|{2}' -f $file.FullName, $file.LastWriteTimeUtc.Ticks, $file.Length
    if ($script:EntraOpsPackFindingCache -and $script:EntraOpsPackFindingCache.Key -eq $cacheKey) {
        $findingSet = $script:EntraOpsPackFindingCache.Value
    } else {
        try {
            $text = Get-Content -LiteralPath $file.FullName -Raw -Encoding UTF8 -ErrorAction Stop
            $findingSet = if ([string]::IsNullOrWhiteSpace($text)) { $null } else { $text | ConvertFrom-Json -ErrorAction Stop }
        } catch {
            # Mostly a file that is cut off, for example while EntraOps writes it or by an incomplete download.
            $why = (([string]$_.Exception.Message) -split '\r?\n' | Where-Object { $_.Trim() } | Select-Object -First 1)
            Skip-EntraOpsPackTest "The EntraOps finding results at $path could not be read: $why The file may be incomplete, for example cut off while it was written or downloaded. Create it again: $howTo."
            return
        }
        $script:EntraOpsPackFindingCache = @{ Key = $cacheKey; Value = $findingSet }
    }

    if ($findingSet -isnot [System.Management.Automation.PSCustomObject] -or $null -eq $findingSet.PSObject.Properties['SchemaVersion'] -or $null -eq $findingSet.PSObject.Properties['Rules']) {
        $what = if ($null -eq $findingSet) { 'is empty' } else { 'is no EntraOps finding results file (it has no SchemaVersion and Rules)' }
        Skip-EntraOpsPackTest "The file $where $what. EntraOps.FindingsPath must point to the findings.json that EntraOps writes to Reports/Findings/data, or to its folder. To create it, $howTo."
        return
    }
    if ("$($findingSet.SchemaVersion)" -notmatch '^1\.') {
        Skip-EntraOpsPackTest "The EntraOps finding results at $path have schema version '$($findingSet.SchemaVersion)', which this version of the pack does not read. Update the EntraOps Maester Pack."
        return
    }

    $context = Get-MgContext
    if ($context -and $context.TenantId -and $findingSet.TenantId -and $findingSet.TenantId -ne $context.TenantId) {
        Skip-EntraOpsPackTest "The EntraOps finding results at $path are for tenant $($findingSet.TenantId), but Maester is connected to tenant $($context.TenantId)."
        return
    }
    if ($context -and $context.TenantId -and -not "$($findingSet.TenantId)") {
        Write-EntraOpsPackWarning "EntraOps Maester Pack: the EntraOps finding results at $path have no tenant ID, so the pack cannot check that they belong to tenant $($context.TenantId). Set TenantId in EntraOpsConfig.json and create the results again."
    }

    $maxAgeSetting = Get-MtSetting -Name 'EntraOps.MaxFindingsAgeDays' -Default 7
    $maxAgeDays = 0
    if (-not [int]::TryParse("$maxAgeSetting", [System.Globalization.NumberStyles]::Integer, [cultureinfo]::InvariantCulture, [ref]$maxAgeDays) -or $maxAgeDays -lt 0) {
        Skip-EntraOpsPackTest "The setting EntraOps.MaxFindingsAgeDays in maester-config.json is '$maxAgeSetting', not a number of days. Set it to the maximum age of the EntraOps finding results in days, or to 0 to turn the check off."
        return
    }
    # ConvertFrom-Json reads the ISO date as a DateTime already; text is parsed invariantly, never in the current culture.
    $generatedAt = [datetime]::MinValue
    $hasDate = if ($findingSet.GeneratedAt -is [datetime]) { $generatedAt = $findingSet.GeneratedAt; $true }
    else {
        [datetime]::TryParse([string]$findingSet.GeneratedAt, [cultureinfo]::InvariantCulture,
            [System.Globalization.DateTimeStyles]::AdjustToUniversal -bor [System.Globalization.DateTimeStyles]::AssumeUniversal, [ref]$generatedAt)
    }
    if ($maxAgeDays -gt 0 -and -not $hasDate) {
        Skip-EntraOpsPackTest "The EntraOps finding results at $path have no readable date (GeneratedAt '$($findingSet.GeneratedAt)'), so their age cannot be checked. Create them again: $howTo. To use them anyway, set EntraOps.MaxFindingsAgeDays in maester-config.json to 0."
        return
    }
    if ($maxAgeDays -gt 0 -and $hasDate -and $generatedAt.ToUniversalTime() -lt [datetime]::UtcNow.AddDays(-$maxAgeDays)) {
        Skip-EntraOpsPackTest "The EntraOps finding results at $path were written on $($generatedAt.ToString('yyyy-MM-dd')), more than $maxAgeDays days ago. Run Invoke-EntraOpsAssessment or New-EntraOpsReportingData again, or raise the EntraOps.MaxFindingsAgeDays setting."
        return
    }

    $reports = Get-EntraOpsPackReportBase -FindingsFile $file.FullName
    if ($reports.Note) { Write-EntraOpsPackWarning "EntraOps Maester Pack: $($reports.Note)" }
    # Links to a folder open on this computer only.
    if ($reports.Base -and $reports.Base -notmatch '^https?://') { Write-EntraOpsPackWarning "EntraOps Maester Pack: the results link to the EntraOps reports in the local folder $($reports.Base), so the links open on this computer only and show its path. For a Maester report that others open, set EntraOps.ReportsPath in maester-config.json to the URL of the published EntraOps reports, or to None." }
    $findingSet | Add-Member -NotePropertyName GeneratedText -NotePropertyValue $(if ($hasDate) { $generatedAt.ToUniversalTime().ToString('yyyy-MM-dd HH:mm', [cultureinfo]::InvariantCulture) + ' UTC' } else { [string]$findingSet.GeneratedAt }) -Force
    $findingSet | Add-Member -NotePropertyName GeneratedAtUtc -NotePropertyValue $(if ($hasDate) { $generatedAt.ToUniversalTime() } else { $null }) -Force
    $findingSet | Add-Member -NotePropertyName ReportBase -NotePropertyValue $reports.Base -Force
    $findingSet | Add-Member -NotePropertyName ReportsNote -NotePropertyValue $reports.Note -Force
    $findingSet
}

function Get-EntraOpsPackReportBase {
    <#
    .SYNOPSIS
    The location of the EntraOps reports that the results link to (Base, ending with a slash, or nothing), and what is wrong with the setting EntraOps.ReportsPath (Note).

    .DESCRIPTION
    The setting EntraOps.ReportsPath is the URL where the EntraOps reports are published (https://...) or their
    folder (the folder that holds PrivilegedAssets, TierBreachAnalyzer and the other reports); None turns the links
    off. Without the setting, the reports next to the results are used: EntraOps writes findings.json to
    Reports/Findings/data, and the EntraOps-Reporting artifact has it in Findings/data, so the reports are two
    folders above it. Without the Privileged Assets report there, the results have no report links. A folder in
    the setting without the Privileged Assets report gives no links either, and a Note that says so: its links
    would not open.

    A folder becomes a path link that starts with a slash (/C:/... on Windows): the Maester report removes file:
    links, but keeps these, and the browser opens them as local files of the report that is opened from disk.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [string] $FindingsFile
    )

    $setting = [string](Get-MtSetting -Name 'EntraOps.ReportsPath' -Default '')
    if ($setting -match '^\s*none\s*$') { return [pscustomobject]@{ Base = $null; Note = $null } }
    if ($setting -match '^\s*https?://') { return [pscustomobject]@{ Base = $setting.Trim().TrimEnd('/') + '/'; Note = $null } }
    if ([string]::IsNullOrWhiteSpace($setting)) {
        $folder = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $FindingsFile))
        if (-not $folder -or -not (Test-Path -LiteralPath (Join-Path -Path $folder -ChildPath 'PrivilegedAssets/index.html') -PathType Leaf)) { return [pscustomobject]@{ Base = $null; Note = $null } }
    } else {
        $folder = Resolve-EntraOpsPackPath $setting
        if (-not (Test-Path -LiteralPath (Join-Path -Path $folder -ChildPath 'PrivilegedAssets/index.html') -PathType Leaf)) {
            return [pscustomobject]@{
                Base = $null
                Note = "EntraOps.ReportsPath in maester-config.json is $folder, which has no EntraOps reports (PrivilegedAssets/index.html), so the results link to no EntraOps report. Set it to the Reports folder of the EntraOps working folder or of the EntraOps-Reporting artifact, to the URL of the published reports, or to None."
            }
        }
    }
    $segments = @(([System.IO.Path]::GetFullPath($folder) -replace '\\', '/').TrimEnd('/').Split('/') | ForEach-Object {
            # The drive (C:) stays as it is; every other part is encoded, for example spaces.
            if ($_ -match '^[A-Za-z]:$') { $_ } else { [uri]::EscapeDataString($_) }
        })
    $path = $segments -join '/'
    if (-not $path.StartsWith('/')) { $path = "/$path" }
    [pscustomobject]@{ Base = "$path/"; Note = $null }
}

function Test-EntraOpsPackMaesterCommand {
    <#
    .SYNOPSIS
    True when the Maester module of the run exports the command (newer Maester versions have more).

    .DESCRIPTION
    Looks at the loaded module only: Get-Command would import Maester, which replaces functions of the same name.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [string] $Name
    )

    [bool](@(Get-Module -Name Maester) | Where-Object { $_.ExportedCommands.ContainsKey($Name) })
}

function Get-EntraOpsPackPortalUrl {
    <#
    .SYNOPSIS
    The Microsoft Entra admin center of the cloud of the Microsoft Graph connection (Global without one), or nothing for an unknown cloud.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param()

    $context = Get-MgContext
    $environment = if ($context -and $context.Environment) { [string]$context.Environment } else { 'Global' }
    if ($environment -notin 'Global', 'USGov', 'USGovDoD', 'China') { return $null }
    if (Test-EntraOpsPackMaesterCommand -Name Get-MtAdminPortalUrl) {
        $url = [string](Get-MtAdminPortalUrl -Environment $environment -Portal Entra)
        if ($url) { return $url }
    }
    if ($environment -eq 'Global') { 'https://entra.microsoft.com/' } else { $null }
}

function Get-EntraOpsPackIcon {
    <#
    .SYNOPSIS
    The icon of a tier or an object type.

    .DESCRIPTION
    The tiers use the icons of the Maester tests that read the EntraOps classification
    (Get-MtXspmPrivilegedClassificationIcon of Maester, which a pack cannot call): Control Plane, Management Plane
    and Workload Plane, and the information icon for the others. Unclassified objects get a question mark: their tier
    is unknown and needs a classification.
    #>
    [CmdletBinding(DefaultParameterSetName = 'Tier')]
    [OutputType([string])]
    param(
        [Parameter(Mandatory, ParameterSetName = 'Tier')]
        [AllowEmptyString()]
        [string] $TierKey,

        [Parameter(Mandatory, ParameterSetName = 'Type')]
        [AllowEmptyString()]
        [string] $TypeKey
    )

    if ($PSCmdlet.ParameterSetName -eq 'Tier') {
        switch ($TierKey) {
            'ControlPlane' { '🔐' }
            'ManagementPlane' { '☁️' }
            'WorkloadPlane' { '⚙️' }
            'Unclassified' { '❔' }
            default { 'ℹ️' }
        }
        return
    }
    switch ($TypeKey.ToLowerInvariant()) {
        'user' { '👤' }
        'group' { '👥' }
        'serviceprincipal' { '🤖' }
        'application' { '🧩' }
        'rolesetting' { '⏱️' }
        'accesspackageassignmentpolicy' { '📦' }
        'conditionalaccesspolicy' { '🛡️' }
        'administrativeunit' { '🏢' }
        'roledefinition' { '📜' }
        'tenant' { '🏛️' }
        default { '' }
    }
}

function Get-EntraOpsPackReportLabel {
    <#
    .SYNOPSIS
    The short name of an EntraOps report as the text of a link: "Tier breach", "Assignment 2".
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [string] $Report
    )

    switch ($Report) {
        'Tier Breach Analyzer' { 'Tier breach' }
        'EAM Dashboard assignment' { 'Assignment' }
        'EAM Dashboard' { 'EAM Dashboard' }
        'Access Path Map' { 'Access path' }
        'PIM Request Flow' { 'PIM flow' }
        'Access Package Flow' { 'Package flow' }
        'Conditional Access Analysis' { 'CA analysis' }
        'Configuration Analyzer' { 'Configuration' }
        'Privilege History' { 'History' }
        'Findings view' { 'Findings view' }
        default {
            # Numbered assignments of a custom role: "EAM Dashboard assignment 2".
            if ($Report -match '^EAM Dashboard assignment (\d+)$') { "Assignment $($Matches[1])" } else { $Report }
        }
    }
}

function Get-EntraOpsPackLegend {
    <#
    .SYNOPSIS
    The legend of the icons of the objects in a list: only the tiers and types that it shows.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [AllowEmptyCollection()]
        [object[]] $Object
    )

    $tiers = [ordered]@{ ControlPlane = 'Control Plane'; ManagementPlane = 'Management Plane'; WorkloadPlane = 'Workload Plane'; UserAccess = 'User Access'; Unclassified = 'Unclassified' }
    $types = [ordered]@{ user = 'user'; group = 'group'; serviceprincipal = 'service principal'; application = 'application'; rolesetting = 'PIM role setting'; accesspackageassignmentpolicy = 'access package policy'; conditionalaccesspolicy = 'Conditional Access policy'; administrativeunit = 'administrative unit'; roledefinition = 'role definition'; tenant = 'tenant' }
    $usedTiers = @($Object | ForEach-Object { $_.TierKey } | Where-Object { $_ } | Select-Object -Unique)
    $usedTypes = @($Object | ForEach-Object { $_.TypeKey } | Where-Object { $_ } | Select-Object -Unique)
    $parts = @(
        foreach ($key in $tiers.Keys) { if ($key -in $usedTiers) { "$(Get-EntraOpsPackIcon -TierKey $key) $($tiers[$key])" } }
        foreach ($key in $types.Keys) { if ($key -in $usedTypes) { "$(Get-EntraOpsPackIcon -TypeKey $key) $($types[$key])" } }
    )
    if ($parts.Count) { "_$($parts -join ' · ')_" }
}

function ConvertTo-EntraOpsPackText {
    <#
    .SYNOPSIS
    Text for one line of Markdown, as it is: line breaks, pipes and HTML are escaped, spaces at its ends are kept.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [AllowEmptyString()]
        [string] $Value
    )

    # An escaped @ keeps a user principal name from becoming a mail link.
    $Value -replace '[\r\n]+', ' ' -replace '\|', '\|' -replace '<', '&lt;' -replace '>', '&gt;' -replace '@', '\@'
}

function ConvertTo-EntraOpsPackName {
    <#
    .SYNOPSIS
    A name (of a role, scope, group, permission ...) as plain text in Markdown: characters that Markdown would read as emphasis, code or a link are escaped.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [AllowEmptyString()]
        [string] $Value
    )

    # An underscore inside a word (prg_Lab) is no emphasis and stays as it is.
    $escaped = $Value.Trim() -replace '([\\`*\[\]])', '\$1' -replace '(?<![\p{L}\p{N}])_|_(?![\p{L}\p{N}])', '\_'
    ConvertTo-EntraOpsPackText $escaped
}

function Get-EntraOpsPackResultDetail {
    <#
    .SYNOPSIS
    The message of a result without its subject (the object and tier that the object line shows): the Detail of EntraOps, or the same for results of EntraOps versions without it.

    .DESCRIPTION
    Follows Get-EntraOpsFindingDetail of EntraOps: only a known subject at the start of the message is removed, and
    only when it names the object of the result with the tier of the result. Any other message is returned unchanged.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        [object] $Result
    )

    if ($null -ne $Result.PSObject.Properties['Detail'] -and $Result.Detail) { return [string]$Result.Detail }
    $message = [string]$Result.Message
    $displayName = [string]$Result.Instance.DisplayName
    $objectType = [string]$Result.Instance.ObjectType
    $tierKey = [string]$Result.Instance.AdminTierLevelName
    if ([string]::IsNullOrWhiteSpace($message) -or [string]::IsNullOrWhiteSpace($displayName)) { return $message }

    $tierNames = @{ ControlPlane = 'Control Plane'; ManagementPlane = 'Management Plane'; WorkloadPlane = 'Workload Plane'; UserAccess = 'User Access' }
    $tier = if ($tierNames.ContainsKey($tierKey)) { $tierNames[$tierKey] } else { $null }
    if ($tier) { $message = $message.Replace("the $tier role '$displayName'", 'the role') }
    if ($objectType -eq 'accessPackageAssignmentPolicy' -and $displayName -match '^(.+) / ([^/]+)$') {
        $message = $message.Replace("the policy '$($Matches[2])' of the access package '$($Matches[1])'", 'the policy')
    }
    if ($objectType -eq 'accessPackageAssignmentPolicy' -and $displayName -match '^(.+) / ([^/]+)$') {
        $policySubject = "The policy '$($Matches[2])' of the access package '$($Matches[1])' "
        if ($message.StartsWith($policySubject, [System.StringComparison]::Ordinal) -and $message.Length -gt $policySubject.Length + 2) {
            $rest = $message.Substring($policySubject.Length)
            return $rest.Substring(0, 1).ToUpperInvariant() + $rest.Substring(1)
        }
    }
    $ofObject = " of '$displayName' has no tier classification."
    if ($message -cmatch "^'[^']+' \([^()]+\) of '" -and $message.EndsWith($ofObject, [System.StringComparison]::Ordinal)) {
        return $message.Substring(0, $message.Length - $ofObject.Length) + ' has no tier classification.'
    }
    if ($message -cmatch "^(Control Plane|Management Plane|Workload Plane|User Access) workload identity '$([regex]::Escape($displayName))' (.{3,})$" -and $Matches[1] -ne $tier) {
        return "With $($Matches[1]) access, $($Matches[2])"
    }
    $subjects = @(
        if ($tierKey -eq 'Unclassified') { 'Unclassified object (counted as User Access) '; 'Unclassified object ' }
        if ($tier) { "$tier object "; "$tier workload identity "; "The $tier role " }
        'The Conditional Access policy '
        'The administrative unit '
        'Service principal '
        'Custom role '
        'Group '
        'User '
        ''
    )
    foreach ($subject in $subjects) {
        $start = "$subject'$displayName'"
        if (-not $message.StartsWith($start, [System.StringComparison]::Ordinal)) { continue }
        $rest = $message.Substring($start.Length)
        foreach ($shown in @($objectType, $tier) | Where-Object { $_ }) {
            if ($rest.StartsWith(" ($shown)", [System.StringComparison]::OrdinalIgnoreCase)) { $rest = $rest.Substring($shown.Length + 3); break }
        }
        $rest = $rest.TrimStart()
        if ($subject -and $rest -cmatch '^of\b') { return "$($subject.Trim()) $rest" }
        if ($rest.Length -lt 3 -or $rest -cmatch '^(of|and|or|to|in)\b' -or $rest -notmatch '^[\p{L}(]') { return $message }
        $rest = $rest -creplace '^(with [\w ]+? role assignments) (?=\p{Ll})', '$1, '
        $rest = $rest -creplace '^\(([^()]+)\)\s+(?=\S)', '$1: '
        return $rest.Substring(0, 1).ToUpperInvariant() + $rest.Substring(1)
    }
    $message
}

function Split-EntraOpsPackMessage {
    <#
    .SYNOPSIS
    A message of EntraOps split into the names it quotes ('Contributor') and the text around them.

    .DESCRIPTION
    Only quotes that open and close a name are names: an apostrophe inside a word (Scotty's Mac) is not a quote.
    Template is the text with a placeholder for each name: two messages with the same template say the same about
    other names, for example the same role at two scopes.
    #>
    [CmdletBinding()]
    param(
        [AllowEmptyString()]
        [string] $Message
    )

    $parts = [System.Collections.Generic.List[string]]::new()
    $names = [System.Collections.Generic.List[string]]::new()
    $position = 0
    foreach ($match in [regex]::Matches($Message, "(?<![\w'])'([^'\r\n]+?)'(?!\w)")) {
        $parts.Add($Message.Substring($position, $match.Index - $position))
        $names.Add($match.Groups[1].Value)
        $position = $match.Index + $match.Length
    }
    $parts.Add($Message.Substring($position))
    [pscustomobject]@{
        Parts    = $parts.ToArray()
        Names    = $names.ToArray()
        Template = $parts.ToArray() -join [char]0
    }
}

function ConvertTo-EntraOpsPackFindingText {
    <#
    .SYNOPSIS
    The Markdown of a message split by Split-EntraOpsPackMessage: its names as plain text, or the Markdown of Value in place of the name at Position.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [object] $Split,

        [int] $Position = -1,

        [string] $Value,

        # The number of names in Value: with several, the text around them is put in the plural.
        [int] $ValueCount = 1
    )

    # Emphasis, sparingly: the tiers in bold (why it is a finding), the role or permission that a name follows in bold
    # (what to change), IDs as code (to copy them). Other names are plain text.
    $guid = '\b[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}\b'
    $text = for ($index = 0; $index -lt $Split.Parts.Count; $index++) {
        # The text between the names can hold a part of a name with an apostrophe: no link, code or emphasis from it either.
        $part = $Split.Parts[$index]
        if ($Position -ge 0 -and $ValueCount -gt 1) {
            # Several names in one place: "the role A and B" is "the roles A and B", "A and B has" is "A and B have".
            if ($index -eq $Position) { $part = $part -creplace '\b(role|permission)(\s)$', '$1s$2' }
            if ($index -eq $Position + 1 -and $Position -eq 0 -and -not $Split.Parts[0].Trim()) { $part = $part -creplace '^((?: \([^()]*\))? )has\b', '$1have' }
        }
        (ConvertTo-EntraOpsPackText ($part -replace '([\\`*\[\]])', '\$1')) -replace $guid, '`$0`' -creplace '(?<![/-] ?)\b(Control Plane|Management Plane|Workload Plane|User Access)\b(?! ?[/-])', '**$1**'
        if ($index -lt $Split.Names.Count) {
            $name = $Split.Names[$index]
            if ($index -eq $Position) { $Value }
            elseif ($name.Trim() -match "^$guid$") { '`' + $name.Trim() + '`' }
            elseif ($part -match '(?i)(\b(role|permission)s?|^Holds)\s$') { '**' + (ConvertTo-EntraOpsPackName $name) + '**' }
            else { ConvertTo-EntraOpsPackName $name }
        }
    }
    (@($text) -join '').Trim()
}

function Get-EntraOpsPackObjectInfo {
    <#
    .SYNOPSIS
    How a result's object is shown and linked: its type and tier for people, its link in the Microsoft Entra admin center and its type in the Maester affected objects.

    .DESCRIPTION
    The Microsoft Entra admin center links use the blades that Maester recognizes, so the Maester report lists the
    linked objects as affected objects: users, groups, service principals, app registrations (by their appId),
    Conditional Access policies and access packages (of an access package assignment policy).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        [object] $Result,

        [AllowEmptyString()]
        [string] $PortalUrl
    )

    $typeNames = @{
        user = 'User'; group = 'Group'; serviceprincipal = 'Service principal'; application = 'Application'
        rolesetting = 'PIM role setting'; accesspackageassignmentpolicy = 'Access package policy'
        conditionalaccesspolicy = 'Conditional Access policy'; administrativeunit = 'Administrative unit'
        roledefinition = 'Role definition'; tenant = 'Tenant'
    }
    $tierNames = @{ ControlPlane = 'Control Plane'; ManagementPlane = 'Management Plane'; WorkloadPlane = 'Workload Plane'; UserAccess = 'User Access'; Unclassified = 'Unclassified' }
    $guid = '^[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$'

    $instance = $Result.Instance
    $evidence = $Result.Evidence
    $id = [string]$instance.ObjectId
    $type = ([string]$instance.ObjectType).ToLowerInvariant()
    $tier = [string]$instance.AdminTierLevelName
    $portalLink = $null
    $affectedType = $null
    $affectedId = $id
    $odataType = $null
    if ($PortalUrl -and $id -match $guid) {
        switch ($type) {
            'user' { $portalLink = "$($PortalUrl)#view/Microsoft_AAD_UsersAndTenants/UserProfileMenuBlade/~/overview/userId/$id"; $affectedType = 'User'; $odataType = '#microsoft.graph.user' }
            'group' { $portalLink = "$($PortalUrl)#view/Microsoft_AAD_IAM/GroupDetailsMenuBlade/~/Overview/groupId/$id"; $affectedType = 'Group'; $odataType = '#microsoft.graph.group' }
            'serviceprincipal' { $portalLink = "$($PortalUrl)#view/Microsoft_AAD_IAM/ManagedAppMenuBlade/~/Overview/objectId/$id"; $affectedType = 'ServicePrincipal'; $odataType = '#microsoft.graph.servicePrincipal' }
            'conditionalaccesspolicy' { $portalLink = "$($PortalUrl)#view/Microsoft_AAD_ConditionalAccess/PolicyBlade/policyId/$id"; $affectedType = 'ConditionalAccessPolicy'; $odataType = '#microsoft.graph.conditionalAccessPolicy' }
            'administrativeunit' { $portalLink = "$($PortalUrl)#view/Microsoft_AAD_IAM/AdministrativeUnitMenuBlade/~/Overview/objectId/$id" }
            # Maester has no Graph object type for applications; it identifies app registrations by appId.
            'application' {
                if ("$($evidence.AppId)" -match $guid) {
                    $portalLink = "$($PortalUrl)#view/Microsoft_AAD_RegisteredApps/ApplicationMenuBlade/~/Overview/appId/$($evidence.AppId)"
                    $affectedType = 'AppRegistration'
                    $affectedId = [string]$evidence.AppId
                }
            }
        }
    }
    # The access package of an assignment policy: Maester lists access packages, not their policies.
    if ($PortalUrl -and $type -eq 'accesspackageassignmentpolicy' -and "$($evidence.AccessPackageId)" -match $guid) {
        $portalLink = "$($PortalUrl)#view/Microsoft_Azure_ELMAdmin/EntitlementMenuBlade/~/overview/entitlementId/$($evidence.AccessPackageId)"
    }

    [pscustomobject]@{
        Id           = $id
        TypeKey      = $type
        TypeIcon     = (Get-EntraOpsPackIcon -TypeKey $type)
        TierIcon     = $(if ($tier) { Get-EntraOpsPackIcon -TierKey $tier })
        Name         = $(if ($instance.DisplayName) { [string]$instance.DisplayName } elseif ($id) { $id } else { [string]$instance.Id })
        # The access package of an assignment policy, which the link opens (and Maester lists by this name).
        PackageName  = $(if ($type -eq 'accesspackageassignmentpolicy' -and $evidence.AccessPackageName) { [string]$evidence.AccessPackageName })
        Type         = $(if ($typeNames.ContainsKey($type)) { $typeNames[$type] } else { [string]$instance.ObjectType })
        Tier         = $(if ($tier -and $tierNames.ContainsKey($tier)) { $tierNames[$tier] } else { $tier })
        TierKey      = $tier
        PortalLink   = $portalLink
        AffectedType = $affectedType
        AffectedId   = $affectedId
        ODataType    = $odataType
    }
}

function Get-EntraOpsPackReportLink {
    <#
    .SYNOPSIS
    The links of a finding result to the EntraOps reports that show its object, as the Findings view of the Privileged Assets report has them.

    .DESCRIPTION
    Mirrors findingLinks of Reports/PrivilegedAssets/js/app.js: the PIM role setting (PIM Request Flow, #flow=),
    the access package assignment policy (Access Package Flow, #flow=), the Conditional Access policy (Conditional
    Access Analysis, #flow=), the Tenant Governance resource (Configuration Analyzer, #object=), the tier breach
    path (Tier Breach Analyzer, #sel=), the role assignment and the object (EAM Dashboard, #assignment= and
    #asset=) and the access path (Access Path Map, #node=). The objects of the Privileged EAM data are the
    objects of the rules of the Privileged Assets, Privileged EAM and Tier Breach areas; objects of other rules
    get no link to the EAM Dashboard or the Access Path Map, which would not find them.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object] $Rule,

        [Parameter(Mandatory)]
        [AllowNull()]
        [object] $Result,

        [Parameter(Mandatory)]
        [string] $ReportBase
    )

    # Href -> label, in the order added: the same link is listed once. Empty links (no ID) are left out at the end.
    # Direct calls only: Maester rates the call of a script block in a variable as dynamic code.
    $links = [ordered]@{}
    $evidence = $Result.Evidence
    $id = [string]$Result.Instance.ObjectId
    $type = ([string]$Result.Instance.ObjectType).ToLowerInvariant()
    $configurationTypes = @{
        rolesetting                   = 'microsoft.entra.rolesetting'
        accesspackageassignmentpolicy = 'microsoft.entra.entitlementmanagementaccesspackageassignmentpolicy'
        conditionalaccesspolicy       = 'microsoft.entra.conditionalaccesspolicy'
        administrativeunit            = 'microsoft.entra.administrativeunit'
    }
    $configuration = if ($configurationTypes.ContainsKey($type) -and $id) { "$($ReportBase)ConfigurationAnalyzer/index.html#object=$([uri]::EscapeDataString("$($configurationTypes[$type])|$id"))" } else { '' }
    switch ($type) {
        'rolesetting' {
            # The flow is "<role ID>|<path>"; results without FlowId carry it in the instance ID ("<role ID>.<path>").
            $flowId = if ($evidence.FlowId) { [string]$evidence.FlowId } else { [string]$Result.Instance.Id -replace '^([^.]+)\.(.+)$', '$1|$2' }
            if ($flowId) { $links["$($ReportBase)PimRequestFlow/index.html#flow=$([uri]::EscapeDataString($flowId))"] = 'PIM Request Flow' }
            $links[$configuration] = 'Configuration Analyzer'
        }
        'accesspackageassignmentpolicy' {
            $flowId = if ($evidence.FlowId) { [string]$evidence.FlowId } else { $id }
            if ($flowId) { $links["$($ReportBase)AccessPackageFlow/index.html#flow=$([uri]::EscapeDataString($flowId))"] = 'Access Package Flow' }
            $links[$configuration] = 'Configuration Analyzer'
        }
        'conditionalaccesspolicy' {
            if ($id) { $links["$($ReportBase)ConditionalAccessAnalysis/index.html#flow=$([uri]::EscapeDataString($id))"] = 'Conditional Access Analysis' }
            $links[$configuration] = 'Configuration Analyzer'
        }
        'administrativeunit' { $links[$configuration] = 'Configuration Analyzer' }
        'roledefinition' {
            # Custom roles: their assignments in the EAM Dashboard.
            $index = 0
            foreach ($assignmentId in @($evidence.RoleAssignmentInstanceIds | Where-Object { $_ } | Select-Object -First 3)) {
                $links["$($ReportBase)EamDashboard/index.html#assignment=$([uri]::EscapeDataString([string]$assignmentId))"] = $(if ($index) { "EAM Dashboard assignment $($index + 1)" } else { 'EAM Dashboard assignment' })
                $index++
            }
        }
        'tenant' {
            $links["$($ReportBase)PrivilegeHistory/index.html"] = 'Privilege History'
            $links["$($ReportBase)TierBreachAnalyzer/index.html"] = 'Tier Breach Analyzer'
        }
        default {
            if ($Rule.Area -eq 'TierBreach' -and $id -and $evidence.Role) {
                # The first path ID makes the selection unambiguous: two assignments can share object, role, service and scope.
                $service = if ($evidence.Service) { $evidence.Service } elseif (@($evidence.Services).Count) { @($evidence.Services)[0] } else { '' }
                $selection = @($id, $evidence.Role, $service, $(if ($evidence.ScopeId) { $evidence.ScopeId } else { '' })) + @(@($evidence.PathIds | Where-Object { $_ }) | Select-Object -First 1)
                $links["$($ReportBase)TierBreachAnalyzer/index.html#sel=$([uri]::EscapeDataString($selection -join '||'))"] = 'Tier Breach Analyzer'
            }
            $assignmentId = if ($evidence.RoleAssignmentInstanceId) { [string]$evidence.RoleAssignmentInstanceId } else { [string]$evidence.AssignmentInstanceId }
            if ($assignmentId) { $links["$($ReportBase)EamDashboard/index.html#assignment=$([uri]::EscapeDataString($assignmentId))"] = 'EAM Dashboard assignment' }
            $inInventory = $id -and $Rule.Area -in 'PrivilegedAssets', 'PrivilegedEAM', 'TierBreach'
            if ($inInventory) { $links["$($ReportBase)EamDashboard/index.html#asset=$([uri]::EscapeDataString($id))"] = 'EAM Dashboard' }
            if ($Rule.Area -eq 'AccessPackageFlow') { $links["$($ReportBase)AccessPackageFlow/index.html"] = 'Access Package Flow' }
            if ($Rule.Area -eq 'PrivilegeHistory') { $links["$($ReportBase)PrivilegeHistory/index.html"] = 'Privilege History' }
            if ($inInventory -and $type -in 'user', 'group', 'serviceprincipal', 'application') { $links["$($ReportBase)AccessPathMap/index.html#node=$([uri]::EscapeDataString($id.ToUpperInvariant()))"] = 'Access Path Map' }
        }
    }
    foreach ($href in $links.Keys) {
        if ($href) { [pscustomobject]@{ Label = $links[$href]; Href = $href } }
    }
}

function Get-EntraOpsPackEvidenceText {
    <#
    .SYNOPSIS
    The evidence of a result that its message does not name: the PIM assignment type, the scope, the groups and examples of the access drift.

    .DESCRIPTION
    Two results can have the same message, for example the same role through nested groups at two scopes. The
    evidence tells them apart and says what to change. Only the PIM assignment type has an icon: a permanent
    assignment is what to change first.
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [AllowNull()]
        [object] $Evidence,

        [AllowEmptyString()]
        [string] $Message
    )

    if ($null -eq $Evidence) { return @() }
    # Whether the message names a value already (case-insensitive).
    $text = if ($Message) { $Message.ToLowerInvariant() } else { '' }
    # The items are Markdown already: names and other text escaped.
    $items = [System.Collections.Generic.List[string]]::new()
    $pim = if ($Evidence.PimAssignmentType) { [string]$Evidence.PimAssignmentType } elseif ($Evidence.PIMAssignmentType) { [string]$Evidence.PIMAssignmentType }
    if ($pim -and -not $text.Contains($pim.ToLowerInvariant())) {
        $items.Add($(switch ($pim) { 'Eligible' { '⏳ eligible' } 'Permanent' { '📌 permanent' } default { "PIM: $(ConvertTo-EntraOpsPackMarkdownCell $pim)" } }))
    }
    $scopeId = if ($Evidence.RoleAssignmentScopeId) { [string]$Evidence.RoleAssignmentScopeId } else { [string]$Evidence.ScopeId }
    # The scope of an API permission (ResourceApps) is the ID of its API, which the message names.
    $scope = if ($Evidence.ScopeName) { [string]$Evidence.ScopeName } elseif ($scopeId -and $scopeId -ne '/' -and "$($Evidence.System)" -ne 'ResourceApps') { $scopeId }
    if ($scope -and -not $text.Contains($scope.ToLowerInvariant())) { $items.Add("scope $(ConvertTo-EntraOpsPackName $scope)") }
    if ($Evidence.TransitiveBy -and -not $text.Contains(([string]$Evidence.TransitiveBy).ToLowerInvariant())) { $items.Add("via $(ConvertTo-EntraOpsPackName $Evidence.TransitiveBy)") }
    $groups = @($Evidence.GroupNames | Where-Object { $_ })
    if ($groups.Count -and -not $text.Contains(([string]$groups[0]).ToLowerInvariant())) { $items.Add("groups $(@($groups | ForEach-Object { ConvertTo-EntraOpsPackName $_ }) -join ' › ')") }
    $examples = @($Evidence.Examples | Where-Object { $_ -and $_.Identity } | ForEach-Object { [string]$_.Identity } | Select-Object -First 3)
    if ($examples.Count) { $items.Add("without access package: $(ConvertTo-EntraOpsPackMarkdownCell ($examples -join ', '))$(if ($Evidence.MoreExamples -or @($Evidence.Examples).Count -gt $examples.Count) { ' and more' })") }
    $items.ToArray()
}

function ConvertTo-EntraOpsPackObjectText {
    <#
    .SYNOPSIS
    The Markdown of an object in a result table: its name in bold, linked to the Microsoft Entra admin center when it has a link.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [object] $Object,

        # Adds the start of the object ID, for objects whose name is not unique in the list.
        [switch] $WithId,

        # Adds the tier and type of the object as icons.
        [switch] $WithType,

        # Longer names without spaces are shortened in the middle (0: never).
        [int] $MaxNameLength = 0
    )

    # An access package policy is linked by its access package ("Package / Policy": the package is the link).
    $fullName = [string]$Object.Name
    $suffix = ''
    if ($Object.PackageName -and $fullName.StartsWith("$($Object.PackageName) / ")) {
        $suffix = ' / ' + (ConvertTo-EntraOpsPackMarkdownCell $fullName.Substring($Object.PackageName.Length + 3))
        $fullName = [string]$Object.PackageName
    }
    # A star would end the bold text (brackets and backslashes are escaped with the cell).
    # A long name without spaces (CloudPosture/securityOperators/...) cannot wrap and would widen the object column
    # for all rows: it is shortened in the middle, and the link shows the full name as its tooltip. Only objects that
    # Maester gets with their full name (GraphObjects) are shortened: Maester names the others by their link text.
    $shown = if ($MaxNameLength -gt 12 -and $Object.ODataType -and $fullName.Length -gt $MaxNameLength -and $fullName -match '\S{30,}') { $fullName.Substring(0, $MaxNameLength - 12) + '…' + $fullName.Substring($fullName.Length - 11) } else { $fullName }
    $name = (ConvertTo-EntraOpsPackMarkdownCell $shown) -replace '\*', '\*'
    if ($WithId -and $Object.Id -and $Object.Id -ne $Object.Name) { $name += " ($(ConvertTo-EntraOpsPackMarkdownCell ($Object.Id.Substring(0, [Math]::Min(8, $Object.Id.Length)))))" }
    $title = if ($shown -ne $fullName) { " `"$((ConvertTo-EntraOpsPackMarkdownCell $fullName) -replace '"', "'")`"" } else { '' }
    $text = if ($Object.PortalLink) { "**[$name]($($Object.PortalLink)$title)**$suffix" } else { "**$name**$suffix" }
    # The tier and type as icons, which the legend of the table names. A type without an icon is named.
    if ($WithType) {
        $icons = @($Object.TierIcon, $Object.TypeIcon) | Where-Object { $_ }
        if ($icons) { $text = "$($icons -join ' ') $text" }
        if (-not $Object.TypeIcon -and $Object.Type) { $text += " ($(ConvertTo-EntraOpsPackMarkdownCell $Object.Type))" }
    }
    $text
}

function ConvertTo-EntraOpsPackLinkText {
    <#
    .SYNOPSIS
    The Markdown of the report links of a result or an object: "↗ Tier breach · Assignment", with the full name of each report as its tooltip.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [AllowNull()]
        [object[]] $Link
    )

    $links = @($Link | Where-Object { $_ } | ForEach-Object { "[$(Get-EntraOpsPackReportLabel $_.Label)]($($_.Href) `"EntraOps $($_.Label -replace '"', "'")`")" })
    if ($links.Count) { "↗ $($links -join ' · ')" }
}

function Get-EntraOpsPackResultObject {
    <#
    .SYNOPSIS
    The results of a rule by object, in the order of their first result: each object with its findings (text, evidence, report links), the links that all its findings share, and its lines.

    .DESCRIPTION
    Findings of an object that say the same about another name (the same role at three scopes, or 29 delegated
    permissions of one API) are one line, which names them all.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object] $Rule,

        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]] $Results,

        [AllowEmptyString()]
        [string] $ReportBase,

        [AllowEmptyString()]
        [string] $PortalUrl
    )

    # The objects in the order of their first result (Group-Object would sort them by ID).
    $byKey = [ordered]@{}
    foreach ($result in $Results) {
        $object = Get-EntraOpsPackObjectInfo -Result $result -PortalUrl $PortalUrl
        $key = if ($object.Id) { $object.Id } else { "name:$($object.Name)" }
        if (-not $byKey.Contains($key)) { $byKey[$key] = [pscustomobject]@{ Object = $object; Results = [System.Collections.Generic.List[object]]::new() } }
        $byKey[$key].Results.Add($result)
    }
    foreach ($entry in $byKey.Values) {
        $findings = @(foreach ($result in $entry.Results) {
                $links = @(if ($ReportBase) { Get-EntraOpsPackReportLink -Rule $Rule -Result $result -ReportBase $ReportBase })
                $detail = Get-EntraOpsPackResultDetail $result
                [pscustomobject]@{
                    Split    = (Split-EntraOpsPackMessage $detail)
                    # The evidence that the shown text does not name.
                    Evidence = (@(Get-EntraOpsPackEvidenceText -Evidence $result.Evidence -Message $detail) -join ' · ')
                    Links    = $links
                    # The links as one string, to find the links that several findings share.
                    HrefSet  = "`n$(@($links | ForEach-Object Href) -join "`n")`n"
                }
            })
        $shared = @($findings[0].Links | Where-Object { $needle = "`n$($_.Href)`n"; -not @($findings | Where-Object { -not $_.HrefSet.Contains($needle) }).Count })
        # One line for findings that differ in one name only (at the same place of the same message).
        $lines = [System.Collections.Generic.List[object]]::new()
        foreach ($finding in $findings) {
            $target = $null
            foreach ($line in $lines) {
                if ($line.Template -cne $finding.Split.Template -or $line.Evidence -cne $finding.Evidence) { continue }
                $differ = @(for ($index = 0; $index -lt $finding.Split.Names.Count; $index++) { if ($line.Split.Names[$index] -cne $finding.Split.Names[$index]) { $index } })
                if ($differ.Count -eq 0) { $target = $line; break }
                if ($differ.Count -eq 1 -and ($line.Position -lt 0 -or $line.Position -eq $differ[0])) { $line.Position = $differ[0]; $target = $line; break }
            }
            if (-not $target) {
                $target = [pscustomobject]@{ Template = $finding.Split.Template; Evidence = $finding.Evidence; Split = $finding.Split; Position = -1; Findings = [System.Collections.Generic.List[object]]::new() }
                $lines.Add($target)
            }
            $target.Findings.Add($finding)
        }
        [pscustomobject]@{
            Object   = $entry.Object
            Count    = $findings.Count
            Findings = $findings
            Shared   = $shared
            Lines    = $lines.ToArray()
        }
    }
}

function ConvertTo-EntraOpsPackLineText {
    <#
    .SYNOPSIS
    The Markdown of a line of findings: its text (the names that differ linked to their reports), its evidence and the links of the line beyond ExcludeHref.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object] $Line,

        # The links that the object shows already.
        [AllowEmptyCollection()]
        [string[]] $ExcludeHref = @(),

        # The most names of one line ("A, B, C and 7 more").
        [int] $MaxNames = 8
    )

    $first = $Line.Findings[0]
    # The links of the line beyond those of the object: those that all its findings share.
    $lineLinks = @($first.Links | Where-Object { $_.Href -notin $ExcludeHref } | Where-Object { $needle = "`n$($_.Href)`n"; -not @($Line.Findings | Where-Object { -not $_.HrefSet.Contains($needle) }).Count })
    $lineHrefs = @($ExcludeHref) + @($lineLinks.Href)
    $numbered = @()
    if ($Line.Position -lt 0) {
        $text = ConvertTo-EntraOpsPackFindingText -Split $Line.Split
        if ($Line.Findings.Count -gt 1) {
            # The same text more than once (for example the same role through two paths): the first report of each
            # finding that the line does not link, numbered ("Tier breach 1 · 2").
            $text += " ($($Line.Findings.Count) times)"
            $index = 0
            $numbered = @(foreach ($finding in $Line.Findings) {
                    $index++
                    $own = @($finding.Links | Where-Object { $_.Href -notin $lineHrefs }) | Select-Object -First 1
                    if ($own) { "[$(if ($index -eq 1) { "$(Get-EntraOpsPackReportLabel $own.Label) 1" } else { $index })]($($own.Href) `"EntraOps $($own.Label -replace '"', "'")`")" }
                })
        }
    } else {
        # The names that differ, each linked to the first report of its finding that the line does not link.
        $byName = [ordered]@{}
        foreach ($finding in $Line.Findings) { $name = $finding.Split.Names[$Line.Position]; if (-not $byName.Contains($name)) { $byName[$name] = $finding } }
        $names = @(foreach ($name in @($byName.Keys | Select-Object -First $MaxNames)) {
                $own = @($byName[$name].Links | Where-Object { $_.Href -notin $lineHrefs }) | Select-Object -First 1
                $shown = if ($own) { "[$(ConvertTo-EntraOpsPackName $name)]($($own.Href) `"EntraOps $($own.Label -replace '"', "'")`")" } else { ConvertTo-EntraOpsPackName $name }
                # The role or permission that a name follows is bold, as a single name is (ConvertTo-EntraOpsPackFindingText).
                if ($Line.Split.Parts[$Line.Position] -match '(?i)(\b(role|permission)s?|^Holds)\s$') { "**$shown**" } else { $shown }
            })
        if ($byName.Count -gt $MaxNames) { $names += "$($byName.Count - $MaxNames) more" }
        $value = if ($names.Count -gt 1) { "$($names[0..($names.Count - 2)] -join ', ') and $($names[-1])" } else { $names[0] }
        $text = ConvertTo-EntraOpsPackFindingText -Split $Line.Split -Position $Line.Position -Value $value -ValueCount $byName.Count
    }
    $linkText = ConvertTo-EntraOpsPackLinkText $lineLinks
    if ($numbered.Count) { $linkText = if ($linkText) { "$linkText · $($numbered -join ' · ')" } else { "↗ $($numbered -join ' · ')" } }
    # The evidence is context: in italics.
    [pscustomobject]@{ Text = $text; Evidence = $(if ($Line.Evidence) { "*$($Line.Evidence)*" }); LinkText = $linkText }
}

function Get-EntraOpsPackTypePlural {
    <#
    .SYNOPSIS
    How to count objects in a section: "142 PIM role settings" when they share one type, otherwise "12 objects".
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [AllowEmptyCollection()]
        [object[]] $Object
    )

    $plural = @{ user = 'users'; group = 'groups'; serviceprincipal = 'service principals'; application = 'applications'; rolesetting = 'PIM role settings'; accesspackageassignmentpolicy = 'access package policies'; conditionalaccesspolicy = 'Conditional Access policies'; administrativeunit = 'administrative units'; roledefinition = 'role definitions' }
    $types = @($Object | ForEach-Object { $_.TypeKey } | Select-Object -Unique)
    $word = if ($types.Count -eq 1 -and $types[0] -and $plural.ContainsKey($types[0])) { $plural[$types[0]] } else { 'objects' }
    "$(@($Object).Count) $word"
}

function ConvertTo-EntraOpsPackResultTable {
    <#
    .SYNOPSIS
    The Markdown tables of the affected instances of a rule: grouped by finding when each object has one, by object otherwise, or one row per object with -ByObject.

    .DESCRIPTION
    The tables have two columns, so they fit the result panel of the Maester report. The object column has its tier
    and type as icons and its name linked to the Microsoft Entra admin center; objects whose name is not unique show
    the start of their ID. The finding is the message of EntraOps without the object (Detail), the evidence it does
    not name and the links to the EntraOps reports.

    When each object has one finding, objects with the same finding (MinShared or more) share a section: the finding
    once, then a table of these objects with their evidence and links ("Can be activated without approval. — 142 PIM role
    settings:"). The other objects follow in one table with their finding.

    When an object has several findings, the table lists them by object: the object once (with the number of its
    findings and the links that all of them share), its findings in the rows below it. Findings of an object that
    say the same about another name are one row ("at A, B and C", each linked to its report). An object shows at
    most MaxPerObject rows, then the number of its other findings, so one object with many findings does not hide
    the others. MaxRows limits the rows of all tables.

    With -ByObject (the unclassified objects of a rule), a row is one object with the number of its instances and
    the message of the first one.
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory)]
        [object] $Rule,

        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]] $Results,

        [AllowEmptyString()]
        [string] $ReportBase,

        [AllowEmptyString()]
        [string] $PortalUrl,

        [int] $MaxRows = 50,

        [int] $MaxPerObject = 5,

        # The most names of one row ("A, B, C and 7 more").
        [int] $MaxNames = 8,

        # The fewest objects with the same finding that share a section.
        [int] $MinShared = 3,

        [switch] $ByObject
    )

    $findingsView = if ($ReportBase) { "$($ReportBase)PrivilegedAssets/index.html?view=findings#rule=$([uri]::EscapeDataString($Rule.RuleId))" }
    $objects = @(Get-EntraOpsPackResultObject -Rule $Rule -Results $Results -ReportBase $ReportBase -PortalUrl $PortalUrl)
    if ($ByObject) { $objects = @($objects | Sort-Object Count -Descending -Stable) }
    # Classified objects first: their findings are certain, those of unclassified objects depend on their tier. Rules
    # that judge the role assignments (not the tier of the object) keep the order of EntraOps.
    elseif (Test-EntraOpsPackObjectTierRule -RuleId $Rule.RuleId) { $objects = @($objects | Sort-Object { $_.Object.TierKey -eq 'Unclassified' } -Stable) }
    # Names shared by objects with different IDs (for example service principals of the same application name).
    $ambiguous = @($objects | ForEach-Object { $_.Object } | Group-Object Name | Where-Object { $_.Count -gt 1 } | ForEach-Object Name)
    foreach ($entry in $objects) { $entry | Add-Member -NotePropertyName Cell -NotePropertyValue (ConvertTo-EntraOpsPackObjectText -Object $entry.Object -WithId:($entry.Object.Name -in $ambiguous) -WithType -MaxNameLength 40) }

    $body = [System.Collections.Generic.List[string]]::new()
    $shownRows = 0
    $shownResults = 0
    $shownObjects = 0
    if ($ByObject) {
        $body.Add('| Object | Findings |')
        $body.Add('| --- | --- |')
        foreach ($entry in $objects) {
            if ($shownRows -ge $MaxRows) { break }
            $first = $entry.Findings[0]
            $text = "$(ConvertTo-EntraOpsPackFindingText -Split $first.Split)$(if ($first.Evidence) { " — *$($first.Evidence)*" })"
            $count = if ($entry.Count -gt 1) { "$($entry.Count) findings, for example: " } else { '' }
            $body.Add("| $($entry.Cell) | $count$((@($text, (ConvertTo-EntraOpsPackLinkText $entry.Shared)) | Where-Object { $_ }) -join ' ') |")
            $shownRows++
            $shownResults += $entry.Count
            $shownObjects++
        }
    } elseif (-not @($objects | Where-Object { $_.Lines.Count -gt 1 }).Count) {
        # One finding per object: objects with the same finding share a section, in the order of their size.
        $byText = [ordered]@{}
        $allItems = [System.Collections.Generic.List[object]]::new()
        foreach ($entry in $objects) {
            $line = ConvertTo-EntraOpsPackLineText -Line $entry.Lines[0] -MaxNames $MaxNames
            if (-not $byText.Contains($line.Text)) { $byText[$line.Text] = [System.Collections.Generic.List[object]]::new() }
            $item = [pscustomobject]@{ Entry = $entry; Line = $line }
            $byText[$line.Text].Add($item)
            $allItems.Add($item)
        }
        $sections = @($byText.Keys | Where-Object { $byText[$_].Count -ge $MinShared } | Sort-Object { $byText[$_].Count } -Descending -Stable)
        $others = @($allItems | Where-Object { $byText[$_.Line.Text].Count -lt $MinShared })
        foreach ($text in $sections) {
            if ($shownRows -ge $MaxRows) { break }
            $items = $byText[$text]
            $withDetails = @($items | Where-Object { $_.Line.Evidence -or $_.Line.LinkText }).Count -gt 0
            if ($body.Count) { $body.Add('') }
            # The finding first, then the objects it applies to (the table below).
            $body.Add("$text — **$(Get-EntraOpsPackTypePlural @($items | ForEach-Object { $_.Entry.Object })):**")
            $body.Add('')
            $body.Add($(if ($withDetails) { '| Object | Details |' } else { '| Object |' }))
            $body.Add($(if ($withDetails) { '| --- | --- |' } else { '| --- |' }))
            foreach ($item in $items) {
                if ($shownRows -ge $MaxRows) { break }
                $details = (@($item.Line.Evidence, $item.Line.LinkText) | Where-Object { $_ }) -join ' '
                $body.Add($(if ($withDetails) { "| $($item.Entry.Cell) | $details |" } else { "| $($item.Entry.Cell) |" }))
                $shownRows++
                $shownResults += $item.Entry.Count
                $shownObjects++
            }
        }
        if ($others.Count -and $shownRows -lt $MaxRows) {
            if ($body.Count) { $body.Add(''); $body.Add('**Other findings:**'); $body.Add('') }
            $body.Add('| Object | Finding |')
            $body.Add('| --- | --- |')
            foreach ($item in $others) {
                if ($shownRows -ge $MaxRows) { break }
                $finding = (@("$($item.Line.Text)$(if ($item.Line.Evidence) { ' — ' + $item.Line.Evidence })", $item.Line.LinkText) | Where-Object { $_ }) -join ' '
                $body.Add("| $($item.Entry.Cell) | $finding |")
                $shownRows++
                $shownResults += $item.Entry.Count
                $shownObjects++
            }
        }
    } else {
        # Several findings per object: the object once, its findings in the rows below it.
        $body.Add('| Object | Finding |')
        $body.Add('| --- | --- |')
        foreach ($entry in $objects) {
            if ($shownRows -ge $MaxRows) { break }
            $multiple = $entry.Lines.Count -gt 1
            # An object with several rows shows the links that all its findings share; a single row has all its links.
            $exclude = if ($multiple) { @($entry.Shared.Href) } else { @() }
            $objectCell = (@($entry.Cell, $(if ($entry.Count -gt 1) { "$($entry.Count) findings" }), $(if ($multiple) { ConvertTo-EntraOpsPackLinkText $entry.Shared })) | Where-Object { $_ }) -join ' · '
            $shownLines = @($entry.Lines | Select-Object -First ([Math]::Min($MaxPerObject, $MaxRows - $shownRows)))
            $firstRow = $true
            foreach ($line in $shownLines) {
                $lineText = ConvertTo-EntraOpsPackLineText -Line $line -ExcludeHref $exclude -MaxNames $MaxNames
                $finding = (@("$($lineText.Text)$(if ($lineText.Evidence) { ' — ' + $lineText.Evidence })", $lineText.LinkText) | Where-Object { $_ }) -join ' '
                $body.Add("| $(if ($firstRow) { $objectCell }) | $finding |")
                $firstRow = $false
                $shownResults += $line.Findings.Count
            }
            $shownRows += $shownLines.Count
            $hidden = $entry.Count - (@($shownLines | ForEach-Object { $_.Findings.Count }) | Measure-Object -Sum).Sum
            if ($hidden -gt 0 -and $shownRows -lt $MaxRows) {
                # The other findings of the object, in the Findings view.
                $body.Add("|  | ... and $(Get-EntraOpsPackCountText $hidden 'more finding') of this object.$(if ($findingsView) { ' ' + (ConvertTo-EntraOpsPackLinkText @([pscustomobject]@{ Label = 'Findings view'; Href = $findingsView })) }) |")
                $shownRows++
                $shownResults += $hidden
            }
            $shownObjects++
        }
    }
    # What the icons mean: the tiers and types of the objects of these tables.
    $output = [System.Collections.Generic.List[string]]::new()
    $legend = Get-EntraOpsPackLegend -Object @($objects | ForEach-Object { $_.Object })
    if ($legend) { $output.Add($legend); $output.Add('') }
    foreach ($line in $body) { $output.Add($line) }
    $remainingObjects = $objects.Count - $shownObjects
    $remainingResults = @($Results).Count - $shownResults
    if ($remainingResults -gt 0) {
        $output.Add('')
        $what = if ($ByObject) { Get-EntraOpsPackCountText $remainingObjects 'more object' } else { "$(Get-EntraOpsPackCountText $remainingResults 'more finding')$(if ($remainingObjects -gt 0) { " on $(Get-EntraOpsPackCountText $remainingObjects 'more object')" })" }
        $output.Add("... and $what. $(if ($ReportBase) { "The [EntraOps Findings view]($findingsView) lists all of them." } else { 'The EntraOps reports list all of them.' })")
    }
    $output.ToArray()
}

function ConvertTo-EntraOpsPackAcceptedTable {
    <#
    .SYNOPSIS
    The Markdown table of the findings of a rule that EntraOps finding exceptions accept: the object, the finding and the exception (state, expiry, reference, justification, who accepted it).
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory)]
        [object] $Rule,

        [AllowEmptyString()]
        [string] $PortalUrl,

        [int] $MaxRows = 20
    )

    $accepted = @($Rule.AcceptedResults | Where-Object { $_ })
    if (-not $accepted.Count) { return }
    '| Object | Finding and exception |'
    '| --- | --- |'
    foreach ($result in @($accepted | Select-Object -First $MaxRows)) {
        $exception = $result.Exception
        $expiresOn = if ($exception.ExpiresOn -is [datetime]) { $exception.ExpiresOn.ToString('yyyy-MM-dd', [cultureinfo]::InvariantCulture) } else { [string]$exception.ExpiresOn }
        $state = if ("$($exception.State)" -eq 'Dismissed') { 'Dismissed (false positive)' } else { 'Risk accepted' }
        $parts = @(
            "$state$(if ($expiresOn) { " until $expiresOn" })"
            $exception.Reference
            $exception.Justification
            $(if ($exception.AcceptedBy) { "by $($exception.AcceptedBy)$(if ($exception.AcceptedOn) { " on $(if ($exception.AcceptedOn -is [datetime]) { $exception.AcceptedOn.ToString('yyyy-MM-dd', [cultureinfo]::InvariantCulture) } else { $exception.AcceptedOn })" })" })
        ) | Where-Object { $_ }
        $object = Get-EntraOpsPackObjectInfo -Result $result -PortalUrl $PortalUrl
        $text = ConvertTo-EntraOpsPackFindingText -Split (Split-EntraOpsPackMessage (Get-EntraOpsPackResultDetail $result))
        "| $(ConvertTo-EntraOpsPackObjectText -Object $object -WithType -MaxNameLength 40) | $(if ($text) { "$text " })$(if ("$($exception.State)" -eq 'Dismissed') { '✔️' } else { '⚖️' }) $(ConvertTo-EntraOpsPackMarkdownCell ($parts -join ' · ')) |"
    }
    if ($accepted.Count -gt $MaxRows) { ''; "... and $(Get-EntraOpsPackCountText ($accepted.Count - $MaxRows) 'more accepted finding')." }
}

function Get-EntraOpsPackRuleSettingText {
    <#
    .SYNOPSIS
    The settings of a rule that EntraOps evaluated it with (Parameters, from EntraOpsConfig.json: the Findings section, or the root for ManagingTenantId and ManagingTenantName), as one line, or nothing.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [object] $Rule
    )

    if ($null -eq $Rule.Parameters) { return $null }
    $settings = @($Rule.Parameters.PSObject.Properties | Where-Object { $_.MemberType -eq 'NoteProperty' } | ForEach-Object {
            $value = if ($_.Value -is [System.Collections.IEnumerable] -and $_.Value -isnot [string]) { $(if (@($_.Value).Count) { @($_.Value) -join ', ' } else { 'none' }) } elseif ([string]::IsNullOrWhiteSpace([string]$_.Value)) { 'none' } else { [string]$_.Value }
            "$($_.Name): $value"
        })
    if (-not $settings.Count) { return $null }
    '🔧 ' + (ConvertTo-EntraOpsPackMarkdownCell "EntraOps settings of this check (EntraOpsConfig.json): $($settings -join '; ').")
}

function Test-EntraOpsPackObjectTierRule {
    <#
    .SYNOPSIS
    Whether the findings of a rule depend on the tier of the object, so that unclassified objects are listed last with the advice to classify them first.

    .DESCRIPTION
    The rules about principals of other tenants (EO.4002, EO.4010, EO.4011, EO.5001) judge the tier of the role
    assignments: classifying the object changes nothing in their result, and an object of another tenant cannot get
    custom security attributes of this tenant. Their findings keep the order of EntraOps (for EO.4010 by the tier of
    the role assignment) and show no advice to classify.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $RuleId
    )

    $RuleId -notin @('EO.4002', 'EO.4010', 'EO.4011', 'EO.5001')
}

function Get-EntraOpsPackCountText {
    <#
    .SYNOPSIS
    A number with its noun in the singular or plural: "1 finding", "3 findings", "2 policies" (-Plural).
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory, Position = 0)]
        [int] $Count,

        [Parameter(Mandatory, Position = 1)]
        [string] $Noun,

        [string] $Plural
    )

    "$Count $(if ($Count -eq 1) { $Noun } elseif ($Plural) { $Plural } else { "$($Noun)s" })"
}

function Join-EntraOpsPackName {
    <#
    .SYNOPSIS
    The first names of a list, and how many more there are.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [AllowEmptyCollection()]
        [string[]] $Name,

        [int] $Max = 5
    )

    (@($Name | Select-Object -First $Max) -join ', ') + $(if ($Name.Count -gt $Max) { " and $($Name.Count - $Max) more" })
}

function Get-EntraOpsPackExceptionText {
    <#
    .SYNOPSIS
    What the finding exceptions of a rule need: expired exceptions, exceptions that match no finding anymore and risk acceptances that expire soon.

    .DESCRIPTION
    Reads the Exceptions of the rule (with the Status that EntraOps gives them: Active, Expired, Stale, NotEvaluated)
    and the exceptions of its accepted results. An expired exception accepts nothing: its findings are reported
    again. A stale exception matches no finding: remove it from the EntraOps Finding Exceptions File. A risk
    acceptance that expires within SoonDays will report its finding again.
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory)]
        [object] $Rule,

        [int] $SoonDays = 30
    )

    $exceptions = @($Rule.Exceptions | Where-Object { $_ })
    $expired = @($exceptions | Where-Object { "$($_.Status)" -eq 'Expired' })
    $stale = @($exceptions | Where-Object { "$($_.Status)" -eq 'Stale' })
    $soon = @(foreach ($accepted in @($Rule.AcceptedResults | Where-Object { $_ -and "$($_.Exception.State)" -ne 'Dismissed' -and $_.Exception.ExpiresOn })) {
            $expiresOn = [datetime]::MinValue
            $hasDate = if ($accepted.Exception.ExpiresOn -is [datetime]) { $expiresOn = $accepted.Exception.ExpiresOn; $true } else { [datetime]::TryParse([string]$accepted.Exception.ExpiresOn, [cultureinfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AssumeUniversal, [ref]$expiresOn) }
            if ($hasDate -and $expiresOn.ToUniversalTime() -le [datetime]::UtcNow.AddDays($SoonDays)) {
                $name = if ($accepted.Instance.DisplayName) { $accepted.Instance.DisplayName } else { $accepted.Instance.ObjectId }
                "$name ($($expiresOn.ToString('yyyy-MM-dd', [cultureinfo]::InvariantCulture)))"
            }
        })
    if ($expired.Count) { '⌛ ' + (ConvertTo-EntraOpsPackMarkdownCell "$(Get-EntraOpsPackCountText $expired.Count 'finding exception') expired, so their findings count again: $(Join-EntraOpsPackName @($expired | ForEach-Object { if ($_.DisplayName) { [string]$_.DisplayName } elseif ($_.ObjectId) { [string]$_.ObjectId } else { [string]$_.InstanceId } })). Renew or remove them in the EntraOps Finding Exceptions File.") }
    if ($stale.Count) { '🧹 ' + (ConvertTo-EntraOpsPackMarkdownCell "$(Get-EntraOpsPackCountText $stale.Count 'finding exception') $(if ($stale.Count -eq 1) { 'matches' } else { 'match' }) no finding anymore: $(Join-EntraOpsPackName @($stale | ForEach-Object { if ($_.DisplayName) { [string]$_.DisplayName } elseif ($_.ObjectId) { [string]$_.ObjectId } else { [string]$_.InstanceId } })). Remove them from the EntraOps Finding Exceptions File.") }
    if ($soon.Count) { '⏰ ' + (ConvertTo-EntraOpsPackMarkdownCell "$(Get-EntraOpsPackCountText $soon.Count 'risk acceptance') $(if ($soon.Count -eq 1) { 'expires' } else { 'expire' }) within $SoonDays days: $(Join-EntraOpsPackName $soon).") }
}

function Add-EntraOpsPackAffectedObject {
    <#
    .SYNOPSIS
    The objects of a rule's results for the Maester affected objects, with their EntraOps tier as a fact.

    .DESCRIPTION
    Returns the users, groups, service principals and Conditional Access policies of the results as Graph
    objects (id, displayName, @odata.type) for Add-MtTestResultDetail -GraphObjects, which records them for the
    test when Maester collects the affected objects (Invoke-Maester -IncludeAffectedObjects): all of them, also
    those beyond the rows of the tables. App registrations have no Graph object type in Maester, which records them
    from their link (by appId). Adds the EntraOps tier of each of these objects to the Affected objects page
    (Add-MtAffectedObjectFact, Maester 3.0 or later; it does nothing when Maester does not collect them), unless
    -SkipTierFact: the Affected objects page shows one tier per object for all tests, so only rules whose results
    carry the classification of the object add it (not the tier of an access package resource or a PIM role).
    #>
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [AllowEmptyCollection()]
        [object[]] $Results,

        [AllowEmptyString()]
        [string] $PortalUrl,

        [AllowNull()]
        [Nullable[datetime]] $AsOf,

        [switch] $SkipTierFact
    )

    $objects = @{}
    foreach ($result in @($Results | Where-Object { $_ })) {
        # Any URL marks the types that Maester lists; the links themselves are built by Maester.
        $object = Get-EntraOpsPackObjectInfo -Result $result -PortalUrl $(if ($PortalUrl) { $PortalUrl } else { 'https://entra.microsoft.com/' })
        if ($object.AffectedType -and -not $objects.ContainsKey("$($object.AffectedType)|$($object.AffectedId)")) { $objects["$($object.AffectedType)|$($object.AffectedId)"] = $object }
    }
    $graphObjects = @($objects.Values | Where-Object { $_.ODataType } | Sort-Object Name | ForEach-Object { [pscustomobject]@{ id = $_.Id; displayName = $_.Name; '@odata.type' = $_.ODataType } })

    $facts = @($objects.Values | Where-Object { $_.Tier -and -not $SkipTierFact } | ForEach-Object {
            [pscustomobject]@{
                Type = $_.AffectedType
                Id   = $_.AffectedId
                Fact = @(@{ Name = 'EntraOps tier'; Value = $(if ($_.TierKey -eq 'Unclassified') { 'Unclassified (counted as User Access)' } else { $_.Tier }); Tone = $(if ($_.TierKey -eq 'Unclassified') { 'Warning' } else { 'Info' }) })
            }
        })
    if ($facts.Count -and (Test-EntraOpsPackMaesterCommand -Name Add-MtAffectedObjectFact)) {
        $factParameters = @{ Source = 'EntraOps' }
        if ($AsOf) { $factParameters.AsOf = $AsOf }
        $facts | Add-MtAffectedObjectFact @factParameters
    }
    $graphObjects
}

function Update-EntraOpsPackExpiredAcceptance {
    <#
    .SYNOPSIS
    Reopens the accepted instances whose finding exception expired after EntraOps evaluated the rule.

    .DESCRIPTION
    findings.json keeps the exceptions as they were on the day of the evaluation. An exception that expired since
    then (ExpiresOn before today, UTC, like the evaluation in EntraOps and the EntraOps reports) no longer accepts
    its instance: the instance counts as open, the rule as failed, and the reason names the expired exceptions.
    Returns a copy of the rule; the cached results stay unchanged.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object] $Rule
    )

    if ("$($Rule.Status)" -notin 'Passed', 'Failed') { return $Rule }
    $today = (Get-Date).ToUniversalTime().ToString('yyyy-MM-dd', [cultureinfo]::InvariantCulture)
    $accepted = @($Rule.AcceptedResults | Where-Object { $null -ne $_ })
    $expired = @($accepted | Where-Object {
            $expiresOn = $_.Exception.ExpiresOn
            # A date that ConvertFrom-Json read as local time is the UTC date of the file (like the evaluation in EntraOps).
            $date = if ($expiresOn -is [datetime]) { $(if ($expiresOn.Kind -eq [System.DateTimeKind]::Local) { $expiresOn.ToUniversalTime() } else { $expiresOn }).ToString('yyyy-MM-dd', [cultureinfo]::InvariantCulture) } else { "$expiresOn" }
            $date.Length -ge 10 -and $date.Substring(0, 10) -match '^\d{4}-\d{2}-\d{2}$' -and [string]::CompareOrdinal($date.Substring(0, 10), $today) -lt 0
        })
    if ($expired.Count -eq 0) { return $Rule }

    $copy = $Rule.PSObject.Copy()
    $names = @($expired | ForEach-Object {
            $name = if ($_.Instance.DisplayName) { $_.Instance.DisplayName } elseif ($_.Instance.ObjectId) { $_.Instance.ObjectId } else { $_.Instance.Id }
            $value = $_.Exception.ExpiresOn
            $expiresOn = if ($value -is [datetime]) { $(if ($value.Kind -eq [System.DateTimeKind]::Local) { $value.ToUniversalTime() } else { $value }).ToString('yyyy-MM-dd', [cultureinfo]::InvariantCulture) } else { "$value".Substring(0, 10) }
            "$name (expired $expiresOn)"
        })
    $note = "$($expired.Count) finding exception(s) expired after the evaluation, so their instances are open again: $(($names | Select-Object -First 10) -join ', ')$(if ($names.Count -gt 10) { " and $($names.Count - 10) more" }). Renew or remove the exceptions in the EntraOps Finding Exceptions File."
    $copy | Add-Member -NotePropertyName AcceptedResults -NotePropertyValue @($accepted | Where-Object { $expired -notcontains $_ }) -Force
    $copy | Add-Member -NotePropertyName AcceptedCount -NotePropertyValue ([Math]::Max(0, [int]$Rule.AcceptedCount - $expired.Count)) -Force
    $copy | Add-Member -NotePropertyName Results -NotePropertyValue @(@($Rule.Results | Where-Object { $null -ne $_ }) + $expired) -Force
    $copy | Add-Member -NotePropertyName FailedCount -NotePropertyValue ([int]$Rule.FailedCount + $expired.Count) -Force
    $copy | Add-Member -NotePropertyName Status -NotePropertyValue 'Failed' -Force
    $copy | Add-Member -NotePropertyName Reason -NotePropertyValue $(if ("$($Rule.Reason)") { "$note $($Rule.Reason)" } else { $note }) -Force
    if ($null -eq $copy.PSObject.Properties['ReasonCode'] -or -not $copy.ReasonCode) { $copy | Add-Member -NotePropertyName ReasonCode -NotePropertyValue 'Note' -Force }
    $copy
}

function Get-EntraOpsPackAcceptedFinding {
    <#
    .SYNOPSIS
    Splits the instances a rule accepted by EntraOps finding exceptions into risk-accepted and dismissed ones.

    .DESCRIPTION
    RiskAcceptedCount counts the risk-accepted instances and RiskAccepted names them (object, expiry date and
    reference; the first MaxNames), DismissedCount counts the dismissed ones. Accepted instances without their exception in findings.json
    count as risk accepted, so they never pass the test.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object] $Rule,

        [int] $MaxNames = 10
    )

    $results = @($Rule.AcceptedResults | Where-Object { $null -ne $_ })
    $dismissed = @($results | Where-Object { "$($_.Exception.State)" -eq 'Dismissed' }).Count
    $risks = @($results | Where-Object { "$($_.Exception.State)" -ne 'Dismissed' } | ForEach-Object {
            $name = if ($_.Instance.DisplayName) { $_.Instance.DisplayName } elseif ($_.Instance.ObjectId) { $_.Instance.ObjectId } else { $_.Instance.Id }
            $details = @($(if ($_.Exception.ExpiresOn) { "until $($_.Exception.ExpiresOn)" }), $_.Exception.Reference) | Where-Object { $_ }
            # Names and references come from the tenant and the exceptions file: safe for the Markdown of the result.
            ConvertTo-EntraOpsPackMarkdownCell "$name$(if ($details) { " ($($details -join ', '))" })"
        })
    # Accepted instances that findings.json counts but doesn't list (no exception details).
    $unlisted = [Math]::Max(0, [int]$Rule.AcceptedCount - $results.Count)
    $names = [System.Collections.Generic.List[string]]::new()
    foreach ($risk in @($risks | Select-Object -First $MaxNames)) { $names.Add($risk) }
    $more = $risks.Count - $names.Count + $unlisted
    if ($more -gt 0) { $names.Add("$more more") }
    [pscustomobject]@{
        RiskAcceptedCount = $risks.Count + $unlisted
        RiskAccepted      = $(if ($names.Count) { @($names) } else { @() })
        DismissedCount    = $dismissed
    }
}

function ConvertTo-EntraOpsPackMarkdownCell {
    <#
    .SYNOPSIS
    Makes a value safe for one line of Markdown (a line of a list or a cell of a table).
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        [AllowEmptyString()]
        $Value
    )

    # Names, reasons and references come from the tenant and the exceptions file: a backslash, bracket or backtick in
    # them must not start a link or code ("Helpdesk\](https://...) [x" would otherwise replace the link of an object).
    ("$Value" -replace '([\\`\[\]])', '\$1' -replace '[\r\n]+', ' ' -replace '\|', '\|' -replace '<', '&lt;' -replace '>', '&gt;' -replace '@', '\@').Trim()
}

function ConvertTo-EntraOpsPackTestReference {
    <#
    .SYNOPSIS
    Names the Maester tests instead of the EntraOps rules that a reason of EntraOps refers to.

    .DESCRIPTION
    A reason of EntraOps can send the reader to another rule ("Classify these objects (EO.2001)"). In Maester that
    check is a test of the pack (MP.EOPS.2001), as the pack's own text names it. The rule of the reason itself stays
    an EntraOps rule: the text around it names that rule and links to it in the EntraOps Findings view. A rule
    without a test of the pack stays as it is.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [AllowNull()]
        [AllowEmptyString()]
        [string] $Text,

        # The rules of the finding results, with the Maester test of each rule (MaesterTestId).
        [object[]] $Rules,

        # The rule of the reason, which keeps its EntraOps ID.
        [string] $RuleId
    )

    if (-not $Text) { return $Text }
    foreach ($id in @([regex]::Matches($Text, '\bEO\.\d{4}\b') | ForEach-Object Value | Select-Object -Unique)) {
        if ($id -eq $RuleId) { continue }
        $testId = @($Rules | Where-Object { $_.RuleId -eq $id -and $_.MaesterTestId } | ForEach-Object { [string]$_.MaesterTestId }) | Select-Object -First 1
        if ($testId) { $Text = $Text -creplace "\b$([regex]::Escape($id))\b", $testId }
    }
    $Text
}

function Test-EntraOpsPackFinding {
    <#
    .SYNOPSIS
    Reports the result of one EntraOps finding rule from findings.json.

    .DESCRIPTION
    Passed when EntraOps evaluated the rule and no instance failed, Failed with tables of the affected
    instances when at least one failed. Instances accepted by a finding exception of EntraOps don't fail the
    test: dismissed instances (false positives) pass it, and a rule without open instances but with
    risk-accepted ones is skipped with the accepted risks as the reason, so they stay visible. Skipped also
    when the rule is excluded or deprecated in EntraOps, had nothing to evaluate, lacked its data (for example
    the report data of the PIM Request Flow rules), or is missing from findings.json (for example results of
    an older EntraOps version). An error when the evaluation of the rule failed in EntraOps (status Error):
    its result is unknown, so the test neither passes nor is skipped.

    A rule that only asks for a review of its results (Investigate in the EntraOps rule catalog, for example
    custom roles with Control Plane permissions) reports them as Investigate instead of Failed.

    The tables of a failed rule link each object to the Microsoft Entra admin center and to the EntraOps reports
    that show it (the PIM Request Flow, Access Package Flow, Conditional Access Analysis, Configuration Analyzer,
    Tier Breach Analyzer, EAM Dashboard and Access Path Map, when the reports are found: EntraOps.ReportsPath),
    and adds the evidence that the message does not name (PIM assignment type, scope, groups). Every result links
    the rule in the Findings view of the Privileged Assets report. The users, groups, service principals, app
    registrations and Conditional Access policies of the results are the affected objects of the test in Maester
    (Invoke-Maester -IncludeAffectedObjects), with their EntraOps tier from the rules that judge the classification
    of the object (Tier Breach, Privileged Assets, Privileged EAM and Privilege History). A rule skipped because only unclassified
    objects are affected lists these objects. The data gaps of the evaluation that affect the rule (DataGaps of
    findings.json) are named with its result.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        # The EntraOps rule ID, for example EO.1001.
        [Parameter(Mandatory)]
        [string] $RuleId,

        # The most affected instances listed in the result.
        [int] $MaxRows = 50
    )

    $findingSet = Get-EntraOpsPackFindingSet
    if ($null -eq $findingSet) { return }

    $rule = @($findingSet.Rules | Where-Object { $_.RuleId -eq $RuleId }) | Select-Object -First 1
    if ($null -eq $rule) {
        Add-MtTestResultDetail -SkippedBecause Custom -SkippedCustomReason "The EntraOps finding results have no result for rule $RuleId. The rule may be evaluated by a newer EntraOps version than the one that wrote the results."
        return
    }
    # Exceptions that expired since the evaluation no longer accept their instances.
    $rule = Update-EntraOpsPackExpiredAcceptance -Rule $rule

    # The tenant of the results: Maester compares it only while Microsoft Graph is connected (not with -SkipGraphConnect).
    $tenant = if ($findingSet.TenantName) { [string]$findingSet.TenantName } elseif ($findingSet.TenantId) { [string]$findingSet.TenantId } else { $null }
    $source = "EntraOps $(ConvertTo-EntraOpsPackMarkdownCell ([string]$findingSet.Generator.Version)) results of $(if ($tenant) { "$(ConvertTo-EntraOpsPackMarkdownCell $tenant), " })$(ConvertTo-EntraOpsPackMarkdownCell ([string]$findingSet.GeneratedText))"
    # Structured reason category emitted by EntraOps (ReasonCode).
    $reasonCode = if ($null -ne $rule.PSObject.Properties['ReasonCode'] -and $rule.ReasonCode) { [string]$rule.ReasonCode } else { $null }
    # The reason as the results show it: other rules it refers to are named by their Maester test.
    $ruleReason = ConvertTo-EntraOpsPackTestReference -Text ([string]$rule.Reason) -Rules @($findingSet.Rules) -RuleId $RuleId
    # The note of a Failed or Passed rule: data it could not evaluate, or a hint how to fix the results.
    $note = if ($ruleReason -and $rule.Status -in 'Failed', 'Passed') { "Note: $(ConvertTo-EntraOpsPackMarkdownCell $ruleReason)" } else { $null }
    # The links of the results: to the EntraOps reports (when found) and to the Microsoft Entra admin center.
    $reportBase = [string]$findingSet.ReportBase
    $portalUrl = Get-EntraOpsPackPortalUrl
    $findingsView = if ($reportBase) { "🔎 [Open $RuleId in the EntraOps Findings view]($($reportBase)PrivilegedAssets/index.html?view=findings#rule=$([uri]::EscapeDataString($RuleId)))" } else { $null }
    # A setting EntraOps.ReportsPath without the reports: the results say why they have no report links.
    $reportsNote = if ($null -ne $findingSet.PSObject.Properties['ReportsNote'] -and $findingSet.ReportsNote) { "📝 $(ConvertTo-EntraOpsPackMarkdownCell $findingSet.ReportsNote)" }
    # Principals of the Global Exclusion List of EntraOps (Classification/Global.json) are not in the Privileged EAM data,
    # so the rules that evaluate it do not cover their privileged access.
    $exclusionCount = if ($null -ne $findingSet.PSObject.Properties['GlobalExclusions'] -and $null -ne $findingSet.GlobalExclusions) { [int]$findingSet.GlobalExclusions.Count } else { 0 }
    $exclusionNote = if ($exclusionCount -gt 0 -and "$($rule.Area)" -in 'TierBreach', 'PrivilegedAssets', 'PrivilegedEAM', 'PrivilegeHistory') {
        "ℹ️ $(Get-EntraOpsPackCountText -Count $exclusionCount -Noun 'principal') of the Global Exclusion List of EntraOps ($(ConvertTo-EntraOpsPackMarkdownCell ([string]$findingSet.GlobalExclusions.FilePath))) $(if ($exclusionCount -eq 1) { 'is' } else { 'are' }) not in the Privileged EAM data, so this check does not cover $(if ($exclusionCount -eq 1) { 'its' } else { 'their' }) privileged access."
    }
    # GroupOriginUnknown and RemoteGroupMembersMissing are reported by EO.4010 and EO.4011 themselves, scoped to what each evaluates.
    $gapNotes = @(if (("$($rule.Status)" -in 'Passed', 'Failed' -or $reasonCode -eq 'Unclassified') -and $null -ne $findingSet.PSObject.Properties['DataGaps']) {
            @($findingSet.DataGaps) | Where-Object { $_ -and "$($_.Message)" -and @($_.RuleIds) -contains $RuleId -and "$($_.Code)" -notin 'GroupOriginUnknown', 'RemoteGroupMembersMissing' } |
                ForEach-Object { "⚠️ $(ConvertTo-EntraOpsPackMarkdownCell "Data gap: $($_.Message)")" }
        })
    $footer = (@($exclusionNote) + $gapNotes + @($findingsView, $reportsNote, "_$($source)_") | Where-Object { $_ }) -join "`n`n"
    # The settings EntraOps evaluated the rule with, and what its finding exceptions need.
    $context = @(@(Get-EntraOpsPackRuleSettingText -Rule $rule) + @(Get-EntraOpsPackExceptionText -Rule $rule) | Where-Object { $_ })
    $contextText = if ($context.Count) { "`n`n" + ($context -join "`n`n") } else { '' }
    switch ([string]$rule.Status) {
        'Excluded' {
            # Excluded in EntraOpsConfig.json (Findings.ExcludedRules), or deprecated in EntraOps (with the reason).
            $why = if ($ruleReason) { $ruleReason } else { 'It is excluded in the EntraOps configuration (Findings.ExcludedRules).' }
            $reason = "EntraOps did not evaluate rule $($RuleId): $why"
            Add-MtTestResultDetail -SkippedBecause Custom -SkippedCustomReason $reason -Result "Skipped. $(ConvertTo-EntraOpsPackMarkdownCell $reason)`n`n$footer"
            return
        }
        'Error' {
            # Maester reports a thrown error as the result Error with its message (ReasonCode TestError). The result
            # detail recorded first replaces the error record (with the line of this file) in the report.
            $why = if ($ruleReason) { $ruleReason } else { 'No reason was recorded.' }
            $message = "EntraOps could not evaluate rule $($RuleId): $why"
            Add-MtTestResultDetail -Result "$(ConvertTo-EntraOpsPackMarkdownCell $message)`n`nRun the EntraOps evaluation again (Invoke-EntraOpsAssessment or New-EntraOpsReportingData).`n`n$footer"
            throw $message
        }
        'Skipped' {
            # Nothing in the scope of the rule is not applicable; only unclassified objects affected needs their
            # classification; any other reason is data the rule was missing.
            $notApplicable = $reasonCode -eq 'NotApplicable' -or (-not $reasonCode -and (-not $rule.Reason -or $rule.Reason -match 'in the scope of this rule \(0 evaluated\)'))
            if ($notApplicable) {
                # The reason says why, for example that another rule reports it: the result keeps it next to Maester's reason.
                $why = if ($ruleReason) { "Skipped. EntraOps did not evaluate rule $($RuleId) because it does not apply: $(ConvertTo-EntraOpsPackMarkdownCell $ruleReason)$contextText`n`n$footer" } else { $null }
                Add-MtTestResultDetail -SkippedBecause NotApplicable -Result $why
            } elseif ($reasonCode -eq 'Unclassified' -or (-not $reasonCode -and $rule.Reason -like 'Only unclassified objects are affected*')) {
                # The unclassified objects that the rule would report once they are classified, by object.
                $reason = "EntraOps did not report rule $($RuleId): $ruleReason"
                $unclassified = @($rule.UnclassifiedResults | Where-Object { $_ })
                $lines = [System.Collections.Generic.List[string]]::new()
                $lines.Add("Skipped. $(ConvertTo-EntraOpsPackMarkdownCell $reason)")
                if ($unclassified.Count) {
                    $lines.Add('')
                    $lines.Add('The unclassified objects that this check would evaluate once they are classified:')
                    $lines.Add('')
                    foreach ($line in (ConvertTo-EntraOpsPackResultTable -Rule $rule -Results $unclassified -ReportBase $reportBase -PortalUrl $portalUrl -MaxRows $MaxRows -ByObject)) { $lines.Add($line) }
                }
                $lines.Add('')
                $lines.Add($footer)
                Add-MtTestResultDetail -SkippedBecause Custom -SkippedCustomReason $reason -Result ($lines -join "`n")
            } else {
                $reason = "EntraOps could not evaluate rule $($RuleId): $ruleReason"
                Add-MtTestResultDetail -SkippedBecause Custom -SkippedCustomReason $reason -Result "Skipped. $(ConvertTo-EntraOpsPackMarkdownCell $reason)`n`n$footer"
            }
            return
        }
        'Passed' {
            $accepted = Get-EntraOpsPackAcceptedFinding -Rule $rule
            if ($accepted.RiskAcceptedCount -gt 0) {
                # The control is not met, but its risk is accepted: neither a pass nor a failure.
                $reason = "Risk accepted in EntraOps: $(Get-EntraOpsPackCountText $accepted.RiskAcceptedCount 'affected instance') of $($rule.EvaluatedCount) evaluated, no open one ($($accepted.RiskAccepted -join '; '))$(if ($accepted.DismissedCount) { "; $($accepted.DismissedCount) more dismissed as false positives" }). Renew or remove the exceptions in the EntraOps Finding Exceptions File."
                $list = @(ConvertTo-EntraOpsPackAcceptedTable -Rule $rule -PortalUrl $portalUrl)
                Add-MtTestResultDetail -SkippedBecause Custom -SkippedCustomReason $reason -Result "Skipped. $reason$contextText$(if ($list.Count) { "`n`n" + ($list -join "`n") })`n`n$footer"
                return
            }
            $dismissed = if ($accepted.DismissedCount) { " $(Get-EntraOpsPackCountText $accepted.DismissedCount 'affected instance') $(if ($accepted.DismissedCount -eq 1) { 'is' } else { 'are' }) dismissed as false positives in the EntraOps finding exceptions." } else { '' }
            Add-MtTestResultDetail -Result "✅ Well done. EntraOps evaluated $(Get-EntraOpsPackCountText ([int]$rule.EvaluatedCount) 'instance') and none is affected.$dismissed$(if ($note) { "`n`n📝 $note" })$contextText`n`n$footer"
            return $true
        }
        'Failed' {
            $results = @($rule.Results | Where-Object { $_ })
            $lines = [System.Collections.Generic.List[string]]::new()
            # Several instances can concern one object, for example its role assignments at several scopes.
            $objectCount = @($results | ForEach-Object { if ($_.Instance.ObjectId) { [string]$_.Instance.ObjectId } else { [string]$_.Instance.Id } } | Select-Object -Unique).Count
            # A rule that asks for a review of its results (Investigate in the EntraOps rule catalog) is not a failed control.
            $investigate = $null -ne $rule.PSObject.Properties['Investigate'] -and $rule.Investigate -eq $true
            # The summary: one paragraph per line, each with its icon.
            $summary = [System.Collections.Generic.List[string]]::new()
            $summary.Add("$(if ($investigate) { '🕵️' } else { '❌' }) EntraOps found $(if ($investigate) { "$(Get-EntraOpsPackCountText ([int]$rule.FailedCount) 'instance') to investigate" } else { Get-EntraOpsPackCountText ([int]$rule.FailedCount) 'affected instance' }) of $($rule.EvaluatedCount) evaluated$(if ($objectCount -gt 0 -and $objectCount -lt $results.Count) { ", on $(Get-EntraOpsPackCountText $objectCount 'object')" }).")
            # Findings on unclassified objects count (for example access to the Control Plane), but their tier is
            # unknown: classifying these objects comes first. Not for the rule that reports the classification itself.
            $onUnclassified = @($results | Where-Object { "$($_.Instance.AdminTierLevelName)" -eq 'Unclassified' })
            if ($onUnclassified.Count -and $RuleId -ne 'EO.2001' -and (Test-EntraOpsPackObjectTierRule -RuleId $RuleId)) {
                $unclassifiedIds = @($onUnclassified | ForEach-Object { if ($_.Instance.ObjectId) { [string]$_.Instance.ObjectId } else { [string]$_.Instance.Id } } | Select-Object -Unique)
                # EO.2001 asks for the classification of an object, but not of every one: it does not report the service
                # principals of Microsoft first-party applications. Only the objects it lists are sent there.
                $classification = @($findingSet.Rules | Where-Object { $_.RuleId -eq 'EO.2001' }) | Select-Object -First 1
                $listedIds = @(@($classification.Results) + @($classification.AcceptedResults) | Where-Object { $_ } | ForEach-Object { [string]$_.Instance.ObjectId })
                $notListed = if ($listedIds.Count) { @($unclassifiedIds | Where-Object { $_ -notin $listedIds }).Count } else { 0 }
                $toClassify = $unclassifiedIds.Count - $notListed
                $hint = if ($toClassify -gt 0) { "classify $(if ($notListed) { "the $toClassify that MP.EOPS.2001 reports first" } elseif ($toClassify -eq 1) { 'this object first (MP.EOPS.2001)' } else { 'these objects first (MP.EOPS.2001)' }), as $(if ($toClassify -eq 1 -and -not $notListed) { 'its tier decides what applies to it' } else { 'their tier decides what applies to them' })." } else { '' }
                if ($notListed) { $hint = "$hint $(if ($toClassify -gt 0) { "The other $(if ($notListed -eq 1) { 'one' } else { $notListed })" } else { $(if ($notListed -eq 1) { 'It' } else { 'They' }) }) $(if ($notListed -eq 1) { 'is' } else { 'are' }) not reported by MP.EOPS.2001 (for example service principals of Microsoft first-party applications, which Microsoft operates): review $(if ($notListed -eq 1) { 'its' } else { 'their' }) access instead.".Trim() }
                $summary.Add("❔ $(if ($results.Count -eq 1) { 'It is' } elseif ($onUnclassified.Count -eq $results.Count) { 'All of them are' } else { "$($onUnclassified.Count) of them $(if ($onUnclassified.Count -eq 1) { 'is' } else { 'are' })" }) on $(Get-EntraOpsPackCountText $unclassifiedIds.Count 'unclassified object'), listed last$(if ($toClassify -gt 0) { ': ' } else { '. ' })$hint")
            }
            if ($investigate) { $summary.Add('💡 This check asks for a review: confirm that each of them is intended, and change or accept (finding exception) the others.') }
            $accepted = Get-EntraOpsPackAcceptedFinding -Rule $rule
            if ($accepted.RiskAcceptedCount -gt 0) { $summary.Add("⚖️ $(Get-EntraOpsPackCountText $accepted.RiskAcceptedCount 'more instance') $(if ($accepted.RiskAcceptedCount -eq 1) { 'is' } else { 'are' }) risk accepted in the EntraOps finding exceptions and listed apart: $($accepted.RiskAccepted -join '; ').") }
            if ($accepted.DismissedCount -gt 0) { $summary.Add("✔️ $(Get-EntraOpsPackCountText $accepted.DismissedCount 'more instance') $(if ($accepted.DismissedCount -eq 1) { 'is' } else { 'are' }) dismissed as false positives in the EntraOps finding exceptions and listed apart.") }
            $unclassified = @($rule.UnclassifiedResults | Where-Object { $_ })
            if ([int]$rule.UnclassifiedCount -gt 0) { $summary.Add("❔ $(Get-EntraOpsPackCountText ([int]$rule.UnclassifiedCount) 'more instance') of unclassified objects $(if ([int]$rule.UnclassifiedCount -eq 1) { 'is' } else { 'are' }) not counted$(if ($unclassified.Count) { ' and listed apart' }): classify these objects (MP.EOPS.2001) to evaluate them.") }
            if ($note) { $summary.Add("📝 $note") }
            foreach ($line in $context) { $summary.Add($line) }
            $lines.Add($summary -join "`n`n")
            $lines.Add('')
            foreach ($line in (ConvertTo-EntraOpsPackResultTable -Rule $rule -Results $results -ReportBase $reportBase -PortalUrl $portalUrl -MaxRows $MaxRows)) { $lines.Add($line) }
            $acceptedTable = @(ConvertTo-EntraOpsPackAcceptedTable -Rule $rule -PortalUrl $portalUrl)
            if ($acceptedTable.Count) {
                $lines.Add('')
                $lines.Add('**⚖️ Accepted findings** (finding exceptions, not counted)')
                $lines.Add('')
                foreach ($line in $acceptedTable) { $lines.Add($line) }
            }
            if ($unclassified.Count) {
                $lines.Add('')
                $lines.Add('**❔ Unclassified objects** (not counted: classify them, see MP.EOPS.2001)')
                $lines.Add('')
                foreach ($line in (ConvertTo-EntraOpsPackResultTable -Rule $rule -Results $unclassified -ReportBase $reportBase -PortalUrl $portalUrl -MaxRows $MaxRows -ByObject)) { $lines.Add($line) }
            }
            $lines.Add('')
            $lines.Add($footer)
            # All affected objects (also those beyond the tables) for the affected objects of Maester, with their tier
            # when the results carry the classification of the object (the Access Package Flow and PIM Request Flow
            # rules carry the tier of the resource or role instead).
            $graphObjects = @(Add-EntraOpsPackAffectedObject -Results $results -PortalUrl $portalUrl -AsOf $findingSet.GeneratedAtUtc -SkipTierFact:("$($rule.Area)" -notin 'TierBreach', 'PrivilegedAssets', 'PrivilegedEAM', 'PrivilegeHistory'))
            $detail = @{ Result = ($lines -join "`n") }
            if ($graphObjects.Count) { $detail.GraphObjects = $graphObjects }
            if ($investigate) {
                Add-MtTestResultDetail @detail -Investigate
                return $true
            }
            Add-MtTestResultDetail @detail
            return $false
        }
        default {
            Add-MtTestResultDetail -SkippedBecause Custom -SkippedCustomReason "Rule $RuleId has the status '$($rule.Status)', which this version of the pack does not know."
            return
        }
    }
}
