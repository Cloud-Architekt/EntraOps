function Read-EntraOpsFindingExceptionFile {
    <#
    .SYNOPSIS
        Reads the finding exceptions (dismissed and risk-accepted findings) of the Finding Exceptions File.
    .DESCRIPTION
        The Finding Exceptions File (Findings.ExceptionsFilePath, default ./Classification/FindingExceptions.json)
        is a JSON array of exceptions, each for results of one finding rule. The Privileged Assets Findings view
        exports it. The fields of an exception:
          * RuleId (required): the rule, for example EO.3001.
          * InstanceId: the finding instance (Instance.Id of the result). Without it, ObjectId: all results of
            the rule for this object. One of them is required; with InstanceId, ObjectId is for information.
          * State (required): RiskAccepted (the risk is known and accepted until ExpiresOn) or Dismissed (a false
            positive, optionally until ExpiresOn).
          * Justification (required), AcceptedBy, AcceptedOn and ExpiresOn (dates, yyyy-MM-dd; the exception
            applies until the end of ExpiresOn), Reference (for example a change or ticket number) and
            DisplayName (of the object, for people reading the file).
        A risk-accepted exception needs AcceptedOn and ExpiresOn, at most MaxDays apart: a later ExpiresOn is
        shortened to AcceptedOn + MaxDays with a warning. MaxDays counts from today when AcceptedOn is in the
        future, so an exception never applies longer than MaxDays from now. Dates are taken as written in the
        file (a date with a time and an offset keeps its own day, it is converted neither to UTC nor to the time
        zone of the computer, on every PowerShell version) and compared with today in UTC; an ExpiresOn before
        AcceptedOn and an AcceptedOn in the future are reported with a warning. Expired exceptions are returned (Expired) with a
        warning: their findings are reported again. Invalid entries, entries of unknown rules and repeated
        entries (same rule, instance or object) are skipped with a warning. A missing file has no exceptions.
    .PARAMETER FilePath
        Path of the file, relative to RootFolder or absolute. Must resolve inside RootFolder.
    .PARAMETER RootFolder
        Folder the path is relative to: the EntraOps folder (the folder of EntraOpsConfig.json).
    .PARAMETER MaxDays
        Longest time a risk can be accepted, in days (Findings.ExceptionMaxDays). 0 for no limit.
    .OUTPUTS
        One object per exception: Key (rule, instance and object, lowercase), RuleId, InstanceId, ObjectId,
        DisplayName, State, Justification, AcceptedBy, AcceptedOn, ExpiresOn, Reference and Expired.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$FilePath,

        [Parameter(Mandatory = $true)]
        [string]$RootFolder,

        [Parameter(Mandatory = $false)]
        [int]$MaxDays = 0
    )

    $ResolvedPath = if ([System.IO.Path]::IsPathFullyQualified($FilePath)) { [System.IO.Path]::GetFullPath($FilePath) } else { [System.IO.Path]::GetFullPath([System.IO.Path]::Combine($RootFolder, $FilePath)) }
    if (-not (Test-EntraOpsPathWithinRoot -Path $ResolvedPath -Root $RootFolder)) {
        Write-Warning "Finding Exceptions File '$FilePath' resolves to '$ResolvedPath', which is outside the EntraOps folder '$RootFolder'. No finding exceptions are applied."
        return
    }
    if (-not (Test-Path -LiteralPath $ResolvedPath -PathType Leaf)) { return }
    try {
        # Dates stay text where PowerShell supports it (7.5 and later), so their day is never converted to local time.
        $JsonParameters = @{ NoEnumerate = $true }
        if ((Get-Command ConvertFrom-Json).Parameters.ContainsKey('DateKind')) { $JsonParameters.DateKind = 'String' }
        $Json = Get-Content -LiteralPath $ResolvedPath -Raw -Encoding UTF8
        $Entries = @($Json | ConvertFrom-Json @JsonParameters)
        if ($Entries.Count -eq 1 -and $Entries[0] -is [System.Array]) { $Entries = @($Entries[0]) }
        # PowerShell 7.4 converts a date with a time to a local date and loses its offset: the text of the file is used instead.
        $DateTexts = @(Get-EntraOpsFindingExceptionDateText -Json $Json)
    } catch {
        Write-Warning "The Finding Exceptions File '$ResolvedPath' could not be read, no finding exceptions are applied: $($_.Exception.Message)"
        return
    }

    $RuleIds = @{}
    foreach ($Rule in @(Get-EntraOpsFindingRule)) { $RuleIds[$Rule.Id.ToUpperInvariant()] = $Rule.Id }
    $Today = (Get-Date).ToUniversalTime().Date
    $Keys = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $Problems = [System.Collections.Generic.List[string]]::new()
    $Expired = [System.Collections.Generic.List[string]]::new()
    $Number = 0
    foreach ($Entry in $Entries) {
        $Number++
        if ($null -eq $Entry -or $Entry -isnot [pscustomobject]) { $Problems.Add("entry $($Number): not an object"); continue }
        $Text = { param($Name) "$(Get-EntraOpsPropertyValue $Entry $Name)".Trim() }
        $RuleId = & $Text 'RuleId'
        $InstanceId = & $Text 'InstanceId'
        $ObjectId = & $Text 'ObjectId'
        $State = & $Text 'State'
        $Justification = & $Text 'Justification'
        $Label = "entry $Number ($(if ($RuleId) { $RuleId } else { 'no RuleId' }))"

        if (-not $RuleIds.ContainsKey($RuleId.ToUpperInvariant())) { $Problems.Add("$($Label): unknown rule"); continue }
        $RuleId = $RuleIds[$RuleId.ToUpperInvariant()]
        if (-not $InstanceId -and -not $ObjectId) { $Problems.Add("$($Label): InstanceId or ObjectId is required"); continue }
        $State = @('RiskAccepted', 'Dismissed') | Where-Object { $_ -eq $State } | Select-Object -First 1
        if (-not $State) { $Problems.Add("$($Label): State must be RiskAccepted or Dismissed"); continue }
        if (-not $Justification) { $Problems.Add("$($Label): Justification is required"); continue }

        $Dates = @{}
        $DateError = $null
        foreach ($Name in 'AcceptedOn', 'ExpiresOn') {
            $Raw = Get-EntraOpsPropertyValue $Entry $Name
            # The date as written in the file. Text is parsed with its own offset, so the day of "2026-06-30" or
            # "2026-06-30T00:00:00+02:00" stays 2026-06-30 on every computer (no conversion to UTC or local time).
            $Written = if ($Number -le $DateTexts.Count -and $null -ne $DateTexts[$Number - 1]) { $DateTexts[$Number - 1][$Name] } else { $null }
            if ($Written) { $Raw = $Written }
            # A date the JSON reader converted cannot give its day as written without the text of the file.
            if ($Raw -is [datetime] -or $Raw -is [datetimeoffset]) { $DateError = "$Name could not be read as written, write it as yyyy-MM-dd"; break }
            $Value = "$Raw".Trim()
            if (-not $Value) { continue }
            $Parsed = [datetimeoffset]::MinValue
            if (-not [datetimeoffset]::TryParse($Value, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AssumeUniversal, [ref]$Parsed)) { $DateError = "$Name '$Value' is not a date (yyyy-MM-dd)"; break }
            $Dates[$Name] = $Parsed.Date
        }
        if ($DateError) { $Problems.Add("$($Label): $DateError"); continue }
        if ($Dates.ContainsKey('AcceptedOn') -and $Dates.ContainsKey('ExpiresOn') -and $Dates.ExpiresOn -lt $Dates.AcceptedOn) {
            Write-Warning "Finding exception $Label expires on $($Dates.ExpiresOn.ToString('yyyy-MM-dd')), before it was accepted on $($Dates.AcceptedOn.ToString('yyyy-MM-dd')). Check the dates."
        }
        if ($Dates.ContainsKey('AcceptedOn') -and $Dates.AcceptedOn -gt $Today) {
            Write-Warning "Finding exception $Label was accepted on $($Dates.AcceptedOn.ToString('yyyy-MM-dd')), a date in the future. Check the date."
        }
        if ($State -eq 'RiskAccepted' -and (-not $Dates.ContainsKey('AcceptedOn') -or -not $Dates.ContainsKey('ExpiresOn'))) { $Problems.Add("$($Label): a risk-accepted exception needs AcceptedOn and ExpiresOn"); continue }
        # The limit counts from AcceptedOn, or from today when AcceptedOn is in the future: a later AcceptedOn must
        # not move the end, so no exception applies longer than MaxDays from now.
        $Start = if ($Dates.ContainsKey('AcceptedOn') -and $Dates.AcceptedOn -gt $Today) { $Today } else { $Dates.AcceptedOn }
        if ($MaxDays -gt 0 -and $State -eq 'RiskAccepted' -and $Dates.ExpiresOn -gt $Start.AddDays($MaxDays)) {
            $Limit = $Start.AddDays($MaxDays)
            Write-Warning "Finding exception $Label expires on $($Dates.ExpiresOn.ToString('yyyy-MM-dd')), more than $MaxDays days (Findings.ExceptionMaxDays) after $(if ($Dates.AcceptedOn -gt $Today) { 'today' } else { 'AcceptedOn' }): it expires on $($Limit.ToString('yyyy-MM-dd'))."
            $Dates.ExpiresOn = $Limit
        }

        $Key = Get-EntraOpsFindingExceptionKey -RuleId $RuleId -InstanceId $InstanceId -ObjectId $ObjectId
        if (-not $Keys.Add($Key)) { $Problems.Add("$($Label): repeats the exception for $(if ($InstanceId) { "instance $InstanceId" } else { "object $ObjectId" })"); continue }
        $IsExpired = $Dates.ContainsKey('ExpiresOn') -and $Dates.ExpiresOn -lt $Today
        if ($IsExpired) { $Expired.Add("$RuleId $(if ($InstanceId) { $InstanceId } else { $ObjectId }) ($($Dates.ExpiresOn.ToString('yyyy-MM-dd')))") }

        [pscustomobject]@{
            PSTypeName    = 'EntraOps.FindingException'
            Key           = $Key
            RuleId        = $RuleId
            InstanceId    = $InstanceId
            ObjectId      = $ObjectId
            DisplayName   = & $Text 'DisplayName'
            State         = $State
            Justification = $Justification
            AcceptedBy    = & $Text 'AcceptedBy'
            AcceptedOn    = $(if ($Dates.ContainsKey('AcceptedOn')) { $Dates.AcceptedOn.ToString('yyyy-MM-dd') } else { '' })
            ExpiresOn     = $(if ($Dates.ContainsKey('ExpiresOn')) { $Dates.ExpiresOn.ToString('yyyy-MM-dd') } else { '' })
            Reference     = & $Text 'Reference'
            Expired       = $IsExpired
        }
    }
    if ($Problems.Count -gt 0) { Write-Warning "Skipped $($Problems.Count) invalid finding exception(s) in ${ResolvedPath}: $($Problems -join '; ')." }
    if ($Expired.Count -gt 0) { Write-Warning "$($Expired.Count) finding exception(s) in $ResolvedPath expired, their findings are reported again: $($Expired -join ', '). Renew or remove them." }
}

function Get-EntraOpsFindingExceptionDateText {
    <#
    .SYNOPSIS
        Reads AcceptedOn and ExpiresOn of the Finding Exceptions File as the text written in the file.
    .DESCRIPTION
        ConvertFrom-Json of PowerShell 7.4 converts text that looks like a date with a time to a date in the time
        zone of the computer, so the day as written is lost. This reader never converts text. Returns one
        hashtable per entry of the file, in file order ($null for an entry that is no object), with the dates
        that are text; nothing when the JSON cannot be read by this reader.
    .PARAMETER Json
        Content of the Finding Exceptions File.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$Json
    )

    if (-not "$Json".Trim()) { return }
    $Options = [System.Text.Json.JsonDocumentOptions]::new()
    $Options.CommentHandling = [System.Text.Json.JsonCommentHandling]::Skip
    $Options.AllowTrailingCommas = $true
    try { $Document = [System.Text.Json.JsonDocument]::Parse($Json, $Options) } catch { return }
    try {
        $Root = $Document.RootElement
        # A single exception without the array is one entry, like ConvertFrom-Json returns it.
        $Elements = if ($Root.ValueKind -eq [System.Text.Json.JsonValueKind]::Array) { @($Root.EnumerateArray()) } else { @($Root) }
        foreach ($Element in $Elements) {
            if ($Element.ValueKind -ne [System.Text.Json.JsonValueKind]::Object) { , $null; continue }
            $Texts = @{}
            foreach ($Property in $Element.EnumerateObject()) {
                if ($Property.Name -in 'AcceptedOn', 'ExpiresOn' -and $Property.Value.ValueKind -eq [System.Text.Json.JsonValueKind]::String) { $Texts[$Property.Name] = $Property.Value.GetString() }
            }
            , $Texts
        }
    } finally { $Document.Dispose() }
}

function Get-EntraOpsFindingExceptionKey {
    <#
    .SYNOPSIS
        Key of a finding exception: rule, instance and (without instance) object, lowercase.
    .DESCRIPTION
        The Privileged Assets Findings view builds the same key to compare its entries with the file.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param (
        [Parameter(Mandatory = $true)]
        [string]$RuleId,

        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string]$InstanceId,

        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string]$ObjectId
    )

    "$RuleId|$InstanceId|$(if ($InstanceId) { '' } else { $ObjectId })".ToLowerInvariant()
}
