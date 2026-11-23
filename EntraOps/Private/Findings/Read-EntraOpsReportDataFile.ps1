function Read-EntraOpsReportDataFile {
    <#
    .SYNOPSIS
        Reads a generated report data file ("window.<name> = <json>;") of the Reports folder.
    .DESCRIPTION
        Returns $null when the file does not exist, else the parsed data (Data, with case-sensitive keys like
        JavaScript objects) and the JSON text (Json). Date strings stay strings like in JavaScript; PowerShell
        before 7.5 converts them to dates (ConvertFrom-Json -DateKind), so callers that need a value exactly
        as written use Get-EntraOpsReportDataRawValue.
    .PARAMETER Path
        Path to the data file.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $null }
    $Content = [System.IO.File]::ReadAllText($Path)
    # The assignment of the data (a header comment before it may contain '=' as well).
    $Assignment = [regex]::Match($Content, 'window\.[A-Za-z_$][\w$]*\s*=')
    $Start = if ($Assignment.Success) { $Assignment.Index + $Assignment.Length - 1 } else { $Content.IndexOf('=') }
    $End = $Content.LastIndexOf(';')
    if ($Start -lt 0 -or $End -le $Start) { throw "Report data file '$Path' is not a 'window.<name> = <json>;' data file." }
    $Json = $Content.Substring($Start + 1, $End - $Start - 1)

    $JsonParameters = @{ AsHashtable = $true; Depth = 100 }
    if ((Get-Command ConvertFrom-Json).Parameters.ContainsKey('DateKind')) { $JsonParameters.DateKind = 'String' }
    try {
        $Data = $Json | ConvertFrom-Json @JsonParameters
    } catch {
        throw "Failed to parse report data file '$Path': $($_.Exception.Message)"
    }
    [pscustomobject]@{
        Path      = $Path
        Json      = $Json
        Data      = $Data
        # Whether string values of Data are exactly as written (no date conversion).
        RawString = $JsonParameters.ContainsKey('DateKind')
    }
}

function Get-EntraOpsReportDataRawValue {
    <#
    .SYNOPSIS
        Returns values of a report data file exactly as written, like JavaScript string interpolation.
    .DESCRIPTION
        Returns the top-level string properties -Name (Values) and, for every element of the top-level array
        -ArrayName, its -ElementProperty values joined by '|' (ElementKeys), like `${a}|${b}` in JavaScript:
        the string value, the JSON text of other values, 'null' for null and 'undefined' for a missing
        property. Reads Data when its strings are exact (PowerShell 7.5 or later), else parses the JSON text
        once for all values.
    .PARAMETER DataFile
        Result of Read-EntraOpsReportDataFile.
    .PARAMETER Name
        Top-level property names to return as strings ($null when missing or not a string).
    .PARAMETER ArrayName
        Top-level array whose elements' -ElementProperty values are returned joined by '|' (one key per
        element; $null for an element that is not an object).
    .PARAMETER ElementProperty
        Properties of the -ArrayName elements.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [object]$DataFile,

        [Parameter(Mandatory = $false)]
        [string[]]$Name = @(),

        [Parameter(Mandatory = $false)]
        [string]$ArrayName,

        [Parameter(Mandatory = $false)]
        [string[]]$ElementProperty = @()
    )

    $Values = [ordered]@{}
    $Keys = [System.Collections.Generic.List[string]]::new()
    if ($DataFile.RawString) {
        $Data = $DataFile.Data
        $IsObject = $Data -is [System.Collections.IDictionary]
        foreach ($Item in $Name) { $Values[$Item] = $(if ($IsObject -and $Data[$Item] -is [string]) { $Data[$Item] } else { $null }) }
        if ($ArrayName -and $IsObject -and $Data[$ArrayName] -is [array]) {
            foreach ($Element in $Data[$ArrayName]) {
                if ($Element -isnot [System.Collections.IDictionary]) { $Keys.Add($null); continue }
                $Parts = foreach ($Property in $ElementProperty) {
                    if (-not $Element.Contains($Property)) { 'undefined' }
                    elseif ($null -eq $Element[$Property]) { 'null' }
                    elseif ($Element[$Property] -is [string]) { $Element[$Property] }
                    else { ConvertTo-Json -InputObject $Element[$Property] -Compress -Depth 100 }
                }
                $Keys.Add($Parts -join '|')
            }
        }
    } else {
        $Document = [System.Text.Json.JsonDocument]::Parse($DataFile.Json)
        try {
            $Root = $Document.RootElement
            $IsObject = $Root.ValueKind -eq 'Object'
            foreach ($Item in $Name) {
                $Value = [System.Text.Json.JsonElement]::new()
                $Values[$Item] = $(if ($IsObject -and $Root.TryGetProperty($Item, [ref]$Value) -and $Value.ValueKind -eq 'String') { $Value.GetString() } else { $null })
            }
            $ArrayElement = [System.Text.Json.JsonElement]::new()
            if ($ArrayName -and $IsObject -and $Root.TryGetProperty($ArrayName, [ref]$ArrayElement) -and $ArrayElement.ValueKind -eq 'Array') {
                foreach ($Element in $ArrayElement.EnumerateArray()) {
                    if ($Element.ValueKind -ne 'Object') { $Keys.Add($null); continue }
                    $Parts = foreach ($Property in $ElementProperty) {
                        $Value = [System.Text.Json.JsonElement]::new()
                        if (-not $Element.TryGetProperty($Property, [ref]$Value)) { 'undefined' }
                        elseif ($Value.ValueKind -eq 'Null') { 'null' }
                        elseif ($Value.ValueKind -eq 'String') { $Value.GetString() }
                        else { $Value.GetRawText() }
                    }
                    $Keys.Add($Parts -join '|')
                }
            }
        } finally {
            $Document.Dispose()
        }
    }
    [pscustomobject]@{ Values = $Values; ElementKeys = $Keys }
}
