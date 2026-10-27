function Get-EntraOpsClassificationOverwriteFile {
    <#
    .SYNOPSIS
        Lists the overwrite files of one type in a classification folder: the base file and its tagged variants.
    .DESCRIPTION
        Returns <BaseName>.json (unless -TaggedOnly) followed by every <BaseName>_<Tag>.json, e.g.
        Classification_RoleDefinitionOverwrites.json and Classification_RoleDefinitionOverwrites_PAW.json.
        The tag is the text after the last "_" of the file name. Tagged files are sorted by name (ordinal,
        case-insensitive), so the order is the same on every platform. Overwrites are applied in this order;
        see Import-EntraOpsClassificationOverwrites for how it affects precedence.
    .PARAMETER Folder
        Classification folder to search (e.g. Classification/<TenantName>).
    .PARAMETER BaseName
        File name of the base overwrite file, e.g. Classification_RoleDefinitionOverwrites.json.
    .PARAMETER TaggedOnly
        Returns only the tagged variants, not the base file.
    .OUTPUTS
        [PSCustomObject] with Path, Name and Tag ($null for the base file).
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Folder,

        [Parameter(Mandatory = $true)]
        [string]$BaseName,

        [Parameter(Mandatory = $false)]
        [switch]$TaggedOnly
    )

    if ([string]::IsNullOrEmpty($Folder) -or -not (Test-Path -LiteralPath $Folder -PathType Container)) { return @() }

    $Stem = [System.IO.Path]::GetFileNameWithoutExtension($BaseName)
    $TaggedPattern = '^' + [regex]::Escape($Stem) + '_(?<Suffix>.+)\.json$'
    $Files = @(Get-ChildItem -LiteralPath $Folder -File -ErrorAction SilentlyContinue)

    $Result = [System.Collections.Generic.List[object]]::new()
    if (-not $TaggedOnly) {
        $BaseFile = $Files | Where-Object { $_.Name -ieq $BaseName } | Select-Object -First 1
        if ($BaseFile) { $Result.Add([PSCustomObject]@{ Path = $BaseFile.FullName; Name = $BaseFile.Name; Tag = $null }) }
    }

    $Tagged = [System.Collections.Generic.List[object]]::new()
    foreach ($File in $Files) {
        $Match = [regex]::Match($File.Name, $TaggedPattern, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
        if (-not $Match.Success) { continue }
        $Tag = ($Match.Groups['Suffix'].Value -split '_')[-1]
        if ([string]::IsNullOrWhiteSpace($Tag)) { continue }
        $Tagged.Add([PSCustomObject]@{ Path = $File.FullName; Name = $File.Name; Tag = $Tag })
    }
    $Tagged.Sort([System.Comparison[object]] { param($a, $b) [System.StringComparer]::OrdinalIgnoreCase.Compare($a.Name, $b.Name) })
    foreach ($Entry in $Tagged) { $Result.Add($Entry) }

    return $Result.ToArray()
}

function Test-EntraOpsClassificationOverwriteFileName {
    <#
    .SYNOPSIS
        Returns $true for a classification overwrite file name (base file or tagged variant).
    .DESCRIPTION
        Matches Classification_RoleActionOverwrites, Classification_RoleDefinitionOverwrites and
        Classification_ApiPermissionOverwrites, with or without a _<Tag> suffix. Used to keep these
        customization files when generated tenant classification files are removed.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param (
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$Name
    )

    return $Name -match '^Classification_(RoleAction|RoleDefinition|ApiPermission)Overwrites(_.+)?\.json$'
}
