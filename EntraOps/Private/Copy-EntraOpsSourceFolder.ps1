function Copy-EntraOpsSourceFolder {
    <#
    .SYNOPSIS
        Copies a folder of an extracted EntraOps source archive into the working folder.

    .DESCRIPTION
        Existing files are only replaced with -Force. Files matching -KeepPattern (path relative to
        -Source) are never replaced, e.g. generated report data or tenant-edited settings. When
        -IncludePattern is set, only matching files are copied. Browser test specs (*.spec.mjs) are not copied.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Source,

        [Parameter(Mandatory = $true)]
        [string]$Destination,

        [Parameter(Mandatory = $false)]
        [string]$KeepPattern,

        [Parameter(Mandatory = $false)]
        [string]$IncludePattern,

        [Parameter(Mandatory = $false)]
        [switch]$Force
    )

    $Installed = 0
    $Kept = 0
    $Skipped = 0
    foreach ($File in @(Get-ChildItem -LiteralPath $Source -Recurse -File | Where-Object { $_.Name -notlike '*.spec.mjs' })) {
        $RelativePath = [System.IO.Path]::GetRelativePath($Source, $File.FullName)
        if (-not [string]::IsNullOrWhiteSpace($IncludePattern) -and $RelativePath -notmatch $IncludePattern) { continue }
        $TargetPath = Join-Path $Destination $RelativePath
        if (Test-Path -LiteralPath $TargetPath -PathType Leaf) {
            if (-not [string]::IsNullOrWhiteSpace($KeepPattern) -and $RelativePath -match $KeepPattern) { $Kept++; continue }
            if (-not $Force) { $Skipped++; continue }
        }
        New-Item -ItemType Directory -Path (Split-Path -Parent $TargetPath) -Force -WhatIf:$false | Out-Null
        Copy-Item -LiteralPath $File.FullName -Destination $TargetPath -Force -WhatIf:$false
        $Installed++
    }
    return [pscustomobject]@{ Installed = $Installed; Kept = $Kept; Skipped = $Skipped }
}
