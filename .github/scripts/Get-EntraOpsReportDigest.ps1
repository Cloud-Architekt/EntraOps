[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [string]$Path
)

# Content digest of a report bundle: SHA-256 over the sorted "<relative path><TAB><file SHA-256>" lines.
# Jobs that hand reports over through artifacts compare it to detect a modified or substituted bundle.
$ErrorActionPreference = 'Stop'
$Root = (Resolve-Path -LiteralPath $Path).Path
$Entries = [System.Collections.Generic.List[string]]::new()
foreach ($File in Get-ChildItem -LiteralPath $Root -Recurse -File -Force) {
    $RelativePath = [System.IO.Path]::GetRelativePath($Root, $File.FullName).Replace('\', '/')
    $Entries.Add("$RelativePath`t$((Get-FileHash -LiteralPath $File.FullName -Algorithm SHA256).Hash)")
}
if ($Entries.Count -eq 0) {
    throw "No report files found in '$Root'."
}
$Entries.Sort([System.StringComparer]::Ordinal)
$Bytes = [System.Text.Encoding]::UTF8.GetBytes($Entries -join "`n")
[System.Convert]::ToHexString([System.Security.Cryptography.SHA256]::HashData($Bytes)).ToLowerInvariant()
