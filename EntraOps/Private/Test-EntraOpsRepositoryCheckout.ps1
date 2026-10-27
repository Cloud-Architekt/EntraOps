function Test-EntraOpsRepositoryCheckout {
    <#
    .SYNOPSIS
        Tests whether a folder is the root of an EntraOps repository checkout (GitHub, Azure DevOps or local clone).
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param (
        [Parameter(Mandatory = $false)]
        [string]$Path
    )

    if ([string]::IsNullOrWhiteSpace($Path)) { return $false }
    # Both markers are committed in every EntraOps repository; a module-only install has neither next to it.
    return (Test-Path -LiteralPath (Join-Path $Path 'EntraOpsUpdateContract.json') -PathType Leaf) -or
    (Test-Path -LiteralPath (Join-Path $Path 'Classification') -PathType Container)
}
