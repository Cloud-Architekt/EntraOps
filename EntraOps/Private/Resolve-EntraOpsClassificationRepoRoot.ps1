function Resolve-EntraOpsClassificationRepoRoot {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ModuleBase
    )

    $candidate = [IO.DirectoryInfo]$ModuleBase
    while ($candidate) {
        if ((Test-Path -LiteralPath (Join-Path $candidate.FullName 'Classification') -PathType Container) -and
            (Test-Path -LiteralPath (Join-Path $candidate.FullName 'EntraOps_Classification') -PathType Container)) {
            return $candidate.FullName
        }
        # EntraOps also exports the shared maintenance command, but its source data and
        # templates are maintained in the sibling AzurePrivilegedIAM checkout.
        if (Test-Path -LiteralPath (Join-Path $candidate.FullName 'Reports/ClassificationExplorer') -PathType Container) {
            $siblings = @(Get-ChildItem -LiteralPath $candidate.Parent.FullName -Directory -Filter 'AzurePrivilegedIAM*' |
                Where-Object {
                    (Test-Path -LiteralPath (Join-Path $_.FullName 'Classification') -PathType Container) -and
                    (Test-Path -LiteralPath (Join-Path $_.FullName 'EntraOps_Classification') -PathType Container)
                })
            if ($siblings.Count -eq 1) { return $siblings[0].FullName }
            throw 'Unable to uniquely resolve the AzurePrivilegedIAM source checkout. Pass -RepoRoot explicitly.'
        }
        $candidate = $candidate.Parent
    }

    throw "Unable to locate the classification source repository from module base '$ModuleBase'. Pass -RepoRoot explicitly."
}
