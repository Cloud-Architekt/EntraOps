function Get-EntraOpsGitBlobHash {
    <#
    .SYNOPSIS
        Computes the git blob hash (SHA-1 of "blob <length>\0<content>") of files without git.
    .DESCRIPTION
        Returns the same hash as "git hash-object <file>" (without filters such as line ending
        conversion), so report data generated from a folder without git history keys and de-duplicates
        its content the same way as data generated from git commits.
    .PARAMETER LiteralPath
        Files to hash. Returns one hash per file, in the same order.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param (
        [Parameter(Mandatory = $true)]
        [string[]]$LiteralPath
    )

    $Sha1 = [System.Security.Cryptography.SHA1]::Create()
    try {
        foreach ($Path in $LiteralPath) {
            $Content = [System.IO.File]::ReadAllBytes($Path)
            $Header = [System.Text.Encoding]::ASCII.GetBytes("blob $($Content.Length)`0")
            $Buffer = [byte[]]::new($Header.Length + $Content.Length)
            [System.Buffer]::BlockCopy($Header, 0, $Buffer, 0, $Header.Length)
            [System.Buffer]::BlockCopy($Content, 0, $Buffer, $Header.Length, $Content.Length)
            [System.Convert]::ToHexString($Sha1.ComputeHash($Buffer)).ToLowerInvariant()
        }
    } finally {
        $Sha1.Dispose()
    }
}
