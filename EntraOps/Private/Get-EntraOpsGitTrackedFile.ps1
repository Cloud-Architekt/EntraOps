function Get-EntraOpsGitTrackedFile {
    <#
    .SYNOPSIS
        Returns the tracked files of a git checkout with their mode and literal path.
    .DESCRIPTION
        Uses the NUL-delimited output with core.quotePath=false: git otherwise quotes paths with special or
        non-ASCII characters.
    .PARAMETER Root
        Root folder of the git checkout.
    .PARAMETER Pathspec
        Optional repository-relative paths (e.g. ./EntraOps) to limit the result to.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Root,
        [Parameter(Mandatory = $false)]
        [string[]]$Pathspec = @()
    )

    # core.fsmonitor=false: a candidate's .git/config must not start a command when its files are listed
    $GitArguments = @('-C', $Root, '-c', 'core.quotePath=false', '-c', 'core.fsmonitor=false', 'ls-files', '--stage', '-z')
    if ($Pathspec.Count -gt 0) {
        $GitArguments += '--'
        $GitArguments += $Pathspec
    }

    # git writes paths as UTF-8; PowerShell decodes native output with the console encoding
    $PreviousOutputEncoding = $null
    try {
        $PreviousOutputEncoding = [Console]::OutputEncoding
        [Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
    } catch {
        $PreviousOutputEncoding = $null
    }
    try {
        $GitOutput = & git @GitArguments
        if ($LASTEXITCODE -ne 0) {
            throw "Could not list the tracked files of '$Root' (git exit code $LASTEXITCODE)."
        }
    } finally {
        if ($null -ne $PreviousOutputEncoding) {
            try { [Console]::OutputEncoding = $PreviousOutputEncoding } catch { Write-Verbose "Console output encoding could not be restored: $_" }
        }
    }

    # PowerShell splits native output at line breaks, which a path can contain: restore them before splitting at NUL
    $RawOutput = @($GitOutput) -join "`n"
    foreach ($Entry in $RawOutput.Split([char]0, [System.StringSplitOptions]::RemoveEmptyEntries)) {
        $Metadata, $Path = $Entry.Split("`t", 2)
        if ([string]::IsNullOrEmpty($Path)) { continue }
        [pscustomobject]@{
            Mode = ($Metadata -split ' ')[0]
            Path = $Path
        }
    }
}
