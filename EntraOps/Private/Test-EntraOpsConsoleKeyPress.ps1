function Test-EntraOpsConsoleKeyPress {
    <#
    .SYNOPSIS
        Tells whether a key was pressed in the console since the last call, without waiting.

    .DESCRIPTION
        Reads all pending key presses, so earlier keystrokes don't count later. Returns $true when one of them was
        -Key, $false when not, and $null when the console can't report key presses (no interactive console or
        redirected input, for example in pipelines), so the caller can leave out a "press a key" hint.
    #>
    [CmdletBinding()]
    [OutputType([System.Nullable[bool]])]
    param (
        [Parameter(Mandatory = $true)]
        [System.ConsoleKey]$Key
    )

    try {
        if (-not [Environment]::UserInteractive -or [Console]::IsInputRedirected) { return $null }
        $Pressed = $false
        while ([Console]::KeyAvailable) {
            if ([Console]::ReadKey($true).Key -eq $Key) { $Pressed = $true }
        }
        return $Pressed
    } catch {
        # Some hosts have no console to read from.
        Write-Verbose "The console can't report key presses: $($_.Exception.Message)"
        return $null
    }
}
