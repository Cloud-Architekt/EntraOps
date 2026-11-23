function Write-EntraOpsWarningOnce {
    <#
    .SYNOPSIS
        Writes a warning only the first time its key occurs in the PowerShell session.

    .DESCRIPTION
        For conditions that every RBAC system (and the Control Plane scope bootstrap) checks again, for example a
        missing Global.json or a PAW reference without a device. Later occurrences are written as verbose messages.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Key,

        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    # The session is shared with the parallel runspaces, a script variable is not
    $Session = Get-Variable -Name __EntraOpsSession -ValueOnly -ErrorAction SilentlyContinue
    $WarningsOnce = if ($Session) { $Session['WarningsOnce'] }
    if ($null -eq $WarningsOnce) {
        if ($null -eq $script:EntraOpsWarningsOnce) {
            $script:EntraOpsWarningsOnce = [System.Collections.Concurrent.ConcurrentDictionary[string, byte]]::new([System.StringComparer]::OrdinalIgnoreCase)
        }
        $WarningsOnce = $script:EntraOpsWarningsOnce
    }
    if ($WarningsOnce.TryAdd($Key, 0)) {
        Write-Warning $Message
    } else {
        Write-Verbose $Message
    }
}
