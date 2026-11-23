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

    if ($null -eq $script:EntraOpsWarningsOnce) {
        $script:EntraOpsWarningsOnce = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    }
    if ($script:EntraOpsWarningsOnce.Add($Key)) {
        Write-Warning $Message
    } else {
        Write-Verbose $Message
    }
}
