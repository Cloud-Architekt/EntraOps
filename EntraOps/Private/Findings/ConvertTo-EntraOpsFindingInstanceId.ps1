function ConvertTo-EntraOpsFindingInstanceId {
    <#
    .SYNOPSIS
        Converts an identifier of a report (for example a flow id) to a finding instance ID.
    .DESCRIPTION
        Instance IDs follow the instance ID rules of Maester test families: letters, digits, '.', '_' and
        '-', at most 128 characters, starting with a letter or digit. The '|' separator of report flow ids
        becomes '.'; any other identifier that does not fit is replaced by a stable hash (32 hex characters).
    .PARAMETER Value
        The identifier, for example "<roleId>|activation".
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param (
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$Value
    )

    $Candidate = $Value.Replace('|', '.')
    if ($Candidate -match '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$') { return $Candidate }
    return [System.Convert]::ToHexString([System.Security.Cryptography.SHA256]::HashData([System.Text.Encoding]::UTF8.GetBytes($Value))).Substring(0, 32).ToLowerInvariant()
}
