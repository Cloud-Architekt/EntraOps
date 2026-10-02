function Get-EntraOpsRoleDefinitionOverwrites {
    # Returns a hashtable RoleDefinitionId -> role classification object from Classification_RoleDefinitionOverwrites.json.
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string]$RbacSystem
    )

    $Overwrites = @{}
    if (-not (Test-Path -LiteralPath $Path)) {
        Write-Warning "Role definition overwrites file '$Path' not found; no role definition overwrites applied."
        return $Overwrites
    }

    foreach ($Entry in @(Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json -Depth 10)) {
        if ($Entry.RbacSystem -ne $RbacSystem -or [string]::IsNullOrWhiteSpace($Entry.RoleDefinitionId)) { continue }
        $Overwrites[$Entry.RoleDefinitionId] = [PSCustomObject]@{
            "EAMTierLevelName"     = $Entry.EAMTierLevelName
            "EAMTierLevelTagValue" = $Entry.EAMTierLevelTagValue
        }
    }

    return $Overwrites
}
