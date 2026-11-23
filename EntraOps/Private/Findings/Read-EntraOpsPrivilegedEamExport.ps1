function Read-EntraOpsPrivilegedEamExport {
    <#
    .SYNOPSIS
        Reads and parses the Privileged EAM export once for the Findings context builders.
    .DESCRIPTION
        Reads PrivilegedEAM/<RbacSystem>/<RbacSystem>.json: only the JSON files directly in the RBAC system
        folders, not the per-object subfolders (user/, group/, serviceprincipal/ ...), sorted by path.
        Returns the files and one entry per file with its RBAC system (the folder name) and the parsed
        objects. The Privileged Assets, Tier Breach and Privileged EAM contexts of one evaluation share the
        result, so the export is parsed only once.
    .PARAMETER ImportPath
        Folder with the Privileged EAM export.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$ImportPath
    )

    if (-not (Test-Path -LiteralPath $ImportPath)) {
        throw "Privileged EAM import path not found: $ImportPath. Run Invoke-EntraOpsPrivilegedEAM (or Save-EntraOpsPrivilegedEAMJson) first, or pass -ImportPath."
    }

    $Files = @(Get-ChildItem -LiteralPath $ImportPath -Directory -ErrorAction SilentlyContinue |
        ForEach-Object { Get-ChildItem -LiteralPath $_.FullName -Filter '*.json' -File } |
        Sort-Object FullName)
    if ($Files.Count -eq 0) {
        Write-Warning "No Privileged EAM JSON files found under $ImportPath (expected <RbacSystem>/<RbacSystem>.json). Generating an empty dataset."
    } else {
        Write-Verbose "Found $($Files.Count) Privileged EAM JSON file(s) to process."
    }

    $Systems = foreach ($File in $Files) {
        $RoleSystem = Split-Path -Leaf (Split-Path -Parent $File.FullName)
        Write-Verbose "Reading $RoleSystem data from $($File.FullName)."
        try {
            $Data = [System.IO.File]::ReadAllText($File.FullName) | ConvertFrom-Json
        } catch {
            # Stop when an enumerated export cannot be read or parsed.
            throw "Failed to read or parse Privileged EAM export file '$($File.FullName)' (RBAC system '$RoleSystem'): $($_.Exception.Message)"
        }
        [pscustomobject]@{ RoleSystem = $RoleSystem; File = $File; Objects = @(@($Data).Where({ $null -ne $_ })) }
    }

    [pscustomobject]@{
        ImportPath = $ImportPath
        Files      = $Files
        Systems    = @($Systems)
    }
}
