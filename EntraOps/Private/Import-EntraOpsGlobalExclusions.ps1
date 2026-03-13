function Import-EntraOpsGlobalExclusions {
    <#
    .SYNOPSIS
        Loads the global exclusion list from Global.json.
    .DESCRIPTION
        Shared helper that loads the global exclusion list used by all EAM cmdlets
        to filter out excluded principal IDs from classification results.
    .PARAMETER FolderClassification
        Base folder for classification files. Defaults to $DefaultFolderClassification.
    .PARAMETER Enabled
        Whether global exclusions are enabled. If $false, returns $null.
    .OUTPUTS
        [array] Array of excluded principal IDs, or $null if disabled.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [string]$FolderClassification = $DefaultFolderClassification,

        [Parameter(Mandatory = $false)]
        [bool]$Enabled = $true
    )

    if (-not $Enabled) {
        return $null
    }

    $GlobalJsonPath = "$FolderClassification/Global.json"
    try {
        if (Test-Path -Path $GlobalJsonPath) {
            $ExclusionList = (Get-Content -Path $GlobalJsonPath | ConvertFrom-Json -Depth 10).ExcludedPrincipalId
            Write-Verbose "Loaded $($ExclusionList.Count) global exclusions from $GlobalJsonPath"
            return $ExclusionList
        } else {
            Write-Warning "Global exclusion file not found at $GlobalJsonPath"
            return $null
        }
    } catch {
        Write-Warning "Failed to load global exclusions from ${GlobalJsonPath}: $_"
        return $null
    }
}
