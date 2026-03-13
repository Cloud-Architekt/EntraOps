function Resolve-EntraOpsClassificationPath {
    <#
    .SYNOPSIS
        Resolves the classification file path with tenant-specific → template fallback logic.
    .DESCRIPTION
        Shared helper that encapsulates the repeated classification file path resolution pattern
        used across all EAM cmdlets. Checks for a tenant-specific file first, then falls back to
        the Templates folder.
    .PARAMETER ClassificationFileName
        Name of the classification JSON file (e.g., "Classification_Defender.json").
    .PARAMETER FolderClassification
        Base folder for classification files. Defaults to $DefaultFolderClassification.
    .OUTPUTS
        [string] Full path to the resolved classification file, or $null if not found.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$ClassificationFileName,

        [Parameter(Mandatory = $false)]
        [string]$FolderClassification = $DefaultFolderClassification
    )

    # Check tenant-specific custom file first
    $TenantSpecificPath = "$($FolderClassification)/$($TenantNameContext)/$($ClassificationFileName)"
    if (Test-Path -Path $TenantSpecificPath) {
        Write-Verbose "Using tenant-specific classification file: $TenantSpecificPath"
        return $TenantSpecificPath
    }

    # Fall back to template
    $TemplatePath = "$($FolderClassification)/Templates/$($ClassificationFileName)"
    if (Test-Path -Path $TemplatePath) {
        Write-Verbose "Using template classification file: $TemplatePath"
        return $TemplatePath
    }

    # Not found
    Write-Error "Classification file $($ClassificationFileName) not found in $($FolderClassification). Please run Update-EntraOpsClassificationFiles to download the latest classification files from AzurePrivilegedIAM repository."
    return $null
}
