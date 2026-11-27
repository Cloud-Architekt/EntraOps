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

    # Fail fast if the classification folder is not set (e.g., Connect-EntraOps was not called)
    if ([string]::IsNullOrWhiteSpace($FolderClassification)) {
        throw "Classification folder is not set. Run Connect-EntraOps first to initialize the EntraOps environment (or pass -FolderClassification explicitly)."
    }

    # Check tenant-specific custom file first
    $TenantSpecificPath = Join-Path -Path (Join-Path -Path $FolderClassification -ChildPath $TenantNameContext) -ChildPath $ClassificationFileName
    if (Test-Path -Path $TenantSpecificPath) {
        Write-Verbose "Using tenant-specific classification file: $TenantSpecificPath"
        return $TenantSpecificPath
    }

    # Fall back to template
    $TemplatePath = Join-Path -Path (Join-Path -Path $FolderClassification -ChildPath 'Templates') -ChildPath $ClassificationFileName
    if (Test-Path -Path $TemplatePath) {
        # Distinguish parameterized from template-only classification files: a system is parameterized
        # iff a ".Param.json" variant of its template exists (e.g. Classification_Azure.Param.json).
        # Template-only systems (e.g. ApiPermissions/ResourceApps) have no tenant-scoped placeholders,
        # and Update-EntraOpsClassificationControlPlaneScope only generates a tenant-specific file for
        # them when overwrites exist - so falling back to the shipped template is expected behavior
        # there, not a configuration gap, and must not raise a warning.
        $ParamVariantPath = Join-Path -Path (Join-Path -Path $FolderClassification -ChildPath 'Templates') -ChildPath ($ClassificationFileName -replace '\.json$', '.Param.json')
        if (Test-Path -Path $ParamVariantPath) {
            Write-EntraOpsWarningOnce -Key "TenantClassificationMissing|$TenantSpecificPath" -Message "Tenant-specific classification file not found ($TenantSpecificPath). Falling back to template $TemplatePath - tenant-scoped placeholders (e.g. privileged scope IDs) are not applied. Run Update-EntraOpsClassificationControlPlaneScope to generate the tenant-specific file."
        } else {
            Write-Verbose "Using shipped template for $ClassificationFileName ($TemplatePath). This classification has no tenant-scoped placeholders; a tenant-specific file is only generated when overwrites are configured (e.g. Classification_ApiPermissionOverwrites.json)."
        }
        return $TemplatePath
    }

    # Not found
    Write-Error "Classification file $($ClassificationFileName) not found in $($FolderClassification). Please run Update-EntraOpsClassificationFiles to download the latest classification files from AzurePrivilegedIAM repository."
    return $null
}
