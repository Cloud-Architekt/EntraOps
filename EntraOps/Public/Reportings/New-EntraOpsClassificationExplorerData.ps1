<#
.SYNOPSIS
    Generate (refresh) the embedded data bundle for the EntraOps Classification Explorer static web app.

.DESCRIPTION
    Thin wrapper around Update-EntraOpsClassificationExplorerData, the shared, mode-aware generator
    function that also drives the standalone (AzurePrivilegedIAM) deployment of this same app - see
    EntraOps/Public/Reportings/Update-EntraOpsClassificationExplorerData.ps1 (synced from
    AzurePrivilegedIAM/Scripts by Sync-EntraOpsClassificationExplorerSource; do not edit the synced
    copy directly, edit the canonical one in AzurePrivilegedIAM and re-sync). Since it is a sibling
    Public function of this module, it is already dot-sourced and available - no path resolution or
    external script invocation is needed.

    This function calls it with -Mode EntraOps: it reads the latest classification JSON from the
    AzurePrivilegedIAM repository (classified roles, permission catalogs) and the EntraOps repository
    (classification-logic templates under Classification/Templates and tenant-specific copies under
    Classification/<TenantName> written by Update-EntraOpsClassificationControlPlaneScope) and
    regenerates the static app content: data/classification-data.js (embedded bundle, including
    window.EOCE_TENANTS), data-manifest.json, data/attack-paths.js and data/tier-map.js. The app then
    runs fully client-side from file:// with no web server.

    This function requires the module to be imported from a repository checkout that contains both
    the Reports/ClassificationExplorer folder and
    EntraOps/Public/Reportings/Update-EntraOpsClassificationExplorerData.ps1.

.PARAMETER RepoRoot
    Path to the repository root that contains the 'Classification' output and 'EntraOps_Classification' source folders
    (the AzurePrivilegedIAM repository). When omitted, the shared generator probes the parent of the app folder, the
    EntraOps repository root itself, and sibling folders of the EntraOps repository named 'AzurePrivilegedIAM*'. When
    no local checkout is found, EntraOps shallow-clones the public AzurePrivilegedIAM repository to a temporary folder
    for this run and deletes it afterwards. With `-WhatIf`, EntraOps reports the temporary clone without creating it.

.PARAMETER EntraOpsRoot
    Path to the EntraOps repository root that contains the classification-logic templates under
    'Classification/Templates' and the tenant-specific parameterized copies under 'Classification/<TenantName>'.
    Defaults to the repository this module lives in.

.PARAMETER AppRoot
    Path to the ClassificationExplorer app folder (where the generated content is written).
    Defaults to Reports/ClassificationExplorer in the EntraOps repository.

.PARAMETER SkipManifest
    Do not write data-manifest.json.

.PARAMETER SkipEmbed
    Do not write data/classification-data.js (and data/tier-map.js).

.PARAMETER SkipHistory
    Do not derive the classification change history (git log over the source files). Forwarded
    to the shared generator's -SkipHistory switch; the Change History view and notifications
    stay empty. When omitted, the inverse of `ClassificationExplorer.GenerateChangeHistory` in
    EntraOpsConfig.json is used. A missing configuration file or setting defaults change-history
    generation to $false because deriving it from the AzurePrivilegedIAM git log is slow and rarely
    meaningful. Pass -SkipHistory:$false to generate it for an individual invocation.

.PARAMETER PassThru
    Emit the result objects (one per source file) to the pipeline.

.EXAMPLE
    New-EntraOpsClassificationExplorerData

    Regenerates the embedded bundle and manifest, auto-detecting the AzurePrivilegedIAM repository.

.EXAMPLE
    New-EntraOpsClassificationExplorerData -RepoRoot "C:\Repos\AzurePrivilegedIAM" -Verbose -WhatIf

    Shows what would be generated from an explicit AzurePrivilegedIAM clone without changing any files.
#>

function New-EntraOpsClassificationExplorerData {

    [CmdletBinding(SupportsShouldProcess = $true)]
    param (
        [Parameter(Mandatory = $false)]
        [System.String]$RepoRoot,

        [Parameter(Mandatory = $false)]
        [System.String]$EntraOpsRoot,

        [Parameter(Mandatory = $false)]
        [System.String]$AppRoot,

        [Parameter(Mandatory = $false)]
        [switch]$SkipManifest,

        [Parameter(Mandatory = $false)]
        [switch]$SkipEmbed,

        [Parameter(Mandatory = $false)]
        [switch]$SkipHistory,

        [Parameter(Mandatory = $false)]
        [switch]$PassThru
    )

    # Config-driven default: the inverse of EntraOpsConfig.json
    # "ClassificationExplorer.GenerateChangeHistory".
    # An explicit -SkipHistory always wins over the config file setting when bound.
    if (-not $PSBoundParameters.ContainsKey('EntraOpsRoot') -and -not [string]::IsNullOrWhiteSpace($Global:EntraOpsBaseFolder)) {
        $EntraOpsRoot = $Global:EntraOpsBaseFolder
        $PSBoundParameters['EntraOpsRoot'] = $EntraOpsRoot
    }
    if (-not $PSBoundParameters.ContainsKey('SkipHistory')) {
        $GenerateChangeHistory = $false
        $ClassificationExplorerConfigRoot = $EntraOpsRoot
        if ([string]::IsNullOrWhiteSpace($ClassificationExplorerConfigRoot)) {
            $ModuleRoot = $MyInvocation.MyCommand.Module.ModuleBase
            if ([string]::IsNullOrWhiteSpace($ModuleRoot) -and -not [string]::IsNullOrWhiteSpace($PSScriptRoot)) {
                $ModuleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
            }
            if (-not [string]::IsNullOrWhiteSpace($ModuleRoot)) {
                $ClassificationExplorerConfigRoot = Split-Path -Parent $ModuleRoot
            }
        }
        if (-not [string]::IsNullOrWhiteSpace($ClassificationExplorerConfigRoot)) {
            $ClassificationExplorerConfigFilePath = Join-Path $ClassificationExplorerConfigRoot 'EntraOpsConfig.json'
            if (Test-Path -LiteralPath $ClassificationExplorerConfigFilePath -PathType Leaf) {
                try {
                    $ClassificationExplorerConfig = Get-Content -LiteralPath $ClassificationExplorerConfigFilePath -Raw | ConvertFrom-Json
                    if ($null -ne $ClassificationExplorerConfig.ClassificationExplorer -and $null -ne $ClassificationExplorerConfig.ClassificationExplorer.GenerateChangeHistory) {
                        $GenerateChangeHistory = [bool]$ClassificationExplorerConfig.ClassificationExplorer.GenerateChangeHistory
                    }
                } catch {
                    Write-Warning "Failed to read ClassificationExplorer settings from ${ClassificationExplorerConfigFilePath}: $($_.Exception.Message). Defaulting GenerateChangeHistory to `$false."
                }
            }
        }
        $SkipHistory = -not $GenerateChangeHistory
        $PSBoundParameters['SkipHistory'] = [switch]$SkipHistory
    }

    try {
        Update-EntraOpsClassificationExplorerData -Mode EntraOps @PSBoundParameters
        return
    } catch {
        $AutoDetectionFailed = $_.Exception.Message -like 'Could not auto-detect the AzurePrivilegedIAM repository*'
        if ($PSBoundParameters.ContainsKey('RepoRoot') -or -not $AutoDetectionFailed) {
            throw
        }
        if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
            throw "Unable to auto-detect AzurePrivilegedIAM and Git is unavailable for the temporary fallback clone. Install Git or pass -RepoRoot pointing to a local AzurePrivilegedIAM clone."
        }

        $TemporaryRepoRoot = Join-Path ([System.IO.Path]::GetTempPath()) "EntraOps_AzurePrivilegedIAM_$([guid]::NewGuid().ToString('N'))"
        if (-not $PSCmdlet.ShouldProcess($TemporaryRepoRoot, 'Clone temporary AzurePrivilegedIAM source repository')) {
            return
        }
        try {
            Write-Verbose "AzurePrivilegedIAM was not found locally. Cloning a temporary shallow copy to $TemporaryRepoRoot..."
            & git clone --depth 1 'https://github.com/Cloud-Architekt/AzurePrivilegedIAM.git' $TemporaryRepoRoot
            if ($LASTEXITCODE -ne 0) {
                throw "Temporary AzurePrivilegedIAM clone failed with exit code $LASTEXITCODE. Clone the repository locally and pass -RepoRoot instead."
            }

            $FallbackParameters = @{}
            foreach ($Parameter in $PSBoundParameters.GetEnumerator()) {
                $FallbackParameters[$Parameter.Key] = $Parameter.Value
            }
            $FallbackParameters.RepoRoot = $TemporaryRepoRoot
            Update-EntraOpsClassificationExplorerData -Mode EntraOps @FallbackParameters
        } finally {
            if (Test-Path -LiteralPath $TemporaryRepoRoot) {
                Remove-Item -LiteralPath $TemporaryRepoRoot -Recurse -Force -ErrorAction SilentlyContinue
            }
        }
    }
}
