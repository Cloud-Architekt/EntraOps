<#
.SYNOPSIS
    Update classification files from AzurePrivilegedIAM repository to get latest definition of levels in Enterprise Access Model.

.DESCRIPTION
    Check all files in the EntraOps_Classification folder in the AzurePrivilegedIAM repository and download them to the folder specified in the $DefaultFolderClassification variable.

.PARAMETER FolderClassification
    Folder where the classification files should be stored. Default is "$DefaultFolderClassification/Templates".

.PARAMETER Classifications
    Array of classification names which should be updated. Default is ("AadResources", "AadResources.Param", "Azure", "Azure.Param", "AppRoles", "ApiPermissions", "Defender", "IdentityGovernance") which are available from the public repository.
    Pass "All" (or include "All" in the array) to update every classification file found in the repository, regardless of the default/explicit list.
    Deprecated templates still published upstream (AzBilling, AzResources, AzResourcesByAzTags) are always skipped.

.PARAMETER IncludeParamFiles
    If set, automatically includes any matching .Param variant files found in the repository for each classification in $Classifications.
    For example, if "DeviceManagement" is in $Classifications and a "Classification_DeviceManagement.Param.json" exists in the repository, it will also be downloaded.
    Ignored when $Classifications is "All", since every file (including .Param variants) is already included.

.PARAMETER IncludeOverwrites
    If set, also downloads the classification overwrite template "Classification_RoleDefinitionOverwrites.json" from the repository.
    Role action overwrites (Classification_RoleActionOverwrites.json) are tenant-specific only and intentionally not downloaded to Templates.

.PARAMETER SkipExisting
    Reuse existing local templates and download only missing files. Defaults to false: existing files
    are overwritten with validated downloads unless -SkipExisting is explicitly enabled.

.PARAMETER FailOnUnavailableRepository
    Fail when the list of templates can't be read from GitHub (for example while its rate limit is exceeded),
    even if the requested templates exist locally. By default, the existing local templates are kept and
    used with a warning, as nothing was changed. Requests are authenticated with GITHUB_TOKEN or GH_TOKEN
    when set, and rate limits and transient errors are retried.

.EXAMPLE
    Update all classification files in default location (./EntraOps_Classification/Templates) with classifications from the public repository AzurePrivilegedIAM
    Update-EntraOpsClassificationFiles

.EXAMPLE
    Update classification files including any available .Param variant files
    Update-EntraOpsClassificationFiles -Classifications ("AadResources", "DeviceManagement") -IncludeParamFiles

.EXAMPLE
    Update every classification file available in the public repository, regardless of the default/explicit list.
    Update-EntraOpsClassificationFiles -Classifications "All"
#>
function Update-EntraOpsClassificationFiles {

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $False)]
        [System.String]$Branch = "main"
        ,  
        [Parameter(Mandatory = $false)]
        [System.String]$FolderClassification = "$DefaultFolderClassification/Templates",

        [Parameter(Mandatory = $false)]
        [Object]$Classifications = ("AadResources", "AadResources.Param", "Azure", "Azure.Param", "AppRoles", "ApiPermissions", "Defender", "DeviceManagement", "IdentityGovernance"),

        [Parameter(Mandatory = $false)]
        [Switch]$IncludeParamFiles = $true
        ,
        [Parameter(Mandatory = $false)]
        [Switch]$IncludeOverwrites = $true
        ,
        [Parameter(Mandatory = $false)]
        [Switch]$SkipExisting = $false
        ,
        [Parameter(Mandatory = $false)]
        [Switch]$FailOnUnavailableRepository = $false
    )

    try {
        $ClassificationTemplates = Invoke-EntraOpsGitHubRequest -Uri "https://api.github.com/repos/Cloud-Architekt/AzurePrivilegedIAM/contents/EntraOps_Classification?ref=$($Branch)"
    } catch {
        $ListingError = $_.Exception.Message
        # Nothing was downloaded, so the local templates are still one consistent set. They are used when every
        # requested template exists ("All": any template), instead of failing the classification for an outage of GitHub.
        $RequestedNames = @(@($Classifications) | Where-Object { $_ -and $_ -ne 'All' } | ForEach-Object { if ($_ -eq 'AppRoles') { 'ApiPermissions' } else { $_ } })
        $LocalTemplatesComplete = if (@($Classifications) -contains 'All' -or $RequestedNames.Count -eq 0) {
            @(Get-ChildItem -Path $FolderClassification -Filter 'Classification_*.json' -File -ErrorAction SilentlyContinue).Count -gt 0
        } else {
            @($RequestedNames | Where-Object { -not (Test-Path -LiteralPath (Join-Path $FolderClassification "Classification_$_.json") -PathType Leaf) }).Count -eq 0
        }
        if ($FailOnUnavailableRepository -or -not $LocalTemplatesComplete) {
            throw "The classification templates could not be listed from Cloud-Architekt/AzurePrivilegedIAM ($Branch): $ListingError$(if (-not $LocalTemplatesComplete) { " The requested templates don't exist in $FolderClassification, so the classification can't continue with local copies." })"
        }
        Write-Warning "The classification templates could not be listed from Cloud-Architekt/AzurePrivilegedIAM ($Branch): $ListingError The existing templates in $FolderClassification are kept and used; they are updated by the next run."
        return
    }

    # Deprecated classification templates that were removed from EntraOps (replaced by the Azure
    # classification) but may still be published in the upstream repository. They are never downloaded,
    # so "-Classifications All" does not bring them back into the Templates folder.
    $DeprecatedClassifications = @('AzBilling', 'AzResources', 'AzResourcesByAzTags')

    # Support "All" as a shortcut to include every classification file available in the repository,
    # so newly added classifications (e.g. Defender, IdentityGovernance, DeviceManagement) are always
    # considered without requiring the default/explicit list to be kept in sync.
    if (@($Classifications) -contains "All") {
        $Classifications = $ClassificationTemplates | ForEach-Object { $_.Name.Replace("Classification_", "").Replace(".json", "") }
        Write-Verbose "Classifications set to 'All': including all $(@($Classifications).Count) classification file(s) found in the repository (deprecated templates are skipped)."
    } else {
        # Normalize Classifications: replace AppRoles with ApiPermissions, or remove it if ApiPermissions already present
        if ("AppRoles" -in $Classifications) {
            if ("ApiPermissions" -in $Classifications) {
                $Classifications = $Classifications | Where-Object { $_ -ne "AppRoles" }
            } else {
                $Classifications = $Classifications | ForEach-Object { if ($_ -eq "AppRoles") { "ApiPermissions" } else { $_ } }
                Write-Warning "AppRoles has been replaced with ApiPermissions. The new classification file also supports delegated permissions."
            }
        }

        # When -IncludeParamFiles is set, expand $Classifications with any .Param variants found in the repository
        if ($IncludeParamFiles) {
            $ParamVariants = $ClassificationTemplates | ForEach-Object {
                $_.Name.Replace("Classification_", "").Replace(".json", "")
            } | Where-Object {
                $BaseName = $_ -replace '\.Param$', ''
                $_ -like "*.Param" -and $BaseName -in $Classifications
            }
            $Classifications = (@($Classifications) + @($ParamVariants)) | Select-Object -Unique
        }
    }

    # When -IncludeOverwrites is set, also download the role definition overwrites template.
    # Role action overwrites are tenant-specific only and therefore not part of the Templates download.
    if ($IncludeOverwrites) {
        $Classifications = (@($Classifications) + "RoleDefinitionOverwrites") | Select-Object -Unique
    }


    $FailedDownloads = [System.Collections.Generic.List[string]]::new()
    foreach ($ClassificationTemplate in $ClassificationTemplates) {
        # Parsing classification name by removing the prefix and suffix from file name
        $ClassificationName = $ClassificationTemplate.Name.Replace("Classification_", "").Replace(".json", "")
        if ($ClassificationName -in $Classifications) {
            if (($ClassificationName -replace '\.Param$', '') -in $DeprecatedClassifications) {
                Write-Verbose "[$($ClassificationTemplate.name)] Skipped: deprecated classification template (no longer supported by EntraOps, use the Azure classification instead)."
                continue
            }

            $LocalFilePath = "$($FolderClassification)/$($ClassificationTemplate.name)"
            if ($SkipExisting -and (Test-Path -LiteralPath $LocalFilePath -PathType Leaf)) {
                Write-Host "[$($ClassificationTemplate.name)] Using existing file: $LocalFilePath" -ForegroundColor Gray
                continue
            }
            $FileExisted = Test-Path $LocalFilePath
            $OldHash = if ($FileExisted) { (Get-FileHash $LocalFilePath -Algorithm SHA256).Hash } else { $null }
            $OldLastWriteTime = if ($FileExisted) { (Get-Item $LocalFilePath).LastWriteTime } else { $null }

            try {
                if (-not (Test-Path -Path $FolderClassification)) {
                    New-Item -Path $FolderClassification -ItemType Directory -Force | Out-Null
                }
                # Download to a temp file and swap atomically so a failed download never truncates the existing file
                Invoke-EntraOpsGitHubRequest -Uri $ClassificationTemplate.download_url -OutFile "$LocalFilePath.tmp"

                # A truncated response or an error page must not replace a valid template. *.Param.json
                # templates carry bare, unquoted placeholders (e.g. <Tier0IncludedResourceScope>) and only
                # become valid JSON after Update-EntraOpsClassificationControlPlaneScope substitutes them,
                # so validate a placeholder-normalized copy instead of the raw text.
                $DownloadedContent = Get-Content -Path "$LocalFilePath.tmp" -Raw
                $ContentToValidate = if ($ClassificationTemplate.name -like '*.Param.json') {
                    ($DownloadedContent -replace '"<[A-Za-z0-9_]+>"', '"placeholder"') -replace '<[A-Za-z0-9_]+>', '"placeholder"'
                } else {
                    $DownloadedContent
                }
                $null = $ContentToValidate | ConvertFrom-Json -Depth 10

                Move-Item -Path "$LocalFilePath.tmp" -Destination $LocalFilePath -Force
            } catch {
                Write-Warning "[$($ClassificationTemplate.name)] Download or validation failed: $($_.Exception.Message)"
                Remove-Item -Path "$LocalFilePath.tmp" -Force -ErrorAction SilentlyContinue
                $FailedDownloads.Add($ClassificationTemplate.name)
                continue
            }

            $NewLastWriteTime = (Get-Item $LocalFilePath).LastWriteTime
            $NewHash = (Get-FileHash $LocalFilePath -Algorithm SHA256).Hash

            if (-not $FileExisted) {
                Write-Host "[$($ClassificationTemplate.name)] New file downloaded at $NewLastWriteTime" -ForegroundColor Green
            } elseif ($OldHash -ne $NewHash) {
                Write-Host "[$($ClassificationTemplate.name)] Updated (Previous: $OldLastWriteTime | Current: $NewLastWriteTime)" -ForegroundColor Cyan
            } else {
                Write-Host "[$($ClassificationTemplate.name)] No changes detected (Last modified: $OldLastWriteTime)" -ForegroundColor Gray
            }
        }
    }
    if ($FailedDownloads.Count -gt 0) {
        # Continuing would classify against a mix of updated and outdated templates from different
        # upstream states, which silently changes tier results. Fail instead and keep the previous set.
        throw "$($FailedDownloads.Count) classification file(s) could not be downloaded or did not contain valid JSON: $($FailedDownloads -join ', '). The previous local copies were left untouched. Re-run Update-EntraOpsClassificationFiles before collecting privileged access data."
    }
}
