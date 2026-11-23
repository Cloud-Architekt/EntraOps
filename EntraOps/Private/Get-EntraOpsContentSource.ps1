function Get-EntraOpsContentSource {
    <#
    .SYNOPSIS
        Provides the EntraOps content (reporting apps, classification templates, samples) that matches the module.

    .DESCRIPTION
        Without -Ref, the content comes from:
          1. the git repository checkout that contains the loaded module (clone of EntraOps or EntraOps-Insiders),
             without a download, for the folders Reports and Samples. Only files tracked in git are used, so
             generated report data and other local files of the checkout are never copied;
          2. otherwise the commit of -Branch whose EntraOps.psd1 has the module version (Resolve-EntraOpsContentRef),
             downloaded as source archive. Without such a commit (for example an Insiders or pre-release module
             newer than the branch), the branch head is downloaded and Matched is $false.
        With -Ref, that branch, tag or commit is downloaded as given.

        Returns SourceRoot, TemporaryFolder, Repository, Ref,
        ContentVersion, ModuleVersion, Matched and Resolution (LocalCheckout, Ref, BranchHead, ReleaseTag,
        BranchHistory, NoMatch, Unknown). Remove TemporaryFolder after use.

    .PARAMETER Folder
        Folders of the content that are needed. The repository checkout of the module is used only for
        Reports and Samples: the classification files of a checkout can belong to its tenant.

    .PARAMETER SkipDownloadWithoutMatch
        Don't download the branch head when the resolution already found no content of the module version
        (NoMatch). The result then has no SourceRoot and Matched $false. For callers that keep the existing
        content in that case, so a run without matching content doesn't download an archive it never uses.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param (
        [Parameter(Mandatory = $false)]
        [ValidateSet('EntraOps', 'EntraOps-Insiders')]
        [string]$Repository = 'EntraOps',

        [Parameter(Mandatory = $false)]
        [string]$Ref,

        [Parameter(Mandatory = $false)]
        [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9._/-]{0,199}$')]
        [string]$Branch = 'main',

        [Parameter(Mandatory = $false)]
        [string]$PersonalAccessToken,

        [Parameter(Mandatory = $false)]
        [string[]]$Folder = @('Reports'),

        # Folder of the loaded module; its parent is used as repository checkout. Defaults to the module folder.
        [Parameter(Mandatory = $false)]
        [string]$ModuleBase,

        [Parameter(Mandatory = $false)]
        [switch]$SkipDownloadWithoutMatch
    )

    $ModuleVersion = Get-EntraOpsModuleVersion

    if ([string]::IsNullOrWhiteSpace($Ref)) {
        if ([string]::IsNullOrWhiteSpace($ModuleBase)) { $ModuleBase = $MyInvocation.MyCommand.Module.ModuleBase }
        if ([string]::IsNullOrWhiteSpace($ModuleBase)) { $ModuleBase = Split-Path -Parent $PSScriptRoot }
        $CheckoutRoot = Split-Path -Parent $ModuleBase
        $LocalFolders = @($Folder | Where-Object { $_ -in @('Reports', 'Samples') })
        $TrackedFiles = @()
        if ($LocalFolders.Count -eq @($Folder).Count -and (Test-EntraOpsRepositoryCheckout -Path $CheckoutRoot) -and (Get-Command git -ErrorAction SilentlyContinue)) {
            $TrackedFiles = @(git -C $CheckoutRoot ls-files -- @($LocalFolders) 2>$null | Where-Object { $_ })
            if ($LASTEXITCODE -ne 0) { $TrackedFiles = @() }
        }
        if ($TrackedFiles.Count -gt 0) {
            $TemporaryFolder = Join-Path ([System.IO.Path]::GetTempPath()) "EntraOpsSource-$([guid]::NewGuid().ToString('N'))"
            try {
                foreach ($RelativePath in $TrackedFiles) {
                    $SourceFile = Join-Path $CheckoutRoot $RelativePath
                    if (-not (Test-Path -LiteralPath $SourceFile -PathType Leaf)) { continue }
                    $TargetFile = Join-Path $TemporaryFolder $RelativePath
                    New-Item -ItemType Directory -Path (Split-Path -Parent $TargetFile) -Force -WhatIf:$false | Out-Null
                    Copy-Item -LiteralPath $SourceFile -Destination $TargetFile -Force -WhatIf:$false
                }
            } catch {
                Remove-Item -LiteralPath $TemporaryFolder -Recurse -Force -ErrorAction SilentlyContinue -WhatIf:$false
                throw
            }
            return [pscustomobject]@{
                SourceRoot      = $TemporaryFolder
                TemporaryFolder = $TemporaryFolder
                Repository      = "repository checkout $CheckoutRoot"
                Ref             = $null
                ContentVersion  = $ModuleVersion
                ModuleVersion   = $ModuleVersion
                Matched         = $true
                Resolution      = 'LocalCheckout'
            }
        }
        $Resolved = Resolve-EntraOpsContentRef -Repository $Repository -Branch $Branch -ModuleVersion $ModuleVersion -PersonalAccessToken $PersonalAccessToken
        $DownloadRef = $Resolved.Ref
        $Resolution = $Resolved.Resolution
        # NoMatch is decided from the manifest of the branch head: the archive of the branch can't match either.
        if ($SkipDownloadWithoutMatch -and $Resolution -eq 'NoMatch' -and -not $Resolved.Matched) {
            return [pscustomobject]@{
                SourceRoot      = $null
                TemporaryFolder = $null
                Repository      = "Cloud-Architekt/$Repository"
                Ref             = $DownloadRef
                ContentVersion  = $Resolved.ContentVersion
                ModuleVersion   = $ModuleVersion
                Matched         = $false
                Resolution      = $Resolution
            }
        }
    } else {
        $DownloadRef = $Ref
        $Resolution = 'Ref'
    }

    $Archive = Get-EntraOpsSourceArchive -Repository $Repository -Ref $DownloadRef -PersonalAccessToken $PersonalAccessToken
    $Archive | Add-Member -NotePropertyName ModuleVersion -NotePropertyValue $ModuleVersion -Force
    $Archive | Add-Member -NotePropertyName Matched -NotePropertyValue ($null -eq $ModuleVersion -or $Archive.ContentVersion -eq $ModuleVersion) -Force
    $Archive | Add-Member -NotePropertyName Resolution -NotePropertyValue $Resolution -Force
    $Archive
}

function Write-EntraOpsContentMarker {
    <#
    .SYNOPSIS
        Records the source and version of the installed reporting apps in Reports/.EntraOpsContent.json.

    .DESCRIPTION
        Invoke-EntraOpsAssessment compares the recorded ContentVersion with the module to update reporting apps
        of another version.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [pscustomobject]$Source
    )

    [ordered]@{
        Repository        = $Source.Repository
        Ref               = $Source.Ref
        Resolution        = $Source.Resolution
        ContentVersion    = if ($Source.ContentVersion) { "$($Source.ContentVersion)" } else { $null }
        ModuleVersion     = if ($Source.ModuleVersion) { "$($Source.ModuleVersion)" } else { $null }
        InstalledDateTime = (Get-Date).ToUniversalTime().ToString('o')
    } | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $Path '.EntraOpsContent.json') -Encoding utf8
}

function Get-EntraOpsContentMarker {
    <#
    .SYNOPSIS
        Reads Reports/.EntraOpsContent.json; $null when the reporting apps have no marker (installed before 1.2.0).
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $MarkerPath = Join-Path $Path '.EntraOpsContent.json'
    if (-not (Test-Path -LiteralPath $MarkerPath -PathType Leaf)) { return $null }
    try { Get-Content -LiteralPath $MarkerPath -Raw | ConvertFrom-Json } catch { $null }
}

function Resolve-EntraOpsContentRepository {
    <#
    .SYNOPSIS
        Selects the distribution repository of the content when the caller passed none: AutomatedEntraOpsUpdate.Repository
        of EntraOpsConfig.json, otherwise the public 'EntraOps' repository.

    .DESCRIPTION
        The release channel of a deployment is configured once, in AutomatedEntraOpsUpdate.Repository, which also selects
        the source of Update-EntraOps. A module-only installation of an Insiders build that took the reporting apps and
        templates from the public repository would switch the channel without notice, so the content follows the same
        setting. The valid values are the distribution repositories of the catalog DistributionRepositories in
        EntraOpsUpdateContract.json, also as Cloud-Architekt/<name>. A module-only installation has no copy of the
        catalog, so they are listed here; a test keeps both in sync. Another value is reported with a warning and the
        public repository is used. The private repository still needs a token: without ENTRAOPS_PAT, the download fails
        with that reason instead of falling back to the public repository.

        Returns Repository and Reason, for the line of the caller that says which repository is used and why.

    .PARAMETER ConfigFilePath
        Configuration files to read; the first that exists is used.

    .PARAMETER Config
        The configuration the caller has already read from ConfigFilePath.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param (
        [Parameter(Mandatory = $false)]
        [string[]]$ConfigFilePath,

        [Parameter(Mandatory = $false)]
        [object]$Config
    )

    $DistributionRepositories = @('EntraOps', 'EntraOps-Insiders')
    $Path = @($ConfigFilePath | Where-Object { -not [string]::IsNullOrWhiteSpace($_) -and (Test-Path -LiteralPath $_ -PathType Leaf) }) | Select-Object -First 1
    if ($null -eq $Config) {
        if (-not $Path) {
            return [pscustomobject]@{ Repository = 'EntraOps'; Reason = 'default, no EntraOpsConfig.json' }
        }
        try {
            $Config = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json -Depth 100
        } catch {
            Write-Warning "$Path is not valid JSON, so AutomatedEntraOpsUpdate.Repository can't be read: the content comes from the public 'EntraOps' repository. $($_.Exception.Message)"
            return [pscustomobject]@{ Repository = 'EntraOps'; Reason = "default, $Path is not valid JSON" }
        }
    }
    $Source = if ($Path) { $Path } else { 'the configuration' }
    $Configured = "$($Config.AutomatedEntraOpsUpdate.Repository)".Trim()
    if ([string]::IsNullOrWhiteSpace($Configured)) {
        return [pscustomobject]@{ Repository = 'EntraOps'; Reason = "default, no AutomatedEntraOpsUpdate.Repository in $Source" }
    }
    $Name = $Configured -replace '^Cloud-Architekt/', ''
    $Repository = $DistributionRepositories | Where-Object { $_ -eq $Name } | Select-Object -First 1
    if (-not $Repository) {
        Write-Warning "AutomatedEntraOpsUpdate.Repository '$Configured' in $Source is not a distribution repository of the EntraOps content ($($DistributionRepositories -join ', ')). The content comes from the public 'EntraOps' repository; select another one with -Repository (Invoke-EntraOpsAssessment: -ContentRepository)."
        return [pscustomobject]@{ Repository = 'EntraOps'; Reason = "default, AutomatedEntraOpsUpdate.Repository '$Configured' in $Source is not supported" }
    }
    [pscustomobject]@{ Repository = $Repository; Reason = "AutomatedEntraOpsUpdate.Repository in $Source" }
}
