function Test-EntraOpsUpdateContract {
[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [string]$CandidateRoot,

    [Parameter(Mandatory = $true)]
    [string]$Repository,

    [Parameter(Mandatory = $true)]
    [string[]]$TargetUpdateFolders
)

$ErrorActionPreference = 'Stop'
# Resolve against the PowerShell location, not the process working directory: Set-Location does not
# move [Environment]::CurrentDirectory, so [System.IO.Path]::GetFullPath would resolve a relative
# candidate path against wherever pwsh was started.
$CandidateRoot = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($CandidateRoot)
$ContractPath = Join-Path $CandidateRoot 'EntraOpsUpdateContract.json'
if (-not (Test-Path -LiteralPath $ContractPath -PathType Leaf)) {
    throw "Update source '$Repository' does not publish EntraOpsUpdateContract.json. It is not a supported source for this updater; no local file was changed."
}

try {
    $Contract = Get-Content -LiteralPath $ContractPath -Raw | ConvertFrom-Json -ErrorAction Stop
} catch {
    throw "Update contract '$ContractPath' is not valid JSON: $_"
}

if ($Contract.SchemaVersion -ne 1 -or $Contract.Product -ne 'EntraOps') {
    throw "Update source '$Repository' publishes an unsupported EntraOps update contract (schema '$($Contract.SchemaVersion)', product '$($Contract.Product)')."
}

# A contract lists every repository allowed to serve it in DistributionRepositories so the same file
# is valid in the public release repository and the private Insiders repository. A single-value
# "Repository" is accepted for contracts published by redistributing forks.
$ContractRepositories = @($Contract.DistributionRepositories.PSObject.Properties | ForEach-Object { [string]$_.Name })
if ($ContractRepositories.Count -eq 0 -and -not [string]::IsNullOrWhiteSpace($Contract.Repository)) {
    $ContractRepositories = @([string]$Contract.Repository)
}
if ($ContractRepositories.Count -eq 0) {
    throw "Update contract '$ContractPath' declares no distribution repository. No local file was changed."
}
if ($ContractRepositories -notcontains $Repository) {
    throw "Update contract repositories '$($ContractRepositories -join ', ')' do not match requested source '$Repository'. No local file was changed."
}

$SupportedTargets = @($Contract.SupportedUpdateTargets | ForEach-Object { [string]$_ })
$UnsupportedTargets = @($TargetUpdateFolders | Where-Object { $SupportedTargets -notcontains $_ })
if ($UnsupportedTargets.Count -gt 0) {
    throw "Update source '$Repository' does not support requested target(s): $($UnsupportedTargets -join ', '). No local file was changed."
}
if ($TargetUpdateFolders -contains './.github/workflows') {
    $MissingWorkflowDependencies = @(@('./.github/actions', './.github/scripts') | Where-Object { $TargetUpdateFolders -notcontains $_ })
    if ($MissingWorkflowDependencies.Count -gt 0) {
        throw "Updating './.github/workflows' also requires target(s): $($MissingWorkflowDependencies -join ', '). No local file was changed."
    }
}

$MissingRequestedTargets = @($TargetUpdateFolders | Where-Object {
        -not (Test-Path -LiteralPath (Join-Path $CandidateRoot $_))
    })
if ($MissingRequestedTargets.Count -gt 0) {
    throw "Update source '$Repository' declares but does not contain requested target(s): $($MissingRequestedTargets -join ', '). No local file was changed."
}

$MissingValidationPaths = @($Contract.RequiredValidationPaths | ForEach-Object { [string]$_ } | Where-Object {
        -not (Test-Path -LiteralPath (Join-Path $CandidateRoot $_))
    })
if ($MissingValidationPaths.Count -gt 0) {
    throw "Update source '$Repository' is incomplete. Contract-required validation path(s) are missing: $($MissingValidationPaths -join ', ')."
}

# The validation tests a git archive, the install copies the checkout: archive attributes would make them
# differ, and a symbolic link would install the content of its local target. Git checkouts are checked by
# their tracked files (Update-EntraOps installs only those), other folders on disk.
$IsGitCheckout = Test-Path -LiteralPath (Join-Path $CandidateRoot '.git')
if ($IsGitCheckout) {
    try {
        $TrackedEntries = @(Get-EntraOpsGitTrackedFile -Root $CandidateRoot)
    } catch {
        throw "Could not list the files of update candidate '$CandidateRoot': $($_.Exception.Message) No local file was changed."
    }
    $SymbolicLinks = @($TrackedEntries | Where-Object { $_.Mode -eq '120000' } | ForEach-Object { $_.Path })
    # A submodule (mode 160000) would be installed as an empty folder
    $Submodules = @($TrackedEntries | Where-Object { $_.Mode -eq '160000' } | ForEach-Object { $_.Path })
    if ($Submodules.Count -gt 0) {
        throw "Update source '$Repository' contains git submodule(s), which are not supported: $($Submodules -join ', '). No local file was changed."
    }
    $AttributeFiles = @($TrackedEntries | ForEach-Object { $_.Path } | Where-Object { ($_ -split '/')[-1] -eq '.gitattributes' })
} else {
    $CandidateItems = @(Get-ChildItem -LiteralPath $CandidateRoot -Force | ForEach-Object {
            $_
            if ($_.PSIsContainer -and -not $_.LinkType) {
                Get-ChildItem -LiteralPath $_.FullName -Recurse -Force
            }
        })
    # Relative paths with '/' like git reports them, on every platform
    $SymbolicLinks = @($CandidateItems | Where-Object { $_.LinkType } | ForEach-Object { [System.IO.Path]::GetRelativePath($CandidateRoot, $_.FullName).Replace('\', '/') })
    $AttributeFiles = @($CandidateItems | Where-Object { -not $_.PSIsContainer -and $_.Name -eq '.gitattributes' } | ForEach-Object { [System.IO.Path]::GetRelativePath($CandidateRoot, $_.FullName).Replace('\', '/') })
}
if ($SymbolicLinks.Count -gt 0) {
    throw "Update source '$Repository' contains symbolic link(s), which are not supported: $($SymbolicLinks -join ', '). No local file was changed."
}
$ArchiveAttributeFiles = @($AttributeFiles | Where-Object {
        $AttributeFilePath = Join-Path $CandidateRoot $_
        (Test-Path -LiteralPath $AttributeFilePath -PathType Leaf) -and (Select-String -LiteralPath $AttributeFilePath -Pattern '\bexport-(ignore|subst)\b' -Quiet)
    })
if ($ArchiveAttributeFiles.Count -gt 0) {
    throw "Update source '$Repository' sets export-ignore or export-subst attributes ($($ArchiveAttributeFiles -join ', ')), so the validated archive would differ from the installed files. No local file was changed."
}

[pscustomobject]@{
    ContractPath     = $ContractPath
    SchemaVersion    = [int]$Contract.SchemaVersion
    Repository       = $Repository
    Repositories     = $ContractRepositories
    SupportedTargets = $SupportedTargets
}
}
