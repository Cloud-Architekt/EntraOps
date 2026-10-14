[CmdletBinding()]
param (
    [Parameter(Mandatory = $false)]
    [string]$CommitMessage = "EntraOps automated update",

    # BUILD_SOURCEBRANCHNAME is only the last segment of the ref (refs/heads/release/v1 -> v1)
    [Parameter(Mandatory = $false)]
    [string]$BranchName = ($env:BUILD_SOURCEBRANCH -replace '^refs/heads/', ''),

    [Parameter(Mandatory = $false)]
    [string]$AccessToken = $env:SYSTEM_ACCESSTOKEN
)

$ErrorActionPreference = "Continue"

if ([string]::IsNullOrWhiteSpace($BranchName) -or $BranchName -like 'refs/*') {
    Write-Error "Unable to determine the target branch from '$env:BUILD_SOURCEBRANCH'. Pass -BranchName or run the pipeline from a branch (refs/heads/...)."
    exit 1
}

if ([string]::IsNullOrWhiteSpace($AccessToken)) {
    Write-Error "Azure DevOps access token is required for git push."
    exit 1
}

# Generated output contains tenant data and is only published to private projects
if (-not [string]::IsNullOrWhiteSpace($env:SYSTEM_COLLECTIONURI) -and -not [string]::IsNullOrWhiteSpace($env:SYSTEM_TEAMPROJECTID)) {
    try {
        $ProjectUri = "$($env:SYSTEM_COLLECTIONURI.TrimEnd('/'))/_apis/projects/$($env:SYSTEM_TEAMPROJECTID)?api-version=7.1"
        $Project = Invoke-RestMethod -Uri $ProjectUri -Headers @{ Authorization = "Bearer $AccessToken" } -Method Get
    } catch {
        Write-Error "Could not verify the Azure DevOps project visibility, refusing to push generated output: $($_.Exception.Message)"
        exit 1
    }
    if ($Project.visibility -ne 'private') {
        Write-Error "Azure DevOps project '$($Project.name)' is not private (visibility: $($Project.visibility)). Refusing to commit and push generated output because it may contain tenant data."
        exit 1
    }
}

git config user.email "entraops-ado@contoso.com"
git config user.name "Azure DevOps"

git add --all
if ($LASTEXITCODE -ne 0) {
    Write-Error "git add failed."
    exit 1
}

# PrivilegedEAM is ignored for local safety because it contains tenant data, but
# the automation pipelines explicitly publish this generated output to private repositories.
if (Test-Path -LiteralPath './PrivilegedEAM' -PathType Container) {
    git add --force --all -- './PrivilegedEAM'
    if ($LASTEXITCODE -ne 0) {
        Write-Error "git add failed for generated PrivilegedEAM output."
        exit 1
    }
}

git diff-index --quiet HEAD
if ($LASTEXITCODE -eq 0) {
    Write-Host "No changes to commit."
    exit 0
}

git commit -m "$CommitMessage [skip ci]"
if ($LASTEXITCODE -ne 0) {
    Write-Error "git commit failed."
    exit 1
}

$CollectionUri = $env:SYSTEM_COLLECTIONURI
if ([string]::IsNullOrWhiteSpace($CollectionUri)) {
    $OriginUrl = [string](git remote get-url origin)
    $OriginUrl = $OriginUrl.Trim()
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($OriginUrl)) {
        Write-Error "Unable to determine the origin URL for credential scoping."
        exit 1
    }
    try {
        $OriginUri = [uri]$OriginUrl
        $CollectionUri = $OriginUri.GetLeftPart([System.UriPartial]::Authority)
    } catch {
        Write-Error "Unable to parse the origin URL for credential scoping: $_"
        exit 1
    }
}

try {
    $CredentialScopeUri = [uri]$CollectionUri
    if (-not $CredentialScopeUri.IsAbsoluteUri -or $CredentialScopeUri.Scheme -ne 'https') {
        throw "Credential scope must be an absolute HTTPS URI."
    }
    $CollectionUri = $CredentialScopeUri.AbsoluteUri
} catch {
    Write-Error "Invalid credential scope URI: $_"
    exit 1
}

$ExtraHeaderKey = "http.$($CollectionUri.TrimEnd('/'))/.extraHeader"
$ManagedEnvironment = @('GIT_CONFIG_COUNT', 'GIT_CONFIG_KEY_0', 'GIT_CONFIG_VALUE_0', 'GIT_CONFIG_KEY_1', 'GIT_CONFIG_VALUE_1')
$PreviousEnvironment = @{}
foreach ($Name in $ManagedEnvironment) {
    $PreviousEnvironment[$Name] = [Environment]::GetEnvironmentVariable($Name)
}

$PushExitCode = 1
try {
    $env:GIT_CONFIG_COUNT = '2'
    $env:GIT_CONFIG_KEY_0 = $ExtraHeaderKey
    $env:GIT_CONFIG_VALUE_0 = ''
    $env:GIT_CONFIG_KEY_1 = $ExtraHeaderKey
    $env:GIT_CONFIG_VALUE_1 = "AUTHORIZATION: bearer $AccessToken"
    # Another pipeline may have pushed since checkout; replay the commit on top of the current branch
    git fetch origin $BranchName
    if ($LASTEXITCODE -ne 0) {
        Write-Error "git fetch failed."
    } else {
        git rebase --autostash "origin/$BranchName"
        if ($LASTEXITCODE -ne 0) {
            Write-Error "git rebase onto origin/$BranchName failed."
            git rebase --abort 2>$null
        } else {
            git push origin HEAD:$BranchName
            $PushExitCode = $LASTEXITCODE
        }
    }
} finally {
    foreach ($Name in $ManagedEnvironment) {
        [Environment]::SetEnvironmentVariable($Name, $PreviousEnvironment[$Name])
    }
}

if ($PushExitCode -ne 0) {
    Write-Error "git push failed."
    exit 1
}

Write-Host "Successfully pushed changes to $BranchName."
