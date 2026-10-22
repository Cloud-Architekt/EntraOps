#Requires -Version 7.4
# Shared helpers of the Azure DevOps pipeline scripts. The job access token is only passed to the git
# commands that need it, through process environment variables scoped to the collection URL, so it is
# never written to .git/config where later steps (module or candidate code) could read it.

function Get-EntraOpsAdoCollectionUri {
    [CmdletBinding()]
    [OutputType([string])]
    param (
        [Parameter(Mandatory = $false)]
        [string]$CollectionUri = $env:SYSTEM_COLLECTIONURI
    )

    if ([string]::IsNullOrWhiteSpace($CollectionUri)) {
        $OriginUrl = (@(& git remote get-url origin) -join "`n").Trim()
        if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($OriginUrl)) {
            throw 'Unable to determine the origin URL for credential scoping.'
        }
        $CollectionUri = ([uri]$OriginUrl).GetLeftPart([System.UriPartial]::Authority)
    }
    $CredentialScopeUri = [uri]$CollectionUri
    if (-not $CredentialScopeUri.IsAbsoluteUri -or $CredentialScopeUri.Scheme -ne 'https') {
        throw "Invalid credential scope '$CollectionUri': it must be an absolute HTTPS URI."
    }
    return $CredentialScopeUri.AbsoluteUri.TrimEnd('/')
}

function Get-EntraOpsAdoBranchName {
    [CmdletBinding()]
    [OutputType([string])]
    param (
        # BUILD_SOURCEBRANCHNAME is only the last segment of the ref (refs/heads/release/v1 -> v1)
        [Parameter(Mandatory = $false)]
        [string]$SourceBranch = $env:BUILD_SOURCEBRANCH
    )

    $BranchName = $SourceBranch -replace '^refs/heads/', ''
    if ([string]::IsNullOrWhiteSpace($BranchName) -or $BranchName -like 'refs/*' -or $BranchName.StartsWith('-') -or $BranchName -match '\s') {
        throw "Unable to determine the branch from '$SourceBranch'. Run the pipeline from a branch (refs/heads/...)."
    }
    return $BranchName
}

function Invoke-EntraOpsAdoAuthenticatedGit {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$AccessToken,

        [Parameter(Mandatory = $true)]
        [string]$CollectionUri,

        [Parameter(Mandatory = $true)]
        [scriptblock]$ScriptBlock
    )

    if ([string]::IsNullOrWhiteSpace($AccessToken)) {
        throw 'The Azure DevOps job access token (System.AccessToken) is required.'
    }
    $ExtraHeaderKey = "http.$($CollectionUri.TrimEnd('/'))/.extraHeader"
    $ManagedEnvironment = @('GIT_CONFIG_COUNT', 'GIT_CONFIG_KEY_0', 'GIT_CONFIG_VALUE_0', 'GIT_CONFIG_KEY_1', 'GIT_CONFIG_VALUE_1')
    $PreviousEnvironment = @{}
    foreach ($Name in $ManagedEnvironment) {
        $PreviousEnvironment[$Name] = [Environment]::GetEnvironmentVariable($Name)
    }
    try {
        # The empty value first resets any extraHeader inherited from the checkout configuration
        $env:GIT_CONFIG_COUNT = '2'
        $env:GIT_CONFIG_KEY_0 = $ExtraHeaderKey
        $env:GIT_CONFIG_VALUE_0 = ''
        $env:GIT_CONFIG_KEY_1 = $ExtraHeaderKey
        $env:GIT_CONFIG_VALUE_1 = "AUTHORIZATION: bearer $AccessToken"
        & $ScriptBlock
    } finally {
        foreach ($Name in $ManagedEnvironment) {
            [Environment]::SetEnvironmentVariable($Name, $PreviousEnvironment[$Name])
        }
    }
}

function Get-EntraOpsAdoSecretValue {
    [CmdletBinding()]
    [OutputType([string])]
    param (
        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string]$Value
    )

    # An undefined pipeline variable is passed on literally as "$(Name)" instead of an empty value
    if ([string]::IsNullOrWhiteSpace($Value) -or $Value -match '^\$\([^)]*\)$') {
        return ''
    }
    return $Value
}

function Assert-EntraOpsAdoProjectIsPrivate {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$AccessToken,

        [Parameter(Mandatory = $true)]
        [string]$CollectionUri,

        [Parameter(Mandatory = $false)]
        [string]$ProjectId = $env:SYSTEM_TEAMPROJECTID
    )

    if ([string]::IsNullOrWhiteSpace($ProjectId)) {
        throw 'Unable to determine the Azure DevOps project (SYSTEM_TEAMPROJECTID) to verify its visibility.'
    }
    try {
        $Project = Invoke-RestMethod -Method Get -Uri "$CollectionUri/_apis/projects/$($ProjectId)?api-version=7.1" -Headers @{ Authorization = "Bearer $AccessToken" }
    } catch {
        throw "Could not verify the Azure DevOps project visibility: $($_.Exception.Message)"
    }
    if ($Project.visibility -ne 'private') {
        throw "Azure DevOps project '$($Project.name)' is not private (visibility: $($Project.visibility)). The repository contains tenant data; refusing to publish."
    }
}
