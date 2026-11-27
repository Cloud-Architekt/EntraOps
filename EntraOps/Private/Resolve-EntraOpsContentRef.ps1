function Resolve-EntraOpsContentRef {
    <#
    .SYNOPSIS
        Finds the commit of an EntraOps branch whose content matches the version of the module.

    .DESCRIPTION
        Content that is downloaded for a module-only installation (reporting apps, classification templates,
        samples) must match the module. The version is taken from EntraOps/EntraOps.psd1:
          * The branch head has the version of the module: the branch is used (BranchHead).
          * The module is older than the branch head: the release tag of the module version (v<version>, then
            <version>) is used when its EntraOps.psd1 has the version (ReleaseTag). Otherwise the history of
            EntraOps.psd1 on the branch is searched for the newest content of the module version, the parent of the
            commit that changed the version away from it (BranchHistory, a commit SHA). The history is listed by
            date and can contain commits of merged side branches, so the version is verified at the candidate; when
            the parent doesn't have it, the commit that has the version is used.
          * The module is newer than the branch head (for example an Insiders or pre-release build), or its version
            isn't on the branch: no matching content exists (NoMatch, Matched = $false, Ref = the branch).
        The branch head and tags are read from raw.githubusercontent.com (public repository) without a GitHub API
        request; only the history search uses the API.

    .PARAMETER Repository
        EntraOps distribution repository: 'EntraOps' (public) or 'EntraOps-Insiders' (private, needs a token).

    .PARAMETER Branch
        Branch to search. Default: main.

    .PARAMETER ModuleVersion
        Version to match. Defaults to the version of the loaded module.

    .PARAMETER PersonalAccessToken
        GitHub token for 'EntraOps-Insiders'. Defaults to ENTRAOPS_PAT.

    .PARAMETER MaxHistoryPages
        Pages of 100 commits of the manifest history to search. Default: 3.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param (
        [Parameter(Mandatory = $false)]
        [ValidateSet('EntraOps', 'EntraOps-Insiders')]
        [string]$Repository = 'EntraOps',

        [Parameter(Mandatory = $false)]
        [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9._/-]{0,199}$')]
        [string]$Branch = 'main',

        [Parameter(Mandatory = $false)]
        [version]$ModuleVersion,

        [Parameter(Mandatory = $false)]
        [string]$PersonalAccessToken,

        [Parameter(Mandatory = $false)]
        [ValidateRange(1, 10)]
        [int]$MaxHistoryPages = 3
    )

    if (-not $PSBoundParameters.ContainsKey('ModuleVersion')) { $ModuleVersion = Get-EntraOpsModuleVersion }
    if ([string]::IsNullOrWhiteSpace($PersonalAccessToken)) { $PersonalAccessToken = $env:ENTRAOPS_PAT }
    if ($Repository -eq 'EntraOps-Insiders' -and [string]::IsNullOrWhiteSpace($PersonalAccessToken)) {
        throw "Repository 'EntraOps-Insiders' is private and requires -PersonalAccessToken or ENTRAOPS_PAT. Use the public 'EntraOps' repository otherwise."
    }
    $Token = if ($Repository -eq 'EntraOps-Insiders') { $PersonalAccessToken } else { $null }

    # ModuleVersion of EntraOps/EntraOps.psd1 at a ref; $null when the file or the version is missing.
    $GetContentVersion = {
        param([string]$AtRef)
        $Text = if ($Repository -eq 'EntraOps-Insiders') {
            Invoke-EntraOpsGitHubRequest -Uri "https://api.github.com/repos/Cloud-Architekt/$Repository/contents/EntraOps/EntraOps.psd1?ref=$AtRef" -Token $Token -Headers @{ Accept = 'application/vnd.github.raw' }
        } else {
            Invoke-EntraOpsGitHubRequest -Uri "https://raw.githubusercontent.com/Cloud-Architekt/$Repository/$AtRef/EntraOps/EntraOps.psd1"
        }
        $Version = [version]::new(0, 0)
        if ("$Text" -match "ModuleVersion\s*=\s*['`"]([0-9][0-9.]*)['`"]" -and [version]::TryParse($Matches[1], [ref]$Version)) { return $Version }
        return $null
    }

    $Result = [ordered]@{
        Repository    = $Repository
        Branch        = $Branch
        Ref           = $Branch
        ModuleVersion = $ModuleVersion
        BranchVersion = $null
        ContentVersion = $null
        Matched       = $false
        Resolution    = 'NoMatch'
    }
    $Result.BranchVersion = & $GetContentVersion $Branch
    $Result.ContentVersion = $Result.BranchVersion
    if ($null -eq $ModuleVersion -or $null -eq $Result.BranchVersion) {
        # Unknown module version: the branch head is the best available content.
        $Result.Resolution = 'Unknown'
        return [pscustomobject]$Result
    }
    if ($Result.BranchVersion -eq $ModuleVersion) {
        $Result.Matched = $true
        $Result.Resolution = 'BranchHead'
        return [pscustomobject]$Result
    }
    if ($ModuleVersion -gt $Result.BranchVersion) {
        return [pscustomobject]$Result
    }

    # A missing tag or file answers 404: no content at this ref. Other errors (rate limit, network) still fail, so they
    # don't end in a wrong NoMatch.
    $TryGetContentVersion = {
        param([string]$AtRef)
        try {
            & $GetContentVersion $AtRef
        } catch {
            $StatusCode = $_.Exception.Response.StatusCode
            if (($null -ne $StatusCode -and [int]$StatusCode -eq 404) -or "$($_.Exception.Message)" -match '\b404\b') {
                Write-Verbose "No EntraOps.psd1 at '$AtRef' of $($Repository): $($_.Exception.Message)"
                return $null
            }
            throw
        }
    }

    # The module is older than the branch: the release of its version, when it is tagged.
    foreach ($Tag in @("v$ModuleVersion", "$ModuleVersion")) {
        if ((& $TryGetContentVersion $Tag) -eq $ModuleVersion) {
            $Result.Ref = $Tag
            $Result.ContentVersion = $ModuleVersion
            $Result.Matched = $true
            $Result.Resolution = 'ReleaseTag'
            return [pscustomobject]$Result
        }
    }

    # Otherwise the newest content of its version, before the commit that changed it.
    $PageSize = 100
    $NewerCommit = $null
    for ($Page = 1; $Page -le $MaxHistoryPages; $Page++) {
        $Commits = @(Invoke-EntraOpsGitHubRequest -Uri "https://api.github.com/repos/Cloud-Architekt/$Repository/commits?sha=$([uri]::EscapeDataString($Branch))&path=EntraOps/EntraOps.psd1&per_page=$PageSize&page=$Page" -Token $Token)
        foreach ($Commit in $Commits) {
            $Version = & $TryGetContentVersion $Commit.sha
            if ($Version -eq $ModuleVersion) {
                # The parent of the commit that changed the version is the newest content of the version. In a date-ordered
                # list with merged side branches, the newer commit can be of another line: then the matching commit is used.
                $Candidates = @(if ($null -ne $NewerCommit -and @($NewerCommit.parents).Count -gt 0) { [string]@($NewerCommit.parents)[0].sha }) + @([string]$Commit.sha)
                foreach ($Candidate in $Candidates) {
                    if ($Candidate -eq $Commit.sha -or (& $TryGetContentVersion $Candidate) -eq $ModuleVersion) {
                        $Result.Ref = $Candidate
                        $Result.ContentVersion = $Version
                        $Result.Matched = $true
                        $Result.Resolution = 'BranchHistory'
                        return [pscustomobject]$Result
                    }
                }
            }
            # Versions only grow along the history: an older version means the module version is not on the branch.
            if ($null -ne $Version -and $Version -lt $ModuleVersion) { return [pscustomobject]$Result }
            $NewerCommit = $Commit
        }
        if ($Commits.Count -lt $PageSize) { break }
    }
    [pscustomobject]$Result
}
