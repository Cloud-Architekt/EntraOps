<#
.SYNOPSIS
    Build the EAM Dashboard objects of the previous Privileged EAM export from git history.

.DESCRIPTION
    Change notification baseline of New-EntraOpsPrivilegedEamDashboardData when no previous
    dataset exists, for example in the reporting pipelines, which never commit generated report
    data. The baseline is the Privileged EAM export of the latest `reporting-*` tag reachable
    from HEAD (the commit of the latest published GitHub reporting release). Without such a tag,
    it is the export before its latest change: HEAD when the export has uncommitted changes,
    otherwise the parent of the latest commit that changed it.

    Returns $null without git, outside a git working copy, without a previous export or when the
    previous export cannot be read, so the caller generates no notifications.

.PARAMETER ImportPath
    Folder with the current Privileged EAM export inside a git working copy.

.PARAMETER TenantId
    Home tenant id passed to Get-EntraOpsPrivilegedEamDashboardObjects.
#>

function Get-EntraOpsPrivilegedEamGitBaselineObjects {

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [System.String]$ImportPath,

        [Parameter(Mandatory = $false)]
        [System.String]$TenantId
    )

    if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
        Write-Verbose 'git was not found on PATH; no EAM Dashboard change notification baseline from git history.'
        return $null
    }
    $GitRoot = & git -C $ImportPath rev-parse --show-toplevel 2>$null
    $RelPath = & git -C $ImportPath rev-parse --show-prefix 2>$null
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($GitRoot) -or [string]::IsNullOrWhiteSpace($RelPath)) {
        Write-Verbose "$ImportPath is not a folder inside a git working copy; no EAM Dashboard change notification baseline from git history."
        return $null
    }
    $GitRoot = $GitRoot.Trim()
    $RelPath = $RelPath.Trim().TrimEnd('/')

    $Tag = @(& git -C $GitRoot tag --list 'reporting-*' --merged HEAD --sort=-refname 2>$null | Where-Object { $_ -match '^reporting-\d{8}-\d{6}$' })[0]
    if ($Tag) {
        $BaselineRef = $Tag
        $BaselineSource = "reporting release $Tag"
    } elseif (& git -C $GitRoot status --porcelain -- $RelPath 2>$null) {
        $BaselineRef = 'HEAD'
        $BaselineSource = 'the last commit'
    } else {
        $LatestCommit = & git -C $GitRoot rev-list -n 1 HEAD -- $RelPath 2>$null
        if ([string]::IsNullOrWhiteSpace($LatestCommit)) {
            Write-Verbose "No commit of $RelPath found; change notifications start with the next export."
            return $null
        }
        $BaselineRef = "$($LatestCommit.Trim())^"
        $BaselineSource = "the commit before $($LatestCommit.Trim().Substring(0, 8))"
    }
    $BaselineSha = & git -C $GitRoot rev-parse --verify --quiet "$BaselineRef^{commit}" 2>$null
    if ([string]::IsNullOrWhiteSpace($BaselineSha)) {
        Write-Verbose "No previous commit of $RelPath found; change notifications start with the next export."
        return $null
    }
    $BaselineSha = $BaselineSha.Trim()

    $TempDir = Join-Path ([System.IO.Path]::GetTempPath()) "EntraOpsEamBaseline_$([guid]::NewGuid().ToString('N'))"
    $TempZip = "$TempDir.zip"
    try {
        # Let git write the zip itself (--output): PowerShell redirection only preserves raw bytes on PS >= 7.5.
        & git -C $GitRoot archive --format=zip --output=$TempZip $BaselineSha -- $RelPath 2>$null
        if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $TempZip -PathType Leaf)) {
            Write-Verbose "$RelPath did not exist at $BaselineSource ($BaselineSha); change notifications start with the next export."
            return $null
        }
        Expand-Archive -LiteralPath $TempZip -DestinationPath $TempDir -Force
        $Objects = Get-EntraOpsPrivilegedEamDashboardObjects -ImportPath (Join-Path $TempDir $RelPath) -TenantId $TenantId
        Write-Host "Change notification baseline: Privileged EAM export of $BaselineSource ($($BaselineSha.Substring(0, 8)))"
        return , @($Objects)
    } catch {
        Write-Warning "The Privileged EAM export of $BaselineSource could not be used as a notification baseline; change notifications will not be generated for this run: $($_.Exception.Message)"
        return $null
    } finally {
        Remove-Item -LiteralPath $TempDir, $TempZip -Recurse -Force -ErrorAction SilentlyContinue
    }
}
