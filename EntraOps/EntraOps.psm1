# Enforce PowerShell 7.4+ (Core) as a hard prerequisite.
# 7.4 is the floor because byte-preserving redirection of native command output (used by the
# Privilege History generator to capture "git archive" zip output) only became the default in 7.4;
# on 7.1-7.3 the stream is decoded as text and the archive is silently corrupted.
if ($PSVersionTable.PSVersion -lt [Version]'7.4') {
    throw "EntraOps requires PowerShell 7.4 or later (PowerShell Core). Current version: $($PSVersionTable.PSVersion). Please install PowerShell 7.4+ from https://aka.ms/powershell"
}

# Suppress welcome banner when loading in parallel runspaces (env var set by parallel blocks)
if ($env:ENTRAOPS_NOWELCOME) {
    $Script:SuppressWelcomeBanner = $true
}

# Get public and private function definition files.
$Public = @( Get-ChildItem -Path $PSScriptRoot\Public\*.ps1 -Recurse -ErrorAction SilentlyContinue )
$Private = @( Get-ChildItem -Path $PSScriptRoot\Private\*.ps1 -Recurse -ErrorAction SilentlyContinue )

# Dot source the files
Foreach ($import in @($Public + $Private)) {
    Try {
        Write-Verbose "Importing $($Import.FullName)"
        . $import.fullname
    } Catch {
        throw "Failed to import function $($import.fullname): $_"
    }
}

# Set Error Action
$ErrorActionPreference = "Stop"
Export-ModuleMember -Function $Public.Basename

# This function has been adopted from the Maester Framework and has been originally written by Merill Fernando
# Enhanced caching with TTL (Time-To-Live) and metadata for performance optimization

# Determine cross-platform user cache path following XDG and OS standards
if ($IsWindows -or $env:OS -match 'Windows_NT') {
    # Windows: %LOCALAPPDATA%\EntraOps (e.g. C:\Users\...\AppData\Local\EntraOps)
    $CacheRoot = [System.Environment]::GetFolderPath([System.Environment+SpecialFolder]::LocalApplicationData)
} elseif ($IsMacOS -or ([System.Runtime.InteropServices.RuntimeInformation]::IsOSPlatform([System.Runtime.InteropServices.OSPlatform]::OSX))) {
    # macOS: ~/Library/Caches/EntraOps
    $CacheRoot = Join-Path $HOME "Library/Caches"
} else {
    # Linux: $XDG_CACHE_HOME/EntraOps or ~/.cache/EntraOps
    $CacheRoot = if ($env:XDG_CACHE_HOME) { $env:XDG_CACHE_HOME } else { Join-Path $HOME ".cache" }
}

$PersistentCachePath = Join-Path $CacheRoot "EntraOps"

$__EntraOpsSession = [hashtable]::Synchronized(@{
    # Shared by reference with parallel runspaces (e.g. Invoke-EntraOpsParallelObjectResolution).
    # Synchronized hashtables protect individual operations; compound updates use explicit locking.
    GraphCache          = [hashtable]::Synchronized(@{})
    CacheMetadata       = [hashtable]::Synchronized(@{})
    MsGraphTokenCache   = [hashtable]::Synchronized(@{})
    ArmTokenCache       = [hashtable]::Synchronized(@{})
    # GroupObjectId -> $true once a group has been confirmed to have no PIM for Groups eligibility/
    # assignment data (Get-EntraOpsPrivilegedTransitiveGroupMember) - a group revisited via a different
    # nesting/catalog path within the same session skips the repeat (and, for structurally PIM-incapable
    # groups, always-failing) Graph probe instead of re-querying and re-warning every time.
    NonPimGroupIds      = [hashtable]::Synchronized(@{})
    RetryStatistics     = [hashtable]::Synchronized(@{
        TotalRetries               = 0
        ThrottledRequests          = 0
        FailedRequests             = 0
        NonRetryableRequests       = 0
        FailedRequestDetails       = [System.Collections.Concurrent.ConcurrentBag[object]]::new()
        NonRetryableRequestDetails = [System.Collections.Concurrent.ConcurrentBag[object]]::new()
    })
    PersistentCachePath = $PersistentCachePath
    DefaultCacheTTL     = 3600  # Default 1 hour for dynamic data
    StaticDataCacheTTL  = 3600  # 1 hour for static reference data (role definitions, etc.)
    AuthenticationType  = $null  # Set by Connect-EntraOps; used to determine cross-tenant token acquisition strategy
})
New-Variable -Name __EntraOpsSession -Value $__EntraOpsSession -Scope Script -Force

# Ensure persistent cache directory exists
if (-not (Test-Path -LiteralPath $__EntraOpsSession.PersistentCachePath)) {
    try {
        New-Item -ItemType Directory -Path $__EntraOpsSession.PersistentCachePath -Force | Out-Null
        Write-Verbose "Created persistent cache directory: $($__EntraOpsSession.PersistentCachePath)"
    } catch {
        Write-Warning "Failed to create persistent cache directory: $_"
    }
}

# Global variable: the working folder for configuration, classification, exports and reports.
$EntraOpsBaseFolderResolution = Resolve-EntraOpsBaseFolder -ModuleRoot $PSScriptRoot
$EntraOpsBasefolder = $EntraOpsBaseFolderResolution.Path
Write-Verbose "EntraOps working folder ($($EntraOpsBaseFolderResolution.Source)): $EntraOpsBasefolder"
New-Variable -Name EntraOpsBaseFolder -Value $EntraOpsBasefolder -Scope Global -Force
