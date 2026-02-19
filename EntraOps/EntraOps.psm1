# Enforce PowerShell 7+ (Core) as a hard prerequisite
if ($PSVersionTable.PSVersion.Major -lt 7) {
    throw "EntraOps requires PowerShell 7.0 or later (PowerShell Core). Current version: $($PSVersionTable.PSVersion). Please install PowerShell 7+ from https://aka.ms/powershell"
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
        Write-Error -Message "Failed to import function $($import.fullname): $_"
    }
}

# Set Error Action
$ErrorActionPreference = "Stop"
Export-ModuleMember -Function $Public.Basename

# Update Clear-ModuleVariable function in internal/Clear-ModuleVariable.ps1 if you add new variables here
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

$__EntraOpsSession = @{
    GraphCache          = @{}
    CacheMetadata       = @{}
    PersistentCachePath = $PersistentCachePath
    DefaultCacheTTL     = 3600  # Default 1 hour for dynamic data
    StaticDataCacheTTL  = 3600  # 1 hour for static reference data (role definitions, etc.)
}
New-Variable -Name __EntraOpsSession -Value $__EntraOpsSession -Scope Script -Force

# Ensure persistent cache directory exists
if (-not (Test-Path $__EntraOpsSession.PersistentCachePath)) {
    try {
        New-Item -ItemType Directory -Path $__EntraOpsSession.PersistentCachePath -Force | Out-Null
        Write-Verbose "Created persistent cache directory: $($__EntraOpsSession.PersistentCachePath)"
    } catch {
        Write-Warning "Failed to create persistent cache directory: $_"
    }
}

# Global variable
$EntraOpsBasefolder = (Get-Item -Path $PSScriptRoot).Parent.FullName
New-Variable -Name EntraOpsBaseFolder -Value $EntraOpsBasefolder -Scope Global -Force
