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
$__EntraOpsSession = @{
    GraphCache = @{}
    CacheMetadata = @{}
    PersistentCachePath = (Join-Path $PSScriptRoot ".cache")
    DefaultCacheTTL = 300  # Default 5 minutes for dynamic data
    StaticDataCacheTTL = 3600  # 1 hour for static reference data (role definitions, etc.)
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
