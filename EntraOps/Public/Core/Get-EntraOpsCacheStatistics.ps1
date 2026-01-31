<#
.SYNOPSIS
    Get statistics about the current EntraOps cache usage and performance metrics.

.DESCRIPTION
    Display detailed information about the in-memory and persistent cache, including entry counts,
    TTL information, expiry status, and cache hit/miss statistics.

.PARAMETER Detailed
    Show detailed information about each cached entry including URIs and expiry times.

.EXAMPLE
    Get a summary of cache statistics:
    Get-EntraOpsCacheStatistics

.EXAMPLE
    Get detailed cache information including all cached URIs:
    Get-EntraOpsCacheStatistics -Detailed
#>

function Get-EntraOpsCacheStatistics {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [switch]$Detailed
    )
    
    $CurrentTime = [DateTime]::UtcNow
    
    # Count total cache entries
    $TotalEntries = $__EntraOpsSession.GraphCache.Count
    
    # Count entries with metadata
    $EntriesWithMetadata = $__EntraOpsSession.CacheMetadata.Count
    $LegacyEntries = $TotalEntries - $EntriesWithMetadata
    
    # Analyze TTL and expiry
    $ExpiredEntries = 0
    $ValidEntries = 0
    $StaticDataEntries = 0
    $DynamicDataEntries = 0
    $TotalResultCount = 0
    $NextExpiry = $null
    
    foreach ($Key in $__EntraOpsSession.CacheMetadata.Keys) {
        $Metadata = $__EntraOpsSession.CacheMetadata[$Key]
        
        if ($CurrentTime -gt $Metadata.ExpiryTime) {
            $ExpiredEntries++
        } else {
            $ValidEntries++
            if ($null -eq $NextExpiry -or $Metadata.ExpiryTime -lt $NextExpiry) {
                $NextExpiry = $Metadata.ExpiryTime
            }
        }
        
        if ($Metadata.IsStaticData) {
            $StaticDataEntries++
        } else {
            $DynamicDataEntries++
        }
        
        $TotalResultCount += $Metadata.ResultCount
    }
    
    # Check persistent cache
    $PersistentCacheCount = 0
    $PersistentCacheSize = 0
    $CacheLocation = $__EntraOpsSession.PersistentCachePath

    if (Test-Path $CacheLocation) {
        # Calculate full size of the dedicated cache directory
        $PersistentFiles = Get-ChildItem -Path $CacheLocation -Recurse -File -ErrorAction SilentlyContinue
        $PersistentCacheCount = $PersistentFiles.Count
        if ($PersistentCacheCount -gt 0) {
            $PersistentCacheSize = ($PersistentFiles | Measure-Object -Property Length -Sum).Sum / 1MB
        }
    } else {
        $CacheLocation = "$CacheLocation (Not created)"
    }
    
    # Create summary object
    $Summary = [PSCustomObject]@{
        'Total Memory Entries'      = $TotalEntries
        'Valid Memory Entries'      = $ValidEntries
        'Expired Memory Entries'    = $ExpiredEntries
        'Legacy Entries (No TTL)'   = $LegacyEntries
        'Static Data Entries'       = $StaticDataEntries
        'Dynamic Data Entries'      = $DynamicDataEntries
        'Total Cached Objects'      = $TotalResultCount
        'Persistent Cache Files'    = $PersistentCacheCount
        'Cache Size on Disk (MB)'   = [math]::Round($PersistentCacheSize, 2)
        'Cache Location'            = $CacheLocation
        'Next Expiry Time (UTC)'    = if ($NextExpiry) { $NextExpiry.ToString("HH:mm:ss") } else { "N/A" }
        'Default TTL (seconds)'     = $__EntraOpsSession.DefaultCacheTTL
        'Static Data TTL (seconds)' = $__EntraOpsSession.StaticDataCacheTTL
    }
    
    Write-Host "`n=== EntraOps Cache Statistics ===" -ForegroundColor Cyan
    $Summary | Format-List
    
    if ($ExpiredEntries -gt 0) {
        Write-Host "Tip: Run 'Clear-EntraOpsCache -CacheType Expired' to remove $ExpiredEntries expired entries." -ForegroundColor Yellow
    }
    
    if ($Detailed) {
        Write-Host "`n=== Detailed Cache Entries ===" -ForegroundColor Cyan
        
        $DetailedEntries = foreach ($Key in $__EntraOpsSession.CacheMetadata.Keys) {
            $Metadata = $__EntraOpsSession.CacheMetadata[$Key]
            $TimeUntilExpiry = ($Metadata.ExpiryTime - $CurrentTime).TotalSeconds
            
            [PSCustomObject]@{
                'URI'                         = $Metadata.Uri
                'Result Count'                = $Metadata.ResultCount
                'Cached Time (UTC)'           = $Metadata.CachedTime.ToString("yyyy-MM-dd HH:mm:ss")
                'Expiry Time (UTC)'           = $Metadata.ExpiryTime.ToString("HH:mm:ss")
                'TTL (seconds)'               = $Metadata.TTLSeconds
                'Time Until Expiry (seconds)' = [math]::Round($TimeUntilExpiry, 0)
                'Is Static Data'              = $Metadata.IsStaticData
                'Status'                      = if ($TimeUntilExpiry -gt 0) { "Valid" } else { "Expired" }
            }
        }
        
        $DetailedEntries | Sort-Object 'Time Until Expiry (seconds)' | Format-Table -AutoSize
    }
}
