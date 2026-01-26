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
    
    foreach ($Key in $__EntraOpsSession.CacheMetadata.Keys) {
        $Metadata = $__EntraOpsSession.CacheMetadata[$Key]
        
        if ($CurrentTime -gt $Metadata.ExpiryTime) {
            $ExpiredEntries++
        } else {
            $ValidEntries++
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
    if (Test-Path $__EntraOpsSession.PersistentCachePath) {
        $PersistentFiles = Get-ChildItem -Path $__EntraOpsSession.PersistentCachePath -Filter "*.json"
        $PersistentCacheCount = $PersistentFiles.Count
        $PersistentCacheSize = ($PersistentFiles | Measure-Object -Property Length -Sum).Sum / 1MB
    }
    
    # Create summary object
    $Summary = [PSCustomObject]@{
        'Total Cache Entries' = $TotalEntries
        'Valid Entries' = $ValidEntries
        'Expired Entries' = $ExpiredEntries
        'Legacy Entries (No TTL)' = $LegacyEntries
        'Static Data Entries' = $StaticDataEntries
        'Dynamic Data Entries' = $DynamicDataEntries
        'Total Cached Objects' = $TotalResultCount
        'Persistent Cache Files' = $PersistentCacheCount
        'Persistent Cache Size (MB)' = [math]::Round($PersistentCacheSize, 2)
        'Default TTL (seconds)' = $__EntraOpsSession.DefaultCacheTTL
        'Static Data TTL (seconds)' = $__EntraOpsSession.StaticDataCacheTTL
        'Cache Directory' = $__EntraOpsSession.PersistentCachePath
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
                'URI' = $Metadata.Uri
                'Result Count' = $Metadata.ResultCount
                'Cached Time' = $Metadata.CachedTime.ToString("yyyy-MM-dd HH:mm:ss")
                'TTL (seconds)' = $Metadata.TTLSeconds
                'Time Until Expiry (seconds)' = [math]::Round($TimeUntilExpiry, 0)
                'Is Static Data' = $Metadata.IsStaticData
                'Status' = if ($TimeUntilExpiry -gt 0) { "Valid" } else { "Expired" }
            }
        }
        
        $DetailedEntries | Sort-Object 'Time Until Expiry (seconds)' | Format-Table -AutoSize
    }
}
