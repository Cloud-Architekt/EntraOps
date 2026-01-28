<#
.SYNOPSIS
    Resets the local cache of Graph API calls. Use this if you need to force a refresh of the cache in the current session.

.DESCRIPTION
    By default all graph responses are cached and re-used for the duration of the session.
    Use this function to clear the cache and force a refresh of the data from Microsoft Graph.
    This function has been written by Merill Fernando as part of Maester Framework.

.PARAMETER CacheType
    Type of cache to clear. Options: All (default), Memory, Persistent, Expired

.PARAMETER Pattern
    Optional URI pattern to selectively clear cache entries (supports wildcards)

.EXAMPLE
    This example clears all cache of Graph API calls in EntraOps.
    Clear-EntraOpsCache

.EXAMPLE
    This example clears only expired cache entries.
    Clear-EntraOpsCache -CacheType Expired

.EXAMPLE
    This example clears cache for role-related endpoints only.
    Clear-EntraOpsCache -Pattern "*roleManagement*"
#>

function Clear-EntraOpsCache {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [ValidateSet("All", "Memory", "Persistent", "Expired")]
        [string]$CacheType = "All",
        
        [Parameter(Mandatory = $false)]
        [string]$Pattern = "*"
    )
    
    $ClearedCount = 0
    
    switch ($CacheType) {
        "Expired" {
            Write-Verbose "Clearing expired cache entries matching pattern: $Pattern"
            $CurrentTime = [DateTime]::UtcNow
            $KeysToRemove = @()
            
            foreach ($Key in $__EntraOpsSession.GraphCache.Keys) {
                if ($Key -like $Pattern -and $__EntraOpsSession.CacheMetadata.ContainsKey($Key)) {
                    $ExpiryTime = $__EntraOpsSession.CacheMetadata[$Key].ExpiryTime
                    if ($CurrentTime -gt $ExpiryTime) {
                        $KeysToRemove += $Key
                    }
                }
            }
            
            foreach ($Key in $KeysToRemove) {
                $__EntraOpsSession.GraphCache.Remove($Key)
                $__EntraOpsSession.CacheMetadata.Remove($Key)
                $ClearedCount++
            }
            Write-Verbose "Cleared $ClearedCount expired cache entries"
        }
        
        "Memory" {
            Write-Verbose "Clearing memory cache matching pattern: $Pattern"
            $KeysToRemove = @($__EntraOpsSession.GraphCache.Keys | Where-Object { $_ -like $Pattern })
            
            foreach ($Key in $KeysToRemove) {
                $__EntraOpsSession.GraphCache.Remove($Key)
                $__EntraOpsSession.CacheMetadata.Remove($Key)
                $ClearedCount++
            }
            Write-Verbose "Cleared $ClearedCount memory cache entries"
        }
        
        "Persistent" {
            Write-Verbose "Clearing persistent cache files matching pattern: $Pattern"
            if (Test-Path $__EntraOpsSession.PersistentCachePath) {
                $Files = Get-ChildItem -Path $__EntraOpsSession.PersistentCachePath -Filter "*.json" | Where-Object { $_.Name -like "*$Pattern*" }
                foreach ($File in $Files) {
                    Remove-Item -Path $File.FullName -Force
                    $ClearedCount++
                }
            }
            Write-Verbose "Cleared $ClearedCount persistent cache files"
        }
        
        "All" {
            Write-Verbose "Clearing all cache (memory and persistent) matching pattern: $Pattern"
            
            # Clear memory cache
            $KeysToRemove = @($__EntraOpsSession.GraphCache.Keys | Where-Object { $_ -like $Pattern })
            foreach ($Key in $KeysToRemove) {
                $__EntraOpsSession.GraphCache.Remove($Key)
                $__EntraOpsSession.CacheMetadata.Remove($Key)
                $ClearedCount++
            }
            
            # Clear persistent cache
            if (Test-Path $__EntraOpsSession.PersistentCachePath) {
                $Files = Get-ChildItem -Path $__EntraOpsSession.PersistentCachePath -Filter "*.json" | Where-Object { $_.Name -like "*$Pattern*" }
                foreach ($File in $Files) {
                    Remove-Item -Path $File.FullName -Force
                    $ClearedCount++
                }
            }
            Write-Verbose "Cleared total of $ClearedCount cache entries"
        }
    }
    
    if ($ClearedCount -eq 0) {
        Write-Verbose "No cache entries found matching pattern: $Pattern"
    } else {
        Write-Host "Cleared $ClearedCount cache entries"
    }
}