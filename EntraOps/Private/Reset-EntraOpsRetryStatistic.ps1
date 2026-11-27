function Reset-EntraOpsRetryStatistic {
    <#
    .SYNOPSIS
        Resets the retry and throttling counters that Save-EntraOpsPrivilegedEAMJson summarizes.
    #>
    [CmdletBinding()]
    param ()

    $Statistics = $__EntraOpsSession.RetryStatistics
    if (-not $Statistics) { return }
    [System.Threading.Monitor]::Enter($Statistics.SyncRoot)
    try {
        $Statistics.TotalRetries = 0
        $Statistics.ThrottledRequests = 0
        $Statistics.FailedRequests = 0
        $Statistics.NonRetryableRequests = 0
        $Statistics.FailedRequestDetails = [System.Collections.Concurrent.ConcurrentBag[object]]::new()
        $Statistics.NonRetryableRequestDetails = [System.Collections.Concurrent.ConcurrentBag[object]]::new()
    } finally {
        [System.Threading.Monitor]::Exit($Statistics.SyncRoot)
    }
}
