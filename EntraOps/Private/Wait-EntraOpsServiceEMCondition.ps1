<#
.SYNOPSIS
    Polls a condition with capped exponential backoff until it is met or the maximum wait time is reached.

.DESCRIPTION
    Used by the ServiceEM cmdlets to wait for Microsoft Graph / Entitlement Management replication of newly
    created objects. The pause between two checks doubles (0, 1, 3, 7, 15 seconds ...) up to
    MaxIntervalSeconds. Returns $true as soon as the condition returns a truthy value, or $false when
    MaxWaitSeconds of elapsed time have passed (including condition checks). An in-flight check is allowed to finish. Results the caller needs after the wait have to be stored in
    a reference object (e.g. a hashtable) inside the condition, because variables assigned in the script
    block don't leave its scope.

.PARAMETER Condition
    Script block that performs the check and returns $true when the expected state is reached.

.PARAMETER Activity
    Description of what is awaited, used in the verbose messages.

.PARAMETER MaxWaitSeconds
    Elapsed time budget, including condition checks; an in-flight check is allowed to finish. Defaults to 300 seconds.

.PARAMETER MaxIntervalSeconds
    Maximum pause between two checks. Defaults to 30 seconds.

.PARAMETER ProgressStatus
    Optional script block returning a short progress message, such as the pending request count.

.PARAMETER logPrefix
    Text prepended to verbose messages.

.EXAMPLE
    $state = @{}
    $ready = Wait-EntraOpsServiceEMCondition -Activity "Catalog" -Condition {
        $state.Catalog = Invoke-EntraOpsMsGraphQuery -Method GET -Uri $uri -OutputType PSObject -DisableCache
        $null -ne $state.Catalog
    }
#>
function Wait-EntraOpsServiceEMCondition {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [scriptblock]$Condition,

        [Parameter(Mandatory = $false)]
        [string]$Activity = "Graph objects",

        [Parameter(Mandatory = $false)]
        [ValidateRange(0, 3600)]
        [int]$MaxWaitSeconds = 300,

        [Parameter(Mandatory = $false)]
        [ValidateRange(1, 300)]
        [int]$MaxIntervalSeconds = 30,

        [Parameter(Mandatory = $false)]
        [string]$logPrefix = "",

        [scriptblock]$ProgressStatus
    )

    $attempt = 0
    $startedAt = Get-Date
    $progressId = Get-Random -Minimum 50000 -Maximum ([int]::MaxValue)
    try {
        while ($true) {
            $elapsed = [Math]::Max(0, ((Get-Date) - $startedAt).TotalSeconds)
            $detail = if ($ProgressStatus) { & $ProgressStatus } else { 'Checking status' }
            Write-Progress -Id $progressId -Activity $Activity -Status "$([Math]::Round($elapsed)) seconds elapsed. $detail"
            # Keep the immediate first check; subsequent sleeps fit within the remaining budget.
            if ($attempt -eq 0) { Start-Sleep -Seconds 0 }
            if (& $Condition) {
                $elapsed = [Math]::Max(0, ((Get-Date) - $startedAt).TotalSeconds)
                Write-Verbose "$logPrefix $Activity completed after $([Math]::Round($elapsed, 1)) seconds"
                return $true
            }
            $elapsed = [Math]::Max(0, ((Get-Date) - $startedAt).TotalSeconds)
            $remaining = $MaxWaitSeconds - $elapsed
            if ($remaining -le 0) {
                Write-Verbose "$logPrefix $Activity timed out after $([Math]::Round($elapsed, 1)) seconds"
                return $false
            }
            $attempt++
            $sleepSeconds = [Math]::Min([Math]::Min([Math]::Pow(2, $attempt) - 1, $MaxIntervalSeconds), $remaining)
            Write-Verbose "$logPrefix Waiting for $Activity ($([Math]::Round($elapsed, 1)) seconds elapsed); checking again in $([Math]::Round($sleepSeconds, 1)) seconds"
            $detail = if ($ProgressStatus) { & $ProgressStatus } else { 'Waiting for the next check' }
            Write-Progress -Id $progressId -Activity $Activity -Status "$([Math]::Round($elapsed)) seconds elapsed. $detail; next check in $([Math]::Round($sleepSeconds, 1)) seconds"
            Start-Sleep -Seconds $sleepSeconds
        }
    } finally {
        Write-Progress -Id $progressId -Activity $Activity -Completed
    }
}
