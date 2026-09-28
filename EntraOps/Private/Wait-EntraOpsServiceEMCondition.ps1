<#
.SYNOPSIS
    Polls a condition with capped exponential backoff until it is met or the maximum wait time is reached.

.DESCRIPTION
    Used by the ServiceEM cmdlets to wait for Microsoft Graph / Entitlement Management replication of newly
    created objects. The pause between two checks doubles (0, 1, 3, 7, 15 seconds ...) up to
    MaxIntervalSeconds. Returns $true as soon as the condition returns a truthy value, or $false when
    MaxWaitSeconds of sleep time have passed. Results the caller needs after the wait have to be stored in
    a reference object (e.g. a hashtable) inside the condition, because variables assigned in the script
    block don't leave its scope.

.PARAMETER Condition
    Script block that performs the check and returns $true when the expected state is reached.

.PARAMETER Activity
    Description of what is awaited, used in the verbose messages.

.PARAMETER MaxWaitSeconds
    Total sleep time after which the wait ends unsuccessfully. Defaults to 300 seconds.

.PARAMETER MaxIntervalSeconds
    Maximum pause between two checks. Defaults to 30 seconds.

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
        [string]$logPrefix = ""
    )

    $attempt = 0
    $waitedSeconds = 0
    while ($true) {
        $sleepSeconds = [int][Math]::Min([Math]::Pow(2, $attempt) - 1, $MaxIntervalSeconds)
        Start-Sleep -Seconds $sleepSeconds
        $waitedSeconds += $sleepSeconds
        if (& $Condition) {
            Write-Verbose "$logPrefix $Activity available (Graph consistency confirmed)"
            return $true
        }
        $attempt++
        if ($waitedSeconds -ge $MaxWaitSeconds) {
            return $false
        }
        Write-Verbose "$logPrefix $Activity not available yet, sleeping $([int][Math]::Min([Math]::Pow(2, $attempt) - 1, $MaxIntervalSeconds)) seconds"
    }
}
