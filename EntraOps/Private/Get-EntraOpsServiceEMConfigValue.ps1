<#
.SYNOPSIS
    Returns a value from the ServiceEM section of the loaded EntraOps configuration.

.DESCRIPTION
    Reads a dot-separated path below $Global:EntraOpsConfig.ServiceEM (e.g. "CreateM365Group" or
    "PIMForGroups.MaximumActivationDuration"). Works with configurations loaded as hashtable
    (Connect-EntraOps) or as PSCustomObject and returns $null if the configuration, the ServiceEM
    section or any part of the path is missing. Lists are returned as they are, also when empty.

.PARAMETER Path
    Dot-separated path below the ServiceEM section.

.EXAMPLE
    Get-EntraOpsServiceEMConfigValue -Path "DefaultAzureRegion"
#>
function Get-EntraOpsServiceEMConfigValue {
    [CmdletBinding()]
    [OutputType([object])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $current = $Global:EntraOpsConfig
    foreach ($segment in @('ServiceEM') + ($Path -split '\.')) {
        if ($null -eq $current) { return $null }
        # Plain assignments: "$current = if (...) { <list> }" would enumerate the list and turn an empty one into $null
        if ($current -is [System.Collections.IDictionary]) {
            if (-not $current.Contains($segment)) { return $null }
            $current = $current[$segment]
        } else {
            $property = $current.PSObject.Properties[$segment]
            if (-not $property) { return $null }
            $current = $property.Value
        }
    }
    # Named -InputObject: bound positionally, Write-Output collects the value into a List (ValueFromRemainingArguments)
    Write-Output -InputObject $current -NoEnumerate
}
