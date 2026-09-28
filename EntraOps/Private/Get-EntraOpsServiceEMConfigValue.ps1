<#
.SYNOPSIS
    Returns a value from the ServiceEM section of the loaded EntraOps configuration.

.DESCRIPTION
    Reads a dot-separated path below $Global:EntraOpsConfig.ServiceEM (e.g. "CreateM365Group" or
    "PIMForGroups.MaximumActivationDuration"). Works with configurations loaded as hashtable
    (Connect-EntraOps) or as PSCustomObject and returns $null if the configuration, the ServiceEM
    section or any part of the path is missing.

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
        if ($current -is [System.Collections.IDictionary]) {
            $current = if ($current.Contains($segment)) { $current[$segment] } else { $null }
        } else {
            $property = $current.PSObject.Properties[$segment]
            $current = if ($property) { $property.Value } else { $null }
        }
    }
    Write-Output -NoEnumerate $current
}
