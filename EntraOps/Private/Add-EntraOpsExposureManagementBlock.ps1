function Add-EntraOpsExposureManagementBlock {
    <#
    .SYNOPSIS
        Adds the Exposure Management query outcome and its results to a scope reasoning payload.
    .DESCRIPTION
        Read by Get-EntraOpsExposureManagementBaseline. Empty results are recorded as well, so a successful
        query without results stays a valid baseline.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [psobject]$Payload,
        [Parameter(Mandatory = $true)]
        [System.Collections.IDictionary]$Metadata,
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object[]]$Results
    )

    $ExposureManagementBlock = [ordered]@{}
    foreach ($MetadataEntry in $Metadata.GetEnumerator()) {
        $ExposureManagementBlock[$MetadataEntry.Key] = $MetadataEntry.Value
    }
    $ExposureManagementBlock['Results'] = @($Results | Where-Object { $null -ne $_ })
    $Payload | Add-Member -NotePropertyName ExposureManagement -NotePropertyValue ([PSCustomObject]$ExposureManagementBlock) -Force
}
