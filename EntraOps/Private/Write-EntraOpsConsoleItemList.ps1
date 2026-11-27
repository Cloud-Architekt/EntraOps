<#
.SYNOPSIS
    Write an informational list to the console: the items with object details enabled, otherwise only their count.

.DESCRIPTION
    Pipeline logs keep every console line. Informational lists of object IDs and scopes are persisted in the
    classification and reasoning files anyway, so without ConsoleOutput.IncludeObjectDetails only their count is
    written. A list that contains the directory scope '/' says so, because a directory-wide scope changes the
    meaning of the classification.

.PARAMETER Label
    Text in front of the list or count, e.g. "Scope entries added".

.PARAMETER Items
    Items of the list.

.PARAMETER IncludeObjectDetails
    Write each item instead of the count. Defaults to ConsoleOutput.IncludeObjectDetails from EntraOpsConfig.json.

.PARAMETER Indent
    Indentation of the label line. Items are indented by two more spaces.

.PARAMETER ItemColor
    Console color of the items.
#>
function Write-EntraOpsConsoleItemList {

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Label
        ,
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [AllowEmptyCollection()]
        [object[]]$Items
        ,
        [Parameter(Mandatory = $false)]
        [boolean]$IncludeObjectDetails = [bool]$Global:EntraOpsIncludeObjectDetails
        ,
        [Parameter(Mandatory = $false)]
        [string]$Indent = '  '
        ,
        [Parameter(Mandatory = $false)]
        [string]$ItemColor = 'DarkGreen'
    )

    $ListItems = @($Items | Where-Object { -not [string]::IsNullOrWhiteSpace("$_") })
    if ($IncludeObjectDetails) {
        Write-Host "$($Indent)$($Label):" -ForegroundColor Gray
        foreach ($Item in $ListItems) {
            Write-Host "$($Indent)  $Item" -ForegroundColor $ItemColor
        }
    } else {
        $DirectoryNote = if ($ListItems -contains '/') { ' (including the directory scope /)' } else { '' }
        Write-Host "$($Indent)$($Label): $($ListItems.Count)$DirectoryNote" -ForegroundColor Gray
    }
}
