<#
.SYNOPSIS
    Update classification files from AzurePrivilegedIAM repository to get latest definition of levels in Enterprise Access Model.

.DESCRIPTION
    Check all files in the EntraOps_Classification folder in the AzurePrivilegedIAM repository and download them to the folder specified in the $DefaultFolderClassification variable.

.PARAMETER FolderClassification
    Folder where the classification files should be stored. Default is "$DefaultFolderClassification/Templates".

.PARAMETER Classifications
    Array of classification names which should be updated. Default is ("AadResources", "AppRoles") which are available from the public repository.

.EXAMPLE
    Update all classification files in default location (./EntraOps_Classification/Templates) with classifications from the public repository AzurePrivilegedIAM
    Update-EntraOpsClassificationFiles
#>
function Update-EntraOpsClassificationFiles {

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [System.String]$FolderClassification = "$DefaultFolderClassification/Templates",

        [Parameter(Mandatory = $false)]
        [Object]$Classifications = ("AadResources", "AadResources.Param", "AppRoles")
    )

    $ClassificationTemplates = Invoke-RestMethod -Method GET -Uri "https://api.github.com/repos/Cloud-Architekt/AzurePrivilegedIAM/contents/EntraOps_Classification"

    foreach ($ClassificationTemplate in $ClassificationTemplates) {
        # Parsing classification name by removing the prefix and suffix from file name
        $ClassificationName = $ClassificationTemplate.Name.Replace("Classification_", "").Replace(".json", "")
        if ($ClassificationName -in $Classifications) {
            Invoke-RestMethod -Method GET -Uri $ClassificationTemplate.download_url -OutFile "$($FolderClassification)/$($ClassificationTemplate.name)"
        }
    }
}
