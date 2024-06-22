<#
.SYNOPSIS
    Update of EntraOps PowerShell module and GitHub workflow files.

.DESCRIPTION
    Cmdlet is used to update the EntraOps PowerShell module and GitHub workflow files.

.EXAMPLE
    This example updates EntraOps with default values of the main branch and the default target folders.
    Update-EntraOps
#>

function Update-EntraOps {
    [cmdletbinding()]
    param (
        [Parameter(Mandatory = $False)]
        [System.String]$Branch = "main"
        ,
        [Parameter(Mandatory = $False)]
        [System.String]$PersonalAccessToken
        ,
        [Parameter(Mandatory = $False)]
        [System.String]$ConfigFile = "./EntraOpsConfig.json"
        ,
        [Parameter(Mandatory = $False)]
        [ValidateSet("./.github", "./EntraOps", "./Parsers", "./Queries", "./Samples", "./Workbooks")]
        [Object]$TargetUpdateFolders = @("./.github", "./EntraOps", "./Parsers", "./Queries", "./Samples" "./Workbooks")
        ,
        [Parameter(Mandatory = $False)]
        [System.String]$TemporaryUpdateFolder = "../latest-version"
    )

    $ErrorActionPreference = "Stop"

    if ($null -ne $PersonalAccessToken) {
        git clone -b $Branch https://$($PersonalAccessToken):@github.com/Cloud-Architekt/EntraOps.git $TemporaryUpdateFolder
    }
    else {
        git clone -b $Branch https://github.com/Cloud-Architekt/EntraOps.git $TemporaryUpdateFolder
    }

    foreach ($TargetUpdateFolder in $TargetUpdateFolders) {

        if (Test-Path -Path $TargetUpdateFolder) {
            Write-Output "Removing folder $TargetUpdateFolder..."
            try {
                Remove-Item -Path $TargetUpdateFolder -Force -Recurse
            }
            catch {
                Write-Error "Failed to remove folder $($TargetUpdateFolder). Error: $_"
            }
        }
        else {
            Write-Output "Creating folder $TargetUpdateFolder..."
            try {
                New-Item -Path $TargetUpdateFolder -ItemType Directory
            }
            catch {
                Write-Error "Failed to create folder $($TargetUpdateFolder). Error: $_"
            }
        }

        Write-Output "Updating folder $TargetUpdateFolder..."
        try {
            Copy-item -Path "$($TemporaryUpdateFolder)/$($TargetUpdateFolder)" -Destination "$($TargetUpdateFolder)" -Force -Recurse
        }
        catch {
            Write-Error "Failed to copy folder $($TemporaryUpdateFolder)/$($TargetUpdateFolder) to $($TargetUpdateFolder). Error: $_"
        }
    }

    Write-Output "Importing updated EntraOps module..."
    try {
        Import-Module ./EntraOps -Force
    }
    catch {
        Write-Error "Failed to import updated EntraOps module. Error: $_"
    }

    if ($TargetUpdateFolders -contains "./.github") {
        Write-Host "Re-adding workflow parameters in GitHub workflows after update..."
        try {
            Update-EntraOpsRequiredWorkflowParameters -ConfigFile $ConfigFile
        }
        catch {
            Write-Error "Failed to update required workflow parameters. Error: $_"
        }
    }

    Write-Output "Cleaning up temporary folder $TemporaryUpdateFolder."
    Remove-Item -Path $TemporaryUpdateFolder -Force -Recurse
}