#Requires -Version 7.4
<#
.SYNOPSIS
    Installs the PowerShell dependencies for isolated EntraOps update validation.
#>
[CmdletBinding()]
param ()

$ErrorActionPreference = 'Stop'
Install-Module Pester -Scope CurrentUser -Force -Repository PSGallery
Install-Module powershell-yaml -Scope CurrentUser -Force -Repository PSGallery
