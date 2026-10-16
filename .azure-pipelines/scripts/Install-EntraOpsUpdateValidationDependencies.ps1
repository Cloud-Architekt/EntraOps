#Requires -Version 7.4
<#
.SYNOPSIS
    Installs the PowerShell dependencies for isolated EntraOps update validation.
#>
[CmdletBinding()]
param ()

$ErrorActionPreference = 'Stop'
# Same versions as the GitHub Update-EntraOps workflow and entraops-test.yml; this job is the trust boundary of the update.
Install-Module Pester -MinimumVersion 5.7.1 -Scope CurrentUser -Force -Repository PSGallery
Install-Module powershell-yaml -RequiredVersion 0.4.12 -Scope CurrentUser -Force -Repository PSGallery
