#Requires -Version 7.4
<#
.SYNOPSIS
    Freezes the trusted publisher and downloads the resolved update commit without executing it.
#>
[CmdletBinding()]
param (
    [string]$ConfigFile = './EntraOpsConfig.json',

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-fA-F]{40}$')]
    [string]$SourceCommit,

    [Parameter(Mandatory = $true)]
    [string]$PublisherPath
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'Ado-GitAuth.ps1')

# The candidate can replace .azure-pipelines; freeze the publisher before applying it so the
# later publication step never runs candidate code with the job access token.
New-Item -ItemType Directory -Path $PublisherPath -Force | Out-Null
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'Publish-EntraOpsAdoUpdate.ps1'), (Join-Path $PSScriptRoot 'Ado-GitAuth.ps1') -Destination $PublisherPath -Force

if ([string]::IsNullOrWhiteSpace((Get-EntraOpsAdoSecretValue -Value $env:ENTRAOPS_PAT))) {
    Remove-Item -LiteralPath Env:ENTRAOPS_PAT -ErrorAction SilentlyContinue
}
Import-Module (Join-Path $PSScriptRoot '../../EntraOps/EntraOps.psd1') -Force
Get-EntraOpsUpdateCandidate -ConfigFile $ConfigFile -DestinationPath ./TmpUpdate -ExpectedSourceCommit $SourceCommit | Out-Host
