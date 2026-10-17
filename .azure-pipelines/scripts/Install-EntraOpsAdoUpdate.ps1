#Requires -Version 7.4
<#
.SYNOPSIS
    Applies the prepared EntraOps update using the isolated job's validation result.
#>
[CmdletBinding()]
param (
    [string]$ConfigFile = './EntraOpsConfig.json',

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-fA-F]{40}$')]
    [string]$SourceCommit,

    [Parameter(Mandatory = $true)]
    [bool]$ValidationRequired,

    [bool]$BrowserTestsValidated = $false
)

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot '../../EntraOps/EntraOps.psd1') -Force
Install-EntraOpsUpdateCandidate -ConfigFile $ConfigFile -SourceCommit $SourceCommit `
    -ValidationRequired:$ValidationRequired -BrowserTestsValidated:$BrowserTestsValidated
