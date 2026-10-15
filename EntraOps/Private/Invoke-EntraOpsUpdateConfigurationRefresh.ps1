function Invoke-EntraOpsUpdateConfigurationRefresh {
    <#
    .SYNOPSIS
        Reapplies configuration using the candidate's template helpers in a clean process.

    .DESCRIPTION
        The updater's loaded helpers may target an older template layout. Load only the required
        helper files from the candidate in a separate process, without inheriting credential variables
        or replacing functions in the caller's session.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$SourceRoot,

        [Parameter(Mandatory = $true)]
        [string]$RepositoryRoot,

        [Parameter(Mandatory = $true)]
        [string]$ConfigFile,

        [switch]$UpdateGitHubWorkflows,

        [switch]$UpdateAzureDevOpsPipelines
    )

    $Settings = @{
        SourceRoot = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($SourceRoot)
        RepositoryRoot = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($RepositoryRoot)
        ConfigFile = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($ConfigFile)
        UpdateGitHubWorkflows = [bool]$UpdateGitHubWorkflows
        UpdateAzureDevOpsPipelines = [bool]$UpdateAzureDevOpsPipelines
    }
    # Encode the data separately so paths and configuration names cannot become executable text.
    $EncodedSettings = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes(($Settings | ConvertTo-Json -Compress)))
    $RefreshScript = @'
$ErrorActionPreference = 'Stop'
$Settings = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('__SETTINGS__')) | ConvertFrom-Json
Set-Location -LiteralPath $Settings.RepositoryRoot
if ($Settings.UpdateGitHubWorkflows) {
    . (Join-Path $Settings.SourceRoot 'EntraOps/Public/Configuration/Update-EntraOpsRequiredWorkflowParameters.ps1')
    Update-EntraOpsRequiredWorkflowParameters -ConfigFile $Settings.ConfigFile
}
if ($Settings.UpdateAzureDevOpsPipelines) {
    . (Join-Path $Settings.SourceRoot 'EntraOps/Public/Configuration/Update-EntraOpsAzureDevOpsSchedules.ps1')
    Update-EntraOpsAzureDevOpsSchedules -ConfigFile $Settings.ConfigFile -PipelineFolder './.azure-pipelines'
}
'@
    $EncodedCommand = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($RefreshScript.Replace('__SETTINGS__', $EncodedSettings)))
    # Match the credential-variable isolation used by candidate validation. The helper is downloaded
    # code and must not inherit a PAT, job token, or other credentials from the updater environment.
    $AllowedEnvironmentNames = @(
        'PATH', 'PSModulePath', 'LANG', 'LC_ALL', 'TMPDIR', 'TEMP', 'TMP', 'CI',
        'HOME', 'USER', 'USERNAME', 'USERPROFILE', 'HOMEDRIVE', 'HOMEPATH', 'APPDATA', 'LOCALAPPDATA',
        'ProgramData', 'ProgramFiles', 'ProgramFiles(x86)', 'SystemRoot', 'SystemDrive', 'windir',
        'COMSPEC', 'PATHEXT', 'DOTNET_CLI_TELEMETRY_OPTOUT', 'POWERSHELL_TELEMETRY_OPTOUT'
    )
    $SavedEnvironment = @{}
    foreach ($Entry in Get-ChildItem Env:) { $SavedEnvironment[$Entry.Name] = $Entry.Value }
    try {
        foreach ($Entry in Get-ChildItem Env:) { Remove-Item -LiteralPath "Env:$($Entry.Name)" -ErrorAction SilentlyContinue }
        foreach ($Name in $AllowedEnvironmentNames) {
            if ($SavedEnvironment.ContainsKey($Name)) { Set-Item -LiteralPath "Env:$Name" -Value $SavedEnvironment[$Name] }
        }
        & (Get-Process -Id $PID).Path -NoLogo -NoProfile -NonInteractive -EncodedCommand $EncodedCommand
        if ($LASTEXITCODE -ne 0) {
            throw "Configuration refresh child process failed with exit code $LASTEXITCODE. The update files were copied, but configuration refresh is incomplete."
        }
    } finally {
        foreach ($Entry in Get-ChildItem Env:) { Remove-Item -LiteralPath "Env:$($Entry.Name)" -ErrorAction SilentlyContinue }
        foreach ($Name in $SavedEnvironment.Keys) { Set-Item -LiteralPath "Env:$Name" -Value $SavedEnvironment[$Name] }
    }
}
