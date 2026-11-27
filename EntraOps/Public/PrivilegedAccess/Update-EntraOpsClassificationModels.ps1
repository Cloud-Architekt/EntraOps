#Requires -Version 7.0
function Update-EntraOpsClassificationModels {

    <#
    .SYNOPSIS
        Update all EntraOps classification models and the Classification Explorer in one orchestrated run.

    .DESCRIPTION
        Runs every classification export in dependency order while parallelizing the independent work:

          * Lane "ApiPermissions" (sequential):
                Export-EntraOpsClassificationAppRoles -> Export-EntraOpsClassificationScopes -> Export-EntraOpsClassificationApiPermissions
          * Lane "EntraIdRoles" (sequential):
                Export-EntraOpsClassificationDirectoryRoles -> Export-EntraOpsClassificationDirectoryRolesFromMsftDocs -> Get-EntraOpsClassificationDirectoryRolesMismatchFromMsftDocs
          * Lane "IdentityGovernance":   Export-EntraOpsClassificationIdentityGovernanceRoles
          * Lane "DeviceManagement":     Export-EntraOpsClassificationDeviceManagementRoles
          * Lane "AzureRoles":           Export-EntraOpsClassificationAzureRoles

        All five lanes run in parallel (Start-ThreadJob); the two multi-step lanes keep their internal order.
        After every lane has finished, Update-EntraOpsClassificationExplorerData (-Mode Standalone) regenerates the Classification Explorer
        bundle (embedded classification data, attack paths, EAM Map dataset and the git-log-based change history for
        the History view; the history part is best effort - it needs 'git' and a non-shallow clone - and never fails
        the overall run).

        A live progress bar and streamed per-lane output are shown during processing. At the end a clean summary is
        printed (and returned) that lists every unclassified action/permission per source and the Microsoft Docs
        mismatch, formatted so the lists can be copied straight into a classification JSON file or into an AI prompt.

    .PARAMETER RepoRoot
        Repository root containing the 'Classification', 'EntraOps_Classification' and 'ClassificationExplorer'
        folders. Defaults to the root inferred from the imported module, or the unique sibling
        AzurePrivilegedIAM checkout when invoked from EntraOps. This command maintains source
        classification data; use New-EntraOpsClassificationExplorerData to refresh the EntraOps report.

    .PARAMETER IncludeCustomRoles
        Include custom role definitions for the role-based exports (Directory, Identity Governance, Device Management, Azure).

    .PARAMETER Tier0IncludedResourceScope
        Azure scopes treated as Control Plane (Tier 0). Passed to Export-EntraOpsClassificationAzureRoles.

    .PARAMETER Tier1IncludedResourceScope
        Azure scopes treated as Management Plane (Tier 1). Passed to Export-EntraOpsClassificationAzureRoles.

    .PARAMETER AzureClassificationFile
        Classification definition file used for Azure roles. Default "./EntraOps_Classification/Classification_Azure.json".

    .PARAMETER AzureRoleDefinitionScope
        Optional scope passed to Get-AzRoleDefinition (e.g. "/" for tenant-scoped built-in roles).

    .PARAMETER ResolveApiPermissionDisplayNames
        Resolve service principal display names from Microsoft Graph in the API permissions export.

    .PARAMETER SkipClassificationExplorerUpdate
        Do not run Update-EntraOpsClassificationExplorerData at the end.

    .PARAMETER SkipEntraOpsRepoSync
        Do not prompt to sync classification templates and the Classification Explorer app source into the EntraOps repository
        (Sync-EntraOpsClassificationExplorerSource) at the end of the run.

    .PARAMETER SkipHistoryUpdate
        Do not refresh the Classification Explorer's git-log-based change history (data/history-data.js,
        used by the History view) as part of the Update-EntraOpsClassificationExplorerData run. Has no effect when
        -SkipClassificationExplorerUpdate is set. Useful to skip the (slower) git-log walk when iterating quickly.

    .PARAMETER Sequential
        Run the lanes one after another instead of in parallel (useful for troubleshooting).

    .EXAMPLE
        Update-EntraOpsClassificationModels

    .EXAMPLE
        Update-EntraOpsClassificationModels -IncludeCustomRoles $true -Tier0IncludedResourceScope "/providers/Microsoft.Management/managementGroups/Tier0"
    #>

    [cmdletbinding()]
    param
    (
        [Parameter(Mandatory = $false)]
        [string]$RepoRoot
        ,
        [Parameter(Mandatory = $false)]
        $IncludeCustomRoles = $False
        ,
        [Parameter(Mandatory = $false)]
        [string[]]$Tier0IncludedResourceScope = @()
        ,
        [Parameter(Mandatory = $false)]
        [string[]]$Tier1IncludedResourceScope = @()
        ,
        [Parameter(Mandatory = $false)]
        [string]$AzureClassificationFile = "./EntraOps_Classification/Classification_Azure.json"
        ,
        [Parameter(Mandatory = $false)]
        $AzureRoleDefinitionScope = $null
        ,
        [Parameter(Mandatory = $false)]
        [switch]$ResolveApiPermissionDisplayNames
        ,
        [Parameter(Mandatory = $false)]
        [switch]$SkipClassificationExplorerUpdate
        ,
        [Parameter(Mandatory = $false)]
        [switch]$SkipEntraOpsRepoSync
        ,
        [Parameter(Mandatory = $false)]
        [switch]$SkipHistoryUpdate
        ,
        [Parameter(Mandatory = $false)]
        [switch]$Sequential
    )

    #region Resolve paths
    $module = $MyInvocation.MyCommand.Module
    if (-not $module -or -not $module.ModuleBase -or -not $module.Path) {
        throw 'Update-EntraOpsClassificationModels must be invoked from an imported module.'
    }
    if ([string]::IsNullOrEmpty($RepoRoot)) {
        $RepoRoot = Resolve-EntraOpsClassificationRepoRoot -ModuleBase $module.ModuleBase
    }
    $RepoRoot = (Resolve-Path -LiteralPath $RepoRoot).Path
    $ClassificationPath = Join-Path $RepoRoot "Classification"
    $ModulePath = $module.Path

    foreach ($requiredFolder in 'Classification', 'EntraOps_Classification', 'ClassificationExplorer') {
        if (-not (Test-Path -LiteralPath (Join-Path $RepoRoot $requiredFolder) -PathType Container)) {
            throw "Classification source folder '$requiredFolder' not found under '$RepoRoot'. Pass -RepoRoot pointing at AzurePrivilegedIAM."
        }
    }
    $OriginalLocation = Get-Location

    if (-not (Test-Path $ModulePath)) { throw "Loaded module path not found at '$ModulePath'." }
    #endregion

    # Keep the EntraOps connection hints when sharing the standalone maintenance implementation.
    if (-not (Get-Command Get-MgContext -ErrorAction SilentlyContinue) -or $null -eq (Get-MgContext -ErrorAction SilentlyContinue)) {
        Write-Warning 'No Microsoft Graph context detected. Run Connect-MgGraph before this command for the Graph based exports.'
    }
    if (-not (Get-Command Get-AzContext -ErrorAction SilentlyContinue) -or $null -eq (Get-AzContext -ErrorAction SilentlyContinue)) {
        Write-Warning 'No Azure context detected. Run Connect-AzAccount before this command for the Azure roles export.'
    }

    $MismatchTempFile = Join-Path ([System.IO.Path]::GetTempPath()) ("EntraOpsDirectoryRolesMismatch_{0}.json" -f ([guid]::NewGuid()))

    $Options = @{
        IncludeCustomRoles               = [bool]$IncludeCustomRoles
        Tier0IncludedResourceScope       = $Tier0IncludedResourceScope
        Tier1IncludedResourceScope       = $Tier1IncludedResourceScope
        AzureClassificationFile          = $AzureClassificationFile
        AzureRoleDefinitionScope         = $AzureRoleDefinitionScope
        ResolveApiPermissionDisplayNames = [bool]$ResolveApiPermissionDisplayNames
        MismatchTempFile                 = $MismatchTempFile
    }
    $Jobs = @()

    try {
        #region Lane definitions
        $LaneApiPermissions = {
            param($RepoRoot, $ModulePath, $Options)
            $ErrorActionPreference = 'Stop'
            Set-Location -LiteralPath $RepoRoot
            Import-Module $ModulePath -ErrorAction Stop

            try { Write-Output "Step 1/3 Export-EntraOpsClassificationAppRoles"; Export-EntraOpsClassificationAppRoles } catch { throw "AppRoles failed: $($_.Exception.Message)" }
            try { Write-Output "Step 2/3 Export-EntraOpsClassificationScopes"; Export-EntraOpsClassificationScopes } catch { throw "Scopes failed: $($_.Exception.Message)" }
            try {
                Write-Output "Step 3/3 Export-EntraOpsClassificationApiPermissions"
                if ($Options.ResolveApiPermissionDisplayNames) { Export-EntraOpsClassificationApiPermissions -ResolveDisplayNames }
                else { Export-EntraOpsClassificationApiPermissions }
            } catch { throw "ApiPermissions failed: $($_.Exception.Message)" }
            Write-Output "Lane complete"
        }

        $LaneEntraIdRoles = {
            param($RepoRoot, $ModulePath, $Options)
            $ErrorActionPreference = 'Stop'
            Set-Location -LiteralPath $RepoRoot
            Import-Module $ModulePath -ErrorAction Stop

            try { Write-Output "Step 1/3 Export-EntraOpsClassificationDirectoryRoles"; Export-EntraOpsClassificationDirectoryRoles -IncludeCustomRoles $Options.IncludeCustomRoles } catch { throw "DirectoryRoles failed: $($_.Exception.Message)" }
            try { Write-Output "Step 2/3 Export-EntraOpsClassificationDirectoryRolesFromMsftDocs"; Export-EntraOpsClassificationDirectoryRolesFromMsftDocs } catch { throw "DirectoryRolesFromMsftDocs failed: $($_.Exception.Message)" }
            try {
                Write-Output "Step 3/3 Get-EntraOpsClassificationDirectoryRolesMismatchFromMsftDocs"
                $mm = Get-EntraOpsClassificationDirectoryRolesMismatchFromMsftDocs -ShowSummaryOnly $true
                $mm | ConvertTo-Json -Depth 8 | Out-File -FilePath $Options.MismatchTempFile -Force
            } catch { throw "Mismatch comparison failed: $($_.Exception.Message)" }
            Write-Output "Lane complete"
        }

        $LaneIdentityGovernance = {
            param($RepoRoot, $ModulePath, $Options)
            $ErrorActionPreference = 'Stop'
            Set-Location -LiteralPath $RepoRoot
            Import-Module $ModulePath -ErrorAction Stop
            try { Write-Output "Export-EntraOpsClassificationIdentityGovernanceRoles"; Export-EntraOpsClassificationIdentityGovernanceRoles -IncludeCustomRoles $Options.IncludeCustomRoles } catch { throw "IdentityGovernanceRoles failed: $($_.Exception.Message)" }
            Write-Output "Lane complete"
        }

        $LaneDeviceManagement = {
            param($RepoRoot, $ModulePath, $Options)
            $ErrorActionPreference = 'Stop'
            Set-Location -LiteralPath $RepoRoot
            Import-Module $ModulePath -ErrorAction Stop
            try { Write-Output "Export-EntraOpsClassificationDeviceManagementRoles"; Export-EntraOpsClassificationDeviceManagementRoles -IncludeCustomRoles $Options.IncludeCustomRoles } catch { throw "DeviceManagementRoles failed: $($_.Exception.Message)" }
            Write-Output "Lane complete"
        }

        $LaneAzureRoles = {
            param($RepoRoot, $ModulePath, $Options)
            $ErrorActionPreference = 'Stop'
            Set-Location -LiteralPath $RepoRoot
            Import-Module $ModulePath -ErrorAction Stop
            $azParams = @{ IncludeCustomRoles = $Options.IncludeCustomRoles }
            if ($Options.Tier0IncludedResourceScope.Count -gt 0) { $azParams.Tier0IncludedResourceScope = $Options.Tier0IncludedResourceScope }
            if ($Options.Tier1IncludedResourceScope.Count -gt 0) { $azParams.Tier1IncludedResourceScope = $Options.Tier1IncludedResourceScope }
            if ($Options.AzureClassificationFile) { $azParams.ClassificationFile = $Options.AzureClassificationFile }
            if ($Options.AzureRoleDefinitionScope) { $azParams.RoleDefinitionScope = $Options.AzureRoleDefinitionScope }
            try { Write-Output "Export-EntraOpsClassificationAzureRoles"; Export-EntraOpsClassificationAzureRoles @azParams } catch { throw "AzureRoles failed: $($_.Exception.Message)" }
            Write-Output "Lane complete"
        }

        $Lanes = @(
            [PSCustomObject]@{ Name = "ApiPermissions"; Script = $LaneApiPermissions }
            [PSCustomObject]@{ Name = "EntraIdRoles"; Script = $LaneEntraIdRoles }
            [PSCustomObject]@{ Name = "IdentityGovernance"; Script = $LaneIdentityGovernance }
            [PSCustomObject]@{ Name = "DeviceManagement"; Script = $LaneDeviceManagement }
            [PSCustomObject]@{ Name = "AzureRoles"; Script = $LaneAzureRoles }
        )
        #endregion

        $StartTime = Get-Date
        Write-Host ""
        Write-Host "=== Updating EntraOps classification models ===" -ForegroundColor Cyan
        Write-Host ("Repository root : {0}" -f $RepoRoot) -ForegroundColor DarkCyan
        Write-Host ("Execution mode  : {0}" -f $(if ($Sequential) { "Sequential" } else { "Parallel (Start-ThreadJob)" })) -ForegroundColor DarkCyan
        Write-Host ("Include custom  : {0}" -f $Options.IncludeCustomRoles) -ForegroundColor DarkCyan
        Write-Host ""

        #region Run lanes
        $UseParallel = (-not $Sequential) -and (Get-Command Start-ThreadJob -ErrorAction SilentlyContinue)
        if ((-not $Sequential) -and (-not $UseParallel)) {
            Write-Warning "Start-ThreadJob not available, falling back to sequential execution."
        }

        if ($UseParallel) {
            $Jobs = foreach ($Lane in $Lanes) {
                Start-ThreadJob -Name $Lane.Name -ScriptBlock $Lane.Script -ArgumentList $RepoRoot, $ModulePath, $Options
            }

            $TotalLanes = $Jobs.Count
            do {
                Start-Sleep -Milliseconds 750
                foreach ($Job in $Jobs) {
                    # Report lane failures together below, including when the caller uses Stop.
                    $NewOutput = Receive-Job -Job $Job -ErrorAction SilentlyContinue
                    foreach ($Line in $NewOutput) {
                        Write-Host ("[{0,-18}] {1}" -f $Job.Name, $Line) -ForegroundColor DarkGray
                    }
                }
                $Completed = @($Jobs | Where-Object { $_.State -in 'Completed', 'Failed', 'Stopped' }).Count
                $Running = (@($Jobs | Where-Object { $_.State -eq 'Running' }) | ForEach-Object { $_.Name }) -join ", "
                Write-Progress -Activity "Updating EntraOps classification models" -Status "$Completed of $TotalLanes lanes complete | running: $Running" -PercentComplete (($Completed / $TotalLanes) * 100)
            } while (@($Jobs | Where-Object { $_.State -notin 'Completed', 'Failed', 'Stopped' }).Count -gt 0)

            # Drain remaining output and retain failures before removing the jobs.
            $LaneFailures = [System.Collections.Generic.List[string]]::new()
            foreach ($Job in $Jobs) {
                $NewOutput = Receive-Job -Job $Job -ErrorAction SilentlyContinue
                foreach ($Line in $NewOutput) {
                    Write-Host ("[{0,-18}] {1}" -f $Job.Name, $Line) -ForegroundColor DarkGray
                }
                if ($Job.State -in 'Failed', 'Stopped') {
                    # Start-ThreadJob exposes the failure on the job itself; it has no child jobs.
                    $Reason = $Job.JobStateInfo.Reason
                    $Message = if ($Reason) { $Reason.Message } else { "Job ended in state '$($Job.State)'" }
                    $LaneFailures.Add(("{0}: {1}" -f $Job.Name, $Message))
                }
            }
            $Jobs | Remove-Job -Force
            $Jobs = @()
            Write-Progress -Activity "Updating EntraOps classification models" -Completed
            if ($LaneFailures.Count -gt 0) {
                throw ("Classification update failed in {0} lane(s): {1}" -f $LaneFailures.Count, ($LaneFailures -join '; '))
            }
        } else {
            $TotalLanes = $Lanes.Count
            $Index = 0
            foreach ($Lane in $Lanes) {
                $Index++
                Write-Progress -Activity "Updating EntraOps classification models (sequential)" -Status "Lane $Index of $TotalLanes : $($Lane.Name)" -PercentComplete ((($Index - 1) / $TotalLanes) * 100)
                Write-Host ("--- Lane: {0} ---" -f $Lane.Name) -ForegroundColor Cyan
                & $Lane.Script $RepoRoot $ModulePath $Options | ForEach-Object { Write-Host ("[{0,-18}] {1}" -f $Lane.Name, $_) -ForegroundColor DarkGray }
            }
            Write-Progress -Activity "Updating EntraOps classification models (sequential)" -Completed
        }
        #endregion

        #region Update Classification Explorer
        if (-not $SkipClassificationExplorerUpdate) {
            if (Get-Command Update-EntraOpsClassificationExplorerData -ErrorAction SilentlyContinue) {
                Write-Host ""
                Write-Host "=== Updating Classification Explorer (Update-EntraOpsClassificationExplorerData -Mode Standalone) ===" -ForegroundColor Cyan
                Write-Progress -Activity "Updating EntraOps classification models" -Status "Refreshing Classification Explorer bundle" -PercentComplete 95
                try {
                    $explorerParams = @{ RepoRoot = $RepoRoot; Mode = 'Standalone' }
                    if ($SkipHistoryUpdate) { $explorerParams.SkipHistory = $true }
                    Update-EntraOpsClassificationExplorerData @explorerParams
                } catch { throw "Update-EntraOpsClassificationExplorerData failed: $($_.Exception.Message)" }
                Write-Progress -Activity "Updating EntraOps classification models" -Completed
            } else {
                throw 'Update-EntraOpsClassificationExplorerData is not exported by the loaded module.'
            }
        }
        #endregion

        #region Sync classification templates and Classification Explorer source to EntraOps repository
        if (-not $SkipEntraOpsRepoSync) {
            if (Get-Command Sync-EntraOpsClassificationExplorerSource -ErrorAction SilentlyContinue) {
                Write-Host ""
                Write-Host "=== Sync classification templates and Classification Explorer source to EntraOps repository ===" -ForegroundColor Cyan
                $EntraOpsRootAnswer = Read-Host 'Update classification templates and Classification Explorer in the EntraOps repository as well? Press Enter to auto-detect, type a custom path, or n to skip'
                if ($EntraOpsRootAnswer -notin @('n', 'N', 'no', 'No')) {
                    try {
                        $syncParameters = @{ RepoRoot = $RepoRoot }
                        if (-not [string]::IsNullOrWhiteSpace($EntraOpsRootAnswer)) {
                            $syncParameters.EntraOpsRoot = $EntraOpsRootAnswer
                        }
                        Sync-EntraOpsClassificationExplorerSource @syncParameters
                    } catch { throw "Sync-EntraOpsClassificationExplorerSource failed: $($_.Exception.Message)" }
                } else {
                    Write-Host "Skipped syncing classification templates and Classification Explorer source to EntraOps repository." -ForegroundColor DarkGray
                }
            } else {
                Write-Verbose 'Classification Explorer source sync is not available in the loaded module.'
            }
        }
        #endregion

        #region Build summary
        function Get-EntraOpsUnclassifiedFromFile {
            param([string]$Path)
            $items = New-Object System.Collections.Generic.List[string]
            if (-not (Test-Path $Path)) { return $items }
            try { $data = Get-Content -Path $Path -Raw | ConvertFrom-Json -Depth 20 } catch { return $items }
            # ConvertFrom-Json collapses a JSON '[]' to $null and a single-element JSON array to a
            # bare object rather than a one-item array - normalize both back to a real array so the
            # foreach below always sees the same shape regardless of how many entries the file has.
            $data = @(if ($null -ne $data) { $data })
            foreach ($item in $data) {
                $props = $item.PSObject.Properties.Name
                if ($props -contains 'RolePermissions') {
                    foreach ($perm in $item.RolePermissions) {
                        $permProps = $perm.PSObject.Properties.Name
                        if (($permProps -contains 'EAMTierLevelName') -and $perm.EAMTierLevelName -eq 'Unclassified' -and ($permProps -contains 'AuthorizedResourceAction') -and $perm.AuthorizedResourceAction) {
                            $items.Add([string]$perm.AuthorizedResourceAction) | Out-Null
                        }
                    }
                } elseif (($props -contains 'EAMTierLevelName') -and $item.EAMTierLevelName -eq 'Unclassified') {
                    $id = $null
                    foreach ($candidate in 'AuthorizedResourceAction', 'PermissionValue', 'AppRoleDisplayName', 'ScopeDisplayName') {
                        if (($props -contains $candidate) -and $item.$candidate) { $id = [string]$item.$candidate; break }
                    }
                    if ($id) { $items.Add($id) | Out-Null }
                }
            }
            return ($items | Sort-Object -Unique)
        }

        $SummarySources = [ordered]@{
            "Classification_AppRoles.json"                          = (Join-Path $ClassificationPath "Classification_AppRoles.json")
            "Classification_Scopes.json"                            = (Join-Path $ClassificationPath "Classification_Scopes.json")
            "Classification_ApiPermissions.json"                    = (Join-Path $ClassificationPath "Classification_ApiPermissions.json")
            "Classification_EntraIdDirectoryRoles.json"             = (Join-Path $ClassificationPath "Classification_EntraIdDirectoryRoles.json")
            "Classification_EntraIdDirectoryRolesFromMsftDocs.json" = (Join-Path $ClassificationPath "Classification_EntraIdDirectoryRolesFromMsftDocs.json")
            "Classification_IdentityGovernance.json"                = (Join-Path $ClassificationPath "Classification_IdentityGovernance.json")
            "Classification_DeviceManagementRoles.json"             = (Join-Path $ClassificationPath "Classification_DeviceManagementRoles.json")
            "Classification_AzureResources.json"                    = (Join-Path $ClassificationPath "Classification_AzureResources.json")
        }

        $UnclassifiedBySource = [ordered]@{}
        foreach ($Source in $SummarySources.Keys) {
            $UnclassifiedBySource[$Source] = @(Get-EntraOpsUnclassifiedFromFile -Path $SummarySources[$Source])
        }

        # Microsoft Docs mismatch
        $Mismatch = $null
        if (Test-Path $MismatchTempFile) {
            try { $Mismatch = Get-Content -Path $MismatchTempFile -Raw | ConvertFrom-Json -Depth 10 } catch { $Mismatch = $null }
            Remove-Item -Path $MismatchTempFile -Force -ErrorAction SilentlyContinue
        }

        $OnlyInDocs = @()
        $OnlyInGraph = @()
        $DocsUnclassified = @()
        if ($Mismatch) {
            $OnlyInDocs = @($Mismatch.ActionDifferences | Where-Object { $_.Difference -eq 'OnlyInDocs' } | Select-Object -ExpandProperty Action -Unique | Sort-Object)
            $OnlyInGraph = @($Mismatch.ActionDifferences | Where-Object { $_.Difference -eq 'OnlyInGraph' } | Select-Object -ExpandProperty Action -Unique | Sort-Object)
            $DocsUnclassified = @($Mismatch.UnclassifiedActions | Select-Object -ExpandProperty Action -Unique | Sort-Object)
        }
        #endregion

        #region Print summary
        $Duration = (Get-Date) - $StartTime
        Write-Host ""
        Write-Host "================ CLASSIFICATION UPDATE SUMMARY ================" -ForegroundColor Cyan
        Write-Host ("Completed in {0:hh\:mm\:ss}" -f $Duration) -ForegroundColor Cyan
        Write-Host ""
        Write-Host "Unclassified items per source:" -ForegroundColor Yellow
        foreach ($Source in $UnclassifiedBySource.Keys) {
            $count = $UnclassifiedBySource[$Source].Count
            $color = if ($count -gt 0) { "Yellow" } else { "Green" }
            Write-Host ("  {0,-52} {1}" -f $Source, $count) -ForegroundColor $color
        }
        Write-Host ""
        Write-Host "Microsoft Docs comparison (Entra ID directory roles):" -ForegroundColor Yellow
        Write-Host ("  Actions only in Graph export : {0}" -f $OnlyInGraph.Count) -ForegroundColor Yellow
        Write-Host ("  Actions only in Docs export  : {0}" -f $OnlyInDocs.Count) -ForegroundColor Magenta
        Write-Host ("  Unclassified (Graph+Docs)    : {0}" -f $DocsUnclassified.Count) -ForegroundColor Red

        # Copy-friendly blocks (plain text, no markdown, safe to paste into JSON or an AI prompt)
        Write-Host ""
        Write-Host "----- COPY/PASTE: UNCLASSIFIED ACTIONS PER SOURCE -----" -ForegroundColor Green
        foreach ($Source in $UnclassifiedBySource.Keys) {
            $list = $UnclassifiedBySource[$Source]
            if ($list.Count -gt 0) {
                Write-Host ""
                Write-Host ("# {0} ({1} unclassified)" -f $Source, $list.Count) -ForegroundColor Green
                $list | ForEach-Object { Write-Host $_ }
            }
        }

        if ($DocsUnclassified.Count -gt 0) {
            Write-Host ""
            Write-Host "----- COPY/PASTE: UNCLASSIFIED DIRECTORY ROLE ACTIONS (Graph + Docs) -----" -ForegroundColor Green
            $DocsUnclassified | ForEach-Object { Write-Host $_ }
        }

        if ($OnlyInDocs.Count -gt 0) {
            Write-Host ""
            Write-Host "----- COPY/PASTE: ACTIONS PRESENT ONLY IN MICROSOFT DOCS (missing from Graph export) -----" -ForegroundColor Green
            $OnlyInDocs | ForEach-Object { Write-Host $_ }
        }
        Write-Host ""
        Write-Host "==============================================================" -ForegroundColor Cyan
        Write-Host ""
        #endregion

        return [PSCustomObject]@{
            RepoRoot              = $RepoRoot
            DurationSeconds       = [math]::Round($Duration.TotalSeconds, 1)
            UnclassifiedBySource  = $UnclassifiedBySource
            TotalUnclassified     = (($UnclassifiedBySource.Values | ForEach-Object { $_.Count }) | Measure-Object -Sum).Sum
            DocsOnlyActions       = $OnlyInDocs
            GraphOnlyActions      = $OnlyInGraph
            DirectoryUnclassified = $DocsUnclassified
            ActionDifferenceCount = if ($Mismatch) { @($Mismatch.ActionDifferences).Count } else { 0 }
        }
    } finally {
        if ($Jobs.Count -gt 0) {
            $Jobs | Stop-Job -ErrorAction SilentlyContinue
            $Jobs | Remove-Job -Force -ErrorAction SilentlyContinue
        }
        Remove-Item -LiteralPath $MismatchTempFile -Force -ErrorAction SilentlyContinue
        Set-Location -LiteralPath $OriginalLocation.Path
    }
}
