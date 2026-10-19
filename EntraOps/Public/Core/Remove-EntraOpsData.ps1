<#
.SYNOPSIS
    Removes the data that EntraOps generated in its working folder, and optionally the cache.

.DESCRIPTION
    Deletes EntraOps output that may contain tenant data, by content type:

        * PrivilegedEAM    - the Privileged EAM export folder (PrivilegedEAM/, including FailedRequests logs)
        * Reports          - the generated report data bundles (Remove-EntraOpsReportingData); the apps are kept
        * Classification   - the tenant classification folders (Classification/<TenantName>/). The manually
                             maintained overwrite files (Classification_RoleActionOverwrites.json,
                             Classification_RoleDefinitionOverwrites.json, Classification_ApiPermissionOverwrites.json
                             and their _<Tag> variants such as Classification_RoleDefinitionOverwrites_PAW.json),
                             Classification/Templates,
                             Classification/Global.json and other files directly in Classification/ (e.g. the
                             Object Classification File) are kept.
        * TenantGovernance - the Tenant Governance snapshots (TenantGovernance/Snapshots/, including the
                             snapshot manifest and a pending snapshot job)
        * Cache            - the in-memory and persistent Microsoft Graph/ARM cache (Clear-EntraOpsCache -CacheType All)

    Only paths inside the working folder are removed. In a git repository (e.g. the EntraOps repository or a
    deployment repository) the exports are tracked history: the cmdlet stops unless -Force is used. Prompts for
    confirmation by default; use -WhatIf to see what would be removed.

.PARAMETER Content
    Content types to remove. Defaults to all.

.PARAMETER Path
    EntraOps working folder. Defaults to $EntraOpsBaseFolder.

.PARAMETER TenantName
    Only remove the classification folders of these tenants (e.g. contoso.onmicrosoft.com). Defaults to all
    tenant folders.

.PARAMETER Force
    Also remove data in a git repository.

.PARAMETER PassThru
    Returns one object per removed or skipped item.

.EXAMPLE
    Remove-EntraOpsData -WhatIf

    Shows which EntraOps output and cache would be removed from the working folder.

.EXAMPLE
    Remove-EntraOpsData -Content PrivilegedEAM, Reports -Confirm:$false

    Removes the Privileged EAM export and the generated report data without prompting.
#>
function Remove-EntraOpsData {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    [OutputType([pscustomobject])]
    param (
        [Parameter(Mandatory = $false)]
        [ValidateSet('PrivilegedEAM', 'Reports', 'Classification', 'TenantGovernance', 'Cache')]
        [System.String[]]$Content = @('PrivilegedEAM', 'Reports', 'Classification', 'TenantGovernance', 'Cache'),

        [Parameter(Mandatory = $false)]
        [System.String]$Path,

        [Parameter(Mandatory = $false)]
        [System.String[]]$TenantName,

        [Parameter(Mandatory = $false)]
        [switch]$Force,

        [Parameter(Mandatory = $false)]
        [switch]$PassThru
    )

    $ErrorActionPreference = 'Stop'

    if ([string]::IsNullOrWhiteSpace($Path)) {
        if ([string]::IsNullOrWhiteSpace($Global:EntraOpsBaseFolder)) {
            throw "The EntraOps working folder is not set. Pass -Path or import the module with 'Import-Module EntraOps -Force'."
        }
        $Path = $Global:EntraOpsBaseFolder
    }
    $Path = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path).TrimEnd([char[]]@('/', '\'))
    if (-not (Test-Path -LiteralPath $Path -PathType Container)) {
        throw "EntraOps working folder '$Path' doesn't exist."
    }

    $FileContent = @($Content | Where-Object { $_ -ne 'Cache' })
    if ($FileContent.Count -gt 0 -and (Test-Path -LiteralPath (Join-Path $Path '.git')) -and -not $Force) {
        throw "'$Path' is a git repository: its EntraOps data is tracked history. Remove it with git, or use -Force to remove the files from the working tree."
    }

    $Results = [System.Collections.Generic.List[object]]::new()
    $RemoveTarget = {
        param([string]$ContentName, [string]$Target)
        if (-not (Test-Path -LiteralPath $Target)) {
            $Results.Add([pscustomobject]@{ Content = $ContentName; Path = $Target; Removed = $false; Reason = 'NotFound' })
            return
        }
        if (-not (Test-EntraOpsPathWithinRoot -Path $Target -Root $Path)) {
            Write-Warning "Skipped '$Target': it resolves outside the working folder '$Path'."
            $Results.Add([pscustomobject]@{ Content = $ContentName; Path = $Target; Removed = $false; Reason = 'OutsideWorkingFolder' })
            return
        }
        if ((Get-Item -LiteralPath $Target -Force).LinkType) {
            Write-Warning "Skipped '$Target': links aren't followed."
            $Results.Add([pscustomobject]@{ Content = $ContentName; Path = $Target; Removed = $false; Reason = 'Link' })
            return
        }
        if ($PSCmdlet.ShouldProcess($Target, "Remove EntraOps $ContentName data")) {
            Remove-Item -LiteralPath $Target -Recurse -Force -WhatIf:$false -Confirm:$false
            Write-Host "Removed $ContentName data: $Target"
            $Results.Add([pscustomobject]@{ Content = $ContentName; Path = $Target; Removed = $true; Reason = $null })
        }
    }

    if ($Content -contains 'PrivilegedEAM') {
        & $RemoveTarget 'PrivilegedEAM' (Join-Path $Path 'PrivilegedEAM')
    }

    if ($Content -contains 'Reports') {
        $ReportsFolder = Join-Path $Path 'Reports'
        if (Test-Path -LiteralPath $ReportsFolder -PathType Container) {
            # Confirm once for the report data like for the other content; -WhatIf still lists the individual files.
            $RemoveReportData = $PSCmdlet.ShouldProcess($ReportsFolder, "Remove EntraOps Reports data")
            if ($RemoveReportData -or $WhatIfPreference) {
                $RemovedReportData = @(Remove-EntraOpsReportingData -EntraOpsRoot $Path -PassThru -WhatIf:$WhatIfPreference -Confirm:$false)
                foreach ($Item in $RemovedReportData) {
                    $Results.Add([pscustomobject]@{ Content = 'Reports'; Path = "$($Item.Path)"; Removed = $Item.Removed; Reason = $Item.Reason })
                }
            }
        } else {
            $Results.Add([pscustomobject]@{ Content = 'Reports'; Path = $ReportsFolder; Removed = $false; Reason = 'NotFound' })
        }
    }

    if ($Content -contains 'Classification') {
        $ClassificationFolder = Join-Path $Path 'Classification'
        $TenantFolders = @(Get-ChildItem -LiteralPath $ClassificationFolder -Directory -Force -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -ne 'Templates' -and (-not $TenantName -or $_.Name -in $TenantName) })
        if ($TenantFolders.Count -eq 0) {
            $Results.Add([pscustomobject]@{ Content = 'Classification'; Path = $ClassificationFolder; Removed = $false; Reason = 'NotFound' })
        }
        foreach ($TenantFolder in $TenantFolders) {
            $Kept = @(Get-ChildItem -LiteralPath $TenantFolder.FullName -File -Force | Where-Object { Test-EntraOpsClassificationOverwriteFileName -Name $_.Name })
            $PreservedTenantFiles = @($Kept.Name)
            if ($Kept.Count -eq 0) {
                & $RemoveTarget 'Classification' $TenantFolder.FullName
                continue
            }
            foreach ($Item in @(Get-ChildItem -LiteralPath $TenantFolder.FullName -Force | Where-Object { $PreservedTenantFiles -notcontains $_.Name })) {
                & $RemoveTarget 'Classification' $Item.FullName
            }
            Write-Host "Kept classification overwrites: $($Kept.FullName -join ', ')"
        }
    }

    if ($Content -contains 'TenantGovernance') {
        & $RemoveTarget 'TenantGovernance' (Join-Path $Path 'TenantGovernance/Snapshots')
    }

    if ($Content -contains 'Cache' -and $PSCmdlet.ShouldProcess('EntraOps cache (memory and persistent)', 'Clear')) {
        Clear-EntraOpsCache -CacheType All | Out-Null
        $Results.Add([pscustomobject]@{ Content = 'Cache'; Path = $__EntraOpsSession.PersistentCachePath; Removed = $true; Reason = $null })
    }

    $RemovedCount = @($Results | Where-Object Removed).Count
    if (-not $WhatIfPreference) {
        Write-Host "Removed $RemovedCount EntraOps data item(s) from $Path."
    }
    if ($PassThru) { $Results }
}
