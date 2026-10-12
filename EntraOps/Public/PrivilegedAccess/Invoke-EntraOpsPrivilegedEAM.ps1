<#
.SYNOPSIS
    Run EntraOps Privileged EAM classification without any pre-configuration.

.DESCRIPTION
    Zero-config entry point that resolves tenant identity from an already-authenticated
    AzContext and MgGraph context, sets up all required global variables, downloads the
    latest classification templates from the AzurePrivilegedIAM repository, computes the
    Control Plane scope, runs Save-EntraOpsPrivilegedEAMJson, and cleans up every
    intermediate file so that only the PrivilegedEAM JSON output remains.

    Prerequisites:
    - PowerShell 7+ with the EntraOps module loaded.
    - An active Az context (Connect-AzAccount).
    - An active Microsoft Graph context (Connect-MgGraph).

    No EntraOpsConfig.json, no Classification folder, and no tenant-specific files are
    required beforehand. All temporary artefacts are removed after the run, except for
    Classification_RoleActionOverwrites.json and Classification_RoleDefinitionOverwrites.json
    in the tenant-specific Classification folder: these are tenant customization files that
    can be authored/maintained outside of this cmdlet (e.g. via the ClassificationExplorer
    "Customize Overwrites" view, or manually) and are always preserved if present. Use
    -KeepClassificationFiles to keep all classification files for the reporting apps.

.PARAMETER RbacSystems
    RBAC systems to classify. Defaults to Azure, EntraID, IdentityGovernance,
    DeviceManagement, and ResourceApps.

.PARAMETER PrivilegedObjectClassificationSource
    Source for Control Plane scope determination passed to
    Update-EntraOpsClassificationControlPlaneScope. Default is "All", combining any existing
    EntraOps EAM export with live Azure Resource Graph and Exposure Management sources.

.PARAMETER ClassificationParameterScope
    Which RBAC systems receive a parameterised classification file before the run.
    Filtered automatically to the intersection with $RbacSystems. Default is
    EntraID, DeviceManagement, and Azure.

.PARAMETER ExportFolder
    Destination folder for PrivilegedEAM JSON output. Defaults to
    <EntraOpsBaseFolder>/PrivilegedEAM/.

.PARAMETER KeepClassificationFiles
    Keep the downloaded classification templates and the generated tenant-specific classification
    files instead of removing them after the run, e.g. so New-EntraOpsReportingData can show the
    classification that was used for the export in the Classification Explorer.

.EXAMPLE
    Run EntraOps with all defaults from an already-authenticated session.
    Invoke-EntraOpsPrivilegedEAM

.EXAMPLE
    Run EntraOps and generate the reporting apps from the export and its classification files.
    Invoke-EntraOpsPrivilegedEAM -KeepClassificationFiles; New-EntraOpsReportingData

.EXAMPLE
    Run for EntraID and Azure only, sourcing Control Plane objects from Azure Resource Graph.
    Invoke-EntraOpsPrivilegedEAM -RbacSystems @("EntraID","Azure") -PrivilegedObjectClassificationSource "PrivilegedRolesFromAzGraph"

.EXAMPLE
    Save output to a custom folder.
    Invoke-EntraOpsPrivilegedEAM -ExportFolder "C:\Output\PrivilegedEAM"
#>
function Invoke-EntraOpsPrivilegedEAM {

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [ValidateSet("Azure", "EntraID", "IdentityGovernance", "DeviceManagement", "ResourceApps", "Defender")]
        [Array]$RbacSystems = @("Azure", "EntraID", "IdentityGovernance", "DeviceManagement", "ResourceApps")
        ,
        [Parameter(Mandatory = $false)]
        [ValidateSet("All", "EntraOps", "PrivilegedObjectIds", "PrivilegedRolesFromAzGraph", "PrivilegedEdgesFromExposureManagement")]
        [string]$PrivilegedObjectClassificationSource = "All"
        ,
        [Parameter(Mandatory = $false)]
        [ValidateSet("EntraID", "DeviceManagement", "Azure")]
        [Array]$ClassificationParameterScope = @("EntraID", "DeviceManagement", "Azure")
        ,
        [Parameter(Mandatory = $false)]
        [System.String]$ExportFolder
        ,
        [Parameter(Mandatory = $false)]
        [switch]$KeepClassificationFiles
    )

    $ErrorActionPreference = "Stop"
    $Activity = "Invoke-EntraOpsPrivilegedEAM"

    # Tracks which paths were created by this cmdlet so only those are cleaned up.
    $CreatedPaths = [System.Collections.Generic.List[string]]::new()
    # Names of classification templates this run actually downloaded into a pre-existing Templates folder.
    # Stays empty unless the download phase completes, so teardown can never delete user-supplied templates.
    $DownloadedTemplates = [System.Collections.Generic.List[string]]::new()

    # Helper: create a directory only if it does not already exist; record it for cleanup.
    function New-EntraOpsDirectory {
        param (
            [string]$Path,
            [System.Collections.Generic.List[string]]$Track
        )
        if (-not (Test-Path -LiteralPath $Path)) {
            New-Item -ItemType Directory -Path $Path -Force | Out-Null
            $Track.Add($Path)
        }
    }

    try {
        # ── Banner ────────────────────────────────────────────────────────────────
        Write-Host ""
        Write-Host "═══════════════════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
        Write-Host "  Invoke-EntraOpsPrivilegedEAM  —  Zero-Config Run" -ForegroundColor Cyan
        Write-Host "  RBAC Systems : $($RbacSystems -join ', ')" -ForegroundColor Cyan
        Write-Host "  CP Source    : $PrivilegedObjectClassificationSource" -ForegroundColor Cyan
        Write-Host "═══════════════════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
        Write-Host ""

        # ── Phase 1: Validate authentication ─────────────────────────────────────
        Write-Progress -Activity $Activity -Status "Phase 1/7: Validating authentication contexts..." -PercentComplete 2

        Write-Host "  [1/7] Validating authentication contexts..." -ForegroundColor Cyan

        $AzContext = Get-AzContext -ErrorAction SilentlyContinue
        if (-not $AzContext -or [string]::IsNullOrEmpty($AzContext.Tenant.Id)) {
            throw "No active Azure context found. Run Connect-AzAccount before invoking this cmdlet."
        }

        $MgContext = Get-MgContext -ErrorAction SilentlyContinue
        if (-not $MgContext -or [string]::IsNullOrEmpty($MgContext.TenantId)) {
            throw "No active Microsoft Graph context found. Run Connect-MgGraph before invoking this cmdlet."
        }

        Write-Host "       Azure  : $($AzContext.Account.Id) @ tenant $($AzContext.Tenant.Id)" -ForegroundColor Gray
        Write-Host "       Graph  : $($MgContext.Account) @ tenant $($MgContext.TenantId)" -ForegroundColor Gray
        Write-Host "       Status : OK" -ForegroundColor Green

        # ── Phase 2: Resolve tenant identity ─────────────────────────────────────
        Write-Progress -Activity $Activity -Status "Phase 2/7: Resolving tenant identity..." -PercentComplete 8

        Write-Host ""
        Write-Host "  [2/7] Resolving tenant identity..." -ForegroundColor Cyan

        $TenantId = $AzContext.Tenant.Id
        if ([string]::IsNullOrEmpty($TenantId)) {
            $TenantId = $MgContext.TenantId
        }

        # Primary: Get-AzTenant (same method used by New-EntraOpsConfigFile)
        $TenantName = $null
        try {
            $TenantDetails = Get-AzTenant -TenantId $TenantId -ErrorAction Stop
            $TenantName = $TenantDetails.Domains[0]
        } catch {
            Write-Warning "Get-AzTenant failed ($($_.Exception.Message)). Falling back to Microsoft Graph organization endpoint..."
        }

        # Fallback: Microsoft Graph /organization
        if ([string]::IsNullOrEmpty($TenantName)) {
            try {
                $OrgResponse = Invoke-MgGraphRequest -Uri "v1.0/organization?`$select=verifiedDomains" -OutputType PSObject -ErrorAction Stop
                $TenantName = ($OrgResponse.value[0].verifiedDomains |
                    Where-Object { $_.isDefault -eq $true } |
                    Select-Object -ExpandProperty name -First 1)
            } catch {
                throw "Unable to determine TenantName from Azure or Microsoft Graph context: $($_.Exception.Message)"
            }
        }

        if ([string]::IsNullOrEmpty($TenantName)) {
            throw "TenantName could not be resolved. Check that Get-AzTenant or Microsoft Graph /organization is accessible."
        }

        Write-Host "       TenantId   : $TenantId" -ForegroundColor Gray
        Write-Host "       TenantName : $TenantName" -ForegroundColor Gray
        Write-Host "       Status     : OK" -ForegroundColor Green

        # ── Phase 3: Initialise environment ──────────────────────────────────────
        Write-Progress -Activity $Activity -Status "Phase 3/7: Initialising environment and global variables..." -PercentComplete 14

        Write-Host ""
        Write-Host "  [3/7] Initialising environment and global variables..." -ForegroundColor Cyan

        if ([string]::IsNullOrEmpty($EntraOpsBaseFolder)) {
            throw "EntraOpsBaseFolder is not set. Ensure the EntraOps module is properly imported."
        }

        # Set global variables mirroring Connect-EntraOps (single-tenant layout)
        New-Variable -Name TenantIdContext            -Value $TenantId   -Scope Global -Force
        New-Variable -Name TenantNameContext          -Value $TenantName -Scope Global -Force
        New-Variable -Name DefaultFolderClassification -Value "$EntraOpsBaseFolder/Classification/" -Scope Global -Force
        New-Variable -Name XdrAvdHuntingAccess         -Value (($MgContext.Scopes) -contains "ThreatHunting.Read.All") -Scope Global -Force
        # Default the query mode only when Connect-EntraOps has not set it yet, so a previously
        # chosen -UseInvokeRestMethodOnly session setting is preserved
        if (-not $__EntraOpsSession.ContainsKey('UseInvokeRestMethodOnly')) {
            $__EntraOpsSession['UseInvokeRestMethodOnly'] = $false
        }
        New-Variable -Name ManagingTenantIdContext      -Value "" -Scope Global -Force
        New-Variable -Name ManagingTenantNameContext    -Value "" -Scope Global -Force

        $ResolvedExportFolder = if ($PSBoundParameters.ContainsKey('ExportFolder') -and -not [string]::IsNullOrEmpty($ExportFolder)) {
            $ExportFolder
        } else {
            "$EntraOpsBaseFolder/PrivilegedEAM/"
        }
        New-Variable -Name DefaultFolderClassifiedEam -Value $ResolvedExportFolder -Scope Global -Force

        # Phase 5 can consume a previous EAM export, but a zero-config first run has no such files yet.
        # Remember that state before creating the output directory so Phase 6 can bootstrap scope reasoning
        # once from the fresh export without imposing a second pass on normal subsequent runs.
        # ALL selected systems must have a prior export: a partial folder (e.g. only EntraID.json, no
        # Azure/ResourceApps data driving managed-identity tiering) still needs the bootstrap pass.
        $HadExistingEamData = @($RbacSystems | Where-Object {
                Test-Path -LiteralPath (Join-Path $ResolvedExportFolder $_ "$_.json") -PathType Leaf
            }).Count -eq @($RbacSystems).Count

        # Build a minimal default EntraOpsConfig in memory (no config file required)
        $DefaultEntraOpsConfig = @{
            TenantId                         = $TenantId
            TenantName                       = $TenantName
            RbacSystems                      = $RbacSystems
            AzureRbacClassification          = @{
                ClassifyConstrainedDelegationAlwaysAsControlPlane = $false
                UnresolvedRoleDefinitionFallbackTier              = "Unclassified"
                DeletedPrincipalAssignmentHandling                = "Filter"
            }
            AutomatedClassificationUpdate    = @{
                Classifications = @(
                    "AadResources", "AadResources.Param", "ApiPermissions",
                    "Azure", "Azure.Param",
                    "Defender",
                    "DeviceManagement", "DeviceManagement.Param",
                    "IdentityGovernance"
                )
            }
            AutomatedControlPlaneScopeUpdate = @{
                PrivilegedObjectClassificationSource = @($PrivilegedObjectClassificationSource)
                EntraOpsScopes                       = $RbacSystems
                AzureHighPrivilegedRoles             = @("Owner", "Role Based Access Control Administrator", "User Access Administrator")
                # "/" covers elevateAccess-scoped assignments; the management group path covers the
                # tenant root management group (the real highest hierarchy in ARM).
                AzureHighPrivilegedScopes            = @("/", "/providers/microsoft.management/managementgroups/$TenantId")
                ExposureCriticalityLevel             = "<1"
            }
            CustomSecurityAttributes         = @{
                PrivilegedUserAttribute             = "privilegedUser"
                PrivilegedUserPawAttribute          = "associatedSecureAdminWorkstation"
                PrivilegedServicePrincipalAttribute = "privilegedWorkloadIdentity"
                UserWorkAccountAttribute            = "associatedWorkAccount"
            }
        }
        New-Variable -Name EntraOpsConfig -Value $DefaultEntraOpsConfig -Scope Global -Force

        # Construct canonical paths used throughout this run
        $ClassificationRoot = Join-Path $EntraOpsBaseFolder "Classification"
        $ClassificationTemplates = Join-Path $ClassificationRoot "Templates"
        $ClassificationTenant = Join-Path $ClassificationRoot $TenantName

        # Ensure required directories exist; track newly created ones for cleanup
        New-EntraOpsDirectory -Path $ClassificationRoot      -Track $CreatedPaths
        New-EntraOpsDirectory -Path $ClassificationTemplates -Track $CreatedPaths
        New-EntraOpsDirectory -Path $ClassificationTenant    -Track $CreatedPaths
        New-EntraOpsDirectory -Path $ResolvedExportFolder    -Track $CreatedPaths

        Write-Host "       Base folder       : $EntraOpsBaseFolder" -ForegroundColor Gray
        Write-Host "       Classification    : $ClassificationRoot" -ForegroundColor Gray
        Write-Host "       EAM output        : $ResolvedExportFolder" -ForegroundColor Gray
        Write-Host "       Paths created     : $($CreatedPaths.Count)" -ForegroundColor Gray
        Write-Host "       Status            : OK" -ForegroundColor Green

        # ── Phase 4: Download latest classification files ─────────────────────────
        Write-Progress -Activity $Activity -Status "Phase 4/7: Downloading latest classification templates..." -PercentComplete 22

        Write-Host ""
        Write-Host "  [4/7] Downloading latest classification templates from AzurePrivilegedIAM..." -ForegroundColor Cyan

        # Snapshot pre-existing templates so teardown can delete only what THIS run downloaded. The previous
        # "Classification_*.json" wildcard removed templates the user had downloaded or authored earlier.
        $PreExistingTemplates = @()
        if (Test-Path -LiteralPath $ClassificationTemplates -ErrorAction SilentlyContinue) {
            $PreExistingTemplates = @(Get-ChildItem -LiteralPath $ClassificationTemplates -Filter "Classification_*.json" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name)
        }

        Update-EntraOpsClassificationFiles `
            -FolderClassification $ClassificationTemplates `
            -Classifications @(
            "AadResources", "AadResources.Param", "ApiPermissions",
            "Azure", "Azure.Param",
            "Defender",
            "DeviceManagement", "DeviceManagement.Param",
            "IdentityGovernance"
        )

        # Record only the templates that did not exist before this run, so teardown removes exactly those.
        if (Test-Path -LiteralPath $ClassificationTemplates -ErrorAction SilentlyContinue) {
            Get-ChildItem -LiteralPath $ClassificationTemplates -Filter "Classification_*.json" -ErrorAction SilentlyContinue |
            Where-Object { $PreExistingTemplates -notcontains $_.Name } |
            ForEach-Object { $DownloadedTemplates.Add($_.Name) | Out-Null }
        }

        Write-Host "       Status : Classification templates updated." -ForegroundColor Green

        # ── Phase 5: Update Control Plane scope ───────────────────────────────────
        Write-Progress -Activity $Activity -Status "Phase 5/7: Updating Control Plane scope classification..." -PercentComplete 38

        Write-Host ""
        Write-Host "  [5/7] Updating Control Plane scope classification..." -ForegroundColor Cyan

        # Limit classification parameter scope to systems that are actually being collected
        $EffectiveClassificationScope = $ClassificationParameterScope | Where-Object {
            ($_ -eq "EntraID" -and $RbacSystems -contains "EntraID") -or
            ($_ -eq "DeviceManagement" -and $RbacSystems -contains "DeviceManagement") -or
            ($_ -eq "Azure" -and $RbacSystems -contains "Azure")
        }

        if ($EffectiveClassificationScope.Count -eq 0) {
            Write-Warning "No ClassificationParameterScope entries intersect with the selected RbacSystems. Skipping Update-EntraOpsClassificationControlPlaneScope."
        } else {
            Write-Host "       Effective scope : $($EffectiveClassificationScope -join ', ')" -ForegroundColor Gray
            Update-EntraOpsClassificationControlPlaneScope `
                -PrivilegedObjectClassificationSource $PrivilegedObjectClassificationSource `
                -ClassificationParameterScope         $EffectiveClassificationScope `
                -EntraOpsScopes                       $RbacSystems
        }

        Write-Host "       Status : Control Plane scope updated." -ForegroundColor Green

        # ── Phase 6: Save EAM JSON ────────────────────────────────────────────────
        Write-Progress -Activity $Activity -Status "Phase 6/7: Running EntraOps classification and saving EAM JSON..." -PercentComplete 62

        Write-Host ""
        Write-Host "  [6/7] Running EntraOps classification and saving Privileged EAM JSON..." -ForegroundColor Cyan
        Write-Host "       RbacSystems : $($RbacSystems -join ', ')" -ForegroundColor Gray
        Write-Host "       Output      : $ResolvedExportFolder" -ForegroundColor Gray

        Save-EntraOpsPrivilegedEAMJson -ExportFolder $ResolvedExportFolder -RbacSystems $RbacSystems

        Write-Host "       Status : EAM JSON saved." -ForegroundColor Green

        if (-not $HadExistingEamData -and $EffectiveClassificationScope.Count -gt 0) {
            Write-Host ""
            Write-Host "       First-run bootstrap: refreshing Control Plane scope from the fresh EAM export..." -ForegroundColor Yellow
            # Same source as the first pass: narrowing to 'EntraOps' here would drop live-source-only
            # objects (e.g. XSPM-critical assets without classified roles) from the Control Plane scope.
            Update-EntraOpsClassificationControlPlaneScope `
                -PrivilegedObjectClassificationSource $PrivilegedObjectClassificationSource `
                -ClassificationParameterScope         $EffectiveClassificationScope `
                -EntraOpsScopes                       $RbacSystems
            # The Graph cache was populated moments ago by the first pass - only the classification
            # files changed, so the re-export can reuse it instead of re-collecting everything.
            Save-EntraOpsPrivilegedEAMJson -ExportFolder $ResolvedExportFolder -RbacSystems $RbacSystems -UseCache $true
            Write-Host "       Status : Scope reasoning and EAM JSON refreshed from first-run output." -ForegroundColor Green
        }

        # ── Summary ───────────────────────────────────────────────────────────────
        Write-Progress -Activity $Activity -Status "Complete." -PercentComplete 100

        $OutputFiles = Get-ChildItem -Path $ResolvedExportFolder -Filter "*.json" -Recurse -ErrorAction SilentlyContinue
        $OutputCount = if ($OutputFiles) { @($OutputFiles).Count } else { 0 }

        Write-Host ""
        Write-Host "═══════════════════════════════════════════════════════════════════════════════" -ForegroundColor Green
        Write-Host "  Invoke-EntraOpsPrivilegedEAM  —  Complete" -ForegroundColor Green
        Write-Host "  Tenant     : $TenantName  ($TenantId)" -ForegroundColor White
        Write-Host "  Output     : $ResolvedExportFolder" -ForegroundColor White
        Write-Host "  JSON files : $OutputCount" -ForegroundColor White
        Write-Host "═══════════════════════════════════════════════════════════════════════════════" -ForegroundColor Green
        Write-Host ""

        Start-Sleep -Milliseconds 400
        Write-Progress -Activity $Activity -Completed
    } catch {
        Write-Progress -Activity $Activity -Completed
        Write-Host ""
        Write-Host "  [ERROR] Invoke-EntraOpsPrivilegedEAM failed at:" -ForegroundColor Red
        Write-Host "  $($_.InvocationInfo.PositionMessage)" -ForegroundColor DarkRed
        Write-Host "  $($_.Exception.Message)" -ForegroundColor Red
        Write-Host ""
        throw
    } finally {
        # ── Always: remove classification artefacts and disconnect ────────────────
        # Null-guards protect against early failures before path variables were set.
        Write-Host "  [Teardown] Removing classification artefacts and disconnecting..." -ForegroundColor Cyan

        if ($KeepClassificationFiles) {
            Write-Host "       Kept    : classification files in $ClassificationRoot (-KeepClassificationFiles)" -ForegroundColor DarkGray
        }

        # Remove the generated tenant-specific classification folder, but preserve
        # Classification_RoleActionOverwrites.json and Classification_RoleDefinitionOverwrites.json:
        # these are tenant customization files that are commonly authored/maintained outside of this
        # cmdlet (e.g. via the ClassificationExplorer "Customize Overwrites" view, or manually) and
        # must survive a zero-config run, unlike the classification files generated by this run.
        # Only clean up a tenant folder THIS run created. Without the $CreatedPaths gate (already used for the
        # Templates and Classification root below) a zero-config run against an existing configured repo
        # permanently deleted the user's generated Classification_Azure.json / ScopeReasoning_*.json - on the
        # success path as well as on failure.
        if (-not $KeepClassificationFiles -and -not [string]::IsNullOrEmpty($ClassificationTenant) -and ($CreatedPaths -contains $ClassificationTenant) -and (Test-Path -LiteralPath $ClassificationTenant -ErrorAction SilentlyContinue)) {
            $PreservedTenantFiles = @('Classification_RoleActionOverwrites.json', 'Classification_RoleDefinitionOverwrites.json')
            Get-ChildItem -LiteralPath $ClassificationTenant -Force -ErrorAction SilentlyContinue |
            Where-Object { $PreservedTenantFiles -notcontains $_.Name } |
            Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
            Write-Host "       Cleaned : $ClassificationTenant (preserved $($PreservedTenantFiles -join ', '))" -ForegroundColor DarkGray

            # Remove the tenant folder itself only if it ends up empty (i.e. no preserved overwrite files remain).
            if (-not (Get-ChildItem -LiteralPath $ClassificationTenant -Force -ErrorAction SilentlyContinue)) {
                Remove-Item -LiteralPath $ClassificationTenant -Recurse -Force -ErrorAction SilentlyContinue
                Write-Host "       Removed : empty folder $ClassificationTenant" -ForegroundColor DarkGray
            }
        }

        # Templates folder: remove whole folder if we created it, otherwise only downloaded files
        if (-not $KeepClassificationFiles -and -not [string]::IsNullOrEmpty($ClassificationTemplates)) {
            if (($CreatedPaths -contains $ClassificationTemplates) -and (Test-Path -LiteralPath $ClassificationTemplates -ErrorAction SilentlyContinue)) {
                Remove-Item -LiteralPath $ClassificationTemplates -Recurse -Force -ErrorAction SilentlyContinue
                Write-Host "       Removed : $ClassificationTemplates" -ForegroundColor DarkGray
            } elseif (Test-Path -LiteralPath $ClassificationTemplates -ErrorAction SilentlyContinue) {
                # Pre-existing folder: remove only the templates this run downloaded, never ones that were
                # already present (they may be user-maintained or downloaded by an earlier configured run).
                # $DownloadedTemplates stays empty if the run failed before the download phase.
                $RemovedTemplateCount = 0
                foreach ($TemplateName in $DownloadedTemplates) {
                    $TemplatePath = Join-Path -Path $ClassificationTemplates -ChildPath $TemplateName
                    if (Test-Path -LiteralPath $TemplatePath -ErrorAction SilentlyContinue) {
                        Remove-Item -LiteralPath $TemplatePath -Force -ErrorAction SilentlyContinue
                        $RemovedTemplateCount++
                    }
                }
                Write-Host "       Cleaned : $RemovedTemplateCount downloaded template(s) from $ClassificationTemplates (pre-existing files preserved)" -ForegroundColor DarkGray
            }
        }

        # Remove Classification root if we created it and it is now empty
        if (-not $KeepClassificationFiles -and -not [string]::IsNullOrEmpty($ClassificationRoot) -and ($CreatedPaths -contains $ClassificationRoot) -and (Test-Path -LiteralPath $ClassificationRoot -ErrorAction SilentlyContinue)) {
            $Remaining = Get-ChildItem -LiteralPath $ClassificationRoot -Recurse -ErrorAction SilentlyContinue
            if (-not $Remaining) {
                Remove-Item -LiteralPath $ClassificationRoot -Recurse -Force -ErrorAction SilentlyContinue
                Write-Host "       Removed : empty root $ClassificationRoot" -ForegroundColor DarkGray
            }
        }

        # Clear EntraOps cache and disconnect from Azure / Microsoft Graph
        try {
            Disconnect-EntraOps -ClearEntraOpsCache All -ErrorAction SilentlyContinue
            Write-Host "       Status : Cache cleared and session disconnected." -ForegroundColor Green
        } catch {
            Write-Warning "Disconnect-EntraOps encountered an error during teardown: $($_.Exception.Message)"
        }
        Write-Host ""
    }
}
