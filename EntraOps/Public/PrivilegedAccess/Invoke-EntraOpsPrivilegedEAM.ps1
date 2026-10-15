<#
.SYNOPSIS
    Run EntraOps Privileged EAM classification with an optional configuration file.

.DESCRIPTION
    Entry point that resolves tenant identity from an already-authenticated
    AzContext and MgGraph context, sets up all required global variables, downloads the
    latest classification templates from the AzurePrivilegedIAM repository, computes the
    Control Plane scope, runs Save-EntraOpsPrivilegedEAMJson, and cleans up every
    intermediate file so that only the PrivilegedEAM JSON output remains.

    Reuses the configuration loaded by Connect-EntraOps. Otherwise, looks for EntraOpsConfig.json
    in the current folder, then the EntraOps working folder. Use -ConfigFilePath to select a file
    explicitly. Command parameters override configuration values. Without a configuration, defaults apply.
    When an automatically found configuration contains AlternateObjectTierLevelAttributes filter
    expressions, a warning is written before the run because these expressions execute as PowerShell
    code. Pass trusted configuration files with -ConfigFilePath.
    The Azure and Microsoft Graph contexts must belong to the same tenant, with or without a configuration.

    Prerequisites:
    - PowerShell 7.4+ with the EntraOps module loaded.
    - An active Az context (Connect-AzAccount).
    - An active Microsoft Graph context (Connect-MgGraph).

    No EntraOpsConfig.json, no Classification folder, and no tenant-specific files are
    required beforehand. All temporary artefacts are removed after the run, except for
    Classification_RoleActionOverwrites.json and Classification_RoleDefinitionOverwrites.json
    in the tenant-specific Classification folder: these are tenant customization files that
    can be authored/maintained outside of this cmdlet (e.g. via the ClassificationExplorer
    "Customize Overwrites" view, or manually) and are always preserved if present. Use
    -KeepClassificationFiles to keep all classification files for the reporting apps.
    This cmdlet disconnects from Azure and Microsoft Graph during teardown. Reconnect before
    generating reports with live Microsoft Graph enrichment, or disable the reporting object lookups.

.PARAMETER RbacSystems
    RBAC systems to classify. Defaults to Azure, EntraID, IdentityGovernance,
    DeviceManagement, and ResourceApps when no configuration supplies RbacSystems.

.PARAMETER PrivilegedObjectClassificationSource
    Source for Control Plane scope determination passed to
    Update-EntraOpsClassificationControlPlaneScope. Uses the configuration value when present.
    Otherwise defaults to "All", combining any existing
    EntraOps EAM export with live Azure Resource Graph and Exposure Management sources.

.PARAMETER ClassificationParameterScope
    Which RBAC systems receive a parameterised classification file before the run.
    Filtered automatically to the intersection with $RbacSystems. Default is
    EntraID, DeviceManagement, and Azure when no configuration supplies ClassificationParameterScope.

.PARAMETER ExportFolder
    Destination folder for PrivilegedEAM JSON output. Defaults to
    the session output folder when reusing a loaded configuration, otherwise <EntraOpsBaseFolder>/PrivilegedEAM/.

.PARAMETER ConfigFilePath
    Path to an EntraOps configuration file. Takes precedence over the configuration loaded by Connect-EntraOps.

.PARAMETER KeepClassificationFiles
    Keep the downloaded classification templates and the generated tenant-specific classification
    files instead of removing them after the run, e.g. so New-EntraOpsReportingData can show the
    classification that was used for the export in the Classification Explorer.
    Controls cleanup only, independently of the choice to reuse or refresh templates.

.PARAMETER ExistingClassificationAction
    When tenant classification files exist, Prompt (default) asks whether to Reuse local templates
    (default choice) or Regenerate using refreshed templates. This prompt is independent of -KeepClassificationFiles.
    Reuse preserves existing templates and downloads only missing templates. Regenerate refreshes templates.
    Both choices rebuild tenant classifications and Control Plane scope reasoning for the selected scope
    through Update-EntraOpsClassificationControlPlaneScope, using the preserved tenant overwrite files.
    Pass Reuse or Regenerate explicitly for unattended runs to avoid prompting.

.EXAMPLE
    Run EntraOps with all defaults from an already-authenticated session.
    Invoke-EntraOpsPrivilegedEAM

.EXAMPLE
    Run EntraOps and generate the reporting apps from the export and its classification files.
    Invoke-EntraOpsPrivilegedEAM -KeepClassificationFiles -ExistingClassificationAction Reuse
    Connect-EntraOps -AuthenticationType UserInteractive -TenantName 'contoso.onmicrosoft.com'
    New-EntraOpsReportingData
    Disconnect-EntraOps

.EXAMPLE
    Run for EntraID and Azure only, sourcing Control Plane objects from Azure Resource Graph.
    Invoke-EntraOpsPrivilegedEAM -RbacSystems @("EntraID","Azure") -PrivilegedObjectClassificationSource "PrivilegedRolesFromAzGraph"

.EXAMPLE
    Save output to a custom folder.
    Invoke-EntraOpsPrivilegedEAM -ExportFolder "C:\Output\PrivilegedEAM"

.EXAMPLE
    Use the configuration loaded by Connect-EntraOps and rebuild tenant classifications from existing templates.
    Connect-EntraOps -TenantName 'contoso.onmicrosoft.com' -ConfigFilePath './EntraOpsConfig.json'
    Invoke-EntraOpsPrivilegedEAM -KeepClassificationFiles -ExistingClassificationAction Reuse
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
        [string[]]$PrivilegedObjectClassificationSource = "All"
        ,
        [Parameter(Mandatory = $false)]
        [ValidateSet("EntraID", "DeviceManagement", "Azure", "Defender", "IdentityGovernance", "ResourceApps")]
        [Array]$ClassificationParameterScope = @("EntraID", "DeviceManagement", "Azure")
        ,
        [Parameter(Mandatory = $false)]
        [System.String]$ExportFolder
        ,
        [Parameter(Mandatory = $false)]
        [switch]$KeepClassificationFiles
        ,
        [Parameter(Mandatory = $false)]
        [System.String]$ConfigFilePath
        ,
        [Parameter(Mandatory = $false)]
        [ValidateSet('Prompt', 'Reuse', 'Regenerate')]
        [string]$ExistingClassificationAction = 'Prompt'
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
        $SessionConfig = Get-Variable -Name EntraOpsConfig -Scope Global -ValueOnly -ErrorAction SilentlyContinue
        $UseSessionConfig = -not $ConfigFilePath -and $null -ne $SessionConfig
        $RunConfig = $null
        $ResolvedConfigPath = $null
        if ($UseSessionConfig) {
            $RunConfig = $SessionConfig
            $ResolvedConfigPath = $__EntraOpsSession['ConfigFilePath']
        } else {
            $ConfigAutoDiscovered = -not $ConfigFilePath
            if (-not $ConfigFilePath) {
                $ConfigFilePath = @(
                    Join-Path (Get-Location -PSProvider FileSystem).ProviderPath 'EntraOpsConfig.json'
                    if (-not [string]::IsNullOrWhiteSpace($EntraOpsBaseFolder)) { Join-Path $EntraOpsBaseFolder 'EntraOpsConfig.json' }
                ) | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } | Select-Object -First 1
            }
            if ($ConfigFilePath) {
                $ResolvedConfigPath = (Resolve-Path -LiteralPath $ConfigFilePath -ErrorAction Stop).ProviderPath
                $RunConfig = Get-Content -LiteralPath $ResolvedConfigPath -Raw | ConvertFrom-Json -Depth 100 -AsHashtable -NoEnumerate
                if ($RunConfig -isnot [System.Collections.IDictionary]) {
                    throw "Configuration file '$ResolvedConfigPath' must contain a JSON object."
                }
                # Warn before any AlternateObjectTierLevelAttributes filter can run: an automatically
                # discovered file (e.g. in a cloned or downloaded folder) was not explicitly chosen as trusted.
                $AlternateConfig = $RunConfig.AlternateObjectTierLevelAttributes
                $HasAlternateFilters = $null -ne $AlternateConfig -and @(foreach ($ObjectType in 'User', 'ServicePrincipal', 'Group') {
                        if (Test-EntraOpsAlternateObjectTierLevelEnabled -ObjectType $ObjectType -AlternateObjectTierLevelAttributes $AlternateConfig) {
                            foreach ($TierName in 'ControlPlane', 'ManagementPlane', 'WorkloadPlane', 'UserAccess') {
                                if (-not [string]::IsNullOrWhiteSpace([string]$AlternateConfig.$ObjectType.$TierName)) { $TierName }
                            }
                        }
                    }).Count -gt 0
                if ($ConfigAutoDiscovered -and $HasAlternateFilters) {
                    Write-Warning "Automatically loaded configuration '$ResolvedConfigPath' contains AlternateObjectTierLevelAttributes filter expressions. These expressions are executed as PowerShell code with your current sessions. Only run with configuration files you trust, and pass trusted files explicitly with -ConfigFilePath."
                }
            }
        }
        $HasConfiguration = $null -ne $RunConfig
        if ($HasConfiguration) {
            if (-not $PSBoundParameters.ContainsKey('RbacSystems') -and $RunConfig.RbacSystems) {
                $RbacSystems = $RunConfig.RbacSystems
            }
            if (-not $PSBoundParameters.ContainsKey('PrivilegedObjectClassificationSource') -and $RunConfig.AutomatedControlPlaneScopeUpdate.PrivilegedObjectClassificationSource) {
                $PrivilegedObjectClassificationSource = $RunConfig.AutomatedControlPlaneScopeUpdate.PrivilegedObjectClassificationSource
            }
            if (-not $PSBoundParameters.ContainsKey('ClassificationParameterScope') -and $null -ne $RunConfig.AutomatedControlPlaneScopeUpdate.ClassificationParameterScope) {
                $ClassificationParameterScope = $RunConfig.AutomatedControlPlaneScopeUpdate.ClassificationParameterScope
            }
        }

        # ── Banner ────────────────────────────────────────────────────────────────
        Write-Host ""
        Write-Host "═══════════════════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
        $RunMode = if ($HasConfiguration) { 'Configured Run' } else { 'Zero-Config Run' }
        Write-Host "  Invoke-EntraOpsPrivilegedEAM  —  $RunMode" -ForegroundColor Cyan
        if ($HasConfiguration) {
            $ConfigSource = if ($ResolvedConfigPath) { $ResolvedConfigPath } else { 'In-memory session configuration (source file path unavailable)' }
            Write-Host "  Config File  : $ConfigSource" -ForegroundColor Yellow
        }
        Write-Host "  RBAC Systems : $($RbacSystems -join ', ')" -ForegroundColor Cyan
        Write-Host "  CP Source    : $($PrivilegedObjectClassificationSource -join ', ')" -ForegroundColor Cyan
        Write-Host "═══════════════════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
        Write-Host ""

        # ── Phase 1: Validate authentication ─────────────────────────────────────
        Write-Progress -Activity $Activity -Status "Phase 1/7: Validating authentication contexts..." -PercentComplete 2

        Write-Host "  [1/7] Validating authentication contexts..." -ForegroundColor Cyan

        $AzContext = Get-AzContext -ErrorAction SilentlyContinue
        if (-not $AzContext -or [string]::IsNullOrEmpty($AzContext.Tenant.Id)) {
            throw "No active Azure context found. Establish an Azure context by running Connect-AzAccount or run Connect-EntraOps before invoking this cmdlet."
        }

        $MgContext = Get-MgContext -ErrorAction SilentlyContinue
        if (-not $MgContext -or [string]::IsNullOrEmpty($MgContext.TenantId)) {
            throw "No active Microsoft Graph context found. Establish an Microsoft Graph context by running Connect-MgGraph or run Connect-EntraOps before invoking this cmdlet."
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
        if ($HasConfiguration -and $RunConfig.TenantId -and $RunConfig.TenantId -ne $TenantId) {
            throw "Configuration tenant '$($RunConfig.TenantId)' does not match the active Azure tenant '$TenantId'. Connect-EntraOps to the configured tenant before running."
        }
        if ($MgContext.TenantId -ne $TenantId) {
            $ReconnectTarget = if ($HasConfiguration) { 'the configured tenant' } else { 'the same tenant in both contexts' }
            throw "Microsoft Graph tenant '$($MgContext.TenantId)' does not match the active Azure tenant '$TenantId'. Reconnect to $ReconnectTarget before running."
        }

        # Keep the configured tenant name so an alternate verified domain does not select a different
        # classification folder. Configurations without an ID must match a verified tenant domain.
        $TenantName = if ($HasConfiguration) { $RunConfig.TenantName }
        if ($TenantName -and -not $RunConfig.TenantId) {
            $TenantDetails = Get-AzTenant -TenantId $TenantId -ErrorAction Stop
            if ($TenantName -notin $TenantDetails.Domains) {
                throw "Configuration TenantName '$TenantName' does not match the active Azure tenant '$TenantId'."
            }
        }
        if ([string]::IsNullOrEmpty($TenantName)) {
            try {
                $TenantDetails = Get-AzTenant -TenantId $TenantId -ErrorAction Stop
                $TenantName = $TenantDetails.Domains[0]
            } catch {
                Write-Warning "Get-AzTenant failed ($($_.Exception.Message)). Falling back to Microsoft Graph organization endpoint..."
            }
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

        # Reuse configured session folders; standalone runs use the single-tenant layout.
        New-Variable -Name TenantIdContext            -Value $TenantId   -Scope Global -Force
        New-Variable -Name TenantNameContext          -Value $TenantName -Scope Global -Force
        # Same "<base>/Classification/" form as Connect-EntraOps; Join-Path would emit '\' on Windows.
        $ClassificationRoot = if ($UseSessionConfig -and -not [string]::IsNullOrWhiteSpace($DefaultFolderClassification)) {
            $DefaultFolderClassification
        } else { "$EntraOpsBaseFolder/Classification/" }
        New-Variable -Name DefaultFolderClassification -Value $ClassificationRoot -Scope Global -Force
        New-Variable -Name XdrAvdHuntingAccess         -Value (($MgContext.Scopes) -contains "ThreatHunting.Read.All") -Scope Global -Force
        # Default the query mode only when Connect-EntraOps has not set it yet, so a previously
        # chosen -UseInvokeRestMethodOnly session setting is preserved
        if (-not $__EntraOpsSession.ContainsKey('UseInvokeRestMethodOnly')) {
            $__EntraOpsSession['UseInvokeRestMethodOnly'] = [bool]$RunConfig.UseInvokeRestMethodOnly
        }
        $ManagingTenantId = if ($HasConfiguration) { [string]$RunConfig.ManagingTenantId } else { '' }
        $ManagingTenantName = if ($HasConfiguration) { [string]$RunConfig.ManagingTenantName } else { '' }
        New-Variable -Name ManagingTenantIdContext      -Value $ManagingTenantId -Scope Global -Force
        New-Variable -Name ManagingTenantNameContext    -Value $ManagingTenantName -Scope Global -Force

        $ResolvedExportFolder = if ($PSBoundParameters.ContainsKey('ExportFolder') -and -not [string]::IsNullOrEmpty($ExportFolder)) {
            $ExportFolder
        } elseif ($UseSessionConfig -and -not [string]::IsNullOrWhiteSpace($DefaultFolderClassifiedEam)) {
            $DefaultFolderClassifiedEam
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
        if (-not $HasConfiguration) { $RunConfig = $DefaultEntraOpsConfig }
        New-Variable -Name EntraOpsConfig -Value $RunConfig -Scope Global -Force
        if ($ResolvedConfigPath) { $__EntraOpsSession['ConfigFilePath'] = $ResolvedConfigPath }
        New-Variable -Name EntraOpsIncludeObjectDetails -Value ([bool]$RunConfig.ConsoleOutput.IncludeObjectDetails) -Scope Global -Force

        # Construct canonical paths used throughout this run
        $ClassificationTemplates = Join-Path $ClassificationRoot "Templates"
        $ClassificationTenant = Join-Path $ClassificationRoot $TenantName

        $ExistingTenantFiles = @(if (Test-Path -LiteralPath $ClassificationTenant -PathType Container) {
            Get-ChildItem -LiteralPath $ClassificationTenant -Filter 'Classification_*.json' -File
        })
        $ReuseExistingTemplates = $ExistingClassificationAction -eq 'Reuse'
        if ($ExistingClassificationAction -eq 'Prompt' -and $ExistingTenantFiles.Count -gt 0) {
            Write-Host "       Found $($ExistingTenantFiles.Count) classification file(s) for '$TenantName' in $ClassificationTenant" -ForegroundColor Yellow
            Write-Host "       Reuse keeps local templates. Regenerate downloads the latest templates. Both choices refresh tenant classifications and Control Plane scopes using the preserved tenant overwrite files." -ForegroundColor Yellow
            do {
                try {
                    $Answer = Read-Host 'Reuse local classification templates or regenerate using the latest templates? [R] Reuse (default) / [G] Regenerate'
                } catch {
                    throw "Unable to prompt for existing classification files. Pass -ExistingClassificationAction Reuse or Regenerate for unattended runs. $($_.Exception.Message)"
                }
                $Answer = ([string]$Answer).Trim()
                $ValidAnswer = $Answer -in @('', 'R', 'Reuse', 'G', 'Regenerate')
                if (-not $ValidAnswer) { Write-Host '       Enter R to reuse or G to regenerate.' -ForegroundColor Yellow }
            } until ($ValidAnswer)
            $ReuseExistingTemplates = $Answer -in @('', 'R', 'Reuse')
        }

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
        Write-Progress -Activity $Activity -Status "Phase 4/7: Preparing classification templates..." -PercentComplete 22

        Write-Host ""
        $TemplateStatus = if ($ReuseExistingTemplates) { 'Reusing existing classification templates and downloading missing files' } else { 'Downloading latest classification templates' }
        Write-Host "  [4/7] $TemplateStatus from AzurePrivilegedIAM..." -ForegroundColor Cyan

        # Snapshot pre-existing templates so teardown can delete only what THIS run downloaded. The previous
        # "Classification_*.json" wildcard removed templates the user had downloaded or authored earlier.
        $PreExistingTemplates = @()
        if (Test-Path -LiteralPath $ClassificationTemplates -ErrorAction SilentlyContinue) {
            $PreExistingTemplates = @(Get-ChildItem -LiteralPath $ClassificationTemplates -Filter "Classification_*.json" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name)
        }

        $Classifications = if ($RunConfig.AutomatedClassificationUpdate.Classifications) {
            $RunConfig.AutomatedClassificationUpdate.Classifications
        } else { $DefaultEntraOpsConfig.AutomatedClassificationUpdate.Classifications }
        Update-EntraOpsClassificationFiles `
            -FolderClassification $ClassificationTemplates `
            -Classifications $Classifications `
            -SkipExisting:$ReuseExistingTemplates

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

        # Always refresh tenant classifications and scope reasoning for selected systems, even when
        # local templates are reused. This also reapplies current tenant role action overwrites.
        $EffectiveClassificationScope = @($ClassificationParameterScope | Where-Object { $_ -in $RbacSystems })
        $ScopeUpdateParameters = @{}
        if ($HasConfiguration) {
            foreach ($Name in @('AzureHighPrivilegedRoles', 'AzureHighPrivilegedScopes', 'ExposureCriticalityLevel', 'PrivilegedObjectIds', 'DeviceMgmtPrivilegedTierScope', 'EntraOpsScopes')) {
                $Value = $RunConfig.AutomatedControlPlaneScopeUpdate.$Name
                if ($null -ne $Value) { $ScopeUpdateParameters[$Name] = $Value }
            }
        }
        if (-not $ScopeUpdateParameters.ContainsKey('EntraOpsScopes')) { $ScopeUpdateParameters.EntraOpsScopes = $RbacSystems }
        $ScopeUpdateParameters.PrivilegedObjectClassificationSource = $PrivilegedObjectClassificationSource
        $ScopeUpdateParameters.ClassificationParameterScope = $EffectiveClassificationScope

        if ($EffectiveClassificationScope.Count -eq 0) {
            Write-Host "       No classification files require generation for the selected scope." -ForegroundColor Gray
        } else {
            Write-Host "       Effective scope : $($EffectiveClassificationScope -join ', ')" -ForegroundColor Gray
            Update-EntraOpsClassificationControlPlaneScope @ScopeUpdateParameters
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
            Update-EntraOpsClassificationControlPlaneScope @ScopeUpdateParameters
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
