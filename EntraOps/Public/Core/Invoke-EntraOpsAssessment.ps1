<#
.SYNOPSIS
    Runs a complete EntraOps assessment of a tenant with one cmdlet: Privileged EAM classification, Tenant
    Governance snapshot, report data and finding results.

.DESCRIPTION
    Intended for a first assessment without an EntraOps repository or experience. The cmdlet

    1. prepares the EntraOps working folder ($EntraOpsBaseFolder): installs the reporting apps of the module
       version when they are missing, or updates apps of another version or without the Findings view
       (Install-EntraOpsReportingFolder),
    2. connects to Azure and Microsoft Graph (Connect-EntraOps, interactive sign-in by default),
    3. starts a Tenant Governance snapshot (Save-EntraOpsTenantGovernanceSnapshotJson) when the tenant meets
       its prerequisites (Test-EntraOpsTenantGovernancePrerequisite), or uses a recent one with
       -TenantGovernanceSnapshotMaxAgeInHours. Otherwise the snapshot is skipped with the next step to prepare
       the tenant; the cmdlet only changes the tenant to prepare it with -SetupTenantGovernance,
    4. classifies the privileged access (Invoke-EntraOpsPrivilegedEAM) while Microsoft Graph captures the
       snapshot. Unless -RbacSystems or the configuration file selects the RBAC systems, Azure RBAC is skipped
       when the account can't query Azure Resource Graph or read any Azure subscription; the other RBAC systems
       are classified,
    5. generates the report data and the finding results (New-EntraOpsReportingData). While the snapshot is
       still being captured, it first generates the reports that don't need it, then waits for the snapshot
       (in an interactive console, press S to stop waiting) and generates Configuration Analyzer, Access
       Package Flow and the findings. Like the reporting pipeline, Configuration Analyzer also analyzes a
       partially successful snapshot (status Partial: resource types with Microsoft Graph errors keep the files
       of the previous snapshot and are marked stale in the report), unless the configuration file sets
       ConfigurationAnalyzer.AllowPartialTenantGovernanceSnapshot to false, and
    6. shows a summary of the findings with the paths of the reports and of findings.json, which the EntraOps
       Maester Pack reads.

    With an interactive sign-in, the delegated permission ConfigurationMonitoring.ReadWrite.All (needed to
    create the snapshot) is only requested, with Microsoft Graph's consent prompt, when the tenant is otherwise
    ready for the snapshot.

    The configuration file that Connect-EntraOps uses (-ConfigFilePath, or the EntraOpsConfig.json it finds) is
    used by all steps, including the report generation and the findings.

    A working folder holds the data of one tenant. When its Tenant Governance snapshot belongs to another tenant,
    the snapshot is neither collected nor used: Configuration Analyzer, PIM Request Flow and Access Package Flow
    are skipped and their report data of the other tenant is removed. Use one working folder per tenant (-Path).

    The working folder needs no git repository: Privilege History and Configuration Analyzer show the current
    export and snapshot without history. Run the assessment from a clone of your EntraOps repository, or commit
    the results, to build up the history.

    The cmdlet disconnects at the end, unless -KeepConnection is used. With -AuthenticationType
    AlreadyAuthenticated the connections belong to the caller and stay as they are; only the EntraOps cache
    is cleared.

    Requirements:
    - PowerShell 7.4 or later. Missing Az and Microsoft Graph modules are installed by Connect-EntraOps.
    - A one-time admin consent to the Microsoft Graph permissions that EntraOps reads with (app 'Microsoft
      Graph Command Line Tools'): an administrator who can grant tenant-wide consent (for example Privileged
      Role Administrator or Cloud Application Administrator) signs in once and selects 'Consent on behalf of
      your organization'.
    - Read access to the tenant, for example Global Reader in Microsoft Entra ID, and Reader on the tenant root
      management group to include Azure RBAC.
    - For the Tenant Governance snapshot, a one-time setup by a Global Administrator or Privileged Role
      Administrator: -SetupTenantGovernance, or Register-EntraOpsTenantGovernanceServicePrincipal. Without it,
      the snapshot is skipped.

.PARAMETER TenantName
    Name of the tenant (e.g. contoso.onmicrosoft.com). Defaults to TenantName of the configuration file and,
    with -AuthenticationType AlreadyAuthenticated, to the default domain of the current Azure context.

.PARAMETER AuthenticationType
    UserInteractive (default) and DeviceAuthentication sign in interactively. AlreadyAuthenticated uses the
    current Azure and Microsoft Graph connections (Connect-AzAccount and Connect-MgGraph).

.PARAMETER ConfigFilePath
    Path to an EntraOps configuration file. Without it, EntraOpsConfig.json of the current folder or of the
    working folder is used when it belongs to the tenant (as Connect-EntraOps finds it), otherwise the defaults apply.

.PARAMETER Path
    EntraOps working folder for the assessment and for the rest of the session (sets $EntraOpsBaseFolder and
    ENTRAOPS_ROOT). Defaults to the current working folder ($EntraOpsBaseFolder).

.PARAMETER ContentRef
    Branch, release tag or commit of the EntraOps repository to install the reporting apps from (alias: -Ref).
    Without it, the reporting apps are installed or updated when they are missing or of another version than the
    module (Reports/.EntraOpsContent.json): from the repository checkout that contains the module, otherwise from
    the newest content of the main branch whose EntraOps.psd1 has the module version (branch head, release tag or
    commit). When no apps of the module
    version are available (for example an Insiders module newer than the main branch), existing apps are kept and
    missing apps are installed from the branch head with a warning.

.PARAMETER ContentRepository
    Repository of the reporting apps: 'EntraOps' (public) or 'EntraOps-Insiders' (private, needs ENTRAOPS_PAT).
    Defaults to AutomatedEntraOpsUpdate.Repository of the configuration file (the release channel of the
    deployment), otherwise 'EntraOps'. The default only applies when the apps are installed or updated; apps of the
    module version from another repository are kept. Use it with -ContentRef <branch> for an Insiders build.

.PARAMETER RbacSystems
    RBAC systems to classify, passed to Invoke-EntraOpsPrivilegedEAM. Defaults to its default or configuration.
    Without -RbacSystems and without RbacSystems in the configuration file, Azure is skipped when the account
    can't query Azure Resource Graph or read any Azure subscription. Pass -RbacSystems to classify exactly these
    systems; the run then fails when one of them can't be read.

.PARAMETER ExistingClassificationAction
    Passed to Invoke-EntraOpsPrivilegedEAM when tenant classification files of an earlier run exist: Reuse
    (default) keeps the local classification templates, Regenerate downloads the latest ones, Prompt asks.

.PARAMETER ControlPlaneScopeAction
    Passed to Invoke-EntraOpsPrivilegedEAM: Refresh (default) updates the Control Plane scope from the tenant,
    Reuse keeps the scope of an earlier run of this tenant (faster and comparable with that run, without the
    changes of the tenant since then), Prompt asks.

    Without -ExistingClassificationAction and -ControlPlaneScopeAction, an interactive run asks once after the
    sign-in, before the snapshot starts, when the working folder has a classification of an earlier run of the
    tenant: reuse templates and Control Plane scope (default when the scope is less than 24 hours old), reuse the
    templates and refresh the scope (default otherwise), or download the latest templates and refresh the scope.
    Unattended runs don't ask and use the defaults.

.PARAMETER SkipTenantGovernanceSnapshot
    Don't capture a Tenant Governance snapshot. The reports use an existing snapshot of the working folder;
    without one, Configuration Analyzer, PIM Request Flow and Access Package Flow and their findings are skipped.

.PARAMETER SetupTenantGovernance
    Prepares the tenant for the Tenant Governance snapshot when it isn't ready, and starts the snapshot in the
    same run. Needs an interactive sign-in (UserInteractive or DeviceAuthentication) of a Global Administrator
    or Privileged Role Administrator. The cmdlet requests the delegated permissions Application.ReadWrite.All,
    AppRoleAssignment.ReadWrite.All and ConfigurationMonitoring.ReadWrite.All in one consent prompt (consent for
    your account only, not on behalf of your organization), then runs
    Register-EntraOpsTenantGovernanceServicePrincipal: it creates Microsoft's first-party service principal
    'Microsoft Tenant Configuration Management' in the tenant and grants it the Microsoft Graph read permissions
    of the captured resource types. Without this switch, the cmdlet never changes the tenant.

.PARAMETER TenantGovernanceTimeoutInSeconds
    Maximum time to wait for the snapshot, counted from its start. Default is 900 (15 minutes). A snapshot
    that isn't complete by then stays pending: the next run of Invoke-EntraOpsAssessment collects it first.

.PARAMETER TenantGovernanceSnapshotMaxAgeInHours
    Uses the last captured snapshot of the working folder instead of starting a new one when it is younger
    than this number of hours, and skips the wait. Default is 0: always start a new snapshot. Configuration
    Analyzer accepts a snapshot of this age.

.PARAMETER OpenReport
    Opens the EntraOps reporting portal (Reports/index.html) at the end.

.PARAMETER KeepConnection
    Keeps the Azure and Microsoft Graph connections after the run instead of disconnecting.

.PARAMETER PassThru
    Returns the result of the assessment (steps, paths and the findings by status and severity). AzureRbac
    tells whether Azure RBAC was classified: Included, NotSelected or Skipped (with Reason and Next).
    TenantGovernanceSnapshot has the Status (Captured, Partial, Reused, Pending, Skipped or Failed), Reason, Next, and
    Setup (Done, Failed or NotPossible with -SetupTenantGovernance).

.EXAMPLE
    Invoke-EntraOpsAssessment -TenantName 'contoso.onmicrosoft.com'

    Signs in interactively, runs the complete assessment in the working folder and shows the findings.

.EXAMPLE
    Invoke-EntraOpsAssessment -TenantName 'contoso.onmicrosoft.com' -Path '~/EntraOps-Assessment' -OpenReport

    Runs the assessment in its own folder and opens the reports afterwards.

.EXAMPLE
    Invoke-EntraOpsAssessment -TenantName 'contoso.onmicrosoft.com' -SetupTenantGovernance

    As Global Administrator or Privileged Role Administrator: prepares the tenant for the Tenant Governance
    snapshot when it isn't ready, and runs the complete assessment including the snapshot.

.EXAMPLE
    Invoke-EntraOpsAssessment -TenantName 'contoso.onmicrosoft.com' -TenantGovernanceSnapshotMaxAgeInHours 24

    Runs the assessment again with the snapshot of the last run when it was captured within the last 24 hours,
    without waiting for a new one.

.EXAMPLE
    Connect-AzAccount -Identity; Connect-MgGraph -Identity -NoWelcome
    Invoke-EntraOpsAssessment -AuthenticationType AlreadyAuthenticated -SkipTenantGovernanceSnapshot

    Uses the current connections, here of a managed identity with the permissions of New-EntraOpsWorkloadIdentity,
    and skips the Tenant Governance snapshot. A delegated Connect-MgGraph session needs the scopes that
    Connect-EntraOps requests; sign in with Connect-EntraOps instead (the default UserInteractive).

.EXAMPLE
    Invoke-EntraOpsAssessment -TenantName 'contoso.onmicrosoft.com'
    Install-MtPack Cloud-Architekt/EntraOps-MaesterPack
    Invoke-Maester -Pack EOPS -SkipBuiltIn -SkipGraphConnect

    Runs the assessment and shows its findings in Maester. The pack reads Reports/Findings/data of the working
    folder (ENTRAOPS_ROOT, <home>/EntraOps or the current folder); for another folder, set EntraOps.FindingsPath
    in maester-config.json.
#>
function Invoke-EntraOpsAssessment {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [ValidatePattern('^$|^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$')]
        [System.String]$TenantName,

        [Parameter(Mandatory = $false)]
        [ValidateSet('UserInteractive', 'DeviceAuthentication', 'AlreadyAuthenticated')]
        [System.String]$AuthenticationType = 'UserInteractive',

        [Parameter(Mandatory = $false)]
        [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
        [System.String]$ConfigFilePath,

        [Parameter(Mandatory = $false)]
        [System.String]$Path,

        [Parameter(Mandatory = $false)]
        [Alias('Ref')]
        [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9._/-]{0,199}$')]
        [System.String]$ContentRef,

        [Parameter(Mandatory = $false)]
        [ValidateSet('EntraOps', 'EntraOps-Insiders')]
        [System.String]$ContentRepository = 'EntraOps',

        [Parameter(Mandatory = $false)]
        [ValidateSet('Azure', 'EntraID', 'IdentityGovernance', 'DeviceManagement', 'ResourceApps', 'Defender')]
        [Array]$RbacSystems,

        [Parameter(Mandatory = $false)]
        [ValidateSet('Prompt', 'Reuse', 'Regenerate')]
        [System.String]$ExistingClassificationAction = 'Reuse',

        [Parameter(Mandatory = $false)]
        [ValidateSet('Prompt', 'Refresh', 'Reuse')]
        [System.String]$ControlPlaneScopeAction = 'Refresh',

        [Parameter(Mandatory = $false)]
        [switch]$SkipTenantGovernanceSnapshot,

        [Parameter(Mandatory = $false)]
        [switch]$SetupTenantGovernance,

        [Parameter(Mandatory = $false)]
        [ValidateRange(60, 86400)]
        [System.Int32]$TenantGovernanceTimeoutInSeconds = 900,

        [Parameter(Mandatory = $false)]
        [ValidateRange(0, 8760)]
        [System.Int32]$TenantGovernanceSnapshotMaxAgeInHours = 0,

        [Parameter(Mandatory = $false)]
        [switch]$OpenReport,

        [Parameter(Mandatory = $false)]
        [switch]$KeepConnection,

        [Parameter(Mandatory = $false)]
        [switch]$PassThru
    )

    $ErrorActionPreference = 'Stop'
    $ProgressId = 4710
    $Activity = 'EntraOps assessment'
    $StepCount = 5
    $WriteStep = {
        param([int]$Number, [string]$Text)
        Write-Progress -Id $ProgressId -Activity $Activity -Status "Step $Number/$($StepCount): $Text" -PercentComplete ([math]::Round(($Number - 1) * 100 / $StepCount))
        Write-Host ''
        Write-Host "[$Number/$StepCount] $Text" -ForegroundColor Cyan
    }
    # mm:ss, or h:mm:ss from one hour on ({0:mm\:ss} alone restarts at 00:00 after an hour).
    $FormatDuration = {
        param([timespan]$Span)
        if ($Span.TotalHours -ge 1) { '{0}:{1:mm\:ss}' -f [math]::Floor($Span.TotalHours), $Span } else { '{0:mm\:ss}' -f $Span }
    }
    # The timeout is at least 60 seconds.
    $TimeoutText = "$([math]::Ceiling($TenantGovernanceTimeoutInSeconds / 60)) minutes"
    $StartTime = Get-Date

    #region 1. Working folder and reporting apps
    & $WriteStep 1 'Preparing the EntraOps working folder...'
    if (-not [string]::IsNullOrWhiteSpace($Path)) {
        $Path = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path).TrimEnd([char[]]@('/', '\'))
        if (-not (Test-Path -LiteralPath $Path -PathType Container)) {
            New-Item -Path $Path -ItemType Directory -Force | Out-Null
        }
        if ($Path -ne "$Global:EntraOpsBaseFolder".TrimEnd([char[]]@('/', '\'))) {
            # Cmdlets read $Global:EntraOpsBaseFolder at run time, like Initialize-EntraOpsWorkspace -Path.
            $Global:EntraOpsBaseFolder = $Path
            $env:ENTRAOPS_ROOT = $Path
        }
    }
    $WorkingFolder = "$Global:EntraOpsBaseFolder".TrimEnd([char[]]@('/', '\'))
    if ([string]::IsNullOrWhiteSpace($WorkingFolder)) {
        throw "The EntraOps working folder is not set. Pass -Path or import the module with 'Import-Module EntraOps -Force'."
    }
    Write-Host "  Working folder : $WorkingFolder"
    # The configuration of the run (passed, or found in the current or working folder) is read here: its
    # AutomatedEntraOpsUpdate.Repository selects the repository of the reporting apps.
    if ([string]::IsNullOrWhiteSpace($ConfigFilePath)) {
        $ConfigCandidates = @(
            Join-Path (Get-Location -PSProvider FileSystem).ProviderPath 'EntraOpsConfig.json'
            Join-Path $WorkingFolder 'EntraOpsConfig.json'
        ) | Select-Object -Unique
        $DetectedConfigPath = $ConfigCandidates | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } | Select-Object -First 1
    } else {
        $ConfigFilePath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($ConfigFilePath)
        $DetectedConfigPath = $ConfigFilePath
    }
    $Config = $null
    if ($DetectedConfigPath) {
        try {
            $Config = Get-Content -LiteralPath $DetectedConfigPath -Raw | ConvertFrom-Json -Depth 100
        } catch {
            if ($ConfigFilePath) { throw "EntraOps configuration file '$ConfigFilePath' is not valid JSON: $($_.Exception.Message)" }
            Write-Warning "$DetectedConfigPath is not valid JSON and is not used: $($_.Exception.Message)"
        }
    }
    $ReportingPortal = Join-Path $WorkingFolder 'Reports/index.html'
    # Reporting apps of another version than the module (or of an EntraOps version before the finding rules,
    # without the Findings view js/findings.js and without a content marker) are updated; Force keeps the generated
    # data (Reports/<App>/data). An explicit -ContentRef or -ContentRepository always installs that content.
    $ReportsFolder = Join-Path $WorkingFolder 'Reports'
    $ModuleVersion = Get-EntraOpsModuleVersion
    $ContentMarker = Get-EntraOpsContentMarker -Path $ReportsFolder
    $ExplicitContent = $PSBoundParameters.ContainsKey('ContentRef') -or $PSBoundParameters.ContainsKey('ContentRepository')
    $ReportsAction = if (-not (Test-Path -LiteralPath $ReportingPortal -PathType Leaf)) { 'installed' }
    elseif ($ExplicitContent) { 'updated' }
    elseif (-not (Test-Path -LiteralPath (Join-Path $ReportsFolder 'PrivilegedAssets/js/findings.js') -PathType Leaf)) { 'updated' }
    elseif ($ContentMarker -and $ModuleVersion -and "$($ContentMarker.ContentVersion)" -ne "$ModuleVersion") { 'updated' }
    if (-not $ReportsAction) {
        Write-Host "  Reporting apps : installed$(if ($ContentMarker.ContentVersion) { " (version $($ContentMarker.ContentVersion))" })"
    } else {
        # Without -ContentRepository, the apps follow the release channel of the deployment.
        if ($PSBoundParameters.ContainsKey('ContentRepository')) {
            $ContentRepositoryReason = '-ContentRepository'
        } else {
            # A configuration that is not valid JSON was reported above and is not read again.
            $SelectedRepository = if ($null -ne $Config) { Resolve-EntraOpsContentRepository -Config $Config -ConfigFilePath $DetectedConfigPath } else { Resolve-EntraOpsContentRepository }
            $ContentRepository = $SelectedRepository.Repository
            $ContentRepositoryReason = $SelectedRepository.Reason
        }
        Write-Host "  Content repo   : $ContentRepository ($ContentRepositoryReason)"
        $InstallParameters = @{ DestinationPath = $ReportsFolder; Repository = $ContentRepository; Force = ($ReportsAction -eq 'updated'); KeepExistingWithoutMatch = (-not $ExplicitContent) }
        if ($PSBoundParameters.ContainsKey('ContentRef')) { $InstallParameters.Ref = $ContentRef }
        try {
            # Its own lines are replaced by the line below.
            $Installed = Install-EntraOpsReportingFolder @InstallParameters 6>$null
            $SourceText = "$($Installed.Repository)$(if ($Installed.Ref) { " at '$($Installed.Ref)'" })"
            if ($Installed.InstalledFile -gt 0) {
                Write-Host "  Reporting apps : $ReportsAction$(if ($Installed.ContentVersion) { " (version $($Installed.ContentVersion))" }) from $SourceText" -ForegroundColor $(if ($Installed.Matched) { 'Gray' } else { 'Yellow' })
            } else {
                Write-Host "  Reporting apps : kept$(if ($ContentMarker.ContentVersion) { " (version $($ContentMarker.ContentVersion))" }), no apps of version $ModuleVersion available from $SourceText" -ForegroundColor Yellow
            }
        } catch {
            if ($ReportsAction -eq 'updated') {
                # The existing apps still work, only without the newest views.
                Write-Warning "The reporting apps could not be updated: $($_.Exception.Message) Update them later with Install-EntraOpsReportingFolder -Force."
            } else {
                throw
            }
        }
    }
    #endregion

    #region Tenant and configuration
    if ([string]::IsNullOrWhiteSpace($TenantName) -and -not [string]::IsNullOrWhiteSpace([string]$Config.TenantName)) {
        $TenantName = [string]$Config.TenantName
    }
    if ([string]::IsNullOrWhiteSpace($TenantName) -and $AuthenticationType -eq 'AlreadyAuthenticated') {
        $AzContext = Get-AzContext -ErrorAction SilentlyContinue
        if ($AzContext -and -not [string]::IsNullOrEmpty($AzContext.Tenant.Id)) {
            $AzTenant = Get-AzTenant -TenantId $AzContext.Tenant.Id -ErrorAction SilentlyContinue | Select-Object -First 1
            $TenantName = if ($AzTenant.DefaultDomain) { $AzTenant.DefaultDomain } else { @($AzTenant.Domains)[0] }
        }
    }
    if ([string]::IsNullOrWhiteSpace($TenantName)) {
        throw 'The tenant is unknown. Pass -TenantName, for example -TenantName contoso.onmicrosoft.com.'
    }
    #endregion

    $Connected = $false
    $ReportResults = @()
    $Snapshot = [ordered]@{ Status = 'Skipped'; Reason = $null; Next = $null; Setup = $null }
    # What the setup of the Tenant Governance snapshot does, shown in the summary when the tenant isn't ready.
    $SnapshotSetupInfo = $null
    $SnapshotOfEarlierRun = $false
    # The command that runs this assessment again, for example to collect a pending snapshot.
    $ReRunCommand = "Invoke-EntraOpsAssessment -TenantName '$TenantName'$(if ($PSBoundParameters.ContainsKey('Path')) { " -Path '$Path'" })"
    $AzureRbac = [ordered]@{ Status = 'Included'; Reason = $null; Next = $null }
    try {
        #region 2. Connect
        & $WriteStep 2 "Connecting to $TenantName..."
        # NoWelcome: its banner, cache details and reminder to disconnect don't apply, the assessment disconnects itself.
        $ConnectParameters = @{
            AuthenticationType = $AuthenticationType
            TenantName         = $TenantName
            NoWelcome          = $true
        }
        if ($ConfigFilePath) { $ConnectParameters.ConfigFilePath = $ConfigFilePath }
        try {
            $null = Connect-EntraOps @ConnectParameters
        } catch {
            # Without a tenant-wide consent, a first sign-in fails with "Need admin approval" or a declined consent.
            # Connect-EntraOps signs in to Azure first: a failed Microsoft Graph sign-in must not leave Azure connected.
            if ($AuthenticationType -ne 'AlreadyAuthenticated') {
                try { Disconnect-EntraOps -ClearEntraOpsCache All -ErrorAction SilentlyContinue | Out-Null } catch { Write-Verbose "Disconnect after the failed sign-in: $($_.Exception.Message)" }
            }
            if ("$($_.Exception.Message)" -match 'AADSTS(65001|65004|90094|90008)\b|admin approval|admin consent|consent_required|declined to consent') {
                throw [System.InvalidOperationException]::new(("The sign-in needs consent to the Microsoft Graph permissions that EntraOps reads with (app 'Microsoft Graph Command Line Tools'). " +
                        "An administrator who can grant tenant-wide consent (for example Privileged Role Administrator or Cloud Application Administrator) runs Invoke-EntraOpsAssessment or Connect-EntraOps once " +
                        "and selects 'Consent on behalf of your organization', or approves your admin consent request. Then run Invoke-EntraOpsAssessment again. Error: $($_.Exception.Message)"), $_.Exception)
            }
            throw
        }
        $Connected = $true
        # The configuration file Connect-EntraOps uses (passed or found): the report generation and the findings
        # read it explicitly, otherwise they would look for EntraOpsConfig.json in the working folder only.
        # Invoke-EntraOpsPrivilegedEAM uses the configuration and the folders of the connection without it.
        $SessionConfigFilePath = $__EntraOpsSession['ConfigFilePath']
        $ConnectedTenantId = if (-not [string]::IsNullOrWhiteSpace($Global:TenantIdContext)) { [string]$Global:TenantIdContext } else { [string](Get-MgContext -ErrorAction SilentlyContinue).TenantId }
        $SignedInAccount = [string](Get-AzContext -ErrorAction SilentlyContinue).Account.Id
        if ([string]::IsNullOrWhiteSpace($SignedInAccount)) { $SignedInAccount = [string](Get-MgContext -ErrorAction SilentlyContinue).Account }
        if (-not [string]::IsNullOrWhiteSpace($SignedInAccount)) { Write-Host "  Account        : $SignedInAccount" }
        Write-Host "  Tenant         : $TenantName$(if ($ConnectedTenantId) { " ($ConnectedTenantId)" })"
        Write-Host "  Config file    : $(if ($SessionConfigFilePath) { $SessionConfigFilePath } else { 'none, defaults apply' })"
        # The report generation reads EntraOpsConfig.json of the working folder on its own (tenant name, settings of
        # the reports and findings): a file that is not valid, or of another tenant, would end up in this tenant's reports.
        $WorkingFolderConfigPath = Join-Path $WorkingFolder 'EntraOpsConfig.json'
        if ((Test-Path -LiteralPath $WorkingFolderConfigPath -PathType Leaf) -and $WorkingFolderConfigPath -ne $SessionConfigFilePath) {
            $WorkingFolderConfig = try { Get-Content -LiteralPath $WorkingFolderConfigPath -Raw | ConvertFrom-Json -Depth 100 } catch {
                throw "$WorkingFolderConfigPath is not valid JSON: $($_.Exception.Message) Fix or remove the file, or use another working folder (-Path)."
            }
            $ConfigTenantName = [string]$WorkingFolderConfig.TenantName
            $ConfigTenantId = [string]$WorkingFolderConfig.TenantId
            $SameTenant = if (-not [string]::IsNullOrWhiteSpace($ConfigTenantId) -and -not [string]::IsNullOrWhiteSpace($ConnectedTenantId)) { $ConfigTenantId -eq $ConnectedTenantId } else { [string]::IsNullOrWhiteSpace($ConfigTenantName) -or $ConfigTenantName -eq $TenantName }
            if (-not $SameTenant) {
                throw "The working folder $WorkingFolder holds the configuration of another tenant ($(if ($ConfigTenantName) { $ConfigTenantName } else { $ConfigTenantId })). A working folder holds one tenant: run Invoke-EntraOpsAssessment -TenantName '$TenantName' -Path <a folder for this tenant>."
            }
        }

        # Without a configured ClassificationParameterScope: the defaults of Invoke-EntraOpsPrivilegedEAM plus Identity
        # Governance, so access package catalogs are tiered by their resources instead of falling back to the template.
        $DefaultClassificationScope = @('EntraID', 'DeviceManagement', 'Azure', 'IdentityGovernance')

        # Classification of an earlier run: asked once here, so the rest of the run needs no input.
        $ClassificationChoiceMade = $PSBoundParameters.ContainsKey('ExistingClassificationAction') -or $PSBoundParameters.ContainsKey('ControlPlaneScopeAction')
        $CanAsk = Test-EntraOpsInteractiveHost
        $TenantClassificationFolder = Join-Path $WorkingFolder "Classification/$TenantName"
        if (-not $ClassificationChoiceMade -and $CanAsk -and @(Get-ChildItem -LiteralPath $TenantClassificationFolder -Filter 'Classification_*.json' -File -ErrorAction SilentlyContinue).Count -gt 0) {
            $ScopeSystems = @($Global:EntraOpsConfig.AutomatedControlPlaneScopeUpdate.ClassificationParameterScope | Where-Object { $_ })
            if ($ScopeSystems.Count -eq 0) { $ScopeSystems = $DefaultClassificationScope }
            $EarlierScope = Get-EntraOpsReusableControlPlaneScope -ClassificationTenantFolder $TenantClassificationFolder -ClassificationParameterScope $ScopeSystems
            Write-Host ''
            Write-Host "  Classification of an earlier run of $TenantName found in $TenantClassificationFolder$(if ($EarlierScope.Reusable) { " (Control Plane scope updated $($EarlierScope.UpdatedAt.ToString('u')), $($EarlierScope.AgeInHours) hour(s) ago)" })." -ForegroundColor Yellow
            $Choices = [ordered]@{}
            if ($EarlierScope.Reusable) { $Choices['U'] = 'Reuse the templates and the Control Plane scope (faster, comparable with that run, without changes of the tenant since then)' }
            $Choices['F'] = 'Reuse the templates and refresh the Control Plane scope from the tenant'
            $Choices['G'] = 'Download the latest templates and refresh the Control Plane scope'
            $DefaultChoice = if ($EarlierScope.Reusable -and $EarlierScope.AgeInHours -lt 24) { 'U' } else { 'F' }
            foreach ($Key in $Choices.Keys) { Write-Host "    [$Key] $($Choices[$Key])$(if ($Key -eq $DefaultChoice) { ' (default)' })" -ForegroundColor Gray }
            do {
                $Answer = try { ([string](Read-Host "  Choose $(@($Choices.Keys) -join '/') (Enter: $DefaultChoice)")).Trim().ToUpperInvariant() } catch { $DefaultChoice }
                if ([string]::IsNullOrWhiteSpace($Answer)) { $Answer = $DefaultChoice }
                if (-not $Choices.Contains($Answer)) { Write-Host "  Enter $(@($Choices.Keys) -join ', ')." -ForegroundColor Yellow }
            } until ($Choices.Contains($Answer))
            $ExistingClassificationAction = if ($Answer -eq 'G') { 'Regenerate' } else { 'Reuse' }
            $ControlPlaneScopeAction = if ($Answer -eq 'U') { 'Reuse' } else { 'Refresh' }
        } elseif ($ExistingClassificationAction -eq 'Prompt' -or $ControlPlaneScopeAction -eq 'Prompt') {
            if (-not $CanAsk) {
                # Unattended: Invoke-EntraOpsPrivilegedEAM can't ask either.
                if ($ExistingClassificationAction -eq 'Prompt') { $ExistingClassificationAction = 'Reuse' }
                if ($ControlPlaneScopeAction -eq 'Prompt') { $ControlPlaneScopeAction = 'Refresh' }
            }
        }
        #endregion

        #region 3. Start the Tenant Governance snapshot
        & $WriteStep 3 'Starting the Tenant Governance snapshot...'
        $SnapshotFolder = Join-Path $WorkingFolder 'TenantGovernance/Snapshots'
        $PendingJobFile = Join-Path $SnapshotFolder '.PendingSnapshotJob.json'
        # A shared working folder (for example <home>/EntraOps) can hold the snapshot or the pending job of another tenant.
        $ManifestFile = Join-Path $SnapshotFolder '.SnapshotManifest.json'
        $OtherTenant = $null
        foreach ($StateFile in @($ManifestFile, $PendingJobFile)) {
            if ($OtherTenant -or -not (Test-Path -LiteralPath $StateFile -PathType Leaf)) { continue }
            $State = try { Get-Content -LiteralPath $StateFile -Raw | ConvertFrom-Json } catch { $null }
            # Snapshots of EntraOps before 1.2.0 (and unreadable state files) don't record their tenant: they are used
            # as this tenant's, with a warning, as the working folder may be shared with another tenant.
            if ([string]::IsNullOrWhiteSpace([string]$State.TenantId)) {
                Write-Warning "$(Split-Path -Leaf $StateFile) in $SnapshotFolder records no tenant (written by EntraOps before 1.2.0 or unreadable), so EntraOps cannot check that it belongs to tenant $ConnectedTenantId. If the folder belongs to another tenant, use -Path with a folder for this tenant."
            }
            if (-not [string]::IsNullOrWhiteSpace([string]$State.TenantId) -and -not [string]::IsNullOrWhiteSpace($ConnectedTenantId) -and [string]$State.TenantId -ne $ConnectedTenantId) {
                $OtherTenant = if (-not [string]::IsNullOrWhiteSpace([string]$State.TenantName)) { "$($State.TenantName) ($($State.TenantId))" } else { [string]$State.TenantId }
            }
        }
        # With -TenantGovernanceSnapshotMaxAgeInHours: the age of the last captured snapshot of this tenant.
        $RecentSnapshotAge = $null
        if ($TenantGovernanceSnapshotMaxAgeInHours -gt 0 -and -not $OtherTenant -and (Test-Path -LiteralPath $ManifestFile -PathType Leaf)) {
            $Manifest = try { Get-Content -LiteralPath $ManifestFile -Raw | ConvertFrom-Json } catch { $null }
            # ConvertFrom-Json turns ISO 8601 dates into DateTime values.
            $CapturedValue = $Manifest.CapturedDateTime
            $CapturedAt = [datetimeoffset]::MinValue
            $HasCapturedAt = if ($CapturedValue -is [datetime]) {
                $CapturedAt = [datetimeoffset]$CapturedValue.ToUniversalTime(); $true
            } else {
                [datetimeoffset]::TryParse([string]$CapturedValue, [cultureinfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AssumeUniversal, [ref]$CapturedAt)
            }
            if ($HasCapturedAt -and [string]$Manifest.TenantId -eq $ConnectedTenantId) {
                $Age = [datetimeoffset]::UtcNow - $CapturedAt
                if ($Age.TotalHours -ge 0 -and $Age.TotalHours -lt $TenantGovernanceSnapshotMaxAgeInHours) { $RecentSnapshotAge = $Age }
            }
        }
        if ($OtherTenant) {
            $Snapshot.Reason = "the snapshot in the working folder belongs to tenant $OtherTenant"
            $Snapshot.Next = "Invoke-EntraOpsAssessment -TenantName '$TenantName' -Path <a folder for this tenant>"
            Write-Warning ("The Tenant Governance snapshot in $SnapshotFolder belongs to tenant $OtherTenant, not to $TenantName. It is neither collected nor used: " +
                'Configuration Analyzer, PIM Request Flow and Access Package Flow are skipped and their report data of the other tenant is removed. Use one working folder per tenant (-Path).')
        } elseif ($SkipTenantGovernanceSnapshot) {
            $Snapshot.Reason = 'with -SkipTenantGovernanceSnapshot'
            Write-Host '  Skipped with -SkipTenantGovernanceSnapshot.'
        } elseif (Test-Path -LiteralPath $PendingJobFile -PathType Leaf) {
            # A snapshot started earlier (for example by a scheduled run) is collected instead of starting another one.
            $Snapshot.Status = 'Started'
            $SnapshotOfEarlierRun = $true
            Write-Host '  A snapshot job of an earlier run is pending: collecting it after the classification.'
        } elseif ($null -ne $RecentSnapshotAge) {
            $Snapshot.Status = 'Reused'
            $Snapshot.Reason = "captured $([math]::Round($RecentSnapshotAge.TotalHours, 1)) hour(s) ago"
            Write-Host "  Using the snapshot $($Snapshot.Reason) (-TenantGovernanceSnapshotMaxAgeInHours $TenantGovernanceSnapshotMaxAgeInHours)."
        } else {
            $SnapshotResources = @($Global:EntraOpsConfig.TenantGovernanceSnapshot.ResourcesToInclude | Where-Object { $_ })
            $PrerequisiteParameters = @{}
            if ($SnapshotResources.Count -gt 0) { $PrerequisiteParameters.ResourcesToInclude = $SnapshotResources }
            $Prerequisite = Test-EntraOpsTenantGovernancePrerequisite @PrerequisiteParameters
            $MgContext = Get-MgContext -ErrorAction SilentlyContinue

            # The service principal is missing or lacks permissions: only -SetupTenantGovernance changes the tenant.
            $SetupNeeded = -not $Prerequisite.IsReady -and (@($Prerequisite.MissingUtcmPermissions | Where-Object { $_ }).Count -gt 0 -or
                (-not $Prerequisite.UtcmServicePrincipalExists -and [string]::IsNullOrWhiteSpace([string]$Prerequisite.PermissionCheckSkippedReason)))
            if ($SetupTenantGovernance -and $SetupNeeded) {
                if ($AuthenticationType -eq 'AlreadyAuthenticated' -or -not $MgContext -or $MgContext.AuthType -eq 'AppOnly') {
                    $Snapshot.Setup = 'NotPossible'
                    Write-Warning '-SetupTenantGovernance needs an interactive sign-in (-AuthenticationType UserInteractive or DeviceAuthentication). Prepare the tenant with Register-EntraOpsTenantGovernanceServicePrincipal instead.'
                } else {
                    Write-Host '  Setting up the Tenant Governance snapshot (-SetupTenantGovernance).'
                    Write-Host '  Consent to Application.ReadWrite.All, AppRoleAssignment.ReadWrite.All and ConfigurationMonitoring.ReadWrite.All for your account (not on behalf of your organization)...'
                    $SetupConsentParameters = @{
                        TenantId     = $MgContext.TenantId
                        Scopes       = @(@($MgContext.Scopes) + 'Application.ReadWrite.All' + 'AppRoleAssignment.ReadWrite.All' + 'ConfigurationMonitoring.ReadWrite.All' | Where-Object { $_ } | Select-Object -Unique)
                        NoWelcome    = $true
                        ContextScope = 'Process'
                        ErrorAction  = 'Stop'
                    }
                    if ($AuthenticationType -eq 'DeviceAuthentication') { $SetupConsentParameters.UseDeviceAuthentication = $true }
                    try {
                        Connect-MgGraph @SetupConsentParameters | Out-Null
                        $RegisterParameters = @{ TenantId = $MgContext.TenantId }
                        if ($SnapshotResources.Count -gt 0) { $RegisterParameters.ResourcesToInclude = $SnapshotResources }
                        # Its status lines are shown, its result object isn't part of the output.
                        Register-EntraOpsTenantGovernanceServicePrincipal @RegisterParameters | ForEach-Object { if ($_ -is [string]) { Write-Host "  $_" } }
                        $Prerequisite = Test-EntraOpsTenantGovernancePrerequisite @PrerequisiteParameters
                        $MgContext = Get-MgContext -ErrorAction SilentlyContinue
                        $Snapshot.Setup = 'Done'
                        Write-Host '  Tenant Governance setup done. Permissions granted just now can take a few minutes to apply.' -ForegroundColor Green
                    } catch {
                        $Snapshot.Setup = 'Failed'
                        Write-Warning "The Tenant Governance setup failed: $($_.Exception.Message) It needs a Global Administrator or Privileged Role Administrator."
                        if (-not (Get-MgContext -ErrorAction SilentlyContinue)) {
                            throw 'The Microsoft Graph connection was lost during the Tenant Governance setup. Run Invoke-EntraOpsAssessment again, with -SkipTenantGovernanceSnapshot to skip the snapshot.'
                        }
                    }
                }
            }

            # Only the delegated permission is missing: request it with Microsoft Graph's (incremental) consent.
            $OnlyPermissionMissing = -not $Prerequisite.IsReady -and -not $Prerequisite.HasConfigurationMonitoringPermission -and
            $Prerequisite.UtcmServicePrincipalExists -and @($Prerequisite.MissingUtcmPermissions).Count -eq 0
            $ConsentResult = $null
            if ($OnlyPermissionMissing -and $AuthenticationType -ne 'AlreadyAuthenticated' -and $MgContext) {
                Write-Host '  Requesting the delegated permission ConfigurationMonitoring.ReadWrite.All to create the snapshot...'
                $ConsentParameters = @{
                    TenantId    = $MgContext.TenantId
                    Scopes      = @(@($MgContext.Scopes) + 'ConfigurationMonitoring.ReadWrite.All' | Where-Object { $_ } | Select-Object -Unique)
                    NoWelcome    = $true
                    ContextScope = 'Process'
                    ErrorAction = 'Stop'
                }
                if ($AuthenticationType -eq 'DeviceAuthentication') { $ConsentParameters.UseDeviceAuthentication = $true }
                try {
                    Connect-MgGraph @ConsentParameters | Out-Null
                    $Prerequisite = Test-EntraOpsTenantGovernancePrerequisite @PrerequisiteParameters
                    $ConsentResult = 'Granted'
                } catch {
                    $ConsentResult = 'Declined'
                    Write-Verbose "ConfigurationMonitoring.ReadWrite.All was not granted: $($_.Exception.Message)"
                    if (-not (Get-MgContext -ErrorAction SilentlyContinue)) {
                        throw 'The Microsoft Graph connection was lost while requesting ConfigurationMonitoring.ReadWrite.All. Run Invoke-EntraOpsAssessment again, with -SkipTenantGovernanceSnapshot to skip the snapshot.'
                    }
                }
            }

            if ($Prerequisite.IsReady) {
                try {
                    # Its own console lines are replaced by the lines below, which say that the run doesn't wait here.
                    $StartedJob = @(Save-EntraOpsTenantGovernanceSnapshotJson -ExportFolder $SnapshotFolder -Operation Start -SkipPrerequisiteCheck 6>$null) |
                        Where-Object { $_ -isnot [string] } | Select-Object -Last 1
                    $Snapshot.Status = 'Started'
                    $ResourceTypeCount = @($StartedJob.ResourcesToInclude | Where-Object { $_ }).Count
                    Write-Host "  Snapshot job $(if ($StartedJob.SnapshotJobId) { "$($StartedJob.SnapshotJobId) " })started: Microsoft Graph captures $(if ($ResourceTypeCount) { "$ResourceTypeCount resource types of " })the tenant configuration in the background." -ForegroundColor Green
                    Write-Host '  Capturing can take a while. The run goes on meanwhile: the classification (step 4) and the reports that' -ForegroundColor Gray
                    Write-Host "  don't need the snapshot come first, then step 5 waits for it (at most $TimeoutText from now)." -ForegroundColor Gray
                } catch {
                    $Snapshot.Status = 'Failed'
                    $Snapshot.Reason = $_.Exception.Message
                    Write-Warning "The Tenant Governance snapshot could not be started: $($Snapshot.Reason)"
                }
            } else {
                # One status and one next step for the missing prerequisite, instead of every advice of the check.
                $GraphTenant = if ($MgContext.TenantId) { $MgContext.TenantId } else { $ConnectedTenantId }
                $UtcmServicePrincipalMissing = -not $Prerequisite.UtcmServicePrincipalExists -and [string]::IsNullOrWhiteSpace([string]$Prerequisite.PermissionCheckSkippedReason)
                $MissingUtcmPermissionCount = @($Prerequisite.MissingUtcmPermissions | Where-Object { $_ }).Count
                $ReRun = 'then run Invoke-EntraOpsAssessment again'
                if ($UtcmServicePrincipalMissing -or $MissingUtcmPermissionCount -gt 0) {
                    $Snapshot.Reason = if ($UtcmServicePrincipalMissing) { 'the tenant has no Microsoft Tenant Configuration Management service principal' } else { "the Microsoft Tenant Configuration Management service principal lacks $MissingUtcmPermissionCount read permission(s)" }
                    $Snapshot.Next = "as Global Administrator or Privileged Role Administrator, $ReRunCommand -SetupTenantGovernance (or Register-EntraOpsTenantGovernanceServicePrincipal$(if ($GraphTenant) { " -TenantId $GraphTenant" }), $ReRun)"
                    # What the setup changes, so an administrator can decide before running it.
                    $GrantCount = if ($UtcmServicePrincipalMissing) {
                        $ResourceDefinition = Get-EntraOpsTenantGovernanceResourceDefinition
                        $Resources = if ($SnapshotResources.Count -gt 0) { $SnapshotResources } else { $ResourceDefinition.DefaultResources }
                        @($Resources | ForEach-Object { $ResourceDefinition.ResourcePermissions[$_] } | Where-Object { $_ } | Sort-Object -Unique).Count
                    } else { $MissingUtcmPermissionCount }
                    $SnapshotSetupInfo = @(
                        "The setup $(if ($UtcmServicePrincipalMissing) { "creates Microsoft's service principal 'Microsoft Tenant Configuration Management' and grants it" } else { 'grants the service principal' }) $GrantCount Microsoft Graph read permission(s)"
                        'for the captured resource types; your sign-in gets ConfigurationMonitoring.ReadWrite.All to start snapshots.'
                    )
                } elseif (-not $Prerequisite.UtcmServicePrincipalExists -and -not [string]::IsNullOrWhiteSpace([string]$Prerequisite.PermissionCheckSkippedReason)) {
                    # The lookup failed (permission, throttling, network): no consent can help, the state is unknown.
                    $Snapshot.Reason = 'the Microsoft Tenant Configuration Management service principal could not be checked'
                    $Snapshot.Next = "Test-EntraOpsTenantGovernancePrerequisite -Verbose (shows the error), $ReRun"
                    Write-Verbose $Prerequisite.PermissionCheckSkippedReason
                } elseif (-not $Prerequisite.HasConfigurationMonitoringPermission) {
                    if ($MgContext.AuthType -eq 'AppOnly' -or [bool]$__EntraOpsSession['UseInvokeRestMethodOnly']) {
                        $Snapshot.Reason = 'the application lacks the Microsoft Graph permission ConfigurationMonitoring.ReadWrite.All'
                        $Snapshot.Next = "Register-EntraOpsTenantGovernanceServicePrincipal -GrantConfigurationMonitoringReadWrite (or New-EntraOpsWorkloadIdentity), $ReRun"
                    } elseif ($AuthenticationType -eq 'AlreadyAuthenticated') {
                        $Snapshot.Reason = 'the Microsoft Graph connection lacks the delegated permission ConfigurationMonitoring.ReadWrite.All'
                        $Snapshot.Next = "Connect-MgGraph$(if ($GraphTenant) { " -TenantId $GraphTenant" }) -Scopes ConfigurationMonitoring.ReadWrite.All, $ReRun"
                    } elseif ($ConsentResult -eq 'Declined') {
                        $Snapshot.Reason = 'the consent to ConfigurationMonitoring.ReadWrite.All was declined or not possible'
                        $Snapshot.Next = 'Invoke-EntraOpsAssessment again and accept the consent prompt (an administrator may have to consent)'
                    } else {
                        $Snapshot.Reason = 'the sign-in has no consent to ConfigurationMonitoring.ReadWrite.All'
                        $Snapshot.Next = 'Invoke-EntraOpsAssessment again and accept the consent prompt (an administrator may have to consent)'
                    }
                } else {
                    $Snapshot.Reason = "the prerequisites are not met: $(@($Prerequisite.Issues)[0])"
                    $Snapshot.Next = "Test-EntraOpsTenantGovernancePrerequisite, $ReRun"
                }
                foreach ($Issue in @($Prerequisite.Issues)) { Write-Verbose "Tenant Governance prerequisite: $Issue" }
                Write-Warning "The Tenant Governance snapshot is skipped: $($Snapshot.Reason). Without it, Configuration Analyzer, PIM Request Flow and Access Package Flow and their findings are skipped. Next: $($Snapshot.Next)."
            }
        }
        # For a job of an earlier run: the start of the wait in this run.
        $SnapshotStartedAt = Get-Date
        #endregion

        #region 4. Privileged EAM, then collect the snapshot
        & $WriteStep 4 'Classifying the privileged access (Privileged EAM)...'
        $EamParameters = @{
            KeepConnection               = $true
            KeepClassificationFiles      = $true
            ExistingClassificationAction = $ExistingClassificationAction
            ControlPlaneScopeAction      = $ControlPlaneScopeAction
        }
        $ConfiguredRbacSystems = @($Global:EntraOpsConfig.RbacSystems | Where-Object { $_ })
        if ($PSBoundParameters.ContainsKey('RbacSystems')) {
            $EamParameters.RbacSystems = $RbacSystems
            if ($RbacSystems -notcontains 'Azure') { $AzureRbac.Status = 'NotSelected' }
        } elseif ($ConfiguredRbacSystems.Count -gt 0) {
            if ($ConfiguredRbacSystems -notcontains 'Azure') { $AzureRbac.Status = 'NotSelected' }
        } else {
            # The Azure classification and the Control Plane scope query Azure Resource Graph with -ThrowOnFailure
            # (a partial result would narrow the scope), so an account without Azure access would stop the whole run.
            # Systems selected explicitly (-RbacSystems, configuration file) keep failing loudly.
            try {
                $VisibleSubscriptions = @(Invoke-EntraOpsAzGraphQuery -KqlQuery "resourcecontainers | where type == 'microsoft.resources/subscriptions' | project subscriptionId | take 1" -ThrowOnFailure)
                if ($VisibleSubscriptions.Count -eq 0) {
                    # Role assignments at the tenant root need elevated access, which sees every subscription.
                    $AzureRbac.Status = 'Skipped'
                    $AzureRbac.Reason = "the account can't read any Azure subscription"
                }
            } catch {
                $AzureRbac.Status = 'Skipped'
                $AzureRbac.Reason = "Azure Resource Graph is not accessible: $($_.Exception.Message)"
            }
            if ($AzureRbac.Status -eq 'Skipped') {
                $AzureRbac.Next = 'grant the account Reader on the tenant root management group, then run Invoke-EntraOpsAssessment again'
                $ScopeConfig = $Global:EntraOpsConfig.AutomatedControlPlaneScopeUpdate
                # The defaults of Invoke-EntraOpsPrivilegedEAM without the parts that read Azure Resource Graph.
                $EamParameters.RbacSystems = @('EntraID', 'IdentityGovernance', 'DeviceManagement', 'ResourceApps')
                $Sources = @(if ($ScopeConfig.PrivilegedObjectClassificationSource) { $ScopeConfig.PrivilegedObjectClassificationSource } else { 'All' })
                if ($Sources -contains 'All') { $Sources = @('EntraOps', 'PrivilegedObjectIds', 'PrivilegedEdgesFromExposureManagement') }
                $Sources = @($Sources | Where-Object { $_ -ne 'PrivilegedRolesFromAzGraph' })
                $EamParameters.PrivilegedObjectClassificationSource = if ($Sources.Count -gt 0) { $Sources } else { @('EntraOps') }
                # Azure, Defender and IdentityGovernance derive their scope from Azure Resource Graph.
                $ClassificationScope = @(if ($null -ne $ScopeConfig.ClassificationParameterScope) { $ScopeConfig.ClassificationParameterScope } else { $DefaultClassificationScope })
                $EamParameters.ClassificationParameterScope = @($ClassificationScope | Where-Object { $_ -notin @('Azure', 'Defender', 'IdentityGovernance') })
                Write-Host "  Azure RBAC is skipped: $($AzureRbac.Reason). The other RBAC systems are classified." -ForegroundColor Yellow
            } elseif ($null -eq $Global:EntraOpsConfig.AutomatedControlPlaneScopeUpdate.ClassificationParameterScope) {
                $EamParameters.ClassificationParameterScope = $DefaultClassificationScope
            }
        }
        $null = Invoke-EntraOpsPrivilegedEAM @EamParameters

        # Like the reporting pipeline: a partially successful snapshot is analyzed (its stale resource types are
        # marked in the report) unless the configuration file sets this to false.
        $AllowPartialSnapshot = $Global:EntraOpsConfig.ConfigurationAnalyzer.AllowPartialTenantGovernanceSnapshot -ne $false
        # Saves the snapshot when Microsoft Graph has captured it; $true when it is captured.
        $CollectSnapshot = {
            $null = Save-EntraOpsTenantGovernanceSnapshotJson -ExportFolder $SnapshotFolder -Operation Collect -SkipPrerequisiteCheck
            if (Test-Path -LiteralPath $PendingJobFile -PathType Leaf) { return $false }
            $Manifest = Get-Content -LiteralPath $ManifestFile -Raw -ErrorAction SilentlyContinue | ConvertFrom-Json -ErrorAction SilentlyContinue
            $Snapshot.Status = 'Captured'
            $Snapshot.Reason = "$(if ($null -ne $Manifest.CapturedResourceCount) { "$($Manifest.CapturedResourceCount) resource(s) captured" } else { 'captured' })$(if (-not $SnapshotOfEarlierRun) { " in $(& $FormatDuration ((Get-Date) - $SnapshotStartedAt))" })"
            if ($Manifest.IsComplete -eq $false) {
                # partiallySuccessful: resource types with Microsoft Graph errors keep the files of the previous snapshot.
                $Snapshot.Status = 'Partial'
                $StaleCount = @($Manifest.StaleResourceTypes | Where-Object { $_ }).Count
                $WithErrorsCount = @($Manifest.PublishedWithErrorsResourceTypes | Where-Object { $_ }).Count
                $Snapshot.Reason += if ($StaleCount -gt 0) {
                    ", $StaleCount resource type(s) kept from the previous snapshot because of Microsoft Graph errors"
                } elseif ($WithErrorsCount -gt 0) {
                    $RetainedTotal = [int](@($Manifest.ResourceTypeStates | ForEach-Object { [int]$_.RetainedResourceCount }) | Measure-Object -Sum).Sum
                    if ($RetainedTotal -gt 0) {
                        ", resources of $WithErrorsCount resource type(s) could not be exported and are kept from the previous snapshot"
                    } else {
                        ", $WithErrorsCount resource type(s) with references that Microsoft Graph could not resolve"
                    }
                } else {
                    ', Microsoft Graph reported errors'
                }
                if (-not $AllowPartialSnapshot) {
                    $Snapshot.Reason += '; Configuration Analyzer is skipped (ConfigurationAnalyzer.AllowPartialTenantGovernanceSnapshot is false)'
                }
                $Snapshot.Next = "Get-EntraOpsTenantGovernanceSnapshotReport$(if ($Manifest.SnapshotId) { " -SnapshotJobId $($Manifest.SnapshotId)" }) lists the errors"
            }
            Write-Host "  Tenant Governance snapshot: $($Snapshot.Reason)." -ForegroundColor $(if ($Snapshot.Status -eq 'Partial') { 'Yellow' } else { 'Green' })
            $true
        }
        if ($Snapshot.Status -eq 'Started') {
            # The snapshot can be complete by the end of the classification.
            try {
                if (-not (& $CollectSnapshot)) {
                    $PendingStatus = try { (Get-Content -LiteralPath $PendingJobFile -Raw | ConvertFrom-Json).LastKnownStatus } catch { $null }
                    Write-Host "  Tenant Governance snapshot: still being captured$(if ($PendingStatus) { " (status $PendingStatus)" })$(if (-not $SnapshotOfEarlierRun) { ", $(& $FormatDuration ((Get-Date) - $SnapshotStartedAt)) since its start" })." -ForegroundColor Gray
                }
            } catch {
                $Snapshot.Status = 'Failed'
                $Snapshot.Reason = $_.Exception.Message
                Write-Warning "The Tenant Governance snapshot failed: $($Snapshot.Reason)"
            }
        }
        #endregion

        #region 5. Report data and findings
        & $WriteStep 5 'Generating the report data and the findings...'
        $ReportingParameters = @{
            EntraOpsRoot                  = $WorkingFolder
            InstallMissingReportingFolder = $true
            FailureAction                 = 'Continue'
            PassThru                      = $true
            AllowPartialTenantGovernanceSnapshot = $AllowPartialSnapshot
        }
        if ($SessionConfigFilePath) { $ReportingParameters.ConfigFilePath = $SessionConfigFilePath }
        if ($OtherTenant) {
            # The report data of these apps would still show the other tenant; the snapshot itself is kept.
            $ReportingParameters.SkipConfigurationAnalyzer = $true
            $ReportingParameters.SkipAccessPackageFlow = $true
            Remove-EntraOpsReportingData -EntraOpsRoot $WorkingFolder -SkipClassificationExplorer -SkipTierBreachAnalyzer -SkipEamDashboard -SkipPrivilegedAssets -SkipPrivilegeHistory -SkipAccessPathMap -SkipFindings -Confirm:$false 6>$null | Out-Null
        }
        if ($Snapshot.Status -eq 'Reused') {
            # Configuration Analyzer rejects a snapshot older than its limit (30 hours by default).
            $SnapshotAgeLimit = Resolve-EntraOpsTenantGovernanceSnapshotMaxAge -Config $Global:EntraOpsConfig
            if ($TenantGovernanceSnapshotMaxAgeInHours -gt $SnapshotAgeLimit) { $ReportingParameters.ConfigurationAnalyzerMaxSnapshotAgeHours = $TenantGovernanceSnapshotMaxAgeInHours }
        }

        if ($Snapshot.Status -ne 'Started') {
            $ReportResults = @(New-EntraOpsReportingData @ReportingParameters)
        } else {
            # While Microsoft Graph captures the snapshot: the reports that don't read it.
            Write-Host '  The Tenant Governance snapshot is still being captured: generating the reports that do not need it first.'
            $WithoutSnapshot = $ReportingParameters.Clone()
            foreach ($Name in 'SkipConfigurationAnalyzer', 'SkipAccessPackageFlow', 'SkipFindings') { $WithoutSnapshot[$Name] = $true }
            $ReportResults = @(New-EntraOpsReportingData @WithoutSnapshot)

            Write-Host ''
            Write-Host "  Waiting for the Tenant Governance snapshot (at most $TimeoutText from its start)..." -ForegroundColor Cyan
            # $null: the console can't report key presses (for example in a pipeline). The first call discards earlier keys.
            $CanStopWaiting = $null -ne (Test-EntraOpsConsoleKeyPress -Key S)
            if ($CanStopWaiting) {
                Write-Host '  Press S to stop waiting: the reports are then generated without the new snapshot, which the next run collects.' -ForegroundColor Gray
            }
            $StoppedWaiting = $false
            $ProgressActivity = 'Capturing the Tenant Governance snapshot'
            $Timeout = & $FormatDuration ([timespan]::FromSeconds($TenantGovernanceTimeoutInSeconds))
            try {
                # Collects first: the snapshot can be complete by the end of these reports, also after the timeout.
                :WaitForSnapshot while (-not (& $CollectSnapshot) -and ((Get-Date) - $SnapshotStartedAt).TotalSeconds -lt $TenantGovernanceTimeoutInSeconds) {
                    $LastStatus = (Get-Content -LiteralPath $PendingJobFile -Raw | ConvertFrom-Json).LastKnownStatus
                    for ($Second = 0; $Second -lt 15 -and ((Get-Date) - $SnapshotStartedAt).TotalSeconds -lt $TenantGovernanceTimeoutInSeconds; $Second++) {
                        Write-Progress -Id ($ProgressId + 1) -ParentId $ProgressId -Activity $ProgressActivity -Status ("Status: {0} - {1} elapsed, waiting up to {2}{3}" -f $LastStatus, (& $FormatDuration ((Get-Date) - $SnapshotStartedAt)), $Timeout, $(if ($CanStopWaiting) { ' (S stops waiting)' }))
                        if ($CanStopWaiting -and (Test-EntraOpsConsoleKeyPress -Key S)) {
                            $StoppedWaiting = $true
                            break WaitForSnapshot
                        }
                        Start-Sleep -Seconds 1
                    }
                }
            } catch {
                $Snapshot.Status = 'Failed'
                $Snapshot.Reason = $_.Exception.Message
                Write-Warning "The Tenant Governance snapshot failed: $($Snapshot.Reason)"
            } finally {
                Write-Progress -Id ($ProgressId + 1) -ParentId $ProgressId -Activity $ProgressActivity -Completed
            }
            if ($Snapshot.Status -eq 'Started') {
                $Elapsed = & $FormatDuration ((Get-Date) - $SnapshotStartedAt)
                $Snapshot.Status = 'Pending'
                $Snapshot.Reason = if ($StoppedWaiting) { "waiting was stopped after $Elapsed" } else { "not complete after $Elapsed" }
                $Snapshot.Next = "$ReRunCommand collects it first"
                Write-Warning "The Tenant Governance snapshot is $(if ($StoppedWaiting) { "not used: waiting was stopped after $Elapsed" } else { "not complete after $Elapsed" }). The reports use the previous snapshot, if any. Microsoft Graph keeps capturing it: $ReRunCommand collects it first."
            }

            # With the snapshot (or the previous one): the reports that read it, and the findings of all reports.
            Write-Host '  Generating Configuration Analyzer, Access Package Flow and the findings...'
            $WithSnapshot = $ReportingParameters.Clone()
            foreach ($Name in 'SkipTierBreachAnalyzer', 'SkipEamDashboard', 'SkipPrivilegedAssets', 'SkipAccessPathMap', 'SkipClassificationExplorer', 'SkipPrivilegeHistory') { $WithSnapshot[$Name] = $true }
            $ReportResults += @(New-EntraOpsReportingData @WithSnapshot)
        }
        #endregion
    } finally {
        Write-Progress -Id $ProgressId -Activity $Activity -Completed
        if ($Connected -and -not $KeepConnection) {
            if ($AuthenticationType -eq 'AlreadyAuthenticated') {
                # The connections belong to the caller (for example later steps of a pipeline): only the cached tenant data is removed.
                try { Clear-EntraOpsCache -CacheType All | Out-Null } catch { Write-Warning "Failed to clear the EntraOps cache: $($_.Exception.Message)" }
            } else {
                Disconnect-EntraOps -ClearEntraOpsCache All -ErrorAction SilentlyContinue | Out-Null
            }
        }
    }

    #region Summary
    $FindingsFile = Join-Path $WorkingFolder 'Reports/Findings/data/findings.json'
    # Only the finding results of this run: a findings.json of an earlier run (or of another tenant in a shared
    # folder) stays in place when the evaluation fails, and must not be summarized as this run's result.
    $FindingsEvaluated = @($ReportResults.App) -contains 'Findings'
    $Rules = if ($FindingsEvaluated -and (Test-Path -LiteralPath $FindingsFile -PathType Leaf)) { @((Get-Content -LiteralPath $FindingsFile -Raw | ConvertFrom-Json -Depth 20).Rules) } else { @() }
    $SeverityOrder = @('Critical', 'High', 'Medium', 'Low', 'Info')
    $FailedRules = @($Rules | Where-Object Status -eq 'Failed' | Sort-Object @{ Expression = { [array]::IndexOf($SeverityOrder, [string]$_.Severity) } }, @{ Expression = { [int]$_.FailedCount }; Descending = $true })
    $FindingSummary = [ordered]@{
        Rules    = $Rules.Count
        Failed   = $FailedRules.Count
        Passed   = @($Rules | Where-Object Status -eq 'Passed').Count
        Skipped  = @($Rules | Where-Object Status -eq 'Skipped').Count
        Excluded = @($Rules | Where-Object Status -eq 'Excluded').Count
        Error    = @($Rules | Where-Object Status -eq 'Error').Count
        Severity = [ordered]@{}
    }
    foreach ($Severity in $SeverityOrder) {
        $FindingSummary.Severity[$Severity] = @($FailedRules | Where-Object Severity -eq $Severity).Count
    }

    Write-Host ''
    Write-Host '═══════════════════════════════════════════════════════════════════════════════' -ForegroundColor Cyan
    Write-Host "  EntraOps assessment of $TenantName  —  $('{0:hh\:mm\:ss}' -f ((Get-Date) - $StartTime))" -ForegroundColor Cyan
    Write-Host '═══════════════════════════════════════════════════════════════════════════════' -ForegroundColor Cyan
    $SnapshotComplete = $Snapshot.Status -in @('Captured', 'Reused')
    Write-Host "  Tenant Governance : $($Snapshot.Status)$(if ($Snapshot.Reason) { " - $($Snapshot.Reason)" })" -ForegroundColor $(if ($SnapshotComplete) { 'Green' } else { 'Yellow' })
    if (-not $SnapshotComplete -and $Snapshot.Next) {
        Write-Host "                      Next: $($Snapshot.Next)" -ForegroundColor Gray
        foreach ($Line in @($SnapshotSetupInfo)) { if ($Line) { Write-Host "                      $Line" -ForegroundColor Gray } }
    }
    if ($AzureRbac.Status -eq 'Skipped') {
        Write-Host "  Azure RBAC        : Skipped - $($AzureRbac.Reason)" -ForegroundColor Yellow
        Write-Host "                      Next: $($AzureRbac.Next)" -ForegroundColor Gray
    }
    if ($Rules.Count -eq 0) {
        Write-Host "  Findings          : $(if ($FindingsEvaluated) { 'no finding results were saved' } else { 'not evaluated in this run, see the warnings above' })" -ForegroundColor Yellow
    } else {
        $SeverityText = @($SeverityOrder | Where-Object { $FindingSummary.Severity[$_] -gt 0 } | ForEach-Object { "$($FindingSummary.Severity[$_]) $_" }) -join ', '
        Write-Host "  Findings          : $($FindingSummary.Failed) of $($FindingSummary.Rules) rules failed$(if ($SeverityText) { " ($SeverityText)" }), $($FindingSummary.Passed) passed, $($FindingSummary.Skipped) skipped$(if ($FindingSummary.Excluded) { ", $($FindingSummary.Excluded) excluded" })$(if ($FindingSummary.Error) { ", $($FindingSummary.Error) error(s)" })" -ForegroundColor White
        foreach ($Rule in @($FailedRules | Select-Object -First 10)) {
            $Color = if ($Rule.Severity -in @('Critical', 'High')) { 'Red' } elseif ($Rule.Severity -eq 'Medium') { 'Yellow' } else { 'Gray' }
            Write-Host ("    {0,-8} {1,-9} {2} ({3})" -f $Rule.RuleId, $Rule.Severity, $Rule.Title, $Rule.FailedCount) -ForegroundColor $Color
        }
        $HasFindingsView = Test-Path -LiteralPath (Join-Path $WorkingFolder 'Reports/PrivilegedAssets/js/findings.js') -PathType Leaf
        if ($FailedRules.Count -gt 10) {
            Write-Host "    ... and $($FailedRules.Count - 10) more: see $(if ($HasFindingsView) { 'Reports/PrivilegedAssets/index.html?view=findings' } else { $FindingsFile })" -ForegroundColor Gray
        }
        # Without a designated tier, an object counts as User Access, so the tier rules report most of its privileged
        # assignments: name their share, so a first assessment isn't read as a list of tier breaches only.
        $UnclassifiedRule = $Rules | Where-Object RuleId -eq 'EO.2001' | Select-Object -First 1
        if ($UnclassifiedRule -and $UnclassifiedRule.Status -eq 'Failed' -and [int]$UnclassifiedRule.FailedCount -gt 0) {
            $ListedResults = @($FailedRules | Select-Object -First 10 | Where-Object RuleId -ne 'EO.2001' | ForEach-Object { @($_.Results) })
            $UnclassifiedResults = @($ListedResults | Where-Object { "$($_.Instance.AdminTierLevelName)" -eq 'Unclassified' }).Count
            Write-Host ("  Classification    : {0} privileged object(s) have no designated tier (EO.2001){1}. Classify them" -f $UnclassifiedRule.FailedCount, $(if ($UnclassifiedResults -gt 0) { "; $UnclassifiedResults of the $($ListedResults.Count) results listed above concern them" })) -ForegroundColor Yellow
            Write-Host '                      (Object Classification File or tier attributes, see EO.2001) for exact tier findings.' -ForegroundColor Gray
        }
        # Rules whose evaluation failed: not a finding, but their result is unknown.
        foreach ($Rule in @($Rules | Where-Object Status -eq 'Error')) {
            Write-Host ("    {0,-8} {1,-9} {2}: {3}" -f $Rule.RuleId, 'Error', $Rule.Title, $Rule.Reason) -ForegroundColor Yellow
        }
    }
    # Privilege History and Configuration Analyzer record where their snapshots came from (historySource).
    $HistorySources = @($ReportResults | Where-Object { $_.App -in @('PrivilegeHistory', 'ConfigurationAnalyzer') } | ForEach-Object { [string]$_.Result.historySource } | Where-Object { $_ })
    if ($HistorySources -contains 'folder') {
        Write-Host '  History           : current run only (no git history)' -ForegroundColor Gray
    }
    Write-Host ''
    Write-Host "  Reports           : $ReportingPortal" -ForegroundColor White
    if (-not (Test-Path -LiteralPath (Join-Path $WorkingFolder 'Reports/PrivilegedAssets/js/findings.js') -PathType Leaf)) {
        Write-Host "                      These reporting apps have no Findings view. Install the apps of EntraOps $ModuleVersion with Install-EntraOpsReportingFolder -Force (-Ref <branch> -Repository EntraOps-Insiders for an Insiders build)." -ForegroundColor Yellow
    }
    Write-Host "  Finding results   : $FindingsFile" -ForegroundColor White
    Write-Host '  Maester           : Install-MtPack Cloud-Architekt/EntraOps-MaesterPack' -ForegroundColor Gray
    Write-Host '                      Invoke-Maester -Pack EOPS -SkipBuiltIn -SkipGraphConnect' -ForegroundColor Gray
    # The pack finds the results of ENTRAOPS_ROOT, <home>/EntraOps and the current folder without a setting.
    $FindingsFolder = Split-Path -Parent $FindingsFile
    $DefaultFindingsFolders = @(
        $(if (-not [string]::IsNullOrWhiteSpace($HOME)) { Join-Path $HOME 'EntraOps/Reports/Findings/data' })
        Join-Path (Get-Location -PSProvider FileSystem).ProviderPath 'Reports/Findings/data'
    )
    if ($FindingsFolder -notin $DefaultFindingsFolders) {
        Write-Host "                      (in a new session, set EntraOps.FindingsPath in maester-config.json to '$FindingsFolder')" -ForegroundColor Gray
    }
    Write-Host '═══════════════════════════════════════════════════════════════════════════════' -ForegroundColor Cyan

    if ($OpenReport -and (Test-Path -LiteralPath $ReportingPortal -PathType Leaf)) {
        Invoke-Item -LiteralPath $ReportingPortal
    }
    #endregion

    if ($PassThru) {
        [pscustomobject]@{
            TenantName               = $TenantName
            WorkingFolder            = $WorkingFolder
            TenantGovernanceSnapshot = [pscustomobject]$Snapshot
            AzureRbac                = [pscustomobject]$AzureRbac
            Reports                  = @($ReportResults.App)
            ReportingPortal          = $ReportingPortal
            FindingsPath             = $FindingsFile
            Findings                 = [pscustomobject]$FindingSummary
            Duration                 = (Get-Date) - $StartTime
        }
    }
}
