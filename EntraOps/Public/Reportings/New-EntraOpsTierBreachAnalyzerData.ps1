<#
.SYNOPSIS
    Generate (refresh) the embedded dataset for the EntraOps Tier Breach Analyzer static web app.

.DESCRIPTION
    Transforms EntraOps Privileged EAM data into the Tier Breach Analyzer dataset.

    Generates data/tier-breach-data.js exposing `window.ENTRAOPS_TB_DATA` so the
    static web app works both when served over HTTP (for example Azure Static
    Web Apps) and when opened directly from the file system (no fetch / CORS
    required).

    Flow modeled (left -> right):
        Object Tier -> Object -> Role -> Service -> Service Tier

    Tiering rules:
      * Object designated tier comes from `ObjectAdminTierLevel`.
      * If an object has no classification (empty / "Unclassified"), it is
        treated as Tier 2 (User Access) which is the lowest / least privileged
        tier.
      * A "tier breach" is a path where the object's tier is LESS privileged
        (higher tier number) than the service it can reach through a role.
        The headline case is a Tier 1 / Tier 2 object reaching a Tier 0 service.

    Source data is the Privileged EAM export written by
    Save-EntraOpsPrivilegedEAMJson: PrivilegedEAM/<RbacSystem>/<RbacSystem>.json
    (only JSON files directly in the RBAC system folder are read, not the
    per-object subfolders user/, group/, serviceprincipal/, ...).

    This function requires the module to be imported from a repository checkout that contains the
    Reports/TierBreachAnalyzer folder.

.PARAMETER RepoRoot
    Path to the EntraOps repository root that contains the PrivilegedEAM export folder (alias: -Path).
    Defaults to the repository this module lives in.

.PARAMETER ImportPath
    Folder with the Privileged EAM export. Defaults to <RepoRoot>/PrivilegedEAM.

.PARAMETER AppRoot
    Path to the TierBreachAnalyzer app folder (where the generated content is written).
    Defaults to Reports/TierBreachAnalyzer in the EntraOps repository.

.PARAMETER OutFile
    Output file. Defaults to <AppRoot>/data/tier-breach-data.js.

.PARAMETER PassThru
    Emit the generated payload object to the pipeline.

.EXAMPLE
    New-EntraOpsTierBreachAnalyzerData

    Regenerates the Tier Breach Analyzer dataset from the PrivilegedEAM folder of this repository.

.EXAMPLE
    New-EntraOpsTierBreachAnalyzerData -ImportPath "C:\Exports\PrivilegedEAM" -Verbose -WhatIf

    Shows what would be generated from an explicit Privileged EAM export without changing any files.
#>

function New-EntraOpsTierBreachAnalyzerData {

    [CmdletBinding(SupportsShouldProcess = $true)]
    param (
        [Parameter(Mandatory = $false)]
        [Alias('Path')]
        [System.String]$RepoRoot,

        [Parameter(Mandatory = $false)]
        [System.String]$ImportPath,

        [Parameter(Mandatory = $false)]
        [System.String]$AppRoot,

        [Parameter(Mandatory = $false)]
        [System.String]$OutFile,

        [Parameter(Mandatory = $false)]
        [switch]$PassThru
    )

    # Resolve the app/repository location relative to the module location:
    # <repo>/EntraOps/Public/<subfolder> -> <repo>/Reports/TierBreachAnalyzer
    # Prefer the module's own ModuleBase (always populated for exported module
    # functions) over $PSScriptRoot, which can be empty depending on how the
    # function was invoked/loaded.
    $ModuleRoot = $MyInvocation.MyCommand.Module.ModuleBase
    if ([string]::IsNullOrWhiteSpace($ModuleRoot) -and -not [string]::IsNullOrWhiteSpace($PSScriptRoot)) {
        $ModuleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    }
    if ([string]::IsNullOrWhiteSpace($ModuleRoot)) {
        throw "Unable to resolve the EntraOps module location. Import the module with 'Import-Module <path-to-EntraOps> -Force' and try again."
    }
    $RepositoryRoot = if (-not [string]::IsNullOrWhiteSpace($Global:EntraOpsBaseFolder)) { $Global:EntraOpsBaseFolder } else { Split-Path -Parent $ModuleRoot }

    if ([string]::IsNullOrWhiteSpace($RepoRoot)) { $RepoRoot = $RepositoryRoot }
    if ([string]::IsNullOrWhiteSpace($AppRoot)) { $AppRoot = Join-Path $RepoRoot 'Reports/TierBreachAnalyzer' }
    if (-not (Test-Path -LiteralPath $AppRoot -PathType Container)) {
        throw "Tier Breach Analyzer app folder not found: $AppRoot. Import the EntraOps module from a repository checkout that contains Reports/TierBreachAnalyzer, or run Install-EntraOpsReportingFolder to download the Reports folder."
    }
    if ([string]::IsNullOrWhiteSpace($ImportPath)) { $ImportPath = Join-Path $RepoRoot 'PrivilegedEAM' }
    if ([string]::IsNullOrWhiteSpace($OutFile)) { $OutFile = Join-Path $AppRoot 'data/tier-breach-data.js' }

    if (-not (Test-Path -LiteralPath $ImportPath)) {
        throw "Privileged EAM import path not found: $ImportPath. Run Invoke-EntraOpsPrivilegedEAM (or Save-EntraOpsPrivilegedEAMJson) first, or pass -ImportPath."
    }

    Write-Verbose "Reading Privileged EAM JSON from $ImportPath."
    Write-Verbose "Writing Tier Breach Analyzer data to $OutFile."

    # Tier numeric value -> label. Lower number = more privileged.
    $TierLabels = [ordered]@{
        '0' = 'Tier 0 - Control Plane'
        '1' = 'Tier 1 - Management Plane'
        '2' = 'Tier 2 - User Access'
    }

    function Get-PropValue {
        # Safe property access for objects from ConvertFrom-Json whose schema can
        # vary between RBAC systems (also strict-mode proof).
        param($Object, [string] $Name)
        $p = $Object.PSObject.Properties[$Name]
        if ($null -ne $p) { return $p.Value }
        return $null
    }

    # Objects and assignment paths are shared with the Findings rules (Invoke-EntraOpsFindingEvaluation).
    $context = New-EntraOpsTierBreachFindingContext -ImportPath $ImportPath
    $files = $context.Files
    $objects = $context.Objects
    $paths = $context.Paths

    # Breach flags use the test of the Tier Breach finding rules (Test-EntraOpsTierBreachPath) for every path,
    # including the paths the rules leave out (delegated permissions, Microsoft first-party service principals)
    # and the paths of unclassified objects that the breach rule counts apart.

    # Maps assignment scope IDs to reusable scope-reasoning entries.
    $scopeReasoningByScope = [ordered]@{}
    $scopeReasoningDetails = Import-EntraOpsAzureScopeReasoning -RepoRoot $RepoRoot

    Write-Verbose "Loaded $($scopeReasoningDetails.Count) Azure scope-reasoning detail record(s)."

    foreach ($path in $paths) {
        # Breach: object less privileged than the service it reaches. The breach rule leaves out Control Plane
        # services (tier0Breach reports them), the analyzer's breach flag covers both.
        $path['tier0Breach'] = Test-EntraOpsTierBreachPath -Key 'tier0Breach' -Path $path
        $path['breach'] = $path['tier0Breach'] -or (Test-EntraOpsTierBreachPath -Key 'breach' -Path $path)

        # Cache Azure scope reasoning once for each assignment scope.
        $scopeId = $path.scopeId
        if ($path.system -eq 'Azure' -and $scopeReasoningDetails.Count -gt 0 -and -not [string]::IsNullOrEmpty("$scopeId") -and -not $scopeReasoningByScope.Contains("$scopeId")) {
            $scopeReasoning = [System.Collections.Generic.List[object]]::new()
            foreach ($sr in (Find-EntraOpsAzureScopeReasoning -ScopeReasoningDetails $scopeReasoningDetails -ScopeId "$scopeId")) {
                $scopeReasoning.Add([ordered]@{
                        resourceName            = "$(Get-PropValue $sr 'ScopeName')"
                        resourceId              = "$(Get-PropValue $sr 'ScopeId')"
                        eamTier                 = "$(Get-PropValue $sr 'EAMTier')"
                        resultingScope          = "$(Get-PropValue $sr 'ResultingScope')"
                        reason                  = "$(Get-PropValue $sr 'Reason')"
                        managedIdentityObjectId = "$(Get-PropValue $sr 'ManagedIdentityObjectId')"
                        # ScopeRelation identifies the scope reason relative to the assignment scope.
                        source                  = "$(Get-PropValue $sr 'Source')"
                        scopeRelation           = $(if ("$(Get-PropValue $sr 'ScopeId')".TrimEnd('/') -ieq "$scopeId".TrimEnd('/')) { 'Exact' } else { 'Descendant resource' })
                    })
            }
            if ($scopeReasoning.Count -gt 0) {
                $scopeReasoningByScope["$scopeId"] = $scopeReasoning
            } else {
                # Cache scope IDs without matching reasoning entries.
                $scopeReasoningByScope["$scopeId"] = @()
            }
        }
    }

    $repoRootFull = (Resolve-Path -LiteralPath $RepoRoot).Path
    $tenantName = Get-EntraOpsReportingTenantName -RepoRoot $RepoRoot
    $payload = [ordered]@{
        tenantName    = $tenantName
        generatedFrom = @(@($files) | ForEach-Object {
                if ($_.FullName.StartsWith($repoRootFull)) {
                    $_.FullName.Substring($repoRootFull.Length).TrimStart('\', '/') -replace '\\', '/'
                } else {
                    $_.Name
                }
            })
        tierLabels    = $TierLabels
        objects       = $objects
        paths         = $paths
        # Scope-reasoning entries shared by assignment scope ID.
        scopeReasoningByScope = $scopeReasoningByScope
    }

    $json = $payload | ConvertTo-Json -Depth 10 -Compress
    $content = "// Auto-generated by New-EntraOpsTierBreachAnalyzerData - do not edit by hand.`n" +
    "window.ENTRAOPS_TB_DATA = $json;`n"

    Write-Verbose "Built Tier Breach Analyzer payload with $($objects.Count) object record(s) and $($paths.Count) assignment path(s)."

    if ($PSCmdlet.ShouldProcess($OutFile, 'Write Tier Breach Analyzer dataset')) {
        Save-EntraOpsReportDataFile -Content $content -LiteralPath $OutFile

        $nBreach = @($paths | Where-Object { $_.breach }).Count
        $nTier0 = @($paths | Where-Object { $_.tier0Breach }).Count
        Write-Host "Objects (user/sp): $($objects.Count)"
        Write-Host "Assignment paths:  $($paths.Count)"
        Write-Host "Tier breaches:     $nBreach"
        Write-Host "Tier 0 breaches:   $nTier0"
        Write-Host "Wrote $OutFile"
    }

    if ($PassThru) { $payload }
}
