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
    Path to the EntraOps repository root that contains the PrivilegedEAM export folder.
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
    if ([string]::IsNullOrWhiteSpace($AppRoot)) { $AppRoot = Join-Path $RepositoryRoot 'Reports/TierBreachAnalyzer' }
    if (-not (Test-Path -LiteralPath $AppRoot -PathType Container)) {
        throw "Tier Breach Analyzer app folder not found: $AppRoot. Import the EntraOps module from a repository checkout that contains Reports/TierBreachAnalyzer, or run Install-EntraOpsReportingFolder to download the Reports folder."
    }
    if ([string]::IsNullOrWhiteSpace($ImportPath)) { $ImportPath = Join-Path $RepoRoot 'PrivilegedEAM' }
    if ([string]::IsNullOrWhiteSpace($OutFile)) { $OutFile = Join-Path $AppRoot 'data/tier-breach-data.js' }

    if (-not (Test-Path -LiteralPath $ImportPath)) {
        throw "Privileged EAM import path not found: $ImportPath. Run Save-EntraOpsPrivilegedEAMJson first or pass -ImportPath."
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

    function ConvertTo-TierNumber {
        <#
            Normalize a raw tier value to a numeric tier (0/1/2).
            Empty string, $null and "Unclassified" map to the default (Tier 2 -
            lowest privilege), matching the handling of unclassified objects.
        #>
        param(
            $Value,
            [int] $Default = 2
        )
        if ($null -eq $Value) { return $Default }
        $s = "$Value".Trim()
        if ($s -eq '' -or $s -eq 'Unclassified') { return $Default }
        $n = 0
        if (-not [int]::TryParse($s, [ref] $n)) { return $Default }
        if ($n -in 0, 1, 2) { return $n }
        return $Default
    }

    # Match PrivilegedEAM/<System>/<System>.json only (one level deep), not the
    # per-object subfolders (user/, group/, serviceprincipal/ ...).
    $files = Get-ChildItem -Path $ImportPath -Directory |
    ForEach-Object { Get-ChildItem -Path $_.FullName -Filter '*.json' -File } |
    Sort-Object FullName

    if (-not $files) {
        Write-Warning "No Privileged EAM JSON files found under $ImportPath (expected <RbacSystem>/<RbacSystem>.json). Generating an empty dataset."
    } else {
        Write-Verbose "Found $($files.Count) Privileged EAM JSON file(s) to process."
    }

    $objects = [System.Collections.Generic.List[object]]::new()
    $paths = [System.Collections.Generic.List[object]]::new()
    # Maps assignment scope IDs to reusable scope-reasoning entries.
    $scopeReasoningByScope = [ordered]@{}
    $scopeReasoningDetails = Import-EntraOpsAzureScopeReasoning -RepoRoot $RepoRoot

    Write-Verbose "Loaded $($scopeReasoningDetails.Count) Azure scope-reasoning detail record(s)."

    $fileNumber = 0
    foreach ($file in @($files)) {
        $fileNumber++
        $roleSystem = Split-Path -Leaf (Split-Path -Parent $file.FullName)
        Write-Verbose "[$fileNumber/$($files.Count)] Reading $roleSystem data from $($file.FullName)."

        try {
            $data = Get-Content -LiteralPath $file.FullName -Raw -Encoding UTF8 |
            ConvertFrom-Json
        } catch {
            # Stop generation when an enumerated export cannot be read or parsed.
            throw "Failed to read or parse Privileged EAM export file '$($file.FullName)' (RBAC system '$roleSystem'): $($_.Exception.Message)"
        }

        $sourceObjectCount = @($data).Count
        $processedObjectCount = 0
        $pathsBeforeFile = $paths.Count
        foreach ($o in @($data)) {
            $processedObjectCount++
            if ($processedObjectCount % 250 -eq 0) {
                Write-Verbose "[$fileNumber/$($files.Count)] Processed $processedObjectCount of $sourceObjectCount $roleSystem source object(s)."
            }

            $objType = Get-PropValue $o 'ObjectType'
            # Only users and service principals.
            if ($objType -notin 'user', 'serviceprincipal') { continue }

            $objectId = Get-PropValue $o 'ObjectId'
            $display = Get-PropValue $o 'ObjectDisplayName'
            if (-not $display) { $display = $objectId }
            $objTier = ConvertTo-TierNumber -Value (Get-PropValue $o 'ObjectAdminTierLevel')

            $objects.Add([ordered]@{
                    id     = $objectId
                    name   = $display
                    type   = $objType
                    system = $roleSystem
                    tier   = $objTier
                })

            foreach ($ra in @(Get-PropValue $o 'RoleAssignments')) {
                if ($null -eq $ra) { continue }
                $roleName = Get-PropValue $ra 'RoleDefinitionName'
                if (-not $roleName) { $roleName = '(unnamed role)' }
                $isPriv = [bool] (Get-PropValue $ra 'RoleIsPrivileged')
                $classifications = @(Get-PropValue $ra 'Classification')
                if ($classifications.Count -eq 0) { continue }

                # Assignment-level context (explains which assignment causes the breach).
                $scopeId = Get-PropValue $ra 'RoleAssignmentScopeId'
                $scopeName = Get-PropValue $ra 'RoleAssignmentScopeName'
                if (-not $scopeName) { $scopeName = $scopeId }
                $assignType = "$(Get-PropValue $ra 'RoleAssignmentType')"
                $assignSub = "$(Get-PropValue $ra 'RoleAssignmentSubType')"
                $pimManaged = [bool] (Get-PropValue $ra 'PIMManagedRole')
                $pimType = "$(Get-PropValue $ra 'PIMAssignmentType')"
                $roleType = "$(Get-PropValue $ra 'RoleType')"
                $assignId = Get-PropValue $ra 'RoleAssignmentId'
                $assignInstanceId = if (Get-PropValue $ra 'RoleAssignmentInstanceId') { Get-PropValue $ra 'RoleAssignmentInstanceId' } else { Get-EntraOpsRoleAssignmentInstanceId -RoleSystem $roleSystem -RoleAssignment $ra }
                $transitiveBy = "$(Get-PropValue $ra 'TransitiveByObjectDisplayName')"

                # De-duplicate services within a single assignment.
                $seen = [System.Collections.Generic.HashSet[string]]::new()
                foreach ($c in $classifications) {
                    if ($null -eq $c) { continue }
                    $service = Get-PropValue $c 'Service'
                    if (-not $service) { $service = '(unclassified)' }
                    $svcTier = ConvertTo-TierNumber -Value (Get-PropValue $c 'AdminTierLevel')
                    $key = "$service|$svcTier"
                    if (-not $seen.Add($key)) { continue }

                    $taggedBy = "$(Get-PropValue $c 'TaggedBy')"
                    $taggedBySystem = "$(Get-PropValue $c 'TaggedByRoleSystem')"

                    # Cache Azure scope reasoning once for each assignment scope.
                    if ($roleSystem -eq 'Azure' -and $scopeReasoningDetails.Count -gt 0 -and -not [string]::IsNullOrEmpty("$scopeId") -and -not $scopeReasoningByScope.Contains("$scopeId")) {
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

                    $paths.Add([ordered]@{
                            objectId           = $objectId
                            objectName         = $display
                            objectType         = $objType
                            objectTier         = $objTier
                            system             = $roleSystem
                            role               = $roleName
                            roleType           = $roleType
                            roleIsPrivileged   = $isPriv
                            service            = $service
                            serviceTier        = $svcTier
                            # Assignment detail.
                            assignmentInstanceId = $assignInstanceId
                            assignmentId       = $assignId
                            scopeName          = $scopeName
                            scopeId            = $scopeId
                            assignmentType     = $assignType
                            assignmentSubType  = $assignSub
                            pimManaged         = $pimManaged
                            pimAssignmentType  = $pimType
                            transitiveBy       = $transitiveBy
                            taggedBy           = $taggedBy
                            taggedByRoleSystem = $taggedBySystem
                            # Breach: object less privileged than the service it reaches.
                            breach             = ($objTier -gt $svcTier)
                            tier0Breach        = ($objTier -gt 0 -and $svcTier -eq 0)
                            # Scope reasoning is resolved through scopeReasoningByScope.
                        })
                }
            }
        }

        Write-Verbose "[$fileNumber/$($files.Count)] Finished ${roleSystem}: processed $sourceObjectCount source object(s), added $($paths.Count - $pathsBeforeFile) assignment path(s)."
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
