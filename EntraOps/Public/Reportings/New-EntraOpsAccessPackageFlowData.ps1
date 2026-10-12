<#
.SYNOPSIS
    Generate live Microsoft Graph enrichment data for the Access Package Flow report.

.DESCRIPTION
    Recovers information omitted by Tenant Governance snapshots: groupMembers user-set IDs,
    access package resource-role scopes, and current package assignments. The generated data is
    merged with the snapshot-only Configuration Analyzer dataset by the static report.
#>

function New-EntraOpsAccessPackageFlowData {

    [CmdletBinding(SupportsShouldProcess = $true)]
    param (
        [Parameter(Mandatory = $false)]
        [System.String]$RepoRoot,

        [Parameter(Mandatory = $false)]
        [System.String]$SnapshotPath,

        [Parameter(Mandatory = $false)]
        [System.String]$AppRoot,

        [Parameter(Mandatory = $false)]
        [System.String]$OutFile,

        [Parameter(Mandatory = $false)]
        [System.Nullable[bool]]$ResolveRequestorApproverTiers,

        [Parameter(Mandatory = $false)]
        [switch]$PassThru
    )

    $ModuleRoot = $MyInvocation.MyCommand.Module.ModuleBase
    if ([string]::IsNullOrWhiteSpace($ModuleRoot) -and -not [string]::IsNullOrWhiteSpace($PSScriptRoot)) {
        $ModuleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    }
    if ([string]::IsNullOrWhiteSpace($ModuleRoot)) {
        throw "Unable to resolve the EntraOps module location. Import the module with 'Import-Module <path-to-EntraOps> -Force' and try again."
    }
    $RepositoryRoot = if (-not [string]::IsNullOrWhiteSpace($Global:EntraOpsBaseFolder)) { $Global:EntraOpsBaseFolder } else { Split-Path -Parent $ModuleRoot }
    if ([string]::IsNullOrWhiteSpace($RepoRoot)) { $RepoRoot = $RepositoryRoot }
    if ([string]::IsNullOrWhiteSpace($SnapshotPath)) { $SnapshotPath = Join-Path $RepoRoot 'TenantGovernance/Snapshots' }
    if ([string]::IsNullOrWhiteSpace($AppRoot)) { $AppRoot = Join-Path $RepoRoot 'Reports/AccessPackageFlow' }
    if ([string]::IsNullOrWhiteSpace($OutFile)) { $OutFile = Join-Path $AppRoot 'data/access-package-assignments-data.js' }

    if (-not (Test-Path -LiteralPath $SnapshotPath -PathType Container)) {
        throw "Tenant Governance snapshot folder not found: $SnapshotPath. Run a successful Save-EntraOpsTenantGovernanceSnapshotJson capture first."
    }
    if (-not $PSBoundParameters.ContainsKey('ResolveRequestorApproverTiers')) {
        $ResolveRequestorApproverTiers = $true
        $ConfigFilePath = Join-Path $RepoRoot 'EntraOpsConfig.json'
        if (Test-Path -LiteralPath $ConfigFilePath -PathType Leaf) {
            try {
                $Config = Get-Content -LiteralPath $ConfigFilePath -Raw | ConvertFrom-Json
                if ($null -ne $Config.ConfigurationAnalyzer -and $null -ne $Config.ConfigurationAnalyzer.ResolveGroupMembersForPrivilegedAssets) {
                    $ResolveRequestorApproverTiers = [bool]$Config.ConfigurationAnalyzer.ResolveGroupMembersForPrivilegedAssets
                }
            } catch {
                Write-Warning "Failed to read ConfigurationAnalyzer settings from ${ConfigFilePath}: $($_.Exception.Message). Group tier resolution remains enabled."
            }
        }
    }

    $PolicyIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($SnapshotFile in @(Get-ChildItem -LiteralPath $SnapshotPath -Recurse -File -Filter '*.json' | Where-Object { $_.Name -notmatch '^\.' })) {
        try {
            $SnapshotResource = Get-Content -LiteralPath $SnapshotFile.FullName -Raw | ConvertFrom-Json -AsHashtable
            if ("$($SnapshotResource.resourceType)".ToLowerInvariant() -ne 'microsoft.entra.entitlementmanagementaccesspackageassignmentpolicy') { continue }
            $PolicyId = "$($SnapshotResource.properties.Id)"
            if (-not [string]::IsNullOrWhiteSpace($PolicyId)) { [void]$PolicyIds.Add($PolicyId) }
        } catch {
            Write-Verbose "Skipped unreadable snapshot resource $($SnapshotFile.FullName): $($_.Exception.Message)"
        }
    }

    # Rank values are purely relational (comparisons/sorting) - canonical Enterprise Access Model
    # order: ControlPlane < ManagementPlane < WorkloadPlane < UserAccess.
    $TierRank = @{ ControlPlane = 0; ManagementPlane = 1; WorkloadPlane = 2; UserAccess = 3 }
    $TierByObjectId = @{}
    if ($ResolveRequestorApproverTiers) {
        $PrivilegedEamPath = Join-Path $RepoRoot 'PrivilegedEAM'
        if (Test-Path -LiteralPath $PrivilegedEamPath -PathType Container) {
            $PrivilegedEamObjects = @(Get-EntraOpsPrivilegedEamDashboardObjects -ImportPath $PrivilegedEamPath)
            foreach ($Object in $PrivilegedEamObjects) {
                $ObjectId = "$($Object.objectId)"
                if (-not $ObjectId) { continue }
                $ObjectTierNames = @("$($Object.objectAdminTierLevelName)") +
                    @($Object.classification | ForEach-Object { "$($_.adminTierLevelName)" }) +
                    @($Object.roleAssignments | ForEach-Object { $_.classification } | ForEach-Object { "$($_.adminTierLevelName)" })
                foreach ($TierName in $ObjectTierNames | Where-Object { $TierRank.ContainsKey($_) }) {
                    if (-not $TierByObjectId.ContainsKey($ObjectId) -or $TierRank[$TierName] -lt $TierRank[$TierByObjectId[$ObjectId]]) {
                        $TierByObjectId[$ObjectId] = $TierName
                    }
                }
            }
        } else {
            Write-Warning "Group tier resolution was requested, but the Privileged EAM export was not found at $PrivilegedEamPath."
        }
    }

    $PolicyRequestorApprovers = [ordered]@{}
    $PackageIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $GroupIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($PolicyId in $PolicyIds) {
        try {
            $Policy = Invoke-EntraOpsMsGraphQuery -Uri "/beta/identityGovernance/entitlementManagement/accessPackageAssignmentPolicies/$PolicyId" -OutputType PSObject -ThrowOnFailure
            if ($null -eq $Policy) { continue }
            $Requestors = @($Policy.requestorSettings.allowedRequestors)
            $Approvers = @($Policy.requestApprovalSettings.approvalStages | ForEach-Object { $_.primaryApprovers })
            $PolicyRequestorApprovers[$PolicyId] = [ordered]@{
                accessPackageId = "$($Policy.accessPackageId)"
                scopeType       = "$($Policy.requestorSettings.scopeType)"
                requestors      = $Requestors
                approvers       = $Approvers
            }
            if ($Policy.accessPackageId) { [void]$PackageIds.Add("$($Policy.accessPackageId)") }
            foreach ($UserSet in @($Requestors) + @($Approvers)) {
                if ("$($UserSet.'@odata.type')" -eq '#microsoft.graph.groupMembers' -and $UserSet.id) {
                    [void]$GroupIds.Add("$($UserSet.id)")
                }
            }
        } catch {
            Write-Warning "Could not resolve access package assignment policy ${PolicyId}: $($_.Exception.Message)"
        }
    }

    $Packages = [ordered]@{}
    $Assignments = [System.Collections.Generic.List[object]]::new()
    $CatalogResourcesByCatalogId = @{}
    $CatalogNamesById = @{}
    foreach ($PackageId in $PackageIds) {
        try {
            $Package = Invoke-EntraOpsMsGraphQuery -Uri "/beta/identityGovernance/entitlementManagement/accessPackages/$PackageId" -OutputType PSObject -ThrowOnFailure
            $CatalogId = "$($Package.catalogId)"
            if ($CatalogId -and -not $CatalogNamesById.ContainsKey($CatalogId)) {
                try {
                    $Catalog = Invoke-EntraOpsMsGraphQuery -Uri "/beta/identityGovernance/entitlementManagement/accessPackageCatalogs/${CatalogId}?`$select=id,displayName" -OutputType PSObject -ThrowOnFailure
                    $CatalogNamesById[$CatalogId] = "$($Catalog.displayName)"
                } catch {
                    Write-Warning "Could not resolve access package catalog ${CatalogId}: $($_.Exception.Message)"
                    $CatalogNamesById[$CatalogId] = ''
                }
            }
            if ($CatalogId -and -not $CatalogResourcesByCatalogId.ContainsKey($CatalogId)) {
                $CatalogResourcesByOriginId = @{}
                try {
                    $CatalogResources = @(Invoke-EntraOpsMsGraphQuery -Uri "/beta/identityGovernance/entitlementManagement/accessPackageCatalogs/${CatalogId}/accessPackageResources?`$select=id,displayName,resourceType,originId,originSystem" -OutputType PSObject -ThrowOnFailure)
                    foreach ($CatalogResource in $CatalogResources | Where-Object { $_.originId }) {
                        $CatalogResourcesByOriginId["$($CatalogResource.originId)"] = $CatalogResource
                    }
                } catch {
                    Write-Warning "Could not resolve catalog resources for access package catalog ${CatalogId}: $($_.Exception.Message)"
                }
                $CatalogResourcesByCatalogId[$CatalogId] = $CatalogResourcesByOriginId
            }
            $ResourceRoleScopes = @()
            try {
                $HydratedPackage = Invoke-EntraOpsMsGraphQuery -Uri "/beta/identityGovernance/entitlementManagement/accessPackages/${PackageId}?`$expand=accessPackageResourceRoleScopes(`$expand=accessPackageResourceRole,accessPackageResourceScope)" -OutputType PSObject -ThrowOnFailure
                $ResourceRoleScopes = @($HydratedPackage.accessPackageResourceRoleScopes)
            } catch {
                Write-Verbose "Nested access package scope expansion failed for ${PackageId}; querying the resource-role-scope collection instead."
                $ResourceRoleScopes = @(Invoke-EntraOpsMsGraphQuery -Uri "/beta/identityGovernance/entitlementManagement/accessPackages/${PackageId}/accessPackageResourceRoleScopes?`$expand=accessPackageResourceRole,accessPackageResourceScope" -OutputType PSObject -ThrowOnFailure)
            }
            $Targets = @(
                foreach ($Scope in $ResourceRoleScopes) {
                    $ResourceScope = $Scope.accessPackageResourceScope
                    $ResourceRole = $Scope.accessPackageResourceRole
                    $OriginId = "$($ResourceScope.originId)"
                    $CatalogResource = if ($CatalogId -and $CatalogResourcesByCatalogId.ContainsKey($CatalogId)) { $CatalogResourcesByCatalogId[$CatalogId][$OriginId] } else { $null }
                    $ResourceDisplayName = "$($CatalogResource.displayName)"
                    if (-not $ResourceDisplayName) { $ResourceDisplayName = "$($ResourceScope.displayName)" }
                    if ("$($ResourceScope.originSystem)" -eq 'AadGroup' -and $OriginId) { [void]$GroupIds.Add($OriginId) }
                    [ordered]@{
                        originId     = $OriginId
                        displayName  = $ResourceDisplayName
                        role         = "$($ResourceRole.displayName)"
                        roleOriginId = "$($ResourceRole.originId)"
                        originSystem = "$($ResourceScope.originSystem)"
                        resourceType = if ($CatalogResource.resourceType) { "$($CatalogResource.resourceType)" } else { "$($ResourceScope.originSystem)" }
                    }
                }
            )
            $Packages[$PackageId] = [ordered]@{
                displayName = "$($Package.displayName)"
                catalogId   = $CatalogId
                catalogName = if ($CatalogId) { "$($CatalogNamesById[$CatalogId])" } else { '' }
                targets     = $Targets
            }
            try {
                $PackageAssignments = @(Invoke-EntraOpsMsGraphQuery -Uri "/beta/identityGovernance/entitlementManagement/accessPackageAssignments?`$filter=accessPackageId eq '${PackageId}'&`$expand=target" -OutputType PSObject -ThrowOnFailure)
                foreach ($Assignment in $PackageAssignments) {
                    $Target = $Assignment.target
                    $Assignments.Add([ordered]@{
                            id                 = "$($Assignment.id)"
                            accessPackageId    = "$($Assignment.accessPackageId)"
                            assignmentPolicyId = "$($Assignment.assignmentPolicyId)"
                            state              = "$($Assignment.state)"
                            status             = "$($Assignment.status)"
                            target             = [ordered]@{
                                objectId      = "$($Target.objectId)"
                                displayName   = "$($Target.displayName)"
                                principalName = "$($Target.principalName)"
                                subjectType   = "$($Target.subjectType)"
                            }
                        })
                }
            } catch {
                Write-Warning "Could not resolve current assignments for access package ${PackageId}: $($_.Exception.Message)"
            }
        } catch {
            Write-Warning "Could not resolve access package ${PackageId}: $($_.Exception.Message)"
        }
    }

    if ($ResolveRequestorApproverTiers -and (Test-Path -LiteralPath $PrivilegedEamPath -PathType Container)) {
        try {
            $ScopeClassifications = @(Get-EntraOpsIdGovScopeClassification -EntraOpsEamFolder $PrivilegedEamPath)
            foreach ($ScopeClassification in $ScopeClassifications | Where-Object { $_.ScopeType -eq 'AccessPackage' -and $_.ScopeId -match '^/AccessPackage/' }) {
                $ClassifiedPackageId = "$($ScopeClassification.ScopeId)" -replace '^/AccessPackage/', ''
                if (-not $Packages.Contains($ClassifiedPackageId)) { continue }
                foreach ($Target in @($Packages[$ClassifiedPackageId].targets)) {
                    $MatchedDetails = @($ScopeClassification.ClassifiedResources | Where-Object {
                            ($Target.originId -and "$($_.ResourceId)" -ieq "$($Target.originId)") -or
                            ($Target.roleOriginId -and "$($_.ResourceId)" -ieq "$($Target.roleOriginId)")
                        })
                    if ($MatchedDetails.Count -eq 0) { continue }
                    $BestTier = @($MatchedDetails.EAMTier | Where-Object { $TierRank.ContainsKey("$_") } | Sort-Object { $TierRank["$_"] } | Select-Object -First 1)[0]
                    if (-not $BestTier) { continue }
                    $Target['tierName'] = "$BestTier"
                    $Target['classificationReason'] = @($MatchedDetails | Where-Object { "$($_.EAMTier)" -eq "$BestTier" } | ForEach-Object { "$($_.Reason)" } | Select-Object -Unique) -join '; '
                }
            }
        } catch {
            Write-Warning "Could not resolve access package target classifications: $($_.Exception.Message)"
        }
    }

    $ResolvedGroupTiers = [ordered]@{}
    if ($ResolveRequestorApproverTiers) {
        foreach ($GroupId in $GroupIds) {
            try {
                $Group = Invoke-EntraOpsMsGraphQuery -Uri "/v1.0/groups/${GroupId}?`$select=id,displayName" -OutputType PSObject -ThrowOnFailure
                $Members = @(Get-EntraOpsPrivilegedTransitiveGroupMember -GroupObjectId $GroupId | Where-Object { $null -ne $_ })
                $PrivilegedMembers = @($Members | Where-Object { $TierByObjectId.ContainsKey("$($_.Id)") })
                $BestTier = @($PrivilegedMembers | ForEach-Object { $TierByObjectId["$($_.Id)"] } | Sort-Object { $TierRank[$_] } | Select-Object -First 1)[0]
                if (-not $BestTier) { $BestTier = 'UserAccess' }
                $MemberTiers = @(
                    foreach ($Member in $Members) {
                        if (-not $Member.Id) { continue }
                        [ordered]@{
                            id          = "$($Member.Id)"
                            displayName = "$($Member.DisplayName)"
                            tierName    = if ($TierByObjectId.ContainsKey("$($Member.Id)")) { $TierByObjectId["$($Member.Id)"] } else { 'UserAccess' }
                        }
                    }
                )
                $ResolvedGroupTiers[$GroupId] = [ordered]@{
                    tierName              = $BestTier
                    displayName           = "$($Group.displayName)"
                    totalMembers          = $Members.Count
                    privilegedMemberCount = $PrivilegedMembers.Count
                    members               = $MemberTiers
                }
            } catch {
                Write-Warning "Could not resolve transitive members of access package group ${GroupId}: $($_.Exception.Message)"
            }
        }
    }

    $Payload = [ordered]@{
        generatedAt              = (Get-Date).ToUniversalTime().ToString('o')
        policyRequestorApprovers = $PolicyRequestorApprovers
        packages                 = $Packages
        resolvedGroupTiers       = $ResolvedGroupTiers
        assignments              = @($Assignments)
    }
    $Content = "// Auto-generated by New-EntraOpsAccessPackageFlowData - do not edit by hand.`nwindow.ENTRAOPS_ACCESSPACKAGE_ASSIGNMENTS = $($Payload | ConvertTo-Json -Depth 20 -Compress);`n"
    if ($PSCmdlet.ShouldProcess($OutFile, 'Write Access Package Flow enrichment dataset')) {
        Save-EntraOpsReportDataFile -Content $Content -LiteralPath $OutFile
    }
    if ($PassThru) { [pscustomobject]$Payload }
}