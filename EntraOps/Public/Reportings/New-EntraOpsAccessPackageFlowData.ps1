<#
.SYNOPSIS
    Generate live Microsoft Graph enrichment data for the Access Package Flow report.

.DESCRIPTION
    Recovers information omitted by Tenant Governance snapshots: groupMembers user-set IDs,
    access package resource-role scopes, and current package assignments. The generated data is
    merged with the snapshot-only Configuration Analyzer dataset by the static report.

    It also reads the access drift of the governed groups and applications (Microsoft Entra ID Governance >
    Access Guardian > Reports > Access Drift, Microsoft Graph beta accessDriftSummary): members or application
    role assignments without an access package assignment (unauthorized) and access package assignments without
    the expected membership (missing), with up to five examples per resource. The access drift report is in
    preview, needs a Microsoft Entra ID Governance or Microsoft Entra Suite license and EntitlementManagement.Read.All,
    and is refreshed about once a day. When it cannot be read, accessDrift.status is 'unavailable' with the reason,
    and the access drift finding rule is skipped.

    The declared tiers of the target groups are written as objectClassifications, in the order of the Privileged EAM
    classification: the Group filters of the Alternate Tier Level Attributes (AlternateObjectTierLevelAttributes.Group,
    evaluated with Get-EntraOpsPrivilegedEntraObject, so the filters see the same details as in Privileged EAM), then
    the Object Classification File (ObjectClassificationFile). The findings use them for groups without role
    assignments, whose tier the Privileged EAM data cannot tell; declaredBy names the source and justification the
    reason.

.PARAMETER RepoRoot
    Root of the EntraOps working folder with TenantGovernance/Snapshots, PrivilegedEAM and EntraOpsConfig.json (alias: -Path).
    Defaults to the EntraOps working folder ($EntraOpsBaseFolder).

.PARAMETER SnapshotPath
    Folder of the Tenant Governance snapshots. Defaults to <RepoRoot>/TenantGovernance/Snapshots. The folder must
    exist; run Save-EntraOpsTenantGovernanceSnapshotJson first.

.PARAMETER AppRoot
    Folder of the Access Package Flow reporting app. Defaults to <RepoRoot>/Reports/AccessPackageFlow.

.PARAMETER OutFile
    Path of the generated data file. Defaults to <AppRoot>/data/access-package-assignments-data.js.

.PARAMETER ResolveRequestorApproverTiers
    Resolves the tiers of requestor and approver groups through transitive group membership and the Privileged EAM
    export in <RepoRoot>/PrivilegedEAM, and the classification of access package targets. Defaults to
    ConfigurationAnalyzer.ResolveGroupMembersForPrivilegedAssets of <RepoRoot>/EntraOpsConfig.json (true when not set).

.PARAMETER PassThru
    Returns the generated dataset in addition to writing the data file.

.EXAMPLE
    Generate the Access Package Flow enrichment data from the snapshots in the EntraOps working folder.
    New-EntraOpsAccessPackageFlowData

.EXAMPLE
    Generate the data without resolving group tiers and return the dataset.
    New-EntraOpsAccessPackageFlowData -ResolveRequestorApproverTiers $false -PassThru
#>

function New-EntraOpsAccessPackageFlowData {

    [CmdletBinding(SupportsShouldProcess = $true)]
    param (
        [Parameter(Mandatory = $false)]
        [Alias('Path')]
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
    $Config = $null
    $ConfigFilePath = Join-Path $RepoRoot 'EntraOpsConfig.json'
    if (Test-Path -LiteralPath $ConfigFilePath -PathType Leaf) {
        try {
            $Config = Get-Content -LiteralPath $ConfigFilePath -Raw | ConvertFrom-Json
        } catch {
            Write-Warning "Failed to read ConfigurationAnalyzer settings from ${ConfigFilePath}: $($_.Exception.Message). Group tier resolution remains enabled and the Object Classification File is not used."
        }
    }
    if (-not $PSBoundParameters.ContainsKey('ResolveRequestorApproverTiers')) {
        $ResolveRequestorApproverTiers = $true
        if ($null -ne $Config -and $null -ne $Config.ConfigurationAnalyzer -and $null -ne $Config.ConfigurationAnalyzer.ResolveGroupMembersForPrivilegedAssets) {
            $ResolveRequestorApproverTiers = [bool]$Config.ConfigurationAnalyzer.ResolveGroupMembersForPrivilegedAssets
        }
    }

    # The Object Classification File (ObjectClassificationFile of EntraOpsConfig.json) declares the tier of objects. A
    # group without role assignments has no classification in the Privileged EAM data: the findings classify such an
    # access package target by its declared tier (objectClassifications), and leave it unclassified without one.
    $ObjectClassificationEntries = @{}
    $ObjectClassificationSetting = if ($null -ne $Config) { $Config.ObjectClassificationFile } else { $null }
    if ($null -ne $ObjectClassificationSetting -and $ObjectClassificationSetting.Enabled -eq $true -and -not [string]::IsNullOrWhiteSpace($ObjectClassificationSetting.FilePath)) {
        try {
            $ObjectClassificationEntries = Import-EntraOpsObjectClassificationFile -FilePath $ObjectClassificationSetting.FilePath -RootFolder $RepoRoot
        } catch {
            Write-Warning "The Object Classification File could not be read: $($_.Exception.Message) Access package target groups without role assignments stay unclassified."
        }
    }
    $ObjectClassifications = [ordered]@{}
    # The Group filters of the Alternate Tier Level Attributes classify groups before the Object Classification File,
    # as in Privileged EAM (custom security attributes don't exist for groups).
    $GroupFilterSetting = if ($null -ne $Config) { $Config.AlternateObjectTierLevelAttributes } else { $null }
    $UseGroupFilters = $null -ne $GroupFilterSetting -and (Test-EntraOpsAlternateObjectTierLevelEnabled -ObjectType 'Group' -AlternateObjectTierLevelAttributes $GroupFilterSetting)
    $GroupFilterTiers = @{}
    function Get-GroupFilterTier([string]$GroupId) {
        $Key = $GroupId.ToLowerInvariant()
        if (-not $GroupFilterTiers.ContainsKey($Key)) {
            $GroupFilterTiers[$Key] = $null
            try {
                $GroupObject = Get-EntraOpsPrivilegedEntraObject -AadObjectId $GroupId -AlternateObjectTierLevelAttributes $GroupFilterSetting -ObjectClassificationFile $null -CustomSecurityAttributeClassification $false -ErrorAction Stop
                if ($null -ne $GroupObject -and "$($GroupObject.ObjectType)" -eq 'group' -and "$($GroupObject.AdminTierLevelName)" -notin @('', 'Unclassified')) { $GroupFilterTiers[$Key] = "$($GroupObject.AdminTierLevelName)" }
            } catch {
                Write-Warning "The Alternate Tier Level Attributes of the access package target group $GroupId could not be evaluated: $($_.Exception.Message)"
            }
        }
        $GroupFilterTiers[$Key]
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
    $PrivilegedEamObjects = $null
    if ($ResolveRequestorApproverTiers) {
        $PrivilegedEamPath = Join-Path $RepoRoot 'PrivilegedEAM'
        if (Test-Path -LiteralPath $PrivilegedEamPath -PathType Container) {
            $PrivilegedEamObjects = Get-EntraOpsPrivilegedEamDashboardObjects -ImportPath $PrivilegedEamPath
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

    # The groups of the Privileged EAM data have role assignments, which classify them: only the other target groups
    # are evaluated by the Group filters (one Get-EntraOpsPrivilegedEntraObject per group).
    $EamObjectIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    if ($UseGroupFilters) {
        $EamPath = Join-Path $RepoRoot 'PrivilegedEAM'
        if ($null -eq $PrivilegedEamObjects -and (Test-Path -LiteralPath $EamPath -PathType Container)) { $PrivilegedEamObjects = Get-EntraOpsPrivilegedEamDashboardObjects -ImportPath $EamPath }
        foreach ($Object in @($PrivilegedEamObjects)) { if ("$($Object.objectId)") { [void]$EamObjectIds.Add("$($Object.objectId)") } }
    }

    $PolicyRequestorApprovers = [ordered]@{}
    $PackageIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $GroupIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    # Inside New-EntraOpsReportingData the run's cache is used, which the Configuration Analyzer data shares: a deleted
    # policy is requested and reported once per run. Called on its own, this generator reports them.
    $OwnsReportingRunCache = Start-EntraOpsReportingRunCache
    foreach ($PolicyId in $PolicyIds) {
        try {
            # $null for a deleted policy, which is reported once per run by Complete-EntraOpsReportingRunCache
            $Policy = Get-EntraOpsAccessPackageAssignmentPolicyForReport -PolicyId $PolicyId
            if ($null -eq $Policy) { continue }
            $Requestors = @($Policy.requestorSettings.allowedRequestors)
            $Approvers = @($Policy.requestApprovalSettings.approvalStages | ForEach-Object { $_.primaryApprovers })
            # The legacy beta policy has no expiration pattern: v1.0 has it (noExpiration, notSpecified, afterDateTime or
            # afterDuration, also in hours), which tells EO.6005 a fixed date or hours from a policy that never expires.
            $LiveExpiration = $null
            try {
                $V1Policy = Invoke-EntraOpsMsGraphQuery -Uri "/v1.0/identityGovernance/entitlementManagement/assignmentPolicies/${PolicyId}?`$select=id,expiration" -OutputType PSObject -ThrowOnFailure -SuppressNotFoundWarning
                if ($null -ne $V1Policy -and $null -ne $V1Policy.expiration -and "$($V1Policy.expiration.type)") {
                    $LiveExpiration = [ordered]@{
                        type        = "$($V1Policy.expiration.type)"
                        endDateTime = $(if ($null -ne $V1Policy.expiration.endDateTime) { "$($V1Policy.expiration.endDateTime)" } else { $null })
                        duration    = $(if ($null -ne $V1Policy.expiration.duration) { "$($V1Policy.expiration.duration)" } else { $null })
                    }
                }
            } catch {
                Write-Verbose "Could not read the expiration of access package assignment policy $PolicyId from Microsoft Graph v1.0: $($_.Exception.Message)"
            }
            # Without it, a fixed date or a number of days of the legacy policy is still an expiration.
            if ($null -eq $LiveExpiration -and "$($Policy.expirationDateTime)") {
                $LiveExpiration = [ordered]@{ type = 'afterDateTime'; endDateTime = "$($Policy.expirationDateTime)"; duration = $null }
            } elseif ($null -eq $LiveExpiration -and "$($Policy.durationInDays)" -match '^\d+$' -and [int]"$($Policy.durationInDays)" -gt 0) {
                $LiveExpiration = [ordered]@{ type = 'afterDuration'; endDateTime = $null; duration = "P$([int]"$($Policy.durationInDays)")D" }
            }
            $PolicyRequestorApprovers[$PolicyId] = [ordered]@{
                accessPackageId = "$($Policy.accessPackageId)"
                scopeType       = "$($Policy.requestorSettings.scopeType)"
                requestors      = $Requestors
                approvers       = $Approvers
                expiration      = $LiveExpiration
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
    if ($OwnsReportingRunCache) { Complete-EntraOpsReportingRunCache }

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
                    if ("$($ResourceScope.originSystem)" -eq 'AadGroup' -and $OriginId) {
                        # The roll-up of a target group only lists its current members; it never sets the tier of the target.
                        [void]$GroupIds.Add($OriginId)
                        if (-not $ObjectClassifications.Contains($OriginId)) {
                            $FilterTier = if ($UseGroupFilters -and -not $EamObjectIds.Contains($OriginId) -and $OriginId -match '^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$') { Get-GroupFilterTier $OriginId } else { $null }
                            $Declared = $ObjectClassificationEntries[$OriginId.ToLowerInvariant()]
                            if ($FilterTier) {
                                $ObjectClassifications[$OriginId] = [ordered]@{ tierName = $FilterTier; justification = "Group filter for $FilterTier in AlternateObjectTierLevelAttributes of EntraOpsConfig.json"; declaredBy = 'Alternate Tier Level Attributes' }
                            } elseif ($null -ne $Declared -and (-not $Declared.ObjectType -or $Declared.ObjectType -eq 'group')) {
                                $ObjectClassifications[$OriginId] = [ordered]@{ tierName = $Declared.AdminTierLevelName; justification = $Declared.Justification; declaredBy = 'Object Classification File' }
                            }
                        }
                    }
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
                    # The beta accessPackageAssignment exposes assignmentState/assignmentStatus and
                    # target.type; v1.0 names them state/status and target.subjectType.
                    $AssignmentState = if ($Assignment.assignmentState) { $Assignment.assignmentState } else { $Assignment.state }
                    $AssignmentStatus = if ($Assignment.assignmentStatus) { $Assignment.assignmentStatus } else { $Assignment.status }
                    $SubjectType = if ($Target.type) { $Target.type } else { $Target.subjectType }
                    $Assignments.Add([ordered]@{
                            id                 = "$($Assignment.id)"
                            accessPackageId    = "$($Assignment.accessPackageId)"
                            assignmentPolicyId = "$($Assignment.assignmentPolicyId)"
                            state              = "$AssignmentState"
                            status             = "$AssignmentStatus"
                            target             = [ordered]@{
                                objectId      = "$($Target.objectId)"
                                displayName   = "$($Target.displayName)"
                                principalName = "$($Target.principalName)"
                                subjectType   = "$SubjectType"
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
                            # user, servicePrincipal or group (a nested group: its members are listed as well).
                            objectType  = "$($Member.'@odata.type')" -replace '^#microsoft\.graph\.', ''
                        }
                    }
                )
                $ResolvedGroupTiers[$GroupId] = [ordered]@{
                    tierName              = $BestTier
                    displayName           = "$($Group.displayName)"
                    totalMembers          = $Members.Count
                    # Members that can act themselves (users and service principals, not nested groups).
                    principalCount        = @($Members | Where-Object { "$($_.'@odata.type')" -ne '#microsoft.graph.group' }).Count
                    privilegedMemberCount = $PrivilegedMembers.Count
                    members               = $MemberTiers
                }
            } catch {
                Write-Warning "Could not resolve transitive members of access package group ${GroupId}: $($_.Exception.Message)"
            }
        }
    }

    # Access drift of the governed groups and applications (preview, Microsoft Graph beta). The summaries list only
    # resources with drift; $expand=details adds up to five drift details per resource.
    $DriftResources = [System.Collections.Generic.List[object]]::new()
    $DriftStatus = 'collected'
    $DriftReason = ''
    foreach ($DriftResourceType in 'group', 'application') {
        try {
            $Filter = [uri]::EscapeDataString("resource/type eq '$DriftResourceType' and driftSource eq 'entra'")
            $Summaries = @(Invoke-EntraOpsMsGraphQuery -Uri "/beta/identityGovernance/insights/accessDriftSummary?`$filter=$Filter&`$expand=details&`$top=100" -OutputType PSObject -ThrowOnFailure -SuppressForbiddenWarning -SuppressBadRequestWarning -SuppressNotFoundWarning)
        } catch {
            $DriftStatus = 'unavailable'
            $DriftReason = $_.Exception.Message
            Write-Warning "Access drift could not be read from Microsoft Graph (needs Microsoft Entra ID Governance or Microsoft Entra Suite and EntitlementManagement.Read.All): $DriftReason"
            break
        }
        foreach ($Summary in $Summaries | Where-Object { $null -ne $_ -and $_.resource.identifier }) {
            $DriftResources.Add([ordered]@{
                    id              = "$($Summary.id)"
                    resourceId      = "$($Summary.resource.identifier)"
                    resourceName    = "$($Summary.resource.displayName)"
                    resourceType    = "$($Summary.resource.type)"
                    catalogId       = "$($Summary.resource.catalogIdentifier)"
                    catalogName     = "$($Summary.resource.catalogName)"
                    total           = [int]$Summary.driftCounts.total
                    unauthorized    = [int]$Summary.driftCounts.unauthorized
                    missing         = [int]$Summary.driftCounts.missing
                    # ISO 8601 also when Graph returned the value as a date (the culture would format it otherwise).
                    createdDateTime = $(if ($Summary.createdDateTime -is [datetime]) { $Summary.createdDateTime.ToUniversalTime().ToString('o', [cultureinfo]::InvariantCulture) } else { "$($Summary.createdDateTime)" })
                    details         = @(foreach ($Detail in @($Summary.details | Where-Object { $null -ne $_ })) {
                            [ordered]@{
                                driftType         = "$($Detail.driftType)"
                                assignedRole      = "$($Detail.assignedRole)"
                                expectedRole      = "$($Detail.expectedRole)"
                                accessPackageId   = "$($Detail.accessPackage.identifier)"
                                accessPackageName = "$($Detail.accessPackage.displayName)"
                                identities        = @(foreach ($Identity in @($Detail.identities | Where-Object { $null -ne $_ })) {
                                        [ordered]@{ id = "$($Identity.identifier)"; principalName = "$($Identity.principalName)"; displayName = "$($Identity.displayName)"; identityType = "$($Identity.identityType)" }
                                    })
                            }
                        })
                })
        }
    }

    $Payload = [ordered]@{
        generatedAt              = (Get-Date).ToUniversalTime().ToString('o')
        policyRequestorApprovers = $PolicyRequestorApprovers
        packages                 = $Packages
        resolvedGroupTiers       = $ResolvedGroupTiers
        # Declared tiers of the target groups (Object Classification File), by group ID.
        objectClassifications    = $ObjectClassifications
        assignments              = @($Assignments)
        accessDrift              = [ordered]@{
            status    = $DriftStatus
            reason    = $DriftReason
            # @(if ...) keeps a single resource an array.
            resources = @(if ($DriftStatus -eq 'collected') { $DriftResources })
        }
    }
    $Content = "// Auto-generated by New-EntraOpsAccessPackageFlowData - do not edit by hand.`nwindow.ENTRAOPS_ACCESSPACKAGE_ASSIGNMENTS = $($Payload | ConvertTo-Json -Depth 20 -Compress);`n"
    if ($PSCmdlet.ShouldProcess($OutFile, 'Write Access Package Flow enrichment dataset')) {
        Save-EntraOpsReportDataFile -Content $Content -LiteralPath $OutFile
    }
    if ($PassThru) { [pscustomobject]$Payload }
}