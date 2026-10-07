<#
.SYNOPSIS
    Creates assignment policies for each service access package.

.DESCRIPTION
    Creates one assignment policy per access package in the catalog. Policies
    define requestor settings (self-add/remove enabled), reviewer settings
    (quarterly reviews, WorkloadPlane-Admins as reviewer of the WorkloadPlane-Users
    policies, ControlPlane-Admins as reviewer of the ManagementPlane-Admins policies, ManagementPlane-Admins
    as reviewer of all other policies, CatalogPlane-Members as last fallback reviewer), and expiration settings.
    Requests for privileged access packages are only approved by the same or a higher tier; CatalogPlane-Members
    only approve their own access package. Reviewers are configurable per policy in
    ServiceEM.AccessReviews.Policies.<Policy> (Group, SelfReview, SpecificReviewers or Manager). Assignments of all policies expire after 365 days
    by default, configurable per policy in ServiceEM.AssignmentPolicies.<Policy>.Expiration.

    Idempotent: existing policies with matching display names are reused.

.PARAMETER ServiceName
    Name of the service. Used in verbose logging and policy lookups.

.PARAMETER ServiceCatalogId
    Object ID of the Entitlement Management catalog.

.PARAMETER ServiceGroups
    Entra group objects. Used to resolve the CatalogPlane-Members and
    ManagementPlane-Admins groups for reviewer assignments.

.PARAMETER ServicePackages
    Access package objects returned by New-EntraOpsServiceEMAccessPackage.

.PARAMETER logPrefix
    Text prepended to verbose messages. Defaults to the function name.

.EXAMPLE
    New-EntraOpsServiceEMAssignmentPolicy `
        -ServiceName "MyService" `
        -ServiceCatalogId "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" `
        -ServiceGroups $groups `
        -ServicePackages $packages

    Creates assignment policies for all non-Unified access packages in the
    MyService catalog, wiring up reviewers from the CatalogPlane-Members and
    ManagementPlane-Admins groups.

#>
function New-EntraOpsServiceEMAssignmentPolicy {
    [OutputType([psobject[]])]
    [cmdletbinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ServiceName,

        [Parameter(Mandatory)]
        [string]$ServiceCatalogId,

        [Parameter(Mandatory)]
        [psobject[]]$ServiceGroups,

        [Parameter(Mandatory)]
        [psobject[]]$ServicePackages,

        [string]$logPrefix = "[$($MyInvocation.MyCommand)]"
    )

    begin {
        $policies = @()
        $assignmentPolicyUri = "/v1.0/identityGovernance/entitlementManagement/assignmentPolicies?`$filter=catalog/id eq '$ServiceCatalogId'&`$expand=accessPackage,catalog"
        try{
            Write-Verbose "$logPrefix Looking up Assignment Policy"
            $policies += Invoke-EntraOpsMsGraphQuery -Method GET -Uri $assignmentPolicyUri -OutputType PSObject -DisableCache
        }catch{
            Write-Error $_
        }
        $catalogPlaneMembersGroupId = ($ServiceGroups|Where-Object{$_.DisplayName -like "*CatalogPlane-Members"}).Id
        # Delegated (tenant-wide or other landing zone) groups are injected by name into ServiceGroups
        $mgmtApproverGroupId = ($ServiceGroups | Where-Object { $_.DisplayName -like "*ManagementPlane-Admins" } | Select-Object -First 1).Id
        $controlPlaneApproverId = ($ServiceGroups | Where-Object { $_.DisplayName -like "*ControlPlane-Admins" } | Select-Object -First 1).Id
        $wlUsersApproverId = ($ServiceGroups | Where-Object { $_.DisplayName -like "*WorkloadPlane-Admins" } | Select-Object -First 1).Id
        if (-not $wlUsersApproverId) { $wlUsersApproverId = $mgmtApproverGroupId }

        # Defaults can be overridden in ServiceEM.AssignmentPolicies and ServiceEM.AccessReviews of EntraOpsConfig
        $serviceEMConfig = if ($null -ne $Global:EntraOpsConfig) { $Global:EntraOpsConfig.ServiceEM }
        $defaultExpiration = 'P365D'
        $getPolicySetting = {
            param([string]$PolicyKey, [string]$Setting, $Default)
            $value = $serviceEMConfig.AssignmentPolicies.$PolicyKey.$Setting
            if ($null -eq $value -or [string]::IsNullOrWhiteSpace([string]$value)) { return $Default }
            return $value
        }
        $getExpiration = {
            param([string]$PolicyKey, [string]$Default)
            $value = [string](& $getPolicySetting $PolicyKey 'Expiration' $Default)
            if ($value -eq 'noExpiration') { return @{ type = 'noExpiration' } }
            if ($value -notmatch '^P(?=\d|T\d)(\d+Y)?(\d+M)?(\d+W)?(\d+D)?(T(?=\d)(\d+H)?(\d+M)?(\d+S)?)?$') {
                throw "Invalid ServiceEM.AssignmentPolicies.$PolicyKey.Expiration '$value' in EntraOpsConfig. Use 'noExpiration' or an ISO 8601 duration such as 'P90D'."
            }
            return @{ type = 'afterDuration'; duration = $value }
        }
        $getApprovalTimeout = {
            param([string]$PolicyKey, [string]$Default)
            $value = [string](& $getPolicySetting $PolicyKey 'ApprovalTimeout' $Default)
            if ($value -notmatch '^P\d+D$') {
                throw "Invalid ServiceEM.AssignmentPolicies.$PolicyKey.ApprovalTimeout '$value' in EntraOpsConfig. Use a duration in days such as 'P2D'."
            }
            return $value
        }
        # Users may extend expiring assignments of the standard request policies; extensions always need approval
        $setExtension = {
            param([hashtable]$Params, [string]$PolicyKey)
            $allowExtension = (& $getPolicySetting $PolicyKey 'AllowExtension' $true) -and $Params.expiration.type -ne 'noExpiration'
            $Params.requestorSettings = $Params.requestorSettings.Clone()
            $Params.requestorSettings.enableTargetsToSelfUpdateAccess = $allowExtension
            $Params.requestApprovalSettings = $Params.requestApprovalSettings.Clone()
            $Params.requestApprovalSettings.isApprovalRequiredForUpdate = $allowExtension
        }
        $accessReviewConfig = $serviceEMConfig.AccessReviews
        $enableAccessReviews = if ($null -ne $accessReviewConfig.EnableAccessReviews) { [bool]$accessReviewConfig.EnableAccessReviews } else { $true }
        $reviewIntervalInMonths = if ($null -ne $accessReviewConfig.RecurrenceIntervalInMonths) { [int]$accessReviewConfig.RecurrenceIntervalInMonths } else { 3 }
        $reviewStartAfterDays = if ($null -ne $accessReviewConfig.StartAfterDays) { [int]$accessReviewConfig.StartAfterDays } else { 4 }
        $reviewDuration = if (-not [string]::IsNullOrWhiteSpace([string]$accessReviewConfig.ReviewDuration)) { [string]$accessReviewConfig.ReviewDuration } else { 'P25D' }
        if ($reviewIntervalInMonths -lt 1 -or $reviewIntervalInMonths -gt 12) {
            throw "Invalid ServiceEM.AccessReviews.RecurrenceIntervalInMonths '$reviewIntervalInMonths' in EntraOpsConfig. Use a value from 1 to 12."
        }
        if ($reviewStartAfterDays -lt 0) {
            throw "Invalid ServiceEM.AccessReviews.StartAfterDays '$reviewStartAfterDays' in EntraOpsConfig. Use 0 or a positive number of days."
        }
        if ($reviewDuration -notmatch '^P\d+D$') {
            throw "Invalid ServiceEM.AccessReviews.ReviewDuration '$reviewDuration' in EntraOpsConfig. Use a duration in days such as 'P25D'."
        }
        $guidPattern = '^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$'
        $reviewerTiers = @('WorkloadPlane-Admins', 'ManagementPlane-Admins', 'ControlPlane-Admins')
        # Group reviewers are service group name suffixes (e.g. WorkloadPlane-Admins) or group object IDs
        $resolveReviewerGroups = {
            param([string]$PolicyKey, [string[]]$Values)
            foreach ($value in $Values) {
                if ($value -match $guidPattern) {
                    @{ "@odata.type" = "#microsoft.graph.groupMembers"; groupId = $value }
                    continue
                }
                # A missing admin group falls back to the same or a higher tier only
                $candidates = if ($value -in $reviewerTiers) { $reviewerTiers[$reviewerTiers.IndexOf($value)..($reviewerTiers.Count - 1)] } else { @($value) }
                $groupId = $null
                foreach ($candidate in $candidates) {
                    $groupId = ($ServiceGroups | Where-Object { $_.DisplayName -like "*$candidate" } | Select-Object -First 1).Id
                    if ($groupId) { break }
                }
                if ($groupId) {
                    @{ "@odata.type" = "#microsoft.graph.groupMembers"; groupId = $groupId }
                } else {
                    Write-Verbose "$logPrefix No reviewer group '$value' or a higher tier found for $PolicyKey"
                }
            }
        }
        $reviewSettingsByPolicy = @{}
        foreach ($reviewPolicyKey in 'BaselinePolicy', 'WorkloadPlaneUsers', 'WorkloadPlaneAdmins', 'ManagementPlaneAdmins', 'InitialWorkloadMembership', 'InitialManagementAdmins', 'InitialWorkloadUsers', 'InitialWorkloadAdmins', 'InitialCatalogMembers') {
            if (-not $enableAccessReviews) { break }
            $reviewerConfig = $accessReviewConfig.Policies.$reviewPolicyKey
            $reviewerType = if (-not [string]::IsNullOrWhiteSpace([string]$reviewerConfig.ReviewerType)) { [string]$reviewerConfig.ReviewerType } else { 'Group' }
            $reviewers = @($reviewerConfig.Reviewers | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } | ForEach-Object { ([string]$_).Trim() })
            $defaultReviewerGroup = switch ($reviewPolicyKey) {
                { $_ -in 'WorkloadPlaneUsers', 'InitialWorkloadUsers' } { 'WorkloadPlane-Admins'; break }
                { $_ -in 'ManagementPlaneAdmins', 'InitialManagementAdmins' } { 'ControlPlane-Admins'; break }
                default { 'ManagementPlane-Admins' }
            }
            $reviewerGroups = if ($reviewers.Count -gt 0) { $reviewers } else { @($defaultReviewerGroup) }
            $reviewSettings = @{
                isEnabled = $true
                expirationBehavior = "keepAccess"
                isRecommendationEnabled = $true
                isReviewerJustificationRequired = $true
                isSelfReview = $false
                schedule = @{
                    startDateTime = (Get-Date).AddDays($reviewStartAfterDays)
                    expiration = @{
                        duration = $reviewDuration
                        type = "afterDuration"
                    }
                    recurrence = @{
                        pattern = @{
                            type = "absoluteMonthly"
                            interval = $reviewIntervalInMonths
                            month = 0
                            dayOfMonth = 0
                        }
                        range = @{
                            type = "noEnd"
                        }
                    }
                }
            }
            switch ($reviewerType) {
                'Group' {
                    $reviewSettings.primaryReviewers = @(& $resolveReviewerGroups $reviewPolicyKey $reviewerGroups)
                    if ($reviewSettings.primaryReviewers.Count -eq 0) { $reviewSettings = $null }
                }
                'SelfReview' {
                    $reviewSettings.isSelfReview = $true
                    $reviewSettings.primaryReviewers = @()
                }
                'Manager' {
                    $reviewSettings.primaryReviewers = @(@{ "@odata.type" = "#microsoft.graph.requestorManager"; managerLevel = 1 })
                    $reviewSettings.fallbackReviewers = @(& $resolveReviewerGroups $reviewPolicyKey $reviewerGroups)
                }
                'SpecificReviewers' {
                    if ($reviewers.Count -eq 0) {
                        throw "ServiceEM.AccessReviews.Policies.$reviewPolicyKey.Reviewers in EntraOpsConfig needs at least one user object ID or UPN for ReviewerType 'SpecificReviewers'."
                    }
                    $reviewSettings.primaryReviewers = @(foreach ($reviewer in $reviewers) {
                            $userId = if ($reviewer -match $guidPattern) { $reviewer } else {
                                (Invoke-EntraOpsMsGraphQuery -Method GET -Uri "/v1.0/users/$([uri]::EscapeDataString($reviewer))?`$select=id" -OutputType PSObject).Id
                            }
                            if (-not $userId) {
                                throw "Reviewer '$reviewer' in ServiceEM.AccessReviews.Policies.$reviewPolicyKey.Reviewers of EntraOpsConfig not found."
                            }
                            @{ "@odata.type" = "#microsoft.graph.singleUser"; userId = $userId }
                        })
                }
                default {
                    throw "Invalid ServiceEM.AccessReviews.Policies.$reviewPolicyKey.ReviewerType '$reviewerType' in EntraOpsConfig. Use 'Group', 'SelfReview', 'SpecificReviewers' or 'Manager'."
                }
            }
            $reviewSettingsByPolicy[$reviewPolicyKey] = $reviewSettings
        }
        $setReviewSettings = {
            param([hashtable]$Params, [string]$PolicyKey)
            if (-not $enableAccessReviews) { return }
            if ($reviewSettingsByPolicy[$PolicyKey]) {
                $Params.reviewSettings = $reviewSettingsByPolicy[$PolicyKey]
            } else {
                Write-Warning "$logPrefix '$($Params.displayName)' is created without access review: no reviewer group of the configured or a higher tier in this scope."
            }
        }
        $wpUsersRequestorScope = [string](& $getPolicySetting 'WorkloadPlaneUsers' 'RequestorScope' 'AllMemberUsers')
        if ($wpUsersRequestorScope -notin @('AllMemberUsers', 'CatalogPlaneMembers')) {
            throw "Invalid ServiceEM.AssignmentPolicies.WorkloadPlaneUsers.RequestorScope '$wpUsersRequestorScope' in EntraOpsConfig. Use 'AllMemberUsers' or 'CatalogPlaneMembers'."
        }
        foreach ($extensionPolicyKey in 'BaselinePolicy', 'WorkloadPlaneUsers', 'WorkloadPlaneAdmins', 'ManagementPlaneAdmins') {
            $allowExtensionValue = & $getPolicySetting $extensionPolicyKey 'AllowExtension' $true
            if ($allowExtensionValue -isnot [bool]) {
                throw "Invalid ServiceEM.AssignmentPolicies.$extensionPolicyKey.AllowExtension '$allowExtensionValue' in EntraOpsConfig. Use true or false."
            }
        }
        $policyParams = @{
            requestorSettings = @{
                enableTargetsToSelfAddAccess = $true
                enableTargetsToSelfUpdateAccess = $false
                enableTargetsToSelfRemoveAccess = $true
                allowCustomAssignmentSchedule = $false
                enableOnBehalfRequestorsToAddAccess = $false
                enableOnBehalfRequestorsToUpdateAccess = $false
                enableOnBehalfRequestorsToRemoveAccess = $false
            }
            accessPackage = @{
                id = ""
            }
        }
        $baselinePolicyParams = @{
            displayName = "Baseline Policy"
            description = "The baseline policy for $ServiceName access packages."
            allowedTargetScope = "specificDirectoryUsers"
            specificAllowedTargets = @(
                @{
                    "@odata.type" = "#microsoft.graph.groupMembers"
                    groupId = $(($ServiceGroups|Where-Object{$_.DisplayName -like "*CatalogPlane-Members"}).Id)
                }
            )
            expiration = & $getExpiration 'BaselinePolicy' $defaultExpiration
            requestApprovalSettings = @{
                isApprovalRequiredForAdd = $true
                isApprovalRequiredForUpdate = $false
                stages = @(
                    @{
                        durationBeforeAutomaticDenial = & $getApprovalTimeout 'BaselinePolicy' 'P2D'
                        isApproverJustificationRequired = $true
                        isEscalationEnabled = $false
                        durationBeforeEscalation = "PT0S"
                        primaryApprovers = @(
                            @{
                                "@odata.type" = "#microsoft.graph.groupMembers"
                                groupId = $(($ServiceGroups|Where-Object{$_.DisplayName -like "*CatalogPlane-Members"}).Id)
                            }
                        )
                    }
                )
            }
        }
        $initialPolicyParams = @{
            displayName = "Initial Membership Policy"
            description = "The initial membership policy for $ServiceName."
            allowedTargetScope = "allMemberUsers"
            expiration = & $getExpiration 'InitialWorkloadMembership' $defaultExpiration
            requestApprovalSettings = @{
                isApprovalRequiredForAdd = $true
                isApprovalRequiredForUpdate = $false
                stages = @(
                    @{
                        durationBeforeAutomaticDenial = "P7D"
                        isApproverJustificationRequired = $true
                        isEscalationEnabled = $false
                        durationBeforeEscalation = "PT0S"
                        primaryApprovers = @(
                            @{
                                "@odata.type" = "#microsoft.graph.requestorManager"
                                managerLevel = 1
                            }
                        )
                        fallbackPrimaryApprovers = @(
                            @{
                                "@odata.type" = "#microsoft.graph.groupMembers"
                                groupId = $(($ServiceGroups|Where-Object{$_.DisplayName -like "*CatalogPlane-Members"}).Id)
                            }
                        )
                    },
                    @{
                        durationBeforeAutomaticDenial = "P14D"
                        isApproverJustificationRequired = $true
                        isEscalationEnabled = $false
                        durationBeforeEscalation = "PT0S"
                        primaryApprovers = @(
                            @{
                                "@odata.type" = "#microsoft.graph.groupMembers"
                                groupId = $(($ServiceGroups|Where-Object{$_.DisplayName -like "*CatalogPlane-Members"}).Id)
                            }
                        )
                    }
                )
            }
        }
        $workloadPlanePolicyParams = @{
            displayName = "Workload Plane Policy"
            description = "The Workload Plane Policy for $ServiceName access packages."
            allowedTargetScope = "specificDirectoryUsers"
            specificAllowedTargets = @(
                @{
                    "@odata.type" = "#microsoft.graph.groupMembers"
                    groupId = $(
                        $wlpMembersId = ($ServiceGroups|Where-Object{$_.DisplayName -like "*WorkloadPlane-Members"}).Id
                        if($wlpMembersId){ $wlpMembersId } else { ($ServiceGroups|Where-Object{$_.DisplayName -like "*CatalogPlane-Members"}).Id }
                    )
                }
            )
            expiration = & $getExpiration 'WorkloadPlaneAdmins' $defaultExpiration
            requestApprovalSettings = @{
                isApprovalRequiredForAdd = $true
                isApprovalRequiredForUpdate = $false
                stages = @(
                    @{
                        durationBeforeAutomaticDenial = & $getApprovalTimeout 'WorkloadPlaneAdmins' 'P2D'
                        isApproverJustificationRequired = $true
                        isEscalationEnabled = $false
                        durationBeforeEscalation = "PT0S"
                        primaryApprovers = @(
                            @{
                                "@odata.type" = "#microsoft.graph.groupMembers"
                                groupId = $mgmtApproverGroupId
                            }
                        )
                    }
                )
            }
        }

        # Admin-only direct assignment policies for the initial assignments made by New-EntraOpsServiceEMAssignment
        $adminOnlyRequestorSettings = @{
            enableTargetsToSelfAddAccess           = $false
            enableTargetsToSelfUpdateAccess        = $false
            enableTargetsToSelfRemoveAccess        = $false
            allowCustomAssignmentSchedule          = $false
            enableOnBehalfRequestorsToAddAccess    = $false
            enableOnBehalfRequestorsToUpdateAccess = $false
            enableOnBehalfRequestorsToRemoveAccess = $false
        }
        $initialDirectPolicies = @(
            [pscustomobject]@{ PackageFilter = "*WorkloadPlane-Users";  DisplayName = "Initial Workload Users Policy"; ConfigKey = "InitialWorkloadUsers" }
            [pscustomobject]@{ PackageFilter = "*WorkloadPlane-Admins"; DisplayName = "Initial Workload Admin Policy"; ConfigKey = "InitialWorkloadAdmins" }
            [pscustomobject]@{ PackageFilter = "*CatalogPlane-Members"; DisplayName = "Initial Catalog Members Policy"; ConfigKey = "InitialCatalogMembers" }
        )
        foreach ($initialDirectPolicy in $initialDirectPolicies) {
            $initialDirectPolicy | Add-Member -NotePropertyName Expiration -NotePropertyValue (& $getExpiration $initialDirectPolicy.ConfigKey $defaultExpiration)
        }
        if (-not $enableAccessReviews) {
            Write-Verbose "$logPrefix Access reviews disabled in ServiceEM.AccessReviews"
        }
    }

    process {
        Write-Verbose "$logPrefix Beginning EM Assignment Policy"

        foreach($package in $ServicePackages){
            $policyParams.accessPackage.id = $package.Id
            if($package.Id -notin $policies.AccessPackage.Id){
                try{
                    Write-Verbose "$logPrefix Assigning Policy for Access Package ID: $($package.Id)"
                    if($package.DisplayName -like "*WorkloadPlane-Members"){
                        $params = $policyParams + $initialPolicyParams
                        $params.displayName = "Initial Workload Membership Policy"
                        & $setReviewSettings $params 'InitialWorkloadMembership'
                        $policies += Invoke-EntraOpsMsGraphQuery -Method POST -Uri "/v1.0/identityGovernance/entitlementManagement/assignmentPolicies" -Body ($params | ConvertTo-Json -Depth 20) -OutputType PSObject
                    }elseif($package.displayName -like "*ManagementPlane-Admins"){
                        # Admin-only policy for the initial assignment of the workload plane admin; requests are disabled
                        $params = $initialPolicyParams.Clone()
                        $params.displayName = "Initial Management Admin Policy"
                        $params.requestApprovalSettings = @{
                            isApprovalRequiredForAdd = $false  # No approval needed for adminAdd
                            isApprovalRequiredForUpdate = $false
                        }
                        $params.expiration = & $getExpiration 'InitialManagementAdmins' $defaultExpiration
                        $params = $policyParams + $params
                        $params.requestorSettings = $adminOnlyRequestorSettings
                        & $setReviewSettings $params 'InitialManagementAdmins'
                        $policies += Invoke-EntraOpsMsGraphQuery -Method POST -Uri "/v1.0/identityGovernance/entitlementManagement/assignmentPolicies" -Body ($params | ConvertTo-Json -Depth 20) -OutputType PSObject
                    } elseif ($package.displayName -like "*WorkloadPlane-Admins" -and -not $mgmtApproverGroupId) {
                        Write-Verbose "$logPrefix Skipping Workload Plane Policy — no ManagementPlane-Admins approver for this scope"
                    }elseif($package.displayName -like "*WorkloadPlane-Admins"){
                        $params = $policyParams + $workloadPlanePolicyParams
                        & $setExtension $params 'WorkloadPlaneAdmins'
                        & $setReviewSettings $params 'WorkloadPlaneAdmins'
                        $policies += Invoke-EntraOpsMsGraphQuery -Method POST -Uri "/v1.0/identityGovernance/entitlementManagement/assignmentPolicies" -Body ($params | ConvertTo-Json -Depth 20) -OutputType PSObject
                    } elseif ($package.displayName -like "*WorkloadPlane-Users" -and -not $wlUsersApproverId) {
                        Write-Verbose "$logPrefix Skipping Workload Plane Users Policy — no WorkloadPlane-Admins or ManagementPlane-Admins approver for this scope"
                    }elseif($package.displayName -like "*WorkloadPlane-Users"){
                        $params = $baselinePolicyParams.Clone()
                        $params.displayName = "Workload Plane Users Policy"
                        $params.expiration = & $getExpiration 'WorkloadPlaneUsers' $defaultExpiration
                        if ($wpUsersRequestorScope -eq 'AllMemberUsers') {
                            $params.allowedTargetScope = "allMemberUsers"
                            $params.Remove('specificAllowedTargets')
                        }
                        $params.requestApprovalSettings = @{
                            isApprovalRequiredForAdd = $true
                            isApprovalRequiredForUpdate = $false
                            stages = @(
                                @{
                                    durationBeforeAutomaticDenial = & $getApprovalTimeout 'WorkloadPlaneUsers' 'P2D'
                                    isApproverJustificationRequired = $true
                                    isEscalationEnabled = $false
                                    durationBeforeEscalation = "PT0S"
                                    primaryApprovers = @(
                                        @{
                                            "@odata.type" = "#microsoft.graph.groupMembers"
                                            groupId       = $wlUsersApproverId
                                        }
                                    )
                                }
                            )
                        }
                        $params = $policyParams + $params
                        & $setExtension $params 'WorkloadPlaneUsers'
                        & $setReviewSettings $params 'WorkloadPlaneUsers'
                        $policies += Invoke-EntraOpsMsGraphQuery -Method POST -Uri "/v1.0/identityGovernance/entitlementManagement/assignmentPolicies" -Body ($params | ConvertTo-Json -Depth 20) -OutputType PSObject
                    }else{
                        $params = $policyParams + $baselinePolicyParams
                        & $setExtension $params 'BaselinePolicy'
                        & $setReviewSettings $params 'BaselinePolicy'
                        $policies += Invoke-EntraOpsMsGraphQuery -Method POST -Uri "/v1.0/identityGovernance/entitlementManagement/assignmentPolicies" -Body ($params | ConvertTo-Json -Depth 20) -OutputType PSObject
                    }
                } catch {
                    Write-Warning "$logPrefix Failed to create assignment policy for package '$($package.DisplayName)' (ID: $($package.Id)). Error: $_"
                }
            }

            # Self-service request of ManagementPlane-Admins by the administrator group, approved by ControlPlane-Admins.
            # Checked per policy name so existing landing zones get the policy on re-run.
            if ($package.DisplayName -like "*ManagementPlane-Admins" -and -not ($policies | Where-Object { $_.AccessPackage.Id -eq $package.Id -and $_.DisplayName -eq "Management Plane Policy" })) {
                if (-not $controlPlaneApproverId -or -not $catalogPlaneMembersGroupId) {
                    Write-Verbose "$logPrefix Skipping Management Plane Policy — no ControlPlane-Admins approver or CatalogPlane-Members requestor group for this scope"
                } else {
                    $params = $policyParams + @{
                        displayName             = "Management Plane Policy"
                        description             = "The Management Plane Policy for $ServiceName ManagementPlane-Admins access package."
                        allowedTargetScope      = "specificDirectoryUsers"
                        specificAllowedTargets  = @(
                            @{
                                "@odata.type" = "#microsoft.graph.groupMembers"
                                groupId       = $catalogPlaneMembersGroupId
                            }
                        )
                        expiration              = & $getExpiration 'ManagementPlaneAdmins' $defaultExpiration
                        requestApprovalSettings = @{
                            isApprovalRequiredForAdd    = $true
                            isApprovalRequiredForUpdate = $false
                            stages                      = @(
                                @{
                                    durationBeforeAutomaticDenial   = & $getApprovalTimeout 'ManagementPlaneAdmins' 'P1D'
                                    isApproverJustificationRequired = $true
                                    isEscalationEnabled             = $false
                                    durationBeforeEscalation        = "PT0S"
                                    primaryApprovers                = @(
                                        @{
                                            "@odata.type" = "#microsoft.graph.groupMembers"
                                            groupId       = $controlPlaneApproverId
                                        }
                                    )
                                }
                            )
                        }
                    }
                    & $setExtension $params 'ManagementPlaneAdmins'
                    & $setReviewSettings $params 'ManagementPlaneAdmins'
                    try {
                        Write-Verbose "$logPrefix Creating Management Plane Policy for Access Package ID: $($package.Id)"
                        $policies += Invoke-EntraOpsMsGraphQuery -Method POST -Uri "/v1.0/identityGovernance/entitlementManagement/assignmentPolicies" -Body ($params | ConvertTo-Json -Depth 20) -OutputType PSObject -ThrowOnFailure
                    } catch {
                        Write-Warning "$logPrefix Failed to create Management Plane Policy for package '$($package.DisplayName)'. ManagementPlane-Admins can't be requested until it exists; re-run the deployment. Error: $_"
                    }
                }
            }

            # Checked per policy name so existing landing zones get the initial policy on re-run
            $initialDirectPolicy = $initialDirectPolicies | Where-Object { $package.DisplayName -like $_.PackageFilter } | Select-Object -First 1
            if ($initialDirectPolicy -and -not ($policies | Where-Object { $_.AccessPackage.Id -eq $package.Id -and $_.DisplayName -eq $initialDirectPolicy.DisplayName })) {
                $params = $policyParams + @{
                    displayName             = $initialDirectPolicy.DisplayName
                    description             = "Administrator direct assignments for the initial assignments of $ServiceName (no requests, no approval)."
                    allowedTargetScope      = "allMemberUsers"
                    expiration              = $initialDirectPolicy.Expiration
                    requestApprovalSettings = @{
                        isApprovalRequiredForAdd    = $false
                        isApprovalRequiredForUpdate = $false
                    }
                }
                $params.requestorSettings = $adminOnlyRequestorSettings
                & $setReviewSettings $params $initialDirectPolicy.ConfigKey
                try {
                    Write-Verbose "$logPrefix Creating $($initialDirectPolicy.DisplayName) for Access Package ID: $($package.Id)"
                    $policies += Invoke-EntraOpsMsGraphQuery -Method POST -Uri "/v1.0/identityGovernance/entitlementManagement/assignmentPolicies" -Body ($params | ConvertTo-Json -Depth 20) -OutputType PSObject
                } catch {
                    Write-Warning "$logPrefix Failed to create $($initialDirectPolicy.DisplayName) for package '$($package.DisplayName)'. Error: $_"
                }
            }
        }
    }

    end {
        $expectedIds = @($policies | Where-Object { $_.id } | Select-Object -ExpandProperty id)
        $check = @{}
        $confirmed = Wait-EntraOpsServiceEMCondition -Activity "Assignment policies" -logPrefix $logPrefix -Condition {
            $check.Policies = Invoke-EntraOpsMsGraphQuery -Method GET -Uri $assignmentPolicyUri -OutputType PSObject -DisableCache
            $actualIds = @($check.Policies | Where-Object { $_.id } | Select-Object -ExpandProperty id)
            ($expectedIds.Count -eq 0 -and $actualIds.Count -eq 0) -or (Compare-Object $expectedIds $actualIds | Measure-Object).Count -eq 0
        }
        if(-not $confirmed){
            throw "Assignment policy consistency with Entra not achieved"
        }
        return [psobject[]]$check.Policies
    }
}