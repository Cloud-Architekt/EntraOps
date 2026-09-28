<#
.SYNOPSIS
    Assigns service members and the service owner to their initial access packages.

.DESCRIPTION
    Submits adminAdd assignment requests to place service members into the
    WorkloadPlane-Members access package and the service owner into the
    WorkloadPlane-Members package (unless already assigned). Uses the
    "Initial Workload Membership Policy" assignment policy. Skipped gracefully
    when no WorkloadPlane-Members package or policy exists (e.g. Sub-only
    landing zones).

    Idempotent: existing delivered assignments are detected and skipped.

.PARAMETER ServiceCatalogId
    Object ID of the Entitlement Management catalog. Used to scope assignment
    lookups so only assignments from this catalog are considered.

.PARAMETER ServiceMembers
    Graph User objects to assign to the WorkloadPlane-Members access package.
    Typically the output of Get-MgUser for each service member UPN.

.PARAMETER WorkloadPlaneAdmin
    Graph User object for the workload plane admin. Added to WorkloadPlane-Members
    unless already present via ServiceMembers.

.PARAMETER ServiceAssignmentPolicies
    Assignment policy objects returned by New-EntraOpsServiceEMAssignmentPolicy.

.PARAMETER ServicePackages
    Access package objects returned by New-EntraOpsServiceEMAccessPackage.

.PARAMETER logPrefix
    Text prepended to verbose messages. Defaults to the function name.

.EXAMPLE
    New-EntraOpsServiceEMAssignment `
        -ServiceCatalogId "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" `
        -ServiceMembers $graphMembers `
        -WorkloadPlaneAdmin $graphOwner `
        -ServiceAssignmentPolicies $policies `
        -ServicePackages $packages

    Assigns every user in $graphMembers (plus the workload plane admin) to the
    AP-<ServiceName>-WorkloadPlane-Members access package via adminAdd.

#>
function New-EntraOpsServiceEMAssignment {
    [OutputType([psobject[]])]
    [cmdletbinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ServiceCatalogId,

        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [psobject[]]$ServiceMembers,

        [psobject]$WorkloadPlaneAdmin,

        [Parameter(Mandatory)]
        [psobject[]]$ServiceAssignmentPolicies,
        
        [Parameter(Mandatory)]
        [psobject[]]$ServicePackages,

        [string]$logPrefix = "[$($MyInvocation.MyCommand)]"
    )

    begin {
        $assignmentRequests = @()
        $assignments = @()

        # Open request states; the $filter only supports one state per query
        foreach ($openState in @('submitted', 'pendingApproval', 'delivering', 'scheduled')) {
            $assignmentRequestsUri = "/v1.0/identityGovernance/entitlementManagement/assignmentRequests?`$filter=state eq '$openState'&`$expand=assignment(`$expand=target),accessPackage"
            try{
                Write-Verbose "$logPrefix Looking up assignment requests in state '$openState'"
                $assignmentRequests += Invoke-EntraOpsMsGraphQuery -Method GET -Uri $assignmentRequestsUri -OutputType PSObject -DisableCache
            }catch{
                Write-Verbose "$logPrefix Failed to find Assignment Requests"
                Write-Error $_
            }
        }

        $assignmentsSplat = "/v1.0/identityGovernance/entitlementManagement/assignments?`$filter=accessPackage/catalog/id eq '$ServiceCatalogId' and state eq 'delivered'&`$expand=accessPackage(`$expand=catalog),accessPackage,target"
        Write-Verbose "$logPrefix $($assignmentsSplat)"
        try{
            $assignments += Invoke-EntraOpsMsGraphQuery -Method GET -Uri $assignmentsSplat -OutputType PSObject -DisableCache
            if(($assignments|Measure-Object).Count -gt 0){
                Write-Verbose "$logPrefix Found Access Package Assignment IDs: $($assignments.Id|ConvertTo-Json -Compress)"
            }
        }catch{
            Write-Verbose "$logPrefix Failed to find Assignments"
            Write-Error $_
        }

        # A user may hold one package and still need another, so existing access is keyed per target and package
        $existingAccess = @{}
        foreach ($assignment in @($assignments | Where-Object { $_ })) {
            $existingAccess["$($assignment.Target.ObjectId)|$($assignment.AccessPackage.Id)"] = 'delivered'
        }
        foreach ($request in @($assignmentRequests | Where-Object { $_ })) {
            $existingAccess["$($request.Assignment.Target.ObjectId)|$($request.AccessPackage.Id)"] = "request $($request.State)"
        }
        $getExistingAccess = { param($TargetId, $AccessPackageId) $existingAccess["$TargetId|$AccessPackageId"] }

        $wlMembersPackage = $ServicePackages|Where-Object{$_.DisplayName -like "*WorkloadPlane-Members"}
        $wlMembersPolicy  = $ServiceAssignmentPolicies|Where-Object{$_.DisplayName -eq "Initial Workload Membership Policy"}
        # Rg scope fallback: no WorkloadPlane-Members access package - use WorkloadPlane-Users
        if(-not $wlMembersPackage){
            $wlMembersPackage = $ServicePackages|Where-Object{$_.DisplayName -like "*WorkloadPlane-Users"}
            # Admin-only direct policy without approval; the request policy is the fallback for older landing zones
            $wlMembersPolicy  = $ServiceAssignmentPolicies|Where-Object{$_.DisplayName -eq "Initial Workload Users Policy"}
            if(-not $wlMembersPolicy){
                $wlMembersPolicy = $ServiceAssignmentPolicies|Where-Object{$_.DisplayName -eq "Workload Plane Users Policy"}
            }
        }
        $assignmentParams = @{
            requestType = "adminAdd"
            assignment = @{
                targetId = ""
                assignmentPolicyId = $wlMembersPolicy.Id
                accessPackageId    = $wlMembersPackage.Id
            }
        }
        # Requests accepted by Graph in this run; only these are awaited in the end block.
        $submittedRequests = [System.Collections.Generic.List[psobject]]::new()

        $assignmentRequestUri = "/v1.0/identityGovernance/entitlementManagement/assignmentRequests"
        $adminOnlyPolicyNames = @('Initial Workload Users Policy', 'Initial Workload Admin Policy', 'Initial Management Admin Policy')
        $addTargetToPolicy = {
            param($Policy, [string]$TargetId)
            $policyUri = "/v1.0/identityGovernance/entitlementManagement/assignmentPolicies/$($Policy.Id)"
            $current = Invoke-EntraOpsMsGraphQuery -Method GET -Uri "$($policyUri)?`$expand=accessPackage" -OutputType PSObject -DisableCache
            if (-not $current -or -not $current.Id) { return $false }
            $targets = @(if ($current.AllowedTargetScope -eq 'specificDirectoryUsers') { $current.SpecificAllowedTargets | Where-Object { $_ } })
            if ($targets | Where-Object { $_.UserId -eq $TargetId }) { return $false }
            $policyBody = [ordered]@{
                displayName             = $current.DisplayName
                description             = $current.Description
                allowedTargetScope      = 'specificDirectoryUsers'
                specificAllowedTargets  = @($targets) + @(@{ '@odata.type' = '#microsoft.graph.singleUser'; userId = $TargetId })
                expiration              = $current.Expiration
                requestorSettings       = $current.RequestorSettings
                requestApprovalSettings = $current.RequestApprovalSettings
                accessPackage           = @{ id = $current.AccessPackage.Id }
            }
            if ($current.ReviewSettings) { $policyBody.reviewSettings = $current.ReviewSettings }
            try {
                Invoke-EntraOpsMsGraphQuery -Method PUT -Uri $policyUri -Body ($policyBody | ConvertTo-Json -Depth 20) -OutputType PSObject -ThrowOnFailure | Out-Null
            } catch {
                Write-Warning "$logPrefix Failed to add $TargetId to the scope of policy '$($current.DisplayName)': $($_.Exception.Message)"
                return $false
            }
            Write-Verbose "$logPrefix Added $TargetId as specific user to policy '$($current.DisplayName)'"
            return $true
        }
        # Entra ID ignores "all members" policies for users in scope of a policy for specific users of the
        # same access package (e.g. the Workload Plane Policy), so the target is added to the admin-only policy
        $submitAssignment = {
            param($Policy, [string]$TargetId)
            $requestBody = $assignmentParams | ConvertTo-Json -Depth 10
            if ($Policy.DisplayName -notin $adminOnlyPolicyNames) {
                return Invoke-EntraOpsMsGraphQuery -Method POST -Uri $assignmentRequestUri -Body $requestBody -OutputType PSObject
            }
            try {
                return Invoke-EntraOpsMsGraphQuery -Method POST -Uri $assignmentRequestUri -Body $requestBody -OutputType PSObject -ThrowOnFailure -SuppressBadRequestWarning
            } catch {
                if ($_.Exception.Data['StatusCode'] -ne 400) { return $null }
            }
            Write-Verbose "$logPrefix $TargetId isn't accepted by policy '$($Policy.DisplayName)', adding the user to its scope"
            if (-not (& $addTargetToPolicy $Policy $TargetId)) {
                return Invoke-EntraOpsMsGraphQuery -Method POST -Uri $assignmentRequestUri -Body $requestBody -OutputType PSObject
            }
            $retry = @{}
            $accepted = Wait-EntraOpsServiceEMCondition -Activity "Updated scope of policy '$($Policy.DisplayName)'" -MaxWaitSeconds 60 -logPrefix $logPrefix -Condition {
                try {
                    $retry.Result = Invoke-EntraOpsMsGraphQuery -Method POST -Uri $assignmentRequestUri -Body $requestBody -OutputType PSObject -ThrowOnFailure -SuppressBadRequestWarning
                    $null -ne $retry.Result
                } catch { $false }
            }
            if ($accepted) { return $retry.Result }
            return Invoke-EntraOpsMsGraphQuery -Method POST -Uri $assignmentRequestUri -Body $requestBody -OutputType PSObject
        }
    }

    process {
        Write-Verbose "$logPrefix Beginning EM Assignment"

        if(-not $wlMembersPackage -or -not $wlMembersPolicy){
            Write-Verbose "$logPrefix WorkloadPlane-Members access package or policy not found (Sub-only landing zone?), skipping member assignments"
        } else {
            foreach($member in $ServiceMembers){
                Write-Verbose "$logPrefix Processing Service Member ID: $($member.Id)"
                $assignmentParams.assignment.targetId = $member.Id
                $existingMemberAccess = & $getExistingAccess $member.Id $wlMembersPackage.Id
                if($existingMemberAccess){
                    Write-Verbose "$logPrefix Member $($member.Id) already has access package $($wlMembersPackage.DisplayName) ($existingMemberAccess), skipping"
                } else {
                    try{
                        Write-Verbose "$logPrefix Creating Assignment Request"
                        $postResult = & $submitAssignment $wlMembersPolicy $member.Id
                        if($null -ne $postResult){
                            $assignmentRequests += $postResult
                            $existingAccess["$($member.Id)|$($wlMembersPackage.Id)"] = "request $($postResult.State)"
                            $submittedRequests.Add([pscustomobject]@{ Id = $postResult.Id; State = $postResult.State; TargetId = $member.Id; AccessPackageId = $wlMembersPackage.Id })
                        } else {
                            Write-Warning "$logPrefix Assignment request for member $($member.Id) was rejected. Check that the user is in the allowed target scope of policy '$($wlMembersPolicy.DisplayName)'."
                        }
                    }catch{
                        Write-Verbose "$logPrefix Failed to create Assignment Request"
                        Write-Error $_
                    }
                }
            }
        }

        # Enroll the workload plane admin: prefer ManagementPlane-Admins; fall back to WorkloadPlane-Admins
        # (Centralized governance - ManagementPlane-Admins is delegated to tenant-wide group).
        $mgmtAdminsPackage = $ServicePackages|Where-Object{$_.DisplayName -like "*ManagementPlane-Admins"}
        $mgmtAdminsPolicy  = $ServiceAssignmentPolicies|Where-Object{$_.DisplayName -eq "Initial Management Admin Policy"}
        if(-not $mgmtAdminsPackage){
            $mgmtAdminsPackage = $ServicePackages|Where-Object{$_.DisplayName -like "*WorkloadPlane-Admins"}
            $mgmtAdminsPolicy  = $ServiceAssignmentPolicies|Where-Object{$_.DisplayName -eq "Initial Workload Admin Policy"}
            if(-not $mgmtAdminsPolicy){
                $mgmtAdminsPolicy = $ServiceAssignmentPolicies|Where-Object{$_.DisplayName -eq "Workload Plane Policy"}
            }
        }
        if($mgmtAdminsPackage -and $mgmtAdminsPolicy -and $WorkloadPlaneAdmin){
            $existingAdminAccess = & $getExistingAccess $WorkloadPlaneAdmin.Id $mgmtAdminsPackage.Id
            if($existingAdminAccess){
                Write-Verbose "$logPrefix Workload plane admin $($WorkloadPlaneAdmin.Id) already has access package $($mgmtAdminsPackage.DisplayName) ($existingAdminAccess), skipping"
            } else {
                try{
                    $assignmentParams.assignment.targetId = $WorkloadPlaneAdmin.Id
                    $assignmentParams.assignment.assignmentPolicyId = $mgmtAdminsPolicy.Id
                    $assignmentParams.assignment.accessPackageId = $mgmtAdminsPackage.Id
                    Write-Verbose "$logPrefix Creating Assignment Request for Workload Plane Admin - $($assignmentParams|ConvertTo-Json -Compress)"
                    $postResult = & $submitAssignment $mgmtAdminsPolicy $WorkloadPlaneAdmin.Id
                    if($null -ne $postResult){
                        $assignmentRequests += $postResult
                        $submittedRequests.Add([pscustomobject]@{ Id = $postResult.Id; State = $postResult.State; TargetId = $WorkloadPlaneAdmin.Id; AccessPackageId = $mgmtAdminsPackage.Id })
                    } else {
                        Write-Warning "$logPrefix Assignment request for workload plane admin $($WorkloadPlaneAdmin.Id) was rejected. Check that the user is in the allowed target scope of policy '$($mgmtAdminsPolicy.DisplayName)'."
                    }
                }catch{
                    Write-Verbose "$logPrefix Failed to create Assignment Request for Workload Plane Admin"
                    Write-Error $_
                }
            }
        } else {
            Write-Verbose "$logPrefix No suitable workload plane admin assignment conditions met, skipping workload plane admin assignment"
        }
    }

    end {
        # Nothing was submitted in this run — no point waiting for fulfillment.
        if($submittedRequests.Count -eq 0){
            Write-Verbose "$logPrefix No new assignment requests submitted, skipping consistency check"
            return [psobject[]]@()
        }

        $check = @{ Pending = @($submittedRequests); Checks = 0 }
        $completed = Wait-EntraOpsServiceEMCondition -Activity "Assignment request fulfillment" -logPrefix $logPrefix -Condition {
            $stillPending = @()
            foreach($request in $check.Pending){
                $current = Invoke-EntraOpsMsGraphQuery -Method GET -Uri "/v1.0/identityGovernance/entitlementManagement/assignmentRequests/$($request.Id)" -OutputType PSObject -DisableCache
                $state = if($current -and $current.State){ $current.State } else { $request.State }
                $request.State = $state
                $requestLabel = "Assignment request $($request.Id) (target $($request.TargetId), access package $($request.AccessPackageId))"
                if($state -in @('delivered','partiallyDelivered')){
                    Write-Verbose "$logPrefix $requestLabel is $state"
                } elseif($state -in @('deliveryFailed','denied','canceled')){
                    Write-Warning "$logPrefix $requestLabel ended in state '$state' (status: $($current.Status))"
                } elseif($state -eq 'pendingApproval'){
                    Write-Warning "$logPrefix $requestLabel is waiting for approval and is not awaited"
                } else {
                    $stillPending += $request
                }
            }
            $check.Pending = $stillPending
            $check.Checks++
            if($check.Pending.Count -gt 0){
                Write-Verbose "$logPrefix Waiting for assignment requests: $(($check.Pending | ForEach-Object { "$($_.Id)=$($_.State)" }) -join ', ')"
                if($check.Checks -eq 5){
                    Write-Warning "$logPrefix Fulfillment can take 5+ minutes to complete"
                }
            }
            $check.Pending.Count -eq 0
        }
        if(-not $completed){
            Write-Warning "$logPrefix Assignment requests not fulfilled after 300 seconds, continuing without waiting: $(($check.Pending | ForEach-Object { "$($_.Id)=$($_.State)" }) -join ', ')"
        }

        $checkAssignments = @()
        $checkAssignments += Invoke-EntraOpsMsGraphQuery -Method GET -Uri $assignmentsSplat -OutputType PSObject -DisableCache
        return [psobject[]]$checkAssignments
    }
}