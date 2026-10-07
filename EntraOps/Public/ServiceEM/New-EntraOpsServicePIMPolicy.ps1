<#
.SYNOPSIS
    Configures PIM activation policies for service admin groups.

.DESCRIPTION
    Updates the Unified Role Management Policy for the member role of each
    admin group (ControlPlane-Admins, ManagementPlane-Admins, WorkloadPlane-Admins) in
    ServiceGroups. Other groups are ignored. Policies enforce:

    - Expiration_Admin_Eligibility: no expiration for eligible assignments.
    - Expiration_Admin_Assignment: 15-day maximum for active assignments
      (ServiceEM.PIMForGroups.MaximumActiveAssignmentDuration).
    - Expiration_EndUser_Assignment: 10-hour maximum for activated sessions
      (ServiceEM.PIMForGroups.MaximumActivationDuration).
    - Enablement_EndUser_Assignment: MFA + Justification required on activation.

    When EntraOpsConfig.ServiceEM.PIMAuthenticationContext.EnableAuthenticationContext
    is true and an AuthenticationContextClassReferenceId is configured for the
    group's access level (ControlPlane / ManagementPlane / WorkloadPlane), a
    dedicated authentication context rule enforces Conditional Access step-up.

    Access level is determined from the group DisplayName (ControlPlane,
    ManagementPlane, or WorkloadPlane).

    When ServiceGroups contains no admin group, returns an empty array without error.

.PARAMETER ServiceGroups
    Owned service group objects that should be managed by PIM for Groups. Only the admin groups
    receive policy updates. Pass only owned (non-delegated) groups.

.PARAMETER ServiceName
    Name of the service. Optional; not currently used in policy computation
    but provided for logging context and future use.

.PARAMETER logPrefix
    Text prepended to verbose messages. Defaults to the function name.

.EXAMPLE
    New-EntraOpsServicePIMPolicy -ServiceGroups $ownedGroups

    Applies PIM policy (MFA + Justification, 10h activation limit) to all
    admin groups for the service.

.EXAMPLE
    New-EntraOpsServicePIMPolicy -ServiceGroups $ownedGroups -ServiceName "MyService"

    Same as above; ServiceName is passed for log context.

#>
function New-EntraOpsServicePIMPolicy {
    [OutputType([psobject[]])]
    [cmdletbinding()]
    param(
        [Parameter(Mandatory)]
        [psobject[]]$ServiceGroups,

        [string]$ServiceName = "",

        [string]$logPrefix = "[$($MyInvocation.MyCommand)]"
    )

    begin {
        $pimGroups = @($ServiceGroups | Where-Object { $_.DisplayName -match '(Control|Management|Workload)Plane-Admins$' -and $_.GroupTypes -notcontains 'Unified' })
        $groupPolicies = @()
        $groupPolicyAssignments = @()
        $policyUpdateFailures = [System.Collections.Generic.List[string]]::new()
        
        # Load PIM Authentication Context configuration from global config
        $pimAuthContextConfig = $null
        if ($Global:EntraOpsConfig.ServiceEM.PIMAuthenticationContext.EnableAuthenticationContext -eq $true) {
            $pimAuthContextConfig = $Global:EntraOpsConfig.ServiceEM.PIMAuthenticationContext
            Write-Verbose "$logPrefix PIM Authentication Context is enabled in configuration"
        } else {
            Write-Verbose "$logPrefix PIM Authentication Context is disabled in configuration - will enforce MFA + Justification only"
        }

        $pimForGroupsConfig = if ($null -ne $Global:EntraOpsConfig) { $Global:EntraOpsConfig.ServiceEM.PIMForGroups }
        $pimDurations = @{}
        foreach ($setting in @(
                @{ Name = 'MaximumActivationDuration'; Default = 'PT10H' },
                @{ Name = 'MaximumActiveAssignmentDuration'; Default = 'P15D' }
            )) {
            $value = [string]$pimForGroupsConfig.($setting.Name)
            if ([string]::IsNullOrWhiteSpace($value)) { $value = $setting.Default }
            if ($value -notmatch '^P(?=\d|T\d)(\d+D)?(T(?=\d)(\d+H)?(\d+M)?)?$') {
                throw "Invalid ServiceEM.PIMForGroups.$($setting.Name) '$value' in EntraOpsConfig. Use an ISO 8601 duration in days, hours or minutes such as 'PT8H' or 'P15D'."
            }
            $pimDurations[$setting.Name] = $value
        }
    }

    process {
        Write-Verbose "$logPrefix Beginning PIM Policy"

        foreach ($group in $pimGroups) {
            # Determine access level from group DisplayName
            $accessLevel = $null
            if ($group.DisplayName -match 'ControlPlane') {
                $accessLevel = "ControlPlane"
            } elseif ($group.DisplayName -match 'ManagementPlane') {
                $accessLevel = "ManagementPlane"
            } elseif ($group.DisplayName -match 'WorkloadPlane') {
                $accessLevel = "WorkloadPlane"
            }

            # Create a fresh copy of policy params for each group to avoid cross-contamination
            $currentGroupPolicyParams = @{
                rules = @(
                    @{
                        "@odata.type"        = "#microsoft.graph.unifiedRoleManagementPolicyExpirationRule"
                        id                   = "Expiration_Admin_Eligibility"
                        isExpirationRequired = $false
                    },
                    @{
                        "@odata.type"        = "#microsoft.graph.unifiedRoleManagementPolicyExpirationRule"
                        id                   = "Expiration_Admin_Assignment"
                        isExpirationRequired = $true
                        maximumDuration      = $pimDurations.MaximumActiveAssignmentDuration
                    },
                    @{
                        "@odata.type"   = "#microsoft.graph.unifiedRoleManagementPolicyExpirationRule"
                        id              = "Expiration_EndUser_Assignment"
                        maximumDuration = $pimDurations.MaximumActivationDuration
                    },
                    @{
                        "@odata.type" = "#microsoft.graph.unifiedRoleManagementPolicyEnablementRule"
                        id            = "Enablement_EndUser_Assignment"
                        enabledRules  = @(
                            "MultiFactorAuthentication",
                            "Justification"
                        )
                    }
                )
            }

            $accessLevelConfig = if ($accessLevel -and $pimAuthContextConfig -is [System.Collections.IDictionary]) {
                $pimAuthContextConfig[$accessLevel]
            } elseif ($accessLevel -and $pimAuthContextConfig) {
                $pimAuthContextConfig.PSObject.Properties[$accessLevel].Value
            }

            # Add authentication context if explicitly enabled and configured for this access level
            if ($pimAuthContextConfig -and 
                $pimAuthContextConfig.EnableAuthenticationContext -eq $true -and
                $accessLevelConfig) {
                
                $authContextId = $accessLevelConfig.AuthenticationContextClassReferenceId
                if (-not [string]::IsNullOrWhiteSpace($authContextId)) {
                    Write-Verbose "$logPrefix Enabling authentication context '$authContextId' for $accessLevel group: $($group.DisplayName)"

                    $currentGroupPolicyParams.rules += @{
                        "@odata.type" = "#microsoft.graph.unifiedRoleManagementPolicyAuthenticationContextRule"
                        id            = "AuthenticationContext_EndUser_Assignment"
                        isEnabled     = $true
                        claimValue    = $authContextId
                    }
                } else {
                    Write-Verbose "$logPrefix Authentication context enabled but no ID configured for $accessLevel - using MFA + Justification only"
                }
            } else {
                Write-Verbose "$logPrefix Authentication context not enabled for $($group.DisplayName) - enforcing MFA + Justification only"
            }

            try {
                Write-Verbose "$logPrefix Looking up PIM Policies with Assignments"
                $groupPolicyAssignment = Invoke-EntraOpsMsGraphQuery -Method GET -Uri "/v1.0/policies/roleManagementPolicyAssignments?`$filter=scopeId eq '$($group.Id)' and scopeType eq 'Group'" -OutputType PSObject
                $groupPolicyAssignments += $groupPolicyAssignment
            } catch {
                Write-Warning "$logPrefix Failed to find PIM Policies with Assignments for group $($group.Id). Ensure the caller has RoleManagementPolicy.ReadWrite.Directory or RoleManagement.Read.Directory permission. Error: $_"
                continue
            }

            $memberPolicy = $groupPolicyAssignment | Where-Object { $_.id -like "*member" }
            if (-not $memberPolicy) {
                Write-Warning "$logPrefix No member policy assignment found for group $($group.Id). Skipping policy update."
                continue
            }

            try {
                Write-Verbose "$logPrefix Updating PIM Policy ID: $($memberPolicy.policyId)"
                Invoke-EntraOpsMsGraphQuery -Method PATCH -Uri "/v1.0/policies/roleManagementPolicies/$($memberPolicy.policyId)" -Body ($currentGroupPolicyParams | ConvertTo-Json -Depth 10) -ThrowOnFailure | Out-Null
            } catch {
                Write-Warning "$logPrefix Failed to update PIM Policy for group $($group.Id). Error: $_"
                $policyUpdateFailures.Add("$($group.Id): $($_.Exception.Message)")
            }
        }
    }

    end {
        if ($policyUpdateFailures.Count -gt 0) {
            throw "$logPrefix Failed to update PIM policy for $($policyUpdateFailures.Count) group(s): $($policyUpdateFailures -join '; ')"
        }

        if ($pimGroups.Count -eq 0) {
            return [psobject[]]@()
        }
        # Update-MgPolicyRoleManagementPolicy updates policy rules synchronously — there is no
        # eventual consistency to wait for. The PolicyId (assignment) never changes across the
        # update, so a retry loop comparing PolicyIds is both unnecessary and fragile under
        # transient Graph timeouts. Return the assignments collected during process; fall back
        # to a single fresh lookup if $groupPolicyAssignments is empty (transient failure in process).
        $result = @($groupPolicyAssignments | Where-Object { $_.id -like "*member" })
        if ($result.Count -eq 0) {
            Write-Verbose "$logPrefix groupPolicyAssignments empty — performing single recovery lookup"
            try {
                foreach ($group in $pimGroups) {
                    $recovery = Invoke-EntraOpsMsGraphQuery -Method GET -Uri "/v1.0/policies/roleManagementPolicyAssignments?`$filter=scopeId eq '$($group.Id)' and scopeType eq 'Group'" -OutputType PSObject
                    $result += @($recovery | Where-Object { $_.id -like "*member" })
                }
            } catch {
                Write-Warning "$logPrefix Recovery lookup failed — returning empty result. Error: $_"
            }
        }
        return [psobject[]]$result
    }
}