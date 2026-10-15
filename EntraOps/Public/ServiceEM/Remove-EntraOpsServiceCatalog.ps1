<#
.SYNOPSIS
    Removes an Entitlement Management catalog, all its contents, the associated
    Entra groups, and the Azure resource group created by the landing zone.

.DESCRIPTION
    Performs a complete teardown of a ServiceEM landing zone:
    1. Cancels open assignment requests of the access packages (e.g. pending approval) and waits for
       requests that can't be canceled (e.g. delivering), because Graph rejects a removal while a
       request is open.
    2. Revokes all active (non-expired) access package assignments via
       adminRemove requests and waits for them to reach a terminal state.
    3. Deletes all access packages in the catalog.
       If a request doesn't complete, a removal or an access package deletion fails, the cmdlet stops
       with an error and keeps the catalog, the groups and the Azure resource group, so a re-run can
       finish the removal.
    4. Deletes the Entra groups registered as catalog resources that were created by the landing zone
       (mailNickname "<ServiceName>.*", ServiceName = catalog name without
       "Catalog-"). Other catalog resources, e.g. shared groups added manually, are kept, as well as any
       group whose Object ID appears in ExcludeGroupIds. A failed group deletion doesn't stop the removal
       of the other groups.
    5. Deletes the catalog itself, only if all groups were deleted; otherwise the catalog is kept so a
       re-run can find it and finish the removal.
    6. Only with -RemoveAzureResourceGroup: deletes the Azure resource group created
       for the service in -SubscriptionId if it exists: RG-<ServiceName> with a
       leading "Rg-" removed (e.g. Catalog-Rg-MyApp -> RG-MyApp), only if it has the tag
       EntraOpsServiceEM = <ServiceName> set by New-EntraOpsServiceAZContainer. Subscription scope
       catalogs (Catalog-Sub-*) never delete a resource group; their Azure role
       assignments on the subscription must be removed manually.
    Failures of steps 4 and 5 are collected and reported in one error at the end.

    Asks for confirmation unless -Force or -Confirm:$false is passed; supports -WhatIf.
    Intended for decommissioning services provisioned by New-EntraOpsServiceBootstrap.

.PARAMETER ServiceCatalogName
    Display name of the catalog to remove (e.g. "Catalog-MyService").

.PARAMETER Force
    Skips the confirmation prompt. Without -Force (and without -Confirm:$false) the cmdlet asks for
    confirmation before deleting anything. Use -WhatIf to show what would be deleted.

.PARAMETER ExcludeGroupIds
    Object IDs of Entra groups that must not be deleted even if they are
    registered as catalog resources. Use this to protect shared delegation
    groups (ControlPlane-Admins, ManagementPlane-Admins, CatalogPlane-Members)
    that are reused across multiple services.

.PARAMETER RemoveAzureResourceGroup
    Opt-in: also deletes the Azure resource group of the service including all its resources.
    Requires -SubscriptionId. Without this switch the resource group is kept. A resource group without the tag
    EntraOpsServiceEM = <ServiceName> (e.g. an existing one reused by the landing zone) is always kept.

.PARAMETER SubscriptionId
    Subscription of the resource group deleted with -RemoveAzureResourceGroup. Required so that a
    resource group with the same name in the subscription of the current Azure context isn't deleted
    by mistake; the previous Azure context is restored afterwards.

.PARAMETER logPrefix
    Text prepended to verbose messages. Defaults to the function name.

.EXAMPLE
    Remove-EntraOpsServiceCatalog -ServiceCatalogName "Catalog-MyService" -Force

    Revokes all active assignments, deletes all access packages, removes the
    catalog and deletes all associated Entra groups. The Azure RG is kept.

.EXAMPLE
    Remove-EntraOpsServiceCatalog -ServiceCatalogName "Catalog-MyService" -Force `
        -ExcludeGroupIds @(
            "00000000-0000-0000-0000-000000000001",  # ControlPlane-Admins (shared)
            "00000000-0000-0000-0000-000000000002"   # ManagementPlane-Admins (shared)
        )

    Same as above but skips deletion of the two shared delegation groups.

.EXAMPLE
    Remove-EntraOpsServiceCatalog -ServiceCatalogName "Catalog-Rg-MyService" -Force -RemoveAzureResourceGroup `
        -SubscriptionId "<subscription-id>"

    Removes all Entra ID / EM artifacts and also deletes the Azure resource group RG-MyService.

.EXAMPLE
    Remove-EntraOpsServiceCatalog -ServiceCatalogName "Catalog-MyService" -WhatIf

    Shows the catalog, access packages and groups that would be deleted without changing anything.

#>
function Remove-EntraOpsServiceCatalog {
    [OutputType([hashtable])]
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory)]
        [string]$ServiceCatalogName,

        [switch]$Force,

        [string[]]$ExcludeGroupIds = @(),

        [switch]$RemoveAzureResourceGroup,

        [ValidatePattern('^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$')]
        [string]$SubscriptionId,

        [string]$logPrefix = "[$($MyInvocation.MyCommand)]"
    )

    process {
        if ($RemoveAzureResourceGroup -and [string]::IsNullOrWhiteSpace($SubscriptionId)) {
            throw "-RemoveAzureResourceGroup requires -SubscriptionId (subscription of the landing zone resource group)."
        }
        if ($Force -and -not $WhatIfPreference) {
            $ConfirmPreference = 'None'
        }
        $encodedServiceCatalogName = ConvertTo-EntraOpsODataStringLiteral -Value $ServiceCatalogName
        $catalog = Invoke-EntraOpsMsGraphQuery -Method GET -Uri "/v1.0/identityGovernance/entitlementManagement/catalogs?`$filter=displayName eq '$encodedServiceCatalogName'&`$expand=accessPackages,resources" -OutputType PSObject -DisableCache
        if (($catalog | Measure-Object).Count -eq 0) {
            Write-Warning "$logPrefix Unable to obtain catalog by name"
            return @{}
        }
        Write-Verbose "$logPrefix Obtained Service Catalog $($catalog.Id)"
        $groupResourceCount = @($catalog.Resources | Where-Object { $_.OriginSystem -eq "AadGroup" }).Count
        $target = "$ServiceCatalogName ($(@($catalog.accessPackages).Count) access packages, $groupResourceCount group resources$(if ($RemoveAzureResourceGroup) { ', Azure resource group' }))"
        if (-not $PSCmdlet.ShouldProcess($target, "Remove assignments, access packages, catalog and landing zone groups")) {
            return @{}
        }

        # Terminal states for assignment requests — any of these means processing is done (success or failure).
        # Graph EM uses camelCase; comparisons are case-insensitive via -iin/-inotin equivalents.
        $terminalStates = @("fulfilled", "delivered", "canceled", "deliveryfailed", "denied", "completed", "partiallydelivered", "dropped")
        $cancellableStatuses = @("accepted", "pendingApproval", "pendingNotBefore", "pendingApprovalEscalated")
        $failures = [System.Collections.Generic.List[string]]::new()

        function Test-OpenRequest ($Request) {
            $Request -and $Request.id -and ($terminalStates -notcontains "$($Request.status)".ToLower()) -and ($terminalStates -notcontains "$($Request.state)".ToLower())
        }

        function Wait-OpenRequest ([string[]]$RequestIds, [string]$Activity) {
            $check = @{ Pending = @() }
            $completed = Wait-EntraOpsServiceEMCondition -Activity $Activity -logPrefix $logPrefix -Condition {
                $check.Pending = @($RequestIds | ForEach-Object {
                        Invoke-EntraOpsMsGraphQuery -Method GET -Uri "/v1.0/identityGovernance/entitlementManagement/assignmentRequests/$_" -OutputType PSObject -DisableCache
                    } | Where-Object { Test-OpenRequest $_ })
                $check.Pending.Count -eq 0
            }
            if ($completed) { return }
            return $check.Pending
        }

        # Step 1: Cancel open requests (e.g. pending approval) or wait for them; Graph rejects adminRemove while one is open.
        $openRequestIds = [System.Collections.Generic.List[string]]::new()
        foreach ($accessPackage in $catalog.accessPackages) {
            $requests = Invoke-EntraOpsMsGraphQuery -Method GET -Uri "/v1.0/identityGovernance/entitlementManagement/assignmentRequests?`$expand=accessPackage&`$filter=accessPackage/id eq '$($accessPackage.Id)'" -OutputType PSObject -DisableCache
            foreach ($request in @($requests) | Where-Object { Test-OpenRequest $_ }) {
                if ($request.status -in $cancellableStatuses -or $request.state -in @("pendingApproval", "scheduled")) {
                    Write-Verbose "$logPrefix Canceling open $($request.requestType) request $($request.id) ($($request.status)) in $($accessPackage.displayName)"
                    try {
                        Invoke-EntraOpsMsGraphQuery -Method POST -Uri "/v1.0/identityGovernance/entitlementManagement/assignmentRequests/$($request.id)/cancel" -ThrowOnFailure | Out-Null
                    } catch {
                        Write-Warning "$logPrefix Failed to cancel request $($request.id) in $($accessPackage.displayName): $($_.Exception.Message)"
                    }
                } else {
                    Write-Verbose "$logPrefix Waiting for open $($request.requestType) request $($request.id) ($($request.status)) in $($accessPackage.displayName)"
                }
                $openRequestIds.Add($request.id)
            }
        }
        if ($openRequestIds.Count -gt 0) {
            $stillOpen = @(Wait-OpenRequest -RequestIds $openRequestIds -Activity "Open assignment requests")
            if ($stillOpen.Count -gt 0) {
                $details = ($stillOpen | ForEach-Object { "$($_.id) (state '$($_.state)', status '$($_.status)')" }) -join ', '
                $failures.Add("$($stillOpen.Count) open assignment request(s) did not complete: $details")
            }
        }

        # Step 2: Submit ALL adminRemove requests across all packages at once.
        $removeRequests = [System.Collections.Generic.List[object]]::new()
        foreach ($accessPackage in $catalog.accessPackages) {
            # Filtering by navigation path 'accessPackage/id' requires ConsistencyLevel:eventual + $count=true.
            $assignments = Invoke-EntraOpsMsGraphQuery -Method GET -Uri "/v1.0/identityGovernance/entitlementManagement/assignments?`$count=true&`$filter=accessPackage/id eq '$($accessPackage.Id)'&`$expand=target" -OutputType PSObject -DisableCache -ConsistencyLevel "eventual"
            foreach ($assignment in @($assignments) | Where-Object { $_ -and ($_.state -ine "expired") }) {
                $targetEmail = if ($assignment.target.PSObject.Properties.Name -contains 'email') { " [$($assignment.target.email)]" }
                $description = "$($assignment.target.displayName)$targetEmail in $($accessPackage.displayName)"
                Write-Verbose "$logPrefix Queuing adminRemove for $description"
                $params = @{ requestType = "adminRemove"; assignment = @{id = $assignment.id } }
                try {
                    $req = Invoke-EntraOpsMsGraphQuery -Method POST -Uri "/v1.0/identityGovernance/entitlementManagement/assignmentRequests" -Body ($params | ConvertTo-Json -Depth 10) -OutputType PSObject -ThrowOnFailure
                    $removeRequests.Add([pscustomobject]@{
                            Id              = $req.id
                            AccessPackageId = $accessPackage.Id
                            Description     = $description
                        })
                } catch {
                    $failures.Add("adminRemove of assignment $($assignment.id) ($($assignment.target.displayName)) in $($accessPackage.displayName) failed: $($_.Exception.Message)")
                }
            }
        }

        # Step 3: Wait for ALL removal requests to reach a terminal state (single polling loop).
        # Access packages with a pending removal still have active grants, Graph rejects their deletion (InvalidDeleteEntitlementHasGrants).
        $blockedAccessPackageIds = [System.Collections.Generic.List[string]]::new()
        if ($removeRequests.Count -gt 0) {
            Write-Verbose "$logPrefix Waiting for $($removeRequests.Count) assignment removal request(s) to complete"
            $stillPending = @(Wait-OpenRequest -RequestIds @($removeRequests | ForEach-Object { $_.Id }) -Activity "Assignment removals")
            foreach ($pending in $stillPending) {
                $removeRequest = $removeRequests | Where-Object { $_.Id -eq $pending.id } | Select-Object -First 1
                $blockedAccessPackageIds.Add($removeRequest.AccessPackageId)
                $failures.Add("removal of $($removeRequest.Description) is still in progress after 5 minutes (request $($pending.id), state '$($pending.state)', status '$($pending.status)')")
            }
        }

        # Step 4: Delete each access package (remove resource role scopes first — Graph 400s otherwise).
        foreach ($accessPackage in $catalog.accessPackages) {
            if ($accessPackage.Id -in $blockedAccessPackageIds) {
                Write-Warning "$logPrefix Keeping $($accessPackage.displayName) [$($accessPackage.Id)]: assignment removal still in progress"
                continue
            }
            try {
                $resourceRoleScopes = Invoke-EntraOpsMsGraphQuery -Method GET -Uri "/v1.0/identityGovernance/entitlementManagement/accessPackages/$($accessPackage.Id)/resourceRoleScopes" -OutputType PSObject -DisableCache
                foreach ($rrs in @($resourceRoleScopes) | Where-Object { $_ -and $_.Id }) {
                    Write-Verbose "$logPrefix Removing resource role scope $($rrs.Id) from $($accessPackage.displayName)"
                    Invoke-EntraOpsMsGraphQuery -Method DELETE -Uri "/v1.0/identityGovernance/entitlementManagement/accessPackages/$($accessPackage.Id)/resourceRoleScopes/$($rrs.Id)" -ThrowOnFailure | Out-Null
                }
                Write-Verbose "$logPrefix Deleting $($accessPackage.displayName) [$($accessPackage.Id)]"
                Invoke-EntraOpsMsGraphQuery -Method DELETE -Uri "/v1.0/identityGovernance/entitlementManagement/accessPackages/$($accessPackage.Id)" -ThrowOnFailure | Out-Null
            } catch {
                $failures.Add("deleting access package $($accessPackage.displayName) failed: $($_.Exception.Message)")
            }
        }

        # Groups that still back access package assignments must stay, so a re-run can finish the removal.
        if ($failures.Count -gt 0) {
            throw "$logPrefix Removal of '$ServiceCatalogName' is incomplete; the catalog, its groups and the Azure resource group were kept. Resolve the following and run the cmdlet again: $($failures -join '; ')"
        }

        # Step 5: Delete the Entra groups created by the landing zone (identified by their mailNickname).
        # The catalog is deleted afterwards, so a re-run can still find it when a group deletion fails.
        $serviceName = $ServiceCatalogName -replace '^Catalog-'
        Write-Verbose "$logPrefix Deleting associated Entra groups from catalog resources"
        $deletedGroupIds = [System.Collections.Generic.List[string]]::new()
        $removalFailures = [System.Collections.Generic.List[string]]::new()
        foreach ($resource in $catalog.Resources | Where-Object { $_.OriginSystem -eq "AadGroup" }) {
            if ($resource.OriginId -in $ExcludeGroupIds) {
                Write-Verbose "$logPrefix Skipping excluded group: $($resource.DisplayName) [$($resource.OriginId)]"
                continue
            }
            try {
                $group = Invoke-EntraOpsMsGraphQuery -Method GET -Uri "/v1.0/groups/$($resource.OriginId)?`$select=id,displayName,mailNickname" -OutputType PSObject -DisableCache -ThrowOnFailure -SuppressNotFoundWarning
            } catch {
                if ($_.Exception.Data['StatusCode'] -ne 404) {
                    $removalFailures.Add("lookup of group $($resource.DisplayName) [$($resource.OriginId)] failed: $($_.Exception.Message)")
                    continue
                }
                $group = $null
            }
            if (-not $group) {
                Write-Verbose "$logPrefix Group $($resource.DisplayName) [$($resource.OriginId)] not found, skipping"
                continue
            }
            if ($group.MailNickname -notlike "$serviceName.*") {
                Write-Warning "$logPrefix Keeping group $($resource.DisplayName) [$($resource.OriginId)]: it wasn't created by this landing zone (mailNickname '$($group.MailNickname)')"
                continue
            }
            try {
                Write-Verbose "$logPrefix Deleting group: $($resource.DisplayName) [$($resource.OriginId)]"
                Invoke-EntraOpsMsGraphQuery -Method DELETE -Uri "/v1.0/groups/$($resource.OriginId)" -ThrowOnFailure | Out-Null
                $deletedGroupIds.Add($resource.OriginId)
            } catch {
                Write-Verbose "$logPrefix Failed to delete group $($resource.DisplayName) [$($resource.OriginId)]"
                $removalFailures.Add("deleting group $($resource.DisplayName) [$($resource.OriginId)] failed: $($_.Exception.Message)")
            }
        }
        if ($deletedGroupIds.Count -gt 0 -and (Get-EntraOpsServiceEMConfigValue -Path 'UpdateObjectClassificationFile') -eq $true) {
            Update-EntraOpsServiceEMObjectClassificationFile -RemoveObjectIds $deletedGroupIds -logPrefix $logPrefix | Out-Null
        }

        # Step 6: Delete the catalog, unless a group is left that a re-run has to find through it.
        if ($removalFailures.Count -gt 0) {
            Write-Warning "$logPrefix Keeping catalog '$ServiceCatalogName': $($removalFailures.Count) group(s) could not be removed"
        } else {
            try {
                Write-Verbose "$logPrefix Deleting Catalog"
                Invoke-EntraOpsMsGraphQuery -Method DELETE -Uri "/v1.0/identityGovernance/entitlementManagement/catalogs/$($catalog.Id)" -ThrowOnFailure | Out-Null
            } catch {
                $removalFailures.Add("deleting catalog $ServiceCatalogName [$($catalog.Id)] failed: $($_.Exception.Message)")
            }
        }

        # Step 7: Delete Azure resource group (opt-in).
        # Only the Rg scope creates a resource group, named without its "Rg-" prefix (see New-EntraOpsServiceAZContainer)
        $rgName = "RG-$($serviceName -replace '^Rg-')"
        if ($serviceName -like 'Sub-*') {
            Write-Warning "$logPrefix '$ServiceCatalogName' is a subscription scope: no resource group is deleted. Remove Azure role assignments and PIM eligible assignments of the deleted groups on the subscription manually."
        } elseif ($RemoveAzureResourceGroup) {
            $previousAzContext = Get-AzContext
            try {
                if ($previousAzContext.Subscription.Id -ne $SubscriptionId) {
                    Write-Verbose "$logPrefix Switching Azure context to subscription $SubscriptionId"
                    Set-AzContext -Subscription $SubscriptionId -Tenant $previousAzContext.Tenant.Id -ErrorAction Stop | Out-Null
                }
                Write-Verbose "$logPrefix Looking up Azure Resource Group: $rgName"
                $rg = Get-AzResourceGroup -Name $rgName -ErrorAction Stop
                if ($rg -and $rg.Tags.EntraOpsServiceEM -ne $serviceName) {
                    Write-Warning "$logPrefix Keeping Azure Resource Group '$rgName': it isn't tagged EntraOpsServiceEM=$serviceName, so it wasn't created by this landing zone. Delete it manually if needed."
                } elseif ($rg) {
                    # PIM eligible schedules outlive the resource group and would block a later landing zone with the same name
                    try {
                        $schedules = @(Get-AzRoleEligibilitySchedule -Scope $rg.ResourceId -ErrorAction Stop | Where-Object { $_.Scope -ieq $rg.ResourceId })
                        foreach ($schedule in $schedules) {
                            Write-Verbose "$logPrefix Removing eligible assignment $($schedule.RoleDefinitionDisplayName) of $($schedule.PrincipalId) on $rgName"
                            New-AzRoleEligibilityScheduleRequest -Name ([guid]::NewGuid()) -Scope $rg.ResourceId -RoleDefinitionId $schedule.RoleDefinitionId -PrincipalId $schedule.PrincipalId -RequestType AdminRemove -ErrorAction Stop | Out-Null
                        }
                    } catch {
                        Write-Warning "$logPrefix Failed to remove PIM eligible assignments on '$rgName': $($_.Exception.Message). They may remain as leftovers."
                    }
                    Write-Verbose "$logPrefix Deleting Azure Resource Group: $rgName"
                    Remove-AzResourceGroup -Name $rgName -Force | Out-Null
                    Write-Verbose "$logPrefix Azure Resource Group deleted: $rgName"
                }
            } catch {
                if ($_.Exception.Message -like "*not exist*" -or $_.Exception.Message -like "*ResourceGroupNotFound*") {
                    Write-Verbose "$logPrefix Azure Resource Group not found: $rgName — skipping"
                } else {
                    Write-Verbose "$logPrefix Failed to delete Azure Resource Group: $rgName"
                    Write-Error $_
                }
            } finally {
                if ($previousAzContext -and (Get-AzContext).Subscription.Id -ne $previousAzContext.Subscription.Id) {
                    Write-Verbose "$logPrefix Restoring Azure context to subscription $($previousAzContext.Subscription.Id)"
                    Set-AzContext -Context $previousAzContext -ErrorAction SilentlyContinue | Out-Null
                }
            }
        } else {
            Write-Warning "$logPrefix Azure Resource Group '$rgName' is kept (use -RemoveAzureResourceGroup to delete it). Role assignments of the deleted groups on it remain as orphaned assignments."
        }

        if ($removalFailures.Count -gt 0) {
            throw "$logPrefix Removal of '$ServiceCatalogName' is incomplete; resolve the following and run the cmdlet again: $($removalFailures -join '; ')"
        }
    }

    end {
        return @{}
    }
}
