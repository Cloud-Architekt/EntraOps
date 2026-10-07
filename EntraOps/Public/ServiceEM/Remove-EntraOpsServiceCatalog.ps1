<#
.SYNOPSIS
    Removes an Entitlement Management catalog, all its contents, the associated
    Entra groups, and the Azure resource group created by the landing zone.

.DESCRIPTION
    Performs a complete teardown of a ServiceEM landing zone:
    1. Revokes all active (non-expired) access package assignments via
       adminRemove requests and waits for them to reach a terminal state.
    2. Deletes all access packages in the catalog.
    3. Deletes the catalog itself.
    4. Deletes the Entra groups registered as catalog resources that were created by the landing zone
       (mailNickname "<ServiceName>.*", ServiceName = catalog name without
       "Catalog-"). Other catalog resources, e.g. shared groups added manually, are kept, as well as any
       group whose Object ID appears in ExcludeGroupIds.
    5. Only with -RemoveAzureResourceGroup: deletes the Azure resource group created
       for the service in -SubscriptionId if it exists: RG-<ServiceName> with a
       leading "Rg-" removed (e.g. Catalog-Rg-MyApp -> RG-MyApp), only if it has the tag
       EntraOpsServiceEM = <ServiceName> set by New-EntraOpsServiceAZContainer. Subscription scope
       catalogs (Catalog-Sub-*) never delete a resource group; their Azure role
       assignments on the subscription must be removed manually.

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

        # Step 1: Submit ALL adminRemove requests across all packages at once.
        $allRemoveRequestIds = [System.Collections.Generic.List[string]]::new()
        foreach ($accessPackage in $catalog.accessPackages) {
            # Filtering by navigation path 'accessPackage/id' requires ConsistencyLevel:eventual + $count=true.
            $assignments = Invoke-EntraOpsMsGraphQuery -Method GET -Uri "/v1.0/identityGovernance/entitlementManagement/assignments?`$count=true&`$filter=accessPackage/id eq '$($accessPackage.Id)'&`$expand=target" -OutputType PSObject -DisableCache -ConsistencyLevel "eventual"
            foreach ($assignment in @($assignments) | Where-Object { $_ -and ($_.state -ine "expired") }) {
                Write-Verbose "$logPrefix Queuing adminRemove for $($assignment.target.displayName) [$($assignment.target.email)] in $($accessPackage.displayName)"
                $params = @{ requestType = "adminRemove"; assignment = @{id = $assignment.id } }
                $req = Invoke-EntraOpsMsGraphQuery -Method POST -Uri "/v1.0/identityGovernance/entitlementManagement/assignmentRequests" -Body ($params | ConvertTo-Json -Depth 10) -OutputType PSObject
                if ($req -and $req.id) {
                    $allRemoveRequestIds.Add($req.id)
                } else {
                    Write-Warning "$logPrefix adminRemove POST returned null for assignment '$($assignment.id)' — skipping"
                }
            }
        }

        # Step 2: Wait for ALL removal requests to reach a terminal state (single polling loop).
        if ($allRemoveRequestIds.Count -gt 0) {
            Write-Verbose "$logPrefix Waiting for $($allRemoveRequestIds.Count) assignment removal request(s) to complete"
            $check = @{}
            $completed = Wait-EntraOpsServiceEMCondition -Activity "Assignment removals" -logPrefix $logPrefix -Condition {
                $check.Pending = @($allRemoveRequestIds | ForEach-Object {
                        Invoke-EntraOpsMsGraphQuery -Method GET -Uri "/v1.0/identityGovernance/entitlementManagement/assignmentRequests/$_" -OutputType PSObject -DisableCache
                    } | Where-Object { $_ -and ($terminalStates -notcontains $_.status.ToLower()) })
                $check.Pending.Count -eq 0
            }
            if (-not $completed) {
                Write-Warning "$logPrefix $($check.Pending.Count) assignment removal(s) still pending after 5 minutes — proceeding anyway"
            }
        }

        # Step 3: Delete each access package (remove resource role scopes first — Graph 400s otherwise).
        foreach ($accessPackage in $catalog.accessPackages) {
            $resourceRoleScopes = Invoke-EntraOpsMsGraphQuery -Method GET -Uri "/v1.0/identityGovernance/entitlementManagement/accessPackages/$($accessPackage.Id)/resourceRoleScopes" -OutputType PSObject -DisableCache
            foreach ($rrs in @($resourceRoleScopes) | Where-Object { $_ -and $_.Id }) {
                Write-Verbose "$logPrefix Removing resource role scope $($rrs.Id) from $($accessPackage.displayName)"
                Invoke-EntraOpsMsGraphQuery -Method DELETE -Uri "/v1.0/identityGovernance/entitlementManagement/accessPackages/$($accessPackage.Id)/resourceRoleScopes/$($rrs.Id)" | Out-Null
            }
            Write-Verbose "$logPrefix Deleting $($accessPackage.displayName) [$($accessPackage.Id)]"
            Invoke-EntraOpsMsGraphQuery -Method DELETE -Uri "/v1.0/identityGovernance/entitlementManagement/accessPackages/$($accessPackage.Id)" | Out-Null
        }

        # Step 4: Delete the catalog.
        Write-Verbose "$logPrefix Deleting Catalog"
        Invoke-EntraOpsMsGraphQuery -Method DELETE -Uri "/v1.0/identityGovernance/entitlementManagement/catalogs/$($catalog.Id)" | Out-Null

        # Step 5: Delete the Entra groups created by the landing zone (identified by their mailNickname).
        $serviceName = $ServiceCatalogName -replace '^Catalog-'
        Write-Verbose "$logPrefix Deleting associated Entra groups from catalog resources"
        foreach ($resource in $catalog.Resources | Where-Object { $_.OriginSystem -eq "AadGroup" }) {
            if ($resource.OriginId -in $ExcludeGroupIds) {
                Write-Verbose "$logPrefix Skipping excluded group: $($resource.DisplayName) [$($resource.OriginId)]"
                continue
            }
            try {
                $group = Invoke-EntraOpsMsGraphQuery -Method GET -Uri "/v1.0/groups/$($resource.OriginId)?`$select=id,displayName,mailNickname" -OutputType PSObject -DisableCache
                if (-not $group) {
                    Write-Verbose "$logPrefix Group $($resource.DisplayName) [$($resource.OriginId)] not found, skipping"
                    continue
                }
                if ($group.MailNickname -notlike "$serviceName.*") {
                    Write-Warning "$logPrefix Keeping group $($resource.DisplayName) [$($resource.OriginId)]: it wasn't created by this landing zone (mailNickname '$($group.MailNickname)')"
                    continue
                }
                Write-Verbose "$logPrefix Deleting group: $($resource.DisplayName) [$($resource.OriginId)]"
                Invoke-EntraOpsMsGraphQuery -Method DELETE -Uri "/v1.0/groups/$($resource.OriginId)" | Out-Null
            } catch {
                Write-Verbose "$logPrefix Failed to delete group $($resource.DisplayName) [$($resource.OriginId)]"
                Write-Error $_
            }
        }

        # Step 6: Delete Azure resource group (opt-in).
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
    }

    end {
        return @{}
    }
}
