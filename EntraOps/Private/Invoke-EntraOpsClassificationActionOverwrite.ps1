function Invoke-EntraOpsClassificationActionOverwrite {
    <#
    .SYNOPSIS
        Applies role action classification overwrites to a classification definition (tier structure)
        before it is written as tenant-specific classification file.
    .DESCRIPTION
        Shared helper used by Update-EntraOpsClassificationControlPlaneScope to bake role action
        overwrites from Classification_RoleActionOverwrites.json into the generated tenant-specific
        classification files. The classification logic in the Get-EntraOpsPrivilegedEAM* cmdlets
        consumes the adjusted files without any runtime overwrite handling.

        For every overwritten role action:
        - The action is removed from all TierLevelDefinition entries in ALL tiers whose
          RoleAssignmentScopeName overlaps with the overwrite scope (wildcard-aware in both
          directions) AND whose ActionType (defaults to "Action" when the property is absent)
          matches the overwrite's ActionType. This avoids duplicated classification entries for
          the same action, e.g. when an action exists in a scoped Control Plane entry and a "/*"
          Management Plane entry, the overwrite consolidates it into a single entry - and never
          removes/merges an action into an entry of the other plane (Action vs DataAction), since
          Azure RBAC keeps those as separate namespaces.
        - The action is added exactly once to the target tier: an existing entry with the same
          Service, ActionType, identical RoleAssignmentScopeName and no scope exclusions is
          reused, otherwise a new entry is created. Service and Category are taken from the
          overwrite definition or, if not defined, inherited from the entries the action was
          removed from ("Custom Classification" as fallback); ActionType is taken from the
          overwrite definition (defaults to "Action") and is only written onto a newly created
          entry when it is "DataAction", keeping "Action" entries identical to the pre-existing
          convention of omitting the property.
        - Entries that are left without any role actions are removed afterwards.

        For ApiPermissions classification files (entries carrying ResourceAppId/ResourceScope),
        the target entry uses ResourceAppId/ResourceScope explicitly defined on the overwrite
        (Import-EntraOpsClassificationOverwrites) when present. Otherwise they are inherited from
        the removed entries when the removed entries share a single distinct value, otherwise
        ResourceAppId is set to $null (matches any resource app) and ResourceScope to "All". When
        the overwrite defines an explicit ResourceAppId and/or ResourceScope, only entries whose
        ResourceAppId/ResourceScope overlap (empty/"All" counts as a wildcard) are considered for
        removal/reuse, so overwrites for one resource app/permission type do not affect others.
    .PARAMETER ClassificationDefinition
        Parsed classification definition (array of tier objects with TierLevelDefinition) as read
        from a Classification_*.Param.json file after placeholder substitution.
    .PARAMETER RoleActionOverwrites
        Normalized role action overwrite definitions from Import-EntraOpsClassificationOverwrites, including an
        ActionType property ("Action" or "DataAction", defaulting to "Action") describing which plane the
        overwritten actions belong to.
    .OUTPUTS
        [array] Updated classification definition.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [array]$ClassificationDefinition,

        [Parameter(Mandatory = $false)]
        [AllowEmptyCollection()]
        [array]$RoleActionOverwrites
    )

    if ($null -eq $RoleActionOverwrites -or $RoleActionOverwrites.Count -eq 0) {
        return , $ClassificationDefinition
    }

    $AppliedOverwrites = [System.Collections.Generic.List[object]]::new()

    # Detect ApiPermissions schema (entries carry ResourceAppId/ResourceScope)
    $HasResourceProperties = $false
    foreach ($Tier in $ClassificationDefinition) {
        foreach ($Definition in @($Tier.TierLevelDefinition)) {
            if ($null -ne $Definition.PSObject.Properties['ResourceScope']) {
                $HasResourceProperties = $true
                break
            }
        }
        if ($HasResourceProperties) { break }
    }

    foreach ($Overwrite in $RoleActionOverwrites) {
        $OverwriteScopes = @($Overwrite.RoleAssignmentScopeName)
        # Only meaningful for ApiPermissions schema (ResourceApps). $null/empty means "any resource app"/"any
        # permission type" and preserves the previous inference-only behavior.
        $OverwriteResourceAppId = $Overwrite.ResourceAppId
        $OverwriteResourceScope = $Overwrite.ResourceScope
        # Plane of the overwritten actions. Defaults to "Action" both when the overwrite entry omits ActionType
        # and for schemas (ApiPermissions) which have no Action/DataAction concept at all.
        $OverwriteActionType = if ("$($Overwrite.ActionType)" -eq 'DataAction') { 'DataAction' } else { 'Action' }

        # Resolve the target tier BEFORE mutating anything. The removal loop below strips the action from
        # every matching tier, so resolving afterwards meant an unresolvable tier name (e.g. a typo, or a
        # non-standard name accepted because an explicit EAMTierLevelTagValue was supplied) left the action
        # removed everywhere and re-added nowhere - silently unclassified tenant-wide.
        $TargetTier = $ClassificationDefinition | Where-Object { $_.EAMTierLevelName -eq $Overwrite.EAMTierLevelName } | Select-Object -First 1
        if ($null -eq $TargetTier) {
            Write-Warning "Skipping role action overwrite for '$(@($Overwrite.RoleDefinitionActions) -join ', ')': Tier level '$($Overwrite.EAMTierLevelName)' not found in classification definition. Classification left unchanged."
            continue
        }

        foreach ($Action in $Overwrite.RoleDefinitionActions) {
            # Remove the action from every entry in all tiers with overlapping scope (and, for ApiPermissions
            # with an explicit ResourceAppId/ResourceScope on the overwrite, overlapping resource app/permission
            # type) so that only a single classification entry for the action remains after the overwrite
            $RemovedFrom = [System.Collections.Generic.List[object]]::new()
            foreach ($Tier in $ClassificationDefinition) {
                foreach ($Definition in @($Tier.TierLevelDefinition)) {
                    $DefinitionActionType = if ("$($Definition.ActionType)" -eq 'DataAction') { 'DataAction' } else { 'Action' }
                    if ($DefinitionActionType -ne $OverwriteActionType) { continue }

                    if (@($Definition.RoleDefinitionActions) -notcontains $Action) {
                        # The action is not listed literally, but a wildcard pattern in this entry can still
                        # match it at runtime (runtime matching is wildcard based, this removal pass is not).
                        # Removing nothing here and adding the action to the target tier leaves an object
                        # matching BOTH entries, so the overwrite silently has no effect. Warn rather than
                        # fail quietly - the author needs to narrow the pattern or overwrite it directly.
                        if ($Tier.EAMTierLevelName -ne $Overwrite.EAMTierLevelName) {
                            $WildcardCover = @($Definition.RoleDefinitionActions | Where-Object { -not [string]::IsNullOrEmpty($_) -and $_ -ne $Action -and $Action -like $_ })
                            if ($WildcardCover.Count -gt 0) {
                                Write-Warning "Role action overwrite for '$Action' may not take effect: tier '$($Tier.EAMTierLevelName)' (service '$($Definition.Service)') classifies it through wildcard pattern(s) '$($WildcardCover -join ', ')'. Narrow the pattern or overwrite the pattern directly."
                            }
                        }
                        continue
                    }

                    # Direction of the scope overlap decides remove vs. exclude. Treating both directions as
                    # "remove" made a narrowly scoped overwrite delete the action from a broadly scoped entry,
                    # unclassifying it everywhere outside the overwrite scope.
                    $OverwriteCoversDefinition = $false   # overwrite scope equal/broader -> remove outright
                    $DefinitionCoversOverwrite = $false   # overwrite scope narrower      -> exclude that scope
                    foreach ($DefinitionScope in @($Definition.RoleAssignmentScopeName)) {
                        foreach ($OverwriteScope in $OverwriteScopes) {
                            if ($DefinitionScope -like $OverwriteScope) { $OverwriteCoversDefinition = $true }
                            elseif ($OverwriteScope -like $DefinitionScope) { $DefinitionCoversOverwrite = $true }
                        }
                    }
                    if (-not $OverwriteCoversDefinition -and -not $DefinitionCoversOverwrite) { continue }

                    if ($HasResourceProperties -and -not [string]::IsNullOrEmpty($OverwriteResourceAppId) -and
                        -not [string]::IsNullOrEmpty($Definition.ResourceAppId) -and "$($Definition.ResourceAppId)" -ne "$OverwriteResourceAppId") { continue }
                    if ($HasResourceProperties -and -not [string]::IsNullOrEmpty($OverwriteResourceScope) -and
                        -not [string]::IsNullOrEmpty($Definition.ResourceScope) -and "$($Definition.ResourceScope)" -ne "All" -and "$OverwriteResourceScope" -ne "All" -and
                        "$($Definition.ResourceScope)" -ne "$OverwriteResourceScope") { continue }

                    $RemovedFromEntry = [PSCustomObject]@{
                        'TierLevelName' = $Tier.EAMTierLevelName
                        'Category'      = $Definition.Category
                        'Service'       = $Definition.Service
                        'ActionType'    = $DefinitionActionType
                        'ResourceAppId' = $Definition.ResourceAppId
                        'ResourceScope' = $Definition.ResourceScope
                    }

                    if (-not $OverwriteCoversDefinition) {
                        # Overwrite scope is narrower than this entry's scope. The entry stays valid for every
                        # other scope it covers, so keep the action classified here and exclude only the
                        # overwritten scope(s) instead of deleting the action from the entry entirely.
                        if ($Tier.EAMTierLevelName -ne $Overwrite.EAMTierLevelName) {
                            $ExistingExclusions = @($Definition.ExcludedRoleAssignmentScopeName | Where-Object { -not [string]::IsNullOrEmpty($_) })
                            $NewExclusions = @($OverwriteScopes | Where-Object { $ExistingExclusions -notcontains $_ })
                            if ($NewExclusions.Count -gt 0) {
                                $MergedExclusions = @($ExistingExclusions) + @($NewExclusions)
                                if ($null -eq $Definition.PSObject.Properties['ExcludedRoleAssignmentScopeName']) {
                                    $Definition | Add-Member -NotePropertyName 'ExcludedRoleAssignmentScopeName' -NotePropertyValue $MergedExclusions -Force
                                } else {
                                    $Definition.ExcludedRoleAssignmentScopeName = $MergedExclusions
                                }
                            }
                        }
                        $RemovedFrom.Add($RemovedFromEntry) | Out-Null
                        continue
                    }

                    # ApiPermissions only: when the overwrite narrows to a single permission type but the matched
                    # entry covers both ("All"), removing the action outright unclassifies the complementary
                    # permission type. Preserve it at the original tier by splitting the entry first.
                    if ($HasResourceProperties -and "$($Definition.ResourceScope)" -eq "All" -and
                        -not [string]::IsNullOrEmpty($OverwriteResourceScope) -and "$OverwriteResourceScope" -ne "All") {
                        # ResourceScope values of the classification: "Application" and "Delegation" (not the RoleType "Delegated").
                        $ComplementaryScope = if ("$OverwriteResourceScope" -eq "Application") { "Delegation" } else { "Application" }
                        $ComplementaryDefinition = $null
                        foreach ($SiblingDefinition in @($Tier.TierLevelDefinition)) {
                            if ($SiblingDefinition.Service -ne $Definition.Service) { continue }
                            if ("$($SiblingDefinition.ResourceScope)" -ne $ComplementaryScope) { continue }
                            if ("$($SiblingDefinition.ResourceAppId)" -ne "$($Definition.ResourceAppId)") { continue }
                            $SiblingActionType = if ("$($SiblingDefinition.ActionType)" -eq 'DataAction') { 'DataAction' } else { 'Action' }
                            if ($SiblingActionType -ne $DefinitionActionType) { continue }
                            $ComplementaryDefinition = $SiblingDefinition
                            break
                        }
                        if ($null -eq $ComplementaryDefinition) {
                            $ComplementaryDefinition = [PSCustomObject][ordered]@{
                                'Category'                = $Definition.Category
                                'Service'                 = $Definition.Service
                                'ResourceAppId'           = $Definition.ResourceAppId
                                'ResourceScope'           = $ComplementaryScope
                                'RoleAssignmentScopeName' = @($Definition.RoleAssignmentScopeName)
                                'RoleDefinitionActions'   = @()
                            }
                            $Tier.TierLevelDefinition = @($Tier.TierLevelDefinition) + @($ComplementaryDefinition)
                        }
                        if (@($ComplementaryDefinition.RoleDefinitionActions) -notcontains $Action) {
                            $ComplementaryDefinition.RoleDefinitionActions = @($ComplementaryDefinition.RoleDefinitionActions) + @($Action)
                            Write-Verbose "Split '$Action' out of ResourceScope 'All' in tier '$($Tier.EAMTierLevelName)': kept '$ComplementaryScope' at the original tier before applying the '$OverwriteResourceScope' overwrite."
                        }
                    }

                    $Definition.RoleDefinitionActions = @($Definition.RoleDefinitionActions | Where-Object { $_ -ne $Action })
                    $RemovedFrom.Add($RemovedFromEntry) | Out-Null
                }
            }

            # Service/Category: explicit overwrite definition first, then inherited from the entries
            # the action was removed from (target tier preferred), "Custom Classification" as fallback
            $RemovedFromTargetTier = @($RemovedFrom | Where-Object { $_.TierLevelName -eq $Overwrite.EAMTierLevelName })
            $TargetService = if (-not [string]::IsNullOrEmpty($Overwrite.Service)) { $Overwrite.Service }
            elseif ($RemovedFromTargetTier.Count -gt 0) { $RemovedFromTargetTier[0].Service }
            elseif ($RemovedFrom.Count -gt 0) { $RemovedFrom[0].Service }
            else { "Custom Classification" }
            $TargetCategory = if ($RemovedFromTargetTier.Count -gt 0) { $RemovedFromTargetTier[0].Category }
            elseif ($RemovedFrom.Count -gt 0) { $RemovedFrom[0].Category }
            else { "ClassificationOverwrite" }

            # ResourceAppId/ResourceScope (ApiPermissions schema only): explicit value on the overwrite first,
            # otherwise inherited from the entries the action was removed from when they share a single distinct
            # value, otherwise $null (any resource app) / "All" (any permission type).
            $TargetResourceAppId = $null
            $TargetResourceScope = $null
            if ($HasResourceProperties) {
                $TargetResourceAppId = if (-not [string]::IsNullOrEmpty($OverwriteResourceAppId)) { $OverwriteResourceAppId }
                else {
                    $DistinctResourceAppIds = @($RemovedFrom.ResourceAppId | Where-Object { -not [string]::IsNullOrEmpty($_) } | Select-Object -Unique)
                    if ($DistinctResourceAppIds.Count -eq 1) { $DistinctResourceAppIds[0] } else { $null }
                }
                $TargetResourceScope = if (-not [string]::IsNullOrEmpty($OverwriteResourceScope)) { $OverwriteResourceScope }
                else {
                    $DistinctResourceScopes = @($RemovedFrom.ResourceScope | Where-Object { -not [string]::IsNullOrEmpty($_) } | Select-Object -Unique)
                    if ($DistinctResourceScopes.Count -eq 1) { $DistinctResourceScopes[0] } else { "All" }
                }
            }

            # Reuse an existing entry with same service, same ActionType (plane), identical scopes, no exclusions
            # and (for ApiPermissions) the same resolved resource app/permission type, otherwise create a new one
            $TargetDefinition = $null
            foreach ($Definition in @($TargetTier.TierLevelDefinition)) {
                if ($Definition.Service -ne $TargetService) { continue }
                $DefinitionActionType = if ("$($Definition.ActionType)" -eq 'DataAction') { 'DataAction' } else { 'Action' }
                if ($DefinitionActionType -ne $OverwriteActionType) { continue }
                if (@($Definition.ExcludedRoleAssignmentScopeName | Where-Object { -not [string]::IsNullOrEmpty($_) }).Count -gt 0) { continue }
                $DefinitionScopes = @($Definition.RoleAssignmentScopeName)
                if ($DefinitionScopes.Count -ne $OverwriteScopes.Count) { continue }
                if (Compare-Object -ReferenceObject $DefinitionScopes -DifferenceObject $OverwriteScopes) { continue }
                if ($HasResourceProperties) {
                    if ("$($Definition.ResourceAppId)" -ne "$TargetResourceAppId") { continue }
                    if ("$($Definition.ResourceScope)" -ne "$TargetResourceScope") { continue }
                }
                $TargetDefinition = $Definition
                break
            }

            if ($null -eq $TargetDefinition) {
                $NewDefinition = [ordered]@{
                    'Category' = $TargetCategory
                    'Service'  = $TargetService
                }
                # Only written when "DataAction" - keeps newly created Action-plane entries identical in shape to
                # the pre-existing convention of omitting the property (which implies "Action").
                if ($OverwriteActionType -eq 'DataAction') {
                    $NewDefinition['ActionType'] = 'DataAction'
                }
                if ($HasResourceProperties) {
                    $NewDefinition['ResourceAppId'] = $TargetResourceAppId
                    $NewDefinition['ResourceScope'] = $TargetResourceScope
                }
                $NewDefinition['RoleAssignmentScopeName'] = $OverwriteScopes
                $NewDefinition['RoleDefinitionActions'] = @()
                $TargetDefinition = [PSCustomObject]$NewDefinition
                $TargetTier.TierLevelDefinition = @($TargetTier.TierLevelDefinition) + @($TargetDefinition)
            }

            if (@($TargetDefinition.RoleDefinitionActions) -notcontains $Action) {
                $TargetDefinition.RoleDefinitionActions = @($TargetDefinition.RoleDefinitionActions) + @($Action)
                $AppliedOverwrites.Add([PSCustomObject]@{
                        Tier       = $Overwrite.EAMTierLevelName
                        SourceFile = $Overwrite.SourceFile
                    }) | Out-Null
            }
        }
    }

    # Remove entries which are left without any role actions after the overwrite pass
    foreach ($Tier in $ClassificationDefinition) {
        $Tier.TierLevelDefinition = @($Tier.TierLevelDefinition | Where-Object { @($_.RoleDefinitionActions | Where-Object { -not [string]::IsNullOrEmpty($_) }).Count -gt 0 })
    }

    if ($AppliedOverwrites.Count -gt 0) {
        Write-Host "  Role action overwrites applied:" -ForegroundColor Yellow
        $AppliedOverwrites | Group-Object Tier, SourceFile | Sort-Object Name | ForEach-Object {
            $Example = $_.Group[0]
            Write-Host "    $($Example.Tier): $($_.Count) role action overwrite(s) from $($Example.SourceFile)" -ForegroundColor Yellow
        }
    }

    return , $ClassificationDefinition
}
