function New-EntraOpsTierBreachFindingContext {
    <#
    .SYNOPSIS
        Builds the assignment paths that the Tier Breach finding rules evaluate.
    .DESCRIPTION
        Reads the Privileged EAM export (PrivilegedEAM/<RbacSystem>/<RbacSystem>.json, only JSON files
        directly in the RBAC system folder, not the per-object subfolders) and returns one object record
        per user or service principal and RBAC system, and one path per role assignment and distinct
        service and tier of its classification:
            Object Tier -> Object -> Role -> Service -> Service Tier

        Object tiers come from ObjectAdminTierLevel and service tiers from the AdminTierLevel of the
        classification; unclassified values are treated as Tier 2 (see ConvertTo-EntraOpsAdminTierLevel).

        Each path gets a deterministic pathId (a hash of object, RBAC system, assignment, service and
        service tier) that identifies it in the finding results, for example as Maester family instance.

        Used by Invoke-EntraOpsFindingEvaluation and New-EntraOpsTierBreachAnalyzerData.
    .PARAMETER ImportPath
        Folder with the Privileged EAM export.
    .PARAMETER Export
        The export from Read-EntraOpsPrivilegedEamExport, to reuse instead of reading -ImportPath.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [string]$ImportPath,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]$Export
    )

    if ($null -eq $Export) { $Export = Read-EntraOpsPrivilegedEamExport -ImportPath $ImportPath }
    $files = $Export.Files
    $objects = [System.Collections.Generic.List[object]]::new()
    $paths = [System.Collections.Generic.List[object]]::new()
    $pathIds = [System.Collections.Generic.HashSet[string]]::new()

    $fileNumber = 0
    foreach ($system in $Export.Systems) {
        $fileNumber++
        $roleSystem = $system.RoleSystem
        $data = $system.Objects

        $sourceObjectCount = @($data).Count
        $processedObjectCount = 0
        $pathsBeforeFile = $paths.Count
        foreach ($o in @($data)) {
            $processedObjectCount++
            if ($processedObjectCount % 250 -eq 0) {
                Write-Verbose "[$fileNumber/$($files.Count)] Processed $processedObjectCount of $sourceObjectCount $roleSystem source object(s)."
            }

            $objType = Get-EntraOpsPropertyValue $o 'ObjectType'
            # Only users and service principals.
            if ($objType -notin 'user', 'serviceprincipal') { continue }

            $objectId = Get-EntraOpsPropertyValue $o 'ObjectId'
            $display = Get-EntraOpsPropertyValue $o 'ObjectDisplayName'
            if (-not $display) { $display = $objectId }
            $objTierName = "$(Get-EntraOpsPropertyValue $o 'ObjectAdminTierLevelName')"
            # The tier level of the object from its tier name, like the other areas (Privileged Assets, Privileged
            # EAM); the level only when the name is not a tier (both come from the classification and can disagree).
            $objTierValue = if ($script:EntraOpsTierRank.ContainsKey($objTierName) -and $objTierName -cne 'Unclassified') { $objTierName } else { Get-EntraOpsPropertyValue $o 'ObjectAdminTierLevel' }
            if ("$objTierValue" -in '', 'Unclassified' -and $objTierName) { $objTierValue = $objTierName }
            $objTier = Get-EntraOpsAdminTierLevel $objTierValue
            # Without a tier name, the object is unclassified only when its tier level is missing or Unclassified too.
            if (-not $objTierName -and "$(Get-EntraOpsPropertyValue $o 'ObjectAdminTierLevel')" -in '', 'Unclassified') { $objTierName = 'Unclassified' }
            # Service principal of a Microsoft first-party application (the finding rules leave it out).
            $isFirstParty = $objType -eq 'serviceprincipal' -and (Test-EntraOpsMicrosoftFirstParty -AppOwnerOrganizationId "$(Get-EntraOpsPropertyValue $o 'OriginTenantId')" -AppId "$(Get-EntraOpsPropertyValue $o 'ObjectUserPrincipalName')")

            $objects.Add([ordered]@{
                    id     = $objectId
                    name   = $display
                    type   = $objType
                    system = $roleSystem
                    tier   = $objTier
                })

            foreach ($ra in @(Get-EntraOpsPropertyValue $o 'RoleAssignments')) {
                if ($null -eq $ra) { continue }
                $roleName = Get-EntraOpsPropertyValue $ra 'RoleDefinitionName'
                if (-not $roleName) { $roleName = '(unnamed role)' }
                $isPriv = [bool] (Get-EntraOpsPropertyValue $ra 'RoleIsPrivileged')
                $classifications = @(Get-EntraOpsPropertyValue $ra 'Classification')
                if ($classifications.Count -eq 0) { continue }

                # Assignment-level context (explains which assignment causes the breach).
                $scopeId = Get-EntraOpsPropertyValue $ra 'RoleAssignmentScopeId'
                $scopeName = Get-EntraOpsPropertyValue $ra 'RoleAssignmentScopeName'
                if (-not $scopeName) { $scopeName = $scopeId }
                $assignType = "$(Get-EntraOpsPropertyValue $ra 'RoleAssignmentType')"
                $assignSub = "$(Get-EntraOpsPropertyValue $ra 'RoleAssignmentSubType')"
                $pimManaged = [bool] (Get-EntraOpsPropertyValue $ra 'PIMManagedRole')
                $pimType = "$(Get-EntraOpsPropertyValue $ra 'PIMAssignmentType')"
                $roleType = "$(Get-EntraOpsPropertyValue $ra 'RoleType')"
                $assignId = Get-EntraOpsPropertyValue $ra 'RoleAssignmentId'
                $assignInstanceId = if (Get-EntraOpsPropertyValue $ra 'RoleAssignmentInstanceId') { Get-EntraOpsPropertyValue $ra 'RoleAssignmentInstanceId' } else { Get-EntraOpsRoleAssignmentInstanceId -RoleSystem $roleSystem -RoleAssignment $ra }
                $transitiveBy = "$(Get-EntraOpsPropertyValue $ra 'TransitiveByObjectDisplayName')"

                # De-duplicate services within a single assignment.
                $seen = [System.Collections.Generic.HashSet[string]]::new()
                foreach ($c in $classifications) {
                    if ($null -eq $c) { continue }
                    $service = Get-EntraOpsPropertyValue $c 'Service'
                    if (-not $service) { $service = '(unclassified)' }
                    # The tier of the service from its tier name, else its level (like the object tier).
                    $svcTierName = "$(Get-EntraOpsPropertyValue $c 'AdminTierLevelName')"
                    $svcTier = if ($script:EntraOpsTierRank.ContainsKey($svcTierName) -and $svcTierName -cne 'Unclassified') { Get-EntraOpsAdminTierLevel $svcTierName } else { Get-EntraOpsAdminTierLevel (Get-EntraOpsPropertyValue $c 'AdminTierLevel') }
                    $key = "$service|$svcTier"
                    if (-not $seen.Add($key)) { continue }

                    # Stable path identifier; a repeated path (same assignment listed twice) gets a suffix.
                    $pathKey = "$objectId|$roleSystem|$roleName|$scopeId|$assignInstanceId|$service|$svcTier".ToLowerInvariant()
                    $pathId = [System.Convert]::ToHexString([System.Security.Cryptography.SHA256]::HashData([System.Text.Encoding]::UTF8.GetBytes($pathKey))).Substring(0, 32).ToLowerInvariant()
                    $candidateId = $pathId
                    $duplicate = 1
                    while (-not $pathIds.Add($candidateId)) {
                        $duplicate++
                        $candidateId = "$pathId-$duplicate"
                    }

                    $paths.Add([ordered]@{
                            pathId             = $candidateId
                            objectId           = $objectId
                            objectName         = $display
                            objectType         = $objType
                            objectTier         = $objTier
                            objectTierName     = $objTierName
                            system             = $roleSystem
                            role               = $roleName
                            roleType           = $roleType
                            roleIsPrivileged   = $isPriv
                            # Delegated permission of an application (acts within the rights of the signed-in user).
                            delegatedPermission = $roleType -eq 'Delegated'
                            microsoftFirstParty = $isFirstParty
                            service            = $service
                            serviceTier        = $svcTier
                            serviceTierName    = $(if ($script:EntraOpsTierRank.ContainsKey($svcTierName) -and $svcTierName -cne 'Unclassified') { $svcTierName } else { $null })
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
                            taggedBy           = "$(Get-EntraOpsPropertyValue $c 'TaggedBy')"
                            taggedByRoleSystem = "$(Get-EntraOpsPropertyValue $c 'TaggedByRoleSystem')"
                        })
                }
            }
        }

        Write-Verbose "[$fileNumber/$($files.Count)] Finished ${roleSystem}: processed $sourceObjectCount source object(s), added $($paths.Count - $pathsBeforeFile) assignment path(s)."
    }

    [pscustomobject]@{
        Area    = 'TierBreach'
        Files   = @($files)
        Objects = $objects
        Paths   = $paths
    }
}
