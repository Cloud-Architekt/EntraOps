function Get-EntraOpsAadApplicationClassification {
    <#
    .SYNOPSIS
        Classifies an AadApplication access package resource from ResourceApps EAM data.
    .DESCRIPTION
        AadApplication originIds are service-principal object IDs; the tier is resolved from the
        service principal's own ResourceApps (workload identity) classification.

        The resulting tier is a PROXY: an app role assignment grants access to the application,
        not the application's API permissions. The heuristic is that access to an app which
        itself holds privileged permissions is equivalent exposure (the app is an escalation
        vector for whoever can use it). A known app without privileged classifications is
        UserAccess. ResourceApps lists every service principal with application or delegated
        permissions, so a service principal that is not in the loaded ResourceApps data holds none
        (for example a single sign-on application).

        ResourceApps knows API permissions only. The role assignments of the service principal in
        the other RBAC systems (every '<RbacSystem>:ByObjectId' index of the cache, for example
        EntraID and Azure) count the same way: an application that holds a Control Plane directory
        role is Control Plane, with or without API permissions. These classifications carry
        ClassificationSource = the RBAC system. A service principal without API permissions and
        without classified role assignments is UserAccess (ClassificationSource NoPermissions).

        When no ResourceApps data could be loaded (no index, or an empty one) the service principal
        fails closed to ControlPlane with a warning (ClassificationSource ResourceAppsMissing).
        Callers remove ClassificationSource before they save a classification.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$ServicePrincipalObjectId,

        [Parameter(Mandatory = $true)]
        [hashtable]$ClassificationCache,

        [Parameter(Mandatory = $false)]
        [string]$DisplayName,

        [Parameter(Mandatory = $false)]
        [string]$ContextLabel,

        [Parameter(Mandatory = $false)]
        [System.Collections.Generic.List[psobject]]$WarningMessages
    )

    $ResourceAppsIndex = $ClassificationCache['ResourceApps:ByObjectId']
    # An empty index (a ResourceApps file without objects) counts as not loaded.
    if ($null -eq $ResourceAppsIndex -or $ResourceAppsIndex.Count -eq 0) {
        if ($null -ne $WarningMessages) {
            $WarningMessages.Add([pscustomobject]@{
                    Type    = 'Unresolved AadApplication'
                    Message = "AadApplication '$DisplayName' ($ServicePrincipalObjectId) in $ContextLabel could not be classified because no ResourceApps data was loaded - treated as ControlPlane (conservative)."
                    Target  = $ServicePrincipalObjectId
                })
        }
        return [pscustomobject]@{
            AdminTierLevel       = '0'
            AdminTierLevelName   = 'ControlPlane'
            Service              = 'Application Access'
            ClassificationSource = 'ResourceAppsMissing'
        }
    }
    $RoleClassifications = @(
        foreach ($IndexKey in @($ClassificationCache.Keys | Where-Object { "$_" -like '*:ByObjectId' -and "$_" -ne 'ResourceApps:ByObjectId' } | Sort-Object)) {
            $Index = $ClassificationCache[$IndexKey]
            if ($Index -isnot [System.Collections.IDictionary] -or -not $Index.Contains($ServicePrincipalObjectId)) { continue }
            $RbacSystem = "$IndexKey" -replace ':ByObjectId$', ''
            foreach ($Item in @($Index[$ServicePrincipalObjectId] | Where-Object { $null -ne $_ } | ForEach-Object { $_.Classification })) {
                if ($null -eq $Item -or -not $Item.AdminTierLevelName -or "$($Item.AdminTierLevelName)" -eq 'Unclassified') { continue }
                # Copy: the item is a live reference into the cache.
                $Copy = $Item.PSObject.Copy()
                $Copy | Add-Member -NotePropertyName ClassificationSource -NotePropertyValue $RbacSystem -Force
                $Copy
            }
        }
    )

    $MatchedApplications = @($ResourceAppsIndex[$ServicePrincipalObjectId] | Where-Object { $null -ne $_ })
    if ($MatchedApplications.Count -eq 0) {
        if ($RoleClassifications.Count -gt 0) { return $RoleClassifications }
        # Not in ResourceApps: the application holds no application or delegated permissions.
        return [pscustomobject]@{
            AdminTierLevel       = '2'
            AdminTierLevelName   = 'UserAccess'
            Service              = 'Application Access'
            ClassificationSource = 'NoPermissions'
        }
    }

    # Real ResourceApps exports carry explicit 'Unclassified' entries (including apps whose ONLY
    # entries are Unclassified). Those are deliberately dropped here: an explicitly-Unclassified-only
    # app IS a "known app without privileged classifications" per this helper's contract and maps to
    # UserAccess - it is not dropped data, the ResourceApps pipeline reviewed the app and classified
    # none of its permissions as privileged. Only real tier classifications are returned.
    $Classifications = @($MatchedApplications | ForEach-Object { $_.Classification } | Where-Object { $null -ne $_ -and $_.AdminTierLevelName -and "$($_.AdminTierLevelName)" -ne 'Unclassified' })
    if ($RoleClassifications.Count -gt 0) { return @($Classifications) + $RoleClassifications }
    if ($Classifications.Count -eq 0) {
        return [pscustomobject]@{
            AdminTierLevel     = '2'
            AdminTierLevelName = 'UserAccess'
            Service            = 'Application Access'
        }
    }

    return $Classifications
}