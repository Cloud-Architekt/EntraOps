function Get-EntraOpsPrivilegedAssetsObjectFinding {
    <#
    .SYNOPSIS
        Evaluates all Privileged Assets finding rules for every inventory object.
    .DESCRIPTION
        Returns, per object ID, one entry per rule key with Applies (the object is in the scope of the
        rule), Failed and RelatedObjectIds (the related objects that cause a relationship finding). The
        logic matches Reports/PrivilegedAssets/js/findings.js, which the report uses for its What-if view.
        New-EntraOpsPrivilegedAssetsFindingContext calls it once when it builds the inventory.

        Tier levels follow the admin tier level (ControlPlane = 0, ManagementPlane and WorkloadPlane = 1,
        UserAccess and Unclassified = 2). The required level of an object is the more privileged of its
        own tier and the highest tier of its role assignments without delegated permissions
        (assignmentSummary.highestAccessTierName): a delegated permission acts within the rights of the signed-in
        user, so it is a tier of the role assignment, not of the object's access. Related objects outside the inventory
        count as level 2. Restricted management "Conflict" (a role-assignable group in a restricted
        management administrative unit) is protected by the role-assignable group, not a gap. Service
        principals of Microsoft first-party applications are neither unclassified nor foreign findings.
    .PARAMETER Context
        The inventory (ObjectsById, RelatedObjects, Objects) of New-EntraOpsPrivilegedAssetsFindingContext.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [object]$Context
    )

    # Tier names are compared case-sensitively, like the report.
    $TierRank = $script:EntraOpsTierRank
    function Get-TierLevel([string]$TierName) {
        if (-not $TierRank.ContainsKey($TierName)) { return $null }
        return Get-EntraOpsAdminTierLevel $TierName
    }
    function Get-EffectiveTier($InventoryObject) {
        if ($TierRank.ContainsKey("$($InventoryObject.tierName)")) { return "$($InventoryObject.tierName)" }
        return 'Unclassified'
    }
    # The most privileged tier of the object's own access: its role assignments without delegated permissions
    # (highestTierName for data of older versions without highestAccessTierName).
    function Get-AccessTier($InventoryObject) {
        $Summary = $InventoryObject.assignmentSummary
        if ($null -eq $Summary) { return 'Unclassified' }
        $AccessTier = if ($Summary -is [System.Collections.IDictionary]) { $(if ($Summary.Contains('highestAccessTierName')) { $Summary['highestAccessTierName'] } else { $Summary['highestTierName'] }) } elseif ($null -ne $Summary.PSObject.Properties['highestAccessTierName']) { $Summary.highestAccessTierName } else { $Summary.highestTierName }
        if ($TierRank.ContainsKey("$AccessTier")) { return "$AccessTier" }
        return 'Unclassified'
    }
    function Get-RequiredLevel($InventoryObject) {
        $OwnLevel = Get-TierLevel (Get-EffectiveTier $InventoryObject)
        $AssignmentLevel = Get-TierLevel (Get-AccessTier $InventoryObject)
        if ($null -eq $AssignmentLevel) { $AssignmentLevel = 2 }
        return [Math]::Min($OwnLevel, $AssignmentLevel)
    }
    function Get-InventoryObject([string]$Id) {
        $Key = $Id.ToLowerInvariant()
        $Found = $Context.ObjectsById[$Key]
        if ($null -ne $Found) { return $Found }
        $Entry = $Context.RelatedObjects[$Key]
        if ($null -ne $Entry -and "$($Entry.objectId)") { return $Context.ObjectsById["$($Entry.objectId)"] }
        return $null
    }
    function Get-RelatedLevel([string]$Id) {
        $Related = Get-InventoryObject $Id
        if ($null -eq $Related) { return 2 }
        $Tier = Get-EffectiveTier $Related
        if ($Tier -eq 'Unclassified') { return 2 }
        return Get-TierLevel $Tier
    }
    function New-Check([bool]$Applies, [bool]$Failed, [string[]]$RelatedObjectIds = @()) {
        [pscustomobject]@{ Applies = $Applies; Failed = ($Applies -and $Failed); RelatedObjectIds = @($RelatedObjectIds) }
    }

    $ObjectFindings = [ordered]@{}
    foreach ($Object in $Context.Objects) {
        $Tier = Get-EffectiveTier $Object
        $ObjectLevel = Get-TierLevel $Tier
        $Highest = Get-AccessTier $Object
        $AssignmentLevel = if ($Highest -ceq 'Unclassified') { $null } else { Get-TierLevel $Highest }
        $Needed = Get-RequiredLevel $Object
        $SubType = "$($Object.objectSubType)".ToLowerInvariant()
        $IsUser = "$($Object.objectType)" -ceq 'user'
        # The access tier as EO.4004 reads it (highestAccessTierName only, no fallback for older data).
        $AccessTierOnly = if ($Object.assignmentSummary -is [System.Collections.IDictionary]) { "$($Object.assignmentSummary['highestAccessTierName'])" } else { "$(Get-EntraOpsPropertyValue $Object.assignmentSummary 'highestAccessTierName')" }

        $Owners = @(@($Object.owners) | Where-Object { $null -ne $_ } | ForEach-Object { "$_" })
        $OwnedObjects = @(@($Object.ownedObjects) | Where-Object { $null -ne $_ } | ForEach-Object { "$_" })
        $OwnedDevices = @(@($Object.ownedDevices) | Where-Object { $null -ne $_ } | ForEach-Object { "$_" })
        $PawDevices = @(@($Object.associatedPawDevice) | Where-Object { $null -ne $_ } | ForEach-Object { "$_".ToLowerInvariant() })
        $WorkAccounts = @(@($Object.associatedWorkAccount) | Where-Object { $null -ne $_ })
        $Sponsors = @(@($Object.sponsors) | Where-Object { $null -ne $_ })
        $IdentityParent = "$($Object.identityParent)"

        $LowerTierOwners = @($Owners | Where-Object { (Get-RelatedLevel $_) -gt $Needed })
        $HigherTierOwned = @($OwnedObjects | Where-Object {
                $Owned = $Context.ObjectsById[$_.ToLowerInvariant()]
                $null -ne $Owned -and (Get-RequiredLevel $Owned) -lt $Needed
            })
        $NonPawDevices = @($OwnedDevices | Where-Object { $PawDevices -notcontains $_.ToLowerInvariant() })
        $ParentLowerTier = $IdentityParent -and (Get-RelatedLevel $IdentityParent) -gt $Needed

        $ObjectFindings["$($Object.objectId)"] = [ordered]@{
            # Unclassified objects are reported by unclassified (EO.2001), not as a tier breach as well.
            tierBreach              = New-Check ($null -ne $AssignmentLevel -and $Tier -ne 'Unclassified') ($ObjectLevel -gt $AssignmentLevel)
            # Microsoft first-party service principals are operated by Microsoft, not classified by the tenant.
            unclassified            = New-Check (-not $Object.isMicrosoftFirstParty) ($Tier -eq 'Unclassified')
            ownerLowerTier          = New-Check ($Owners.Count -gt 0) ($LowerTierOwners.Count -gt 0) $LowerTierOwners
            ownsHigherTier          = New-Check ($OwnedObjects.Count -gt 0) ($HigherTierOwned.Count -gt 0) $HigherTierOwned
            parentLowerTier         = New-Check ([bool]$IdentityParent) $ParentLowerTier $(if ($ParentLowerTier) { $IdentityParent } else { @() })
            # Sponsors belong to agent identities and agent users, and to the blueprint itself: the tenant principal of
            # a blueprint (agentidentityblueprintprincipal) has none, its sponsors are kept on the blueprint.
            sponsorMissing          = New-Check ($SubType.StartsWith('agent', [System.StringComparison]::Ordinal) -and $SubType -notin 'agentidentityblueprint', 'agentidentityblueprintprincipal') ($Sponsors.Count -eq 0)
            deviceNotPaw            = New-Check ($IsUser -and $Needed -le 1) ($NonPawDevices.Count -gt 0) $NonPawDevices
            # A user of another tenant (guest, B2B member, synchronized or Tenant Governance user) has its PAW and work
            # account in its home tenant: reported by EO.4010/EO.4011, not here.
            pawMissing              = New-Check ($IsUser -and $Needed -eq 0 -and -not $Object.isForeign) ($PawDevices.Count -eq 0)
            workAccountMissing      = New-Check ($IsUser -and $Needed -le 1 -and $SubType -eq 'member' -and -not $Object.isForeign) ($WorkAccounts.Count -eq 0)
            hybridPrivileged        = New-Check ($Needed -eq 0) ([bool]$Object.onPremSynchronized)
            # A group with Control or Management Plane access is reported by unprotectedPrivilegedGroup (EO.4004), not twice.
            # EO.4004 reads highestAccessTierName only, so data without it keeps the group here.
            # An object of another tenant (a group or member with access through Tenant Governance) is managed there: its
            # restricted management is decided in its tenant.
            restrictedManagementGap = New-Check (($IsUser -or ("$($Object.objectType)" -ceq 'group' -and $AccessTierOnly -cnotin @('ControlPlane', 'ManagementPlane'))) -and $Needed -le 1 -and -not $Object.isObjectOfOtherTenant -and "$($Object.originType)" -cne 'TenantGovernance') ("$($Object.restrictedManagement)" -ceq 'Not applied')
            # Microsoft first-party service principals are multi-tenant applications of Microsoft, operated by Microsoft.
            foreign                 = New-Check (-not $Object.isMicrosoftFirstParty) ([bool]$Object.isForeign)
        }
    }
    $ObjectFindings
}

function Invoke-EntraOpsPrivilegedAssetsFindingRule {
    <#
    .SYNOPSIS
        Evaluates a Privileged Assets finding rule against the inventory of the Privileged Assets context.
    .DESCRIPTION
        Pure evaluation of the inventory from New-EntraOpsPrivilegedAssetsFindingContext (no file or
        Graph access). Returns the evaluated instances (see Invoke-EntraOpsFindingRuleSet): every object in
        the scope of the rule (for example only Control Plane users for pawMissing), from the checks the
        context evaluated once per object (ObjectFindings).
        Role assignment of a principal managed by another tenant (foreign, EO.4010) lists the role assignments of the objects of other tenants instead: one
        instance per assignment (InstanceKey "<system>|<object ID>|<assignment instance ID>", like the Privileged EAM
        rules), most privileged first.
    .PARAMETER Context
        Context from New-EntraOpsPrivilegedAssetsFindingContext (Objects, ObjectFindings).
    .PARAMETER Rule
        The Privileged Assets finding rule (from Get-EntraOpsFindingRule).
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [object]$Context,

        [Parameter(Mandatory = $true)]
        [object]$Rule
    )

    $TierRank = $script:EntraOpsTierRank
    function Get-ObjectTier($InventoryObject) { if ($TierRank.ContainsKey("$($InventoryObject.tierName)")) { "$($InventoryObject.tierName)" } else { 'Unclassified' } }
    function Get-AccessTier($InventoryObject) {
        $Summary = $InventoryObject.assignmentSummary
        if ($null -eq $Summary) { return 'Unclassified' }
        $AccessTier = if ($Summary.Contains('highestAccessTierName')) { $Summary['highestAccessTierName'] } else { $Summary['highestTierName'] }
        if ($TierRank.ContainsKey("$AccessTier")) { "$AccessTier" } else { 'Unclassified' }
    }
    # "Management Plane object 'name' (user)", with the access of its role assignments when it is more privileged.
    function Get-ObjectLabel($InventoryObject) {
        $Tier = Get-ObjectTier $InventoryObject
        $Access = Get-AccessTier $InventoryObject
        $AccessText = if ($Access -ne 'Unclassified' -and (Get-EntraOpsAdminTierLevel $Access) -lt (Get-EntraOpsAdminTierLevel $Tier)) { " with $(Get-EntraOpsTierDisplayName $Access) role assignments" } else { '' }
        "$(Get-EntraOpsTierDisplayName $Tier) object '$($InventoryObject.displayName)' ($($InventoryObject.objectType))$AccessText"
    }
    # Display names of more than one object (inventory and related objects): a related object (owner, owned object,
    # parent) is named with the start of its ID ('Jane Doe (0e1e6c34)'), so two owners of the same name are not taken
    # for one. The object of a result is named by its display name: the reports show its ID with the result.
    $IdsByName = [System.Collections.Generic.Dictionary[string, System.Collections.Generic.HashSet[string]]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $KnownObjects = @($Context.ObjectsById.Values) + @(if ($null -ne $Context.PSObject.Properties['RelatedObjects'] -and $null -ne $Context.RelatedObjects) { $Context.RelatedObjects.Values })
    foreach ($Known in $KnownObjects) {
        $KnownName = "$($Known.displayName)"
        $KnownId = "$($Known.objectId)".ToLowerInvariant()
        if (-not $KnownName -or -not $KnownId) { continue }
        if (-not $IdsByName.ContainsKey($KnownName)) { $IdsByName[$KnownName] = [System.Collections.Generic.HashSet[string]]::new() }
        $null = $IdsByName[$KnownName].Add($KnownId)
    }
    function Get-UniqueName([string]$Name, [string]$Id) {
        if ($Name -and $Id.Length -ge 8 -and $IdsByName.ContainsKey($Name) -and $IdsByName[$Name].Count -gt 1) { "$Name ($($Id.Substring(0, 8).ToLowerInvariant()))" } else { $Name }
    }
    # A related object (owner, owned object, parent): its name and tier, or that it is not a privileged object.
    function Get-RelatedText([string]$RelatedId) {
        $Key = $RelatedId.ToLowerInvariant()
        $Related = $Context.ObjectsById[$Key]
        if ($null -eq $Related -and $null -ne $Context.PSObject.Properties['RelatedObjects']) {
            $Entry = $Context.RelatedObjects[$Key]
            if ($null -ne $Entry -and "$($Entry.objectId)") { $Related = $Context.ObjectsById["$($Entry.objectId)"] }
            if ($null -eq $Related -and $null -ne $Entry -and "$($Entry.displayName)") { return "'$(Get-UniqueName "$($Entry.displayName)" $(if ("$($Entry.objectId)") { "$($Entry.objectId)" } else { $Key }))' (not privileged, counted as User Access)" }
        }
        if ($null -eq $Related) { return "'$RelatedId' (not privileged, counted as User Access)" }
        # Own tier (ownerLowerTier, parentLowerTier); ownsHigherTier also compares the access tier.
        $RelatedTier = Get-ObjectTier $Related
        $RelatedAccess = Get-AccessTier $Related
        $AccessText = if ($RelatedAccess -ne 'Unclassified' -and (Get-EntraOpsAdminTierLevel $RelatedAccess) -lt (Get-EntraOpsAdminTierLevel $RelatedTier)) { ", with $(Get-EntraOpsTierDisplayName $RelatedAccess) role assignments" } else { '' }
        "'$(Get-UniqueName "$($Related.displayName)" "$($Related.objectId)")' ($(Get-EntraOpsTierDisplayName $RelatedTier)$AccessText)"
    }
    function Get-RelatedName([string]$RelatedId) {
        $Key = $RelatedId.ToLowerInvariant()
        $Related = $Context.ObjectsById[$Key]
        if ($null -eq $Related -and $null -ne $Context.PSObject.Properties['RelatedObjects']) { $Related = $Context.RelatedObjects[$Key] }
        if ($null -ne $Related -and "$($Related.displayName)") { "$($Related.displayName)" } else { $RelatedId }
    }
    # Up to $Max items, then "and N more".
    function Join-Limited([string[]]$Items, [int]$Max = 5) {
        $Text = @($Items | Select-Object -First $Max) -join ', '
        if ($Items.Count -gt $Max) { $Text += " and $($Items.Count - $Max) more" }
        $Text
    }

    # The managing tenant (ManagingTenantId and ManagingTenantName of EntraOpsConfig.json): its principals are listed
    # like the others, named as the managing tenant and marked (ManagingTenant), so expected and unexpected access can be
    # told apart. EO.4011 accepts their Control Plane access; this inventory keeps it visible.
    $ParameterValues = if ($null -ne $Rule.PSObject.Properties['ParameterValues'] -and $null -ne $Rule.ParameterValues) { $Rule.ParameterValues } else { @{} }
    $ManagingTenantId = "$($ParameterValues['ManagingTenantId'])"
    $ManagingTenantName = "$($ParameterValues['ManagingTenantName'])"
    # Emergency access accounts (Findings.EmergencyAccessAccounts, by object ID or user principal name) are shared
    # accounts without a personal work account (EO.4009) or personal PAW (EO.4008): skipped and named in a note.
    $EmergencyAccess = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    if ($Rule.Key -cin 'pawMissing', 'workAccountMissing') {
        foreach ($Entry in @(@($ParameterValues['EmergencyAccessAccounts']) | Where-Object { "$_" })) { $null = $EmergencyAccess.Add("$Entry".Trim()) }
    }
    $SkippedEmergencyAccess = [System.Collections.Generic.List[string]]::new()
    # The role assignments that are access of the object: delegated permissions act within the rights of the signed-in
    # user (EO.5005 reports the Control Plane ones), so they are not listed.
    function Get-ForeignAssignment($InventoryObject) { @($InventoryObject.assignments | Where-Object { $_.roleType -ne 'Delegated' }) }
    function Get-ForeignInstanceKey($InventoryObject, $Assignment) {
        if ($null -eq $Assignment) { return "$($InventoryObject.objectId)" }
        "$($Assignment.roleSystem)|$($InventoryObject.objectId)|$($Assignment.id)"
    }
    # The failed instances of EO.4010, returned sorted at the end: Control Plane assignments first, then by object,
    # role and scope; an object with delegated permissions only last.
    $ForeignResults = [System.Collections.Generic.List[object]]::new()

    foreach ($Object in $Context.Objects) {
        $Check = $Context.ObjectFindings["$($Object.objectId)"][$Rule.Key]
        if ($null -eq $Check) { throw "No Privileged Assets evaluator for finding rule '$($Rule.Id)' ($($Rule.Key))." }
        if (-not $Check.Applies) { continue }
        if ($EmergencyAccess.Count -gt 0 -and $Rule.Key -cin 'pawMissing', 'workAccountMissing') {
            $Keys = @("$($Object.objectId)", "$($Object.userPrincipalName)") | Where-Object { $_ }
            if (@($Keys | Where-Object { $EmergencyAccess.Contains($_) }).Count -gt 0) {
                $Label = "'$($Object.displayName)' ($($Object.objectId))"
                if (-not $SkippedEmergencyAccess.Contains($Label)) { $SkippedEmergencyAccess.Add($Label) }
                continue
            }
        }
        if ($Rule.Key -ceq 'foreign') {
            $Assignments = Get-ForeignAssignment $Object
            if (-not $Check.Failed) {
                if ($Assignments.Count -eq 0) { [pscustomobject]@{ Failed = $false; InstanceKey = (Get-ForeignInstanceKey $Object $null) } }
                foreach ($Assignment in $Assignments) { [pscustomobject]@{ Failed = $false; InstanceKey = (Get-ForeignInstanceKey $Object $Assignment) } }
                continue
            }
            $ObjectTier = Get-ObjectTier $Object
            # The object as the subject that Get-EntraOpsFindingDetail removes; the tier of each assignment follows.
            $Subject = "$(Get-EntraOpsTierDisplayName $ObjectTier) object '$($Object.displayName)' ($($Object.objectType)) is $(Get-EntraOpsFindingOriginText -Object $Object -HomeTenantId $Context.HomeTenantId -ManagingTenantId $ManagingTenantId -ManagingTenantName $ManagingTenantName), outside the home tenant"
            $OriginEvidence = [ordered]@{}
            foreach ($Field in 'originType', 'originTenantId', 'originId') {
                if ("$($Object[$Field])") { $OriginEvidence[$Field.Substring(0, 1).ToUpperInvariant() + $Field.Substring(1)] = "$($Object[$Field])" }
            }
            if (Test-EntraOpsFindingManagingTenant -Object $Object -ManagingTenantId $ManagingTenantId) { $OriginEvidence['ManagingTenant'] = $true }
            $Base = [ordered]@{ ObjectId = "$($Object.objectId)"; ObjectType = "$($Object.objectType)"; DisplayName = "$($Object.displayName)"; AdminTierLevel = Get-EntraOpsAdminTierLevel $Object.tierName; AdminTierLevelName = $ObjectTier }
            if ($Assignments.Count -eq 0) {
                $Result = [pscustomobject]([ordered]@{ Failed = $true; InstanceKey = (Get-ForeignInstanceKey $Object $null) } + $Base + [ordered]@{
                        Message  = "$Subject. It has delegated permissions only, which act within the rights of the signed-in user."
                        Evidence = $OriginEvidence
                    })
                $ForeignResults.Add([pscustomobject]@{ Rank = $TierRank.Count; Name = "$($Object.displayName)"; Role = ''; Scope = ''; Result = $Result })
                continue
            }
            foreach ($Assignment in $Assignments) {
                $Tier = if ($TierRank.ContainsKey("$($Assignment.tierName)")) { "$($Assignment.tierName)" } else { 'Unclassified' }
                $Role = if ("$($Assignment.roleDefinitionName)") { "$($Assignment.roleDefinitionName)" } elseif ("$($Assignment.roleDefinitionId)") { "$($Assignment.roleDefinitionId)" } else { '(unnamed role)' }
                $Scope = if ("$($Assignment.scopeName)") { "$($Assignment.scopeName)" } else { "$($Assignment.scopeId)" }
                $Evidence = [ordered]@{} + $OriginEvidence
                $Evidence['System'] = "$($Assignment.roleSystem)"
                $Evidence['RoleDefinitionName'] = $Role
                $Evidence['RoleAssignmentScopeId'] = "$($Assignment.scopeId)"
                if ("$($Assignment.scopeName)") { $Evidence['ScopeName'] = "$($Assignment.scopeName)" }
                $Evidence['Tier'] = $Tier
                $Evidence['RoleAssignmentType'] = "$($Assignment.assignmentType)"
                if ("$($Assignment.pimAssignmentType)") { $Evidence['PIMAssignmentType'] = "$($Assignment.pimAssignmentType)" }
                if ("$($Assignment.transitiveBy)") { $Evidence['TransitiveBy'] = "$($Assignment.transitiveBy)" }
                # The ID of the assignment in the EAM Dashboard (#assignment=).
                $Evidence['RoleAssignmentInstanceId'] = "$($Assignment.id)"
                $How = @(
                    if ("$($Assignment.pimAssignmentType)") { "$("$($Assignment.pimAssignmentType)".ToLowerInvariant())" }
                    if ("$($Assignment.transitiveBy)") { "through '$($Assignment.transitiveBy)'" }
                ) -join ', '
                $Result = [pscustomobject]([ordered]@{ Failed = $true; InstanceKey = (Get-ForeignInstanceKey $Object $Assignment) } + $Base + [ordered]@{
                        Message  = "$Subject, with the $(Get-EntraOpsTierDisplayName $Tier) role '$Role' ($($Assignment.roleSystem))$(if ($Scope) { " at '$Scope'" })$(if ($How) { " ($How)" })."
                        Evidence = $Evidence
                    })
                $ForeignResults.Add([pscustomobject]@{ Rank = $TierRank[$Tier]; Name = "$($Object.displayName)"; Role = $Role; Scope = $Scope; Result = $Result })
            }
            continue
        }
        if (-not $Check.Failed) { [pscustomobject]@{ Failed = $false; InstanceKey = "$($Object.objectId)" }; continue }
        $RelatedIds = @($Check.RelatedObjectIds | Where-Object { $_ } | ForEach-Object { "$_" })
        # Names of the related objects (owners, owned objects, parent or devices), so the result names them.
        $RelatedNames = @(foreach ($RelatedId in $RelatedIds) { Get-RelatedName $RelatedId })
        $ObjectTier = Get-ObjectTier $Object
        $AccessTier = Get-AccessTier $Object
        $Label = Get-ObjectLabel $Object
        $Evidence = [ordered]@{
            TierName           = $ObjectTier
            AssignmentTierName = $AccessTier
            RelatedObjectIds   = $RelatedIds
            RelatedObjectNames = $RelatedNames
        }
        if ("$($Object.objectType)" -eq 'application' -and "$($Object.userPrincipalName)" -match '^[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$') { $Evidence['AppId'] = "$($Object.userPrincipalName)" }
        $Message = switch ($Rule.Key) {
            'tierBreach' {
                # The role assignments (without delegated permissions) of a more privileged tier than the object, named
                # by their tier (most privileged first): a User Access object can hold Control and Management Plane roles.
                $ObjectLevel = Get-EntraOpsAdminTierLevel $ObjectTier
                $RolesByTier = @($Object.assignments | Where-Object { $_.roleType -ne 'Delegated' -and $TierRank.ContainsKey("$($_.tierName)") -and $_.tierName -ne 'Unclassified' -and (Get-EntraOpsAdminTierLevel $_.tierName) -lt $ObjectLevel } |
                        Group-Object { "$($_.tierName)" } | Sort-Object { $TierRank[$_.Name] } | ForEach-Object {
                            [pscustomobject]@{ Tier = $_.Name; Roles = @($_.Group | ForEach-Object { "'$(if ($_.roleDefinitionName) { $_.roleDefinitionName } else { $_.roleDefinitionId })' ($($_.roleSystem))" } | Select-Object -Unique) }
                        })
                $Roles = @($RolesByTier | ForEach-Object { $_.Roles } | Select-Object -Unique)
                $Evidence['CausingRoles'] = $Roles
                $RoleText = if ($RolesByTier.Count) { @($RolesByTier | ForEach-Object { "of the $(Get-EntraOpsTierDisplayName $_.Tier): $(Join-Limited $_.Roles 3)" }) -join ', and ' } else { "of the $(Get-EntraOpsTierDisplayName $AccessTier)" }
                "$(Get-EntraOpsTierDisplayName $ObjectTier) object '$($Object.displayName)' ($($Object.objectType)) holds role assignments $RoleText."
            }
            'unclassified' {
                if ($AccessTier -ne 'Unclassified') { "Unclassified object '$($Object.displayName)' ($($Object.objectType)) holds $(Get-EntraOpsTierDisplayName $AccessTier) role assignments." }
                else { "Unclassified object '$($Object.displayName)' ($($Object.objectType)) has no tier classification." }
            }
            'ownerLowerTier' { "$Label has owners of a lower tier: $(Join-Limited @($RelatedIds | ForEach-Object { Get-RelatedText $_ }))." }
            'ownsHigherTier' { "$Label owns objects of a more privileged tier: $(Join-Limited @($RelatedIds | ForEach-Object { Get-RelatedText $_ }))." }
            'parentLowerTier' { "$Label has the identity parent $(Join-Limited @($RelatedIds | ForEach-Object { Get-RelatedText $_ })) of a lower tier." }
            'sponsorMissing' { "$Label has no sponsor." }
            'deviceNotPaw' {
                # Devices by name, with the number of devices of the same name.
                $Devices = @($RelatedNames | Group-Object | ForEach-Object { if ($_.Count -gt 1) { "'$($_.Name)' ($($_.Count))" } else { "'$($_.Name)'" } })
                "$Label owns $($RelatedIds.Count) device(s) that are not its privileged access workstation: $(Join-Limited $Devices)."
            }
            'pawMissing' {
                # A PAW attribute whose references match no device (a stale or mistyped device ID) counts as none, but says so.
                $PawReferences = @(@($Object.pawReferences) | Where-Object { $_ } | ForEach-Object { "$_" })
                if ($PawReferences.Count -gt 0) {
                    $Evidence['UnresolvedPawReferences'] = $PawReferences
                    "$Label has no associated privileged access workstation (PAW): its PAW reference $(Join-Limited @($PawReferences | ForEach-Object { "'$_'" }) 3) matches no device."
                } else {
                    "$Label has no associated privileged access workstation (PAW)."
                }
            }
            'workAccountMissing' { "$Label is not linked to a work account." }
            'hybridPrivileged' { "$Label is synchronized from Active Directory." }
            'restrictedManagementGap' {
                # Directory roles of an unprotected object are roles that lower administrators can still manage.
                $DirectoryRoles = @($Object.assignments | Where-Object { $_.roleSystem -eq 'EntraID' } | ForEach-Object { if ($_.roleDefinitionName) { $_.roleDefinitionName } else { $_.roleDefinitionId } } | Select-Object -Unique)
                if ($DirectoryRoles.Count -gt 0) {
                    $Evidence['DirectoryRoles'] = $DirectoryRoles
                    "$Label is not protected by restricted management (restricted management administrative unit, role-assignable group or directory role): Helpdesk, Password, Authentication or User Administrators can still reset the password of holders of its directory role(s) $(Join-Limited @($DirectoryRoles | ForEach-Object { "'$_'" }) 3)."
                } else {
                    "$Label is not protected by restricted management (restricted management administrative unit, role-assignable group or directory role)."
                }
            }
            default { "$($Rule.Title): $Label." }
        }

        [pscustomobject]@{
            Failed             = $true
            InstanceKey        = "$($Object.objectId)"
            ObjectId           = "$($Object.objectId)"
            ObjectType         = "$($Object.objectType)"
            DisplayName        = "$($Object.displayName)"
            AdminTierLevel     = Get-EntraOpsAdminTierLevel $Object.tierName
            AdminTierLevelName = $ObjectTier
            Message            = $Message
            Evidence           = $Evidence
        }
    }
    # Names compare case-insensitively, like the reports; Sort-Object -Stable keeps the inventory order of equal entries.
    $ForeignResults | Sort-Object -Stable -Property Rank, Name, Role, Scope | ForEach-Object { $_.Result }
    if ($SkippedEmergencyAccess.Count -gt 0) {
        [pscustomobject]@{ NoteOnly = $true; Note = "$($SkippedEmergencyAccess.Count) emergency access account(s) of Findings.EmergencyAccessAccounts are not reported: $(Join-EntraOpsFindingName $SkippedEmergencyAccess)." }
    }
    if ($Rule.Key -ceq 'foreign') {
        # What the inventory cannot list (also data gaps of findings.json): groups whose origin is unknown (a group
        # synchronized from another tenant looks local), and the members of privileged groups of other tenants.
        $OriginGap = Get-EntraOpsFindingGroupOriginGap -Inventory $Context
        if ($null -ne $OriginGap) { [pscustomobject]@{ NoteOnly = $true; Note = $OriginGap.Note } }
        $RemoteGap = Get-EntraOpsFindingRemoteGroupGap -Inventory $Context -ManagingTenantId $ManagingTenantId
        if ($null -ne $RemoteGap) { [pscustomobject]@{ NoteOnly = $true; Note = $RemoteGap.Note } }
    }
}
