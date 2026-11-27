function Get-EntraOpsFindingGroupOriginGap {
    <#
    .SYNOPSIS
        Groups of the Privileged EAM data whose origin is unknown, with the note of the rules about principals of other tenants.
    .DESCRIPTION
        A group without OriginType was read without originTenantInfo (Microsoft Graph refuses it without the permission
        Group-XTenantIdentitySync.Read.All, see Get-EntraOpsObjectOriginTenantInfo), or comes from an export of EntraOps
        before 1.2.0. A group synchronized from another tenant (cross-tenant synchronization) then looks like a group of
        this tenant, so EO.4010 and EO.4011 cannot report it. Groups of another tenant (Tenant Governance, remote groups)
        have their tenant as origin and are not counted.
        Returns nothing when every group has an origin, else Count, Names and Note.
    .PARAMETER Inventory
        The Privileged Assets context (New-EntraOpsPrivilegedAssetsFindingContext).
    .PARAMETER ControlPlane
        Count only the groups with Control Plane access (EO.4011), not all groups with role assignments (EO.4010).
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [object]$Inventory,

        [Parameter(Mandatory = $false)]
        [switch]$ControlPlane
    )

    $Objects = @($Inventory.Objects)
    $Groups = @($Objects | Where-Object { "$($_.objectType)" -eq 'group' -and [string]::IsNullOrWhiteSpace("$($_.originType)") })
    if ($ControlPlane) { $Groups = @($Groups | Where-Object { (Get-EntraOpsFindingObjectAccessTier $_) -eq 'ControlPlane' }) }
    if ($Groups.Count -eq 0) { return }
    # An export without any origin is of EntraOps before 1.2.0: the permission is not the cause.
    $HasOrigin = @($Objects | Where-Object { -not [string]::IsNullOrWhiteSpace("$($_.originType)") }).Count -gt 0
    $Hint = if ($HasOrigin) { 'permission Group-XTenantIdentitySync.Read.All missing?' } else { 'Privileged EAM data of EntraOps before 1.2.0?' }
    $Names = @($Groups | ForEach-Object { "$($_.displayName)".Trim() } | Sort-Object)
    $Scope = if ($ControlPlane) { 'with Control Plane access' } else { 'with role assignments' }
    [pscustomobject]@{
        Count = $Groups.Count
        Names = $Names
        Note  = "The origin of $($Groups.Count) group(s) $Scope ($(Join-EntraOpsFindingName $Names)) is unknown ($Hint); groups synchronized from other tenants are not recognized."
    }
}

function Get-EntraOpsFindingRemoteGroupGap {
    <#
    .SYNOPSIS
        Groups of other tenants with privileged access whose members are not in the Privileged EAM data.
    .DESCRIPTION
        The Privileged EAM collection reads the members of a group of another tenant (a remote group of Tenant Governance)
        only in the managing tenant (ManagingTenantId of EntraOpsConfig.json, Stage 5b of Get-EntraOpsPrivilegedEAMEntraId).
        Without it, or for a group of another tenant, the members and their access are missing in the data, so the rules
        about principals of other tenants cannot report them.
        The export marks the groups of other tenants with CrossTenantMembersExpanded (EntraOps 1.2.0 or later). For data
        without the mark, a group counts as expanded when a member reaches a role through it, or when it belongs to the
        managing tenant (an empty group has no members to list).
        Returns nothing when the members of all these groups were collected, else Count, Names, Groups and Note.
    .PARAMETER Inventory
        The Privileged Assets context (New-EntraOpsPrivilegedAssetsFindingContext).
    .PARAMETER ManagingTenantId
        ManagingTenantId of EntraOpsConfig.json.
    .PARAMETER Tier
        The access tiers of the groups to count: Control Plane for EO.4011, Control and Management Plane for EO.4010.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [object]$Inventory,

        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string]$ManagingTenantId,

        [Parameter(Mandatory = $false)]
        [string[]]$Tier = @('ControlPlane', 'ManagementPlane')
    )

    $ManagingTenantId = "$ManagingTenantId".Trim()
    # Assigned, not output by an if statement: an empty set would be unrolled to $null.
    $Expanded = @{}
    if ($null -ne $Inventory.PSObject.Properties['CrossTenantMembersExpanded'] -and $Inventory.CrossTenantMembersExpanded -is [System.Collections.IDictionary]) { $Expanded = $Inventory.CrossTenantMembersExpanded }
    $Reached = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    if ($null -ne $Inventory.PSObject.Properties['TransitiveGroupIds'] -and $Inventory.TransitiveGroupIds -is [System.Collections.Generic.HashSet[string]]) { $Reached = $Inventory.TransitiveGroupIds }
    $Groups = foreach ($Object in @($Inventory.Objects)) {
        if ("$($Object.objectType)" -ne 'group' -or -not $Object.isObjectOfOtherTenant) { continue }
        if ((Get-EntraOpsFindingObjectAccessTier $Object) -notin $Tier) { continue }
        $Id = "$($Object.objectId)".ToLowerInvariant()
        $OfManagingTenant = $ManagingTenantId -and "$($Object.objectTenantId)" -eq $ManagingTenantId
        $IsExpanded = if ($Expanded.Contains($Id)) { [bool]$Expanded[$Id] } else { $Reached.Contains($Id) -or $OfManagingTenant }
        if ($IsExpanded) { continue }
        [pscustomobject]@{
            Name   = "$($Object.displayName)".Trim()
            Tenant = "$($Object.objectTenantId)"
            Cause  = $(if (-not $ManagingTenantId) { 'NoManagingTenant' } elseif (-not $OfManagingTenant) { 'OtherTenant' } else { 'Failed' })
        }
    }
    $Groups = @($Groups | Sort-Object Name)
    if ($Groups.Count -eq 0) { return }

    $TierText = if (@($Tier).Count -eq 1) { "$(Get-EntraOpsTierDisplayName $Tier[0]) access" } else { "$(@($Tier | ForEach-Object { Get-EntraOpsTierDisplayName $_ }) -join ' or ') access" }
    $CauseText = @(foreach ($Cause in @($Groups | Group-Object Cause)) {
            $One = $Cause.Count -eq 1
            $Which = if ($Cause.Count -eq $Groups.Count) { if ($One) { 'The group' } else { 'These groups' } } else { "$($Cause.Count) of them" }
            $Its = if ($One) { 'its' } else { 'their' }
            switch ($Cause.Name) {
                'NoManagingTenant' { "ManagingTenantId is not set in EntraOpsConfig.json, and EntraOps reads the members of groups of other tenants only in the managing tenant: set it to the governing tenant and collect the Privileged EAM data again." }
                'OtherTenant' { "$Which $(if ($One) { 'belongs to a tenant' } else { 'belong to tenants' }) other than the managing tenant $ManagingTenantId, where EntraOps cannot read members: review $Its members in $Its $(if ($One) { 'tenant' } else { 'tenants' })." }
                'Failed' { "$Which $(if ($One) { 'belongs' } else { 'belong' }) to the managing tenant, but $Its members could not be read during the collection (see the warnings of the Privileged EAM collection)." }
            }
        })
    $Names = @($Groups.Name)
    [pscustomobject]@{
        Count  = $Groups.Count
        Names  = $Names
        Groups = $Groups
        Note   = "The members of $($Groups.Count) group(s) of other tenants with $TierText are not in the Privileged EAM data, so their access is not evaluated: $(Join-EntraOpsFindingName $Names). $($CauseText -join ' ')"
    }
}

function Get-EntraOpsFindingObjectAccessTier {
    <#
    .SYNOPSIS
        The access tier of an inventory object: its role assignments without delegated permissions (highestAccessTierName).
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param (
        [Parameter(Mandatory = $true)]
        [AllowNull()]
        [object]$Object
    )

    if ($null -eq $Object) { return '' }
    if ($Object -is [System.Collections.IDictionary] -and $Object.Contains('accessTier') -and $Object['accessTier']) { return "$($Object['accessTier'])" }
    $Summary = $Object.assignmentSummary
    if ($null -eq $Summary) { return '' }
    if ($Summary -is [System.Collections.IDictionary]) { return "$($Summary['highestAccessTierName'])" }
    "$(Get-EntraOpsPropertyValue $Summary 'highestAccessTierName')"
}

function Get-EntraOpsFindingTenantGovernanceGap {
    <#
    .SYNOPSIS
        Data gaps of the Tenant Governance snapshot that the rules of the report data evaluate.
    .DESCRIPTION
        Reads snapshotHealth of the Configuration Analyzer data (New-EntraOpsTenantGovernanceConfigurationAnalyzerData)
        and returns, for the resource types the finding rules read, one gap per code:
          * TenantGovernanceSnapshotOutdated: the snapshot is older than its maximum age (isStale).
          * TenantGovernanceResourceTypeStale: resource types that could not be captured, so their files come from an
            earlier snapshot (PreservedStale).
          * TenantGovernanceResourceTypeIncomplete: resource types exported with errors (PublishedWithErrors), without
            the known limitation of the snapshot export (Test-EntraOpsTenantGovernanceKnownExportLimitation) when no
            resource of the type was retained from the previous snapshot.
        Resource types that no rule reads (for example the Security & Compliance types) are not counted.
    .PARAMETER ReportData
        The report data of Import-EntraOpsReportFindingData.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]$ReportData
    )

    if ($null -eq $ReportData -or $null -eq $ReportData.PSObject.Properties['ConfigurationAnalyzer']) { return }
    $Analyzer = $ReportData.ConfigurationAnalyzer
    if ($Analyzer -isnot [System.Collections.IDictionary] -or -not $Analyzer.Contains('snapshotHealth')) { return }
    $Health = $Analyzer['snapshotHealth']
    if ($Health -isnot [System.Collections.IDictionary]) { return }

    # The resource types the rules read: <Area>:<Key> selects one rule, Area:<Area> all rules of an area.
    $PimRules = @('Area:PimRequestFlow', 'TenantGovernance:controlPlaneActivationAuthContext', 'TenantGovernance:eligibleAssignmentDuration', 'TenantGovernance:controlPlaneActivationDuration', 'TenantGovernance:privilegedRoleAlert')
    $AccessPackageRules = @('Area:AccessPackageFlow', 'TenantGovernance:accessPackageExpiration', 'TenantGovernance:accessPackageAccessReview')
    $TypeRules = [ordered]@{
        'microsoft.entra.rolesetting'                                         = $PimRules
        'microsoft.entra.roledefinition'                                      = $PimRules
        'microsoft.entra.conditionalaccesspolicy'                             = @('TenantGovernance:conditionalAccessControlPlaneExclusion')
        'microsoft.entra.entitlementmanagementaccesspackage'                  = $AccessPackageRules
        'microsoft.entra.entitlementmanagementaccesspackageassignmentpolicy' = $AccessPackageRules
        'microsoft.entra.administrativeunit'                                  = @('TenantGovernance:dynamicPrivilegedAdministrativeUnit')
    }
    $Catalog = @(Get-EntraOpsFindingRule)
    function Get-TypeRuleId([string[]]$ResourceTypes) {
        @(foreach ($Selector in @($ResourceTypes | ForEach-Object { $TypeRules[$_] } | Select-Object -Unique)) {
                $Area, $Key = $Selector -split ':', 2
                if ($Area -eq 'Area') { $Catalog | Where-Object { $_.Area -eq $Key } | ForEach-Object { $_.Id } }
                else { $Catalog | Where-Object { $_.Area -eq $Area -and $_.Key -ceq $Key } | ForEach-Object { $_.Id } }
            }) | Sort-Object -Unique
    }
    $States = @(@($Health['resourceTypeStates']) | Where-Object { $_ -is [System.Collections.IDictionary] -and $TypeRules.Contains("$($_['resourceType'])".ToLowerInvariant()) })
    $Diagnostics = @(@($Health['diagnostics']) | Where-Object { $_ -is [System.Collections.IDictionary] -and -not "$($_['attemptSnapshotId'])" })

    if ($Health['isStale'] -eq $true) {
        $AgeText = if ($null -ne $Health['ageHours']) { " $([math]::Round([double]$Health['ageHours'] / 24, 1)) days ago" } else { '' }
        $Types = @($TypeRules.Keys)
        [pscustomobject][ordered]@{
            Code    = 'TenantGovernanceSnapshotOutdated'
            Message = "The Tenant Governance snapshot was captured$AgeText, more than its maximum age of $($Health['maxAgeHours']) hours: the rules evaluate the configuration at that time, not the current tenant. Take a new snapshot (Invoke-EntraOpsTenantGovernanceSnapshot) and generate the report data again."
            Count   = 1
            RuleIds = @(Get-TypeRuleId $Types)
        }
    }

    $Stale = @($States | Where-Object { "$($_['status'])" -eq 'PreservedStale' })
    if ($Stale.Count -gt 0) {
        $Types = @($Stale | ForEach-Object { "$($_['resourceType'])".ToLowerInvariant() } | Sort-Object -Unique)
        [pscustomobject][ordered]@{
            Code    = 'TenantGovernanceResourceTypeStale'
            Message = "The Tenant Governance snapshot could not capture $(Join-EntraOpsFindingName $Types), so the rules evaluate $(if ($Types.Count -eq 1) { 'its' } else { 'their' }) configuration of an earlier snapshot. See the diagnostics in the Configuration Analyzer report and take a new snapshot."
            Count   = $Types.Count
            RuleIds = @(Get-TypeRuleId $Types)
        }
    }

    $Incomplete = foreach ($State in @($States | Where-Object { "$($_['status'])" -eq 'PublishedWithErrors' })) {
        $Type = "$($State['resourceType'])".ToLowerInvariant()
        $Retained = [int]$State['retainedResourceCount']
        $TypeDiagnostics = @($Diagnostics | Where-Object { "$($_['resourceType'])".ToLowerInvariant() -eq $Type })
        # The known limitation leaves no gap while every resource of the type was exported.
        $Relevant = @($TypeDiagnostics | Where-Object {
                $Known = if ($_.Contains('knownLimitation')) { [bool]$_['knownLimitation'] } else { Test-EntraOpsTenantGovernanceKnownExportLimitation -ResourceType $Type -ErrorCategory "$($_['errorCategory'])" -ErrorCode "$($_['errorCode'])" -Message "$($_['message'])" }
                -not $Known -or $Retained -gt 0
            })
        if ($Relevant.Count -eq 0 -and $Retained -eq 0) { continue }
        $Occurrences = [int](@($Relevant | ForEach-Object { [int]$_['occurrences'] }) | Measure-Object -Sum).Sum
        # Two examples, up to the first sentence that names what was skipped.
        $Examples = @($Relevant | Select-Object -First 2 | ForEach-Object { ("$($_['message'])" -split '(?<=\.) (?=\[)', 2)[0].Trim() })
        [pscustomobject]@{
            Type        = $Type
            Occurrences = $Occurrences
            Retained    = $Retained
            Text        = "$Type ($Occurrences error(s)$(if ($Retained -gt 0) { ", $Retained resource(s) kept from the previous snapshot" })$(if ($Examples.Count -gt 0) { ", for example: $($Examples -join ' ')" }))"
        }
    }
    $Incomplete = @($Incomplete)
    if ($Incomplete.Count -gt 0) {
        [pscustomobject][ordered]@{
            Code    = 'TenantGovernanceResourceTypeIncomplete'
            Message = "The Tenant Governance snapshot exported resource types with errors, so the rules evaluate them without the parts Microsoft Graph could not export (a reference to a deleted object leaves the setting without it): $($Incomplete.Text -join '; ')"
            Count   = $Incomplete.Count
            RuleIds = @(Get-TypeRuleId @($Incomplete.Type))
        }
    }
}

function Get-EntraOpsFindingClassificationGap {
    <#
    .SYNOPSIS
        Data gaps of the object classification and the account attributes of privileged users.
    .DESCRIPTION
          * ObjectTierCoverageLow: at least half of the users and service principals of the tenant with Control or
            Management Plane access (without Microsoft first-party service principals and principals of other tenants)
            have no classification. The tier rules count them as User Access, so most of their results ask for a
            classification rather than confirm a breach.
          * PawAssociationNotPopulated: privileged users are in the scope of EO.4008, but no user of the tenant has
            an associated PAW: the attribute is probably not maintained (EO.4007 and EO.4008 report every user).
          * WorkAccountNotPopulated: the same for the associated work account (EO.4009).
    .PARAMETER Inventory
        The Privileged Assets context (New-EntraOpsPrivilegedAssetsFindingContext).
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [object]$Inventory
    )

    $Objects = @($Inventory.Objects)
    $Privileged = @($Objects | Where-Object {
            "$($_.objectType)" -in 'user', 'serviceprincipal', 'servicePrincipal' -and -not $_.isMicrosoftFirstParty -and -not $_.isForeign -and
            (Get-EntraOpsFindingObjectAccessTier $_) -in 'ControlPlane', 'ManagementPlane'
        })
    $Unclassified = @($Privileged | Where-Object { "$($_.tierName)" -eq 'Unclassified' -or [string]::IsNullOrWhiteSpace("$($_.tierName)") })
    if ($Privileged.Count -gt 0 -and $Unclassified.Count -gt 0 -and $Unclassified.Count * 2 -ge $Privileged.Count) {
        $TierRuleIds = @(Get-EntraOpsFindingRule | Where-Object { $_.Category -eq 'TierBoundaries' -or $_.Key -cin 'unclassified' } | ForEach-Object { $_.Id } | Sort-Object -Unique)
        [pscustomobject][ordered]@{
            Code    = 'ObjectTierCoverageLow'
            Message = "$($Unclassified.Count) of $($Privileged.Count) users and service principals of the tenant with Control or Management Plane access have no classification (custom security attribute, Alternate Tier Level Attributes or the Object Classification File). The tier rules count them as User Access, so most of their results first ask for a classification: classify the objects (EO.2001), then the remaining results are tier breaches. Groups are classified only by the Object Classification File or the Alternate Tier Level Attributes for groups."
            Count   = $Unclassified.Count
            RuleIds = $TierRuleIds
        }
    }

    $Findings = if ($null -ne $Inventory.PSObject.Properties['ObjectFindings']) { $Inventory.ObjectFindings } else { $null }
    $HomeUsers = @($Objects | Where-Object { "$($_.objectType)" -eq 'user' -and -not $_.isForeign })
    $Attributes = @(
        @{ Code = 'PawAssociationNotPopulated'; Check = 'pawMissing'; Property = 'associatedPawDevice'; Name = 'associated privileged access workstation'; Setting = 'CustomSecurityAttributes.PrivilegedUserPawAttribute, by default associatedSecureAdminWorkstation'; RuleKeys = @('deviceNotPaw', 'pawMissing') }
        @{ Code = 'WorkAccountNotPopulated'; Check = 'workAccountMissing'; Property = 'associatedWorkAccount'; Name = 'associated work account'; Setting = 'CustomSecurityAttributes.UserWorkAccountAttribute, by default associatedWorkAccount, or the identity info of Microsoft Defender XDR with XDR hunting enabled'; RuleKeys = @('workAccountMissing') }
    )
    foreach ($Attribute in $Attributes) {
        $InScope = @(if ($null -ne $Findings) {
                $HomeUsers | Where-Object { $Check = $Findings["$($_.objectId)"]; $null -ne $Check -and $null -ne $Check[$Attribute.Check] -and $Check[$Attribute.Check].Applies }
            })
        if ($InScope.Count -eq 0) { continue }
        $Populated = @($HomeUsers | Where-Object { @(@($_[$Attribute.Property]) | Where-Object { "$_" }).Count -gt 0 })
        if ($Populated.Count -gt 0) { continue }
        [pscustomobject][ordered]@{
            Code    = $Attribute.Code
            Message = "No user of the tenant has an $($Attribute.Name) ($($Attribute.Setting)), so all $($InScope.Count) privileged user(s) in the scope of $(@(Get-EntraOpsFindingRule | Where-Object { $_.Area -eq 'PrivilegedAssets' -and $_.Key -cin $Attribute.RuleKeys } | ForEach-Object { $_.Id }) -join ' and ') are all reported. If the attribute is maintained, check that the collection can read it; if the tenant has none, the results are correct."
            Count   = $InScope.Count
            RuleIds = @(Get-EntraOpsFindingRule | Where-Object { $_.Area -eq 'PrivilegedAssets' -and $_.Key -cin $Attribute.RuleKeys } | ForEach-Object { $_.Id } | Sort-Object -Unique)
        }
    }
}

function Get-EntraOpsFindingDataGap {
    <#
    .SYNOPSIS
        The data gaps of a finding evaluation: data that is missing, so that rules evaluate less than they seem to.
    .DESCRIPTION
        Each entry has Code, Message, Count (the number of affected groups or files) and RuleIds (the rules whose results
        are incomplete). Save-EntraOpsFindingJson writes them as DataGaps of findings.json, and the Findings view of the
        Privileged Assets report shows them above the results.
          * GroupOriginUnknown: groups with role assignments whose origin is unknown (Get-EntraOpsFindingGroupOriginGap).
          * RemoteGroupMembersMissing: groups of other tenants with Control or Management Plane access whose members
            were not collected (Get-EntraOpsFindingRemoteGroupGap).
          * ObjectClassificationFileMissing: the Object Classification File is enabled (ObjectClassificationFile of
            EntraOpsConfig.json), but the file does not exist, so no object is classified by it.
          * ObjectTierCoverageLow, PawAssociationNotPopulated, WorkAccountNotPopulated: see
            Get-EntraOpsFindingClassificationGap.
          * TenantGovernanceSnapshotOutdated, TenantGovernanceResourceTypeStale, TenantGovernanceResourceTypeIncomplete:
            see Get-EntraOpsFindingTenantGovernanceGap.
    .PARAMETER Inventory
        The Privileged Assets context of the evaluation, or $null when the Privileged EAM data was not read.
    .PARAMETER ManagingTenantId
        ManagingTenantId of EntraOpsConfig.json.
    .PARAMETER ConfigFilePath
        EntraOpsConfig.json; the Object Classification File is read relative to its folder.
    .PARAMETER ReportData
        The report data of the evaluation (Import-EntraOpsReportFindingData), or $null when it was not read.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]$Inventory,

        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string]$ManagingTenantId,

        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string]$ConfigFilePath,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]$ReportData
    )

    # The rules about principals of other tenants: EO.4010 (role assignments) and EO.4011 (Control Plane). Released rule
    # IDs never change (FindingRules.lock.json).
    $ForeignRuleIds = @('EO.4010', 'EO.4011')
    if ($null -ne $Inventory -and $null -ne $Inventory.PSObject.Properties['Objects']) {
        $Origin = Get-EntraOpsFindingGroupOriginGap -Inventory $Inventory
        if ($null -ne $Origin) {
            [pscustomobject][ordered]@{ Code = 'GroupOriginUnknown'; Message = $Origin.Note; Count = $Origin.Count; RuleIds = $ForeignRuleIds }
        }
        $Remote = Get-EntraOpsFindingRemoteGroupGap -Inventory $Inventory -ManagingTenantId $ManagingTenantId
        if ($null -ne $Remote) {
            [pscustomobject][ordered]@{ Code = 'RemoteGroupMembersMissing'; Message = $Remote.Note; Count = $Remote.Count; RuleIds = $ForeignRuleIds }
        }
        Get-EntraOpsFindingClassificationGap -Inventory $Inventory
    }
    Get-EntraOpsFindingTenantGovernanceGap -ReportData $ReportData

    if (-not [string]::IsNullOrWhiteSpace($ConfigFilePath) -and (Test-Path -LiteralPath $ConfigFilePath -PathType Leaf)) {
        $Config = try { Get-Content -LiteralPath $ConfigFilePath -Raw | ConvertFrom-Json -ErrorAction Stop } catch { Write-Verbose "No data gaps read from $($ConfigFilePath): $($_.Exception.Message)"; $null }
        $Section = if ($null -ne $Config -and $null -ne $Config.PSObject.Properties['ObjectClassificationFile']) { $Config.ObjectClassificationFile } else { $null }
        $FilePath = if ($null -ne $Section -and $null -ne $Section.PSObject.Properties['FilePath']) { "$($Section.FilePath)".Trim() } else { '' }
        if ($null -ne $Section -and $null -ne $Section.PSObject.Properties['Enabled'] -and $Section.Enabled -eq $true -and $FilePath) {
            # Relative to the EntraOps folder (the folder of EntraOpsConfig.json), like Import-EntraOpsObjectClassificationFile.
            $Root = Split-Path -Parent $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($ConfigFilePath)
            $ResolvedPath = if ([System.IO.Path]::IsPathFullyQualified($FilePath)) { $FilePath } else { [System.IO.Path]::GetFullPath([System.IO.Path]::Combine($Root, $FilePath)) }
            if (-not (Test-Path -LiteralPath $ResolvedPath -PathType Leaf)) {
                $TierRuleIds = @(Get-EntraOpsFindingRule | Where-Object { $_.Category -eq 'TierBoundaries' -or $_.Key -cin 'unclassified', 'unclassifiedTarget' } | ForEach-Object { $_.Id } | Sort-Object -Unique)
                [pscustomobject][ordered]@{
                    Code    = 'ObjectClassificationFileMissing'
                    Message = "The Object Classification File is enabled (ObjectClassificationFile of EntraOpsConfig.json), but $FilePath does not exist: no object is classified by it, so the objects it should classify are unclassified or have the tier of their other classification. Create the file (for example in the Object Classification view of the Privileged Assets report) or disable the setting, and collect the Privileged EAM data again."
                    Count   = 1
                    RuleIds = $TierRuleIds
                }
            }
        }
    }
}
