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
    .PARAMETER Inventory
        The Privileged Assets context of the evaluation, or $null when the Privileged EAM data was not read.
    .PARAMETER ManagingTenantId
        ManagingTenantId of EntraOpsConfig.json.
    .PARAMETER ConfigFilePath
        EntraOpsConfig.json; the Object Classification File is read relative to its folder.
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
        [string]$ConfigFilePath
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
    }

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
