<#
.SYNOPSIS
    Get transitive group members of a security group in Microsoft Entra ID.

.DESCRIPTION
    Get transitive group members of a security group in Microsoft Entra ID.
    This covers also direct and nested group members which are eligible or active members in PIM for Groups.

.PARAMETER GroupObjectId
    Object ID of the security group in Microsoft Entra ID.

.EXAMPLE
    Get a list of all direct and nested group members of a security group in Microsoft Entra ID:
    Get-EntaOpsPrivilegedTransitiveGroupMember -GroupObjectId "00000000-0000-0000-0000-000000000000"
#>

function Get-EntraOpsPrivilegedTransitiveGroupMember {

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $True)]
        [System.String]$GroupObjectId
    )

    # Check details for security group to identify synchronized groups
    try {
        $GroupUri = "/beta/groups/$($GroupObjectId)?`$select=id,displayName,onPremisesSyncEnabled"
        $GroupDetails = Invoke-EntraOpsMsGraphQuery -Method "Get" -Uri $GroupUri -OutputType PSObject | select-object DisplayName, Id, onPremisesSyncEnabled
        Write-Verbose "Get transitive group members of $($GroupDetails.displayName)"
    }
    catch {
        Write-Error $_
        throw "Group object with ID $($GroupObjectId) can not be found!"
    }

    # Check if group is synchronized from on-premises AD and otherwise check if group has member assignments in PIM for Groups
    if ($GroupDetails.onPremisesSyncEnabled -ne $true) {
        try {
            Write-Verbose "Try to get identify if $($GroupDetails.displayName) has eligible or active users in PIM for Groups"
            $PimForGroupMembersUri = "/beta/identityGovernance/privilegedAccess/group/eligibilitySchedules?`$filter=groupId eq `'$($GroupObjectId)`'&`$expand=principal"
            $PimForGroupMembers = (Invoke-EntraOpsMsGraphQuery -Method "Get" -Uri $PimForGroupMembersUri -OutputType PSObject)
        }
        catch {
            Write-Error $_
            throw "Validation of Group object with ID $($GroupObjectId) on eligible or active assignment has been failed"
        }
    }
    else {
        Write-Verbose "Group $($GroupDetails.displayName) is synchronized from on-premises AD and can not be managed by PIM for Groups"
    }

    $AllGroupMembers = @()

    # Check direct or nested eligible membership for cloud-only security groups which can be managed by PIM for Groups
    if ($PimForGroupMembers) {

        # Query for roleAssignmentScheduleInstances to get permanent and active members
        $PimForGroupsMembersUri = "/beta/identityGovernance/privilegedAccess/group/assignmentScheduleInstances?`$filter=groupId eq `'$($GroupObjectId)`'&`$expand=principal"
        $PimForGroupsMembers = (Invoke-EntraOpsMsGraphQuery -Method "Get" -Uri $PimForGroupsMembersUri -OutputType PSObject)

        #Permanent Members in PIM-managed Group
        Write-Verbose "- Permanent membership"
        $PermanentMembers = ($PimForGroupsMembers | Where-Object { $_.assignmentType -eq "assigned" }).principal | Where-Object { $null -ne $_.Id } | select-object DisplayName, Id, '@odata.type'
        $PermanentMembers | Add-Member -MemberType NoteProperty -Name "RoleAssignmentSubType" -Value "Permanent member" -Force

        #Active Members in PIM-managed Group
        $ActiveMembers = ($PimForGroupsMembers | Where-Object { $_.assignmentType -eq "active" }).principal | Where-Object { $null -ne $_.Id } | select-object DisplayName, Id, '@odata.type'
        $ActiveMembers | Add-Member -MemberType NoteProperty -Name "RoleAssignmentSubType" -Value "Active member" -Force

        # Eligible Member
        Write-Verbose "- Direct eligible membership"
        $EligibleMembersUri = "/beta/identityGovernance/privilegedAccess/group/eligibilitySchedules?`$filter=groupId eq `'$($GroupObjectId)`'&`$expand=principal"
        $EligibleMembers = (Invoke-EntraOpsMsGraphQuery -Method "Get" -Uri $EligibleMembersUri -OutputType PSObject | Where-Object { $_.status -eq "Provisioned" -and $_.accessId -eq "member" }).principal | Where-Object { $null -ne $_.Id } | select-object DisplayName, Id, '@odata.type'
        $EligibleMembers | Add-Member -MemberType NoteProperty -Name "RoleAssignmentSubType" -Value "Eligible member" -Force

        # Check if Eligible Member groups have nested permanent group assignments
        Write-Verbose "- Nested permanent group member of eligible group"
        $EligibleNestedPermanentMembers = $EligibleMembers | Where-Object { $_.'@odata.type' -eq "#microsoft.graph.group" } | ForEach-Object {
            $EligibleNestedPermanentMembersUri = "/beta/groups/$($_.id)/transitiveMembers?`$select=id,displayName,userPrincipalName"
            $EligibleNestedPermanentMember = Invoke-EntraOpsMsGraphQuery -Method "Get" -Uri $EligibleNestedPermanentMembersUri -OutputType PSObject
            $EligibleNestedPermanentMember | Add-Member -MemberType NoteProperty -Name "RoleAssignmentSubType" -Value "Nested Eligible member" -Force
            $EligibleNestedPermanentMember | Where-Object { $null -ne $_.Id }
        }

        # Summarize all eligible and transitive eligible members of direct or direct nested groups
        $AllGroupMembers = @()
        $AllGroupMembers += $PermanentMembers
        $AllGroupMembers += $EligibleMembers
        $AllGroupMembers += $EligibleNestedPermanentMembers

        #region Check if Eligible Member group has eligible member
        Write-Verbose "- Eligible member group has eligible members"

        $NestedMemberGroups = $AllGroupMembers | Where-Object { $_.'@odata.type' -eq "#microsoft.graph.group" }
        $TransitiveNestedEligibleMembers = @()
        foreach ($NestedMemberGroup in $NestedMemberGroups) {
            do {
                Write-Verbose "- Expand nesting for $($NestedMemberGroup.id)"
                $NestedEligibleMembers = $($NestedMemberGroup) | foreach-object {
                    $NestedEligibleMember = Get-EntraOpsPrivilegedTransitiveGroupMember -GroupObjectId $_.id
                    $NestedEligibleMember | Add-Member -MemberType NoteProperty -Name "RoleAssignmentSubType" -Value "Nested Eligible group member" -Force

                    #Check if nested group is not already in the list
                    $NestedEligibleMember = $NestedEligibleMember | Where-Object { $_.Id -notin $TransitiveNestedEligibleMembers.Id }
                    return $NestedEligibleMember
                }

                $TransitiveNestedEligibleMembers += $NestedEligibleMembers
                $EligibleNestedMemberGroup = $NestedEligibleMembers | Where-Object { $_.'@odata.type' -eq "#microsoft.graph.group" }
            } until ($EligibleNestedMemberGroup.'@odata.type' -notcontains "#microsoft.graph.group" -or $null -eq $EligibleNestedMemberGroup)
        }
        #endregion

        $AllGroupMembers += $TransitiveNestedEligibleMembers | Where-Object { $_.id -notin $AllGroupMembers.id }

    }
    else {
        # Permanent Transitive Member
        Write-Verbose "- Transitive permanent membership"
        $TransitivePermanentMembersUri = "/beta/groups/$($GroupObjectId)/transitiveMembers?`$select=id,displayName,userPrincipalName"
        $TransitivePermanentMembers = Invoke-EntraOpsMsGraphQuery -Method "Get" -Uri $TransitivePermanentMembersUri -OutputType PSObject | Where-Object { $null -ne $_.Id } | select-object DisplayName, Id, '@odata.type'
        $TransitivePermanentMembers | Add-Member -MemberType NoteProperty -Name "RoleAssignmentSubType" -Value "Permanent member" -Force

        # No eligible members to add
        $AllGroupMembers += $TransitivePermanentMembers
    }
    #endregion
    return $AllGroupMembers
}