function Test-EntraOpsDirectoryRoleRestrictsManagement {
    <#
    .SYNOPSIS
        True when a Microsoft Entra directory role protects its holder from lower administrators (restricted management by role).
    .DESCRIPTION
        A user with a directory role is protected from password resets and other sensitive actions by Helpdesk,
        Password, Authentication and User Administrators, except for a few roles that these administrators can still
        manage (Microsoft Learn, "Privileged roles and permissions in Microsoft Entra ID", sections "Who can reset
        passwords" and "Who can perform sensitive actions"): Directory Readers, Guest Inviter, Password Administrator,
        Helpdesk Administrator, Message Center Reader, Reports Reader, User Experience Success Manager, Usage Summary
        Reports Reader, Authentication Administrator, Groups Administrator and User Administrator. Every other built-in
        and custom role protects its holder, also when it is eligible only or scoped to an administrative unit.

        The roles are compared by their template ID (the role definition ID of a built-in role), which does not change
        with the display name. An empty or unknown ID counts as protecting, like a custom role.
    .PARAMETER RoleDefinitionId
        Role definition ID (template ID of a built-in role) of the role assignment or eligibility.
    .EXAMPLE
        Test-EntraOpsDirectoryRoleRestrictsManagement -RoleDefinitionId '88d8e3e3-8f55-4a1e-953a-9b9898b8876b'

        False: Helpdesk Administrators can reset the password of a Directory Readers holder.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param (
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$RoleDefinitionId
    )

    # Roles whose holders Helpdesk, Password, Authentication or User Administrators can still manage.
    $NonRestrictingRoleTemplateIds = @(
        '88d8e3e3-8f55-4a1e-953a-9b9898b8876b' # Directory Readers
        '95e79109-95c0-4d8e-aee3-d01accf2d47b' # Guest Inviter
        '966707d0-3269-4727-9be2-8c3a10f19b9d' # Password Administrator
        '729827e3-9c14-49f7-bb1b-9608f156bbb8' # Helpdesk Administrator
        '790c1fb9-7f7d-4f88-86a1-ef1f95c05c1b' # Message Center Reader
        '4a5d8f65-41da-4de4-8968-e035b65339cf' # Reports Reader
        '27460883-1df1-4691-b032-3b79643e5e63' # User Experience Success Manager
        '75934031-6c7e-415a-99d7-48dbd49e875e' # Usage Summary Reports Reader
        'c4e39bd9-1100-46d3-8c65-fb160da0071f' # Authentication Administrator
        'fdd7a751-b60b-444a-984c-02652fe8fa1c' # Groups Administrator
        'fe930be7-5e62-47db-91af-98c3a49a38b1' # User Administrator
    )
    if ([string]::IsNullOrWhiteSpace($RoleDefinitionId)) { return $true }
    return $NonRestrictingRoleTemplateIds -notcontains $RoleDefinitionId.Trim().ToLowerInvariant()
}
