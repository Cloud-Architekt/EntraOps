<#
.SYNOPSIS
    Resolves or creates a role-assignable delegation group for ServiceEM landing zones.

.DESCRIPTION
    Looks up the delegation group by config ID, then by default name (only role-assignable
    security groups are accepted by name). If neither exists,
    attempts to create a role-assignable group (requires RoleManagement.ReadWrite.Directory
    scope). Persists the group ID back into EntraOpsConfig.json and the global variable
    to avoid duplicate creation on subsequent runs.

    A supplied group ID that isn't found (HTTP 404) falls back to the name-based lookup with a warning, but
    is never replaced: no group is created and the configuration isn't changed. A supplied ID that isn't a
    valid object ID, other lookup errors, and more than one role-assignable group with the default name
    stop with an error.

.PARAMETER Plane
    The plane to resolve: ControlPlane or ManagementPlane.

.PARAMETER GroupId
    Existing group ID from parameter or config. When non-empty the group is looked up and returned.

.PARAMETER DefaultGroupName
    Default display name used to search for an existing group by name.

.PARAMETER ConfigKey
    Key inside ServiceEM config to persist the group ID (e.g., ControlPlaneDelegationGroupId).

.PARAMETER ConfigFilePath
    Path to EntraOpsConfig.json for persistence. Defaults to EntraOpsConfig.json in the current folder
    when it exists, otherwise in the EntraOps working folder ($EntraOpsBaseFolder).

.PARAMETER logPrefix
    Log prefix for verbose output.

.OUTPUTS
    System.String — the Object ID of the resolved or created group.
#>
function Resolve-EntraOpsServiceEMDelegationGroup {
    [OutputType([string])]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet("ControlPlane", "ManagementPlane")]
        [string]$Plane,

        [string]$GroupId = "",

        [Parameter(Mandatory)]
        [string]$DefaultGroupName,

        [Parameter(Mandatory)]
        [string]$ConfigKey,

        # Like Connect-EntraOps: the current folder's EntraOpsConfig.json, otherwise the one in the working folder
        [string]$ConfigFilePath = $(if ((Test-Path -LiteralPath "$PWD/EntraOpsConfig.json" -PathType Leaf) -or [string]::IsNullOrWhiteSpace($Global:EntraOpsBaseFolder)) { "$PWD/EntraOpsConfig.json" } else { Join-Path $Global:EntraOpsBaseFolder 'EntraOpsConfig.json' }),

        [string]$logPrefix = "[Resolve-EntraOpsServiceEMDelegationGroup]"
    )

    # 1. If a GroupId was supplied (parameter or config), validate it and return.
    # Only a confirmed "not found" falls back to the name-based lookup; a malformed ID or any other error (e.g. 403, throttling) stops.
    $configuredGroupMissing = $false
    if (-not [string]::IsNullOrWhiteSpace($GroupId)) {
        Write-Verbose "$logPrefix $Plane delegation group ID supplied: $GroupId — validating"
        if ($GroupId -notmatch '^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$') {
            throw "$logPrefix The $Plane delegation group ID '$GroupId' (ServiceEM.$ConfigKey or parameter) is not a valid object ID. Set the Object ID of a role-assignable security group, or remove the value to look up the group by name."
        }
        $existing = $null
        try {
            $existing = Invoke-EntraOpsMsGraphQuery -Method GET -Uri "/v1.0/groups/$($GroupId)?`$select=id,displayName,isAssignableToRole,securityEnabled" -OutputType PSObject -DisableCache -ThrowOnFailure -SuppressNotFoundWarning
        } catch {
            if ($_.Exception.Data['StatusCode'] -ne 404) {
                throw "$logPrefix Failed to look up the $Plane delegation group '$GroupId' (ServiceEM.$ConfigKey): $($_.Exception.Message)"
            }
            $existing = $null
        }
        if ($existing.Id) {
            # Membership of a group that isn't role-assignable can be managed by less privileged administrators
            if (-not ($existing.isAssignableToRole -eq $true -and $existing.securityEnabled -eq $true)) {
                throw "$Plane delegation group '$($existing.DisplayName)' ($($existing.Id)) isn't a role-assignable security group. Use a role-assignable security group for ServiceEM.${Plane}DelegationGroupId."
            }
            Write-Verbose "$logPrefix Validated $Plane group: $($existing.DisplayName) ($($existing.Id))"
            return $existing.Id
        }
        $configuredGroupMissing = $true
        Write-Warning "$logPrefix Supplied $Plane group ID '$GroupId' was not found. Looking for an existing role-assignable group named '$DefaultGroupName'."
    }

    # 2. Search by default display name.
    Write-Verbose "$logPrefix Searching for existing $Plane group by name: '$DefaultGroupName'"
    try {
        $encodedDefaultGroupName = ConvertTo-EntraOpsODataStringLiteral -Value $DefaultGroupName
        $candidates = @(Invoke-EntraOpsMsGraphQuery -Method GET -Uri "/v1.0/groups?`$filter=displayName eq '$encodedDefaultGroupName'&`$select=id,displayName,isAssignableToRole,securityEnabled" -OutputType PSObject -DisableCache -ThrowOnFailure | Where-Object { $_.Id })
    } catch {
        throw "$logPrefix Failed to look up the $Plane delegation group by name '$DefaultGroupName': $($_.Exception.Message)"
    }
    # Display names are not unique: only accept role-assignable security groups to avoid binding to a look-alike group
    $found = @($candidates | Where-Object { $_.isAssignableToRole -eq $true -and $_.securityEnabled -eq $true })
    if ($candidates.Count -gt $found.Count) {
        Write-Warning "$logPrefix Ignored $($candidates.Count - $found.Count) group(s) named '$DefaultGroupName' that are not role-assignable security groups."
    }

    if ($found.Count -gt 1) {
        throw "$logPrefix Found $($found.Count) role-assignable groups named '$DefaultGroupName' ($(@($found.Id) -join ', ')). Set the Object ID of the intended $Plane delegation group in EntraOpsConfig.json under ServiceEM.$ConfigKey (or pass it as parameter) and re-run."
    }

    if ($found.Count -eq 1) {
        $resolvedId = $found[0].Id
        if ($configuredGroupMissing) {
            # The configured ID is kept so the operator can confirm the substitute group by updating it; this run uses the substitute
            Write-Warning "$logPrefix Using the existing role-assignable group '$DefaultGroupName' ($resolvedId) instead of the configured $Plane group '$GroupId', which wasn't found. Verify this group and update ServiceEM.$ConfigKey in EntraOpsConfig.json (or the parameter) to its ID."
            return $resolvedId
        }
        Write-Verbose "$logPrefix Found existing $Plane group '$DefaultGroupName' ($resolvedId)"
        # Persist to config
        Save-EntraOpsServiceEMConfigKey -ConfigKey $ConfigKey -Value $resolvedId -ConfigFilePath $ConfigFilePath -logPrefix $logPrefix
        return $resolvedId
    }

    if ($configuredGroupMissing) {
        throw "$logPrefix The $Plane delegation group '$GroupId' (ServiceEM.$ConfigKey or parameter) was not found and no role-assignable group named '$DefaultGroupName' exists. No new group is created to replace a configured one: restore the group or set the Object ID of an existing role-assignable group in ServiceEM.$ConfigKey, then re-run."
    }

    # 3. Attempt to create a role-assignable group.
    Write-Verbose "$logPrefix No existing $Plane group found. Checking permissions to create a role-assignable group."

    # Check for RoleManagement.ReadWrite.Directory scope which is required for IsAssignableToRole groups.
    $mgContext = Get-MgContext
    $requiredScope = "RoleManagement.ReadWrite.Directory"
    if ($mgContext.Scopes -notcontains $requiredScope) {
        $errorMsg = @(
            "CANNOT AUTO-CREATE ROLE-ASSIGNABLE DELEGATION GROUP FOR $Plane",
            "",
            "REASON:",
            "  The connected identity does not have the required Microsoft Graph permission scope '$requiredScope'.",
            "",
            "OPTIONS TO RESOLVE:",
            "",
            "  Option A - Create group manually (Recommended for production):",
            "    1. Create a security group with these properties:",
            "       - DisplayName: $DefaultGroupName",
            "       - IsAssignableToRole: true",
            "       - SecurityEnabled: true",
            "       - MailEnabled: false",
            "    2. Add the group ObjectId to EntraOpsConfig.json under ServiceEM.$ConfigKey",
            "    3. Re-run the landing zone cmdlet",
            "",
            "  Option B - Switch to PerService governance model (No pre-existing groups required):",
            "    - Set GovernanceModel to 'PerService' in EntraOpsConfig.json or pass -GovernanceModel PerService, OR",
            "    - Pass -AllowPerServiceFallback to New-EntraOpsSubscriptionLandingZone to create per-service groups when Centralized groups are not found",
            "",
            "  Option C - Grant permissions (for dev/test only):",
            "    - Grant RoleManagement.ReadWrite.Directory to the calling identity",
            "    - This allows auto-creation of delegation groups",
            "",
            "DOCUMENTATION:",
            "  See ServiceEM.md for detailed setup instructions."
        ) -join "`n"
        throw $errorMsg
    }

    Write-Verbose "$logPrefix Creating role-assignable $Plane group: '$DefaultGroupName'"
    try {
        $newGroupParams = @{
            displayName         = $DefaultGroupName
            description         = "Tenant-wide $Plane delegation group for ServiceEM landing zones (role-assignable)"
            mailNickname        = ($DefaultGroupName -replace '[^a-zA-Z0-9]', '')
            securityEnabled     = $true
            mailEnabled         = $false
            isAssignableToRole  = $true
        }
        $newGroup = Invoke-EntraOpsMsGraphQuery -Method POST -Uri "/v1.0/groups" -Body ($newGroupParams | ConvertTo-Json -Depth 5) -OutputType PSObject -ThrowOnFailure
        if (-not $newGroup.Id) {
            throw "Group creation returned no object ID."
        }
        Write-Verbose "$logPrefix Created role-assignable $Plane group '$DefaultGroupName' ($($newGroup.Id))"
    } catch {
        $errorMsg = @(
            "Failed to create role-assignable delegation group for $Plane.",
            "Error: $_",
            "",
            "For security, this group should be created manually:",
            "",
            "  Suggested group name:  $DefaultGroupName",
            "  IsAssignableToRole:    true",
            "  SecurityEnabled:       true",
            "  MailEnabled:           false",
            "",
            "Set its Object ID in EntraOpsConfig.json under ServiceEM.$ConfigKey, then re-run."
        ) -join "`n"
        throw $errorMsg
    }

    # Persist to config
    Save-EntraOpsServiceEMConfigKey -ConfigKey $ConfigKey -Value $newGroup.Id -ConfigFilePath $ConfigFilePath -logPrefix $logPrefix

    return $newGroup.Id
}

<#
.SYNOPSIS
    Persists a ServiceEM config key to EntraOpsConfig.json and the global variable.
#>
function Save-EntraOpsServiceEMConfigKey {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ConfigKey,

        [Parameter(Mandatory)]
        [string]$Value,

        [string]$ConfigFilePath = "$PWD/EntraOpsConfig.json",

        [string]$logPrefix = "[Save-EntraOpsServiceEMConfigKey]"
    )

    # Update global variable
    if ($null -ne $Global:EntraOpsConfig) {
        if (-not $Global:EntraOpsConfig.ContainsKey('ServiceEM')) {
            $Global:EntraOpsConfig['ServiceEM'] = @{}
        }
        $Global:EntraOpsConfig.ServiceEM[$ConfigKey] = $Value
        Write-Verbose "$logPrefix Updated Global:EntraOpsConfig.ServiceEM.$ConfigKey = $Value"
    }

    # Update config file on disk
    if (Test-Path $ConfigFilePath) {
        try {
            $configJson = Get-Content -Path $ConfigFilePath -Raw | ConvertFrom-Json -Depth 10 -AsHashtable
            if (-not $configJson.ContainsKey('ServiceEM')) {
                $configJson['ServiceEM'] = [ordered]@{
                    ControlPlaneDelegationGroupId    = ""
                    ManagementPlaneDelegationGroupId = ""
                    AdministratorGroupId             = ""
                }
            }
            $configJson.ServiceEM[$ConfigKey] = $Value
            $configJson | ConvertTo-Json -Depth 10 | Set-Content -Path $ConfigFilePath -Encoding UTF8
            Write-Verbose "$logPrefix Persisted ServiceEM.$ConfigKey to $ConfigFilePath"
        } catch {
            Write-Warning "$logPrefix Failed to persist $ConfigKey to config file: $_"
        }
    }
}
