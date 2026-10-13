<#
.SYNOPSIS
    Resolves or creates a role-assignable delegation group for ServiceEM landing zones.

.DESCRIPTION
    Looks up the delegation group by config ID, then by default name. If neither exists,
    attempts to create a role-assignable group (requires RoleManagement.ReadWrite.Directory
    scope). Persists the group ID back into EntraOpsConfig.json and the global variable
    to avoid duplicate creation on subsequent runs.

.PARAMETER Plane
    The plane to resolve: ControlPlane or ManagementPlane.

.PARAMETER GroupId
    Existing group ID from parameter or config. When non-empty the group is looked up and returned.

.PARAMETER DefaultGroupName
    Default display name used to search for an existing group by name.

.PARAMETER ConfigKey
    Key inside ServiceEM config to persist the group ID (e.g., ControlPlaneDelegationGroupId).

.PARAMETER ConfigFilePath
    Path to EntraOpsConfig.json for persistence.

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

        [string]$ConfigFilePath = "$PWD/EntraOpsConfig.json",

        [string]$logPrefix = "[Resolve-EntraOpsServiceEMDelegationGroup]"
    )

    # 1. If a GroupId was supplied (parameter or config), validate it exists and return.
    if (-not [string]::IsNullOrWhiteSpace($GroupId)) {
        Write-Verbose "$logPrefix $Plane delegation group ID supplied: $GroupId — validating"
        try {
            if ($GroupId -notmatch '^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$') {
                throw "'$GroupId' is not a valid object ID"
            }
            $existing = Invoke-EntraOpsMsGraphQuery -Method GET -Uri "/v1.0/groups/$GroupId" -OutputType PSObject -DisableCache -ThrowOnFailure -SuppressNotFoundWarning
            if (-not $existing.Id) {
                throw "Group '$GroupId' not found"
            }
            Write-Verbose "$logPrefix Validated $Plane group: $($existing.DisplayName) ($($existing.Id))"
            return $existing.Id
        } catch {
            Write-Warning "$logPrefix Supplied $Plane group ID '$GroupId' could not be found. Falling back to name-based lookup."
        }
    }

    # 2. Search by default display name.
    Write-Verbose "$logPrefix Searching for existing $Plane group by name: '$DefaultGroupName'"
    try {
        $encodedDefaultGroupName = ConvertTo-EntraOpsODataStringLiteral -Value $DefaultGroupName
        $found = @(Invoke-EntraOpsMsGraphQuery -Method GET -Uri "/v1.0/groups?`$filter=displayName eq '$encodedDefaultGroupName'" -OutputType PSObject -DisableCache -ThrowOnFailure | Where-Object { $_.Id })
    } catch {
        Write-Verbose "$logPrefix Name-based lookup failed: $_"
        $found = $null
    }

    if ($found -and ($found | Measure-Object).Count -eq 1) {
        $resolvedId = $found.Id
        Write-Verbose "$logPrefix Found existing $Plane group '$DefaultGroupName' ($resolvedId)"
        # Persist to config
        Save-EntraOpsServiceEMConfigKey -ConfigKey $ConfigKey -Value $resolvedId -ConfigFilePath $ConfigFilePath -logPrefix $logPrefix
        return $resolvedId
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
            "    - Set GovernanceModel to 'PerService' in EntraOpsConfig.json, OR",
            "    - Wait for auto-fallback (if enabled) when Centralized groups are not found",
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
