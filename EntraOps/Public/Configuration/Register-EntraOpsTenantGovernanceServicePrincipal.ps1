<#
.SYNOPSIS
    Create and configure the first-party "Microsoft Tenant Configuration Management" (UTCM) service
    principal required by the EntraOps Tenant Governance Snapshot feature.

.DESCRIPTION
    The Tenant Governance Snapshot feature relies on the Microsoft Graph Tenant Configuration
    Management (UTCM) API to read the configured Microsoft Entra resources on EntraOps' behalf. The
    API is backed by a first-party service principal ("Microsoft Tenant Configuration Management",
    AppId 03b07b79-c5bc-4b5e-9bfa-13acf4a99998) which needs to exist in the tenant and hold
    least-privileged Microsoft Graph *read* application permissions for every resource type that
    should be captured in a snapshot.

    This cmdlet is idempotent: it creates the service principal if it doesn't exist yet, and only
    adds permissions that are not already assigned. Re-run it whenever ResourcesToInclude is
    extended with new resource types, or use New-EntraOpsWorkloadIdentity (which calls this cmdlet
    automatically when TenantGovernanceSnapshot.EnableTenantGovernanceSnapshot is set to $true).

    "ConfigurationMonitoring.ReadWrite.All" is Microsoft's documented least-privileged Microsoft
    Graph permission for the createSnapshot API - it's required for both delegated and application
    authentication, there's no Read.All-only option for creating a snapshot job (Read.All is only
    sufficient for reading/listing already-created jobs). New-EntraOpsWorkloadIdentity grants it to
    the workload identity by default. Use -GrantConfigurationMonitoringReadWrite to (re-)apply this
    grant standalone, e.g. for an existing workload identity that was set up with an older EntraOps
    version that only granted "ConfigurationMonitoring.Read.All".

    Requires an interactive or otherwise privileged Microsoft Graph session with
    "Application.ReadWrite.All" and "AppRoleAssignment.ReadWrite.All" (Global Administrator or
    Privileged Role Administrator is typically required to grant admin-consented application
    permissions).

    Reference: https://learn.microsoft.com/en-us/graph/utcm-entra-resources

.PARAMETER ResourcesToInclude
    Array of Microsoft Entra resource types (e.g. "microsoft.entra.conditionalAccessPolicy") for
    which the UTCM service principal should be granted read permissions. Defaults to the resources
    configured in TenantGovernanceSnapshot.ResourcesToInclude of the config file (if found), otherwise
    the recommended tenant governance resource set.

.PARAMETER ConfigFile
    Location of the config file used to resolve the default ResourcesToInclude and TenantId. Default
    is ./EntraOpsConfig.json. The cmdlet also works without a config file.

.PARAMETER TenantId
    TenantId to connect Microsoft Graph to. Defaults to the TenantId in the config file, or the
    current Microsoft Graph context if no config file is used or found.

.PARAMETER GrantConfigurationMonitoringReadWrite
    Grants the required "ConfigurationMonitoring.ReadWrite.All" Microsoft Graph permission to the
    EntraOps workload identity (resolved from ClientId in the config file). New-EntraOpsWorkloadIdentity
    already grants this by default for new setups - use this switch to (re-)apply it standalone,
    e.g. for an existing workload identity that was previously set up with only
    "ConfigurationMonitoring.Read.All" (which is not sufficient for creating a snapshot). Default is $false.

.EXAMPLE
    Register-EntraOpsTenantGovernanceServicePrincipal

.EXAMPLE
    Grant permissions only for Conditional Access and Named Locations.
    Register-EntraOpsTenantGovernanceServicePrincipal -ResourcesToInclude @("microsoft.entra.conditionalAccessPolicy","microsoft.entra.namedLocationPolicy")

.EXAMPLE
    Additionally grant the elevated ConfigurationMonitoring.ReadWrite.All permission to the workload identity.
    Register-EntraOpsTenantGovernanceServicePrincipal -GrantConfigurationMonitoringReadWrite
#>
function Register-EntraOpsTenantGovernanceServicePrincipal {
    [CmdletBinding(SupportsShouldProcess)]
    param (
        [Parameter(Mandatory = $false)]
        [Array]$ResourcesToInclude
        ,
        [Parameter(Mandatory = $false)]
        [string]$ConfigFile = "$EntraOpsBasefolder/EntraOpsConfig.json"
        ,
        [Parameter(Mandatory = $false)]
        [string]$TenantId
        ,
        [Parameter(Mandatory = $false)]
        [switch]$GrantConfigurationMonitoringReadWrite
    )

    $ErrorActionPreference = "Stop"
    $UtcmAppId = "03b07b79-c5bc-4b5e-9bfa-13acf4a99998"

    #region Resolve defaults from config file (optional)
    $Config = $null
    if (Test-Path -Path $ConfigFile -ErrorAction SilentlyContinue) {
        try {
            $Config = Get-Content -Path $ConfigFile | ConvertFrom-Json
        } catch {
            Write-Warning "Failed to read config file $ConfigFile. Continuing with cmdlet defaults. Error: $_"
        }
    }

    # Filter out any null values resulting from PowerShell array wrapping of $null
    $ResourcesToInclude = @($ResourcesToInclude) | Where-Object { $null -ne $_ }

    if ($ResourcesToInclude.Count -eq 0) {
        $ResourcesToInclude = if ($Config.TenantGovernanceSnapshot.ResourcesToInclude) {
            @($Config.TenantGovernanceSnapshot.ResourcesToInclude) | Where-Object { $null -ne $_ }
        } else {
            (Get-EntraOpsTenantGovernanceResourceDefinition).DefaultResources
        }
        
        if ($ResourcesToInclude.Count -eq 0) {
            $ResourcesToInclude = (Get-EntraOpsTenantGovernanceResourceDefinition).DefaultResources
        }
    }

    if (-not $TenantId -and $Config.TenantId) {
        $TenantId = $Config.TenantId
    }
    #endregion

    #region Connect to Microsoft Graph with required scopes (reuse existing session if sufficient)
    Install-EntraOpsRequiredModule -ModuleName Microsoft.Graph.Authentication

    $GraphScopes = @(
        "Application.ReadWrite.All",
        "AppRoleAssignment.ReadWrite.All"
    )
    $CurrentContext = Get-MgContext -ErrorAction SilentlyContinue
    $HasRequiredScopes = $CurrentContext -and (@($GraphScopes | Where-Object { $CurrentContext.Scopes -notcontains $_ })).Count -eq 0
    if (-not $HasRequiredScopes) {
        Write-Output "Connect to Microsoft Graph..."
        if ($TenantId) {
            Connect-MgGraph -Scopes $GraphScopes -TenantId $TenantId
        } else {
            Connect-MgGraph -Scopes $GraphScopes
        }
    } else {
        Write-Verbose "Reusing existing Microsoft Graph session with sufficient permissions."
    }
    #endregion

    # -ThrowOnFailure: a failed lookup must not look like a missing object
    Write-Verbose "Get Microsoft Graph API App Roles..."
    $MsGraph = @(Invoke-EntraOpsMsGraphQuery -Method GET -Uri "/v1.0/servicePrincipals?`$filter=appId eq '00000003-0000-0000-c000-000000000000'" -OutputType PSObject -DisableCache -ThrowOnFailure) | Select-Object -First 1

    # Some resource types (e.g. microsoft.securityandcompliance.*) are backed by the Office 365
    # Exchange Online API rather than Microsoft Graph, and require the "Exchange.ManageAsApp"
    # application permission granted on this resource service principal instead.
    Write-Verbose "Get Office 365 Exchange Online API App Roles..."
    $ExchangeOnline = @(Invoke-EntraOpsMsGraphQuery -Method GET -Uri "/v1.0/servicePrincipals?`$filter=appId eq '00000002-0000-0ff1-ce00-000000000000'" -OutputType PSObject -DisableCache -ThrowOnFailure) | Select-Object -First 1

    #region Create the UTCM service principal if it does not exist
    Write-Output "Checking Microsoft Tenant Configuration Management (UTCM) service principal..."
    $UtcmSp = @(Invoke-EntraOpsMsGraphQuery -Method GET -Uri "/v1.0/servicePrincipals?`$filter=appId eq '$UtcmAppId'" -OutputType PSObject -DisableCache -ThrowOnFailure) | Select-Object -First 1
    if (-not $UtcmSp) {
        if ($PSCmdlet.ShouldProcess("Microsoft Tenant Configuration Management (AppId: $UtcmAppId)", "Create service principal")) {
            Write-Host "Creating Service Principal for Microsoft Tenant Configuration Management (AppId: $UtcmAppId)..."
            $CreateSpBody = @{ appId = $UtcmAppId } | ConvertTo-Json -Depth 5
            try {
                $UtcmSp = Invoke-EntraOpsMsGraphQuery -Method POST -Uri "/v1.0/servicePrincipals" -Body $CreateSpBody -OutputType PSObject -DisableCache -ThrowOnFailure
            } catch {
                throw "Failed to create Service Principal for Microsoft Tenant Configuration Management. Error: $_"
            }
        }
    } else {
        Write-Host "Service Principal for Microsoft Tenant Configuration Management already exists (Id: $($UtcmSp.id))"
    }
    #endregion

    #region Assign least-privileged read permissions for the configured resources
    $ResourceDefinition = Get-EntraOpsTenantGovernanceResourceDefinition
    $RequiredUtcmPermissions = [System.Collections.Generic.HashSet[string]]::new()
    foreach ($Resource in $ResourcesToInclude) {
        $Permissions = $ResourceDefinition.ResourcePermissions[$Resource]
        if (-not $Permissions) {
            Write-Warning "No known permission mapping for resource type '$Resource'. Check https://learn.microsoft.com/en-us/graph/utcm-entra-resources and add the required Read permission(s) to the UTCM service principal manually."
            continue
        }
        foreach ($Permission in $Permissions) { $RequiredUtcmPermissions.Add($Permission) | Out-Null }
    }

    # Not every mapped permission is a read permission: microsoft.securityandcompliance.* resource types map to
    # Exchange.ManageAsApp, which allows running Exchange Online PowerShell as an app. Surface any non-read
    # grant explicitly and require confirmation rather than assigning it under a "read permissions" banner.
    $NonReadPermissions = @($RequiredUtcmPermissions | Where-Object { $_ -notmatch '\.Read(\.|$)' } | Sort-Object)
    if ($NonReadPermissions.Count -gt 0) {
        Write-Warning "The following permission(s) are NOT read-only and grant management capability to the Microsoft Tenant Configuration Management service principal: $($NonReadPermissions -join ', '). They are required by the resource type(s) selected in ResourcesToInclude."
        # -WhatIf only reports the grant; a declined confirmation stops before anything is assigned.
        if (-not $PSCmdlet.ShouldProcess("Microsoft Tenant Configuration Management service principal ($($UtcmSp.id))", "Grant non-read permission(s): $($NonReadPermissions -join ', ')") -and -not $WhatIfPreference) {
            throw "Aborted by user: remove the resource type(s) requiring $($NonReadPermissions -join ', ') from ResourcesToInclude, or re-run and confirm the grant."
        }
    }

    $ReadPermissionCount = $RequiredUtcmPermissions.Count - $NonReadPermissions.Count
    Write-Output "Assigning $($RequiredUtcmPermissions.Count) required permission(s) to the UTCM service principal ($ReadPermissionCount read, $($NonReadPermissions.Count) non-read)..."
    # Under -WhatIf a missing service principal was not created, so it has no assignments yet.
    $ExistingUtcmAssignments = if ($UtcmSp.id) { @(Invoke-EntraOpsMsGraphQuery -Method GET -Uri "/v1.0/servicePrincipals/$($UtcmSp.id)/appRoleAssignments" -OutputType PSObject -DisableCache -ThrowOnFailure) } else { @() }
    $AssignedCount = 0
    $AlreadyPresentCount = 0
    $FailedPermissions = [System.Collections.Generic.List[string]]::new()
    foreach ($RequiredPermission in $RequiredUtcmPermissions) {
        # Resolve which resource service principal (Microsoft Graph or Office 365 Exchange Online) owns this app role.
        $ResourceSp = $MsGraph
        $AppRole = $MsGraph.appRoles | Where-Object { $_.value -eq $RequiredPermission }
        if (-not $AppRole -and $ExchangeOnline) {
            $AppRole = $ExchangeOnline.appRoles | Where-Object { $_.value -eq $RequiredPermission }
            if ($AppRole) { $ResourceSp = $ExchangeOnline }
        }
        if (-not $AppRole) {
            Write-Warning "Could not find app role '$RequiredPermission' on Microsoft Graph or Office 365 Exchange Online."
            $FailedPermissions.Add($RequiredPermission)
            continue
        }
        $IsAssigned = $ExistingUtcmAssignments | Where-Object { $_.appRoleId -eq $AppRole.id -and $_.resourceId -eq $ResourceSp.id }
        if (-not $IsAssigned) {
            if (-not $PSCmdlet.ShouldProcess("Microsoft Tenant Configuration Management service principal", "Assign $($AppRole.value)")) {
                continue
            }
            Write-Host "- Assigning $($AppRole.value) to Microsoft Tenant Configuration Management service principal"
            $AssignmentBody = @{
                principalId = $UtcmSp.id
                resourceId  = $ResourceSp.id
                appRoleId   = $AppRole.id
            } | ConvertTo-Json -Depth 5
            try {
                Invoke-EntraOpsMsGraphQuery -Method POST -Uri "/v1.0/servicePrincipals/$($UtcmSp.id)/appRoleAssignments" -Body $AssignmentBody -OutputType PSObject -DisableCache -ThrowOnFailure | Out-Null
                $AssignedCount++
            } catch {
                Write-Warning "Failed to assign $($AppRole.value) to Microsoft Tenant Configuration Management service principal. This can happen if the signed-in account doesn't hold sufficient privilege to consent to this specific permission (some application permissions can only be admin-consented by a Global Administrator, even when signed in as Application Administrator or Privileged Role Administrator). Error: $_"
                $FailedPermissions.Add($RequiredPermission)
            }
        } else {
            Write-Verbose "$($AppRole.value) already assigned to Microsoft Tenant Configuration Management service principal"
            $AlreadyPresentCount++
        }
    }
    #endregion

    Write-Output "Microsoft Tenant Configuration Management service principal is configured. $AssignedCount new permission(s) assigned, $AlreadyPresentCount already present."
    if ($FailedPermissions.Count -gt 0) {
        Write-Warning "Failed to assign $($FailedPermissions.Count) permission(s) to the UTCM service principal: $($FailedPermissions -join ', '). This commonly happens when the signed-in account only holds Application Administrator, Cloud Application Administrator or Privileged Role Administrator rather than Global Administrator - some Microsoft Graph application permissions can only be admin-consented by a Global Administrator. Sign in as a Global Administrator and re-run Register-EntraOpsTenantGovernanceServicePrincipal to grant the remaining permission(s)."
    }

    #region Optionally (re-)grant the required ConfigurationMonitoring.ReadWrite.All permission to the EntraOps workload identity
    # ConfigurationMonitoring.ReadWrite.All is granted by default via New-EntraOpsWorkloadIdentity for
    # new setups. This switch lets it be (re-)applied standalone, e.g. for an existing workload
    # identity that was previously set up with only the insufficient "ConfigurationMonitoring.Read.All".
    $ReadWriteGranted = $false
    if ($GrantConfigurationMonitoringReadWrite) {
        if (-not $Config -or [string]::IsNullOrEmpty($Config.ClientId) -or $Config.ClientId -like "Use New-EntraOpsWorkloadIdentity*") {
            Write-Warning "Cannot grant ConfigurationMonitoring.ReadWrite.All: no valid ClientId found in '$ConfigFile'. Run New-EntraOpsWorkloadIdentity first, or pass -ConfigFile pointing to a populated config file."
        } else {
            Write-Output "Granting elevated 'ConfigurationMonitoring.ReadWrite.All' permission to the EntraOps workload identity (AppId: $($Config.ClientId))..."
            $WorkloadIdentitySp = @(Invoke-EntraOpsMsGraphQuery -Method GET -Uri "/v1.0/servicePrincipals?`$filter=appId eq '$($Config.ClientId)'" -OutputType PSObject -DisableCache -ThrowOnFailure) | Select-Object -First 1
            if (-not $WorkloadIdentitySp) {
                Write-Warning "Could not find a service principal for AppId $($Config.ClientId) in the tenant."
            } else {
                $ReadWriteAppRole = $MsGraph.appRoles | Where-Object { $_.value -eq "ConfigurationMonitoring.ReadWrite.All" }
                if (-not $ReadWriteAppRole) {
                    Write-Warning "Could not find Microsoft Graph app role 'ConfigurationMonitoring.ReadWrite.All'."
                } else {
                    $ExistingWorkloadIdentityAssignments = @(Invoke-EntraOpsMsGraphQuery -Method GET -Uri "/v1.0/servicePrincipals/$($WorkloadIdentitySp.id)/appRoleAssignments" -OutputType PSObject -DisableCache -ThrowOnFailure)
                    $IsWorkloadIdentityAssigned = $ExistingWorkloadIdentityAssignments | Where-Object { $_.appRoleId -eq $ReadWriteAppRole.id -and $_.resourceId -eq $MsGraph.id }
                    if (-not $IsWorkloadIdentityAssigned -and -not $PSCmdlet.ShouldProcess("EntraOps workload identity ($($Config.ClientId))", "Assign ConfigurationMonitoring.ReadWrite.All")) {
                        Write-Verbose "Skipped ConfigurationMonitoring.ReadWrite.All assignment."
                    } elseif (-not $IsWorkloadIdentityAssigned) {
                        $WorkloadIdentityAssignmentBody = @{
                            principalId = $WorkloadIdentitySp.id
                            resourceId  = $MsGraph.id
                            appRoleId   = $ReadWriteAppRole.id
                        } | ConvertTo-Json -Depth 5
                        try {
                            Invoke-EntraOpsMsGraphQuery -Method POST -Uri "/v1.0/servicePrincipals/$($WorkloadIdentitySp.id)/appRoleAssignments" -Body $WorkloadIdentityAssignmentBody -OutputType PSObject -DisableCache -ThrowOnFailure | Out-Null
                            Write-Host "- Assigned ConfigurationMonitoring.ReadWrite.All to the EntraOps workload identity" -ForegroundColor Yellow
                            $ReadWriteGranted = $true
                        } catch {
                            Write-Warning "Failed to assign ConfigurationMonitoring.ReadWrite.All to the workload identity. Error: $_"
                        }
                    } else {
                        Write-Verbose "ConfigurationMonitoring.ReadWrite.All already assigned to the EntraOps workload identity"
                        $ReadWriteGranted = $true
                    }
                }
            }
        }
    } else {
        Write-Verbose "Skipping elevated ConfigurationMonitoring.ReadWrite.All grant (use -GrantConfigurationMonitoringReadWrite to enable it)."
    }
    #endregion

    [PSCustomObject]@{
        ServicePrincipalId                       = $UtcmSp.id
        AppId                                     = $UtcmAppId
        ResourcesToInclude                        = @($ResourcesToInclude)
        RequiredPermissions                       = @($RequiredUtcmPermissions)
        NewlyAssignedCount                        = $AssignedCount
        AlreadyPresentCount                       = $AlreadyPresentCount
        FailedPermissions                         = @($FailedPermissions)
        ConfigurationMonitoringReadWriteGranted    = $ReadWriteGranted
    }
}
