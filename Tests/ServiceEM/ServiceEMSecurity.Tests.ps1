#Requires -Modules Pester
#Requires -Version 7.0

BeforeAll {
    $script:TestRepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
    $script:PreviousEntraOpsConfig = Get-Variable EntraOpsConfig -Scope Global -ErrorAction SilentlyContinue

    function Invoke-EntraOpsMsGraphQuery {
        param(
            [string]$Method,
            [string]$Uri,
            [string]$Body,
            [string]$ConsistencyLevel,
            [string]$OutputType,
            [switch]$DisableCache,
            [switch]$ThrowOnFailure,
            [switch]$SuppressNotFoundWarning,
            [switch]$SuppressBadRequestWarning
        )
        throw 'Invoke-EntraOpsMsGraphQuery must be mocked'
    }
    function Save-EntraOpsServiceEMConfigKey { param($ConfigKey, $Value, $ConfigFilePath, $logPrefix) }
    function Get-MgContext { throw 'Get-MgContext must be mocked' }
    function Get-AzResourceGroup { param($Name, $ErrorAction) throw 'Get-AzResourceGroup must be mocked' }
    function Remove-AzResourceGroup { param($Name, [switch]$Force) }
    function Get-AzContext { throw 'Get-AzContext must be mocked' }
    function Set-AzContext { param($Subscription, $Tenant, $Context, $ErrorAction) throw 'Set-AzContext must be mocked' }
    function Get-AzSubscription { param($SubscriptionId, $TenantId, $ErrorAction) throw 'Get-AzSubscription must be mocked' }

    . "$script:TestRepositoryRoot/EntraOps/Private/ConvertTo-EntraOpsODataStringLiteral.ps1"
    . "$script:TestRepositoryRoot/EntraOps/Private/Resolve-EntraOpsServiceEMDelegationGroup.ps1"
    . "$script:TestRepositoryRoot/EntraOps/Private/Wait-EntraOpsServiceEMCondition.ps1"
    . "$script:TestRepositoryRoot/EntraOps/Private/Get-EntraOpsServiceEMConfigValue.ps1"
    . "$script:TestRepositoryRoot/EntraOps/Public/ServiceEM/New-EntraOpsServiceEMCatalog.ps1"
    . "$script:TestRepositoryRoot/EntraOps/Public/ServiceEM/New-EntraOpsServiceEMAssignmentPolicy.ps1"
    . "$script:TestRepositoryRoot/EntraOps/Public/ServiceEM/New-EntraOpsServicePIMPolicy.ps1"
    . "$script:TestRepositoryRoot/EntraOps/Public/ServiceEM/Remove-EntraOpsServiceCatalog.ps1"
}

AfterAll {
    if ($script:PreviousEntraOpsConfig) {
        Set-Variable EntraOpsConfig -Scope Global -Value $script:PreviousEntraOpsConfig.Value
    } else {
        Remove-Variable EntraOpsConfig -Scope Global -ErrorAction SilentlyContinue
    }
}

Describe 'ServiceEM shared helpers' {
    AfterEach {
        $Global:EntraOpsConfig = $null
    }

    It 'returns true as soon as the condition is met' {
        Mock Start-Sleep {}
        $state = @{ Calls = 0 }

        Wait-EntraOpsServiceEMCondition -Condition { $state.Calls++; $state.Calls -ge 3 } | Should -BeTrue

        $state.Calls | Should -Be 3
    }

    It 'caps the interval and returns false after the maximum wait time' {
        $script:Sleeps = [System.Collections.Generic.List[int]]::new()
        Mock Start-Sleep { $script:Sleeps.Add($Seconds) }

        Wait-EntraOpsServiceEMCondition -Condition { $false } -MaxWaitSeconds 100 -MaxIntervalSeconds 30 | Should -BeFalse

        ($script:Sleeps | Measure-Object -Maximum).Maximum | Should -Be 30
        ($script:Sleeps | Measure-Object -Sum).Sum | Should -BeGreaterOrEqual 100
        $script:Sleeps -join ',' | Should -Be '0,1,3,7,15,30,30,30'
    }

    It 'reads ServiceEM config values from hashtable and PSCustomObject configurations' {
        $Global:EntraOpsConfig = @{ ServiceEM = @{ CreateM365Group = $true; PIMForGroups = @{ MaximumActivationDuration = 'PT4H' } } }
        Get-EntraOpsServiceEMConfigValue -Path 'CreateM365Group' | Should -BeTrue
        Get-EntraOpsServiceEMConfigValue -Path 'PIMForGroups.MaximumActivationDuration' | Should -Be 'PT4H'

        $Global:EntraOpsConfig = [pscustomobject]@{ ServiceEM = [pscustomobject]@{ DefaultAzureRegion = 'westeurope' } }
        Get-EntraOpsServiceEMConfigValue -Path 'DefaultAzureRegion' | Should -Be 'westeurope'
        Get-EntraOpsServiceEMConfigValue -Path 'Missing.Value' | Should -BeNullOrEmpty

        $Global:EntraOpsConfig = $null
        Get-EntraOpsServiceEMConfigValue -Path 'CreateM365Group' | Should -BeNullOrEmpty
    }
}

Describe 'ServiceEM workload plane admin and group ownership' {
    BeforeAll {
        foreach ($name in 'New-EntraOpsServiceEntraGroup', 'New-EntraOpsServiceEMCatalogResource', 'New-EntraOpsServiceEMCatalogResourceRole', 'New-EntraOpsServiceEMAccessPackage', 'New-EntraOpsServiceEMAccessPackageResourceAssignment', 'New-EntraOpsServiceEMAssignment', 'New-EntraOpsServicePIMAssignment', 'New-EntraOpsServiceAZContainer', 'New-EntraOpsServiceBootstrap') {
            . "$script:TestRepositoryRoot/EntraOps/Public/ServiceEM/$name.ps1"
        }
    }

    BeforeEach {
        Mock Get-MgContext { [pscustomobject]@{ Account = 'caller@contoso.com'; AuthType = 'Delegated' } }
        Mock Invoke-EntraOpsMsGraphQuery {
            if ($Uri -like '/v1.0/users/*') { return [pscustomobject]@{ Id = "id:$($Uri -replace '^/v1.0/users/')" } }
        }
        Mock New-EntraOpsServiceEntraGroup { @([pscustomobject]@{ Id = 'g1'; DisplayName = 'SG-Rg-X-WorkloadPlane-Admins' }) }
        Mock New-EntraOpsServiceEMCatalog { [pscustomobject]@{ Id = 'cat' } }
        Mock New-EntraOpsServiceEMCatalogResource { @([pscustomobject]@{ Id = 'r1' }) }
        Mock New-EntraOpsServiceEMCatalogResourceRole { @() }
        Mock New-EntraOpsServiceEMAccessPackage { @([pscustomobject]@{ Id = 'ap1'; DisplayName = 'AP-Rg-X-WorkloadPlane-Admins' }) }
        Mock New-EntraOpsServiceEMAccessPackageResourceAssignment { @() }
        Mock New-EntraOpsServiceEMAssignmentPolicy { @([pscustomobject]@{ Id = 'pol1'; DisplayName = 'Workload Plane Policy' }) }
        Mock New-EntraOpsServiceEMAssignment { @() }
        Mock New-EntraOpsServicePIMPolicy { @() }
        Mock New-EntraOpsServicePIMAssignment { @() }
    }

    It 'assigns the workload plane admin to the admin access package without setting group owners' {
        New-EntraOpsServiceBootstrap -ServiceName 'Rg-X' -SkipAzureResourceGroup -WorkloadPlaneAdmin 'admin@contoso.com' -ServiceMembers @() 6>$null | Out-Null

        Should -Invoke New-EntraOpsServiceEntraGroup -Times 1 -Exactly -ParameterFilter { [string]::IsNullOrEmpty($WorkloadPlaneAdmin) }
        Should -Invoke New-EntraOpsServiceEMAssignment -Times 1 -Exactly -ParameterFilter { $WorkloadPlaneAdmin.Id -eq 'id:admin@contoso.com' }
        Should -Invoke New-EntraOpsServicePIMAssignment -Times 1 -Exactly -ParameterFilter { [string]::IsNullOrEmpty($WorkloadPlaneAdminPrincipalId) }
    }

    It 'sets the workload plane admin as permanent owner only with GroupOwnership Permanent and warns' {
        New-EntraOpsServiceBootstrap -ServiceName 'Rg-X' -SkipAzureResourceGroup -WorkloadPlaneAdmin 'admin@contoso.com' -ServiceMembers @() -GroupOwnership Permanent -WarningVariable warnings -WarningAction SilentlyContinue 6>$null | Out-Null

        Should -Invoke New-EntraOpsServiceEntraGroup -Times 1 -Exactly -ParameterFilter { $WorkloadPlaneAdmin -eq 'https://graph.microsoft.com/v1.0/users/id:admin@contoso.com' }
        Should -Invoke New-EntraOpsServicePIMAssignment -Times 1 -Exactly -ParameterFilter { [string]::IsNullOrEmpty($WorkloadPlaneAdminPrincipalId) -and -not $EnableOwnerAssignment }
        @($warnings | Where-Object { "$_" -like '*-GroupOwnership Permanent*bypassing access package approvals*' }).Count | Should -Be 1
    }

    It 'makes the workload plane admin an eligible owner with GroupOwnership Eligible' {
        New-EntraOpsServiceBootstrap -ServiceName 'Rg-X' -SkipAzureResourceGroup -WorkloadPlaneAdmin 'admin@contoso.com' -ServiceMembers @() -GroupOwnership Eligible -WarningAction SilentlyContinue 6>$null | Out-Null

        Should -Invoke New-EntraOpsServiceEntraGroup -Times 1 -Exactly -ParameterFilter { [string]::IsNullOrEmpty($WorkloadPlaneAdmin) }
        Should -Invoke New-EntraOpsServicePIMAssignment -Times 1 -Exactly -ParameterFilter { $WorkloadPlaneAdminPrincipalId -eq 'id:admin@contoso.com' -and $EnableOwnerAssignment }
    }

    It 'resolves the signed-in user as eligible owner with GroupOwnership Eligible only' {
        New-EntraOpsServiceBootstrap -ServiceName 'Rg-X' -SkipAzureResourceGroup -ServiceMembers @() -GroupOwnership Eligible -WarningAction SilentlyContinue 6>$null | Out-Null

        Should -Invoke New-EntraOpsServicePIMAssignment -Times 1 -Exactly -ParameterFilter { $WorkloadPlaneAdminPrincipalId -eq 'id:caller@contoso.com' }
    }

    It 'ignores ManagementPlane-Members in custom service roles with a warning' {
        $roles = @(
            [pscustomobject]@{ accessLevel = 'ManagementPlane'; name = 'Members'; groupType = '' },
            [pscustomobject]@{ accessLevel = 'WorkloadPlane'; name = 'Admins'; groupType = '' }
        )

        New-EntraOpsServiceBootstrap -ServiceName 'Rg-X' -SkipAzureResourceGroup -ServiceMembers @() -ServiceRoles $roles -WarningVariable warnings -WarningAction SilentlyContinue 6>$null | Out-Null

        Should -Invoke New-EntraOpsServiceEntraGroup -Times 1 -Exactly -ParameterFilter { @($ServiceRoles | Where-Object { $_.accessLevel -eq 'ManagementPlane' }).Count -eq 0 }
        @($warnings | Where-Object { "$_" -like '*ManagementPlane-Members is no longer supported*' }).Count | Should -Be 1
    }

    It 'accepts NoPimEscalation as alias of NoPimForGroups' {
        New-EntraOpsServiceBootstrap -ServiceName 'Rg-X' -SkipAzureResourceGroup -ServiceMembers @() -NoPimEscalation 6>$null | Out-Null

        Should -Invoke New-EntraOpsServicePIMAssignment -Times 0 -Exactly
        Should -Invoke New-EntraOpsServiceEntraGroup -Times 1 -Exactly -ParameterFilter { $NoPimForGroups }
    }

    It 'forwards CatalogPlaneMembers and does not create the PIM staging group by default' {
        New-EntraOpsServiceBootstrap -ServiceName 'Rg-X' -SkipAzureResourceGroup -ServiceMembers @() -CatalogPlaneMembers @('ops@contoso.com') 6>$null | Out-Null

        Should -Invoke New-EntraOpsServiceEMAssignment -Times 1 -Exactly -ParameterFilter { @($CatalogPlaneMembers.Id) -join ',' -eq 'id:ops@contoso.com' }
        Should -Invoke New-EntraOpsServiceEntraGroup -Times 1 -Exactly -ParameterFilter { -not $EnablePIMStagingGroup }
    }

    Context 'initial ControlPlane-Admins members' {
        BeforeEach {
            $script:CpRequests = [System.Collections.Generic.List[object]]::new()
            Mock New-EntraOpsServiceEntraGroup { @([pscustomobject]@{ Id = 'cp'; DisplayName = 'SG-Rg-X-ControlPlane-Admins' }) }
            Mock Invoke-EntraOpsMsGraphQuery {
                if ($Uri -like '/v1.0/users/*') { return [pscustomobject]@{ Id = "id:$($Uri -replace '^/v1.0/users/')" } }
                if ($Method -eq 'POST') { $script:CpRequests.Add([pscustomobject]@{ Uri = $Uri; Body = ($Body | ConvertFrom-Json) }); return [pscustomobject]@{ Id = 'req' } }
                if ($Uri -like '/v1.0/groups/cp/members*') { return @([pscustomobject]@{ Id = 'id:existing@contoso.com' }) }
                return @()
            }
            Mock Get-AzContext { [pscustomobject]@{ Tenant = [pscustomobject]@{ Id = 't' }; Subscription = [pscustomobject]@{ Id = '11111111-1111-1111-1111-111111111111' } } }
            Mock Get-AzSubscription { [pscustomobject]@{ Id = $SubscriptionId } }
            Mock New-EntraOpsServiceAZContainer { [pscustomobject]@{ ResourceId = 'rg' } }
        }

        It 'adds permanent members when the Azure roles of ControlPlane-Admins are PIM-eligible' {
            New-EntraOpsServiceBootstrap -ServiceName 'Rg-X' -AzureRegion 'westeurope' -SubscriptionId '11111111-1111-1111-1111-111111111111' -ServiceMembers @() `
                -ControlPlaneAdmins @('cp@contoso.com', 'existing@contoso.com') 6>$null | Out-Null

            $script:CpRequests.Count | Should -Be 1
            $script:CpRequests[0].Uri | Should -Be '/v1.0/groups/cp/members/$ref'
            $script:CpRequests[0].Body.'@odata.id' | Should -Be 'https://graph.microsoft.com/v1.0/directoryObjects/id:cp@contoso.com'
        }

        It 'gives the admin groups of another scope their Azure roles on this scope' {
            New-EntraOpsServiceBootstrap -ServiceName 'Rg-X' -AzureRegion 'westeurope' -SubscriptionId '11111111-1111-1111-1111-111111111111' -ServiceMembers @() `
                -ManagementPlaneApproverGroupId 'sub-mp' -ControlPlaneApproverGroupId 'sub-cp' 6>$null | Out-Null

            Should -Invoke New-EntraOpsServiceAZContainer -Times 1 -Exactly -ParameterFilter {
                ($ServiceGroups | Where-Object { $_.Id -eq 'sub-mp' -and $_.DisplayName -eq 'SG-Rg-X-ManagementPlane-Admins' }) -and
                -not ($ServiceGroups | Where-Object { $_.Id -eq 'sub-cp' })
            }
        }

        It 'adds PIM for Groups eligible members without Azure roles' {
            New-EntraOpsServiceBootstrap -ServiceName 'Rg-X' -SkipAzureResourceGroup -ServiceMembers @() -ControlPlaneAdmins @('cp@contoso.com') 6>$null | Out-Null

            $script:CpRequests.Count | Should -Be 1
            $script:CpRequests[0].Uri | Should -Be '/v1.0/identityGovernance/privilegedAccess/group/eligibilityScheduleRequests'
            $script:CpRequests[0].Body.accessId | Should -Be 'member'
            $script:CpRequests[0].Body.groupId | Should -Be 'cp'
            $script:CpRequests[0].Body.principalId | Should -Be 'id:cp@contoso.com'
        }

        It 'warns when no per-service ControlPlane-Admins group exists' {
            Mock New-EntraOpsServiceEntraGroup { @([pscustomobject]@{ Id = 'g1'; DisplayName = 'SG-Rg-X-WorkloadPlane-Admins' }) }

            New-EntraOpsServiceBootstrap -ServiceName 'Rg-X' -SkipAzureResourceGroup -ServiceMembers @() -ControlPlaneAdmins @('cp@contoso.com') -WarningVariable warnings -WarningAction SilentlyContinue 6>$null | Out-Null

            $script:CpRequests.Count | Should -Be 0
            @($warnings | Where-Object { "$_" -like '*-ControlPlaneAdmins is ignored*' }).Count | Should -Be 1
        }
    }

    It 'resolves no workload plane admin without WorkloadPlaneAdmin and GroupOwnership' {
        New-EntraOpsServiceBootstrap -ServiceName 'Rg-X' -SkipAzureResourceGroup -ServiceMembers @() 6>$null | Out-Null

        Should -Invoke New-EntraOpsServiceEMAssignment -Times 1 -Exactly -ParameterFilter { $null -eq $WorkloadPlaneAdmin }
    }

    It 'adds the workload plane admin to the service members only with AddWorkloadPlaneAdminToUsers' {
        New-EntraOpsServiceBootstrap -ServiceName 'Rg-X' -SkipAzureResourceGroup -WorkloadPlaneAdmin 'admin@contoso.com' -ServiceMembers @('dev@contoso.com') 6>$null | Out-Null
        New-EntraOpsServiceBootstrap -ServiceName 'Rg-X' -SkipAzureResourceGroup -WorkloadPlaneAdmin 'admin@contoso.com' -ServiceMembers @('dev@contoso.com') -AddWorkloadPlaneAdminToUsers 6>$null | Out-Null

        Should -Invoke New-EntraOpsServiceEMAssignment -Times 1 -Exactly -ParameterFilter { @($ServiceMembers.Id) -join ',' -eq 'id:dev@contoso.com' }
        Should -Invoke New-EntraOpsServiceEMAssignment -Times 1 -Exactly -ParameterFilter { @($ServiceMembers.Id) -join ',' -eq 'id:dev@contoso.com,id:admin@contoso.com' }
    }

    It 'uses AddWorkloadPlaneAdminToUsers from ServiceEM config unless the parameter is set explicitly' {
        $Global:EntraOpsConfig = @{ ServiceEM = @{ AddWorkloadPlaneAdminToUsers = $true } }
        try {
            New-EntraOpsServiceBootstrap -ServiceName 'Rg-X' -SkipAzureResourceGroup -WorkloadPlaneAdmin 'admin@contoso.com' -ServiceMembers @() 6>$null | Out-Null
            New-EntraOpsServiceBootstrap -ServiceName 'Rg-X' -SkipAzureResourceGroup -WorkloadPlaneAdmin 'admin@contoso.com' -ServiceMembers @() -AddWorkloadPlaneAdminToUsers:$false 6>$null | Out-Null
        } finally {
            $Global:EntraOpsConfig = $null
        }

        Should -Invoke New-EntraOpsServiceEMAssignment -Times 1 -Exactly -ParameterFilter { @($ServiceMembers.Id) -contains 'id:admin@contoso.com' }
        Should -Invoke New-EntraOpsServiceEMAssignment -Times 1 -Exactly -ParameterFilter { @($ServiceMembers).Count -eq 0 }
    }

    It 'uses GroupPrefix from ServiceEM config unless the parameter is set explicitly' {
        $Global:EntraOpsConfig = @{ ServiceEM = @{ GroupPrefix = 'GRP' } }
        try {
            New-EntraOpsServiceBootstrap -ServiceName 'Rg-X' -SkipAzureResourceGroup -ServiceMembers @() 6>$null | Out-Null
            New-EntraOpsServiceBootstrap -ServiceName 'Rg-X' -SkipAzureResourceGroup -ServiceMembers @() -GroupPrefix 'SEC' 6>$null | Out-Null
            $Global:EntraOpsConfig = @{ ServiceEM = @{ GroupPrefix = 'S G' } }
            { New-EntraOpsServiceBootstrap -ServiceName 'Rg-X' -SkipAzureResourceGroup -ServiceMembers @() 6>$null } | Should -Throw "*GroupPrefix 'S G' is invalid*"
        } finally {
            $Global:EntraOpsConfig = $null
        }

        Should -Invoke New-EntraOpsServiceEntraGroup -Times 1 -Exactly -ParameterFilter { $GroupPrefix -eq 'GRP' }
        Should -Invoke New-EntraOpsServiceEntraGroup -Times 1 -Exactly -ParameterFilter { $GroupPrefix -eq 'SEC' }
    }

    It 'stops before creating objects when a user lookup fails' {
        Mock Invoke-EntraOpsMsGraphQuery {
            if ($Uri -eq '/v1.0/users/missing@contoso.com') { return $null }
            if ($Uri -eq '/v1.0/users/broken@contoso.com') { throw 'Request_ResourceNotFound' }
            if ($Uri -like '/v1.0/users/*') { return [pscustomobject]@{ Id = "id:$($Uri -replace '^/v1.0/users/')" } }
        }

        { New-EntraOpsServiceBootstrap -ServiceName 'Rg-X' -SkipAzureResourceGroup -ServiceMembers @('dev@contoso.com', 'missing@contoso.com') 6>$null } |
        Should -Throw '*Unable to resolve service member (/v1.0/users/missing@contoso.com): object not found*'
        { New-EntraOpsServiceBootstrap -ServiceName 'Rg-X' -SkipAzureResourceGroup -WorkloadPlaneAdmin 'broken@contoso.com' -ServiceMembers @() 6>$null } |
        Should -Throw '*Unable to resolve WorkloadPlaneAdmin*Request_ResourceNotFound*'

        Should -Invoke New-EntraOpsServiceEntraGroup -Times 0 -Exactly
        Should -Invoke New-EntraOpsServiceEMCatalog -Times 0 -Exactly
    }

    It 'forwards SkipCatalogOwnerAssignment to the catalog role assignment' {
        New-EntraOpsServiceBootstrap -ServiceName 'Rg-X' -SkipAzureResourceGroup -ServiceMembers @() -SkipCatalogOwnerAssignment 6>$null | Out-Null

        Should -Invoke New-EntraOpsServiceEMCatalogResourceRole -Times 1 -Exactly -ParameterFilter { $SkipCatalogOwnerAssignment }
    }

    It 'creates no Microsoft 365 group and passes no existing one downstream by default' {
        Mock New-EntraOpsServiceEntraGroup {
            @(
                [pscustomobject]@{ Id = 'm365'; DisplayName = 'Rg-X Members'; GroupTypes = @('Unified') },
                [pscustomobject]@{ Id = 'g1'; DisplayName = 'SG-Rg-X-WorkloadPlane-Admins'; GroupTypes = @() }
            )
        }

        New-EntraOpsServiceBootstrap -ServiceName 'Rg-X' -SkipAzureResourceGroup -ServiceMembers @() 6>$null | Out-Null

        Should -Invoke New-EntraOpsServiceEntraGroup -Times 1 -Exactly -ParameterFilter {
            @($ServiceRoles | Where-Object groupType -EQ 'Unified').Count -eq 0 -and @($ServiceRoles).Count -gt 0
        }
        Should -Invoke New-EntraOpsServicePIMAssignment -Times 1 -Exactly -ParameterFilter { $ServiceGroups.Id -notcontains 'm365' }
        Should -Invoke New-EntraOpsServiceEMCatalogResource -Times 1 -Exactly -ParameterFilter { $ServiceGroups.Id -notcontains 'm365' }
    }

    It 'creates the Microsoft 365 group with CreateM365Group' {
        Mock New-EntraOpsServiceEntraGroup {
            @(
                [pscustomobject]@{ Id = 'm365'; DisplayName = 'Rg-X Members'; GroupTypes = @('Unified') },
                [pscustomobject]@{ Id = 'g1'; DisplayName = 'SG-Rg-X-WorkloadPlane-Admins'; GroupTypes = @() }
            )
        }

        New-EntraOpsServiceBootstrap -ServiceName 'Rg-X' -SkipAzureResourceGroup -ServiceMembers @() -CreateM365Group 6>$null | Out-Null

        Should -Invoke New-EntraOpsServiceEntraGroup -Times 1 -Exactly -ParameterFilter { @($ServiceRoles | Where-Object groupType -EQ 'Unified').Count -eq 1 }
        Should -Invoke New-EntraOpsServicePIMAssignment -Times 1 -Exactly -ParameterFilter { $ServiceGroups.Id -contains 'm365' }
    }

    It 'uses CreateM365Group from ServiceEM config unless the parameter is passed' {
        $Global:EntraOpsConfig = @{ ServiceEM = @{ CreateM365Group = $true } }
        try {
            New-EntraOpsServiceBootstrap -ServiceName 'Rg-X' -SkipAzureResourceGroup -ServiceMembers @() 6>$null | Out-Null
            New-EntraOpsServiceBootstrap -ServiceName 'Rg-X' -SkipAzureResourceGroup -ServiceMembers @() -CreateM365Group:$false 6>$null | Out-Null
        } finally {
            $Global:EntraOpsConfig = $null
        }

        Should -Invoke New-EntraOpsServiceEntraGroup -Times 1 -Exactly -ParameterFilter { @($ServiceRoles | Where-Object groupType -EQ 'Unified').Count -eq 1 }
        Should -Invoke New-EntraOpsServiceEntraGroup -Times 1 -Exactly -ParameterFilter { @($ServiceRoles | Where-Object groupType -EQ 'Unified').Count -eq 0 }
    }

    It 'skips a scope that has no groups left without the Microsoft 365 group' {
        $roles = @([pscustomobject]@{ accessLevel = ''; name = 'Members'; groupType = 'Unified' })

        New-EntraOpsServiceBootstrap -ServiceName 'Sub-X' -SkipAzureResourceGroup -ServiceMembers @() -ServiceRoles $roles 6>$null | Out-Null

        Should -Invoke New-EntraOpsServiceEntraGroup -Times 0 -Exactly
        Should -Invoke New-EntraOpsServiceEMCatalog -Times 0 -Exactly
    }

    Context 'administrator group membership' {
        BeforeAll {
            $script:RgRoles = @(
                [pscustomobject]@{ accessLevel = ''; name = 'Members'; groupType = 'Unified' },
                [pscustomobject]@{ accessLevel = 'WorkloadPlane'; name = 'Users'; groupType = '' },
                [pscustomobject]@{ accessLevel = 'WorkloadPlane'; name = 'Admins'; groupType = '' }
            )
            $script:AdminGroupId = '44444444-4444-4444-4444-444444444444'
        }

        BeforeEach {
            Mock Invoke-EntraOpsMsGraphQuery {
                if ($Uri -like '/v1.0/users/*') { return [pscustomobject]@{ Id = "id:$($Uri -replace '^/v1.0/users/')" } }
                if ($Uri -like '*/checkMemberGroups') { return $script:MemberOfResult }
            }
        }

        It 'throws before creating groups when the admin is not in the administrator group' {
            $script:MemberOfResult = $null

            { New-EntraOpsServiceBootstrap -ServiceName 'Rg-X' -SkipAzureResourceGroup -WorkloadPlaneAdmin 'admin@contoso.com' -ServiceMembers @() -ServiceRoles $script:RgRoles -AdministratorGroupId $script:AdminGroupId 6>$null } |
            Should -Throw '*is not a member of the administrator group*'

            Should -Invoke Invoke-EntraOpsMsGraphQuery -Times 1 -Exactly -ParameterFilter { $Uri -eq '/v1.0/directoryObjects/id:admin@contoso.com/checkMemberGroups' -and $Body -match $script:AdminGroupId }
            Should -Invoke New-EntraOpsServiceEntraGroup -Times 0 -Exactly
        }

        It 'continues when the admin is in the administrator group' {
            $script:MemberOfResult = @($script:AdminGroupId)

            { New-EntraOpsServiceBootstrap -ServiceName 'Rg-X' -SkipAzureResourceGroup -WorkloadPlaneAdmin 'admin@contoso.com' -ServiceMembers @() -ServiceRoles $script:RgRoles -AdministratorGroupId $script:AdminGroupId 6>$null } |
            Should -Not -Throw

            Should -Invoke New-EntraOpsServiceEntraGroup -Times 1 -Exactly
        }

        It 'skips the check when WorkloadPlane-Members scopes the admin policy' {
            $roles = @($script:RgRoles) + [pscustomobject]@{ accessLevel = 'WorkloadPlane'; name = 'Members'; groupType = '' }

            New-EntraOpsServiceBootstrap -ServiceName 'Rg-X' -SkipAzureResourceGroup -WorkloadPlaneAdmin 'admin@contoso.com' -ServiceMembers @() -ServiceRoles $roles -AdministratorGroupId $script:AdminGroupId 6>$null | Out-Null

            Should -Invoke Invoke-EntraOpsMsGraphQuery -Times 0 -Exactly -ParameterFilter { $Uri -like '*/checkMemberGroups' }
        }
    }
}

Describe 'ServiceEM catalog owner assignment' {
    BeforeAll {
        . "$script:TestRepositoryRoot/EntraOps/Public/ServiceEM/New-EntraOpsServiceEMCatalogResourceRole.ps1"
        $script:OwnerRoleId = 'ae79f266-94d4-4dab-b730-feca7e132178'
        $script:CatalogGroups = @('SG-Rg-X-CatalogPlane-Members', 'SG-Rg-X-WorkloadPlane-Admins', 'prg_Tenant-ControlPlane-Admins') |
        ForEach-Object { [pscustomobject]@{ Id = "id:$_"; DisplayName = $_ } }
    }

    BeforeEach {
        $script:RoleBodies = [System.Collections.Generic.List[object]]::new()
        $script:CreatedRoles = [System.Collections.Generic.List[object]]::new()
        Mock Start-Sleep {}
        Mock Invoke-EntraOpsMsGraphQuery {
            if ($Method -eq 'POST') {
                $role = $Body | ConvertFrom-Json
                $script:RoleBodies.Add($role)
                $created = [pscustomobject]@{ id = [guid]::NewGuid().Guid; principalId = $role.principalId; roleDefinitionId = $role.roleDefinitionId }
                $script:CreatedRoles.Add($created)
                return $created
            }
            return $script:CreatedRoles.ToArray()
        }
    }

    It 'assigns Catalog Owner to ControlPlane-Admins by default' {
        New-EntraOpsServiceEMCatalogResourceRole -ServiceGroups $script:CatalogGroups -ServiceCatalogId 'cat' 6>$null | Out-Null

        @($script:RoleBodies | Where-Object { $_.roleDefinitionId -eq $script:OwnerRoleId -and $_.principalId -eq 'id:prg_Tenant-ControlPlane-Admins' }).Count | Should -Be 1
    }

    It 'skips the Catalog Owner assignment with SkipCatalogOwnerAssignment' {
        New-EntraOpsServiceEMCatalogResourceRole -ServiceGroups $script:CatalogGroups -ServiceCatalogId 'cat' -SkipCatalogOwnerAssignment 6>$null | Out-Null

        @($script:RoleBodies | Where-Object { $_.roleDefinitionId -eq $script:OwnerRoleId }).Count | Should -Be 0
        $script:RoleBodies.Count | Should -BeGreaterThan 0
    }
}

Describe 'ServiceEM access package assignment fulfillment' {
    BeforeAll {
        . "$script:TestRepositoryRoot/EntraOps/Public/ServiceEM/New-EntraOpsServiceEMAssignment.ps1"
        $script:Packages = @(
            [pscustomobject]@{ Id = 'ap-users'; DisplayName = 'AP-Rg-X-WorkloadPlane-Users' },
            [pscustomobject]@{ Id = 'ap-admins'; DisplayName = 'AP-Rg-X-WorkloadPlane-Admins' }
        )
        $script:Policies = @(
            [pscustomobject]@{ Id = 'pol-users'; DisplayName = 'Workload Plane Users Policy' },
            [pscustomobject]@{ Id = 'pol-admins'; DisplayName = 'Workload Plane Policy' }
        )
    }

    BeforeEach {
        Mock Start-Sleep {}
        Mock Invoke-EntraOpsMsGraphQuery {
            if ($Method -eq 'POST') {
                $target = ($Body | ConvertFrom-Json).assignment.targetId
                if ($target -eq 'out-of-scope') { return $null }
                return [pscustomobject]@{ Id = "req-$target"; State = 'submitted' }
            }
            if ($Uri -match '/assignmentRequests/(req-.+)$') {
                return [pscustomobject]@{ Id = $Matches[1]; State = (& $script:NextState $Matches[1]); Status = 'x' }
            }
            return @()
        }
    }

    It 'does not wait for members whose request was rejected' {
        $script:NextState = { param($id) 'delivered' }

        New-EntraOpsServiceEMAssignment -ServiceCatalogId 'cat' -ServiceMembers @([pscustomobject]@{ Id = 'out-of-scope' }, [pscustomobject]@{ Id = 'admin' }) `
            -WorkloadPlaneAdmin ([pscustomobject]@{ Id = 'admin2' }) -ServiceAssignmentPolicies $script:Policies -ServicePackages $script:Packages `
            -WarningVariable warnings -WarningAction SilentlyContinue 6>$null | Out-Null

        @($warnings | Where-Object { "$_" -like '*out-of-scope*rejected*' }).Count | Should -Be 1
        Should -Invoke Start-Sleep -Times 1 -Exactly
    }

    It 'stops waiting for requests that need approval or failed' {
        $script:NextState = { param($id) if ($id -eq 'req-admin') { 'pendingApproval' } else { 'deliveryFailed' } }

        New-EntraOpsServiceEMAssignment -ServiceCatalogId 'cat' -ServiceMembers @([pscustomobject]@{ Id = 'admin' }) `
            -WorkloadPlaneAdmin ([pscustomobject]@{ Id = 'admin2' }) -ServiceAssignmentPolicies $script:Policies -ServicePackages $script:Packages `
            -WarningVariable warnings -WarningAction SilentlyContinue 6>$null | Out-Null

        @($warnings | Where-Object { "$_" -like '*waiting for approval*' }).Count | Should -Be 1
        @($warnings | Where-Object { "$_" -like '*deliveryFailed*' }).Count | Should -Be 1
        Should -Invoke Start-Sleep -Times 1 -Exactly
    }

    It 'uses the initial direct assignment policies when they exist' {
        $script:AssignmentBodies = [System.Collections.Generic.List[object]]::new()
        Mock Invoke-EntraOpsMsGraphQuery {
            if ($Method -eq 'POST') {
                $body = $Body | ConvertFrom-Json
                $script:AssignmentBodies.Add($body)
                return [pscustomobject]@{ Id = "req-$($body.assignment.targetId)"; State = 'submitted' }
            }
            if ($Uri -match '/assignmentRequests/(req-.+)$') { return [pscustomobject]@{ Id = $Matches[1]; State = 'delivered' } }
            return @()
        }
        $policies = @($script:Policies) + @(
            [pscustomobject]@{ Id = 'pol-initial-users'; DisplayName = 'Initial Workload Users Policy' },
            [pscustomobject]@{ Id = 'pol-initial-admins'; DisplayName = 'Initial Workload Admin Policy' }
        )

        New-EntraOpsServiceEMAssignment -ServiceCatalogId 'cat' -ServiceMembers @([pscustomobject]@{ Id = 'member' }) `
            -WorkloadPlaneAdmin ([pscustomobject]@{ Id = 'admin' }) -ServiceAssignmentPolicies $policies -ServicePackages $script:Packages 6>$null | Out-Null

        ($script:AssignmentBodies | Where-Object { $_.assignment.targetId -eq 'member' }).assignment.assignmentPolicyId | Should -Be 'pol-initial-users'
        ($script:AssignmentBodies | Where-Object { $_.assignment.targetId -eq 'admin' }).assignment.assignmentPolicyId | Should -Be 'pol-initial-admins'
    }

    It 'adds a rejected target as specific user to the admin-only initial policy and retries' {
        $script:AssignmentBodies = [System.Collections.Generic.List[object]]::new()
        $script:PolicyPuts = [System.Collections.Generic.List[object]]::new()
        Mock Invoke-EntraOpsMsGraphQuery {
            if ($Method -eq 'PUT') { $script:PolicyPuts.Add([pscustomobject]@{ Uri = $Uri; Body = ($Body | ConvertFrom-Json) }); return }
            if ($Method -eq 'POST') {
                $body = $Body | ConvertFrom-Json
                if ($body.assignment.targetId -eq 'admin' -and $script:PolicyPuts.Count -eq 0) {
                    $exception = [System.InvalidOperationException]::new('BadRequest')
                    $exception.Data['StatusCode'] = 400
                    throw $exception
                }
                $script:AssignmentBodies.Add($body)
                return [pscustomobject]@{ Id = "req-$($body.assignment.targetId)"; State = 'submitted' }
            }
            if ($Uri -like '*/assignmentPolicies/pol-initial-admins*') {
                return [pscustomobject]@{
                    Id = 'pol-initial-admins'; DisplayName = 'Initial Workload Admin Policy'; Description = 'd'; AllowedTargetScope = 'allMemberUsers'; SpecificAllowedTargets = @()
                    Expiration = [pscustomobject]@{ type = 'noExpiration' }; RequestorSettings = [pscustomobject]@{ enableTargetsToSelfAddAccess = $false }
                    RequestApprovalSettings = [pscustomobject]@{ isApprovalRequiredForAdd = $false }; AccessPackage = [pscustomobject]@{ Id = 'ap-admins' }
                }
            }
            if ($Uri -match '/assignmentRequests/(req-.+)$') { return [pscustomobject]@{ Id = $Matches[1]; State = 'delivered' } }
            return @()
        }
        $policies = @($script:Policies) + @([pscustomobject]@{ Id = 'pol-initial-admins'; DisplayName = 'Initial Workload Admin Policy' })

        New-EntraOpsServiceEMAssignment -ServiceCatalogId 'cat' -ServiceMembers @() `
            -WorkloadPlaneAdmin ([pscustomobject]@{ Id = 'admin' }) -ServiceAssignmentPolicies $policies -ServicePackages $script:Packages 6>$null | Out-Null

        $script:PolicyPuts.Count | Should -Be 1
        $script:PolicyPuts[0].Body.allowedTargetScope | Should -Be 'specificDirectoryUsers'
        $script:PolicyPuts[0].Body.specificAllowedTargets[0].'@odata.type' | Should -Be '#microsoft.graph.singleUser'
        $script:PolicyPuts[0].Body.specificAllowedTargets[0].userId | Should -Be 'admin'
        $script:PolicyPuts[0].Body.accessPackage.id | Should -Be 'ap-admins'
        $script:AssignmentBodies.assignment.assignmentPolicyId | Should -Be 'pol-initial-admins'
    }

    It 'assigns the admin package even if the admin already holds another package of the catalog' {
        $script:AssignmentBodies = [System.Collections.Generic.List[object]]::new()
        Mock Invoke-EntraOpsMsGraphQuery {
            if ($Method -eq 'POST') {
                $body = $Body | ConvertFrom-Json
                $script:AssignmentBodies.Add($body)
                return [pscustomobject]@{ Id = "req-$($body.assignment.targetId)"; State = 'submitted' }
            }
            if ($Uri -like '*/assignments?*') {
                return @([pscustomobject]@{ Id = 'a1'; Target = [pscustomobject]@{ ObjectId = 'admin' }; AccessPackage = [pscustomobject]@{ Id = 'ap-users' } })
            }
            if ($Uri -match '/assignmentRequests/(req-.+)$') { return [pscustomobject]@{ Id = $Matches[1]; State = 'delivered' } }
            return @()
        }

        New-EntraOpsServiceEMAssignment -ServiceCatalogId 'cat' -ServiceMembers @([pscustomobject]@{ Id = 'admin' }) `
            -WorkloadPlaneAdmin ([pscustomobject]@{ Id = 'admin' }) -ServiceAssignmentPolicies $script:Policies -ServicePackages $script:Packages 6>$null | Out-Null

        $script:AssignmentBodies.Count | Should -Be 1
        $script:AssignmentBodies[0].assignment.accessPackageId | Should -Be 'ap-admins'
    }

    It 'does not submit a duplicate while a request of the same package waits for approval' {
        $script:AssignmentBodies = [System.Collections.Generic.List[object]]::new()
        Mock Invoke-EntraOpsMsGraphQuery {
            if ($Method -eq 'POST') { $script:AssignmentBodies.Add(($Body | ConvertFrom-Json)); return [pscustomobject]@{ Id = 'req-x'; State = 'submitted' } }
            if ($Uri -like "*assignmentRequests?*state eq 'pendingApproval'*") {
                return @([pscustomobject]@{ Id = 'r1'; State = 'pendingApproval'; Assignment = [pscustomobject]@{ Target = [pscustomobject]@{ ObjectId = 'admin' } }; AccessPackage = [pscustomobject]@{ Id = 'ap-admins' } })
            }
            return @()
        }

        New-EntraOpsServiceEMAssignment -ServiceCatalogId 'cat' -ServiceMembers @() `
            -WorkloadPlaneAdmin ([pscustomobject]@{ Id = 'admin' }) -ServiceAssignmentPolicies $script:Policies -ServicePackages $script:Packages 6>$null | Out-Null

        $script:AssignmentBodies.Count | Should -Be 0
    }

    It 'continues with a warning instead of waiting indefinitely' {
        $script:NextState = { param($id) 'delivering' }

        { New-EntraOpsServiceEMAssignment -ServiceCatalogId 'cat' -ServiceMembers @([pscustomobject]@{ Id = 'admin' }) `
            -ServiceAssignmentPolicies $script:Policies -ServicePackages $script:Packages `
            -WarningVariable script:warnings -WarningAction SilentlyContinue 6>$null } | Should -Not -Throw

        @($script:warnings | Where-Object { "$_" -like '*continuing without waiting*req-admin=delivering*' }).Count | Should -Be 1
        Should -Invoke Start-Sleep -Times 15 -Exactly
        Should -Invoke Start-Sleep -ParameterFilter { $Seconds -gt 30 } -Times 0 -Exactly
    }

    It 'assigns the workload plane admin and CatalogPlaneMembers to CatalogPlane-Members' {
        $script:AssignmentBodies = [System.Collections.Generic.List[object]]::new()
        Mock Invoke-EntraOpsMsGraphQuery {
            if ($Method -eq 'POST') {
                $body = $Body | ConvertFrom-Json
                $script:AssignmentBodies.Add($body)
                return [pscustomobject]@{ Id = "req-$($body.assignment.targetId)-$($body.assignment.accessPackageId)"; State = 'submitted' }
            }
            if ($Uri -match '/assignmentRequests/(req-.+)$') { return [pscustomobject]@{ Id = $Matches[1]; State = 'delivered' } }
            return @()
        }
        $packages = @($script:Packages) + [pscustomobject]@{ Id = 'ap-catalog'; DisplayName = 'AP-Rg-X-CatalogPlane-Members' }
        $policies = @($script:Policies) + [pscustomobject]@{ Id = 'pol-initial-catalog'; DisplayName = 'Initial Catalog Members Policy' }

        New-EntraOpsServiceEMAssignment -ServiceCatalogId 'cat' -ServiceMembers @() -WorkloadPlaneAdmin ([pscustomobject]@{ Id = 'admin' }) `
            -CatalogPlaneMembers @([pscustomobject]@{ Id = 'ops' }, [pscustomobject]@{ Id = 'admin' }) `
            -ServiceAssignmentPolicies $policies -ServicePackages $packages 6>$null | Out-Null

        $catalogBodies = @($script:AssignmentBodies | Where-Object { $_.assignment.accessPackageId -eq 'ap-catalog' })
        @($catalogBodies | ForEach-Object { $_.assignment.targetId } | Sort-Object) | Should -Be @('admin', 'ops')
        @($catalogBodies | ForEach-Object { $_.assignment.assignmentPolicyId } | Select-Object -Unique) | Should -Be @('pol-initial-catalog')
    }
}

Describe 'ServiceEM Azure subscription targeting' {
    BeforeAll {
        foreach ($name in 'New-EntraOpsServiceEntraGroup', 'New-EntraOpsServiceEMCatalogResource', 'New-EntraOpsServiceEMCatalogResourceRole', 'New-EntraOpsServiceEMAccessPackage', 'New-EntraOpsServiceEMAccessPackageResourceAssignment', 'New-EntraOpsServiceEMAssignment', 'New-EntraOpsServicePIMAssignment', 'New-EntraOpsServiceAZContainer', 'New-EntraOpsServiceBootstrap', 'New-EntraOpsSubscriptionLandingZone') {
            . "$script:TestRepositoryRoot/EntraOps/Public/ServiceEM/$name.ps1"
        }
        $script:TargetSub = '11111111-1111-1111-1111-111111111111'
        $script:PreviousSub = '22222222-2222-2222-2222-222222222222'
    }

    BeforeEach {
        $script:CurrentSub = $script:PreviousSub
        $script:SubAtContainer = $null
        Mock Get-AzContext { [pscustomobject]@{ Tenant = [pscustomobject]@{ Id = 'tenant-1' }; Subscription = [pscustomobject]@{ Id = $script:CurrentSub } } }
        Mock Set-AzContext {
            if ($Subscription) { $script:CurrentSub = $Subscription } elseif ($Context) { $script:CurrentSub = $Context.Subscription.Id }
        }
        Mock Get-AzSubscription { [pscustomobject]@{ Id = $SubscriptionId } }
        Mock Get-MgContext { [pscustomobject]@{ Account = 'caller@contoso.com'; AuthType = 'Delegated' } }
        Mock Invoke-EntraOpsMsGraphQuery {}
        Mock New-EntraOpsServiceEntraGroup { @([pscustomobject]@{ Id = 'g1'; DisplayName = 'SG-Rg-X-WorkloadPlane-Admins' }) }
        Mock New-EntraOpsServiceEMCatalog { [pscustomobject]@{ Id = 'cat' } }
        Mock New-EntraOpsServiceEMCatalogResource { @([pscustomobject]@{ Id = 'r1' }) }
        Mock New-EntraOpsServiceEMCatalogResourceRole { @() }
        Mock New-EntraOpsServiceEMAccessPackage { @([pscustomobject]@{ Id = 'ap1'; DisplayName = 'AP-Rg-X-WorkloadPlane-Admins' }) }
        Mock New-EntraOpsServiceEMAccessPackageResourceAssignment { @() }
        Mock New-EntraOpsServiceEMAssignmentPolicy { @() }
        Mock New-EntraOpsServiceEMAssignment { @() }
        Mock New-EntraOpsServicePIMPolicy { @() }
        Mock New-EntraOpsServicePIMAssignment { @() }
        Mock New-EntraOpsServiceAZContainer { $script:SubAtContainer = $script:CurrentSub; [pscustomobject]@{ ResourceId = 'rg-id' } }
    }

    It 'requires SubscriptionId in Bootstrap before creating any Entra object' {
        { New-EntraOpsServiceBootstrap -ServiceName 'Rg-X' -AzureRegion 'westeurope' -ServiceMembers @() } |
        Should -Throw '*-SubscriptionId is required*'

        Should -Invoke New-EntraOpsServiceEntraGroup -Times 0 -Exactly
    }

    It 'requires SubscriptionId in the landing zone before any scope is bootstrapped' {
        Mock New-EntraOpsServiceBootstrap {}

        { New-EntraOpsSubscriptionLandingZone -DeploymentPrefix 'X' -AzureRegion 'westeurope' -GovernanceModel PerService } |
        Should -Throw '*-SubscriptionId is required*'

        Should -Invoke New-EntraOpsServiceBootstrap -Times 0 -Exactly
    }

    It 'does not require SubscriptionId with SkipAzureResourceGroup' {
        { New-EntraOpsServiceBootstrap -ServiceName 'Rg-X' -SkipAzureResourceGroup -ServiceMembers @() 6>$null } | Should -Not -Throw

        Should -Invoke Get-AzSubscription -Times 0 -Exactly
        Should -Invoke Set-AzContext -Times 0 -Exactly
    }

    It 'fails before creating Entra objects when the subscription is not accessible' {
        Mock Get-AzSubscription { throw 'Subscription not found' }

        { New-EntraOpsServiceBootstrap -ServiceName 'Rg-X' -AzureRegion 'westeurope' -SubscriptionId $script:TargetSub -ServiceMembers @() } |
        Should -Throw '*Subscription not found*'

        Should -Invoke New-EntraOpsServiceEntraGroup -Times 0 -Exactly
    }

    It 'creates the resource group in the target subscription and restores the previous context' {
        New-EntraOpsServiceBootstrap -ServiceName 'Rg-X' -AzureRegion 'westeurope' -SubscriptionId $script:TargetSub -ServiceMembers @() 6>$null | Out-Null

        Should -Invoke Get-AzSubscription -Times 1 -Exactly -ParameterFilter { $SubscriptionId -eq $script:TargetSub -and $TenantId -eq 'tenant-1' }
        Should -Invoke Set-AzContext -Times 1 -Exactly -ParameterFilter { $Subscription -eq $script:TargetSub -and $Tenant -eq 'tenant-1' }
        $script:SubAtContainer | Should -Be $script:TargetSub
        $script:CurrentSub | Should -Be $script:PreviousSub
    }

    It 'restores the previous context when resource group creation fails' {
        Mock New-EntraOpsServiceAZContainer { throw 'RG failed' }

        { New-EntraOpsServiceBootstrap -ServiceName 'Rg-X' -AzureRegion 'westeurope' -SubscriptionId $script:TargetSub -ServiceMembers @() 6>$null } |
        Should -Throw '*RG failed*'

        $script:CurrentSub | Should -Be $script:PreviousSub
    }

    It 'forwards SubscriptionId only to the Rg scope of the landing zone' {
        Mock New-EntraOpsServiceBootstrap { [pscustomobject]@{ ServiceName = $ServiceName } }
        Mock Resolve-EntraOpsServiceEMDelegationGroup { '33333333-3333-3333-3333-333333333333' }

        New-EntraOpsSubscriptionLandingZone -DeploymentPrefix 'X' -DeploymentScope Both -AzureRegion 'westeurope' -SubscriptionId $script:TargetSub -GovernanceModel PerService 6>$null | Out-Null

        Should -Invoke New-EntraOpsServiceBootstrap -Times 1 -Exactly -ParameterFilter { $ServiceName -eq 'Rg-X' -and $SubscriptionId -eq $script:TargetSub -and -not $SkipAzureResourceGroup }
        Should -Invoke New-EntraOpsServiceBootstrap -Times 1 -Exactly -ParameterFilter { $ServiceName -eq 'Sub-X' -and [string]::IsNullOrEmpty($SubscriptionId) -and $SkipAzureResourceGroup }
    }
}

Describe 'ServiceEM landing zone deployment scope' {
    BeforeAll {
        . "$script:TestRepositoryRoot/EntraOps/Public/ServiceEM/New-EntraOpsServiceBootstrap.ps1"
        . "$script:TestRepositoryRoot/EntraOps/Public/ServiceEM/New-EntraOpsSubscriptionLandingZone.ps1"
        $script:TargetSub = '11111111-1111-1111-1111-111111111111'
        $script:HasRole = { param($roles, $level, $name) [bool]($roles | Where-Object { $_.accessLevel -eq $level -and $_.name -eq $name }) }
    }

    BeforeEach {
        $Global:EntraOpsConfig = @{}
        Mock Get-AzContext { [pscustomobject]@{ Tenant = [pscustomobject]@{ Id = 'tenant-1' }; Subscription = [pscustomobject]@{ Id = $script:TargetSub } } }
        Mock Get-AzSubscription { [pscustomobject]@{ Id = $SubscriptionId } }
        Mock Resolve-EntraOpsServiceEMDelegationGroup { '33333333-3333-3333-3333-333333333333' }
        Mock New-EntraOpsServiceBootstrap { [pscustomobject]@{ ServiceName = $ServiceName } }
    }

    It 'creates a single resource group scope with one Microsoft 365 group by default' {
        New-EntraOpsSubscriptionLandingZone -DeploymentPrefix 'X' -AzureRegion 'westeurope' -SubscriptionId $script:TargetSub -GovernanceModel PerService 6>$null | Out-Null

        Should -Invoke New-EntraOpsServiceBootstrap -Times 1 -Exactly
        Should -Invoke New-EntraOpsServiceBootstrap -Times 1 -Exactly -ParameterFilter {
            $ServiceName -eq 'Rg-X' -and $AzureScope -eq 'ResourceGroup' -and $SubscriptionId -eq $script:TargetSub -and
            @($ServiceRoles | Where-Object groupType -EQ 'Unified').Count -eq 1 -and
            (& $script:HasRole $ServiceRoles 'ControlPlane' 'Admins') -and (& $script:HasRole $ServiceRoles 'ManagementPlane' 'Admins') -and
            (& $script:HasRole $ServiceRoles 'WorkloadPlane' 'Admins')
        }
    }

    It 'creates a single subscription scope without requiring an Azure region' {
        New-EntraOpsSubscriptionLandingZone -DeploymentPrefix 'X' -DeploymentScope Subscription -SubscriptionId $script:TargetSub -GovernanceModel PerService 6>$null | Out-Null

        Should -Invoke New-EntraOpsServiceBootstrap -Times 1 -Exactly
        Should -Invoke New-EntraOpsServiceBootstrap -Times 1 -Exactly -ParameterFilter {
            $ServiceName -eq 'Sub-X' -and $AzureScope -eq 'Subscription' -and $SubscriptionId -eq $script:TargetSub -and -not $SkipAzureResourceGroup
        }
    }

    It 'keeps only the workload groups of the single scope in the Centralized model' {
        New-EntraOpsSubscriptionLandingZone -DeploymentPrefix 'X' -AzureRegion 'westeurope' -SubscriptionId $script:TargetSub -GovernanceModel Centralized -AdministratorGroupId '44444444-4444-4444-4444-444444444444' 6>$null | Out-Null

        Should -Invoke New-EntraOpsServiceBootstrap -Times 1 -Exactly -ParameterFilter {
            @($ServiceRoles).Count -eq 3 -and -not (& $script:HasRole $ServiceRoles 'ControlPlane' 'Admins') -and -not (& $script:HasRole $ServiceRoles 'ManagementPlane' 'Admins')
        }
    }

    It 'requires AdministratorGroupId in the Centralized model before creating any object' {
        { New-EntraOpsSubscriptionLandingZone -DeploymentPrefix 'X' -AzureRegion 'westeurope' -SubscriptionId $script:TargetSub -GovernanceModel Centralized 6>$null } |
        Should -Throw '*Centralized governance model requires -AdministratorGroupId*'

        Should -Invoke Resolve-EntraOpsServiceEMDelegationGroup -Times 0 -Exactly
        Should -Invoke New-EntraOpsServiceBootstrap -Times 0 -Exactly
    }

    It 'uses DefaultAzureRegion and SkipCatalogOwnerAssignment from ServiceEM config' {
        $Global:EntraOpsConfig = @{ ServiceEM = @{ DefaultAzureRegion = 'swedencentral'; SkipCatalogOwnerAssignment = $true; CreateM365Group = $true } }

        New-EntraOpsSubscriptionLandingZone -DeploymentPrefix 'X' -SubscriptionId $script:TargetSub -GovernanceModel PerService 6>$null | Out-Null

        Should -Invoke New-EntraOpsServiceBootstrap -Times 1 -Exactly -ParameterFilter { $AzureRegion -eq 'swedencentral' -and $SkipCatalogOwnerAssignment -and $CreateM365Group }
    }

    It 'prefers explicit parameters over ServiceEM config defaults' {
        $Global:EntraOpsConfig = @{ ServiceEM = @{ DefaultAzureRegion = 'swedencentral'; SkipCatalogOwnerAssignment = $true; CreateM365Group = $true } }

        New-EntraOpsSubscriptionLandingZone -DeploymentPrefix 'X' -AzureRegion 'westeurope' -SubscriptionId $script:TargetSub -GovernanceModel PerService -SkipCatalogOwnerAssignment:$false -CreateM365Group:$false 6>$null | Out-Null

        Should -Invoke New-EntraOpsServiceBootstrap -Times 1 -Exactly -ParameterFilter { $AzureRegion -eq 'westeurope' -and -not $SkipCatalogOwnerAssignment -and -not $CreateM365Group }
    }

    It 'forwards GroupPrefix from parameter, ServiceEM config or default' {
        New-EntraOpsSubscriptionLandingZone -DeploymentPrefix 'A' -AzureRegion 'westeurope' -SubscriptionId $script:TargetSub -GovernanceModel PerService 6>$null | Out-Null
        $Global:EntraOpsConfig = @{ ServiceEM = @{ GroupPrefix = 'GRP' } }
        New-EntraOpsSubscriptionLandingZone -DeploymentPrefix 'B' -AzureRegion 'westeurope' -SubscriptionId $script:TargetSub -GovernanceModel PerService 6>$null | Out-Null
        New-EntraOpsSubscriptionLandingZone -DeploymentPrefix 'C' -AzureRegion 'westeurope' -SubscriptionId $script:TargetSub -GovernanceModel PerService -GroupPrefix 'SEC' 6>$null | Out-Null

        Should -Invoke New-EntraOpsServiceBootstrap -Times 1 -Exactly -ParameterFilter { $ServiceName -eq 'Rg-A' -and $GroupPrefix -eq 'SG' }
        Should -Invoke New-EntraOpsServiceBootstrap -Times 1 -Exactly -ParameterFilter { $ServiceName -eq 'Rg-B' -and $GroupPrefix -eq 'GRP' }
        Should -Invoke New-EntraOpsServiceBootstrap -Times 1 -Exactly -ParameterFilter { $ServiceName -eq 'Rg-C' -and $GroupPrefix -eq 'SEC' }
    }

    It 'forwards CreateM365Group to every scope and creates no Microsoft 365 group by default' {
        New-EntraOpsSubscriptionLandingZone -DeploymentPrefix 'X' -DeploymentScope Both -AzureRegion 'westeurope' -SubscriptionId $script:TargetSub -GovernanceModel PerService -CreateM365Group 6>$null | Out-Null
        New-EntraOpsSubscriptionLandingZone -DeploymentPrefix 'Y' -AzureRegion 'westeurope' -SubscriptionId $script:TargetSub -GovernanceModel PerService 6>$null | Out-Null

        Should -Invoke New-EntraOpsServiceBootstrap -Times 2 -Exactly -ParameterFilter { $CreateM365Group }
        Should -Invoke New-EntraOpsServiceBootstrap -Times 1 -Exactly -ParameterFilter { $ServiceName -eq 'Rg-Y' -and -not $CreateM365Group }
    }

    It 'rejects custom landing zone components for a single scope' {
        { New-EntraOpsSubscriptionLandingZone -DeploymentPrefix 'X' -DeploymentScope ResourceGroup -SkipAzureResourceGroup -LandingZoneComponents @([pscustomobject]@{ Role = 'Rg'; ServiceRole = @() }) } |
        Should -Throw '*only be used with -DeploymentScope Both*'
    }

    It 'forwards ControlPlaneAdmins only to the scope with ControlPlane-Admins and its group as approver to the -Smb scope' {
        Mock New-EntraOpsServiceBootstrap {
            if ($ServiceName -like 'Sub-*') { return @{ ServiceName = $ServiceName; Groups = @([pscustomobject]@{ Id = 'sub-cp'; DisplayName = 'SG-Sub-X-ControlPlane-Admins' }) } }
            @{ ServiceName = $ServiceName }
        }

        New-EntraOpsSubscriptionLandingZone -DeploymentPrefix 'X' -DeploymentScope Both -Smb -AzureRegion 'westeurope' -SubscriptionId $script:TargetSub -GovernanceModel PerService `
            -ControlPlaneAdmins @('cp@contoso.com') -CatalogPlaneMembers @('ops@contoso.com') 6>$null | Out-Null

        Should -Invoke New-EntraOpsServiceBootstrap -Times 1 -Exactly -ParameterFilter {
            $ServiceName -eq 'Sub-X' -and @($ControlPlaneAdmins) -join ',' -eq 'cp@contoso.com' -and [string]::IsNullOrEmpty($ControlPlaneApproverGroupId)
        }
        Should -Invoke New-EntraOpsServiceBootstrap -Times 1 -Exactly -ParameterFilter {
            $ServiceName -eq 'Rg-X' -and -not $ControlPlaneAdmins -and $ControlPlaneApproverGroupId -eq 'sub-cp'
        }
        Should -Invoke New-EntraOpsServiceBootstrap -Times 2 -Exactly -ParameterFilter { @($CatalogPlaneMembers) -join ',' -eq 'ops@contoso.com' }
        Should -Invoke New-EntraOpsServiceBootstrap -Times 2 -Exactly -ParameterFilter { -not (& $script:HasRole $ServiceRoles 'ManagementPlane' 'Members') }
        Should -Invoke New-EntraOpsServiceBootstrap -Times 1 -Exactly -ParameterFilter {
            $ServiceName -eq 'Rg-X' -and (& $script:HasRole $ServiceRoles 'ManagementPlane' 'Admins')
        }
    }

    It 'passes the Sub scope ManagementPlane-Admins as approver to the Rg scope without -Smb' {
        Mock New-EntraOpsServiceBootstrap {
            if ($ServiceName -like 'Sub-*') {
                return @{ ServiceName = $ServiceName; Groups = @(
                        [pscustomobject]@{ Id = 'sub-pim'; DisplayName = 'SG-PIM-Sub-X-ManagementPlane-Admins' },
                        [pscustomobject]@{ Id = 'sub-mp'; DisplayName = 'SG-Sub-X-ManagementPlane-Admins' },
                        [pscustomobject]@{ Id = 'sub-cp'; DisplayName = 'SG-Sub-X-ControlPlane-Admins' }) }
            }
            @{ ServiceName = $ServiceName }
        }

        New-EntraOpsSubscriptionLandingZone -DeploymentPrefix 'X' -DeploymentScope Both -AzureRegion 'westeurope' -SubscriptionId $script:TargetSub -GovernanceModel PerService 6>$null | Out-Null

        Should -Invoke New-EntraOpsServiceBootstrap -Times 1 -Exactly -ParameterFilter {
            $ServiceName -eq 'Rg-X' -and $ManagementPlaneApproverGroupId -eq 'sub-mp' -and $ControlPlaneApproverGroupId -eq 'sub-cp'
        }
        Should -Invoke New-EntraOpsServiceBootstrap -Times 1 -Exactly -ParameterFilter { $ServiceName -eq 'Sub-X' -and [string]::IsNullOrEmpty($ManagementPlaneApproverGroupId) }
    }

    It 'forwards GroupOwnership and NoPimForGroups to every scope' {
        New-EntraOpsSubscriptionLandingZone -DeploymentPrefix 'X' -AzureRegion 'westeurope' -SubscriptionId $script:TargetSub -GovernanceModel PerService -GroupOwnership Eligible -NoPimEscalation 6>$null | Out-Null

        Should -Invoke New-EntraOpsServiceBootstrap -Times 1 -Exactly -ParameterFilter { $GroupOwnership -eq 'Eligible' -and $NoPimForGroups }
    }

    It 'ignores ControlPlaneAdmins in the Centralized model with a warning' {
        New-EntraOpsSubscriptionLandingZone -DeploymentPrefix 'X' -AzureRegion 'westeurope' -SubscriptionId $script:TargetSub -GovernanceModel Centralized `
            -AdministratorGroupId '44444444-4444-4444-4444-444444444444' -ControlPlaneAdmins @('cp@contoso.com') -WarningVariable warnings -WarningAction SilentlyContinue 6>$null | Out-Null

        Should -Invoke New-EntraOpsServiceBootstrap -Times 1 -Exactly -ParameterFilter { -not $ControlPlaneAdmins }
        @($warnings | Where-Object { "$_" -like '*-ControlPlaneAdmins is ignored*' }).Count | Should -Be 1
    }
}

Describe 'ServiceEM PIM for Groups eligible assignments' {
    BeforeAll {
        . "$script:TestRepositoryRoot/EntraOps/Public/ServiceEM/New-EntraOpsServicePIMAssignment.ps1"
    }

    BeforeEach {
        $script:EligibilityBodies = [System.Collections.Generic.List[object]]::new()
        Mock Start-Sleep {}
        Mock Invoke-EntraOpsMsGraphQuery {
            if ($Method -eq 'POST') {
                $script:EligibilityBodies.Add(($Body | ConvertFrom-Json))
                return
            }
            $groupId = [regex]::Match($Uri, "groupId eq '([^']+)'").Groups[1].Value
            return @($script:EligibilityBodies | Where-Object groupId -EQ $groupId | ForEach-Object {
                    [pscustomobject]@{ id = "$($_.groupId)-$($_.principalId)"; groupId = $_.groupId; principalId = $_.principalId; accessId = $_.accessId; targetSchedule = @{ scheduleInfo = @{ expiration = @{ type = 'noExpiration' } } } }
                })
        }
    }

    It 'makes only ManagementPlane-Admins eligible for its staging group and never the Microsoft 365 group' {
        $groups = @('Sub-X Members', 'SG-Sub-X-ManagementPlane-Admins', 'SG-PIM-Sub-X-ManagementPlane-Admins', 'SG-Sub-X-WorkloadPlane-Users') | ForEach-Object { [pscustomobject]@{ Id = "id:$_"; DisplayName = $_ } }
        $groups[0] | Add-Member -NotePropertyName GroupTypes -NotePropertyValue @('Unified')

        New-EntraOpsServicePIMAssignment -ServiceGroups $groups 6>$null | Out-Null

        $script:EligibilityBodies.Count | Should -Be 1
        $script:EligibilityBodies[0].groupId | Should -Be 'id:SG-PIM-Sub-X-ManagementPlane-Admins'
        $script:EligibilityBodies[0].principalId | Should -Be 'id:SG-Sub-X-ManagementPlane-Admins'
        @($script:EligibilityBodies | Where-Object principalId -EQ 'id:Sub-X Members').Count | Should -Be 0
    }

    It 'creates eligible owner assignments only on the WorkloadPlane groups with EnableOwnerAssignment' {
        $groups = @('Rg-X Members', 'SG-Rg-X-WorkloadPlane-Users', 'SG-Rg-X-WorkloadPlane-Admins', 'SG-Rg-X-ControlPlane-Admins', 'SG-Rg-X-ManagementPlane-Admins') | ForEach-Object { [pscustomobject]@{ Id = "id:$_"; DisplayName = $_ } }

        New-EntraOpsServicePIMAssignment -ServiceGroups $groups -WorkloadPlaneAdminPrincipalId 'admin-id' 6>$null | Out-Null
        $script:EligibilityBodies.Count | Should -Be 0

        New-EntraOpsServicePIMAssignment -ServiceGroups $groups -WorkloadPlaneAdminPrincipalId 'admin-id' -EnableOwnerAssignment 6>$null | Out-Null
        $script:EligibilityBodies.Count | Should -Be 2
        @($script:EligibilityBodies | Where-Object { $_.accessId -eq 'owner' -and $_.principalId -eq 'admin-id' }).Count | Should -Be 2
    }

    It 'matches the PIM staging group by mailNickname when the groups use another prefix' {
        $groups = @(
            [pscustomobject]@{ Id = 'old-admins'; DisplayName = 'SG-Sub-X-ManagementPlane-Admins'; MailNickname = 'Sub-X.ManagementPlane.Admins' }
            [pscustomobject]@{ Id = 'old-pim'; DisplayName = 'SG-PIM-Sub-X-ManagementPlane-Admins'; MailNickname = 'PIM.Sub-X.ManagementPlane.Admins' }
        )

        New-EntraOpsServicePIMAssignment -ServiceGroups $groups -GroupPrefix 'GRP' 6>$null | Out-Null

        ($script:EligibilityBodies | Where-Object groupId -EQ 'old-pim').principalId | Should -Be 'old-admins'
    }

    It 'creates no eligible member assignment without a Members group' {
        $groups = @('SG-Sub-X-ManagementPlane-Admins', 'SG-PIM-Sub-X-ManagementPlane-Admins', 'SG-Sub-X-WorkloadPlane-Admins') | ForEach-Object { [pscustomobject]@{ Id = "id:$_"; DisplayName = $_ } }

        New-EntraOpsServicePIMAssignment -ServiceGroups $groups 6>$null | Out-Null

        $script:EligibilityBodies.Count | Should -Be 1
        $script:EligibilityBodies[0].groupId | Should -Be 'id:SG-PIM-Sub-X-ManagementPlane-Admins'
        $script:EligibilityBodies[0].principalId | Should -Be 'id:SG-Sub-X-ManagementPlane-Admins'
    }

    It 'returns without warning when there is nothing to assign' {
        $groups = @('SG-Rg-X-WorkloadPlane-Users', 'SG-Rg-X-WorkloadPlane-Admins') | ForEach-Object { [pscustomobject]@{ Id = "id:$_"; DisplayName = $_ } }
        Mock Write-Warning {}

        New-EntraOpsServicePIMAssignment -ServiceGroups $groups 6>$null | Out-Null

        $script:EligibilityBodies.Count | Should -Be 0
        Should -Invoke Write-Warning -Times 0 -Exactly
    }
}

Describe 'ServiceEM Azure container scope' {
    BeforeAll {
        . "$script:TestRepositoryRoot/EntraOps/Public/ServiceEM/New-EntraOpsServiceAZContainer.ps1"
        function New-AzResourceGroup { param($Name, $Location, $Tag) }
        function Get-AzRoleDefinition { param($Name, $WarningAction) }
        function Get-AzRoleAssignment { param($Scope, $ObjectId) }
        function New-AzRoleAssignment { param($Scope, $ResourceGroupName, $RoleDefinitionName, $ObjectId) }
        function Get-AzRoleEligibilitySchedule { param($Scope) }
        function Get-AzRoleEligibilityScheduleInstance { param($Scope, $Filter, $ErrorAction) }
        function Get-AzRoleManagementPolicy { param($Scope, $Name, $WarningAction) }
        function Update-AzRoleManagementPolicy { param($Scope, $Name, $Rule, $WarningAction) }
        function New-AzRoleEligibilityScheduleRequest { param($Name, $RoleDefinitionId, $PrincipalId, $Scope, $RequestType, $Justification, $ExpirationType, $ScheduleInfoStartDateTime, $Condition, $ConditionVersion) }
        $script:Groups = @('SG-Sub-X-WorkloadPlane-Admins', 'SG-Sub-X-WorkloadPlane-Users', 'SG-Sub-X-ManagementPlane-Admins', 'SG-Sub-X-ControlPlane-Admins') |
        ForEach-Object { [pscustomobject]@{ Id = "id:$_"; DisplayName = $_ } }
    }

    BeforeEach {
        $script:InheritedScope = $null
        Mock Get-AzContext { [pscustomobject]@{ Subscription = [pscustomobject]@{ Id = 'sub1' } } }
        Mock Get-AzResourceGroup { [pscustomobject]@{ ResourceId = '/subscriptions/sub1/resourceGroups/RG-X'; ResourceGroupName = 'RG-X' } }
        Mock New-AzResourceGroup {}
        Mock Get-AzRoleDefinition { [pscustomobject]@{ Name = $Name; Id = "rd-$Name" } }
        Mock Get-AzRoleAssignment {}
        Mock New-AzRoleAssignment {}
        Mock Get-AzRoleEligibilitySchedule {}
        Mock Get-AzRoleEligibilityScheduleInstance {
            if ($script:InheritedScope -and $Filter -match 'ManagementPlane-Admins') {
                [pscustomobject]@{ RoleDefinitionDisplayName = 'Contributor'; Scope = $script:InheritedScope }
            }
        }
        Mock Get-AzRoleManagementPolicy { [pscustomobject]@{ Rule = @() } }
        Mock New-AzRoleEligibilityScheduleRequest {}
    }

    It 'assigns the roles on the subscription without creating a resource group' {
        New-EntraOpsServiceAZContainer -ServiceName 'Sub-X' -ServiceGroups $script:Groups -AzureScope Subscription -WarningAction SilentlyContinue 6>$null | Out-Null

        Should -Invoke Get-AzResourceGroup -Times 0 -Exactly
        Should -Invoke New-AzResourceGroup -Times 0 -Exactly
        Should -Invoke New-AzRoleAssignment -Times 1 -Exactly -ParameterFilter { $Scope -eq '/subscriptions/sub1' -and $ObjectId -eq 'id:SG-Sub-X-WorkloadPlane-Admins' }
        Should -Invoke New-AzRoleEligibilityScheduleRequest -Times 4 -Exactly -ParameterFilter { $Scope -eq '/subscriptions/sub1' }
        Should -Invoke New-AzRoleEligibilityScheduleRequest -Times 0 -Exactly -ParameterFilter { $PrincipalId -eq 'id:SG-Sub-X-WorkloadPlane-Admins' -and $RoleDefinitionId -like '*rd-Contributor' }
        Should -Invoke New-AzRoleEligibilityScheduleRequest -Times 1 -Exactly -ParameterFilter { $PrincipalId -eq 'id:SG-Sub-X-WorkloadPlane-Admins' -and $RoleDefinitionId -like '*rd-Role Based Access Control Administrator' }
    }

    It 'warns about an eligible Contributor of WorkloadPlane-Admins from an earlier version' {
        Mock Get-AzRoleEligibilitySchedule { [pscustomobject]@{ RoleDefinitionDisplayName = 'Contributor'; PrincipalId = 'id:SG-Sub-X-WorkloadPlane-Admins' } }

        New-EntraOpsServiceAZContainer -ServiceName 'Sub-X' -ServiceGroups $script:Groups -AzureScope Subscription -WarningVariable warnings -WarningAction SilentlyContinue 6>$null | Out-Null

        @($warnings | Where-Object { "$_" -like '*eligible Contributor assignment*earlier version*' }).Count | Should -Be 1
    }

    It 'tags a new resource group with the service name' {
        $script:RgLookups = 0
        Mock Get-AzResourceGroup {
            $script:RgLookups++
            if ($script:RgLookups -eq 1) { throw 'Provided resource group does not exist.' }
            [pscustomobject]@{ ResourceId = '/subscriptions/sub1/resourceGroups/RG-X'; ResourceGroupName = 'RG-X' }
        }
        Mock Start-Sleep {}

        New-EntraOpsServiceAZContainer -ServiceName 'Rg-X' -ServiceGroups $script:Groups -Location 'westeurope' -WarningAction SilentlyContinue 6>$null | Out-Null

        Should -Invoke New-AzResourceGroup -Times 1 -Exactly -ParameterFilter { $Name -eq 'RG-X' -and $Tag.EntraOpsServiceEM -eq 'Rg-X' }
    }

    It 'treats a management group assignment as inherited at subscription scope' {
        $script:InheritedScope = '/providers/Microsoft.Management/managementGroups/mg1'

        New-EntraOpsServiceAZContainer -ServiceName 'Sub-X' -ServiceGroups $script:Groups -AzureScope Subscription -WarningAction SilentlyContinue 6>$null | Out-Null

        Should -Invoke New-AzRoleEligibilityScheduleRequest -Times 0 -Exactly -ParameterFilter { $PrincipalId -eq 'id:SG-Sub-X-ManagementPlane-Admins' -and $RoleDefinitionId -like '*rd-Contributor' }
    }

    It 'does not treat a sibling resource group assignment as inherited' {
        $script:InheritedScope = '/subscriptions/sub1/resourceGroups/RG-Other'

        New-EntraOpsServiceAZContainer -ServiceName 'Rg-X' -ServiceGroups $script:Groups -Location 'westeurope' -WarningAction SilentlyContinue 6>$null | Out-Null

        Should -Invoke New-AzRoleEligibilityScheduleRequest -Times 1 -Exactly -ParameterFilter { $PrincipalId -eq 'id:SG-Sub-X-ManagementPlane-Admins' -and $RoleDefinitionId -like '*rd-Contributor' -and $Scope -eq '/subscriptions/sub1/resourceGroups/RG-X' }
    }

    It 'assigns Owner to the PIM staging group only with pimForGroups' {
        $groups = @($script:Groups) + [pscustomobject]@{ Id = 'id:pim'; DisplayName = 'SG-PIM-Sub-X-ManagementPlane-Admins' }

        New-EntraOpsServiceAZContainer -ServiceName 'Sub-X' -ServiceGroups $groups -AzureScope Subscription -WarningAction SilentlyContinue 6>$null | Out-Null
        Should -Invoke New-AzRoleAssignment -Times 0 -Exactly -ParameterFilter { $ObjectId -eq 'id:pim' }

        New-EntraOpsServiceAZContainer -ServiceName 'Sub-X' -ServiceGroups $groups -AzureScope Subscription -pimForGroups -WarningAction SilentlyContinue 6>$null | Out-Null
        Should -Invoke New-AzRoleAssignment -Times 1 -Exactly -ParameterFilter { $ObjectId -eq 'id:pim' -and $RoleDefinitionName -eq 'Owner' -and $Scope -eq '/subscriptions/sub1' }
    }
}

Describe 'ServiceEM access package resource roles' {
    BeforeAll {
        . "$script:TestRepositoryRoot/EntraOps/Public/ServiceEM/New-EntraOpsServiceEMAccessPackageResourceAssignment.ps1"
    }

    It 'adds the Microsoft 365 group to every access package of the scope' {
        $script:RoleScopeBodies = [System.Collections.Generic.List[object]]::new()
        Mock Start-Sleep {}
        Mock Invoke-EntraOpsMsGraphQuery {
            if ($Method -eq 'POST') {
                $script:RoleScopeBodies.Add([pscustomobject]@{ Uri = $Uri; Body = ($Body | ConvertFrom-Json -Depth 10) })
                return [pscustomobject]@{ Id = [guid]::NewGuid().Guid }
            }
            if ($Uri -like '*/resourceRoles?*') {
                $resourceId = [regex]::Match($Uri, "resource/id eq '([^']+)'").Groups[1].Value
                return @([pscustomobject]@{ Id = "role-$resourceId"; DisplayName = 'Member'; OriginId = "Member_$resourceId" })
            }
            if ($Uri -like '*/accessPackages?*') {
                $scopes = @($script:RoleScopeBodies | ForEach-Object { [pscustomobject]@{ Role = [pscustomobject]@{ OriginId = $_.Body.role.originId }; Scope = [pscustomobject]@{ OriginId = $_.Body.scope.originId } } })
                return @([pscustomobject]@{ ResourceRoleScopes = $scopes })
            }
            return @()
        }
        $groups = @(
            [pscustomobject]@{ Id = 'm365'; DisplayName = 'Rg-X Members'; GroupTypes = @('Unified') }
            [pscustomobject]@{ Id = 'wu'; DisplayName = 'SG-Rg-X-WorkloadPlane-Users'; GroupTypes = @() }
            [pscustomobject]@{ Id = 'wa'; DisplayName = 'SG-Rg-X-WorkloadPlane-Admins'; GroupTypes = @() }
        )
        $resources = @($groups | ForEach-Object { [pscustomobject]@{ Id = "res-$($_.Id)"; DisplayName = $_.DisplayName; OriginSystem = 'AadGroup'; OriginId = $_.Id } })
        $packages = @('AP-Rg-X-WorkloadPlane-Users', 'AP-Rg-X-WorkloadPlane-Admins') | ForEach-Object { [pscustomobject]@{ Id = "ap:$_"; DisplayName = $_; ResourceRoleScopes = @() } }

        New-EntraOpsServiceEMAccessPackageResourceAssignment -ServiceCatalogId 'cat' -ServiceName 'Rg-X' -ServiceGroups $groups -ServicePackages $packages -ServiceCatalogResources $resources 6>$null | Out-Null

        $script:RoleScopeBodies.Count | Should -Be 4
        foreach ($package in $packages) {
            @($script:RoleScopeBodies | Where-Object { $_.Uri -like "*/accessPackages/$($package.Id)/*" -and $_.Body.scope.originId -eq 'm365' }).Count | Should -Be 1
        }
        Should -Invoke Invoke-EntraOpsMsGraphQuery -Times 3 -Exactly -ParameterFilter { $Method -eq 'GET' -and $Uri -like '*/resourceRoles`?*' }
    }
}

Describe 'ServiceEM Graph lookup safety' {
    It 'encodes an apostrophe in the destructive catalog lookup' {
        $script:CatalogLookupUri = $null
        Mock Invoke-EntraOpsMsGraphQuery {
            $script:CatalogLookupUri = $Uri
            return @()
        }

        Remove-EntraOpsServiceCatalog -ServiceCatalogName "Catalog-Director's Service" -Force -WarningAction SilentlyContinue | Out-Null

        $script:CatalogLookupUri | Should -Match "displayName eq 'Catalog-Director%27%27s%20Service'"
        $script:CatalogLookupUri | Should -Not -Match "Director's Service"
    }

    It 'uses the same encoded catalog name for every catalog lookup' {
        $script:CatalogLookupUris = [System.Collections.Generic.List[string]]::new()
        Mock Invoke-EntraOpsMsGraphQuery {
            if ($Method -eq 'GET') {
                $script:CatalogLookupUris.Add($Uri)
                return [pscustomobject]@{ Id = 'catalog-id'; DisplayName = "Catalog-Director's Service" }
            }
            throw "Unexpected Graph method: $Method"
        }
        Mock Start-Sleep {}

        New-EntraOpsServiceEMCatalog -ServiceName "Director's Service" | Out-Null

        $script:CatalogLookupUris.Count | Should -Be 2
        @($script:CatalogLookupUris | Where-Object { $_ -notmatch "displayName eq 'Catalog-Director%27%27s%20Service'" }) |
        Should -BeNullOrEmpty
    }

    It 'encodes an escaped OData literal in the delegation group name filter' {
        $script:GroupLookupUri = $null
        Mock Invoke-EntraOpsMsGraphQuery {
            $script:GroupLookupUri = $Uri
            return [pscustomobject]@{ Id = 'group-id'; DisplayName = "Tier 'Zero' Admins" }
        }
        Mock Save-EntraOpsServiceEMConfigKey {}

        $result = Resolve-EntraOpsServiceEMDelegationGroup -Plane ControlPlane -DefaultGroupName "Tier 'Zero' Admins" -ConfigKey ControlPlaneDelegationGroupId

        $result | Should -Be 'group-id'
        $script:GroupLookupUri | Should -BeLike "*displayName eq 'Tier%20%27%27Zero%27%27%20Admins'"
        $script:GroupLookupUri | Should -Not -Match "Tier 'Zero'"
    }

    It 'does not use a non-GUID delegation group ID in the request path' {
        $script:GroupLookupUris = [System.Collections.Generic.List[string]]::new()
        Mock Invoke-EntraOpsMsGraphQuery {
            $script:GroupLookupUris.Add($Uri)
            return [pscustomobject]@{ Id = 'group-id'; DisplayName = 'PRG-Tenant-ControlPlane-IdentityOps' }
        }
        Mock Save-EntraOpsServiceEMConfigKey {}

        Resolve-EntraOpsServiceEMDelegationGroup -Plane ControlPlane -GroupId '../users' -DefaultGroupName 'PRG-Tenant-ControlPlane-IdentityOps' -ConfigKey ControlPlaneDelegationGroupId -WarningAction SilentlyContinue |
        Should -Be 'group-id'
        @($script:GroupLookupUris | Where-Object { $_ -like '*../users*' }) | Should -BeNullOrEmpty
    }

    It 'creates delegation groups without owner' {
        $script:CreatedGroupBodies = [System.Collections.Generic.List[object]]::new()
        Mock Get-MgContext { [pscustomobject]@{ Scopes = @('RoleManagement.ReadWrite.Directory'); Account = 'admin@contoso.com' } }
        Mock Invoke-EntraOpsMsGraphQuery {
            if ($Method -eq 'POST') {
                $script:CreatedGroupBodies.Add(($Body | ConvertFrom-Json -Depth 5))
                return [pscustomobject]@{ Id = 'new-group-id' }
            }
            return @()
        }
        Mock Save-EntraOpsServiceEMConfigKey {}

        Resolve-EntraOpsServiceEMDelegationGroup -Plane ControlPlane -DefaultGroupName 'PRG-Test' -ConfigKey ControlPlaneDelegationGroupId | Should -Be 'new-group-id'

        $script:CreatedGroupBodies[0].PSObject.Properties.Name | Should -Not -Contain 'owners@odata.bind'
    }
}

Describe 'ServiceEM assignment policy group references' {
    BeforeAll {
        function script:New-TestGroup($Name) { [pscustomobject]@{ Id = "id:$Name"; DisplayName = $Name } }
        function script:New-TestPackage($Name) { [pscustomobject]@{ Id = "ap:$Name"; DisplayName = $Name } }
    }

    BeforeEach {
        $script:PolicyBodies = [System.Collections.Generic.List[object]]::new()
        $script:CreatedPolicies = [System.Collections.Generic.List[object]]::new()
        Mock Start-Sleep {}
        Mock Invoke-EntraOpsMsGraphQuery {
            if ($Method -eq 'POST') {
                $policy = $Body | ConvertFrom-Json -Depth 20
                $script:PolicyBodies.Add($policy)
                $created = [pscustomobject]@{ id = [guid]::NewGuid().Guid; displayName = $policy.displayName; accessPackage = $policy.accessPackage }
                $script:CreatedPolicies.Add($created)
                return $created
            }
            if ($Uri -like '/v1.0/users/*') { return [pscustomobject]@{ id = 'upn-user-id' } }
            return $script:CreatedPolicies.ToArray()
        }
    }

    It 'does not reference the PIM staging group as ManagementPlane-Admins' {
        $groups = @('Sub-X Members', 'SG-Sub-X-CatalogPlane-Members', 'SG-Sub-X-ControlPlane-Admins', 'SG-Sub-X-ManagementPlane-Admins', 'SG-PIM-Sub-X-ManagementPlane-Admins') |
        ForEach-Object { New-TestGroup $_ }
        $packages = @('AP-Sub-X-CatalogPlane-Members', 'AP-Sub-X-ManagementPlane-Admins') | ForEach-Object { New-TestPackage $_ }

        New-EntraOpsServiceEMAssignmentPolicy -ServiceName 'Sub-X' -ServiceCatalogId 'cat' -ServiceGroups $groups -ServicePackages $packages | Out-Null

        $script:PolicyBodies.Count | Should -Be 4
        foreach ($policy in $script:PolicyBodies) {
            $expectedReviewer = if ($policy.displayName -in 'Management Plane Policy', 'Initial Management Admin Policy') { 'id:SG-Sub-X-ControlPlane-Admins' } else { 'id:SG-Sub-X-ManagementPlane-Admins' }
            $policy.reviewSettings.primaryReviewers.groupId | Should -Be $expectedReviewer -Because "'$($policy.displayName)' is reviewed by the same or a higher tier"
        }
        $adminPolicy = $script:PolicyBodies | Where-Object displayName -EQ 'Initial Management Admin Policy'
        $adminPolicy.allowedTargetScope | Should -Be 'allMemberUsers'
        $adminPolicy.requestApprovalSettings.isApprovalRequiredForAdd | Should -BeFalse
        $adminPolicy.requestorSettings.enableTargetsToSelfAddAccess | Should -BeFalse
        $adminPolicy.requestorSettings.enableOnBehalfRequestorsToAddAccess | Should -BeFalse
    }

    Context 'Management Plane Policy' {
        BeforeAll {
            $script:MpPackages = @('AP-Sub-X-CatalogPlane-Members', 'AP-Sub-X-ManagementPlane-Admins') | ForEach-Object { New-TestPackage $_ }
        }

        It 'lets the administrator group request ManagementPlane-Admins with approval by ControlPlane-Admins' {
            $groups = @('SG-Sub-X-CatalogPlane-Members', 'SG-Sub-X-ControlPlane-Admins', 'SG-Sub-X-ManagementPlane-Admins') | ForEach-Object { New-TestGroup $_ }

            New-EntraOpsServiceEMAssignmentPolicy -ServiceName 'Sub-X' -ServiceCatalogId 'cat' -ServiceGroups $groups -ServicePackages $script:MpPackages | Out-Null

            $mpPolicy = $script:PolicyBodies | Where-Object displayName -EQ 'Management Plane Policy'
            $mpPolicy.accessPackage.id | Should -Be 'ap:AP-Sub-X-ManagementPlane-Admins'
            $mpPolicy.allowedTargetScope | Should -Be 'specificDirectoryUsers'
            $mpPolicy.specificAllowedTargets.groupId | Should -Be 'id:SG-Sub-X-CatalogPlane-Members'
            $mpPolicy.requestorSettings.enableTargetsToSelfAddAccess | Should -BeTrue
            $stage = $mpPolicy.requestApprovalSettings.stages[0]
            $stage.primaryApprovers.groupId | Should -Be 'id:SG-Sub-X-ControlPlane-Admins'
            $stage.isEscalationEnabled | Should -BeFalse
            $stage.PSObject.Properties.Name | Should -Not -Contain 'fallbackPrimaryApprovers'
        }

        It 'uses the ControlPlane-Admins group of another scope as approver' {
            $groups = @('SG-Rg-X-CatalogPlane-Members', 'SG-Rg-X-ManagementPlane-Admins') | ForEach-Object { New-TestGroup $_ }
            $packages = @('AP-Rg-X-ManagementPlane-Admins') | ForEach-Object { New-TestPackage $_ }

            New-EntraOpsServiceEMAssignmentPolicy -ServiceName 'Rg-X' -ServiceCatalogId 'cat' -ServiceGroups $groups -ServicePackages $packages | Out-Null
            @($script:PolicyBodies | Where-Object displayName -EQ 'Management Plane Policy').Count | Should -Be 0

            New-EntraOpsServiceEMAssignmentPolicy -ServiceName 'Rg-X' -ServiceCatalogId 'cat' -ServiceGroups $groups -ServicePackages $packages -ControlPlaneApproverGroupId 'sub-cp' | Out-Null
            ($script:PolicyBodies | Where-Object displayName -EQ 'Management Plane Policy').requestApprovalSettings.stages[0].primaryApprovers.groupId | Should -Be 'sub-cp'
        }

        It 'adds a missing Management Plane Policy to an existing landing zone' {
            $groups = @('SG-Sub-X-CatalogPlane-Members', 'SG-Sub-X-ControlPlane-Admins', 'SG-Sub-X-ManagementPlane-Admins') | ForEach-Object { New-TestGroup $_ }
            $script:CreatedPolicies.Add([pscustomobject]@{ id = 'existing'; displayName = 'Initial Management Admin Policy'; accessPackage = [pscustomobject]@{ id = 'ap:AP-Sub-X-ManagementPlane-Admins' } })

            New-EntraOpsServiceEMAssignmentPolicy -ServiceName 'Sub-X' -ServiceCatalogId 'cat' -ServiceGroups $groups -ServicePackages @($script:MpPackages[1]) | Out-Null

            @($script:PolicyBodies).displayName | Should -Be @('Management Plane Policy')
        }

        It 'creates an admin-only Initial Catalog Members Policy' {
            $groups = @('SG-Sub-X-CatalogPlane-Members') | ForEach-Object { New-TestGroup $_ }

            New-EntraOpsServiceEMAssignmentPolicy -ServiceName 'Sub-X' -ServiceCatalogId 'cat' -ServiceGroups $groups -ServicePackages @($script:MpPackages[0]) | Out-Null

            $policy = $script:PolicyBodies | Where-Object displayName -EQ 'Initial Catalog Members Policy'
            $policy.accessPackage.id | Should -Be 'ap:AP-Sub-X-CatalogPlane-Members'
            $policy.requestorSettings.enableTargetsToSelfAddAccess | Should -BeFalse
            $policy.requestApprovalSettings.isApprovalRequiredForAdd | Should -BeFalse
        }
    }

    It 'never lets CatalogPlane-Members approve privileged packages when ManagementPlane-Admins is not in the scope' {
        $groups = @('Rg-X Members', 'SG-Rg-X-CatalogPlane-Members', 'SG-Rg-X-WorkloadPlane-Users', 'SG-Rg-X-WorkloadPlane-Admins') |
        ForEach-Object { New-TestGroup $_ }
        $packages = @('AP-Rg-X-CatalogPlane-Members', 'AP-Rg-X-WorkloadPlane-Users', 'AP-Rg-X-WorkloadPlane-Admins') | ForEach-Object { New-TestPackage $_ }

        New-EntraOpsServiceEMAssignmentPolicy -ServiceName 'Rg-X' -ServiceCatalogId 'cat' -ServiceGroups $groups -ServicePackages $packages | Out-Null

        foreach ($name in 'Workload Plane Policy') {
            @($script:PolicyBodies | Where-Object displayName -EQ $name).Count | Should -Be 0 -Because "'$name' has no ManagementPlane-Admins approver"
        }
        @($script:PolicyBodies | Where-Object displayName -EQ 'Initial Workload Admin Policy').Count | Should -Be 1
        ($script:PolicyBodies | Where-Object displayName -EQ 'Workload Plane Users Policy').requestApprovalSettings.stages.primaryApprovers.groupId |
        Should -Be 'id:SG-Rg-X-WorkloadPlane-Admins'
    }

    It 'uses the ManagementPlane-Admins group of another scope as approver and reviewer' {
        $groups = @('SG-Rg-X-CatalogPlane-Members', 'SG-Rg-X-WorkloadPlane-Users', 'SG-Rg-X-WorkloadPlane-Admins') |
        ForEach-Object { New-TestGroup $_ }
        $packages = @('AP-Rg-X-WorkloadPlane-Admins') | ForEach-Object { New-TestPackage $_ }

        New-EntraOpsServiceEMAssignmentPolicy -ServiceName 'Rg-X' -ServiceCatalogId 'cat' -ServiceGroups $groups -ServicePackages $packages -ManagementPlaneApproverGroupId 'sub-mp' | Out-Null

        foreach ($name in 'Workload Plane Policy') {
            $policy = $script:PolicyBodies | Where-Object displayName -EQ $name
            $policy.requestApprovalSettings.stages.primaryApprovers.groupId | Should -Be 'sub-mp'
            $policy.reviewSettings.primaryReviewers.groupId | Should -Be 'sub-mp'
        }
    }

    Context 'access review reviewers' {
        BeforeAll {
            $script:ArGroups = @('Rg-X Members', 'SG-Rg-X-CatalogPlane-Members', 'SG-Rg-X-ManagementPlane-Admins', 'SG-Rg-X-WorkloadPlane-Users', 'SG-Rg-X-WorkloadPlane-Admins') |
            ForEach-Object { New-TestGroup $_ }
            $script:ArPackages = @('AP-Rg-X-WorkloadPlane-Users', 'AP-Rg-X-WorkloadPlane-Admins') | ForEach-Object { New-TestPackage $_ }
        }

        AfterEach {
            $Global:EntraOpsConfig = $null
        }

        It 'lets WorkloadPlane-Admins review the WorkloadPlane-Users assignments by default' {
            New-EntraOpsServiceEMAssignmentPolicy -ServiceName 'Rg-X' -ServiceCatalogId 'cat' -ServiceGroups $script:ArGroups -ServicePackages $script:ArPackages | Out-Null

            foreach ($name in 'Workload Plane Users Policy', 'Initial Workload Users Policy') {
                $review = ($script:PolicyBodies | Where-Object displayName -EQ $name).reviewSettings
                $review.primaryReviewers.groupId | Should -Be 'id:SG-Rg-X-WorkloadPlane-Admins' -Because "'$name' is reviewed by the workload plane admins"
                $review.isSelfReview | Should -BeFalse
            }
            foreach ($name in 'Workload Plane Policy', 'Initial Workload Admin Policy') {
                ($script:PolicyBodies | Where-Object displayName -EQ $name).reviewSettings.primaryReviewers.groupId | Should -Be 'id:SG-Rg-X-ManagementPlane-Admins'
            }
        }

        It 'applies group, self-review, specific reviewers and manager from ServiceEM.AccessReviews.Policies' {
            $Global:EntraOpsConfig = @{ ServiceEM = @{ AccessReviews = @{ Policies = @{
                            WorkloadPlaneUsers    = @{ ReviewerType = 'SelfReview' }
                            InitialWorkloadUsers  = @{ ReviewerType = 'Manager' }
                            WorkloadPlaneAdmins   = @{ ReviewerType = 'SpecificReviewers'; Reviewers = @('11111111-1111-1111-1111-111111111111', 'admin@contoso.com') }
                            InitialWorkloadAdmins = @{ ReviewerType = 'Group'; Reviewers = @('22222222-2222-2222-2222-222222222222', 'CatalogPlane-Members') }
                        } } } }

            New-EntraOpsServiceEMAssignmentPolicy -ServiceName 'Rg-X' -ServiceCatalogId 'cat' -ServiceGroups $script:ArGroups -ServicePackages $script:ArPackages | Out-Null

            $selfReview = ($script:PolicyBodies | Where-Object displayName -EQ 'Workload Plane Users Policy').reviewSettings
            $selfReview.isSelfReview | Should -BeTrue
            @($selfReview.primaryReviewers).Count | Should -Be 0

            $managerReview = ($script:PolicyBodies | Where-Object displayName -EQ 'Initial Workload Users Policy').reviewSettings
            $managerReview.primaryReviewers.'@odata.type' | Should -Be '#microsoft.graph.requestorManager'
            $managerReview.primaryReviewers.managerLevel | Should -Be 1
            $managerReview.fallbackReviewers.groupId | Should -Be 'id:SG-Rg-X-WorkloadPlane-Admins'

            $specificReview = ($script:PolicyBodies | Where-Object displayName -EQ 'Workload Plane Policy').reviewSettings
            $specificReview.primaryReviewers.'@odata.type' | Should -Be @('#microsoft.graph.singleUser', '#microsoft.graph.singleUser')
            $specificReview.primaryReviewers.userId | Should -Be @('11111111-1111-1111-1111-111111111111', 'upn-user-id')

            ($script:PolicyBodies | Where-Object displayName -EQ 'Initial Workload Admin Policy').reviewSettings.primaryReviewers.groupId |
            Should -Be @('22222222-2222-2222-2222-222222222222', 'id:SG-Rg-X-CatalogPlane-Members')
        }

        It 'rejects an invalid reviewer type and specific reviewers without reviewers' {
            $Global:EntraOpsConfig = @{ ServiceEM = @{ AccessReviews = @{ Policies = @{ BaselinePolicy = @{ ReviewerType = 'Owner' } } } } }
            { New-EntraOpsServiceEMAssignmentPolicy -ServiceName 'Rg-X' -ServiceCatalogId 'cat' -ServiceGroups $script:ArGroups -ServicePackages $script:ArPackages } |
            Should -Throw "*BaselinePolicy.ReviewerType 'Owner'*"

            $Global:EntraOpsConfig = @{ ServiceEM = @{ AccessReviews = @{ Policies = @{ WorkloadPlaneUsers = @{ ReviewerType = 'SpecificReviewers' } } } } }
            { New-EntraOpsServiceEMAssignmentPolicy -ServiceName 'Rg-X' -ServiceCatalogId 'cat' -ServiceGroups $script:ArGroups -ServicePackages $script:ArPackages } |
            Should -Throw "*WorkloadPlaneUsers.Reviewers*SpecificReviewers*"
            $script:PolicyBodies.Count | Should -Be 0
        }
    }

    It 'allows all member users as targets of the WorkloadPlane-Users policy' {
        $groups = @('Rg-X Members', 'SG-Rg-X-CatalogPlane-Members', 'SG-Rg-X-WorkloadPlane-Users', 'SG-Rg-X-WorkloadPlane-Admins') | ForEach-Object { New-TestGroup $_ }
        $packages = @('AP-Rg-X-WorkloadPlane-Users') | ForEach-Object { New-TestPackage $_ }

        New-EntraOpsServiceEMAssignmentPolicy -ServiceName 'Rg-X' -ServiceCatalogId 'cat' -ServiceGroups $groups -ServicePackages $packages | Out-Null

        $usersPolicy = $script:PolicyBodies | Where-Object displayName -EQ 'Workload Plane Users Policy'
        $usersPolicy.allowedTargetScope | Should -Be 'allMemberUsers'
        $usersPolicy.PSObject.Properties.Name | Should -Not -Contain 'specificAllowedTargets'
    }

    Context 'initial direct assignment policies' {
        BeforeAll {
            $script:WpGroups = @('Rg-X Members', 'SG-Rg-X-WorkloadPlane-Users', 'SG-Rg-X-WorkloadPlane-Admins', 'SG-Rg-X-ManagementPlane-Admins') | ForEach-Object { New-TestGroup $_ }
            $script:WpPackages = @('AP-Rg-X-WorkloadPlane-Users', 'AP-Rg-X-WorkloadPlane-Admins') | ForEach-Object { New-TestPackage $_ }
        }

        AfterEach {
            $Global:EntraOpsConfig = $null
        }

        It 'creates admin-only policies without approval and without expiration by default' {
            $Global:EntraOpsConfig = $null

            New-EntraOpsServiceEMAssignmentPolicy -ServiceName 'Rg-X' -ServiceCatalogId 'cat' -ServiceGroups $script:WpGroups -ServicePackages $script:WpPackages | Out-Null

            foreach ($name in 'Initial Workload Users Policy', 'Initial Workload Admin Policy') {
                $policy = $script:PolicyBodies | Where-Object displayName -EQ $name
                $policy.allowedTargetScope | Should -Be 'allMemberUsers'
                $policy.requestApprovalSettings.isApprovalRequiredForAdd | Should -BeFalse
                $policy.requestorSettings.enableTargetsToSelfAddAccess | Should -BeFalse
                $policy.requestorSettings.enableOnBehalfRequestorsToAddAccess | Should -BeFalse
                $policy.expiration.type | Should -Be 'afterDuration'
                $policy.expiration.duration | Should -Be 'P365D'
            }
            foreach ($policy in $script:PolicyBodies) {
                $policy.expiration.duration | Should -Be 'P365D' -Because "'$($policy.displayName)' uses the default expiration"
            }
            ($script:PolicyBodies | Where-Object displayName -EQ 'Initial Workload Admin Policy').accessPackage.id | Should -Be 'ap:AP-Rg-X-WorkloadPlane-Admins'
        }

        It 'uses the expiration from ServiceEM.AssignmentPolicies' {
            $Global:EntraOpsConfig = @{ ServiceEM = @{ AssignmentPolicies = @{ InitialWorkloadAdmins = @{ Expiration = 'P90D' } } } }

            New-EntraOpsServiceEMAssignmentPolicy -ServiceName 'Rg-X' -ServiceCatalogId 'cat' -ServiceGroups $script:WpGroups -ServicePackages $script:WpPackages | Out-Null

            $adminPolicy = $script:PolicyBodies | Where-Object displayName -EQ 'Initial Workload Admin Policy'
            $adminPolicy.expiration.type | Should -Be 'afterDuration'
            $adminPolicy.expiration.duration | Should -Be 'P90D'
            ($script:PolicyBodies | Where-Object displayName -EQ 'Initial Workload Users Policy').expiration.duration | Should -Be 'P365D'
        }

        It 'rejects an invalid expiration value' {
            $Global:EntraOpsConfig = @{ ServiceEM = @{ AssignmentPolicies = @{ InitialWorkloadUsers = @{ Expiration = '90 days' } } } }

            { New-EntraOpsServiceEMAssignmentPolicy -ServiceName 'Rg-X' -ServiceCatalogId 'cat' -ServiceGroups $script:WpGroups -ServicePackages $script:WpPackages } |
            Should -Throw "*InitialWorkloadUsers.Expiration '90 days'*"
        }

        It 'applies expiration, approval timeout and requestor scope from ServiceEM.AssignmentPolicies' {
            $Global:EntraOpsConfig = @{ ServiceEM = @{ AssignmentPolicies = @{
                        WorkloadPlaneAdmins = @{ Expiration = 'PT8H'; ApprovalTimeout = 'P1D' }
                        WorkloadPlaneUsers  = @{ RequestorScope = 'CatalogPlaneMembers' }
                    } } }
            $groups = @($script:WpGroups) + (New-TestGroup 'SG-Rg-X-CatalogPlane-Members')

            New-EntraOpsServiceEMAssignmentPolicy -ServiceName 'Rg-X' -ServiceCatalogId 'cat' -ServiceGroups $groups -ServicePackages $script:WpPackages | Out-Null

            $adminPolicy = $script:PolicyBodies | Where-Object displayName -EQ 'Workload Plane Policy'
            $adminPolicy.expiration.duration | Should -Be 'PT8H'
            $adminPolicy.requestApprovalSettings.stages[0].durationBeforeAutomaticDenial | Should -Be 'P1D'
            $usersPolicy = $script:PolicyBodies | Where-Object displayName -EQ 'Workload Plane Users Policy'
            $usersPolicy.allowedTargetScope | Should -Be 'specificDirectoryUsers'
            $usersPolicy.specificAllowedTargets.groupId | Should -Be 'id:SG-Rg-X-CatalogPlane-Members'
            $usersPolicy.expiration.duration | Should -Be 'P365D'
        }

        It 'applies and disables access reviews from ServiceEM.AccessReviews' {
            $Global:EntraOpsConfig = @{ ServiceEM = @{ AccessReviews = @{ RecurrenceIntervalInMonths = 6; ReviewDuration = 'P14D' } } }
            New-EntraOpsServiceEMAssignmentPolicy -ServiceName 'Rg-X' -ServiceCatalogId 'cat' -ServiceGroups $script:WpGroups -ServicePackages @($script:WpPackages[0]) | Out-Null
            $review = ($script:PolicyBodies | Where-Object displayName -EQ 'Workload Plane Users Policy').reviewSettings
            $review.schedule.recurrence.pattern.interval | Should -Be 6
            $review.schedule.expiration.duration | Should -Be 'P14D'

            $script:PolicyBodies.Clear()
            $script:CreatedPolicies.Clear()
            $Global:EntraOpsConfig = @{ ServiceEM = @{ AccessReviews = @{ EnableAccessReviews = $false } } }
            New-EntraOpsServiceEMAssignmentPolicy -ServiceName 'Rg-X' -ServiceCatalogId 'cat' -ServiceGroups $script:WpGroups -ServicePackages @($script:WpPackages[0]) | Out-Null
            foreach ($policy in $script:PolicyBodies) {
                $policy.PSObject.Properties.Name | Should -Not -Contain 'reviewSettings'
            }
        }

        It 'allows extension with approval on the standard policies but not on the initial policies' {
            New-EntraOpsServiceEMAssignmentPolicy -ServiceName 'Rg-X' -ServiceCatalogId 'cat' -ServiceGroups $script:WpGroups -ServicePackages $script:WpPackages | Out-Null

            foreach ($name in 'Workload Plane Users Policy', 'Workload Plane Policy') {
                $policy = $script:PolicyBodies | Where-Object displayName -EQ $name
                $policy.requestorSettings.enableTargetsToSelfUpdateAccess | Should -BeTrue -Because "'$name' allows extensions"
                $policy.requestApprovalSettings.isApprovalRequiredForUpdate | Should -BeTrue -Because "extensions of '$name' need approval"
            }
            foreach ($name in 'Initial Workload Users Policy', 'Initial Workload Admin Policy') {
                ($script:PolicyBodies | Where-Object displayName -EQ $name).requestorSettings.enableTargetsToSelfUpdateAccess | Should -BeFalse
            }
        }

        It 'disables extension per policy and without expiration' {
            $Global:EntraOpsConfig = @{ ServiceEM = @{ AssignmentPolicies = @{
                        WorkloadPlaneUsers  = @{ AllowExtension = $false }
                        WorkloadPlaneAdmins = @{ Expiration = 'noExpiration' }
                    } } }

            New-EntraOpsServiceEMAssignmentPolicy -ServiceName 'Rg-X' -ServiceCatalogId 'cat' -ServiceGroups $script:WpGroups -ServicePackages $script:WpPackages | Out-Null

            foreach ($name in 'Workload Plane Users Policy', 'Workload Plane Policy') {
                $policy = $script:PolicyBodies | Where-Object displayName -EQ $name
                $policy.requestorSettings.enableTargetsToSelfUpdateAccess | Should -BeFalse
                $policy.requestApprovalSettings.isApprovalRequiredForUpdate | Should -BeFalse
            }

            $Global:EntraOpsConfig = @{ ServiceEM = @{ AssignmentPolicies = @{ BaselinePolicy = @{ AllowExtension = 'yes' } } } }
            { New-EntraOpsServiceEMAssignmentPolicy -ServiceName 'Rg-X' -ServiceCatalogId 'cat' -ServiceGroups $script:WpGroups -ServicePackages @(New-TestPackage 'AP-Rg-X-CatalogPlane-Members') } |
            Should -Throw "*BaselinePolicy.AllowExtension 'yes'*"
        }

        It 'rejects invalid approval timeouts and requestor scopes' {
            $Global:EntraOpsConfig = @{ ServiceEM = @{ AssignmentPolicies = @{ BaselinePolicy = @{ ApprovalTimeout = 'PT12H' } } } }
            { New-EntraOpsServiceEMAssignmentPolicy -ServiceName 'Rg-X' -ServiceCatalogId 'cat' -ServiceGroups $script:WpGroups -ServicePackages $script:WpPackages } |
            Should -Throw "*BaselinePolicy.ApprovalTimeout 'PT12H'*"

            $Global:EntraOpsConfig = @{ ServiceEM = @{ AssignmentPolicies = @{ WorkloadPlaneUsers = @{ RequestorScope = 'Everyone' } } } }
            { New-EntraOpsServiceEMAssignmentPolicy -ServiceName 'Rg-X' -ServiceCatalogId 'cat' -ServiceGroups $script:WpGroups -ServicePackages $script:WpPackages } |
            Should -Throw "*WorkloadPlaneUsers.RequestorScope 'Everyone'*"
        }

        It 'adds only the missing initial policy to an existing landing zone' {
            $script:CreatedPolicies.Add([pscustomobject]@{ id = 'existing-users'; displayName = 'Workload Plane Users Policy'; accessPackage = [pscustomobject]@{ id = 'ap:AP-Rg-X-WorkloadPlane-Users' } })
            $script:CreatedPolicies.Add([pscustomobject]@{ id = 'existing-initial'; displayName = 'Initial Workload Users Policy'; accessPackage = [pscustomobject]@{ id = 'ap:AP-Rg-X-WorkloadPlane-Users' } })

            New-EntraOpsServiceEMAssignmentPolicy -ServiceName 'Rg-X' -ServiceCatalogId 'cat' -ServiceGroups $script:WpGroups -ServicePackages @($script:WpPackages[0]) | Out-Null

            $script:PolicyBodies.Count | Should -Be 0
        }
    }
}

Describe 'ServiceEM catalog removal resource group' {
    BeforeEach {
        $script:DeletedUris = [System.Collections.Generic.List[string]]::new()
        Mock Invoke-EntraOpsMsGraphQuery {
            if ($Method -eq 'DELETE') { $script:DeletedUris.Add($Uri); return }
            if ($Uri -like '/v1.0/groups/*') {
                $id = ($Uri -split '/|\?')[3]
                $nickname = @{ 'own'= 'Rg-MyApp.WorkloadPlane.Users'; 'pim' = 'PIM.Rg-MyApp.ManagementPlane.Admins'; 'foreign' = 'Shared.Admins' }[$id]
                return [pscustomobject]@{ Id = $id; MailNickname = $nickname }
            }
            if ($Method -eq 'GET') { return [pscustomobject]@{ Id = 'catalog-id'; accessPackages = @(); Resources = $script:CatalogResources } }
        }
        $script:CatalogResources = @()
        Mock Get-AzContext { [pscustomobject]@{ Tenant = [pscustomobject]@{ Id = 'tenant-1' }; Subscription = [pscustomobject]@{ Id = $script:CurrentSub } } }
        Mock Set-AzContext { $script:CurrentSub = if ($Context) { $Context.Subscription.Id } else { $Subscription } }
        Mock Get-AzResourceGroup { [pscustomobject]@{ ResourceGroupName = $Name; Tags = @{ EntraOpsServiceEM = 'Rg-MyApp' } } }
        Mock Remove-AzResourceGroup {}
        $script:CurrentSub = '22222222-2222-2222-2222-222222222222'
        $script:TargetSub = '11111111-1111-1111-1111-111111111111'
    }

    It 'keeps the resource group by default' {
        Remove-EntraOpsServiceCatalog -ServiceCatalogName 'Catalog-Rg-MyApp' -Force -WarningAction SilentlyContinue | Out-Null

        Should -Invoke Remove-AzResourceGroup -Times 0 -Exactly
    }

    It 'removes the resource group in the given subscription and restores the Azure context' {
        Remove-EntraOpsServiceCatalog -ServiceCatalogName 'Catalog-Rg-MyApp' -Force -RemoveAzureResourceGroup -SubscriptionId $script:TargetSub | Out-Null

        Should -Invoke Set-AzContext -Times 1 -Exactly -ParameterFilter { $Subscription -eq $script:TargetSub }
        Should -Invoke Remove-AzResourceGroup -Times 1 -Exactly -ParameterFilter { $Name -eq 'RG-MyApp' }
        Should -Invoke Set-AzContext -Times 1 -Exactly -ParameterFilter { $null -ne $Context }
    }

    It 'keeps a resource group that was not created by the landing zone' {
        Mock Get-AzResourceGroup { [pscustomobject]@{ ResourceGroupName = $Name; Tags = @{ Owner = 'someone' } } }

        Remove-EntraOpsServiceCatalog -ServiceCatalogName 'Catalog-Rg-MyApp' -Force -RemoveAzureResourceGroup -SubscriptionId $script:TargetSub -WarningVariable warnings -WarningAction SilentlyContinue | Out-Null

        Should -Invoke Remove-AzResourceGroup -Times 0 -Exactly
        @($warnings | Where-Object { "$_" -like "*Keeping Azure Resource Group 'RG-MyApp'*" }).Count | Should -Be 1
        $script:CurrentSub | Should -Be '22222222-2222-2222-2222-222222222222'
    }

    It 'requires SubscriptionId before anything is deleted' {
        { Remove-EntraOpsServiceCatalog -ServiceCatalogName 'Catalog-Rg-MyApp' -Force -RemoveAzureResourceGroup } |
        Should -Throw '*requires -SubscriptionId*'

        $script:DeletedUris.Count | Should -Be 0
        Should -Invoke Remove-AzResourceGroup -Times 0 -Exactly
    }

    It 'deletes only groups created by the landing zone' {
        $script:CatalogResources = @('own', 'pim', 'foreign') | ForEach-Object { [pscustomobject]@{ OriginSystem = 'AadGroup'; OriginId = $_; DisplayName = $_ } }

        Remove-EntraOpsServiceCatalog -ServiceCatalogName 'Catalog-Rg-MyApp' -Force -WarningVariable warnings -WarningAction SilentlyContinue | Out-Null

        $script:DeletedUris | Should -Contain '/v1.0/groups/own'
        $script:DeletedUris | Should -Contain '/v1.0/groups/pim'
        $script:DeletedUris | Should -Not -Contain '/v1.0/groups/foreign'
        @($warnings | Where-Object { "$_" -like "*Keeping group foreign*" }).Count | Should -Be 1
    }

    It 'does not remove the Rg scope resource group when removing the Sub scope catalog' {
        Remove-EntraOpsServiceCatalog -ServiceCatalogName 'Catalog-Sub-MyApp' -Force -RemoveAzureResourceGroup -SubscriptionId $script:TargetSub -WarningAction SilentlyContinue | Out-Null

        Should -Invoke Remove-AzResourceGroup -Times 0 -Exactly
    }

    It 'deletes nothing with WhatIf' {
        $script:CatalogResources = @('own') | ForEach-Object { [pscustomobject]@{ OriginSystem = 'AadGroup'; OriginId = $_; DisplayName = $_ } }

        Remove-EntraOpsServiceCatalog -ServiceCatalogName 'Catalog-Rg-MyApp' -RemoveAzureResourceGroup -SubscriptionId $script:TargetSub -WhatIf | Out-Null

        $script:DeletedUris.Count | Should -Be 0
        Should -Invoke Remove-AzResourceGroup -Times 0 -Exactly
        Should -Invoke Set-AzContext -Times 0 -Exactly
    }
}

Describe 'ServiceEM PIM policy safety' {
    BeforeEach {
        $Global:EntraOpsConfig = [pscustomobject]@{
            ServiceEM = [pscustomobject]@{
                PIMAuthenticationContext = [pscustomobject]@{
                    EnableAuthenticationContext = $true
                    ControlPlane                = [pscustomobject]@{
                        AuthenticationContextClassReferenceId = 'c1'
                    }
                }
            }
        }
        $script:PolicyPatchBody = $null
        $script:PolicyPatchThrowsOnFailure = $false
    }

    It 'sends authentication context as a dedicated policy rule' {
        Mock Invoke-EntraOpsMsGraphQuery {
            if ($Method -eq 'GET') {
                return [pscustomobject]@{ Id = 'assignment-member'; PolicyId = 'policy-id' }
            }
            if ($Method -eq 'PATCH') {
                $script:PolicyPatchBody = $Body
                $script:PolicyPatchThrowsOnFailure = $ThrowOnFailure.IsPresent
                return
            }
            throw "Unexpected Graph method: $Method"
        }

        New-EntraOpsServicePIMPolicy -ServiceGroups @([pscustomobject]@{ Id = 'group-id'; DisplayName = 'SG-Test-ControlPlane-Admins' }) | Out-Null

        $payload = $script:PolicyPatchBody | ConvertFrom-Json -Depth 10
        $authenticationContextRules = @($payload.rules | Where-Object { $_.id -eq 'AuthenticationContext_EndUser_Assignment' })
        $authenticationContextRules.Count | Should -Be 1
        $authenticationContextRules[0].'@odata.type' | Should -Be '#microsoft.graph.unifiedRoleManagementPolicyAuthenticationContextRule'
        $authenticationContextRules[0].isEnabled | Should -BeTrue
        $authenticationContextRules[0].claimValue | Should -Be 'c1'
        @($payload.rules | Where-Object { $_.id -eq 'Enablement_EndUser_Assignment' }).enabledRules |
        Should -Not -Contain 'AuthenticationContext'
        $script:PolicyPatchThrowsOnFailure | Should -BeTrue
    }

    It 'uses the durations from ServiceEM.PIMForGroups' {
        $Global:EntraOpsConfig.ServiceEM | Add-Member -NotePropertyName PIMForGroups -NotePropertyValue ([pscustomobject]@{ MaximumActivationDuration = 'PT4H'; MaximumActiveAssignmentDuration = 'P7D' })
        Mock Invoke-EntraOpsMsGraphQuery {
            if ($Method -eq 'GET') { return [pscustomobject]@{ Id = 'assignment-member'; PolicyId = 'policy-id' } }
            if ($Method -eq 'PATCH') { $script:PolicyPatchBody = $Body; return }
        }

        New-EntraOpsServicePIMPolicy -ServiceGroups @([pscustomobject]@{ Id = 'group-id'; DisplayName = 'SG-Test-WorkloadPlane-Admins' }) 6>$null | Out-Null

        $payload = $script:PolicyPatchBody | ConvertFrom-Json -Depth 10
        ($payload.rules | Where-Object id -EQ 'Expiration_EndUser_Assignment').maximumDuration | Should -Be 'PT4H'
        ($payload.rules | Where-Object id -EQ 'Expiration_Admin_Assignment').maximumDuration | Should -Be 'P7D'
    }

    It 'rejects an invalid PIM for Groups duration' {
        $Global:EntraOpsConfig.ServiceEM | Add-Member -NotePropertyName PIMForGroups -NotePropertyValue ([pscustomobject]@{ MaximumActivationDuration = '10 hours' })

        { New-EntraOpsServicePIMPolicy -ServiceGroups @([pscustomobject]@{ Id = 'group-id'; DisplayName = 'SG-Test-WorkloadPlane-Admins' }) } |
        Should -Throw "*PIMForGroups.MaximumActivationDuration '10 hours'*"
    }

    It 'throws after a policy PATCH failure instead of returning success' {
        Mock Invoke-EntraOpsMsGraphQuery {
            if ($Method -eq 'GET') {
                return [pscustomobject]@{ Id = 'assignment-member'; PolicyId = 'policy-id' }
            }
            if ($Method -eq 'PATCH') {
                throw 'Graph rejected the policy update'
            }
        }

        { New-EntraOpsServicePIMPolicy -ServiceGroups @([pscustomobject]@{ Id = 'failed-group'; DisplayName = 'SG-Test-ControlPlane-Admins' }) } |
        Should -Throw '*Failed to update PIM policy for 1 group(s)*failed-group*'
    }
}