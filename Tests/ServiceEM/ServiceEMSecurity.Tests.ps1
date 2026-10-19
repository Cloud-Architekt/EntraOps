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
    function Remove-AzResourceGroup { [CmdletBinding()] param($Name, [switch]$Force) }
    function Get-AzContext { throw 'Get-AzContext must be mocked' }
    function Set-AzContext { param($Subscription, $Tenant, $Context, $ErrorAction) throw 'Set-AzContext must be mocked' }
    function Get-AzSubscription { param($SubscriptionId, $TenantId, $ErrorAction) throw 'Get-AzSubscription must be mocked' }

    . "$script:TestRepositoryRoot/EntraOps/Private/ConvertTo-EntraOpsODataStringLiteral.ps1"
    . "$script:TestRepositoryRoot/EntraOps/Private/Resolve-EntraOpsServiceEMDelegationGroup.ps1"
    . "$script:TestRepositoryRoot/EntraOps/Private/Wait-EntraOpsServiceEMCondition.ps1"
    . "$script:TestRepositoryRoot/EntraOps/Private/Get-EntraOpsServiceEMConfigValue.ps1"
    . "$script:TestRepositoryRoot/EntraOps/Private/Test-EntraOpsPathWithinRoot.ps1"
    . "$script:TestRepositoryRoot/EntraOps/Private/Update-EntraOpsServiceEMObjectClassificationFile.ps1"
    . "$script:TestRepositoryRoot/EntraOps/Private/Set-EntraOpsServiceEMWorkloadClassification.ps1"
    . "$script:TestRepositoryRoot/EntraOps/Private/Undo-EntraOpsServiceEMUnregisteredGroup.ps1"
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

Describe 'ServiceEM security and consistency' {
BeforeEach {
    $script:ServiceEMNow = [datetime]'2026-01-01T00:00:00Z'
    Mock Get-Date { $script:ServiceEMNow }
}

Describe 'ServiceEM shared helpers' {
    AfterEach {
        $Global:EntraOpsConfig = $null
    }

    It 'returns true as soon as the condition is met' {
        Mock Start-Sleep { $script:ServiceEMNow = $script:ServiceEMNow.AddSeconds($Seconds) }
        $state = @{ Calls = 0 }

        Wait-EntraOpsServiceEMCondition -Condition { $state.Calls++; $state.Calls -ge 3 } | Should -BeTrue

        $state.Calls | Should -Be 3
    }

    It 'caps the interval and returns false after the maximum wait time' {
        $script:Sleeps = [System.Collections.Generic.List[int]]::new()
        Mock Start-Sleep { $script:Sleeps.Add($Seconds); $script:ServiceEMNow = $script:ServiceEMNow.AddSeconds($Seconds) }

        Wait-EntraOpsServiceEMCondition -Condition { $false } -MaxWaitSeconds 100 -MaxIntervalSeconds 30 | Should -BeFalse

        ($script:Sleeps | Measure-Object -Maximum).Maximum | Should -Be 30
        ($script:Sleeps | Measure-Object -Sum).Sum | Should -Be 100
        $script:Sleeps -join ',' | Should -Be '0,1,3,7,15,30,30,14'
    }

    It 'includes time spent performing checks in the timeout budget' {
        Mock Start-Sleep { $script:ServiceEMNow = $script:ServiceEMNow.AddSeconds($Seconds) }
        $state = @{ Calls = 0 }

        Wait-EntraOpsServiceEMCondition -MaxWaitSeconds 100 -Condition {
            $state.Calls++
            $script:ServiceEMNow = $script:ServiceEMNow.AddSeconds(75)
            $false
        } | Should -BeFalse

        $state.Calls | Should -Be 2
        Should -Invoke Start-Sleep -Times 0 -Exactly -ParameterFilter { $Seconds -gt 1 }
    }

    It 'checks once without sleeping when the wait budget is zero' {
        Mock Start-Sleep {}
        $state = @{ Calls = 0 }

        Wait-EntraOpsServiceEMCondition -MaxWaitSeconds 0 -Condition { $state.Calls++; $false } | Should -BeFalse

        $state.Calls | Should -Be 1
        Should -Invoke Start-Sleep -Times 0 -Exactly -ParameterFilter { $Seconds -gt 0 }
    }

    It 'shows elapsed time and pending counts and clears progress on timeout' {
        Mock Start-Sleep { $script:ServiceEMNow = $script:ServiceEMNow.AddSeconds($Seconds) }
        Mock Write-Progress {}

        Wait-EntraOpsServiceEMCondition -Activity 'Access delivery' -MaxWaitSeconds 1 -ProgressStatus { '2 requests pending' } -Condition { $false } | Should -BeFalse

        Should -Invoke Write-Progress -ParameterFilter { $Activity -eq 'Access delivery' -and $Status -like '*seconds elapsed*2 requests pending*' }
        Should -Invoke Write-Progress -Times 1 -Exactly -ParameterFilter { $Activity -eq 'Access delivery' -and $Completed }
    }

    It 'clears wait progress when a condition throws' {
        Mock Start-Sleep {}
        Mock Write-Progress {}

        { Wait-EntraOpsServiceEMCondition -Activity 'Access delivery' -Condition { throw 'Graph lookup failed' } } | Should -Throw '*Graph lookup failed*'

        Should -Invoke Write-Progress -Times 1 -Exactly -ParameterFilter { $Activity -eq 'Access delivery' -and $Completed }
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

    It 'returns the config value itself instead of a wrapping collection' {
        $Global:EntraOpsConfig = @{ ServiceEM = @{ CreateM365Group = $true; AdministrativeUnits = @{ ControlPlane = 'au-id' }; Roles = @('a', 'b') } }

        (Get-EntraOpsServiceEMConfigValue -Path 'CreateM365Group') -is [bool] | Should -BeTrue
        (Get-EntraOpsServiceEMConfigValue -Path 'AdministrativeUnits') -is [hashtable] | Should -BeTrue
        (Get-EntraOpsServiceEMConfigValue -Path 'Roles').Count | Should -Be 2
        $null -eq (Get-EntraOpsServiceEMConfigValue -Path 'Missing') | Should -BeTrue
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
        Should -Invoke New-EntraOpsServicePIMAssignment -Times 0 -Exactly
    }

    It 'sets the workload plane admin as permanent owner only with GroupOwnership Permanent and warns' {
        New-EntraOpsServiceBootstrap -ServiceName 'Rg-X' -SkipAzureResourceGroup -WorkloadPlaneAdmin 'admin@contoso.com' -ServiceMembers @() -GroupOwnership Permanent -WarningVariable warnings -WarningAction SilentlyContinue 6>$null | Out-Null

        Should -Invoke New-EntraOpsServiceEntraGroup -Times 1 -Exactly -ParameterFilter { $WorkloadPlaneAdmin -eq 'https://graph.microsoft.com/v1.0/users/id:admin@contoso.com' }
        Should -Invoke New-EntraOpsServicePIMAssignment -Times 0 -Exactly
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
        @($warnings | Where-Object { "$_" -like '*ManagementPlane-Members isn''t supported*' }).Count | Should -Be 1
    }

    Context 'PIM for Groups' {
        BeforeEach {
            $script:BootstrapSteps = [System.Collections.Generic.List[string]]::new()
            Mock New-EntraOpsServiceEntraGroup {
                @('WorkloadPlane-Users', 'WorkloadPlane-Admins', 'ManagementPlane-Admins', 'ControlPlane-Admins', 'CatalogPlane-Members') |
                ForEach-Object { [pscustomobject]@{ Id = $_; DisplayName = "SG-Rg-X-$_" } }
            }
            Mock New-EntraOpsServicePIMPolicy { $script:BootstrapSteps.Add('PIMPolicy'); @() }
            Mock New-EntraOpsServiceEMCatalogResource { $script:BootstrapSteps.Add('CatalogResource'); @([pscustomobject]@{ Id = 'r1' }) }
        }

        It 'configures no PIM for Groups by default' {
            New-EntraOpsServiceBootstrap -ServiceName 'Rg-X' -SkipAzureResourceGroup -ServiceMembers @() -WarningVariable warnings -WarningAction SilentlyContinue 6>$null | Out-Null

            Should -Invoke New-EntraOpsServicePIMPolicy -Times 0 -Exactly
            Should -Invoke New-EntraOpsServicePIMAssignment -Times 0 -Exactly
            Should -Invoke New-EntraOpsServiceEMAccessPackageResourceAssignment -Times 1 -Exactly -ParameterFilter { @($EligibleMemberGroupIds).Count -eq 0 }
            @($warnings | Where-Object { "$_" -like '*Microsoft Entra ID Governance*' }).Count | Should -Be 0
        }

        It 'manages ControlPlane-Admins and ManagementPlane-Admins with EnablePimForGroups and warns about the license' {
            New-EntraOpsServiceBootstrap -ServiceName 'Rg-X' -SkipAzureResourceGroup -ServiceMembers @() -EnablePimForGroups -WarningVariable warnings -WarningAction SilentlyContinue 6>$null | Out-Null

            Should -Invoke New-EntraOpsServicePIMPolicy -Times 1 -Exactly -ParameterFilter { (@($ServiceGroups.Id | Sort-Object) -join ',') -eq 'ControlPlane-Admins,ManagementPlane-Admins' }
            Should -Invoke New-EntraOpsServiceEMAccessPackageResourceAssignment -Times 1 -Exactly -ParameterFilter { (@($EligibleMemberGroupIds | Sort-Object) -join ',') -eq 'ControlPlane-Admins,ManagementPlane-Admins' }
            @($warnings | Where-Object { "$_" -like '*-EnablePimForGroups:*Microsoft Entra ID Governance*P2 alone*' }).Count | Should -Be 1
            $script:BootstrapSteps[0] | Should -Be 'PIMPolicy' -Because 'the catalog only offers the Eligible Member role of groups managed by PIM'
        }

        It 'manages WorkloadPlane-Admins with EnableWorkloadPlanePimForGroups' {
            New-EntraOpsServiceBootstrap -ServiceName 'Rg-X' -SkipAzureResourceGroup -ServiceMembers @() -EnableWorkloadPlanePimForGroups -WarningVariable warnings -WarningAction SilentlyContinue 6>$null | Out-Null

            Should -Invoke New-EntraOpsServicePIMPolicy -Times 1 -Exactly -ParameterFilter { (@($ServiceGroups.Id) -join ',') -eq 'WorkloadPlane-Admins' }
            Should -Invoke New-EntraOpsServiceEMAccessPackageResourceAssignment -Times 1 -Exactly -ParameterFilter { (@($EligibleMemberGroupIds) -join ',') -eq 'WorkloadPlane-Admins' }
            @($warnings | Where-Object { "$_" -like '*-EnableWorkloadPlanePimForGroups:*Microsoft Entra ID Governance*' }).Count | Should -Be 1
        }
    }

    It 'forwards CatalogPlaneMembers' {
        New-EntraOpsServiceBootstrap -ServiceName 'Rg-X' -SkipAzureResourceGroup -ServiceMembers @() -CatalogPlaneMembers @('ops@contoso.com') 6>$null | Out-Null

        Should -Invoke New-EntraOpsServiceEMAssignment -Times 1 -Exactly -ParameterFilter { @($CatalogPlaneMembers.Id) -join ',' -eq 'id:ops@contoso.com' }
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

        It 'gives delegated admin groups of a governance landing zone their Azure roles on this scope' {
            Mock New-EntraOpsServiceEntraGroup { @([pscustomobject]@{ Id = 'wa'; DisplayName = 'SG-Rg-X-WorkloadPlane-Admins' }) }
            Mock Invoke-EntraOpsMsGraphQuery {
                if ($Uri -like '/v1.0/groups/*') { return [pscustomobject]@{ Id = ($Uri -replace '^/v1.0/groups/' -replace '\?.*$'); DisplayName = 'governance group'; IsAssignableToRole = $true; SecurityEnabled = $true } }
                return @()
            }
            $mp = '22222222-2222-2222-2222-222222222222'; $cp = '33333333-3333-3333-3333-333333333333'

            New-EntraOpsServiceBootstrap -ServiceName 'Rg-X' -AzureRegion 'westeurope' -SubscriptionId '11111111-1111-1111-1111-111111111111' -ServiceMembers @() `
                -ManagementPlaneDelegationGroupId $mp -ControlPlaneDelegationGroupId $cp 6>$null | Out-Null

            Should -Invoke New-EntraOpsServiceAZContainer -Times 1 -Exactly -ParameterFilter {
                ($ServiceGroups | Where-Object { $_.Id -eq $mp -and $_.DisplayName -eq 'SG-Rg-X-ManagementPlane-Admins' -and $_.IsDelegated }) -and
                ($ServiceGroups | Where-Object { $_.Id -eq $cp -and $_.DisplayName -eq 'SG-Rg-X-ControlPlane-Admins' -and $_.IsDelegated }) -and
                -not $SkipControlPlaneDelegation
            }
        }

        It 'adds PIM for Groups eligible members with EnablePimForGroups' {
            New-EntraOpsServiceBootstrap -ServiceName 'Rg-X' -SkipAzureResourceGroup -ServiceMembers @() -ControlPlaneAdmins @('cp@contoso.com') -EnablePimForGroups -WarningAction SilentlyContinue 6>$null | Out-Null

            $script:CpRequests.Count | Should -Be 1
            $script:CpRequests[0].Uri | Should -Be '/v1.0/identityGovernance/privilegedAccess/group/eligibilityScheduleRequests'
            $script:CpRequests[0].Body.accessId | Should -Be 'member'
            $script:CpRequests[0].Body.groupId | Should -Be 'cp'
            $script:CpRequests[0].Body.principalId | Should -Be 'id:cp@contoso.com'
        }

        It 'completes the other steps and then fails when a ControlPlane admin can not be added' {
            # Like the real helper: a failed lookup only throws with -ThrowOnFailure, otherwise it returns nothing.
            Mock Invoke-EntraOpsMsGraphQuery {
                if ($Uri -like '/v1.0/users/*') { return [pscustomobject]@{ Id = "id:$($Uri -replace '^/v1.0/users/')" } }
                if ($Uri -like '/v1.0/groups/cp/members*') { if ($ThrowOnFailure) { throw 'simulated lookup failure' }; return @() }
                if ($Method -eq 'POST') { $script:CpRequests.Add([pscustomobject]@{ Uri = $Uri; Body = ($Body | ConvertFrom-Json) }); return [pscustomobject]@{ Id = 'req' } }
                return @()
            }

            { New-EntraOpsServiceBootstrap -ServiceName 'Rg-X' -AzureRegion 'westeurope' -SubscriptionId '11111111-1111-1111-1111-111111111111' -ServiceMembers @() `
                    -ControlPlaneAdmins @('cp@contoso.com') -WarningAction SilentlyContinue 6>$null } | Should -Throw '*Failed to add 1 ControlPlane admin(s)*simulated lookup failure*'

            $script:CpRequests.Count | Should -Be 0
            Should -Invoke New-EntraOpsServiceAZContainer -Times 1 -Exactly
        }

        It 'warns when no per-service ControlPlane-Admins group exists' {
            Mock New-EntraOpsServiceEntraGroup { @([pscustomobject]@{ Id = 'g1'; DisplayName = 'SG-Rg-X-WorkloadPlane-Admins' }) }

            New-EntraOpsServiceBootstrap -ServiceName 'Rg-X' -SkipAzureResourceGroup -ServiceMembers @() -ControlPlaneAdmins @('cp@contoso.com') -WarningVariable warnings -WarningAction SilentlyContinue 6>$null | Out-Null

            $script:CpRequests.Count | Should -Be 0
            @($warnings | Where-Object { "$_" -like '*-ControlPlaneAdmins is ignored*' }).Count | Should -Be 1
        }
    }

    It 'stops before creating objects when a delegated admin group is not role-assignable' {
        Mock Invoke-EntraOpsMsGraphQuery {
            if ($Uri -like '/v1.0/users/*') { return [pscustomobject]@{ Id = "id:$($Uri -replace '^/v1.0/users/')" } }
            if ($Uri -like '/v1.0/groups/*') { return [pscustomobject]@{ Id = '11111111-1111-1111-1111-111111111111'; DisplayName = 'Helpdesk'; IsAssignableToRole = $false; SecurityEnabled = $true } }
        }

        { New-EntraOpsServiceBootstrap -ServiceName 'Rg-X' -SkipAzureResourceGroup -ServiceMembers @() -ControlPlaneDelegationGroupId '11111111-1111-1111-1111-111111111111' 6>$null } |
        Should -Throw "*Delegated ControlPlane-Admins group 'Helpdesk'*isn't a role-assignable security group*"
        Should -Invoke New-EntraOpsServiceEntraGroup -Times 0 -Exactly
    }

    It 'stops before creating objects when a delegated group lookup fails' {
        Mock Invoke-EntraOpsMsGraphQuery {
            if ($Uri -like '/v1.0/users/*') { return [pscustomobject]@{ Id = "id:$($Uri -replace '^/v1.0/users/')" } }
            if ($Uri -like '/v1.0/groups/*') { throw 'Request_ResourceNotFound' }
        }

        { New-EntraOpsServiceBootstrap -ServiceName 'Rg-X' -SkipAzureResourceGroup -ServiceMembers @() -ControlPlaneDelegationGroupId '11111111-1111-1111-1111-111111111111' 6>$null } |
        Should -Throw '*Unable to resolve delegated ControlPlane-Admins group*Request_ResourceNotFound*'
        { New-EntraOpsServiceBootstrap -ServiceName 'Rg-X' -SkipAzureResourceGroup -ServiceMembers @() -ManagementPlaneDelegationGroupId '../users' 6>$null } |
        Should -Throw '*ManagementPlaneDelegationGroupId*'

        Should -Invoke New-EntraOpsServiceEntraGroup -Times 0 -Exactly
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

    It 'uses RoleAssignableWorkloadPlaneAdmins from ServiceEM config unless the parameter is set explicitly' {
        try {
            New-EntraOpsServiceBootstrap -ServiceName 'Rg-A' -SkipAzureResourceGroup -ServiceMembers @() 6>$null | Out-Null
            $Global:EntraOpsConfig = @{ ServiceEM = @{ RoleAssignableWorkloadPlaneAdmins = $true } }
            New-EntraOpsServiceBootstrap -ServiceName 'Rg-B' -SkipAzureResourceGroup -ServiceMembers @() 6>$null | Out-Null
            New-EntraOpsServiceBootstrap -ServiceName 'Rg-C' -SkipAzureResourceGroup -ServiceMembers @() -RoleAssignableWorkloadPlaneAdmins:$false 6>$null | Out-Null
        } finally {
            $Global:EntraOpsConfig = $null
        }

        Should -Invoke New-EntraOpsServiceEntraGroup -Times 1 -Exactly -ParameterFilter { $ServiceName -eq 'Rg-A' -and -not $RoleAssignableWorkloadPlaneAdmins }
        Should -Invoke New-EntraOpsServiceEntraGroup -Times 1 -Exactly -ParameterFilter { $ServiceName -eq 'Rg-B' -and $RoleAssignableWorkloadPlaneAdmins }
        Should -Invoke New-EntraOpsServiceEntraGroup -Times 1 -Exactly -ParameterFilter { $ServiceName -eq 'Rg-C' -and -not $RoleAssignableWorkloadPlaneAdmins }
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

    It 'escapes guest user principal names in user lookups' {
        Mock Invoke-EntraOpsMsGraphQuery {
            if ($Uri -like '/v1.0/users/*') { return [pscustomobject]@{ Id = "id:$($Uri -replace '^/v1.0/users/')" } }
        }

        New-EntraOpsServiceBootstrap -ServiceName 'Rg-X' -SkipAzureResourceGroup -WorkloadPlaneAdmin 'adele_fabrikam.com#EXT#@contoso.com' -ServiceMembers @('ben_fabrikam.com#EXT#@contoso.com') 6>$null | Out-Null

        Should -Invoke Invoke-EntraOpsMsGraphQuery -Times 1 -Exactly -ParameterFilter { $Uri -eq '/v1.0/users/adele_fabrikam.com%23EXT%23@contoso.com' }
        Should -Invoke Invoke-EntraOpsMsGraphQuery -Times 1 -Exactly -ParameterFilter { $Uri -eq '/v1.0/users/ben_fabrikam.com%23EXT%23@contoso.com' }
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
        Should -Invoke New-EntraOpsServiceEMCatalogResource -Times 1 -Exactly -ParameterFilter { $ServiceGroups.Id -contains 'm365' }
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
            $script:AdminGroupRoleAssignable = $true
            $script:AdminGroupSecurityEnabled = $true
            Mock Invoke-EntraOpsMsGraphQuery {
                if ($Uri -like '/v1.0/users/*') { return [pscustomobject]@{ Id = "id:$($Uri -replace '^/v1.0/users/')" } }
                if ($Uri -like "/v1.0/groups/$script:AdminGroupId*") { return [pscustomobject]@{ Id = $script:AdminGroupId; DisplayName = 'PRG-Admins'; IsAssignableToRole = $script:AdminGroupRoleAssignable; SecurityEnabled = $script:AdminGroupSecurityEnabled } }
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

        It 'warns when the administrator group is not role-assignable' {
            $script:MemberOfResult = @($script:AdminGroupId)
            $script:AdminGroupRoleAssignable = $false

            New-EntraOpsServiceBootstrap -ServiceName 'Rg-X' -SkipAzureResourceGroup -WorkloadPlaneAdmin 'admin@contoso.com' -ServiceMembers @() -ServiceRoles $script:RgRoles -AdministratorGroupId $script:AdminGroupId -WarningVariable warnings -WarningAction SilentlyContinue 6>$null | Out-Null

            @($warnings | Where-Object { "$_" -like "*CatalogPlane-Members group 'PRG-Admins'*isn't role-assignable*" }).Count | Should -Be 1
            Should -Invoke New-EntraOpsServiceEntraGroup -Times 1 -Exactly
        }

        It 'throws before creating groups when the administrator group is not a security group' {
            $script:MemberOfResult = @($script:AdminGroupId)
            $script:AdminGroupRoleAssignable = $false
            $script:AdminGroupSecurityEnabled = $false

            { New-EntraOpsServiceBootstrap -ServiceName 'Rg-X' -SkipAzureResourceGroup -WorkloadPlaneAdmin 'admin@contoso.com' -ServiceMembers @() -ServiceRoles $script:RgRoles -AdministratorGroupId $script:AdminGroupId 6>$null } |
            Should -Throw "*CatalogPlane-Members group 'PRG-Admins'*isn't a security group*"
            Should -Invoke New-EntraOpsServiceEntraGroup -Times 0 -Exactly
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
        Mock Start-Sleep { $script:ServiceEMNow = $script:ServiceEMNow.AddSeconds($Seconds) }
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

    It 'assigns Catalog Reader only to WorkloadPlane-Admins' {
        $groups = @($script:CatalogGroups) + [pscustomobject]@{ Id = 'mp'; DisplayName = 'SG-Rg-X-ManagementPlane-Admins' }

        New-EntraOpsServiceEMCatalogResourceRole -ServiceGroups $groups -ServiceCatalogId 'cat' -WarningAction SilentlyContinue 6>$null | Out-Null

        @($script:RoleBodies | Where-Object { $_.roleDefinitionId -eq '44272f93-9762-48e8-af59-1b5351b1d6b3' } | ForEach-Object { $_.principalId }) |
        Should -Be @('id:SG-Rg-X-WorkloadPlane-Admins')
        @($script:RoleBodies | Where-Object { $_.principalId -eq 'id:SG-Rg-X-CatalogPlane-Members' }).Count | Should -Be 0
        @($script:RoleBodies | Where-Object { $_.principalId -eq 'mp' } | ForEach-Object { $_.roleDefinitionId }) |
        Should -Be @('e2182095-804a-4656-ae11-64734e9b7ae5')
    }

    It 'warns about same-tier escalation only for a per-service ManagementPlane-Admins group' {
        $perService = @($script:CatalogGroups) + [pscustomobject]@{ Id = 'mp'; DisplayName = 'SG-Rg-X-ManagementPlane-Admins' }
        $centralized = @($script:CatalogGroups) + [pscustomobject]@{ Id = 'mp-tenant'; DisplayName = 'SG-Rg-X-ManagementPlane-Admins'; IsDelegated = $true }

        New-EntraOpsServiceEMCatalogResourceRole -ServiceGroups $perService -ServiceCatalogId 'cat' -WarningVariable perServiceWarnings -WarningAction SilentlyContinue 6>$null | Out-Null
        New-EntraOpsServiceEMCatalogResourceRole -ServiceGroups $centralized -ServiceCatalogId 'cat' -WarningVariable centralizedWarnings -WarningAction SilentlyContinue 6>$null | Out-Null

        @($perServiceWarnings | Where-Object { "$_" -like '*add further ManagementPlane admins*-GovernanceModel Centralized*' }).Count | Should -Be 1
        @($centralizedWarnings | Where-Object { "$_" -like '*Access package assignment manager*' }).Count | Should -Be 0
        @($script:RoleBodies | Where-Object { $_.roleDefinitionId -eq 'e2182095-804a-4656-ae11-64734e9b7ae5' }).principalId | Should -Be @('mp', 'mp-tenant')
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
        Mock Start-Sleep { $script:ServiceEMNow = $script:ServiceEMNow.AddSeconds($Seconds) }
        Mock Invoke-EntraOpsMsGraphQuery {
            if ($Method -eq 'POST') {
                if (-not $ThrowOnFailure) { throw 'POST without -ThrowOnFailure' }
                $target = ($Body | ConvertFrom-Json).assignment.targetId
                if ($target -eq 'out-of-scope') {
                    $exception = [System.InvalidOperationException]::new('Graph 400 out of scope')
                    $exception.Data['StatusCode'] = 400
                    throw $exception
                }
                return [pscustomobject]@{ Id = "req-$target"; State = 'submitted' }
            }
            if ($Uri -match '/assignmentRequests/(req-.+)$') {
                return [pscustomobject]@{ Id = $Matches[1]; State = (& $script:NextState $Matches[1]); Status = 'x' }
            }
            return @()
        }
    }

    It 'submits the other requests, waits for them and reports a rejected request' {
        $script:NextState = { param($id) 'delivered' }

        { New-EntraOpsServiceEMAssignment -ServiceCatalogId 'cat' -ServiceMembers @([pscustomobject]@{ Id = 'out-of-scope' }, [pscustomobject]@{ Id = 'admin' }) `
                -WorkloadPlaneAdmin ([pscustomobject]@{ Id = 'admin2' }) -ServiceAssignmentPolicies $script:Policies -ServicePackages $script:Packages 6>$null } |
        Should -Throw '*Failed to create 1 access package assignment request(s)*member out-of-scope to AP-Rg-X-WorkloadPlane-Users: Graph 400 out of scope*'

        Should -Invoke Invoke-EntraOpsMsGraphQuery -Times 1 -Exactly -ParameterFilter { $Uri -like '*/assignmentRequests/req-admin' }
        Should -Invoke Invoke-EntraOpsMsGraphQuery -Times 1 -Exactly -ParameterFilter { $Uri -like '*/assignmentRequests/req-admin2' }
        Should -Invoke Start-Sleep -Times 1 -Exactly
    }

    It 'reports an error other than a scope rejection on an admin-only policy without changing the policy' {
        Mock Invoke-EntraOpsMsGraphQuery {
            if ($Method -eq 'PUT') { throw 'Unexpected PUT' }
            if ($Method -eq 'POST') {
                $exception = [System.InvalidOperationException]::new('Graph 403')
                $exception.Data['StatusCode'] = 403
                throw $exception
            }
            return @()
        }
        $policies = @($script:Policies) + @([pscustomobject]@{ Id = 'pol-initial-admins'; DisplayName = 'Initial Workload Admin Policy' })

        { New-EntraOpsServiceEMAssignment -ServiceCatalogId 'cat' -ServiceMembers @() `
                -WorkloadPlaneAdmin ([pscustomobject]@{ Id = 'admin' }) -ServiceAssignmentPolicies $policies -ServicePackages $script:Packages 6>$null } |
        Should -Throw '*workload plane admin admin to AP-Rg-X-WorkloadPlane-Admins: Graph 403*'

        Should -Invoke Invoke-EntraOpsMsGraphQuery -Times 0 -Exactly -ParameterFilter { $Uri -like '*/assignmentPolicies/*' }
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
        $statuses = [System.Collections.Generic.List[object]]::new()
        Mock Invoke-EntraOpsMsGraphQuery {
            if ($Method -eq 'POST') { $script:AssignmentBodies.Add(($Body | ConvertFrom-Json)); return [pscustomobject]@{ Id = 'req-x'; State = 'submitted' } }
            if ($Uri -like "*assignmentRequests?*accessPackage/id eq 'ap-admins'*") {
                return @(
                    [pscustomobject]@{ Id = 'r1'; State = 'pendingApproval'; Assignment = [pscustomobject]@{ Target = [pscustomobject]@{ ObjectId = 'admin' } }; AccessPackage = [pscustomobject]@{ Id = 'ap-admins' } }
                    [pscustomobject]@{ Id = 'r0'; State = 'delivered'; Assignment = [pscustomobject]@{ Target = [pscustomobject]@{ ObjectId = 'other' } }; AccessPackage = [pscustomobject]@{ Id = 'ap-admins' } }
                )
            }
            return @()
        }

        New-EntraOpsServiceEMAssignment -ServiceCatalogId 'cat' -ServiceMembers @() `
            -AssignmentRequestStatuses $statuses `
            -WorkloadPlaneAdmin ([pscustomobject]@{ Id = 'admin' }) -ServiceAssignmentPolicies $script:Policies -ServicePackages $script:Packages 6>$null | Out-Null

        $script:AssignmentBodies.Count | Should -Be 0
        $statuses.Count | Should -Be 1
        $statuses[0].State | Should -Be 'pendingApproval'
        $statuses[0].TargetId | Should -Be 'admin'
        $statuses[0].AccessPackageId | Should -Be 'ap-admins'
    }

    It 'continues with a warning instead of waiting indefinitely' {
        $script:NextState = { param($id) 'delivering' }
        $statuses = [System.Collections.Generic.List[object]]::new()

        { New-EntraOpsServiceEMAssignment -ServiceCatalogId 'cat' -ServiceMembers @([pscustomobject]@{ Id = 'admin' }) `
                -AssignmentRequestStatuses $statuses `
                -ServiceAssignmentPolicies $script:Policies -ServicePackages $script:Packages `
                -WarningVariable script:warnings -WarningAction SilentlyContinue 6>$null } | Should -Not -Throw

        @($script:warnings | Where-Object { "$_" -like '*continuing without waiting*req-admin=delivering*' }).Count | Should -Be 1
        Should -Invoke Start-Sleep -Times 15 -Exactly
        Should -Invoke Start-Sleep -ParameterFilter { $Seconds -gt 30 } -Times 0 -Exactly
        $statuses.Count | Should -Be 1
        $statuses[0].State | Should -Be 'delivering'
        $statuses[0].Status | Should -Be 'x'
        $statuses[0].TargetId | Should -Be 'admin'
        $statuses[0].AccessPackageId | Should -Be 'ap-users'
        ($script:ServiceEMNow - [datetime]'2026-01-01T00:00:00Z').TotalSeconds | Should -Be 300
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

    It 'forwards RoleAssignableWorkloadPlaneAdmins from parameter or ServiceEM config' {
        New-EntraOpsSubscriptionLandingZone -DeploymentPrefix 'A' -AzureRegion 'westeurope' -SubscriptionId $script:TargetSub -GovernanceModel PerService 6>$null | Out-Null
        New-EntraOpsSubscriptionLandingZone -DeploymentPrefix 'B' -AzureRegion 'westeurope' -SubscriptionId $script:TargetSub -GovernanceModel PerService -RoleAssignableWorkloadPlaneAdmins 6>$null | Out-Null
        $Global:EntraOpsConfig = @{ ServiceEM = @{ RoleAssignableWorkloadPlaneAdmins = $true } }
        New-EntraOpsSubscriptionLandingZone -DeploymentPrefix 'C' -AzureRegion 'westeurope' -SubscriptionId $script:TargetSub -GovernanceModel PerService 6>$null | Out-Null
        New-EntraOpsSubscriptionLandingZone -DeploymentPrefix 'D' -AzureRegion 'westeurope' -SubscriptionId $script:TargetSub -GovernanceModel PerService -RoleAssignableWorkloadPlaneAdmins:$false 6>$null | Out-Null

        Should -Invoke New-EntraOpsServiceBootstrap -Times 1 -Exactly -ParameterFilter { $ServiceName -eq 'Rg-A' -and -not $RoleAssignableWorkloadPlaneAdmins }
        Should -Invoke New-EntraOpsServiceBootstrap -Times 1 -Exactly -ParameterFilter { $ServiceName -eq 'Rg-B' -and $RoleAssignableWorkloadPlaneAdmins }
        Should -Invoke New-EntraOpsServiceBootstrap -Times 1 -Exactly -ParameterFilter { $ServiceName -eq 'Rg-C' -and $RoleAssignableWorkloadPlaneAdmins }
        Should -Invoke New-EntraOpsServiceBootstrap -Times 1 -Exactly -ParameterFilter { $ServiceName -eq 'Rg-D' -and -not $RoleAssignableWorkloadPlaneAdmins }
    }

    It 'forwards CreateM365Group and creates no Microsoft 365 group by default' {
        New-EntraOpsSubscriptionLandingZone -DeploymentPrefix 'X' -AzureRegion 'westeurope' -SubscriptionId $script:TargetSub -GovernanceModel PerService -CreateM365Group 6>$null | Out-Null
        New-EntraOpsSubscriptionLandingZone -DeploymentPrefix 'Y' -AzureRegion 'westeurope' -SubscriptionId $script:TargetSub -GovernanceModel PerService 6>$null | Out-Null

        Should -Invoke New-EntraOpsServiceBootstrap -Times 1 -Exactly -ParameterFilter { $ServiceName -eq 'Rg-X' -and $CreateM365Group }
        Should -Invoke New-EntraOpsServiceBootstrap -Times 1 -Exactly -ParameterFilter { $ServiceName -eq 'Rg-Y' -and -not $CreateM365Group }
    }

    It 'only supports single-scope deployments' {
        { New-EntraOpsSubscriptionLandingZone -DeploymentPrefix 'X' -DeploymentScope Both -SkipAzureResourceGroup } | Should -Throw '*does not belong to the set*'
    }

    It 'uses the governance groups of another landing zone as delegated groups' {
        $ids = @{ ControlPlane = '11111111-aaaa-aaaa-aaaa-111111111111'; ManagementPlane = '22222222-aaaa-aaaa-aaaa-222222222222'; Administrator = '33333333-aaaa-aaaa-aaaa-333333333333' }
        Mock Resolve-EntraOpsServiceEMDelegationGroup { $GroupId }

        New-EntraOpsSubscriptionLandingZone -DeploymentPrefix 'X' -AzureRegion 'westeurope' -SubscriptionId $script:TargetSub -GovernanceModel PerService `
            -ControlPlaneDelegationGroupId $ids.ControlPlane -ManagementPlaneDelegationGroupId $ids.ManagementPlane -AdministratorGroupId $ids.Administrator `
            -ControlPlaneAdmins @('cp@contoso.com') -CatalogPlaneMembers @('ops@contoso.com') -WarningVariable warnings -WarningAction SilentlyContinue 6>$null | Out-Null

        Should -Invoke New-EntraOpsServiceBootstrap -Times 1 -Exactly -ParameterFilter {
            $ServiceName -eq 'Rg-X' -and $SkipControlPlaneDelegation -and $SkipManagementPlaneDelegation -and
            $ControlPlaneDelegationGroupId -eq $ids.ControlPlane -and $ManagementPlaneDelegationGroupId -eq $ids.ManagementPlane -and $AdministratorGroupId -eq $ids.Administrator -and
            -not (& $script:HasRole $ServiceRoles 'ControlPlane' 'Admins') -and -not (& $script:HasRole $ServiceRoles 'ManagementPlane' 'Admins') -and
            -not $ControlPlaneAdmins -and @($CatalogPlaneMembers) -join ',' -eq 'ops@contoso.com'
        }
        @($warnings | Where-Object { "$_" -like '*-ControlPlaneAdmins is ignored*' }).Count | Should -Be 1
    }

    It 'forwards GroupOwnership and the PIM for Groups switches to every scope' {
        New-EntraOpsSubscriptionLandingZone -DeploymentPrefix 'X' -AzureRegion 'westeurope' -SubscriptionId $script:TargetSub -GovernanceModel PerService -GroupOwnership Eligible -EnablePimForGroups -EnableWorkloadPlanePimForGroups 6>$null | Out-Null

        Should -Invoke New-EntraOpsServiceBootstrap -Times 1 -Exactly -ParameterFilter { $GroupOwnership -eq 'Eligible' -and $EnablePimForGroups -and $EnableWorkloadPlanePimForGroups }
    }

    It 'ignores ControlPlaneAdmins in the Centralized model with a warning' {
        New-EntraOpsSubscriptionLandingZone -DeploymentPrefix 'X' -AzureRegion 'westeurope' -SubscriptionId $script:TargetSub -GovernanceModel Centralized `
            -AdministratorGroupId '44444444-4444-4444-4444-444444444444' -ControlPlaneAdmins @('cp@contoso.com') -WarningVariable warnings -WarningAction SilentlyContinue 6>$null | Out-Null

        Should -Invoke New-EntraOpsServiceBootstrap -Times 1 -Exactly -ParameterFilter { -not $ControlPlaneAdmins }
        @($warnings | Where-Object { "$_" -like '*-ControlPlaneAdmins is ignored*' }).Count | Should -Be 1
    }

    It 'stops in the Centralized model when a tenant-wide delegation group cannot be resolved' {
        Mock Resolve-EntraOpsServiceEMDelegationGroup { if ($Plane -eq 'ManagementPlane') { throw 'Graph 403' } '33333333-3333-3333-3333-333333333333' }

        { New-EntraOpsSubscriptionLandingZone -DeploymentPrefix 'X' -AzureRegion 'westeurope' -SubscriptionId $script:TargetSub -GovernanceModel Centralized -AdministratorGroupId '44444444-4444-4444-4444-444444444444' -WarningAction SilentlyContinue 6>$null } |
        Should -Throw '*Centralized governance model failed*-AllowPerServiceFallback*Graph 403*'

        Should -Invoke New-EntraOpsServiceBootstrap -Times 0 -Exactly
    }

    It 'falls back to per-service admin groups only with AllowPerServiceFallback' {
        Mock Resolve-EntraOpsServiceEMDelegationGroup { throw 'Graph 403' }

        New-EntraOpsSubscriptionLandingZone -DeploymentPrefix 'X' -AzureRegion 'westeurope' -SubscriptionId $script:TargetSub -GovernanceModel Centralized -AdministratorGroupId '44444444-4444-4444-4444-444444444444' -AllowPerServiceFallback -WarningAction SilentlyContinue 6>$null | Out-Null

        Should -Invoke New-EntraOpsServiceBootstrap -Times 1 -Exactly -ParameterFilter {
            -not $SkipControlPlaneDelegation -and -not $SkipManagementPlaneDelegation -and
            (& $script:HasRole $ServiceRoles 'ControlPlane' 'Admins') -and (& $script:HasRole $ServiceRoles 'ManagementPlane' 'Admins')
        }
    }
}

Describe 'ServiceEM PIM for Groups eligible assignments' {
    BeforeAll {
        . "$script:TestRepositoryRoot/EntraOps/Public/ServiceEM/New-EntraOpsServicePIMAssignment.ps1"
    }

    BeforeEach {
        $script:EligibilityBodies = [System.Collections.Generic.List[object]]::new()
        Mock Start-Sleep { $script:ServiceEMNow = $script:ServiceEMNow.AddSeconds($Seconds) }
        Mock Invoke-EntraOpsMsGraphQuery {
            if ($Method -eq 'POST') {
                $script:EligibilityBodies.Add(($Body | ConvertFrom-Json))
                return
            }
            if ($Uri -like '/v1.0/policies/roleManagementPolicyAssignments?*') {
                return @([pscustomobject]@{ policy = [pscustomobject]@{ rules = @($script:OwnerPolicyRules) } })
            }
            if ($Uri -notlike '/v1.0/identityGovernance/privilegedAccess/group/eligibilitySchedules?*') { throw "Unexpected Graph URI: $Uri" }
            $groupId = [regex]::Match($Uri, "groupId eq '([^']+)'").Groups[1].Value
            return @(@($script:ExistingSchedules) + @($script:EligibilityBodies) | Where-Object { $_ -and $_.groupId -eq $groupId } | ForEach-Object {
                    [pscustomobject]@{ id = "$($_.groupId)-$($_.principalId)"; groupId = $_.groupId; principalId = $_.principalId; accessId = $_.accessId; scheduleInfo = @{ expiration = @{ type = 'noExpiration' } } }
                })
        }
        $script:ExistingSchedules = @()
        $script:OwnerPolicyRules = @()
    }

    It 'requests the maximum duration when the owner policy does not allow permanent eligibility' {
        $groups = @([pscustomobject]@{ Id = 'id:SG-Rg-X-WorkloadPlane-Admins'; DisplayName = 'SG-Rg-X-WorkloadPlane-Admins' })
        $script:OwnerPolicyRules = @([pscustomobject]@{ id = 'Expiration_Admin_Eligibility'; isExpirationRequired = $true; maximumDuration = 'P180D' })

        New-EntraOpsServicePIMAssignment -ServiceGroups $groups -WorkloadPlaneAdminPrincipalId 'admin-id' -EnableOwnerAssignment 6>$null | Out-Null

        $script:EligibilityBodies[0].scheduleInfo.expiration.type | Should -Be 'afterDuration'
        $script:EligibilityBodies[0].scheduleInfo.expiration.duration | Should -Be 'P180D'
        Should -Invoke Invoke-EntraOpsMsGraphQuery -Times 1 -Exactly -ParameterFilter { $Uri -like "*roleManagementPolicyAssignments*scopeId eq 'id:SG-Rg-X-WorkloadPlane-Admins'*roleDefinitionId eq 'owner'*" }
    }

    It 'keeps a permanent owner eligibility when the owner policy allows it' {
        $groups = @([pscustomobject]@{ Id = 'id:SG-Rg-X-WorkloadPlane-Admins'; DisplayName = 'SG-Rg-X-WorkloadPlane-Admins' })
        $script:OwnerPolicyRules = @([pscustomobject]@{ id = 'Expiration_Admin_Eligibility'; isExpirationRequired = $false; maximumDuration = 'P365D' })

        New-EntraOpsServicePIMAssignment -ServiceGroups $groups -WorkloadPlaneAdminPrincipalId 'admin-id' -EnableOwnerAssignment 6>$null | Out-Null

        $script:EligibilityBodies[0].scheduleInfo.expiration.type | Should -Be 'noExpiration'
    }

    It 'skips groups where the workload plane admin is already eligible owner' {
        $groups = @('SG-Rg-X-WorkloadPlane-Users', 'SG-Rg-X-WorkloadPlane-Admins') | ForEach-Object { [pscustomobject]@{ Id = "id:$_"; DisplayName = $_ } }
        $script:ExistingSchedules = @([pscustomobject]@{ groupId = 'id:SG-Rg-X-WorkloadPlane-Admins'; principalId = 'admin-id'; accessId = 'owner' })

        $result = New-EntraOpsServicePIMAssignment -ServiceGroups $groups -WorkloadPlaneAdminPrincipalId 'admin-id' -EnableOwnerAssignment 6>$null

        @($script:EligibilityBodies.groupId) | Should -Be @('id:SG-Rg-X-WorkloadPlane-Users')
        @($result | Where-Object { $_.accessId -eq 'owner' -and $_.principalId -eq 'admin-id' }).Count | Should -Be 2
        Should -Invoke Invoke-EntraOpsMsGraphQuery -Times 0 -Exactly -ParameterFilter { $Method -eq 'GET' -and $Uri -like '*eligibilityScheduleRequests*' }
        Should -Invoke Invoke-EntraOpsMsGraphQuery -Times 1 -Exactly -ParameterFilter { $Method -eq 'POST' -and $ThrowOnFailure }
    }

    It 'creates eligible owner assignments only on the WorkloadPlane groups with EnableOwnerAssignment' {
        $groups = @('Rg-X Members', 'SG-Rg-X-WorkloadPlane-Users', 'SG-Rg-X-WorkloadPlane-Admins', 'SG-Rg-X-ControlPlane-Admins', 'SG-Rg-X-ManagementPlane-Admins') | ForEach-Object { [pscustomobject]@{ Id = "id:$_"; DisplayName = $_ } }
        $groups[0] | Add-Member -NotePropertyName GroupTypes -NotePropertyValue @('Unified')

        New-EntraOpsServicePIMAssignment -ServiceGroups $groups -WorkloadPlaneAdminPrincipalId 'admin-id' 6>$null | Out-Null
        $script:EligibilityBodies.Count | Should -Be 0

        New-EntraOpsServicePIMAssignment -ServiceGroups $groups -WorkloadPlaneAdminPrincipalId 'admin-id' -EnableOwnerAssignment 6>$null | Out-Null
        $script:EligibilityBodies.Count | Should -Be 2
        @($script:EligibilityBodies | Where-Object { $_.accessId -eq 'owner' -and $_.principalId -eq 'admin-id' }).Count | Should -Be 2
        @($script:EligibilityBodies | Where-Object { $_.accessId -eq 'member' }).Count | Should -Be 0
    }

    It 'processes the other groups and stops with one error when an eligible owner assignment fails' {
        $groups = @('SG-Rg-X-WorkloadPlane-Users', 'SG-Rg-X-WorkloadPlane-Admins') | ForEach-Object { [pscustomobject]@{ Id = "id:$_"; DisplayName = $_ } }
        Mock Invoke-EntraOpsMsGraphQuery -ParameterFilter { $Method -eq 'POST' -and ($Body | ConvertFrom-Json).groupId -eq 'id:SG-Rg-X-WorkloadPlane-Users' } { throw 'Graph 400 group not onboarded' }

        { New-EntraOpsServicePIMAssignment -ServiceGroups $groups -WorkloadPlaneAdminPrincipalId 'admin-id' -EnableOwnerAssignment -WarningAction SilentlyContinue 6>$null } |
        Should -Throw "*Failed to ensure 1 PIM for Groups eligible owner assignment(s)*SG-Rg-X-WorkloadPlane-Users*Graph 400 group not onboarded*"
        @($script:EligibilityBodies.groupId) | Should -Be @('id:SG-Rg-X-WorkloadPlane-Admins')
    }

    It 'stops with an error when the eligibility lookup fails' {
        $groups = @([pscustomobject]@{ Id = 'id:SG-Rg-X-WorkloadPlane-Admins'; DisplayName = 'SG-Rg-X-WorkloadPlane-Admins' })
        Mock Invoke-EntraOpsMsGraphQuery -ParameterFilter { $Method -eq 'GET' } { throw 'Graph 403' }

        { New-EntraOpsServicePIMAssignment -ServiceGroups $groups -WorkloadPlaneAdminPrincipalId 'admin-id' -EnableOwnerAssignment -WarningAction SilentlyContinue 6>$null } |
        Should -Throw "*lookup of 'SG-Rg-X-WorkloadPlane-Admins'*Graph 403*"
        $script:EligibilityBodies.Count | Should -Be 0
    }

    It 'requires the workload plane admin with EnableOwnerAssignment' {
        $groups = @([pscustomobject]@{ Id = 'id:SG-Rg-X-WorkloadPlane-Admins'; DisplayName = 'SG-Rg-X-WorkloadPlane-Admins' })

        { New-EntraOpsServicePIMAssignment -ServiceGroups $groups -EnableOwnerAssignment 6>$null } |
        Should -Throw '*-WorkloadPlaneAdminPrincipalId is required*'
        Should -Invoke Invoke-EntraOpsMsGraphQuery -Times 0 -Exactly
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

    It 'tags a new resource group with the service name' {
        $script:RgLookups = 0
        Mock Get-AzResourceGroup {
            $script:RgLookups++
            if ($script:RgLookups -eq 1) { throw 'Provided resource group does not exist.' }
            [pscustomobject]@{ ResourceId = '/subscriptions/sub1/resourceGroups/RG-X'; ResourceGroupName = 'RG-X' }
        }
        Mock Start-Sleep { $script:ServiceEMNow = $script:ServiceEMNow.AddSeconds($Seconds) }

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

    It 'assigns no Owner role' {
        New-EntraOpsServiceAZContainer -ServiceName 'Sub-X' -ServiceGroups $script:Groups -AzureScope Subscription -WarningAction SilentlyContinue 6>$null | Out-Null

        Should -Invoke New-AzRoleAssignment -Times 0 -Exactly -ParameterFilter { $RoleDefinitionName -eq 'Owner' }
    }

    It 'limits the ManagementPlane RBAC Administrator with a deny-list that applies to the single requested role' {
        $script:MgmtCondition = $null
        Mock New-AzRoleEligibilityScheduleRequest { if ($PrincipalId -eq 'id:SG-Sub-X-ManagementPlane-Admins' -and $Condition) { $script:MgmtCondition = $Condition } }
        $excluded = '8e3af657-a8ff-443c-a75c-2fe8c4bcb635, 18d7d88d-d35e-4fb5-a5c3-7773c20a72d9, f58310d9-a9f6-439a-9e8d-f62e7b41a168'

        New-EntraOpsServiceAZContainer -ServiceName 'Sub-X' -ServiceGroups $script:Groups -AzureScope Subscription -WarningAction SilentlyContinue 6>$null | Out-Null

        $script:MgmtCondition | Should -Not -BeNullOrEmpty
        $script:MgmtCondition | Should -Not -BeLike '*ForAllOfAnyValues*'
        foreach ($attribute in '@Request', '@Resource') {
            $script:MgmtCondition | Should -BeLike "*$attribute[[]Microsoft.Authorization/roleAssignments:RoleDefinitionId[]] ForAnyOfAllValues:GuidNotEquals {$excluded}*"
            $script:MgmtCondition | Should -BeLike "*$attribute[[]Microsoft.Authorization/roleAssignments:PrincipalId[]] ForAnyOfAnyValues:GuidEquals {id:SG-Sub-X-WorkloadPlane-Admins}*"
        }
    }

    Context 'existing eligible RBAC Administrator assignment of the same principal' {
        BeforeAll {
            $script:GuidGroups = @(
                [pscustomobject]@{ Id = 'aaaaaaaa-0000-0000-0000-000000000001'; DisplayName = 'SG-Sub-X-WorkloadPlane-Admins' }
                [pscustomobject]@{ Id = 'aaaaaaaa-0000-0000-0000-000000000002'; DisplayName = 'SG-Sub-X-ManagementPlane-Admins' }
            )
            $script:OldTargetId = 'bbbbbbbb-0000-0000-0000-000000000001'
            $script:NewTestCondition = {
                param($RoleOperator, $RoleIds, $TargetId)
                "((!(ActionMatches{'Microsoft.Authorization/roleAssignments/write'})) OR (@Request[Microsoft.Authorization/roleAssignments:RoleDefinitionId] $RoleOperator {$RoleIds} AND @Request[Microsoft.Authorization/roleAssignments:PrincipalId] ForAnyOfAnyValues:GuidEquals {$TargetId})) AND ((!(ActionMatches{'Microsoft.Authorization/roleAssignments/delete'})) OR (@Resource[Microsoft.Authorization/roleAssignments:RoleDefinitionId] $RoleOperator {$RoleIds} AND @Resource[Microsoft.Authorization/roleAssignments:PrincipalId] ForAnyOfAnyValues:GuidEquals {$TargetId}))"
            }
        }

        BeforeEach {
            Mock Start-Sleep { $script:ServiceEMNow = $script:ServiceEMNow.AddSeconds($Seconds) }
            $script:TargetGroupExists = $false
            $script:ExistingSchedules = @()
            Mock Get-AzRoleEligibilitySchedule { $script:ExistingSchedules }
            Mock New-AzRoleEligibilityScheduleRequest { if ($RequestType -eq 'AdminRemove') { $script:ExistingSchedules = @() } }
            Mock Invoke-EntraOpsMsGraphQuery {
                if ($script:TargetGroupExists) { return [pscustomobject]@{ Id = $script:OldTargetId } }
                $ex = [System.InvalidOperationException]::new('Graph 404')
                $ex.Data['StatusCode'] = 404
                throw $ex
            }
            $script:SetExisting = {
                param($Condition)
                $script:ExistingSchedules = @([pscustomobject]@{
                        RoleDefinitionDisplayName = 'Role Based Access Control Administrator'
                        RoleDefinitionId          = '/subscriptions/sub1/providers/Microsoft.Authorization/roleDefinitions/rd-Role Based Access Control Administrator'
                        PrincipalId               = 'aaaaaaaa-0000-0000-0000-000000000002'
                        Scope                     = '/subscriptions/sub1'
                        Condition                 = $Condition
                    })
            }
        }

        It 'removes a ServiceEM leftover whose target group no longer exists' {
            & $script:SetExisting (& $script:NewTestCondition 'ForAnyOfAllValues:GuidNotEquals' '8e3af657-a8ff-443c-a75c-2fe8c4bcb635' $script:OldTargetId)

            New-EntraOpsServiceAZContainer -ServiceName 'Sub-X' -ServiceGroups $script:GuidGroups -AzureScope Subscription -WarningAction SilentlyContinue 6>$null | Out-Null

            Should -Invoke Invoke-EntraOpsMsGraphQuery -Times 1 -Exactly -ParameterFilter { $Uri -like "/v1.0/groups/$($script:OldTargetId)*" -and $ThrowOnFailure }
            Should -Invoke New-AzRoleEligibilityScheduleRequest -Times 1 -Exactly -ParameterFilter { $RequestType -eq 'AdminRemove' -and $PrincipalId -eq 'aaaaaaaa-0000-0000-0000-000000000002' }
            Should -Invoke New-AzRoleEligibilityScheduleRequest -Times 1 -Exactly -ParameterFilter { $RequestType -eq 'AdminAssign' -and $PrincipalId -eq 'aaaaaaaa-0000-0000-0000-000000000002' -and $Condition -like '*aaaaaaaa-0000-0000-0000-000000000001*' }
        }

        It 'keeps a ServiceEM assignment whose target group still exists' {
            $script:TargetGroupExists = $true
            & $script:SetExisting (& $script:NewTestCondition 'ForAnyOfAllValues:GuidNotEquals' '8e3af657-a8ff-443c-a75c-2fe8c4bcb635' $script:OldTargetId)

            { New-EntraOpsServiceAZContainer -ServiceName 'Sub-X' -ServiceGroups $script:GuidGroups -AzureScope Subscription -WarningAction SilentlyContinue 6>$null | Out-Null } |
            Should -Throw "*constrained Role Based Access Control Administrator delegation wasn't assigned*aaaaaaaa-0000-0000-0000-000000000002*$($script:OldTargetId)*"

            Should -Invoke New-AzRoleEligibilityScheduleRequest -Times 0 -Exactly -ParameterFilter { $RequestType -eq 'AdminRemove' }
            Should -Invoke New-AzRoleEligibilityScheduleRequest -Times 0 -Exactly -ParameterFilter { $PrincipalId -eq 'aaaaaaaa-0000-0000-0000-000000000002' -and $Condition }
            Should -Invoke New-AzRoleEligibilityScheduleRequest -Times 1 -Exactly -ParameterFilter { $PrincipalId -eq 'aaaaaaaa-0000-0000-0000-000000000002' -and $RoleDefinitionId -like '*rd-Contributor' }
        }

        It 'keeps an assignment with a condition not created by ServiceEM' {
            & $script:SetExisting "((!(ActionMatches{'Microsoft.Authorization/roleAssignments/write'})) OR (@Request[Microsoft.Authorization/roleAssignments:RoleDefinitionId] ForAnyOfAnyValues:GuidEquals {acdd72a7-3385-48ef-bd42-f606fba81ae7}))"

            { New-EntraOpsServiceAZContainer -ServiceName 'Sub-X' -ServiceGroups $script:GuidGroups -AzureScope Subscription -WarningAction SilentlyContinue 6>$null | Out-Null } |
            Should -Throw "*delegation wasn't assigned*its condition wasn't created by ServiceEM*"

            Should -Invoke New-AzRoleEligibilityScheduleRequest -Times 0 -Exactly -ParameterFilter { $RequestType -eq 'AdminRemove' }
            Should -Invoke Invoke-EntraOpsMsGraphQuery -Times 0 -Exactly
        }

        It 'keeps an assignment without condition' {
            & $script:SetExisting $null

            { New-EntraOpsServiceAZContainer -ServiceName 'Sub-X' -ServiceGroups $script:GuidGroups -AzureScope Subscription -WarningAction SilentlyContinue 6>$null | Out-Null } |
            Should -Throw "*delegation wasn't assigned*"

            Should -Invoke New-AzRoleEligibilityScheduleRequest -Times 0 -Exactly -ParameterFilter { $RequestType -eq 'AdminRemove' }
        }
    }
}

Describe 'ServiceEM access package resource roles' {
    BeforeAll {
        . "$script:TestRepositoryRoot/EntraOps/Public/ServiceEM/New-EntraOpsServiceEMAccessPackageResourceAssignment.ps1"
    }

    It 'adds the Microsoft 365 group to every access package of the scope' {
        $script:RoleScopeBodies = [System.Collections.Generic.List[object]]::new()
        Mock Start-Sleep { $script:ServiceEMNow = $script:ServiceEMNow.AddSeconds($Seconds) }
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

    It 'adds the remaining resource roles and reports a failed one' {
        $script:RoleScopeBodies = [System.Collections.Generic.List[object]]::new()
        Mock Start-Sleep { $script:ServiceEMNow = $script:ServiceEMNow.AddSeconds($Seconds) }
        Mock Invoke-EntraOpsMsGraphQuery {
            if ($Method -eq 'POST') {
                if (-not $ThrowOnFailure) { throw 'POST without -ThrowOnFailure' }
                $body = $Body | ConvertFrom-Json -Depth 10
                if ($body.scope.originId -eq 'wu') { throw 'Graph 400 for wu' }
                $script:RoleScopeBodies.Add([pscustomobject]@{ Uri = $Uri; Body = $body })
                return [pscustomobject]@{ Id = [guid]::NewGuid().Guid }
            }
            if ($Uri -like '*/resourceRoles?*') {
                $resourceId = [regex]::Match($Uri, "resource/id eq '([^']+)'").Groups[1].Value
                return @([pscustomobject]@{ Id = "role-$resourceId"; DisplayName = 'Member'; OriginId = "Member_$resourceId" })
            }
            return @()
        }
        $groups = @(
            [pscustomobject]@{ Id = 'wu'; DisplayName = 'SG-Rg-X-WorkloadPlane-Users'; GroupTypes = @() }
            [pscustomobject]@{ Id = 'wa'; DisplayName = 'SG-Rg-X-WorkloadPlane-Admins'; GroupTypes = @() }
        )
        $resources = @($groups | ForEach-Object { [pscustomobject]@{ Id = "res-$($_.Id)"; DisplayName = $_.DisplayName; OriginSystem = 'AadGroup'; OriginId = $_.Id } })
        $packages = @('AP-Rg-X-WorkloadPlane-Users', 'AP-Rg-X-WorkloadPlane-Admins') | ForEach-Object { [pscustomobject]@{ Id = "ap:$_"; DisplayName = $_; ResourceRoleScopes = @() } }

        { New-EntraOpsServiceEMAccessPackageResourceAssignment -ServiceCatalogId 'cat' -ServiceName 'Rg-X' -ServiceGroups $groups -ServicePackages $packages -ServiceCatalogResources $resources 6>$null } |
        Should -Throw "*Failed to add 1 resource role(s)*Member of 'SG-Rg-X-WorkloadPlane-Users' in 'AP-Rg-X-WorkloadPlane-Users': Graph 400 for wu*"

        @($script:RoleScopeBodies.Body.scope.originId) | Should -Be @('wa')
    }

    It 'accepts further resource roles in the catalog packages and still waits for missing ones' {
        $script:RoleScopeBodies = [System.Collections.Generic.List[object]]::new()
        $script:DropCreated = $false
        Mock Start-Sleep { $script:ServiceEMNow = $script:ServiceEMNow.AddSeconds($Seconds) }
        Mock Invoke-EntraOpsMsGraphQuery {
            if ($Method -eq 'POST') {
                $script:RoleScopeBodies.Add(($Body | ConvertFrom-Json -Depth 10))
                return [pscustomobject]@{ Id = [guid]::NewGuid().Guid }
            }
            if ($Uri -like '*/resourceRoles?*') {
                $resourceId = [regex]::Match($Uri, "resource/id eq '([^']+)'").Groups[1].Value
                return @([pscustomobject]@{ Id = "role-$resourceId"; DisplayName = 'Member'; OriginId = "Member_$resourceId" })
            }
            if ($Uri -like '*/accessPackages?*') {
                $scopes = @(if (-not $script:DropCreated) { $script:RoleScopeBodies | ForEach-Object { [pscustomobject]@{ Role = [pscustomobject]@{ OriginId = $_.role.originId }; Scope = [pscustomobject]@{ OriginId = $_.scope.originId } } } })
                # Resource role of another access package in the catalog, e.g. added manually
                $scopes += [pscustomobject]@{ Role = [pscustomobject]@{ OriginId = 'Member_shared' }; Scope = [pscustomobject]@{ OriginId = 'shared' } }
                return @([pscustomobject]@{ ResourceRoleScopes = $scopes })
            }
            return @()
        }
        $groups = @([pscustomobject]@{ Id = 'wu'; DisplayName = 'SG-Rg-X-WorkloadPlane-Users'; GroupTypes = @() })
        $resources = @($groups | ForEach-Object { [pscustomobject]@{ Id = "res-$($_.Id)"; DisplayName = $_.DisplayName; OriginSystem = 'AadGroup'; OriginId = $_.Id } })
        $packages = @([pscustomobject]@{ Id = 'ap:AP-Rg-X-WorkloadPlane-Users'; DisplayName = 'AP-Rg-X-WorkloadPlane-Users'; ResourceRoleScopes = @() })

        New-EntraOpsServiceEMAccessPackageResourceAssignment -ServiceCatalogId 'cat' -ServiceName 'Rg-X' -ServiceGroups $groups -ServicePackages $packages -ServiceCatalogResources $resources 6>$null | Out-Null
        Should -Invoke Start-Sleep -Times 1 -Exactly

        $script:RoleScopeBodies.Clear()
        $script:DropCreated = $true
        { New-EntraOpsServiceEMAccessPackageResourceAssignment -ServiceCatalogId 'cat' -ServiceName 'Rg-X' -ServiceGroups $groups -ServicePackages $packages -ServiceCatalogResources $resources 6>$null } |
        Should -Throw '*Access Package role assignment consistency*'
    }

    Context 'eligible membership' {
        BeforeEach {
            $script:RoleScopeBodies = [System.Collections.Generic.List[object]]::new()
            $script:DeletedUris = [System.Collections.Generic.List[string]]::new()
            $script:OfferEligibleRole = $true
            Mock Start-Sleep { $script:ServiceEMNow = $script:ServiceEMNow.AddSeconds($Seconds) }
            Mock Invoke-EntraOpsMsGraphQuery {
                if ($Method -eq 'POST') {
                    $script:RoleScopeBodies.Add([pscustomobject]@{ Uri = $Uri; Body = ($Body | ConvertFrom-Json -Depth 10) })
                    return [pscustomobject]@{ Id = [guid]::NewGuid().Guid }
                }
                if ($Method -eq 'DELETE') { $script:DeletedUris.Add($Uri); return }
                if ($Uri -like '*/resourceRoles?*') {
                    $resourceId = [regex]::Match($Uri, "resource/id eq '([^']+)'").Groups[1].Value
                    $groupId = $resourceId -replace '^res-'
                    $roles = @([pscustomobject]@{ Id = "role-$resourceId"; DisplayName = 'Member'; OriginId = "Member_$groupId" })
                    if ($script:OfferEligibleRole) { $roles += [pscustomobject]@{ Id = "erole-$resourceId"; DisplayName = 'Eligible Member'; OriginId = "EligibleMember_$groupId" } }
                    return $roles
                }
                if ($Uri -like '*/accessPackages?*') {
                    $scopes = @($script:RoleScopeBodies | ForEach-Object { [pscustomobject]@{ Role = [pscustomobject]@{ OriginId = $_.Body.role.originId }; Scope = [pscustomobject]@{ OriginId = $_.Body.scope.originId } } })
                    return @([pscustomobject]@{ ResourceRoleScopes = $scopes })
                }
                return @()
            }
            $script:EligibleGroups = @(
                [pscustomobject]@{ Id = 'wa'; DisplayName = 'SG-Rg-X-WorkloadPlane-Admins'; GroupTypes = @() }
                [pscustomobject]@{ Id = 'ma'; DisplayName = 'SG-Rg-X-ManagementPlane-Admins'; GroupTypes = @() }
            )
            $script:EligibleResources = @($script:EligibleGroups | ForEach-Object { [pscustomobject]@{ Id = "res-$($_.Id)"; DisplayName = $_.DisplayName; OriginSystem = 'AadGroup'; OriginId = $_.Id } })
        }

        It 'delivers the Eligible Member role only for the groups managed by PIM for Groups' {
            $packages = @('AP-Rg-X-WorkloadPlane-Admins', 'AP-Rg-X-ManagementPlane-Admins') | ForEach-Object { [pscustomobject]@{ Id = "ap:$_"; DisplayName = $_; ResourceRoleScopes = @() } }

            New-EntraOpsServiceEMAccessPackageResourceAssignment -ServiceCatalogId 'cat' -ServiceName 'Rg-X' -ServiceGroups $script:EligibleGroups -ServicePackages $packages -ServiceCatalogResources $script:EligibleResources -EligibleMemberGroupIds @('ma') 6>$null | Out-Null

            ($script:RoleScopeBodies | Where-Object { $_.Body.scope.originId -eq 'ma' }).Body.role.originId | Should -Be 'EligibleMember_ma'
            ($script:RoleScopeBodies | Where-Object { $_.Body.scope.originId -eq 'wa' }).Body.role.originId | Should -Be 'Member_wa'
        }

        It 'replaces an active Member role from an earlier deployment with Eligible Member' {
            $existing = [pscustomobject]@{ Id = 'rrs-active'; Role = [pscustomobject]@{ OriginId = 'Member_ma' }; Scope = [pscustomobject]@{ OriginId = 'ma' } }
            $packages = @([pscustomobject]@{ Id = 'ap:mp'; DisplayName = 'AP-Rg-X-ManagementPlane-Admins'; ResourceRoleScopes = @($existing) })

            New-EntraOpsServiceEMAccessPackageResourceAssignment -ServiceCatalogId 'cat' -ServiceName 'Rg-X' -ServiceGroups @($script:EligibleGroups[1]) -ServicePackages $packages -ServiceCatalogResources $script:EligibleResources -EligibleMemberGroupIds @('ma') -WarningVariable warnings -WarningAction SilentlyContinue 6>$null | Out-Null

            $script:DeletedUris | Should -Be @('/v1.0/identityGovernance/entitlementManagement/accessPackages/ap:mp/resourceRoleScopes/rrs-active')
            $script:RoleScopeBodies.Body.role.originId | Should -Be 'EligibleMember_ma'
            @($warnings | Where-Object { "$_" -like '*Replacing the active Member role*' }).Count | Should -Be 1
        }

        It 'keeps the removed active Member role out of the consistency check when the Microsoft 365 group is processed (<Name>)' -ForEach @(
            @{ Name = 'Microsoft 365 group last'; Order = @('ma', 'm365') }
            @{ Name = 'Microsoft 365 group first'; Order = @('m365', 'ma') }
        ) {
            $all = @{
                ma   = $script:EligibleGroups[1]
                m365 = [pscustomobject]@{ Id = 'm365'; DisplayName = 'Rg-X Members'; GroupTypes = @('Unified') }
            }
            $groups = @($Order | ForEach-Object { $all[$_] })
            $resources = @($groups | ForEach-Object { [pscustomobject]@{ Id = "res-$($_.Id)"; DisplayName = $_.DisplayName; OriginSystem = 'AadGroup'; OriginId = $_.Id } })
            $existing = [pscustomobject]@{ Id = 'rrs-active'; Role = [pscustomobject]@{ OriginId = 'Member_ma' }; Scope = [pscustomobject]@{ OriginId = 'ma' } }
            $packages = @([pscustomobject]@{ Id = 'ap:mp'; DisplayName = 'AP-Rg-X-ManagementPlane-Admins'; ResourceRoleScopes = @($existing) })

            { New-EntraOpsServiceEMAccessPackageResourceAssignment -ServiceCatalogId 'cat' -ServiceName 'Rg-X' -ServiceGroups $groups -ServicePackages $packages -ServiceCatalogResources $resources -EligibleMemberGroupIds @('ma') -WarningAction SilentlyContinue 6>$null | Out-Null } | Should -Not -Throw

            ($script:RoleScopeBodies | Where-Object { $_.Body.scope.originId -eq 'ma' }).Body.role.originId | Should -Be 'EligibleMember_ma'
        }

        It 'does not add Eligible Member when the active Member role cannot be removed' {
            Mock Invoke-EntraOpsMsGraphQuery -ParameterFilter { $Method -eq 'DELETE' } -MockWith { throw 'Graph 500' }
            $existing = [pscustomobject]@{ Id = 'rrs-active'; Role = [pscustomobject]@{ OriginId = 'Member_ma' }; Scope = [pscustomobject]@{ OriginId = 'ma' } }
            $script:ExistingScope = $existing
            Mock Invoke-EntraOpsMsGraphQuery -ParameterFilter { $Method -eq 'GET' -and $Uri -like '*/accessPackages`?*' } -MockWith { @([pscustomobject]@{ ResourceRoleScopes = @($script:ExistingScope) }) }
            $packages = @([pscustomobject]@{ Id = 'ap:mp'; DisplayName = 'AP-Rg-X-ManagementPlane-Admins'; ResourceRoleScopes = @($existing) })

            New-EntraOpsServiceEMAccessPackageResourceAssignment -ServiceCatalogId 'cat' -ServiceName 'Rg-X' -ServiceGroups @($script:EligibleGroups[1]) -ServicePackages $packages -ServiceCatalogResources $script:EligibleResources -EligibleMemberGroupIds @('ma') -WarningVariable warnings -WarningAction SilentlyContinue 6>$null | Out-Null

            $script:RoleScopeBodies.Count | Should -Be 0
            @($warnings | Where-Object { "$_" -like '*Eligible Member is not added*' }).Count | Should -Be 1
        }

        It 'does not add the active Member role next to Eligible Member on a re-run without PIM for Groups' {
            # Otherwise every assignee would get standing membership and bypass the PIM activation
            $existing = [pscustomobject]@{ Id = 'rrs-eligible'; Role = [pscustomobject]@{ OriginId = 'EligibleMember_ma' }; Scope = [pscustomobject]@{ OriginId = 'ma' } }
            $script:ExistingScope = $existing
            Mock Invoke-EntraOpsMsGraphQuery -ParameterFilter { $Method -eq 'GET' -and $Uri -like '*/accessPackages`?*' } -MockWith { @([pscustomobject]@{ ResourceRoleScopes = @($script:ExistingScope) }) }
            $packages = @([pscustomobject]@{ Id = 'ap:mp'; DisplayName = 'AP-Rg-X-ManagementPlane-Admins'; ResourceRoleScopes = @($existing) })

            New-EntraOpsServiceEMAccessPackageResourceAssignment -ServiceCatalogId 'cat' -ServiceName 'Rg-X' -ServiceGroups @($script:EligibleGroups[1]) -ServicePackages $packages -ServiceCatalogResources $script:EligibleResources -WarningVariable warnings -WarningAction SilentlyContinue 6>$null | Out-Null

            $script:RoleScopeBodies.Count | Should -Be 0
            $script:DeletedUris.Count | Should -Be 0
            @($warnings | Where-Object { "$_" -like '*active Member role is not added*' }).Count | Should -Be 1
        }

        It 'reports a group whose catalog resource roles cannot be read instead of skipping it' {
            Mock Invoke-EntraOpsMsGraphQuery -ParameterFilter { $Uri -like '*/resourceRoles`?*' } -MockWith {
                if (-not $ThrowOnFailure) { return $null }
                throw 'Graph 503'
            }
            $packages = @([pscustomobject]@{ Id = 'ap:wa'; DisplayName = 'AP-Rg-X-WorkloadPlane-Admins'; ResourceRoleScopes = @() })

            { New-EntraOpsServiceEMAccessPackageResourceAssignment -ServiceCatalogId 'cat' -ServiceName 'Rg-X' -ServiceGroups @($script:EligibleGroups[0]) -ServicePackages $packages -ServiceCatalogResources $script:EligibleResources 6>$null } |
                Should -Throw "*catalog resource roles of 'SG-Rg-X-WorkloadPlane-Admins' could not be read: Graph 503*"
        }

        It 'matches the catalog resource of a group by object ID, not by display name' {
            # A catalog resource with the same name but another object ID (e.g. a renamed or foreign group) is not used
            $resources = @(
                [pscustomobject]@{ Id = 'res-other'; DisplayName = 'SG-Rg-X-WorkloadPlane-Admins'; OriginSystem = 'AadGroup'; OriginId = 'other' }
                [pscustomobject]@{ Id = 'res-wa'; DisplayName = 'SG-Old-Name'; OriginSystem = 'AadGroup'; OriginId = 'wa' }
            )
            $packages = @([pscustomobject]@{ Id = 'ap:wa'; DisplayName = 'AP-Rg-X-WorkloadPlane-Admins'; ResourceRoleScopes = @() })

            New-EntraOpsServiceEMAccessPackageResourceAssignment -ServiceCatalogId 'cat' -ServiceName 'Rg-X' -ServiceGroups @($script:EligibleGroups[0]) -ServicePackages $packages -ServiceCatalogResources $resources 6>$null | Out-Null

            $script:RoleScopeBodies.Body.role.resource.id | Should -Be 'res-wa'
        }

        It 'never falls back to the active Member role when Eligible Member is not offered' {
            $script:OfferEligibleRole = $false
            $packages = @([pscustomobject]@{ Id = 'ap:mp'; DisplayName = 'AP-Rg-X-ManagementPlane-Admins'; ResourceRoleScopes = @() })

            New-EntraOpsServiceEMAccessPackageResourceAssignment -ServiceCatalogId 'cat' -ServiceName 'Rg-X' -ServiceGroups @($script:EligibleGroups[1]) -ServicePackages $packages -ServiceCatalogResources $script:EligibleResources -EligibleMemberGroupIds @('ma') -WarningVariable warnings -WarningAction SilentlyContinue 6>$null | Out-Null

            $script:RoleScopeBodies.Count | Should -Be 0
            @($warnings | Where-Object { "$_" -like '*Eligible Member role not found*' }).Count | Should -Be 1
        }
    }
}

Describe 'ServiceEM catalog resource onboarding' {
    BeforeAll {
        . "$script:TestRepositoryRoot/EntraOps/Public/ServiceEM/New-EntraOpsServiceEMCatalogResource.ps1"
        $script:NewGraphError = {
            param($StatusCode, $ErrorCode)
            $ex = [System.InvalidOperationException]::new("Graph $StatusCode")
            $ex.Data['StatusCode'] = $StatusCode
            $ex.Data['ErrorCode'] = $ErrorCode
            $ex
        }
        $script:ResourceGroups = @([pscustomobject]@{ Id = 'g1'; DisplayName = 'SG-Rg-X-WorkloadPlane-Users' })
    }

    BeforeEach {
        Mock Start-Sleep { $script:ServiceEMNow = $script:ServiceEMNow.AddSeconds($Seconds) }
        $script:PostCalls = 0
        $script:PostErrors = @()
        Mock Invoke-EntraOpsMsGraphQuery {
            if ($Method -eq 'POST') {
                $script:PostCalls++
                if ($script:PostCalls -le $script:PostErrors.Count) { throw $script:PostErrors[$script:PostCalls - 1] }
                return [pscustomobject]@{ id = 'request' }
            }
            if ($script:PostCalls -gt 0) { return [pscustomobject]@{ Id = 'r1'; DisplayName = 'SG-Rg-X-WorkloadPlane-Users'; OriginSystem = 'AadGroup'; OriginId = 'g1' } }
            return @()
        }
    }

    It 'retries while the group is not indexed yet' {
        $script:PostErrors = @((& $script:NewGraphError 400 'ResourceNotFoundInOriginSystem'), (& $script:NewGraphError 400 'ResourceNotFoundInOriginSystem'))

        New-EntraOpsServiceEMCatalogResource -ServiceGroups $script:ResourceGroups -ServiceCatalogId 'cat' 6>$null | Out-Null

        $script:PostCalls | Should -Be 3
    }

    It 'treats an already onboarded group as success' {
        $script:PostErrors = @((& $script:NewGraphError 400 'ResourceAlreadyOnboarded'))

        New-EntraOpsServiceEMCatalogResource -ServiceGroups $script:ResourceGroups -ServiceCatalogId 'cat' 6>$null | Out-Null

        $script:PostCalls | Should -Be 1
    }

    It 'fails immediately on other errors' {
        $script:PostErrors = @((& $script:NewGraphError 403 'Authorization_RequestDenied'))

        { New-EntraOpsServiceEMCatalogResource -ServiceGroups $script:ResourceGroups -ServiceCatalogId 'cat' 6>$null } | Should -Throw '*Graph 403*'
        $script:PostCalls | Should -Be 1
    }

    It 'accepts further resources in the catalog, e.g. a Microsoft 365 group of an earlier run' {
        Mock Invoke-EntraOpsMsGraphQuery {
            if ($Method -eq 'POST') { throw 'Unexpected POST' }
            @([pscustomobject]@{ Id = 'r1'; DisplayName = 'SG-Rg-X-WorkloadPlane-Users'; OriginSystem = 'AadGroup'; OriginId = 'g1' }, [pscustomobject]@{ Id = 'r2'; DisplayName = 'Rg-X Members'; OriginSystem = 'AadGroup'; OriginId = 'g2' })
        }

        $result = New-EntraOpsServiceEMCatalogResource -ServiceGroups $script:ResourceGroups -ServiceCatalogId 'cat' 6>$null

        @($result).Count | Should -Be 2
        Should -Invoke Start-Sleep -Times 1 -Exactly
    }

    It 'still waits for a missing expected resource' {
        Mock Invoke-EntraOpsMsGraphQuery {
            if ($Method -eq 'POST') { return [pscustomobject]@{ id = 'request' } }
            @([pscustomobject]@{ Id = 'r2'; DisplayName = 'Rg-X Members'; OriginSystem = 'AadGroup'; OriginId = 'g2' })
        }

        { New-EntraOpsServiceEMCatalogResource -ServiceGroups $script:ResourceGroups -ServiceCatalogId 'cat' 6>$null } | Should -Throw '*Catalog Resource object consistency*'
    }

    It 'records the groups whose registration was accepted, including already registered ones' {
        $script:PostErrors = @((& $script:NewGraphError 400 'ResourceAlreadyOnboarded'))
        $registered = [System.Collections.Generic.List[string]]::new()

        New-EntraOpsServiceEMCatalogResource -ServiceGroups $script:ResourceGroups -ServiceCatalogId 'cat' -RegisteredGroupIds $registered 6>$null | Out-Null

        @($registered) | Should -Be @('g1')
    }

    It 'keeps polling the consistency check after a <StatusCode> lookup error' -ForEach @(
        @{ StatusCode = 503; ErrorCode = 'ServiceUnavailable' }
        @{ StatusCode = 404; ErrorCode = 'ResourceNotFound' }
    ) {
        $script:GetCalls = 0
        $script:PollError = (& $script:NewGraphError $StatusCode $ErrorCode)
        Mock Invoke-EntraOpsMsGraphQuery {
            if ($Method -eq 'POST') { return [pscustomobject]@{ id = 'request' } }
            $script:GetCalls++
            # 1: initial lookup (empty), 2: first consistency poll fails, 3: consistent
            if ($script:GetCalls -eq 2) { throw $script:PollError }
            if ($script:GetCalls -ge 3) { return @([pscustomobject]@{ Id = 'r1'; DisplayName = 'SG-Rg-X-WorkloadPlane-Users'; OriginSystem = 'AadGroup'; OriginId = 'g1' }) }
            return @()
        }

        $result = New-EntraOpsServiceEMCatalogResource -ServiceGroups $script:ResourceGroups -ServiceCatalogId 'cat' 6>$null

        @($result).Count | Should -Be 1
        $script:GetCalls | Should -Be 3
    }

    It 'reports a permission error of the consistency check at once instead of waiting' {
        $script:GetCalls = 0
        Mock Invoke-EntraOpsMsGraphQuery {
            if ($Method -eq 'POST') { return [pscustomobject]@{ id = 'request' } }
            $script:GetCalls++
            if ($script:GetCalls -ge 2) { throw (& $script:NewGraphError 403 'Authorization_RequestDenied') }
            return @()
        }

        { New-EntraOpsServiceEMCatalogResource -ServiceGroups $script:ResourceGroups -ServiceCatalogId 'cat' 6>$null } | Should -Throw 'Graph 403'
        $script:GetCalls | Should -Be 2
    }

    It 'includes the last lookup error when the consistency wait expires' {
        Mock Invoke-EntraOpsMsGraphQuery {
            if ($Method -eq 'POST') { return [pscustomobject]@{ id = 'request' } }
            if ($Uri -like '*resources*' -and $script:InitialLookupDone) { throw (& $script:NewGraphError 503 'ServiceUnavailable') }
            $script:InitialLookupDone = $true
            return @()
        }
        $script:InitialLookupDone = $false

        { New-EntraOpsServiceEMCatalogResource -ServiceGroups $script:ResourceGroups -ServiceCatalogId 'cat' 6>$null } |
        Should -Throw '*consistency with Entra not achieved. Last catalog resource lookup error: Graph 503*'
    }

    It 'fails the initial lookup instead of registering against an unknown catalog state' {
        Mock Invoke-EntraOpsMsGraphQuery {
            if ($Method -eq 'POST') { throw 'Unexpected POST' }
            throw (& $script:NewGraphError 403 'Authorization_RequestDenied')
        }

        { New-EntraOpsServiceEMCatalogResource -ServiceGroups $script:ResourceGroups -ServiceCatalogId 'cat' 6>$null } | Should -Throw '*Failed to look up catalog resources for cat*Graph 403*'
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
        Mock Start-Sleep { $script:ServiceEMNow = $script:ServiceEMNow.AddSeconds($Seconds) }

        New-EntraOpsServiceEMCatalog -ServiceName "Director's Service" | Out-Null

        $script:CatalogLookupUris.Count | Should -Be 2
        @($script:CatalogLookupUris | Where-Object { $_ -notmatch "displayName eq 'Catalog-Director%27%27s%20Service'" }) |
        Should -BeNullOrEmpty
    }

    It 'encodes an escaped OData literal in the delegation group name filter' {
        $script:GroupLookupUri = $null
        Mock Invoke-EntraOpsMsGraphQuery {
            $script:GroupLookupUri = $Uri
            return [pscustomobject]@{ Id = 'group-id'; DisplayName = "Tier 'Zero' Admins"; isAssignableToRole = $true; securityEnabled = $true }
        }
        Mock Save-EntraOpsServiceEMConfigKey {}

        $result = Resolve-EntraOpsServiceEMDelegationGroup -Plane ControlPlane -DefaultGroupName "Tier 'Zero' Admins" -ConfigKey ControlPlaneDelegationGroupId

        $result | Should -Be 'group-id'
        $script:GroupLookupUri | Should -BeLike "*displayName eq 'Tier%20%27%27Zero%27%27%20Admins'*"
        $script:GroupLookupUri | Should -Not -Match "Tier 'Zero'"
    }

    It 'rejects a non-GUID delegation group ID without any lookup or name-based fallback' {
        Mock Invoke-EntraOpsMsGraphQuery { [pscustomobject]@{ Id = 'group-id'; DisplayName = 'PRG-Tenant-ControlPlane-IdentityOps'; isAssignableToRole = $true; securityEnabled = $true } }
        Mock Save-EntraOpsServiceEMConfigKey {}

        { Resolve-EntraOpsServiceEMDelegationGroup -Plane ControlPlane -GroupId '../users' -DefaultGroupName 'PRG-Tenant-ControlPlane-IdentityOps' -ConfigKey ControlPlaneDelegationGroupId } |
        Should -Throw "*ControlPlane delegation group ID '../users'*is not a valid object ID*"
        Should -Invoke Invoke-EntraOpsMsGraphQuery -Times 0 -Exactly
        Should -Invoke Save-EntraOpsServiceEMConfigKey -Times 0 -Exactly
    }

    It 'rejects a configured delegation group ID that is not a role-assignable security group' {
        Mock Invoke-EntraOpsMsGraphQuery { [pscustomobject]@{ Id = '11111111-1111-1111-1111-111111111111'; DisplayName = 'Helpdesk'; isAssignableToRole = $false; securityEnabled = $true } }
        Mock Save-EntraOpsServiceEMConfigKey {}

        { Resolve-EntraOpsServiceEMDelegationGroup -Plane ControlPlane -GroupId '11111111-1111-1111-1111-111111111111' -DefaultGroupName 'PRG-Test' -ConfigKey ControlPlaneDelegationGroupId } |
        Should -Throw "*ControlPlane delegation group 'Helpdesk'*isn't a role-assignable security group*"
        Should -Invoke Save-EntraOpsServiceEMConfigKey -Times 0 -Exactly
    }

    It 'accepts a configured delegation group ID of a role-assignable security group' {
        Mock Invoke-EntraOpsMsGraphQuery { [pscustomobject]@{ Id = '11111111-1111-1111-1111-111111111111'; DisplayName = 'PRG-Test'; isAssignableToRole = $true; securityEnabled = $true } }

        Resolve-EntraOpsServiceEMDelegationGroup -Plane ControlPlane -GroupId '11111111-1111-1111-1111-111111111111' -DefaultGroupName 'PRG-Test' -ConfigKey ControlPlaneDelegationGroupId |
        Should -Be '11111111-1111-1111-1111-111111111111'
        Should -Invoke Invoke-EntraOpsMsGraphQuery -Times 1 -Exactly -ParameterFilter { $Uri -like '/v1.0/groups/11111111-1111-1111-1111-111111111111?*isAssignableToRole*' }
    }

    It 'ignores a same-named delegation group that is not a role-assignable security group' {
        $script:CreatedGroupBodies = [System.Collections.Generic.List[object]]::new()
        Mock Get-MgContext { [pscustomobject]@{ Scopes = @('RoleManagement.ReadWrite.Directory'); Account = 'admin@contoso.com' } }
        Mock Invoke-EntraOpsMsGraphQuery {
            if ($Method -eq 'POST') {
                $script:CreatedGroupBodies.Add(($Body | ConvertFrom-Json -Depth 5))
                return [pscustomobject]@{ Id = 'new-group-id' }
            }
            return [pscustomobject]@{ Id = 'lookalike-id'; DisplayName = 'PRG-Test'; isAssignableToRole = $false; securityEnabled = $true }
        }
        Mock Save-EntraOpsServiceEMConfigKey {}

        Resolve-EntraOpsServiceEMDelegationGroup -Plane ControlPlane -DefaultGroupName 'PRG-Test' -ConfigKey ControlPlaneDelegationGroupId -WarningAction SilentlyContinue | Should -Be 'new-group-id'

        Should -Invoke Save-EntraOpsServiceEMConfigKey -Times 1 -Exactly -ParameterFilter { $Value -eq 'new-group-id' }
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

    Context 'configured delegation group lookup failures' {
        BeforeAll {
            $script:ConfiguredId = '11111111-1111-1111-1111-111111111111'
            $script:NewStatusError = {
                param($StatusCode)
                $ex = [System.InvalidOperationException]::new("Graph $StatusCode")
                $ex.Data['StatusCode'] = $StatusCode
                $ex
            }
        }

        BeforeEach {
            $script:IdLookupStatus = 404
            $script:NameMatches = @()
            Mock Get-MgContext { [pscustomobject]@{ Scopes = @('RoleManagement.ReadWrite.Directory'); Account = 'admin@contoso.com' } }
            Mock Save-EntraOpsServiceEMConfigKey {}
            Mock Invoke-EntraOpsMsGraphQuery {
                if ($Method -eq 'POST') { return [pscustomobject]@{ Id = 'new-group-id' } }
                if ($Uri -like "/v1.0/groups/$($script:ConfiguredId)*") { throw (& $script:NewStatusError $script:IdLookupStatus) }
                if ($script:NameMatches -eq 'fail') { throw (& $script:NewStatusError 503) }
                return $script:NameMatches
            }
        }

        It 'stops on errors other than not found without falling back to the name lookup' {
            $script:IdLookupStatus = 403

            { Resolve-EntraOpsServiceEMDelegationGroup -Plane ManagementPlane -GroupId $script:ConfiguredId -DefaultGroupName 'PRG-Test' -ConfigKey ManagementPlaneDelegationGroupId } |
            Should -Throw "*Failed to look up the ManagementPlane delegation group '$($script:ConfiguredId)'*Graph 403*"

            Should -Invoke Invoke-EntraOpsMsGraphQuery -Times 1 -Exactly
            Should -Invoke Save-EntraOpsServiceEMConfigKey -Times 0 -Exactly
        }

        It 'does not create a group or overwrite the configured ID when the configured group was not found' {
            { Resolve-EntraOpsServiceEMDelegationGroup -Plane ManagementPlane -GroupId $script:ConfiguredId -DefaultGroupName 'PRG-Test' -ConfigKey ManagementPlaneDelegationGroupId -WarningAction SilentlyContinue } |
            Should -Throw "*delegation group '$($script:ConfiguredId)'*was not found*No new group is created*"

            Should -Invoke Invoke-EntraOpsMsGraphQuery -Times 0 -Exactly -ParameterFilter { $Method -eq 'POST' }
            Should -Invoke Save-EntraOpsServiceEMConfigKey -Times 0 -Exactly
        }

        It 'uses a single role-assignable group with the default name without overwriting the configured ID' {
            $script:NameMatches = @([pscustomobject]@{ Id = 'named-id'; DisplayName = 'PRG-Test'; isAssignableToRole = $true; securityEnabled = $true })

            Resolve-EntraOpsServiceEMDelegationGroup -Plane ManagementPlane -GroupId $script:ConfiguredId -DefaultGroupName 'PRG-Test' -ConfigKey ManagementPlaneDelegationGroupId -WarningVariable warnings -WarningAction SilentlyContinue |
            Should -Be 'named-id'

            Should -Invoke Save-EntraOpsServiceEMConfigKey -Times 0 -Exactly
            @($warnings | Where-Object { "$_" -like '*Update ServiceEM.ManagementPlaneDelegationGroupId*' }).Count | Should -Be 1
        }

        It 'stops when more than one role-assignable group has the default name' {
            $script:NameMatches = @('a-id', 'b-id') | ForEach-Object { [pscustomobject]@{ Id = $_; DisplayName = 'PRG-Test'; isAssignableToRole = $true; securityEnabled = $true } }

            { Resolve-EntraOpsServiceEMDelegationGroup -Plane ControlPlane -DefaultGroupName 'PRG-Test' -ConfigKey ControlPlaneDelegationGroupId } |
            Should -Throw '*Found 2 role-assignable groups named*a-id, b-id*'

            Should -Invoke Invoke-EntraOpsMsGraphQuery -Times 0 -Exactly -ParameterFilter { $Method -eq 'POST' }
            Should -Invoke Save-EntraOpsServiceEMConfigKey -Times 0 -Exactly
        }

        It 'stops when the name lookup fails instead of creating a group' {
            $script:NameMatches = 'fail'

            { Resolve-EntraOpsServiceEMDelegationGroup -Plane ControlPlane -DefaultGroupName 'PRG-Test' -ConfigKey ControlPlaneDelegationGroupId } |
            Should -Throw "*Failed to look up the ControlPlane delegation group by name 'PRG-Test'*"

            Should -Invoke Invoke-EntraOpsMsGraphQuery -Times 0 -Exactly -ParameterFilter { $Method -eq 'POST' }
        }
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
        Mock Start-Sleep { $script:ServiceEMNow = $script:ServiceEMNow.AddSeconds($Seconds) }
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

    It 'uses the admin groups of the scope as reviewers' {
        $groups = @('Sub-X Members', 'SG-Sub-X-CatalogPlane-Members', 'SG-Sub-X-ControlPlane-Admins', 'SG-Sub-X-ManagementPlane-Admins') |
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

    It 'creates a missing main policy on re-run although the initial policy of the package exists' {
        $groups = @('SG-Rg-X-CatalogPlane-Members', 'SG-Rg-X-WorkloadPlane-Admins', 'SG-Rg-X-ManagementPlane-Admins') | ForEach-Object { New-TestGroup $_ }
        $package = New-TestPackage 'AP-Rg-X-WorkloadPlane-Users'
        # First run: the main policy failed, the initial direct-assignment policy was created
        $script:CreatedPolicies.Add([pscustomobject]@{ id = 'initial'; displayName = 'Initial Workload Users Policy'; accessPackage = [pscustomobject]@{ id = $package.Id } })

        New-EntraOpsServiceEMAssignmentPolicy -ServiceName 'Rg-X' -ServiceCatalogId 'cat' -ServiceGroups $groups -ServicePackages @($package) | Out-Null

        @($script:PolicyBodies.displayName) | Should -Be @('Workload Plane Users Policy')
    }

    It 'stops before creating any policy when the existing policies cannot be read' {
        Mock Invoke-EntraOpsMsGraphQuery -ParameterFilter { $Method -eq 'GET' } -MockWith {
            if (-not $ThrowOnFailure) { return $null }
            throw 'Graph 503'
        }
        $groups = @('SG-Rg-X-CatalogPlane-Members', 'SG-Rg-X-ManagementPlane-Admins') | ForEach-Object { New-TestGroup $_ }

        { New-EntraOpsServiceEMAssignmentPolicy -ServiceName 'Rg-X' -ServiceCatalogId 'cat' -ServiceGroups $groups -ServicePackages @(New-TestPackage 'AP-Rg-X-CatalogPlane-Members') } |
            Should -Throw '*Failed to look up the assignment policies*no policy was created*Graph 503*'
        $script:PolicyBodies.Count | Should -Be 0
    }

    It 'uses the WorkloadPlane-Admins group as approver of the initial membership without CatalogPlane group' {
        # Custom roles example of New-EntraOpsServiceBootstrap: no CatalogPlane-Members group
        $groups = @('SG-Rg-X-WorkloadPlane-Members', 'SG-Rg-X-WorkloadPlane-Admins', 'SG-Rg-X-ManagementPlane-Admins') | ForEach-Object { New-TestGroup $_ }

        New-EntraOpsServiceEMAssignmentPolicy -ServiceName 'Rg-X' -ServiceCatalogId 'cat' -ServiceGroups $groups -ServicePackages @(New-TestPackage 'AP-Rg-X-WorkloadPlane-Members') -WarningAction SilentlyContinue | Out-Null

        $membershipPolicy = $script:PolicyBodies | Where-Object displayName -EQ 'Initial Workload Membership Policy'
        $membershipPolicy.requestApprovalSettings.stages[0].fallbackPrimaryApprovers.groupId | Should -Be 'id:SG-Rg-X-WorkloadPlane-Admins'
        $membershipPolicy.requestApprovalSettings.stages[1].primaryApprovers.groupId | Should -Be 'id:SG-Rg-X-WorkloadPlane-Admins'
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

        It 'uses a delegated ControlPlane-Admins group as approver' {
            $groups = @('SG-Rg-X-CatalogPlane-Members', 'SG-Rg-X-ManagementPlane-Admins') | ForEach-Object { New-TestGroup $_ }
            $packages = @('AP-Rg-X-ManagementPlane-Admins') | ForEach-Object { New-TestPackage $_ }

            New-EntraOpsServiceEMAssignmentPolicy -ServiceName 'Rg-X' -ServiceCatalogId 'cat' -ServiceGroups $groups -ServicePackages $packages -WarningAction SilentlyContinue | Out-Null
            @($script:PolicyBodies | Where-Object displayName -EQ 'Management Plane Policy').Count | Should -Be 0

            $delegated = [pscustomobject]@{ Id = 'gov-cp'; DisplayName = 'SG-Rg-X-ControlPlane-Admins'; IsDelegated = $true }
            New-EntraOpsServiceEMAssignmentPolicy -ServiceName 'Rg-X' -ServiceCatalogId 'cat' -ServiceGroups (@($groups) + $delegated) -ServicePackages $packages | Out-Null
            ($script:PolicyBodies | Where-Object displayName -EQ 'Management Plane Policy').requestApprovalSettings.stages[0].primaryApprovers.groupId | Should -Be 'gov-cp'
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

    It 'uses a delegated ManagementPlane-Admins group as approver and reviewer' {
        $groups = @('SG-Rg-X-CatalogPlane-Members', 'SG-Rg-X-WorkloadPlane-Users', 'SG-Rg-X-WorkloadPlane-Admins') |
        ForEach-Object { New-TestGroup $_ }
        $groups += [pscustomobject]@{ Id = 'gov-mp'; DisplayName = 'SG-Rg-X-ManagementPlane-Admins'; IsDelegated = $true }
        $packages = @('AP-Rg-X-WorkloadPlane-Admins') | ForEach-Object { New-TestPackage $_ }

        New-EntraOpsServiceEMAssignmentPolicy -ServiceName 'Rg-X' -ServiceCatalogId 'cat' -ServiceGroups $groups -ServicePackages $packages | Out-Null

        foreach ($name in 'Workload Plane Policy') {
            $policy = $script:PolicyBodies | Where-Object displayName -EQ $name
            $policy.requestApprovalSettings.stages.primaryApprovers.groupId | Should -Be 'gov-mp'
            $policy.reviewSettings.primaryReviewers.groupId | Should -Be 'gov-mp'
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

        It 'falls back to a higher tier reviewer only, never to CatalogPlane-Members' {
            $groups = @('SG-Rg-X-CatalogPlane-Members', 'SG-Rg-X-WorkloadPlane-Users', 'SG-Rg-X-ControlPlane-Admins') | ForEach-Object { New-TestGroup $_ }
            $packages = @('AP-Rg-X-WorkloadPlane-Users', 'AP-Rg-X-CatalogPlane-Members') | ForEach-Object { New-TestPackage $_ }

            New-EntraOpsServiceEMAssignmentPolicy -ServiceName 'Rg-X' -ServiceCatalogId 'cat' -ServiceGroups $groups -ServicePackages $packages -WarningAction SilentlyContinue | Out-Null

            ($script:PolicyBodies | Where-Object displayName -EQ 'Initial Workload Users Policy').reviewSettings.primaryReviewers.groupId |
            Should -Be 'id:SG-Rg-X-ControlPlane-Admins' -Because 'WorkloadPlane-Admins and ManagementPlane-Admins are missing'
            @($script:PolicyBodies.reviewSettings.primaryReviewers.groupId) | Should -Not -Contain 'id:SG-Rg-X-CatalogPlane-Members'
        }

        It 'creates the policy without access review when no reviewer of the same or a higher tier exists' {
            $groups = @('SG-Rg-X-CatalogPlane-Members', 'SG-Rg-X-WorkloadPlane-Users') | ForEach-Object { New-TestGroup $_ }
            $packages = @('AP-Rg-X-CatalogPlane-Members') | ForEach-Object { New-TestPackage $_ }

            New-EntraOpsServiceEMAssignmentPolicy -ServiceName 'Rg-X' -ServiceCatalogId 'cat' -ServiceGroups $groups -ServicePackages $packages -WarningVariable warnings -WarningAction SilentlyContinue | Out-Null

            $policy = $script:PolicyBodies | Where-Object displayName -EQ 'Initial Catalog Members Policy'
            $policy.PSObject.Properties.Name | Should -Not -Contain 'reviewSettings'
            @($warnings | Where-Object { "$_" -like "*'Initial Catalog Members Policy' is created without access review*" }).Count | Should -Be 1
        }

        It 'applies group, self-review, specific reviewers and manager from ServiceEM.AccessReviews.Policies' {
            $Global:EntraOpsConfig = @{ ServiceEM = @{ AccessReviews = @{ Policies = @{
                            WorkloadPlaneUsers    = @{ ReviewerType = 'SelfReview' }
                            InitialWorkloadUsers  = @{ ReviewerType = 'Manager' }
                            WorkloadPlaneAdmins   = @{ ReviewerType = 'SpecificReviewers'; Reviewers = @('11111111-1111-1111-1111-111111111111', 'admin@contoso.com') }
                            InitialWorkloadAdmins = @{ ReviewerType = 'Group'; Reviewers = @('22222222-2222-2222-2222-222222222222', 'CatalogPlane-Members') }
                        } 
                    } 
                } 
            }

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
                    } 
                } 
            }
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
                    } 
                } 
            }

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

        It 'restricts the Initial Workload Admin Policy to the workload plane admin when no ManagementPlane-Admins package exists' {
            New-EntraOpsServiceEMAssignmentPolicy -ServiceName 'Rg-X' -ServiceCatalogId 'cat' -ServiceGroups $script:WpGroups -ServicePackages $script:WpPackages -WorkloadPlaneAdminId 'admin-id' | Out-Null

            $adminPolicy = $script:PolicyBodies | Where-Object displayName -EQ 'Initial Workload Admin Policy'
            $adminPolicy.allowedTargetScope | Should -Be 'specificDirectoryUsers'
            $adminPolicy.specificAllowedTargets.'@odata.type' | Should -Be '#microsoft.graph.singleUser'
            $adminPolicy.specificAllowedTargets.userId | Should -Be 'admin-id'
            ($script:PolicyBodies | Where-Object displayName -EQ 'Initial Workload Users Policy').allowedTargetScope | Should -Be 'allMemberUsers'
        }

        It 'restricts only the Initial Management Admin Policy when a ManagementPlane-Admins package exists' {
            $groups = @($script:WpGroups) + (New-TestGroup 'SG-Rg-X-ControlPlane-Admins') + (New-TestGroup 'SG-Rg-X-CatalogPlane-Members')
            $packages = @($script:WpPackages) + (New-TestPackage 'AP-Rg-X-ManagementPlane-Admins')

            New-EntraOpsServiceEMAssignmentPolicy -ServiceName 'Rg-X' -ServiceCatalogId 'cat' -ServiceGroups $groups -ServicePackages $packages -WorkloadPlaneAdminId 'admin-id' | Out-Null

            $mgmtPolicy = $script:PolicyBodies | Where-Object displayName -EQ 'Initial Management Admin Policy'
            $mgmtPolicy.allowedTargetScope | Should -Be 'specificDirectoryUsers'
            $mgmtPolicy.specificAllowedTargets.userId | Should -Be 'admin-id'
            ($script:PolicyBodies | Where-Object displayName -EQ 'Initial Workload Admin Policy').allowedTargetScope | Should -Be 'allMemberUsers'
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
                $nickname = @{ 'own' = 'Rg-MyApp.WorkloadPlane.Users'; 'pim' = 'PIM.Rg-MyApp.ManagementPlane.Admins'; 'foreign' = 'Shared.Admins' }[$id]
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

    It 'reports Azure cleanup needs attention when Azure deletion produces a <FailureMode>' -TestCases @(
        @{ FailureMode = 'terminating error' }, @{ FailureMode = 'nonterminating error' }
    ) {
        param($FailureMode)
        $script:AzureFailureMode = $FailureMode
        Mock Get-AzRoleEligibilitySchedule { @() }
        Mock Remove-AzResourceGroup {
            if ($script:AzureFailureMode -eq 'terminating error') { throw 'Azure deletion denied' }
            Write-Error 'Azure deletion denied'
        }

        $result = Remove-EntraOpsServiceCatalog -ServiceCatalogName 'Catalog-Rg-MyApp' -Force -RemoveAzureResourceGroup -SubscriptionId $script:TargetSub -ErrorAction SilentlyContinue -InformationVariable feedback 6>$null

        $result | Should -BeOfType [hashtable]
        ($feedback.MessageData -join ' ') | Should -BeLike '*Azure cleanup needs attention*'
        ($feedback.MessageData -join ' ') | Should -Not -BeLike "*Azure resource group 'RG-MyApp' deleted*"
        Should -Invoke Remove-AzResourceGroup -Times 1 -Exactly -ParameterFilter { $ErrorAction -eq 'Stop' }
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
        $script:DeletedUris | Should -Not -Contain '/v1.0/groups/pim'
        $script:DeletedUris | Should -Not -Contain '/v1.0/groups/foreign'
        @($warnings | Where-Object { "$_" -like "*Keeping group foreign*" }).Count | Should -Be 1
    }

    It 'does not remove the Rg scope resource group when removing the Sub scope catalog' {
        Remove-EntraOpsServiceCatalog -ServiceCatalogName 'Catalog-Sub-MyApp' -Force -RemoveAzureResourceGroup -SubscriptionId $script:TargetSub -WarningAction SilentlyContinue | Out-Null

        Should -Invoke Remove-AzResourceGroup -Times 0 -Exactly
    }

    It 'deletes the other groups, keeps the catalog and reports all failures when a group deletion fails' {
        $Global:EntraOpsConfig = @{ ServiceEM = @{ UpdateObjectClassificationFile = $true } }
        Mock Update-EntraOpsServiceEMObjectClassificationFile {}
        $script:FailingGroups = @('own2')
        Mock Invoke-EntraOpsMsGraphQuery {
            if ($Method -eq 'DELETE') {
                $id = ($Uri -split '/')[-1]
                if ($id -in $script:FailingGroups) { throw "Graph 403 for $id" }
                $script:DeletedUris.Add($Uri); return
            }
            if ($Uri -like '/v1.0/groups/*') {
                $id = ($Uri -split '/|\?')[3]
                return [pscustomobject]@{ Id = $id; MailNickname = "Rg-MyApp.$id" }
            }
            return [pscustomobject]@{ Id = 'catalog-id'; accessPackages = @(); Resources = $script:CatalogResources }
        }
        $script:CatalogResources = @('own1', 'own2', 'own3') | ForEach-Object { [pscustomobject]@{ OriginSystem = 'AadGroup'; OriginId = $_; DisplayName = $_ } }

        try {
            { Remove-EntraOpsServiceCatalog -ServiceCatalogName 'Catalog-Rg-MyApp' -Force -RemoveAzureResourceGroup -SubscriptionId $script:TargetSub -WarningAction SilentlyContinue } |
            Should -Throw '*incomplete*deleting group own2 [[]own2[]] failed: Graph 403 for own2*'

            $script:DeletedUris | Should -Contain '/v1.0/groups/own1'
            $script:DeletedUris | Should -Contain '/v1.0/groups/own3'
            $script:DeletedUris | Should -Not -Contain '/v1.0/identityGovernance/entitlementManagement/catalogs/catalog-id'
            Should -Invoke Update-EntraOpsServiceEMObjectClassificationFile -Times 1 -Exactly -ParameterFilter { ($RemoveObjectIds -join ',') -eq 'own1,own3' }
            Should -Invoke Remove-AzResourceGroup -Times 1 -Exactly

            # A re-run finds the catalog and finishes the removal
            $script:FailingGroups = @()
            Remove-EntraOpsServiceCatalog -ServiceCatalogName 'Catalog-Rg-MyApp' -Force -WarningAction SilentlyContinue | Out-Null
            $script:DeletedUris | Should -Contain '/v1.0/groups/own2'
            $script:DeletedUris | Should -Contain '/v1.0/identityGovernance/entitlementManagement/catalogs/catalog-id'
        } finally {
            $Global:EntraOpsConfig = $null
        }
    }

    It 'keeps the catalog when a group lookup fails with an error other than not found' {
        Mock Invoke-EntraOpsMsGraphQuery {
            if ($Method -eq 'DELETE') { $script:DeletedUris.Add($Uri); return }
            if ($Uri -like '/v1.0/groups/*') {
                $ex = [System.InvalidOperationException]::new('Graph 503')
                $ex.Data['StatusCode'] = 503
                throw $ex
            }
            return [pscustomobject]@{ Id = 'catalog-id'; accessPackages = @(); Resources = $script:CatalogResources }
        }
        $script:CatalogResources = @('own') | ForEach-Object { [pscustomobject]@{ OriginSystem = 'AadGroup'; OriginId = $_; DisplayName = $_ } }

        { Remove-EntraOpsServiceCatalog -ServiceCatalogName 'Catalog-Rg-MyApp' -Force -WarningAction SilentlyContinue } | Should -Throw '*lookup of group own*Graph 503*'

        $script:DeletedUris.Count | Should -Be 0
    }

    It 'skips groups that no longer exist and deletes the catalog' {
        Mock Invoke-EntraOpsMsGraphQuery {
            if ($Method -eq 'DELETE') { $script:DeletedUris.Add($Uri); return }
            if ($Uri -like '/v1.0/groups/*') {
                $ex = [System.InvalidOperationException]::new('Graph 404')
                $ex.Data['StatusCode'] = 404
                throw $ex
            }
            return [pscustomobject]@{ Id = 'catalog-id'; accessPackages = @(); Resources = $script:CatalogResources }
        }
        $script:CatalogResources = @('gone') | ForEach-Object { [pscustomobject]@{ OriginSystem = 'AadGroup'; OriginId = $_; DisplayName = $_ } }

        Remove-EntraOpsServiceCatalog -ServiceCatalogName 'Catalog-Rg-MyApp' -Force -WarningAction SilentlyContinue | Out-Null

        @($script:DeletedUris) | Should -Be @('/v1.0/identityGovernance/entitlementManagement/catalogs/catalog-id')
    }

    It 'deletes nothing with WhatIf' {
        $script:CatalogResources = @('own') | ForEach-Object { [pscustomobject]@{ OriginSystem = 'AadGroup'; OriginId = $_; DisplayName = $_ } }

        Remove-EntraOpsServiceCatalog -ServiceCatalogName 'Catalog-Rg-MyApp' -RemoveAzureResourceGroup -SubscriptionId $script:TargetSub -WhatIf | Out-Null

        $script:DeletedUris.Count | Should -Be 0
        Should -Invoke Remove-AzResourceGroup -Times 0 -Exactly
        Should -Invoke Set-AzContext -Times 0 -Exactly
    }
}

Describe 'ServiceEM workload group classification' {
    BeforeEach {
        Mock Start-Sleep { $script:ServiceEMNow = $script:ServiceEMNow.AddSeconds($Seconds) }
        $script:AuPosts = [System.Collections.Generic.List[string]]::new()
        $script:AuRestricted = $false
        Mock Invoke-EntraOpsMsGraphQuery {
            if ($Method -eq 'GET') { return [pscustomobject]@{ id = ($Uri -split '/|\?')[3]; displayName = 'AU'; isMemberManagementRestricted = $script:AuRestricted } }
            if ($Method -eq 'POST') { $script:AuPosts.Add("$(($Uri -split '/')[3])|$(($Body | ConvertFrom-Json).'@odata.id' -replace '.*/')") }
        }
        $script:WorkloadGroups = @(
            [pscustomobject]@{ Id = 'wa'; DisplayName = 'SG-Rg-X-WorkloadPlane-Admins'; MailNickname = 'Rg-X.WorkloadPlane.Admins'; IsAssignableToRole = $true }
            [pscustomobject]@{ Id = 'wu'; DisplayName = 'SG-Rg-X-WorkloadPlane-Users'; MailNickname = 'Rg-X.WorkloadPlane.Users'; IsAssignableToRole = $false }
            [pscustomobject]@{ Id = 'ca'; DisplayName = 'SG-Rg-X-ControlPlane-Admins'; MailNickname = 'Rg-X.ControlPlane.Admins'; IsAssignableToRole = $true }
            [pscustomobject]@{ Id = 'ma'; DisplayName = 'SG-Rg-X-ManagementPlane-Admins'; IsDelegated = $true }
        )
        $script:AuWorkload = '11111111-1111-1111-1111-111111111111'
        $script:AuUsers = '22222222-2222-2222-2222-222222222222'
    }

    AfterEach {
        $Global:EntraOpsConfig = $null
    }

    It 'adds only WorkloadPlane-Admins and WorkloadPlane-Users to the configured administrative units' {
        $Global:EntraOpsConfig = @{ ServiceEM = @{ AdministrativeUnits = @{ WorkloadPlane = $script:AuWorkload; UserAccess = $script:AuUsers } } }

        $result = Set-EntraOpsServiceEMWorkloadClassification -ServiceGroups $script:WorkloadGroups -ServiceName 'Rg-X' 6>$null

        @($script:AuPosts | Sort-Object) | Should -Be @("$($script:AuWorkload)|wa", "$($script:AuUsers)|wu")
        ($result | Where-Object Id -EQ 'wu').AdminTierLevelName | Should -Be 'UserAccess'
    }

    It 'warns and skips role-assignable or PIM-managed groups for a restricted management administrative unit' {
        $Global:EntraOpsConfig = @{ ServiceEM = @{ AdministrativeUnits = @{ WorkloadPlane = $script:AuWorkload; UserAccess = $script:AuUsers } } }
        $script:AuRestricted = $true

        Set-EntraOpsServiceEMWorkloadClassification -ServiceGroups $script:WorkloadGroups -ServiceName 'Rg-X' -WarningVariable warnings -WarningAction SilentlyContinue 6>$null | Out-Null

        $script:AuPosts | Should -Be @("$($script:AuUsers)|wu")
        @($warnings | Where-Object { "$_" -like '*restricted management administrative unit*role-assignable*' }).Count | Should -Be 1
    }

    It 'writes new entries to the Object Classification File and keeps existing entries' {
        $EntraOpsBaseFolder = $TestDrive
        $Global:EntraOpsConfig = @{ ServiceEM = @{ UpdateObjectClassificationFile = $true }; ObjectClassificationFile = @{ Enabled = $true; FilePath = './Classification/ObjectClassification.json' } }
        $groups = @($script:WorkloadGroups | ForEach-Object { $_.PSObject.Copy() })
        $groups[0].Id = '33333333-3333-3333-3333-333333333333'
        $groups[1].Id = '44444444-4444-4444-4444-444444444444'
        $filePath = Join-Path $TestDrive 'Classification/ObjectClassification.json'
        New-Item -ItemType Directory -Path (Split-Path $filePath) -Force | Out-Null
        ConvertTo-Json -InputObject @([pscustomobject]@{ ObjectId = $groups[1].Id; ObjectType = 'group'; AdminTierLevelName = 'WorkloadPlane' }) | Set-Content $filePath

        $warnings = @(Set-EntraOpsServiceEMWorkloadClassification -ServiceGroups $groups -ServiceName 'Rg-X' 3>&1 6>$null | Where-Object { $_ -is [System.Management.Automation.WarningRecord] })

        $entries = Get-Content $filePath -Raw | ConvertFrom-Json
        ($entries | Where-Object ObjectId -EQ $groups[0].Id).AdminTierLevelName | Should -Be 'WorkloadPlane'
        ($entries | Where-Object ObjectId -EQ $groups[1].Id).AdminTierLevelName | Should -Be 'WorkloadPlane'
        @($entries).Count | Should -Be 2
        @($warnings | Where-Object { "$_" -like '*already lists*kept*' }).Count | Should -Be 1
        $script:AuPosts.Count | Should -Be 0

        Update-EntraOpsServiceEMObjectClassificationFile -RemoveObjectIds @($groups[0].Id) | Out-Null
        @(Get-Content $filePath -Raw | ConvertFrom-Json).ObjectId | Should -Be @($groups[1].Id)
    }
}

Describe 'ServiceEM catalog removal with open assignment requests' {
    BeforeEach {
        Mock Start-Sleep { $script:ServiceEMNow = $script:ServiceEMNow.AddSeconds($Seconds) }
        $script:DeletedUris = [System.Collections.Generic.List[string]]::new()
        $script:PostedUris = [System.Collections.Generic.List[string]]::new()
        $script:OpenRequest = [pscustomobject]@{ id = 'open-req'; requestType = 'userAdd'; state = 'pendingApproval'; status = 'PendingApproval' }
        $script:AdminRemoveFails = $false
        $script:AssignmentRemoved = $false
        Mock Invoke-EntraOpsMsGraphQuery {
            if ($Method -eq 'DELETE') { $script:DeletedUris.Add($Uri); return }
            if ($Method -eq 'POST') {
                $script:PostedUris.Add($Uri)
                if ($Uri -like '*/open-req/cancel') { $script:OpenRequest.state = 'canceled'; $script:OpenRequest.status = 'Canceled'; return }
                if ($script:AdminRemoveFails) { throw 'There is already an existing open request.' }
                return [pscustomobject]@{ id = 'remove-req' }
            }
            if ($Uri -like '*/assignmentRequests/open-req') { return $script:OpenRequest }
            if ($Uri -like '*/assignmentRequests/remove-req') { $script:AssignmentRemoved = $true; return [pscustomobject]@{ id = 'remove-req'; state = 'delivered'; status = 'Delivered' } }
            if ($Uri -like '*/assignmentRequests?*') { return $script:OpenRequest }
            if ($Uri -like '*/assignments?*') { if ($script:AssignmentRemoved) { return @() }; return [pscustomobject]@{ id = 'assignment-1'; state = 'delivered'; target = [pscustomobject]@{ displayName = 'User' } } }
            if ($Uri -like '*/resourceRoleScopes') { return @() }
            if ($Uri -like '/v1.0/groups/*') { return [pscustomobject]@{ Id = 'own'; MailNickname = 'Rg-MyApp.WorkloadPlane.Users' } }
            return [pscustomobject]@{
                Id             = 'catalog-id'
                accessPackages = @([pscustomobject]@{ Id = 'ap-1'; displayName = 'AP-Rg-MyApp-WorkloadPlane-Users' })
                Resources      = @([pscustomobject]@{ OriginSystem = 'AadGroup'; OriginId = 'own'; DisplayName = 'own' })
            }
        }
    }

    It 'cancels a pending approval request before removing the assignment' {
        Remove-EntraOpsServiceCatalog -ServiceCatalogName 'Catalog-Rg-MyApp' -Force -WarningAction SilentlyContinue 6>$null | Out-Null

        $script:PostedUris[0] | Should -BeLike '*/assignmentRequests/open-req/cancel'
        $script:PostedUris | Should -Contain '/v1.0/identityGovernance/entitlementManagement/assignmentRequests'
        $script:DeletedUris | Should -Contain '/v1.0/identityGovernance/entitlementManagement/accessPackages/ap-1'
        $script:DeletedUris | Should -Contain '/v1.0/identityGovernance/entitlementManagement/catalogs/catalog-id'
        $script:DeletedUris | Should -Contain '/v1.0/groups/own'
    }

    It 'waits for a request that cannot be canceled instead of canceling it' {
        $script:OpenRequest = [pscustomobject]@{ id = 'open-req'; requestType = 'adminRemove'; state = 'delivering'; status = 'Delivering' }
        Mock Wait-EntraOpsServiceEMCondition { & $Condition | Out-Null; $script:OpenRequest.state = 'delivered'; $script:OpenRequest.status = 'Delivered'; & $Condition }

        Remove-EntraOpsServiceCatalog -ServiceCatalogName 'Catalog-Rg-MyApp' -Force -WarningAction SilentlyContinue 6>$null | Out-Null

        @($script:PostedUris | Where-Object { $_ -like '*/cancel' }).Count | Should -Be 0
        $script:DeletedUris | Should -Contain '/v1.0/identityGovernance/entitlementManagement/catalogs/catalog-id'
    }

    It 'keeps the catalog and groups when an assignment cannot be removed' {
        $script:AdminRemoveFails = $true

        { Remove-EntraOpsServiceCatalog -ServiceCatalogName 'Catalog-Rg-MyApp' -Force -WarningAction SilentlyContinue 6>$null } |
        Should -Throw '*incomplete*adminRemove of assignment assignment-1*'
        $script:DeletedUris | Should -Not -Contain '/v1.0/identityGovernance/entitlementManagement/catalogs/catalog-id'
        $script:DeletedUris | Should -Not -Contain '/v1.0/groups/own'
    }

    It 'keeps the catalog and groups when an open request does not complete' {
        $script:OpenRequest = [pscustomobject]@{ id = 'open-req'; requestType = 'adminRemove'; state = 'delivering'; status = 'Delivering' }

        { Remove-EntraOpsServiceCatalog -ServiceCatalogName 'Catalog-Rg-MyApp' -Force -WarningAction SilentlyContinue 6>$null } |
        Should -Throw '*1 open assignment request(s) did not complete*'
        $script:DeletedUris | Should -Not -Contain '/v1.0/groups/own'
    }

    It 'keeps the access package when an assignment removal does not complete' {
        $script:OpenRequest = [pscustomobject]@{ id = 'open-req'; requestType = 'userAdd'; state = 'delivered'; status = 'Delivered' }
        Mock Invoke-EntraOpsMsGraphQuery -ParameterFilter { $Uri -like '*/assignmentRequests/remove-req' } {
            [pscustomobject]@{ id = 'remove-req'; state = 'delivering'; status = 'Delivering' }
        }

        { Remove-EntraOpsServiceCatalog -ServiceCatalogName 'Catalog-Rg-MyApp' -Force -WarningAction SilentlyContinue 6>$null } |
        Should -Throw "*removal of User*still in progress*request remove-req, state 'delivering'*"
        $script:DeletedUris | Should -Not -Contain '/v1.0/identityGovernance/entitlementManagement/accessPackages/ap-1'
        $script:DeletedUris | Should -Not -Contain '/v1.0/identityGovernance/entitlementManagement/catalogs/catalog-id'
        $script:DeletedUris | Should -Not -Contain '/v1.0/groups/own'
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

    It 'retries the policy PATCH while the policy object returns 404' {
        Mock Start-Sleep { $script:ServiceEMNow = $script:ServiceEMNow.AddSeconds($Seconds) }
        $script:PatchCalls = 0
        Mock Invoke-EntraOpsMsGraphQuery {
            if ($Method -eq 'GET') { return [pscustomobject]@{ Id = 'assignment-member'; PolicyId = 'policy-id' } }
            if ($Method -eq 'PATCH') {
                $script:PatchCalls++
                if ($script:PatchCalls -lt 3) {
                    $ex = [System.InvalidOperationException]::new('404 (Not Found)')
                    $ex.Data['StatusCode'] = 404
                    throw $ex
                }
            }
        }

        New-EntraOpsServicePIMPolicy -ServiceGroups @([pscustomobject]@{ Id = 'group-id'; DisplayName = 'SG-Test-ControlPlane-Admins' }) 6>$null | Out-Null

        $script:PatchCalls | Should -Be 3
    }

    It 'does not retry the policy PATCH on non-404 errors' {
        Mock Start-Sleep { $script:ServiceEMNow = $script:ServiceEMNow.AddSeconds($Seconds) }
        $script:PatchCalls = 0
        Mock Invoke-EntraOpsMsGraphQuery {
            if ($Method -eq 'GET') { return [pscustomobject]@{ Id = 'assignment-member'; PolicyId = 'policy-id' } }
            if ($Method -eq 'PATCH') {
                $script:PatchCalls++
                $ex = [System.InvalidOperationException]::new('403 (Forbidden)')
                $ex.Data['StatusCode'] = 403
                throw $ex
            }
        }

        { New-EntraOpsServicePIMPolicy -ServiceGroups @([pscustomobject]@{ Id = 'group-id'; DisplayName = 'SG-Test-ControlPlane-Admins' }) 6>$null } |
        Should -Throw '*Failed to update PIM policy for 1 group(s)*'
        $script:PatchCalls | Should -Be 1
    }

    It 'waits for the member policy assignment of a new group without using the cache' {
        Mock Start-Sleep { $script:ServiceEMNow = $script:ServiceEMNow.AddSeconds($Seconds) }
        $script:GetCalls = 0
        $script:PatchCalls = 0
        Mock Invoke-EntraOpsMsGraphQuery {
            if ($Method -eq 'GET') {
                $script:GetCalls++
                if ($script:GetCalls -lt 2) { return $null }
                return [pscustomobject]@{ Id = 'assignment-member'; PolicyId = 'policy-id' }
            }
            if ($Method -eq 'PATCH') { $script:PatchCalls++ }
        }

        New-EntraOpsServicePIMPolicy -ServiceGroups @([pscustomobject]@{ Id = 'group-id'; DisplayName = 'SG-Test-ControlPlane-Admins' }) 6>$null | Out-Null

        $script:GetCalls | Should -Be 2
        $script:PatchCalls | Should -Be 1
        Should -Invoke Invoke-EntraOpsMsGraphQuery -ParameterFilter { $Method -eq 'GET' -and -not $DisableCache } -Times 0 -Exactly
    }

    It 'fails when the policy PATCH keeps returning 404 until the wait times out' {
        Mock Start-Sleep { $script:ServiceEMNow = $script:ServiceEMNow.AddSeconds($Seconds) }
        Mock Invoke-EntraOpsMsGraphQuery {
            if ($Method -eq 'GET') { return [pscustomobject]@{ Id = 'assignment-member'; PolicyId = 'policy-id' } }
            if ($Method -eq 'PATCH') {
                $ex = [System.InvalidOperationException]::new('404 (Not Found)')
                $ex.Data['StatusCode'] = 404
                throw $ex
            }
        }

        { New-EntraOpsServicePIMPolicy -ServiceGroups @([pscustomobject]@{ Id = 'group-id'; DisplayName = 'SG-Test-ControlPlane-Admins' }) 3>$null 6>$null } |
        Should -Throw '*group-id: Policy policy-id still not found*Last error: 404 (Not Found)*'
        Should -Invoke Invoke-EntraOpsMsGraphQuery -ParameterFilter { $Method -eq 'PATCH' -and -not $SuppressNotFoundWarning } -Times 0 -Exactly
    }

    It 'updates the remaining groups after a failed group and then reports the failure' {
        Mock Start-Sleep { $script:ServiceEMNow = $script:ServiceEMNow.AddSeconds($Seconds) }
        $script:PatchedUris = [System.Collections.Generic.List[string]]::new()
        Mock Invoke-EntraOpsMsGraphQuery {
            if ($Method -eq 'GET') {
                if ($Uri -like "*'failed-group'*") { throw 'Forbidden' }
                $groupId = [regex]::Match($Uri, "scopeId eq '([^']+)'").Groups[1].Value
                return [pscustomobject]@{ Id = "$groupId-member"; PolicyId = "policy-$groupId" }
            }
            if ($Method -eq 'PATCH') { $script:PatchedUris.Add($Uri) }
        }
        $groups = @(
            [pscustomobject]@{ Id = 'failed-group'; DisplayName = 'SG-Test-ControlPlane-Admins' },
            [pscustomobject]@{ Id = 'ok-group'; DisplayName = 'SG-Test-ManagementPlane-Admins' }
        )

        { New-EntraOpsServicePIMPolicy -ServiceGroups $groups 3>$null 6>$null } |
        Should -Throw '*Failed to update PIM policy for 1 group(s)*failed-group*'
        $script:PatchedUris | Should -Be @('/v1.0/policies/roleManagementPolicies/policy-ok-group')
    }

    It 'fails when no member policy assignment appears before the wait times out' {
        Mock Start-Sleep { $script:ServiceEMNow = $script:ServiceEMNow.AddSeconds($Seconds) }
        Mock Invoke-EntraOpsMsGraphQuery {
            if ($Method -eq 'GET') { return $null }
            if ($Method -eq 'PATCH') { throw 'PATCH must not be called' }
        }

        { New-EntraOpsServicePIMPolicy -ServiceGroups @([pscustomobject]@{ Id = 'group-id'; DisplayName = 'SG-Test-ControlPlane-Admins' }) 3>$null 6>$null } |
        Should -Throw '*group-id: no member policy assignment found*'
        Should -Invoke Invoke-EntraOpsMsGraphQuery -ParameterFilter { $Method -eq 'PATCH' } -Times 0 -Exactly
    }

    It 'fails when the member policy assignment lookup fails' {
        Mock Start-Sleep { $script:ServiceEMNow = $script:ServiceEMNow.AddSeconds($Seconds) }
        Mock Invoke-EntraOpsMsGraphQuery {
            if ($Method -eq 'GET') { throw 'Forbidden' }
        }

        { New-EntraOpsServicePIMPolicy -ServiceGroups @([pscustomobject]@{ Id = 'group-id'; DisplayName = 'SG-Test-ControlPlane-Admins' }) 3>$null 6>$null } |
        Should -Throw '*group-id: policy assignment lookup failed*'
        Should -Invoke Invoke-EntraOpsMsGraphQuery -ParameterFilter { $Method -eq 'GET' } -Times 1 -Exactly
    }

    It 'updates only the policies of the admin groups' {
        $script:PolicyLookupUris = [System.Collections.Generic.List[string]]::new()
        Mock Invoke-EntraOpsMsGraphQuery {
            if ($Method -eq 'GET') { $script:PolicyLookupUris.Add($Uri); return [pscustomobject]@{ Id = 'assignment-member'; PolicyId = 'policy-id' } }
        }
        $groups = @('Test Members', 'SG-Test-CatalogPlane-Members', 'SG-Test-WorkloadPlane-Users', 'SG-Test-WorkloadPlane-Admins', 'SG-Members-ManagementPlane-Admins') |
        ForEach-Object { [pscustomobject]@{ Id = $_; DisplayName = $_ } }

        New-EntraOpsServicePIMPolicy -ServiceGroups $groups 6>$null | Out-Null

        $script:PolicyLookupUris.Count | Should -Be 2
        @($script:PolicyLookupUris | Where-Object { $_ -like "*'SG-Test-WorkloadPlane-Admins'*" -or $_ -like "*'SG-Members-ManagementPlane-Admins'*" }).Count | Should -Be 2
    }
}

Describe 'ServiceEM create failures' {
    BeforeAll {
        . "$script:TestRepositoryRoot/EntraOps/Public/ServiceEM/New-EntraOpsServiceEMCatalogResourceRole.ps1"
        . "$script:TestRepositoryRoot/EntraOps/Public/ServiceEM/New-EntraOpsServiceEMAccessPackage.ps1"
    }

    BeforeEach {
        Mock Start-Sleep { $script:ServiceEMNow = $script:ServiceEMNow.AddSeconds($Seconds) }
        Mock Write-Warning {}
        $script:Created = [System.Collections.Generic.List[object]]::new()
        $script:FailOn = $null
        $script:ExtraOnRecheck = @()
        $script:GetCalls = 0
        Mock Invoke-EntraOpsMsGraphQuery {
            if ($Method -eq 'GET') {
                $script:GetCalls++
                # Objects that appear after the initial lookup, e.g. added manually or by another deployment
                if ($script:GetCalls -gt 1) { return @($script:Created.ToArray()) + @($script:ExtraOnRecheck) }
            }
            if ($Method -eq 'POST') {
                if (-not $ThrowOnFailure) { throw 'POST without -ThrowOnFailure' }
                $body = $Body | ConvertFrom-Json -Depth 20
                if ("$($body.roleDefinitionId)$($body.displayName)" -like $script:FailOn) { throw "Graph 400 for $script:FailOn" }
                $created = [pscustomobject]@{ id = [guid]::NewGuid().Guid; displayName = $body.displayName; accessPackage = $body.accessPackage; principalId = $body.principalId; roleDefinitionId = $body.roleDefinitionId }
                $script:Created.Add($created)
                return $created
            }
            return $script:Created.ToArray()
        }
    }

    It 'assigns the remaining catalog roles and reports a failed one' {
        $groups = @('SG-Rg-X-ControlPlane-Admins', 'SG-Rg-X-WorkloadPlane-Admins', 'SG-Rg-X-ManagementPlane-Admins') | ForEach-Object { [pscustomobject]@{ Id = "id:$_"; DisplayName = $_ } }
        $script:FailOn = 'ae79f266-94d4-4dab-b730-feca7e132178'

        { New-EntraOpsServiceEMCatalogResourceRole -ServiceGroups $groups -ServiceCatalogId 'cat' 6>$null } |
        Should -Throw '*Failed to assign 1 catalog role(s)*Owner for id:SG-Rg-X-ControlPlane-Admins*Graph 400*'

        @($script:Created.roleDefinitionId) | Should -Be @('44272f93-9762-48e8-af59-1b5351b1d6b3', 'e2182095-804a-4656-ae11-64734e9b7ae5')
    }

    It 'creates the remaining access packages and reports a failed one' {
        $roles = @('WorkloadPlane,Users', 'WorkloadPlane,Admins', 'ManagementPlane,Admins') | ForEach-Object { $a, $n = $_ -split ','; [pscustomobject]@{ accessLevel = $a; name = $n; groupType = '' } }
        $script:FailOn = 'AP-Rg-X-WorkloadPlane-Admins'

        { New-EntraOpsServiceEMAccessPackage -ServiceName 'Rg-X' -ServiceCatalogId 'cat' -ServiceRoles $roles 6>$null } |
        Should -Throw '*Failed to create 1 access package(s)*AP-Rg-X-WorkloadPlane-Admins*Graph 400*'

        @($script:Created.displayName) | Should -Be @('AP-Rg-X-WorkloadPlane-Users', 'AP-Rg-X-ManagementPlane-Admins')
    }

    It 'creates the remaining assignment policies and reports a failed one' {
        $groups = @('SG-Sub-X-CatalogPlane-Members', 'SG-Sub-X-ControlPlane-Admins', 'SG-Sub-X-ManagementPlane-Admins') | ForEach-Object { [pscustomobject]@{ Id = "id:$_"; DisplayName = $_ } }
        $packages = @('AP-Sub-X-CatalogPlane-Members', 'AP-Sub-X-ManagementPlane-Admins') | ForEach-Object { [pscustomobject]@{ Id = "ap:$_"; DisplayName = $_ } }
        $script:FailOn = 'Initial Management Admin Policy'

        { New-EntraOpsServiceEMAssignmentPolicy -ServiceName 'Sub-X' -ServiceCatalogId 'cat' -ServiceGroups $groups -ServicePackages $packages 6>$null } |
        Should -Throw "*Failed to create 1 assignment policy(ies)*'AP-Sub-X-ManagementPlane-Admins'*Graph 400*"

        @($script:Created.displayName) | Should -Contain 'Management Plane Policy'
        @($script:Created.displayName) | Should -Contain 'Initial Catalog Members Policy'
        @($script:Created.displayName) | Should -Not -Contain 'Initial Management Admin Policy'
    }

    It 'accepts further catalog role assignments in the consistency check' {
        $groups = @('SG-Rg-X-WorkloadPlane-Admins') | ForEach-Object { [pscustomobject]@{ Id = "id:$_"; DisplayName = $_ } }
        $script:ExtraOnRecheck = @([pscustomobject]@{ id = 'foreign-assignment'; principalId = 'someone'; roleDefinitionId = 'ae79f266-94d4-4dab-b730-feca7e132178' })

        $result = New-EntraOpsServiceEMCatalogResourceRole -ServiceGroups $groups -ServiceCatalogId 'cat' -WarningAction SilentlyContinue 6>$null

        @($result.id) | Should -Contain 'foreign-assignment'
        Should -Invoke Start-Sleep -Times 1 -Exactly
    }

    It 'accepts further assignment policies in the consistency check' {
        $groups = @('SG-Sub-X-CatalogPlane-Members') | ForEach-Object { [pscustomobject]@{ Id = "id:$_"; DisplayName = $_ } }
        $packages = @('AP-Sub-X-CatalogPlane-Members') | ForEach-Object { [pscustomobject]@{ Id = "ap:$_"; DisplayName = $_ } }
        $script:ExtraOnRecheck = @([pscustomobject]@{ id = 'foreign-policy'; displayName = 'Manual Policy'; accessPackage = [pscustomobject]@{ id = 'ap:other' } })

        $result = New-EntraOpsServiceEMAssignmentPolicy -ServiceName 'Sub-X' -ServiceCatalogId 'cat' -ServiceGroups $groups -ServicePackages $packages 6>$null

        @($result.id) | Should -Contain 'foreign-policy'
        Should -Invoke Start-Sleep -Times 1 -Exactly
    }

    It 'still waits for an expected catalog role assignment that is missing' {
        $groups = @('SG-Rg-X-WorkloadPlane-Admins') | ForEach-Object { [pscustomobject]@{ Id = "id:$_"; DisplayName = $_ } }
        Mock Invoke-EntraOpsMsGraphQuery {
            if ($Method -eq 'POST') { return [pscustomobject]@{ id = 'created-assignment' } }
            return @([pscustomobject]@{ id = 'foreign-assignment' })
        }

        { New-EntraOpsServiceEMCatalogResourceRole -ServiceGroups $groups -ServiceCatalogId 'cat' -WarningAction SilentlyContinue 6>$null } |
        Should -Throw '*Catalog Resource Role Assignment consistency*'
    }
}

Describe 'ServiceEM provisioning failure cleanup' {
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
        # The group step reports what it created through the hidden -CreatedGroupIds list; one group already existed
        Mock New-EntraOpsServiceEntraGroup {
            $CreatedGroupIds.Add('new-admins')
            @([pscustomobject]@{ Id = 'existing-users'; DisplayName = 'SG-Rg-X-WorkloadPlane-Users' }, [pscustomobject]@{ Id = 'new-admins'; DisplayName = 'SG-Rg-X-WorkloadPlane-Admins' })
        }
        Mock New-EntraOpsServiceEMCatalog { [pscustomobject]@{ Id = 'cat' } }
        Mock New-EntraOpsServiceEMCatalogResource { @([pscustomobject]@{ Id = 'r1' }) }
        Mock New-EntraOpsServiceEMCatalogResourceRole { @() }
        Mock New-EntraOpsServiceEMAccessPackage { @([pscustomobject]@{ Id = 'ap1'; DisplayName = 'AP-Rg-X-WorkloadPlane-Admins' }) }
        Mock New-EntraOpsServiceEMAccessPackageResourceAssignment { @() }
        Mock New-EntraOpsServiceEMAssignmentPolicy { @([pscustomobject]@{ Id = 'pol1'; DisplayName = 'Workload Plane Policy' }) }
        Mock New-EntraOpsServiceEMAssignment { @() }
        Mock New-EntraOpsServicePIMPolicy { @() }
        Mock New-EntraOpsServicePIMAssignment { @() }
        Mock Set-EntraOpsServiceEMWorkloadClassification { @() }
        Mock Undo-EntraOpsServiceEMUnregisteredGroup {}
    }

    It 'removes the groups created in this run when the PIM policy step fails, then reports that error' {
        Mock New-EntraOpsServicePIMPolicy { throw 'PIM onboarding race' }

        { New-EntraOpsServiceBootstrap -ServiceName 'Rg-X' -SkipAzureResourceGroup -ServiceMembers @() -EnableWorkloadPlanePimForGroups -WarningAction SilentlyContinue 6>$null } |
        Should -Throw '*PIM onboarding race*'

        # No catalog yet, so nothing is registered and the created group is the only candidate
        Should -Invoke Undo-EntraOpsServiceEMUnregisteredGroup -Times 1 -Exactly -ParameterFilter {
            @($CreatedGroupIds) -eq @('new-admins') -and @($RegisteredGroupIds).Count -eq 0 -and [string]::IsNullOrEmpty($ServiceCatalogId)
        }
        Should -Invoke Set-EntraOpsServiceEMWorkloadClassification -Times 0 -Exactly
        Should -Invoke New-EntraOpsServiceEMCatalog -Times 0 -Exactly
    }

    It 'passes the catalog and the registered groups to the cleanup when resource registration fails' {
        Mock New-EntraOpsServiceEMCatalogResource {
            $RegisteredGroupIds.Add('new-admins')
            throw 'Catalog Resource object consistency with Entra not achieved'
        }

        { New-EntraOpsServiceBootstrap -ServiceName 'Rg-X' -SkipAzureResourceGroup -ServiceMembers @() -WarningAction SilentlyContinue 6>$null } |
        Should -Throw '*consistency with Entra not achieved*'

        Should -Invoke Undo-EntraOpsServiceEMUnregisteredGroup -Times 1 -Exactly -ParameterFilter {
            @($CreatedGroupIds) -eq @('new-admins') -and @($RegisteredGroupIds) -eq @('new-admins') -and $ServiceCatalogId -eq 'cat'
        }
        Should -Invoke Set-EntraOpsServiceEMWorkloadClassification -Times 0 -Exactly
    }

    It 'reports the provisioning error even when the cleanup itself fails' {
        Mock New-EntraOpsServiceEMCatalog { throw 'catalog quota' }
        Mock Undo-EntraOpsServiceEMUnregisteredGroup { throw 'cleanup exploded' }

        { New-EntraOpsServiceBootstrap -ServiceName 'Rg-X' -SkipAzureResourceGroup -ServiceMembers @() -WarningAction SilentlyContinue 6>$null } |
        Should -Throw '*catalog quota*'
    }

    It 'includes unfinished access requests in the bootstrap report' {
        Mock New-EntraOpsServiceEMAssignment {
            $AssignmentRequestStatuses.Add([pscustomobject]@{ Id = 'request-1'; State = 'delivering'; Status = 'ReadyToFulfill'; TargetId = 'admin'; AccessPackageId = 'ap1' })
            @()
        }

        Mock Write-Progress {}
        $result = New-EntraOpsServiceBootstrap -ServiceName 'Rg-X' -SkipAzureResourceGroup -ServiceMembers @() -WarningAction SilentlyContinue -InformationVariable feedback 6>$null

        $result.Assignments | Should -BeNullOrEmpty
        @($result.AssignmentRequests).Count | Should -Be 1
        $result.AssignmentRequests[0].State | Should -Be 'delivering'
        $result.AssignmentRequests[0].Status | Should -Be 'ReadyToFulfill'
        ($feedback.MessageData -join ' ') | Should -BeLike '*1 access request(s) pending*Access is not ready*'
        Should -Invoke Write-Progress -Times 1 -Exactly -ParameterFilter { $Activity -eq 'Provisioning ServiceEM: Rg-X' -and $Completed }
    }

    It 'does not run the cleanup once registration succeeded, even if a later step fails' {
        Mock New-EntraOpsServiceEMAccessPackage { throw 'access package failed' }
        Mock Write-Progress {}

        { New-EntraOpsServiceBootstrap -ServiceName 'Rg-X' -SkipAzureResourceGroup -ServiceMembers @() -WarningAction SilentlyContinue 6>$null } |
        Should -Throw '*access package failed*'

        Should -Invoke Undo-EntraOpsServiceEMUnregisteredGroup -Times 0 -Exactly
        Should -Invoke Set-EntraOpsServiceEMWorkloadClassification -Times 1 -Exactly
        Should -Invoke Write-Progress -Times 1 -Exactly -ParameterFilter { $Activity -eq 'Provisioning ServiceEM: Rg-X' -and $Completed }
    }

    It 'creates the Azure resource group before it reports a failed eligible owner assignment' {
        Mock New-EntraOpsServicePIMAssignment { throw 'eligible owner assignment failed' }
        Mock Get-AzContext { [pscustomobject]@{ Tenant = [pscustomobject]@{ Id = 't' }; Subscription = [pscustomobject]@{ Id = '11111111-1111-1111-1111-111111111111' } } }
        Mock Get-AzSubscription { [pscustomobject]@{ Id = $SubscriptionId } }
        Mock New-EntraOpsServiceAZContainer { [pscustomobject]@{ ResourceId = 'rg' } }

        $thrown = $null
        try {
            New-EntraOpsServiceBootstrap -ServiceName 'Rg-X' -AzureRegion 'westeurope' -SubscriptionId '11111111-1111-1111-1111-111111111111' -ServiceMembers @() `
                -GroupOwnership Eligible -WarningVariable warnings -WarningAction SilentlyContinue 6>$null | Out-Null
        } catch { $thrown = $_ }

        "$thrown" | Should -BeLike '*eligible owner assignment failed*'
        Should -Invoke New-EntraOpsServiceAZContainer -Times 1 -Exactly
        Should -Invoke Undo-EntraOpsServiceEMUnregisteredGroup -Times 0 -Exactly
        @($warnings | Where-Object { "$_" -like '*eligible owner assignment failed. The remaining steps continue*' }).Count | Should -Be 1
    }
}

Describe 'ServiceEM retry after an early provisioning failure' {
    BeforeAll {
        foreach ($name in 'New-EntraOpsServiceEntraGroup', 'New-EntraOpsServiceEMCatalogResource', 'New-EntraOpsServiceEMCatalogResourceRole', 'New-EntraOpsServiceEMAccessPackage', 'New-EntraOpsServiceEMAccessPackageResourceAssignment', 'New-EntraOpsServiceEMAssignment', 'New-EntraOpsServicePIMAssignment', 'New-EntraOpsServiceAZContainer', 'New-EntraOpsServiceBootstrap') {
            . "$script:TestRepositoryRoot/EntraOps/Public/ServiceEM/$name.ps1"
        }
        $script:Deploy = { New-EntraOpsServiceBootstrap -ServiceName 'Rg-X' -SkipAzureResourceGroup -ServiceMembers @() -EnableWorkloadPlanePimForGroups -WarningAction SilentlyContinue 6>$null }
        $script:GroupNamed = { param($Suffix) @($script:TenantGroups.Values | Where-Object { $_.DisplayName -like "*-$Suffix" })[0] }
    }

    # The real group and cleanup cmdlets run against an in-memory tenant that keeps its groups and catalog
    # registrations between the two runs; only the steps after them are mocked.
    BeforeEach {
        $script:TenantGroups = [ordered]@{}
        $script:CatalogGroupIds = [System.Collections.Generic.List[string]]::new()
        $script:NextGroupId = 0
        $script:RegisterOnlyThenFail = $null
        Mock Start-Sleep { $script:ServiceEMNow = $script:ServiceEMNow.AddSeconds($Seconds) }
        Mock Get-MgContext { [pscustomobject]@{ Account = 'caller@contoso.com'; AuthType = 'Delegated' } }
        Mock Invoke-EntraOpsMsGraphQuery {
            if ($Uri -like '/v1.0/users/*') { return [pscustomobject]@{ Id = "id:$($Uri -replace '^/v1.0/users/')" } }
            if ($Method -eq 'POST' -and $Uri -eq '/v1.0/groups') {
                $request = $Body | ConvertFrom-Json
                $script:NextGroupId++
                $group = [pscustomobject]@{
                    Id = "group-$($script:NextGroupId)"; DisplayName = $request.displayName; MailNickname = $request.mailNickname
                    GroupTypes = @($request.groupTypes | Where-Object { $_ }); IsAssignableToRole = [bool]$request.isAssignableToRole; SecurityEnabled = [bool]$request.securityEnabled
                }
                $script:TenantGroups[$group.Id] = $group
                return $group
            }
            if ($Method -eq 'GET' -and $Uri.StartsWith('/v1.0/groups?')) { return @($script:TenantGroups.Values) }
            if ($Method -eq 'GET' -and $Uri -match '^/v1.0/groups/([^?]+)') { return $script:TenantGroups[$Matches[1]] }
            if ($Method -eq 'DELETE' -and $Uri -match '^/v1.0/groups/(.+)$') { $script:TenantGroups.Remove($Matches[1]); return $null }
            if ($Uri.StartsWith('/v1.0/identityGovernance/entitlementManagement/catalogs?')) {
                return @([pscustomobject]@{ Id = 'cat'; DisplayName = 'Catalog-Rg-X'; Resources = @($script:CatalogGroupIds | ForEach-Object { [pscustomobject]@{ OriginId = $_ } }) })
            }
            if ($Uri.StartsWith('/v1.0/identityGovernance/entitlementManagement/catalogs/cat/resources')) {
                return @($script:CatalogGroupIds | ForEach-Object { [pscustomobject]@{ OriginSystem = 'AadGroup'; OriginId = $_ } })
            }
            return @()
        }
        Mock New-EntraOpsServiceEMCatalog { [pscustomobject]@{ Id = 'cat' } }
        # Registers the groups in the in-memory catalog; with RegisterOnlyThenFail, registers that group only and fails
        Mock New-EntraOpsServiceEMCatalogResource {
            foreach ($group in $ServiceGroups) {
                if ($script:RegisterOnlyThenFail -and $group.DisplayName -notlike "*-$($script:RegisterOnlyThenFail)") { continue }
                if ($group.Id -notin $script:CatalogGroupIds) { $script:CatalogGroupIds.Add($group.Id) }
                if ($null -ne $RegisteredGroupIds) { $RegisteredGroupIds.Add($group.Id) }
            }
            if ($script:RegisterOnlyThenFail) { throw 'Group object consistency with Entitlement Management not achieved' }
            @($ServiceGroups | ForEach-Object { [pscustomobject]@{ Id = "res-$($_.Id)"; OriginId = $_.Id; OriginSystem = 'AadGroup' } })
        }
        Mock New-EntraOpsServiceEMCatalogResourceRole { @() }
        Mock New-EntraOpsServiceEMAccessPackage { @() }
        Mock New-EntraOpsServicePIMPolicy { @() }
        Mock Set-EntraOpsServiceEMWorkloadClassification { @() }
    }

    It 'recreates the groups on the retry after the PIM policy step failed' {
        Mock New-EntraOpsServicePIMPolicy { throw 'PIM onboarding race' }
        { & $script:Deploy } | Should -Throw '*PIM onboarding race*'
        $script:TenantGroups.Count | Should -Be 0

        Mock New-EntraOpsServicePIMPolicy { @() }
        $report = & $script:Deploy

        @($report.Groups).Count | Should -BeGreaterThan 0
        & $script:GroupNamed 'WorkloadPlane-Users' | Should -Not -BeNullOrEmpty
        @($script:TenantGroups.Keys | Where-Object { $_ -notin $script:CatalogGroupIds }).Count | Should -Be 0
    }

    It 'reuses the registered group and recreates the others on the retry after a partial registration' {
        $script:RegisterOnlyThenFail = 'WorkloadPlane-Users'
        { & $script:Deploy } | Should -Throw '*consistency with Entitlement Management not achieved*'
        $usersGroup = & $script:GroupNamed 'WorkloadPlane-Users'
        @($script:TenantGroups.Keys) | Should -Be @($usersGroup.Id)

        $script:RegisterOnlyThenFail = $null
        & $script:Deploy | Out-Null

        (& $script:GroupNamed 'WorkloadPlane-Users').Id | Should -Be $usersGroup.Id
        $script:TenantGroups.Count | Should -BeGreaterThan 1
        @($script:TenantGroups.Keys | Where-Object { $_ -notin $script:CatalogGroupIds }).Count | Should -Be 0
    }

    It 'stops the retry at the provenance check when the groups of the failed run were not removed' {
        Mock Undo-EntraOpsServiceEMUnregisteredGroup {}
        Mock New-EntraOpsServicePIMPolicy { throw 'PIM onboarding race' }
        { & $script:Deploy } | Should -Throw '*PIM onboarding race*'

        Mock New-EntraOpsServicePIMPolicy { @() }
        { & $script:Deploy } | Should -Throw "*isn't a resource of the catalog 'Catalog-Rg-X'*"
    }
}

Describe 'ServiceEM report' {
    BeforeAll {
        . "$script:TestRepositoryRoot/EntraOps/Public/ServiceEM/Get-EntraOpsServiceEMReport.ps1"
    }

    It 'returns one report object with the assignments of each access package' {
        Mock Get-MgContext { [pscustomobject]@{ TenantId = 'tenant-1'; Account = 'caller@contoso.com' } }
        Mock Invoke-EntraOpsMsGraphQuery {
            switch -Wildcard ($Uri) {
                '/v1.0/identityGovernance/entitlementManagement/catalogs?*' { return @([pscustomobject]@{ Id = 'cat'; DisplayName = 'Catalog-Rg-X'; Resources = @() }) }
                '/v1.0/identityGovernance/entitlementManagement/accessPackages?*' { return @('ap1', 'ap2') | ForEach-Object { [pscustomobject]@{ Id = $_; DisplayName = $_; AssignmentPolicies = @(); ResourceRoleScopes = @() } } }
                '/v1.0/identityGovernance/entitlementManagement/assignments?*' {
                    $packageId = [regex]::Match($Uri, "accessPackage/id eq '([^']+)'").Groups[1].Value
                    return @([pscustomobject]@{ Id = "assignment-$packageId"; AccessPackage = [pscustomobject]@{ Id = $packageId } })
                }
                default { return @() }
            }
        }

        $report = Get-EntraOpsServiceEMReport

        @($report).Count | Should -Be 1
        $report.TenantId | Should -Be 'tenant-1'
        $catalog = $report.Catalogs | Where-Object { $_.Catalog.displayName -eq 'Catalog-Rg-X' }
        foreach ($package in $catalog.AccessPackages) {
            @($package.Assignments.Id) | Should -Be @("assignment-$($package.AccessPackage.Id)")
        }
        Should -Invoke Invoke-EntraOpsMsGraphQuery -Times 2 -Exactly -ParameterFilter { $Uri -like '*/assignments?*accessPackage/id eq*' -and $ConsistencyLevel -eq 'eventual' }
        Should -Invoke Invoke-EntraOpsMsGraphQuery -Times 0 -Exactly -ParameterFilter { $Uri -like '*accessPackage/catalog/id eq*' }
    }
}

}
