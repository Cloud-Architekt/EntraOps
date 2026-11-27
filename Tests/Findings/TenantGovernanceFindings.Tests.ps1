#Requires -Modules Pester

Describe 'Tenant Governance and Privilege History findings' {
    BeforeAll {
        $script:TestRepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
        Import-Module (Join-Path $script:TestRepositoryRoot 'EntraOps/EntraOps.psd1') -Force -WarningAction SilentlyContinue

        function Get-TestId([int]$Number) { '{0:d8}-0000-0000-0000-{1:d12}' -f $Number, $Number }
        function Write-TestDataFile([string]$Path, [string]$Variable, $Data) {
            New-Item -ItemType Directory -Path (Split-Path -Parent $Path) -Force | Out-Null
            "window.$Variable = $($Data | ConvertTo-Json -Depth 20 -Compress);" | Set-Content -LiteralPath $Path
        }
        $script:Roles = @{ ControlPlaneLong = (Get-TestId 101); ControlPlaneShort = (Get-TestId 102); ManagementPlane = (Get-TestId 103) }
        $script:Units = @{ Dynamic = (Get-TestId 301); Assigned = (Get-TestId 302); DynamicUnprivileged = (Get-TestId 303) }

        function New-TestRoleSetting([string]$RoleId, [string]$Name, [hashtable]$Property = @{}) {
            $Setting = [ordered]@{
                Id = $RoleId; DisplayName = $Name; ActivationReqMFA = $true; ApprovaltoActivate = $true; ActivateApprover = @()
                ActivationMaxDuration = 'PT2H'; AuthenticationContextRequired = $true; AuthenticationContextName = 'c1'
                PermanentEligibleAssignmentisExpirationRequired = $true; ExpireEligibleAssignment = 'P180D'; PermanentActiveAssignmentisExpirationRequired = $true; AssignmentReqMFA = $true
                EligibleAlertNotificationDefaultRecipient = $true; EligibleAssignmentAlertNotificationDefaultRecipient = $true; ActiveAlertNotificationDefaultRecipient = $true
                EligibleAlertNotificationAdditionalRecipient = @(); EligibleAssignmentAlertNotificationAdditionalRecipient = @(); ActiveAlertNotificationAdditionalRecipient = @()
            }
            foreach ($Key in $Property.Keys) { $Setting[$Key] = $Property[$Key] }
            $Setting
        }

        $script:Root = Join-Path $TestDrive 'reports'
        $Blobs = [ordered]@{}
        $Resource = { param($Type, $Name, $Properties) $Hash = "h$($Blobs.Count + 1)"; $Blobs[$Hash] = [ordered]@{ resourceType = $Type; displayName = $Name; properties = $Properties }; [ordered]@{ p = "$Type/test/$Name.json"; h = $Hash } }
        $Resources = @(
            # EligibleAssignment* are the activation alerts in the M365DSC naming of the snapshot.
            & $Resource 'microsoft.entra.rolesetting' 'CP long' (New-TestRoleSetting $script:Roles.ControlPlaneLong 'CP long' @{ ActivationMaxDuration = 'PT8H'; AuthenticationContextRequired = $false; ExpireEligibleAssignment = 'P2Y'; ActiveAlertNotificationDefaultRecipient = $false; EligibleAssignmentAlertNotificationDefaultRecipient = $false })
            & $Resource 'microsoft.entra.rolesetting' 'CP short' (New-TestRoleSetting $script:Roles.ControlPlaneShort 'CP short' @{ ActiveAlertNotificationDefaultRecipient = $false; ActiveAlertNotificationAdditionalRecipient = @('soc@contoso.com') })
            & $Resource 'microsoft.entra.rolesetting' 'MP role' (New-TestRoleSetting $script:Roles.ManagementPlane 'MP role' @{ ActivationMaxDuration = 'PT10H'; AuthenticationContextRequired = $false; PermanentEligibleAssignmentisExpirationRequired = $false; ExpireEligibleAssignment = 'P5Y' })
            & $Resource 'microsoft.entra.entitlementmanagementaccesspackage' 'CP Access' ([ordered]@{ Id = 'pk1'; DisplayName = 'CP Access'; AccessPackageResourceRoleScopes = @(@{ AccessPackageResourceOriginId = (Get-TestId 201); AccessPackageResourceTierName = 'ControlPlane' }) })
            & $Resource 'microsoft.entra.entitlementmanagementaccesspackage' 'UA Access' ([ordered]@{ Id = 'pk2'; DisplayName = 'UA Access'; AccessPackageResourceRoleScopes = @(@{ AccessPackageResourceOriginId = (Get-TestId 202); AccessPackageResourceTierName = 'UserAccess' }) })
            & $Resource 'microsoft.entra.entitlementmanagementaccesspackageassignmentpolicy' 'Forever' ([ordered]@{ Id = 'pol1'; DisplayName = 'Forever'; AccessPackageId = 'pk1'; DurationInDays = 0; AccessReviewSettings = @{ IsEnabled = $false }; RequestApprovalSettings = @{ IsApprovalRequired = $true } })
            & $Resource 'microsoft.entra.entitlementmanagementaccesspackageassignmentpolicy' 'Reviewed' ([ordered]@{ Id = 'pol2'; DisplayName = 'Reviewed'; AccessPackageId = 'pk1'; DurationInDays = 30; AccessReviewSettings = @{ IsEnabled = $true }; RequestApprovalSettings = @{ IsApprovalRequired = $true } })
            & $Resource 'microsoft.entra.entitlementmanagementaccesspackageassignmentpolicy' 'Users' ([ordered]@{ Id = 'pol3'; DisplayName = 'Users'; AccessPackageId = 'pk2'; DurationInDays = 0; AccessReviewSettings = @{ IsEnabled = $false } })
            & $Resource 'microsoft.entra.conditionalaccesspolicy' 'Require MFA' ([ordered]@{ Id = 'ca1'; DisplayName = 'Require MFA'; State = 'enabled'; ExcludeUsers = @('breakglass@contoso.com'); ExcludeGroups = @('CP Admins') })
            & $Resource 'microsoft.entra.conditionalaccesspolicy' 'Block legacy' ([ordered]@{ Id = 'ca2'; DisplayName = 'Block legacy'; State = 'enabled'; ExcludeUsers = @('breakglass@contoso.com'); ExcludeGroups = @() })
            & $Resource 'microsoft.entra.conditionalaccesspolicy' 'Disabled' ([ordered]@{ Id = 'ca3'; DisplayName = 'Disabled'; State = 'disabled'; ExcludeGroups = @('CP Admins') })
            & $Resource 'microsoft.entra.administrativeunit' 'Dynamic' ([ordered]@{ Id = $script:Units.Dynamic; DisplayName = 'Dynamic'; MembershipType = 'Dynamic'; MembershipRule = '(user.department -eq "IT")' })
            & $Resource 'microsoft.entra.administrativeunit' 'Assigned' ([ordered]@{ Id = $script:Units.Assigned; DisplayName = 'Assigned' })
            & $Resource 'microsoft.entra.administrativeunit' 'Dynamic other' ([ordered]@{ Id = $script:Units.DynamicUnprivileged; DisplayName = 'Dynamic other'; MembershipType = 'Dynamic' })
        )
        Write-TestDataFile "$script:Root/ConfigurationAnalyzer/data/configuration-analyzer-data.js" 'ENTRAOPS_CONFIGANALYZER_DATA' ([ordered]@{
                snapshots = @([ordered]@{ commitSha = 'cccccccc'; commitDate = '2026-10-20T10:00:00.0000000+00:00'; hasDetail = $true; resources = $Resources })
                blobs     = $Blobs
            })
        Write-TestDataFile "$script:Root/ClassificationExplorer/data/tier-map.js" 'EOCE_TIER_MAP' ([ordered]@{
                roles = @(
                    @{ sys = 'EntraID'; roleId = $script:Roles.ControlPlaneLong; roleClass = 'ControlPlane' }
                    @{ sys = 'EntraID'; roleId = $script:Roles.ControlPlaneShort; roleClass = 'ControlPlane' }
                    @{ sys = 'EntraID'; roleId = $script:Roles.ManagementPlane; roleClass = 'ManagementPlane' }
                )
            })
        $EamObject = { param($Id, $Type, $Upn, $Name, $Tier, $Units = @(), $RoleAssignments = @()) [ordered]@{ objectId = $Id; objectType = $Type; objectUserPrincipalName = $Upn; objectDisplayName = $Name; objectAdminTierLevelName = $Tier; assignedAdministrativeUnits = @($Units | ForEach-Object { @{ id = $_; displayName = 'AU' } }); roleAssignments = @($RoleAssignments) } }
        Write-TestDataFile "$script:Root/EamDashboard/data/eam-dashboard-data.js" 'ENTRAOPS_EAM_DATA' ([ordered]@{
                objects = @(
                    & $EamObject (Get-TestId 1) 'user' 'breakglass@contoso.com' 'Break glass' 'ControlPlane'
                    & $EamObject (Get-TestId 2) 'group' '' 'CP Admins' 'ControlPlane'
                    # The current assignment of the Management Plane role keeps it in the scope of the role setting rules.
                    & $EamObject (Get-TestId 3) 'user' 'admin@contoso.com' 'Admin' 'ManagementPlane' @($script:Units.Dynamic, $script:Units.Assigned) @(@{ roleDefinitionId = $script:Roles.ManagementPlane; roleSystem = 'EntraID'; classification = @(@{ adminTierLevelName = 'ManagementPlane' }) })
                    & $EamObject (Get-TestId 4) 'user' 'user@contoso.com' 'User' 'UserAccess' @($script:Units.DynamicUnprivileged)
                )
            })
        # Privilege History: newest snapshot first, as the rules sort by commit date.
        $HistoryObject = { param($Id, $Assignments, $Tier = 'ControlPlane') [ordered]@{ objectId = $Id; objectType = 'user'; objectDisplayName = "User $Id"; objectAdminTierLevelName = $Tier; roleAssignments = $Assignments } }
        $HistoryAssignment = {
            param($Id, $Tier, [switch]$WithoutInstanceId)
            $Assignment = [ordered]@{ roleAssignmentInstanceId = $Id; roleAssignmentId = "a-$Id"; roleDefinitionName = "Role $Id"; roleSystem = 'EntraID'; pimAssignmentType = 'Eligible'; roleType = 'BuiltInRole'; classification = @(@{ adminTierLevelName = $Tier }) }
            if ($WithoutInstanceId) { $Assignment.Remove('roleAssignmentInstanceId') }
            $Assignment
        }
        Write-TestDataFile "$script:Root/PrivilegeHistory/data/privilege-history-data.js" 'ENTRAOPS_PRIVILEGE_HISTORY_DATA' ([ordered]@{
                snapshots = @(
                    # u2 (Management Plane) holds two Control Plane roles: ra5 is a tier breach of both snapshots, ra4 a new one.
                    [ordered]@{ commitSha = 'new'; commitDate = '2026-10-26T10:00:00Z'; hasDetail = $true; totals = @{ tierBreaches = 7 }; objects = @(
                            & $HistoryObject 'u1' @((& $HistoryAssignment 'ra1' 'ControlPlane'), (& $HistoryAssignment 'ra2' 'ControlPlane'), (& $HistoryAssignment 'ra3' 'ManagementPlane'))
                            & $HistoryObject 'u2' @((& $HistoryAssignment 'ra4' 'ControlPlane'), (& $HistoryAssignment 'ra5' 'ControlPlane')) 'ManagementPlane'
                        ) }
                    # Written by an older EntraOps version without instance IDs: ra1 and ra5 are matched by their assignment ID.
                    [ordered]@{ commitSha = 'old'; commitDate = '2026-10-19T10:00:00Z'; hasDetail = $true; totals = @{ tierBreaches = 5 }; objects = @(
                            & $HistoryObject 'u1' @((& $HistoryAssignment 'ra1' 'ControlPlane' -WithoutInstanceId))
                            & $HistoryObject 'u2' @((& $HistoryAssignment 'ra5' 'ControlPlane' -WithoutInstanceId)) 'ManagementPlane'
                        ) }
                )
            })

        $script:Results = @{}
        foreach ($Result in Invoke-EntraOpsFindingEvaluation -Area TenantGovernance, PrivilegeHistory -ReportPath $script:Root -ConfigFilePath (Join-Path $TestDrive 'none.json') -WarningAction SilentlyContinue) { $script:Results[$Result.Key] = $Result }
    }

    It '<Key>: <Failed> of <Evaluated> instance(s) fail' -ForEach @(
        @{ Key = 'eligibleAssignmentDuration'; Evaluated = 2; Failed = 1; Names = @('CP long') }
        @{ Key = 'controlPlaneActivationDuration'; Evaluated = 2; Failed = 1; Names = @('CP long') }
        @{ Key = 'controlPlaneActivationAuthContext'; Evaluated = 2; Failed = 1; Names = @('CP long') }
        @{ Key = 'privilegedRoleAlert'; Evaluated = 3; Failed = 1; Names = @('CP long') }
        @{ Key = 'accessPackageExpiration'; Evaluated = 2; Failed = 1; Names = @('CP Access / Forever') }
        @{ Key = 'accessPackageAccessReview'; Evaluated = 2; Failed = 1; Names = @('CP Access / Forever') }
        @{ Key = 'conditionalAccessControlPlaneExclusion'; Evaluated = 2; Failed = 2; Names = @('Require MFA', 'Block legacy') }
        @{ Key = 'dynamicPrivilegedAdministrativeUnit'; Evaluated = 2; Failed = 1; Names = @('Dynamic') }
        @{ Key = 'newControlPlaneAccess'; Evaluated = 4; Failed = 2; Names = @('User u1', 'User u2') }
        @{ Key = 'tierBreachIncrease'; Evaluated = 2; Failed = 1; Names = @('User u2') }
    ) {
        $Result = $script:Results[$Key]
        $Result.EvaluatedCount | Should -Be $Evaluated
        $Result.FailedCount | Should -Be $Failed
        @($Result.Results.Instance.DisplayName) | Should -Be $Names
    }

    It 'explains the findings with their evidence' {
        $script:Results['privilegedRoleAlert'].Results[0].Evidence.MissingAlerts | Should -Be @('activation', 'active assignment')
        # Without Findings.EmergencyAccessAccounts the account excluded from every enabled policy is reported, too.
        $script:Results['conditionalAccessControlPlaneExclusion'].Results[0].Evidence.ExcludedControlPlane | Should -Be @('breakglass@contoso.com', 'CP Admins')
        $script:Results['newControlPlaneAccess'].Results[0].Message | Should -Be "Control Plane object 'User u1' got the Control Plane role 'Role ra2' (EntraID) between 2026-10-19 and 2026-10-26."
        # The breaches are counted like EO.1001 and EO.1003, not taken from the totals of the chart (5 and 7).
        $script:Results['tierBreachIncrease'].Results[0].Message | Should -Be "Management Plane object 'User u2' holds the Control Plane role 'Role ra4' (EntraID), a new tier breach between 2026-10-19 and 2026-10-26 (1 tier breaches before, 2 now)."
        $script:Results['tierBreachIncrease'].Results[0].Instance.AdminTierLevel | Should -Be 1
        $script:Results['tierBreachIncrease'].Results[0].Evidence.RoleTierLevelName | Should -Be 'ControlPlane'
        $script:Results['tierBreachIncrease'].Results[0].Instance.AdminTierLevelName | Should -Be 'ManagementPlane'
        # No delegated permission in the snapshots: nothing in the scope of EO.8003.
        $script:Results['newDelegatedPrivilegedPermission'].Status | Should -Be 'Skipped'
        $script:Results['newDelegatedPrivilegedPermission'].ReasonCode | Should -Be 'NotApplicable'
    }

    It 'skips the rules with a reason when the report data is missing' {
        $Skipped = @(Invoke-EntraOpsFindingEvaluation -Area TenantGovernance, PrivilegeHistory -ReportPath (Join-Path $TestDrive 'missing'))
        $Skipped.Count | Should -Be 11
        $Skipped.Status | Select-Object -Unique | Should -Be 'Skipped'
        ($Skipped | Where-Object Area -eq 'TenantGovernance')[0].Reason | Should -Match 'Configuration Analyzer'
        ($Skipped | Where-Object Area -eq 'PrivilegeHistory')[0].Reason | Should -Match 'Privilege History'
    }

    It 'returns only the rules of data that cannot be read with status Error' {
        $Broken = Join-Path $TestDrive 'broken'
        Copy-Item -LiteralPath $script:Root -Destination $Broken -Recurse
        'window.ENTRAOPS_PRIVILEGE_HISTORY_DATA = {"snapshots": [ broken;' | Set-Content -LiteralPath "$Broken/PrivilegeHistory/data/privilege-history-data.js"

        $Results = @(Invoke-EntraOpsFindingEvaluation -Area TenantGovernance, PrivilegeHistory -ReportPath $Broken -WarningAction SilentlyContinue)
        ($Results | Where-Object Area -eq 'PrivilegeHistory').Status | Should -Be @('Error', 'Error', 'Error')
        ($Results | Where-Object Area -eq 'PrivilegeHistory')[0].Reason | Should -Match 'could not be evaluated'
        ($Results | Where-Object { $_.Area -eq 'TenantGovernance' -and $_.Status -eq 'Failed' }).Count | Should -Be 8
    }

    It 'saves no rules for an empty pipeline instead of evaluating all rules' {
        $Folder = Join-Path $TestDrive 'empty'
        @(Invoke-EntraOpsFindingEvaluation -Area TenantGovernance -Category Drift -ReportPath $script:Root) | Save-EntraOpsFindingJson -ExportFolder $Folder -TenantId 't' -TenantName 't' 6> $null
        @((Get-Content -LiteralPath "$Folder/findings.json" -Raw | ConvertFrom-Json).Rules).Count | Should -Be 0
    }

    It 'uses the Findings settings of EntraOpsConfig.json' {
        $ConfigFile = Join-Path $TestDrive 'EntraOpsConfig.json'
        [ordered]@{
            ConfigurationAnalyzer = [ordered]@{ PimRequestFlowExcludedRiskFlags = @('noMfaActivation') }
            Findings              = [ordered]@{
                ExcludedRules                  = @('EO.3014', 'TenantGovernance.accessPackageExpiration')
                ControlPlaneActivationMaxHours = 8
                EligibleAssignmentMaxDays      = 1000
                # The group CP Admins by object ID: the account breakglass is reported instead.
                EmergencyAccessAccounts        = @((Get-TestId 2))
            }
        } | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $ConfigFile

        $Results = @{}
        foreach ($Result in Invoke-EntraOpsFindingEvaluation -Area TenantGovernance -ReportPath $script:Root -ConfigFilePath $ConfigFile) { $Results[$Result.Key] = $Result }
        $Results['privilegedRoleAlert'].Status | Should -Be 'Excluded'
        $Results['accessPackageExpiration'].Status | Should -Be 'Excluded'
        # CP long: activation for PT8H and eligible assignments for P2Y are within the configured maximum.
        $Results['controlPlaneActivationDuration'].Status | Should -Be 'Passed'
        $Results['controlPlaneActivationDuration'].Parameters.MaxHours | Should -Be 8
        $Results['eligibleAssignmentDuration'].Status | Should -Be 'Passed'
        $Results['eligibleAssignmentDuration'].Parameters.MaxDays | Should -Be 1000
        @($Results['conditionalAccessControlPlaneExclusion'].Results.Instance.DisplayName) | Should -Be @('Require MFA', 'Block legacy')
        @($Results['conditionalAccessControlPlaneExclusion'].Results.Evidence.ExcludedControlPlane | Select-Object -Unique) | Should -Be @('breakglass@contoso.com')

        & (Get-Module EntraOps) { param($Path) (Get-EntraOpsFindingSetting -ConfigFilePath $Path -WarningAction SilentlyContinue).ExcludedRules } $ConfigFile |
            Should -Be @('EO.3014', 'TenantGovernance.accessPackageExpiration', 'PimRequestFlow.noMfaActivation')
    }

    It 'returns the rules of an invalid setting with status Error and warns about unknown settings and rules' {
        $ConfigFile = Join-Path $TestDrive 'invalid.json'
        [ordered]@{
            Findings = [ordered]@{
                ExcludedRules             = @('EO.9999', 'TenantGovernance.privilegedRoleAlert')
                EligibleAssignmentMaxDays = '1y'
                # A number as text is a number.
                ControlPlaneActivationMaxHours = '8'
                MaxDayz                   = 1
            }
        } | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $ConfigFile

        $Results = @{}
        foreach ($Result in Invoke-EntraOpsFindingEvaluation -Area TenantGovernance -ReportPath $script:Root -ConfigFilePath $ConfigFile -WarningVariable Warnings -WarningAction SilentlyContinue) { $Results[$Result.Key] = $Result }
        $Results['eligibleAssignmentDuration'].Status | Should -Be 'Error'
        $Results['eligibleAssignmentDuration'].Reason | Should -Be "Findings.EligibleAssignmentMaxDays must be a number, but is '1y'"
        $Results['controlPlaneActivationDuration'].Status | Should -Be 'Passed'
        $Results['controlPlaneActivationDuration'].Parameters.MaxHours | Should -Be 8
        $Results['privilegedRoleAlert'].Status | Should -Be 'Excluded'
        $Results['controlPlaneActivationAuthContext'].Status | Should -Be 'Failed'

        $Text = @($Warnings | ForEach-Object { "$_" }) -join "`n"
        $Text | Should -Match "Findings.EligibleAssignmentMaxDays must be a number, but is '1y'"
        $Text | Should -Match 'Unknown Findings setting\(s\) in .*: MaxDayz\. Valid settings: ExcludedRules, .*EligibleAssignmentMaxDays'
        $Text | Should -Match "Findings.ExcludedRules: 'EO.9999' matches no finding rule.*EO.1001, EO.1002"
    }

    It 'notes Tenant Governance resource types exported with errors on the rules that read them, but not the known export limitation' {
        $Folder = Join-Path $TestDrive 'snapshot-health'
        Copy-Item -LiteralPath $script:Root -Destination $Folder -Recurse
        $Path = "$Folder/ConfigurationAnalyzer/data/configuration-analyzer-data.js"
        $Content = Get-Content -LiteralPath $Path -Raw
        $Data = $Content.Substring($Content.IndexOf('=') + 1).TrimEnd().TrimEnd(';') | ConvertFrom-Json -AsHashtable -DateKind String
        $Policy = 'microsoft.entra.entitlementmanagementaccesspackageassignmentpolicy'
        $Data.snapshotHealth = [ordered]@{
            status = 'partiallySuccessful'; isComplete = $false; isStale = $false; ageHours = 1; maxAgeHours = 30
            staleResourceTypes = @('microsoft.securityandcompliance.deviceconfigurationpolicy')
            resourceTypeStates = @(
                [ordered]@{ resourceType = 'microsoft.entra.conditionalaccesspolicy'; status = 'PublishedWithErrors'; retainedResourceCount = 0 }
                [ordered]@{ resourceType = $Policy; status = 'PublishedWithErrors'; retainedResourceCount = 0 }
                # No rule reads this type: not a gap of the findings.
                [ordered]@{ resourceType = 'microsoft.securityandcompliance.deviceconfigurationpolicy'; status = 'PreservedStale'; retainedResourceCount = 0 }
            )
            diagnostics = @(
                [ordered]@{ resourceType = 'microsoft.entra.conditionalaccesspolicy'; errorCategory = 'ExportError'; errorCode = 'Request_ResourceNotFound'; occurrences = 2; message = "Couldn't find ExcludedGroup '<id>', that is defined in policy 'Block legacy'. Skipping group. [Request_ResourceNotFound] : Resource '<id>' does not exist." }
                [ordered]@{ resourceType = $Policy; errorCategory = 'ExportError'; errorCode = 'Request_ResourceNotFound'; occurrences = 49; message = "[Request_ResourceNotFound] : Resource '<id>' does not exist or one of its queried reference-property objects are not present." }
            )
        }
        "window.ENTRAOPS_CONFIGANALYZER_DATA = $($Data | ConvertTo-Json -Depth 20 -Compress);" | Set-Content -LiteralPath $Path

        $Results = @{}
        foreach ($Result in Invoke-EntraOpsFindingEvaluation -Area TenantGovernance -ReportPath $Folder -ConfigFilePath (Join-Path $TestDrive 'none.json') -WarningAction SilentlyContinue) { $Results[$Result.Key] = $Result }
        $Gap = @($Results['conditionalAccessControlPlaneExclusion'].DataGaps | Where-Object Code -eq 'TenantGovernanceResourceTypeIncomplete')
        $Gap.Count | Should -Be 1
        $Gap[0].Message | Should -BeLike "*microsoft.entra.conditionalaccesspolicy (2 error(s), for example: Couldn't find ExcludedGroup '<id>', that is defined in policy 'Block legacy'. Skipping group.)"
        $Gap[0].Message | Should -Not -BeLike "*$Policy*"
        @($Results['accessPackageExpiration'].DataGaps).Count | Should -Be 0
        @($Results.Values | ForEach-Object { $_.DataGaps } | Where-Object Code -eq 'TenantGovernanceResourceTypeStale').Count | Should -Be 0
    }

    It 'skips the PIM role setting rules with missing data when no privileged role has the setting in the snapshot' {
        $Folder = Join-Path $TestDrive 'pim-without-settings'
        Copy-Item -LiteralPath $script:Root -Destination $Folder -Recurse
        $Path = "$Folder/ConfigurationAnalyzer/data/configuration-analyzer-data.js"
        $Content = Get-Content -LiteralPath $Path -Raw
        $Data = $Content.Substring($Content.IndexOf('=') + 1).TrimEnd().TrimEnd(';') | ConvertFrom-Json -AsHashtable -DateKind String
        foreach ($Blob in @($Data.blobs.Values | Where-Object { $_.resourceType -eq 'microsoft.entra.rolesetting' })) {
            $Blob.properties.PermanentEligibleAssignmentisExpirationRequired = $true
            foreach ($Name in @($Blob.properties.Keys | Where-Object { $_ -in 'ExpireEligibleAssignment', 'ActivationMaxDuration' -or $_ -like '*AlertNotification*' })) { $Blob.properties.Remove($Name) }
        }
        "window.ENTRAOPS_CONFIGANALYZER_DATA = $($Data | ConvertTo-Json -Depth 20 -Compress);" | Set-Content -LiteralPath $Path

        $Results = @{}
        foreach ($Result in Invoke-EntraOpsFindingEvaluation -Area TenantGovernance -ReportPath $Folder -ConfigFilePath (Join-Path $TestDrive 'none.json') -WarningAction SilentlyContinue) { $Results[$Result.Key] = $Result }
        $Results['eligibleAssignmentDuration'].Reason | Should -Be 'None of the 3 Control and Management Plane roles has a readable expiration of eligible assignments (ExpireEligibleAssignment) in the Tenant Governance snapshot.'
        $Results['controlPlaneActivationDuration'].Reason | Should -Be 'None of the 2 Control Plane roles has a readable maximum activation duration (ActivationMaxDuration) in the Tenant Governance snapshot.'
        $Results['privilegedRoleAlert'].Reason | Should -BeLike 'The Tenant Governance snapshot has no notification settings of the 3 Control and Management Plane roles*'
        foreach ($Key in 'eligibleAssignmentDuration', 'controlPlaneActivationDuration', 'privilegedRoleAlert') {
            $Results[$Key].Status | Should -Be 'Skipped'
            $Results[$Key].ReasonCode | Should -Be 'MissingData' -Because "$Key had privileged roles in scope, but none could be evaluated"
        }
    }

    It 'warns about rules of -ExcludeRule that match no rule' {
        $null = Invoke-EntraOpsFindingEvaluation -Area PrivilegeHistory -ReportPath $script:Root -ConfigFilePath (Join-Path $TestDrive 'none.json') -ExcludeRule 'PrivilegeHistory.unknownKey', 'EO.8001' -WarningVariable Warnings -WarningAction SilentlyContinue
        @($Warnings | Where-Object { "$_" -like "-ExcludeRule: 'PrivilegeHistory.unknownKey' matches no finding rule*" }).Count | Should -Be 1
    }

    Context 'Conditional Access exclusions of Control Plane users and groups' {
        BeforeAll {
            # A Reports folder with the given Conditional Access policies and the objects of the shared fixture.
            function New-TestConditionalAccessData([string]$Name, [object[]]$Policies) {
                $Folder = Join-Path $TestDrive $Name
                Copy-Item -LiteralPath $script:Root -Destination $Folder -Recurse
                $Path = "$Folder/ConfigurationAnalyzer/data/configuration-analyzer-data.js"
                $Content = Get-Content -LiteralPath $Path -Raw
                $Data = $Content.Substring($Content.IndexOf('=') + 1).TrimEnd().TrimEnd(';') | ConvertFrom-Json -AsHashtable -DateKind String
                $Data.snapshots[0].resources = @($Data.snapshots[0].resources | Where-Object { $_.p -notlike 'microsoft.entra.conditionalaccesspolicy/*' })
                $Number = 0
                foreach ($Policy in $Policies) {
                    $Number++
                    $Data.blobs["ca$Number"] = [ordered]@{ resourceType = 'microsoft.entra.conditionalaccesspolicy'; properties = $Policy }
                    $Data.snapshots[0].resources += [ordered]@{ p = "microsoft.entra.conditionalaccesspolicy/test/$Number.json"; h = "ca$Number" }
                }
                "window.ENTRAOPS_CONFIGANALYZER_DATA = $($Data | ConvertTo-Json -Depth 20 -Compress);" | Set-Content -LiteralPath $Path
                $Folder
            }
            function Get-TestConditionalAccessResult([string]$ReportPath) {
                Invoke-EntraOpsFindingEvaluation -Area TenantGovernance -ReportPath $ReportPath -ConfigFilePath (Join-Path $TestDrive 'none.json') | Where-Object Key -eq 'conditionalAccessControlPlaneExclusion'
            }
        }

        It 'reports the Control Plane user excluded from the only enabled policy' {
            $Folder = New-TestConditionalAccessData 'ca-single' @([ordered]@{ Id = 'ca1'; DisplayName = 'Require MFA'; State = 'enabled'; ExcludeUsers = @('breakglass@contoso.com') })
            $Result = Get-TestConditionalAccessResult $Folder
            $Result.Status | Should -Be 'Failed'
            $Result.Results.Evidence.ExcludedControlPlane | Should -Be @('breakglass@contoso.com')
            # With one policy, the exclusion is no candidate for the setting: the single-exclusion hint names it.
            $Result.Reason | Should -Not -BeLike '*excluded from every enabled*'
        }

        It 'reports a Control Plane group excluded from every enabled policy' {
            $Folder = New-TestConditionalAccessData 'ca-group' @(
                [ordered]@{ Id = 'ca1'; DisplayName = 'Require MFA'; State = 'enabled'; ExcludeGroups = @('CP Admins') }
                [ordered]@{ Id = 'ca2'; DisplayName = 'Block legacy'; State = 'enabled'; ExcludeGroups = @('CP Admins') }
            )
            $Result = Get-TestConditionalAccessResult $Folder
            $Result.FailedCount | Should -Be 2
            @($Result.Results.Evidence.ExcludedControlPlane | Select-Object -Unique) | Should -Be @('CP Admins')
            # The reason points to the setting.
            $Result.ReasonCode | Should -Be 'Note'
            $Result.Reason | Should -BeLike "2 of 2 failed policies only exclude 'CP Admins'*set Findings.EmergencyAccessAccounts*"
        }

        It 'reports a Control Plane user excluded from every enabled policy without the setting and names it as candidate' {
            $Folder = New-TestConditionalAccessData 'ca-candidate' @(
                [ordered]@{ Id = 'ca1'; DisplayName = 'Require MFA'; State = 'enabled'; ExcludeUsers = @('breakglass@contoso.com'); ExcludeGroups = @('CP Admins') }
                [ordered]@{ Id = 'ca2'; DisplayName = 'Block legacy'; State = 'enabled'; ExcludeUsers = @('breakglass@contoso.com') }
            )
            $Result = Get-TestConditionalAccessResult $Folder
            # Nothing is taken for an emergency access account without Findings.EmergencyAccessAccounts.
            $Result.Status | Should -Be 'Failed'
            $Result.FailedCount | Should -Be 2
            ($Result.Results | Where-Object { $_.Instance.DisplayName -eq 'Require MFA' }).Evidence.ExcludedControlPlane | Should -Be @('breakglass@contoso.com', 'CP Admins')
            ($Result.Results | Where-Object { $_.Instance.DisplayName -eq 'Block legacy' }).Evidence.ExcludedControlPlane | Should -Be @('breakglass@contoso.com')
            $Result.ReasonCode | Should -Be 'Note'
            $Result.Reason | Should -Be "1 Control Plane user(s) are excluded from every enabled Conditional Access policy: 'Break glass' ($(Get-TestId 1)). If they are emergency access accounts, add them (or their group) to Findings.EmergencyAccessAccounts."
            # Lists of names in a note are cut after five.
            & (Get-Module EntraOps) { Join-EntraOpsFindingName -Name @(1..7 | ForEach-Object { "u$_" }) } | Should -Be 'u1, u2, u3, u4, u5 and 2 more'
        }

        It 'does not report the configured emergency access account' {
            $Folder = New-TestConditionalAccessData 'ca-configured' @(
                [ordered]@{ Id = 'ca1'; DisplayName = 'Require MFA'; State = 'enabled'; ExcludeUsers = @('breakglass@contoso.com') }
                [ordered]@{ Id = 'ca2'; DisplayName = 'Block legacy'; State = 'enabled'; ExcludeUsers = @('breakglass@contoso.com') }
            )
            $Config = Join-Path $TestDrive 'ca-configured.json'
            @{ Findings = @{ EmergencyAccessAccounts = @('breakglass@contoso.com') } } | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $Config
            $Result = Invoke-EntraOpsFindingEvaluation -Area TenantGovernance -ReportPath $Folder -ConfigFilePath $Config | Where-Object Key -eq 'conditionalAccessControlPlaneExclusion'
            $Result.Status | Should -Be 'Passed'
            $Result.FailedCount | Should -Be 0
        }

        It 'does not treat a policy that also excludes the identity as covering a block policy allow-list (EO.4003)' {
            $Folder = New-TestConditionalAccessData 'ca-self-excl' @(
                [ordered]@{ Id = 'ca1'; DisplayName = 'Block portals'; State = 'enabled'; BuiltInControls = @('block'); IncludeUsers = @('All'); ExcludeUsers = @('breakglass@contoso.com') }
                [ordered]@{ Id = 'ca2'; DisplayName = 'Require MFA'; State = 'enabled'; BuiltInControls = @('mfa'); IncludeUsers = @('breakglass@contoso.com'); ExcludeUsers = @('breakglass@contoso.com') }
            )
            $Result = Get-TestConditionalAccessResult $Folder
            $Result.Status | Should -Be 'Failed'
            @($Result.Results | Where-Object { $_.Instance.Id -eq 'ca1' }).Count | Should -Be 1
        }

        It 'skips the rules that need the privileged objects when the EAM Dashboard data is missing' {
            $Folder = New-TestConditionalAccessData 'ca-no-objects' @(
                [ordered]@{ Id = 'ca1'; DisplayName = 'Require MFA'; State = 'enabled'; ExcludeUsers = @('breakglass@contoso.com') }
            )
            Remove-Item -LiteralPath "$Folder/EamDashboard/data/eam-dashboard-data.js"
            $Results = @{}
            foreach ($Result in Invoke-EntraOpsFindingEvaluation -Area TenantGovernance -ReportPath $Folder -ConfigFilePath (Join-Path $TestDrive 'none.json')) { $Results[$Result.Key] = $Result }
            # Without the objects, the excluded Control Plane user would not resolve and the rule would pass.
            foreach ($Key in 'conditionalAccessControlPlaneExclusion', 'dynamicPrivilegedAdministrativeUnit') {
                $Results[$Key].Status | Should -Be 'Skipped'
                $Results[$Key].ReasonCode | Should -Be 'MissingData'
                $Results[$Key].Reason | Should -BeLike '*The report data has no EAM Dashboard data with the classified privileged objects. Generate it with New-EntraOpsReportingData*'
            }
            # The roles keep their tier of the Classification Explorer data.
            $Results['controlPlaneActivationDuration'].Status | Should -Be 'Failed'

            # Without both datasets with the role tiers, the rules of the PIM role settings have missing data, not an empty scope.
            Remove-Item -LiteralPath "$Folder/ClassificationExplorer/data/tier-map.js"
            foreach ($Result in Invoke-EntraOpsFindingEvaluation -Area TenantGovernance -ReportPath $Folder -ConfigFilePath (Join-Path $TestDrive 'none.json')) { $Results[$Result.Key] = $Result }
            foreach ($Key in 'eligibleAssignmentDuration', 'controlPlaneActivationDuration', 'controlPlaneActivationAuthContext', 'privilegedRoleAlert') {
                $Results[$Key].Status | Should -Be 'Skipped'
                $Results[$Key].ReasonCode | Should -Be 'MissingData'
                $Results[$Key].Reason | Should -BeLike 'None of the PIM role settings has a tier, because the report data has no Classification Explorer data*and no EAM Dashboard data*'
            }
        }

        It 'evaluates policies without excluded users when the EAM Dashboard data is missing' {
            $Folder = New-TestConditionalAccessData 'ca-no-objects-roles' @(
                [ordered]@{ Id = 'ca1'; DisplayName = 'Require MFA'; State = 'enabled'; BuiltInControls = @('mfa'); IncludeUsers = @('All'); ExcludeRoles = @('CP long') }
            )
            Remove-Item -LiteralPath "$Folder/EamDashboard/data/eam-dashboard-data.js"
            # Roles are resolved by the PIM role settings, not by the objects.
            (Get-TestConditionalAccessResult $Folder).Status | Should -Be 'Failed'
        }

        It 'skips when the EAM Dashboard data is missing and none of the excluded groups resolves' {
            $Folder = New-TestConditionalAccessData 'ca-no-objects-groups' @(
                [ordered]@{ Id = 'ca1'; DisplayName = 'Require MFA'; State = 'enabled'; BuiltInControls = @('mfa'); IncludeUsers = @('All'); ExcludeGroups = @('CP Admins') }
            )
            Remove-Item -LiteralPath "$Folder/EamDashboard/data/eam-dashboard-data.js"
            $Result = Get-TestConditionalAccessResult $Folder
            $Result.Status | Should -Be 'Skipped'
            $Result.ReasonCode | Should -Be 'MissingData'
            $Result.Reason | Should -BeLike 'The groups excluded from the Conditional Access policies cannot be resolved to their tier.*'

            $Path = "$Folder/ConfigurationAnalyzer/data/configuration-analyzer-data.js"
            $Content = Get-Content -LiteralPath $Path -Raw
            $Data = $Content.Substring($Content.IndexOf('=') + 1).TrimEnd().TrimEnd(';') | ConvertFrom-Json -AsHashtable -DateKind String
            $Data.resolvedGroupTiers = [ordered]@{ (Get-TestId 2) = [ordered]@{ tierName = 'ControlPlane'; tierNames = @('ControlPlane'); displayName = 'CP Admins'; totalMembers = 1; principalCount = 1; privilegedMemberCount = 1; members = @() } }
            "window.ENTRAOPS_CONFIGANALYZER_DATA = $($Data | ConvertTo-Json -Depth 20 -Compress);" | Set-Content -LiteralPath $Path
            (Get-TestConditionalAccessResult $Folder).Status | Should -Be 'Failed'
        }

        It 'does not report the allow-list of a block policy when other enabled policies target it' {
            $Folder = New-TestConditionalAccessData 'ca-allowlist' @(
                # Blocks admin portals for everyone except the Control Plane group, which has its own policy.
                [ordered]@{ Id = 'ca1'; DisplayName = 'Block admin portals'; State = 'enabled'; BuiltInControls = @('block'); IncludeUsers = @('All'); ExcludeGroups = @('CP Admins') }
                [ordered]@{ Id = 'ca2'; DisplayName = 'Privileged access'; State = 'enabled'; BuiltInControls = @('mfa'); IncludeGroups = @('CP Admins') }
                # A grant policy that excludes the same group is still reported.
                [ordered]@{ Id = 'ca3'; DisplayName = 'Require compliant device'; State = 'enabled'; BuiltInControls = @('compliantDevice'); IncludeUsers = @('All'); ExcludeGroups = @('CP Admins') }
            )
            $Result = Get-TestConditionalAccessResult $Folder
            @($Result.Results.Instance.DisplayName) | Should -Be @('Require compliant device')
            $Result.EvaluatedCount | Should -Be 3
        }

        It 'reports the exclusion of a block policy when no other enabled policy targets it' {
            $Folder = New-TestConditionalAccessData 'ca-block' @(
                [ordered]@{ Id = 'ca1'; DisplayName = 'Block legacy authentication'; State = 'enabled'; BuiltInControls = @('block'); IncludeUsers = @('All'); ExcludeGroups = @('CP Admins') }
                [ordered]@{ Id = 'ca2'; DisplayName = 'Require MFA'; State = 'enabled'; BuiltInControls = @('mfa'); IncludeUsers = @('All') }
            )
            $Result = Get-TestConditionalAccessResult $Folder
            @($Result.Results.Instance.DisplayName) | Should -Be @('Block legacy authentication')
            $Result.Results[0].Message | Should -BeLike "*(block access)*no other enabled policy targets them: CP Admins."
        }

        It 'names excluded groups without member data instead of passing them silently' {
            $Folder = New-TestConditionalAccessData 'ca-unresolved' @(
                [ordered]@{ Id = 'ca1'; DisplayName = 'Require MFA'; State = 'enabled'; BuiltInControls = @('mfa'); IncludeUsers = @('All'); ExcludeGroups = @('Unknown exclusion group') }
            )
            $Result = Get-TestConditionalAccessResult $Folder
            $Result.Status | Should -Be 'Passed'
            $Result.Reason | Should -BeLike "1 excluded group(s) could not be resolved to their members*: Unknown exclusion group. Generate the Configuration Analyzer data*"
        }

        It 'does not resolve an excluded group by a display name that several groups share' {
            $Folder = New-TestConditionalAccessData 'ca-ambiguous' @(
                [ordered]@{ Id = 'ca1'; DisplayName = 'Require MFA'; State = 'enabled'; BuiltInControls = @('mfa'); IncludeUsers = @('All'); ExcludeGroups = @('Shared name') }
            )
            # Two groups of this name were resolved: the policy (which names the group) doesn't tell which one it excludes.
            $Path = "$Folder/ConfigurationAnalyzer/data/configuration-analyzer-data.js"
            $Content = Get-Content -LiteralPath $Path -Raw
            $Data = $Content.Substring($Content.IndexOf('=') + 1).TrimEnd().TrimEnd(';') | ConvertFrom-Json -AsHashtable -DateKind String
            $Data.resolvedGroupTiers = [ordered]@{
                '11111111-1111-1111-1111-111111111111' = [ordered]@{ tierName = 'UserAccess'; tierNames = @('UserAccess'); displayName = 'Shared name'; totalMembers = 1; principalCount = 1; privilegedMemberCount = 0; members = @() }
                '22222222-2222-2222-2222-222222222222' = [ordered]@{ tierName = 'ControlPlane'; tierNames = @('ControlPlane'); displayName = 'Shared name'; totalMembers = 1; principalCount = 1; privilegedMemberCount = 1; members = @() }
            }
            "window.ENTRAOPS_CONFIGANALYZER_DATA = $($Data | ConvertTo-Json -Depth 20 -Compress);" | Set-Content -LiteralPath $Path

            $Result = Get-TestConditionalAccessResult $Folder
            $Result.Status | Should -Be 'Passed'
            $Result.ReasonCode | Should -Be 'Note'
            $Result.Reason | Should -BeLike "1 excluded group(s) could not be resolved to their members*1 of them have a display name that several groups or objects share*: Shared name. Rename the groups to tell them apart."
        }

        It 'reports excluded Control Plane roles unless the allow-list of a block policy targets them elsewhere' {
            $Folder = New-TestConditionalAccessData 'ca-roles' @(
                # Management Plane roles are not reported.
                [ordered]@{ Id = 'ca1'; DisplayName = 'Require MFA'; State = 'enabled'; BuiltInControls = @('mfa'); IncludeUsers = @('All'); ExcludeRoles = @('CP long', 'MP role') }
                [ordered]@{ Id = 'ca2'; DisplayName = 'Block admin portals'; State = 'enabled'; BuiltInControls = @('block'); IncludeUsers = @('All'); ExcludeRoles = @('CP short') }
                [ordered]@{ Id = 'ca3'; DisplayName = 'Privileged roles'; State = 'enabled'; BuiltInControls = @('mfa'); IncludeRoles = @('CP short') }
            )
            $Result = Get-TestConditionalAccessResult $Folder
            @($Result.Results.Instance.DisplayName) | Should -Be @('Require MFA')
            $Result.Results[0].Evidence.ExcludedControlPlaneRoles | Should -Be @('CP long')
            $Result.Results[0].Message | Should -BeLike "*users, groups or roles: role 'CP long'."
        }
    }

    It 'compares Privilege History snapshots with a short or missing commit date' {
        $Folder = Join-Path $TestDrive 'history-dates'
        Copy-Item -LiteralPath $script:Root -Destination $Folder -Recurse
        $Object = [ordered]@{ objectId = 'u1'; objectType = 'user'; objectDisplayName = 'User u1'; objectAdminTierLevelName = 'ControlPlane'; roleAssignments = @([ordered]@{ roleAssignmentInstanceId = 'ra1'; roleDefinitionName = 'Role ra1'; roleSystem = 'EntraID'; roleType = 'BuiltInRole'; classification = @(@{ adminTierLevelName = 'ControlPlane' }) }) }
        # A PIM activation of an eligible assignment is no new access.
        $Activated = [ordered]@{ objectId = 'u1'; objectType = 'user'; objectDisplayName = 'User u1'; objectAdminTierLevelName = 'ControlPlane'; roleAssignments = @([ordered]@{ roleAssignmentInstanceId = 'ra1-activated'; roleDefinitionName = 'Role ra1'; roleSystem = 'EntraID'; pimAssignmentType = 'Activated'; roleType = 'BuiltInRole'; classification = @(@{ adminTierLevelName = 'ControlPlane' }) }) }
        $OldObject = [ordered]@{ objectId = 'u0'; objectType = 'user'; objectDisplayName = 'User u0'; objectAdminTierLevelName = 'UserAccess'; roleAssignments = @([ordered]@{ roleAssignmentInstanceId = 'ra0'; roleDefinitionName = 'Role ra0'; roleSystem = 'EntraID'; roleType = 'BuiltInRole'; classification = @(@{ adminTierLevelName = 'UserAccess' }) }) }
        "window.ENTRAOPS_PRIVILEGE_HISTORY_DATA = $(([ordered]@{ snapshots = @(
            [ordered]@{ commitSha = 'new'; commitDate = '2026-10'; totals = @{ tierBreaches = 2 }; objects = @($Object, $Activated) }
            [ordered]@{ commitSha = 'old'; commitDate = ''; totals = @{ tierBreaches = 1 }; objects = @($OldObject) }
            # Thinned out by -MaxDetailedSnapshots: trend numbers only, not compared.
            [ordered]@{ commitSha = 'thin'; commitDate = '2026-09-30T10:00:00Z'; hasDetail = $false; totals = @{ tierBreaches = 9 }; objects = @() }
        ) }) | ConvertTo-Json -Depth 20 -Compress);" | Set-Content -LiteralPath "$Folder/PrivilegeHistory/data/privilege-history-data.js"

        $Results = @(Invoke-EntraOpsFindingEvaluation -Area PrivilegeHistory -ReportPath $Folder -ConfigFilePath (Join-Path $TestDrive 'none.json'))
        # No tier breach and no delegated permission: the tier breach rule passes for the tenant, EO.8003 has nothing in scope.
        $Results.Status | Should -Be @('Failed', 'Passed', 'Skipped')
        ($Results | Where-Object Key -eq 'newControlPlaneAccess').EvaluatedCount | Should -Be 1
        # The snapshot without a date is the older one.
        ($Results | Where-Object Key -eq 'newControlPlaneAccess').Results[0].Message | Should -Be "Control Plane object 'User u1' got the Control Plane role 'Role ra1' (EntraID) between commit old and 2026-10-01."
    }

    It 'fails on every new tier breach, also when the number did not increase, and passes without one' {
        $Folder = Join-Path $TestDrive 'history-no-increase'
        Copy-Item -LiteralPath $script:Root -Destination $Folder -Recurse
        $Breach = [ordered]@{ objectId = 'u2'; objectType = 'user'; objectDisplayName = 'User u2'; objectAdminTierLevelName = 'UserAccess'; roleAssignments = @([ordered]@{ roleAssignmentInstanceId = 'ra9'; roleDefinitionName = 'Role ra9'; roleSystem = 'EntraID'; roleType = 'BuiltInRole'; classification = @(@{ adminTierLevelName = 'ManagementPlane'; service = 'Groups' }) }) }
        $OldBreach = [ordered]@{ objectId = 'u0'; objectType = 'user'; objectDisplayName = 'User u0'; objectAdminTierLevelName = 'UserAccess'; roleAssignments = @([ordered]@{ roleAssignmentInstanceId = 'ra0'; roleDefinitionName = 'Role ra0'; roleSystem = 'EntraID'; roleType = 'BuiltInRole'; classification = @(@{ adminTierLevelName = 'ManagementPlane' }) }) }
        $Write = { param($Objects, $OldObjects) "window.ENTRAOPS_PRIVILEGE_HISTORY_DATA = $(([ordered]@{ snapshots = @(
            [ordered]@{ commitSha = 'new'; commitDate = '2026-10-26T10:00:00Z'; totals = @{ tierBreaches = 1 }; objects = @($Objects) }
            [ordered]@{ commitSha = 'old'; commitDate = '2026-10-19T10:00:00Z'; totals = @{ tierBreaches = 1 }; objects = @($OldObjects) }
        ) }) | ConvertTo-Json -Depth 20 -Compress);" | Set-Content -LiteralPath "$Folder/PrivilegeHistory/data/privilege-history-data.js" }

        # A new tier breach while another one was removed: the number did not increase, the new breach fails.
        & $Write @($Breach) @($OldBreach)
        $Result = Invoke-EntraOpsFindingEvaluation -Area PrivilegeHistory -ReportPath $Folder -ConfigFilePath (Join-Path $TestDrive 'none.json') | Where-Object Key -eq 'tierBreachIncrease'
        $Result.Status | Should -Be 'Failed'
        $Result.Results[0].Message | Should -Be "User Access object 'User u2' holds the Management Plane role 'Role ra9' (EntraID) (services: Groups), a new tier breach between 2026-10-19 and 2026-10-26 (1 tier breaches before, 1 now)."

        # Without a tier breach in the newest snapshot, the tenant passes.
        & $Write @() @($OldBreach)
        $Result = Invoke-EntraOpsFindingEvaluation -Area PrivilegeHistory -ReportPath $Folder -ConfigFilePath (Join-Path $TestDrive 'none.json') | Where-Object Key -eq 'tierBreachIncrease'
        $Result.Status | Should -Be 'Passed'
        $Result.EvaluatedCount | Should -Be 1

        # The same breach in both snapshots passes.
        & $Write @($Breach) @($Breach)
        $Result = Invoke-EntraOpsFindingEvaluation -Area PrivilegeHistory -ReportPath $Folder -ConfigFilePath (Join-Path $TestDrive 'none.json') | Where-Object Key -eq 'tierBreachIncrease'
        $Result.Status | Should -Be 'Passed'
    }

    It 'counts tier breaches like EO.1001 and EO.1003: Tier 1 is no breach of Tier 1, no Microsoft first-party apps, no delegated permissions' {
        $Folder = Join-Path $TestDrive 'history-breach-rules'
        Copy-Item -LiteralPath $script:Root -Destination $Folder -Recurse
        $Assignment = { param($Id, $Tier, $RoleType = 'BuiltInRole') [ordered]@{ roleAssignmentInstanceId = $Id; roleDefinitionName = "Role $Id"; roleSystem = 'EntraID'; roleType = $RoleType; classification = @(@{ adminTierLevelName = $Tier }) } }
        $Objects = @(
            # Workload Plane object with a Management Plane role: both Tier 1, no breach.
            [ordered]@{ objectId = 'wp'; objectType = 'user'; objectDisplayName = 'WP'; objectAdminTierLevelName = 'WorkloadPlane'; roleAssignments = @(& $Assignment 'w1' 'ManagementPlane') }
            # Microsoft first-party service principal with a Control Plane role: not counted.
            [ordered]@{ objectId = 'ms'; objectType = 'serviceprincipal'; objectDisplayName = 'MS-PIM'; objectAdminTierLevelName = 'UserAccess'; isMicrosoftFirstParty = $true; roleAssignments = @(& $Assignment 'm1' 'ControlPlane') }
            # A delegated Control Plane permission: reported by EO.8003, not as a tier breach.
            [ordered]@{ objectId = 'app'; objectType = 'serviceprincipal'; objectDisplayName = 'App'; objectAdminTierLevelName = 'UserAccess'; roleAssignments = @(& $Assignment 'd1' 'ControlPlane' 'Delegated') }
            # A group: only users and service principals hold tier breaches, like EO.1001 and EO.1003.
            [ordered]@{ objectId = 'grp'; objectType = 'group'; objectDisplayName = 'Group'; objectAdminTierLevelName = 'UserAccess'; roleAssignments = @(& $Assignment 'g1' 'ControlPlane') }
        )
        "window.ENTRAOPS_PRIVILEGE_HISTORY_DATA = $(([ordered]@{ snapshots = @(
            [ordered]@{ commitSha = 'new'; commitDate = '2026-10-26T10:00:00Z'; totals = @{ tierBreaches = 4 }; objects = $Objects }
            [ordered]@{ commitSha = 'old'; commitDate = '2026-10-19T10:00:00Z'; totals = @{ tierBreaches = 0 }; objects = @([ordered]@{ objectId = 'x'; objectType = 'user'; objectDisplayName = 'X'; objectAdminTierLevelName = 'UserAccess'; roleAssignments = @(& $Assignment 'x1' 'UserAccess') }) }
        ) }) | ConvertTo-Json -Depth 20 -Compress);" | Set-Content -LiteralPath "$Folder/PrivilegeHistory/data/privilege-history-data.js"

        $Results = @{}
        foreach ($Result in Invoke-EntraOpsFindingEvaluation -Area PrivilegeHistory -ReportPath $Folder -ConfigFilePath (Join-Path $TestDrive 'none.json')) { $Results[$Result.Key] = $Result }
        $Results['tierBreachIncrease'].Status | Should -Be 'Passed'
        # The delegated Control Plane permission is new access by consent (EO.8003), not new Control Plane access (EO.8001).
        @($Results['newControlPlaneAccess'].Results.Instance.DisplayName) | Should -Be @('MS-PIM', 'Group')
        @($Results['newDelegatedPrivilegedPermission'].Results.Instance.DisplayName) | Should -Be @('App')
    }

    It 'compares an unclassified object as User Access for new tier breaches' {
        $Folder = Join-Path $TestDrive 'history-unclassified'
        Copy-Item -LiteralPath $script:Root -Destination $Folder -Recurse
        $Client = { param([object[]]$Roles) [ordered]@{ objectId = 'client'; objectType = 'serviceprincipal'; objectDisplayName = 'Client'; objectAdminTierLevelName = 'Unclassified'; roleAssignments = @(
            foreach ($Role in $Roles) { [ordered]@{ roleAssignmentInstanceId = "i-$($Role.Name)"; roleDefinitionName = $Role.Name; roleSystem = 'ResourceApps'; roleType = 'Application'; classification = @(@{ adminTierLevelName = $Role.Tier; service = 'S' }) } }
        ) } }
        "window.ENTRAOPS_PRIVILEGE_HISTORY_DATA = $(([ordered]@{ snapshots = @(
            [ordered]@{ commitSha = 'new'; commitDate = '2026-10-26T10:00:00Z'; totals = @{ tierBreaches = 2 }; objects = @(& $Client @(@{ Name = 'User.Read.All'; Tier = 'UserAccess' }, @{ Name = 'AuditLog.Read.All'; Tier = 'ManagementPlane' })) }
            [ordered]@{ commitSha = 'old'; commitDate = '2026-10-19T10:00:00Z'; totals = @{ tierBreaches = 1 }; objects = @(& $Client @()) }
        ) }) | ConvertTo-Json -Depth 20 -Compress);" | Set-Content -LiteralPath "$Folder/PrivilegeHistory/data/privilege-history-data.js"

        $Result = Invoke-EntraOpsFindingEvaluation -Area PrivilegeHistory -ReportPath $Folder -ConfigFilePath (Join-Path $TestDrive 'none.json') | Where-Object Key -eq 'tierBreachIncrease'
        # The User Access role of the unclassified object is no tier breach; the Management Plane role is, counted apart
        # like EO.1003 (the tier of the object is unknown), so the rule is skipped with the reason.
        @($Result.Results).Count | Should -Be 0
        $Result.UnclassifiedCount | Should -Be 1
        $Result.UnclassifiedResults[0].Evidence['RoleDefinitionName'] | Should -Be 'AuditLog.Read.All'
        $Result.Status | Should -Be 'Skipped'
        $Result.ReasonCode | Should -Be 'Unclassified'
    }

    It 'reports a new scope of a delegated permission grant that shares the assignment ID of the grant (EO.8003)' {
        $Folder = Join-Path $TestDrive 'history-shared-assignment-id'
        Copy-Item -LiteralPath $script:Root -Destination $Folder -Recurse
        $Grant = { param([string[]]$Scopes, [hashtable]$Property = @{}) $Object = [ordered]@{ objectId = 'app'; objectType = 'serviceprincipal'; objectDisplayName = 'Client'; objectAdminTierLevelName = 'UserAccess'; roleAssignments = @(
            foreach ($Scope in $Scopes) { [ordered]@{ roleAssignmentInstanceId = "grant1-$Scope"; roleAssignmentId = 'grant1'; roleDefinitionName = $Scope; roleSystem = 'ResourceApps'; roleType = 'Delegated'; resourceName = 'Microsoft Graph'; classification = @(@{ adminTierLevelName = $(if ($Scope -eq 'User.Read') { 'UserAccess' } else { 'ManagementPlane' }); service = 'Reader' }) } }
        ) }; foreach ($Key in $Property.Keys) { $Object[$Key] = $Property[$Key] }; $Object }
        $Write = { param($New, $Old) "window.ENTRAOPS_PRIVILEGE_HISTORY_DATA = $(([ordered]@{ snapshots = @(
            [ordered]@{ commitSha = 'new'; commitDate = '2026-10-26T10:00:00Z'; totals = @{ tierBreaches = 2 }; objects = @($New) }
            [ordered]@{ commitSha = 'old'; commitDate = '2026-10-19T10:00:00Z'; totals = @{ tierBreaches = 1 }; objects = @($Old) }
        ) }) | ConvertTo-Json -Depth 20 -Compress);" | Set-Content -LiteralPath "$Folder/PrivilegeHistory/data/privilege-history-data.js" }
        $Evaluate = { $Results = @{}; foreach ($Result in Invoke-EntraOpsFindingEvaluation -Area PrivilegeHistory -ReportPath $Folder -ConfigFilePath (Join-Path $TestDrive 'none.json')) { $Results[$Result.Key] = $Result }; $Results }

        & $Write (& $Grant @('Policy.Read.All', 'AuditLog.Read.All', 'User.Read')) (& $Grant @('Policy.Read.All'))
        $Results = & $Evaluate
        # Delegated permissions are no tier breach (EO.8002) and no new Control Plane access (EO.8001).
        $Results['tierBreachIncrease'].Status | Should -Not -Be 'Failed'
        $Delegated = $Results['newDelegatedPrivilegedPermission']
        $Delegated.Status | Should -Be 'Failed'
        # User.Read is User Access: only Control and Management Plane permissions are in scope.
        $Delegated.EvaluatedCount | Should -Be 2
        @($Delegated.Results.Evidence.RoleDefinitionName) | Should -Be @('AuditLog.Read.All')
        $Delegated.Results[0].Message | Should -Be "'Client' got the delegated Management Plane permission 'AuditLog.Read.All' of 'Microsoft Graph' between 2026-10-19 and 2026-10-26."

        # Microsoft first-party applications are left out, the clients whose permissions the tenant grants by consent are not.
        & $Write (& $Grant @('Policy.Read.All', 'AuditLog.Read.All') @{ isMicrosoftFirstParty = $true }) (& $Grant @('Policy.Read.All') @{ isMicrosoftFirstParty = $true })
        (& $Evaluate)['newDelegatedPrivilegedPermission'].Status | Should -Be 'Skipped'
        & $Write (& $Grant @('Policy.Read.All', 'AuditLog.Read.All') @{ isMicrosoftFirstParty = $true; isMicrosoftConsentClient = $true }) (& $Grant @('Policy.Read.All') @{ isMicrosoftFirstParty = $true; isMicrosoftConsentClient = $true })
        @((& $Evaluate)['newDelegatedPrivilegedPermission'].Results.Evidence.RoleDefinitionName) | Should -Be @('AuditLog.Read.All')
    }

    It 'does not report the PIM activation of an eligible assignment as a new tier breach (EO.8002)' {
        $Folder = Join-Path $TestDrive 'history-activated-breach'
        Copy-Item -LiteralPath $script:Root -Destination $Folder -Recurse
        $Assignment = { param($Id, $PimType) [ordered]@{ roleAssignmentInstanceId = $Id; roleDefinitionName = 'Role ra1'; roleSystem = 'EntraID'; pimAssignmentType = $PimType; roleType = 'BuiltInRole'; classification = @(@{ adminTierLevelName = 'ControlPlane' }) } }
        $User = { param([object[]]$Assignments) [ordered]@{ objectId = 'u1'; objectType = 'user'; objectDisplayName = 'User u1'; objectAdminTierLevelName = 'ManagementPlane'; roleAssignments = $Assignments } }
        # The export lists the activation as its own assignment next to the eligible one.
        "window.ENTRAOPS_PRIVILEGE_HISTORY_DATA = $(([ordered]@{ snapshots = @(
            [ordered]@{ commitSha = 'new'; commitDate = '2026-10-26T10:00:00Z'; totals = @{ tierBreaches = 2 }; objects = @(& $User @((& $Assignment 'ra1' 'Eligible'), (& $Assignment 'ra1-activated' 'Activated'))) }
            [ordered]@{ commitSha = 'old'; commitDate = '2026-10-19T10:00:00Z'; totals = @{ tierBreaches = 1 }; objects = @(& $User @(& $Assignment 'ra1' 'Eligible')) }
        ) }) | ConvertTo-Json -Depth 20 -Compress);" | Set-Content -LiteralPath "$Folder/PrivilegeHistory/data/privilege-history-data.js"

        $Result = Invoke-EntraOpsFindingEvaluation -Area PrivilegeHistory -ReportPath $Folder -ConfigFilePath (Join-Path $TestDrive 'none.json') | Where-Object Key -eq 'tierBreachIncrease'
        $Result.Status | Should -Be 'Passed'
        # The eligible assignment is the tier breach of both snapshots.
        $Result.EvaluatedCount | Should -Be 1
    }

    It 'skips EO.8001, EO.8002 and EO.8003 for Privilege History data without the role type of the assignments' {
        $Folder = Join-Path $TestDrive 'history-no-role-type'
        Copy-Item -LiteralPath $script:Root -Destination $Folder -Recurse
        $Object = [ordered]@{ objectId = 'u1'; objectType = 'user'; objectDisplayName = 'User u1'; objectAdminTierLevelName = 'UserAccess'; roleAssignments = @([ordered]@{ roleAssignmentInstanceId = 'ra1'; roleDefinitionName = 'Role ra1'; roleSystem = 'EntraID'; classification = @(@{ adminTierLevelName = 'ControlPlane' }) }) }
        "window.ENTRAOPS_PRIVILEGE_HISTORY_DATA = $(([ordered]@{ snapshots = @(
            [ordered]@{ commitSha = 'new'; commitDate = '2026-10-26T10:00:00Z'; totals = @{ tierBreaches = 1 }; objects = @($Object) }
            [ordered]@{ commitSha = 'old'; commitDate = '2026-10-19T10:00:00Z'; totals = @{ tierBreaches = 0 }; objects = @() }
        ) }) | ConvertTo-Json -Depth 20 -Compress);" | Set-Content -LiteralPath "$Folder/PrivilegeHistory/data/privilege-history-data.js"
        $Results = @(Invoke-EntraOpsFindingEvaluation -Area PrivilegeHistory -ReportPath $Folder -ConfigFilePath (Join-Path $TestDrive 'none.json'))
        # Without the role type, EO.8001 would report a delegated permission as new Control Plane access.
        foreach ($Key in 'newControlPlaneAccess', 'tierBreachIncrease', 'newDelegatedPrivilegedPermission') {
            $Result = $Results | Where-Object Key -eq $Key
            $Result.Status | Should -Be 'Skipped'
            $Result.ReasonCode | Should -Be 'MissingData'
            $Result.Reason | Should -Match 'role type'
        }
    }

    It 'uses the default parameters without EntraOpsConfig.json' {
        $script:Results['controlPlaneActivationDuration'].Parameters.MaxHours | Should -Be 4
        $script:Results['eligibleAssignmentDuration'].Parameters.MaxDays | Should -Be 365
        # A list stays a list (also empty), so findings.json writes [] instead of null.
        $script:Results['conditionalAccessControlPlaneExclusion'].Parameters.EmergencyAccessAccounts -is [array] | Should -BeTrue
        @($script:Results['conditionalAccessControlPlaneExclusion'].Parameters.EmergencyAccessAccounts).Count | Should -Be 0
    }

    It 'names the role and a readable duration in the messages of the PIM settings' {
        $script:Results['controlPlaneActivationDuration'].Results[0].Message | Should -BeLike "The Control Plane role 'CP long' can be activated for * hours, longer than the configured maximum of 4 hours."
        $script:Results['controlPlaneActivationDuration'].Results[0].Message | Should -Not -Match 'PT\d'
    }

    It 'notes a PIM setting that fails for every evaluated role: the default setting of the tenant' {
        $Result = & (Get-Module EntraOps) {
            $Flow = { param($Id) [pscustomobject]@{ id = "$Id|activation"; path = 'activation'; roleId = $Id; roleName = "Role $Id"; roleTier = 'ControlPlane'; p = @{ AuthenticationContextRequired = $false } } }
            $Context = [pscustomobject]@{ Area = 'TenantGovernance'; SnapshotKey = 'k'; ReportData = [pscustomobject]@{}; Pim = [pscustomobject]@{ Flows = @((& $Flow 'r1'), (& $Flow 'r2')) }; AccessPackage = [pscustomobject]@{ Flows = @() }; ConditionalAccessPolicies = @(); AdministrativeUnits = @() }
            Invoke-EntraOpsFindingRuleSet -Context $Context | Where-Object Key -eq 'controlPlaneActivationAuthContext'
        }
        $Result.Status | Should -Be 'Failed'
        $Result.FailedCount | Should -Be 2
        $Result.ReasonCode | Should -Be 'Note'
        $Result.Reason | Should -BeLike "All 2 evaluated roles fail this check, so the setting was probably never changed from Microsoft's default. PIM keeps one policy per role*Update-MgPolicyRoleManagementPolicyRule*"
    }

    It 'converts ISO 8601 durations to hours' {
        & (Get-Module EntraOps) {
            ConvertFrom-EntraOpsIsoDuration 'PT8H' | Should -Be 8
            ConvertFrom-EntraOpsIsoDuration 'PT1H30M' | Should -Be 1.5
            ConvertFrom-EntraOpsIsoDuration 'P365D' | Should -Be (365 * 24)
            ConvertFrom-EntraOpsIsoDuration 'P1Y' | Should -Be (365 * 24)
            ConvertFrom-EntraOpsIsoDuration 'P' | Should -BeNullOrEmpty
            ConvertFrom-EntraOpsIsoDuration 'eight hours' | Should -BeNullOrEmpty
            Format-EntraOpsIsoDuration 'PT8H' | Should -Be '8 hours'
            Format-EntraOpsIsoDuration 'P1Y' | Should -Be '1 year'
            Format-EntraOpsIsoDuration 'P1DT12H' | Should -Be '1 day 12 hours'
            Format-EntraOpsIsoDuration 'eight hours' | Should -Be 'eight hours'
        }
    }
}
