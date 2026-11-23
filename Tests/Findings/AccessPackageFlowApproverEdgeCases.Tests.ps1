#Requires -Modules Pester

# Approver edge cases of the Access Package Flow (EO.1009, EO.1010) and PIM Request Flow (EO.1008) approver checks:
# approver groups without members, fallback approvers, policies without live data, objects of the same display name,
# and the date of the access drift (EO.6003, EO.6004).
Describe 'Access Package Flow approver edge cases' {
    BeforeAll {
        $script:TestRepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
        Import-Module (Join-Path $script:TestRepositoryRoot 'EntraOps/EntraOps.psd1') -Force -WarningAction SilentlyContinue

        $script:NewIndex = { [System.Collections.Generic.Dictionary[string, object]]::new([System.StringComparer]::Ordinal) }
        # Report data with a Control Plane group (by its access) without members, as Import-EntraOpsReportFindingData builds it.
        function New-EmptyGroupReportData {
            $Objects = & $script:NewIndex
            $Objects['EMPTY'] = [pscustomobject]@{ objectId = 'empty'; objectType = 'group'; displayName = 'Empty Approvers'; tierName = 'ControlPlane'; objectTierName = 'Unclassified'; members = $null }
            $Objects['CP'] = [pscustomobject]@{ objectId = 'cp'; objectType = 'user'; displayName = 'CP Admin'; tierName = 'ControlPlane'; objectTierName = 'ControlPlane'; members = $null }
            $Groups = & $script:NewIndex
            $Groups['EMPTY'] = [pscustomobject]@{ tierName = 'UserAccess'; displayName = 'Empty Approvers'; members = @(); totalMembers = 0; principalCount = 0 }
            [pscustomobject]@{ ObjectTierIndex = $Objects; ResolvedGroupTierIndex = $Groups; AssignmentResolvedGroupTierIndex = (& $script:NewIndex) }
        }
        function New-Flow([string]$Id, [object[]]$Approvers, [string]$TargetTier = 'ControlPlane', [string]$PackageName = 'Package', [bool]$LivePolicy = $true, [object[]]$Assigned = @()) {
            $Flow = [pscustomobject]@{
                id = $Id; name = 'Policy'; accessPackageId = "pk-$Id"; accessPackageName = $PackageName; scopeType = 'SpecificDirectorySubjects'; acceptsRequests = $true
                isApprovalRequired = $true; approvers = $Approvers; targets = @([pscustomobject]@{ resourceName = 'Target'; tier = $TargetTier; originId = "t-$Id" })
                assignedPrincipals = $Assigned; livePolicy = $LivePolicy; checks = $null
            }
            $Flow.checks = & (Get-Module EntraOps) { param($Flow) Get-EntraOpsAccessPackageFlowFlag -Flow $Flow } $Flow
            $Flow
        }
        function New-Approver([string]$Label, [string]$Tier, [string]$ProtectionTier, [bool]$Resolved = $true, [string]$Source = 'direct', [string]$Id = 'id', [bool]$IsBackup = $false, [bool]$NoMembers = $false, [string]$SubjectType = 'groupMembers', [string]$Member = $null) {
            [pscustomobject]@{ label = $Label; tier = $Tier; protectionTier = $ProtectionTier; protectionMember = $Member; resolved = $Resolved; source = $Source; id = $Id; stage = 0; subjectType = $SubjectType; noMembers = $NoMembers; isBackup = $IsBackup }
        }
        function Invoke-Rule($Flows, [string]$Key) {
            & (Get-Module EntraOps) { param($Flows, $Key) Invoke-EntraOpsAccessPackageFlowFindingRule -Context ([pscustomobject]@{ Flows = $Flows; SnapshotKey = 'k'; HasAssignments = $true }) -Rule ([pscustomobject]@{ Key = $Key; Id = 'EO.test' }) } $Flows $Key
        }
    }

    Context 'approver group without members' {
        It 'has no protection tier and is marked NoMembers' {
            $ReportData = New-EmptyGroupReportData
            $Detail = & (Get-Module EntraOps) { param($ReportData) Get-EntraOpsApproverProtectionTier -ReportData $ReportData -Id 'empty' -Hit $ReportData.ObjectTierIndex['EMPTY'] -Detail } $ReportData
            $Detail.Tier | Should -BeNullOrEmpty
            $Detail.NoMembers | Should -BeTrue
            & (Get-Module EntraOps) { param($ReportData) Get-EntraOpsApproverProtectionTier -ReportData $ReportData -Id 'empty' } $ReportData | Should -BeNullOrEmpty
            # A group with a member is not marked.
            $ReportData.ResolvedGroupTierIndex['EMPTY'] = [pscustomobject]@{ tierName = 'ControlPlane'; members = @(@{ id = 'cp' }); totalMembers = 1 }
            (& (Get-Module EntraOps) { param($ReportData) Get-EntraOpsApproverProtectionTier -ReportData $ReportData -Id 'empty' -Detail } $ReportData).NoMembers | Should -BeFalse
        }

        It 'counts as a group approver without a member who can approve (also for the PIM Request Flow context)' {
            $ReportData = New-EmptyGroupReportData
            & (Get-Module EntraOps) { param($ReportData) Test-EntraOpsGroupApproverWithoutMemberData -ReportData $ReportData -Id 'empty' -Hit $ReportData.ObjectTierIndex['EMPTY'] } $ReportData | Should -BeTrue
            # Also when the hit is the (empty) group roll-up itself.
            & (Get-Module EntraOps) { param($ReportData) Test-EntraOpsGroupApproverWithoutMemberData -ReportData $ReportData -Id 'empty' -Hit $ReportData.ResolvedGroupTierIndex['EMPTY'] } $ReportData | Should -BeTrue
            & (Get-Module EntraOps) { param($ReportData) Test-EntraOpsGroupApproverWithoutMemberData -ReportData $ReportData -Id 'cp' -Hit $ReportData.ObjectTierIndex['CP'] } $ReportData | Should -BeFalse
        }

        It 'never falls back to the tier of its access' {
            $Compared = { param($Approver) & (Get-Module EntraOps) { param($Approver) Get-EntraOpsApproverComparedTier -Approver $Approver } $Approver }
            & $Compared ([pscustomobject]@{ tier = 'ControlPlane'; protectionTier = $null; source = 'emptyGroup' }) | Should -BeNullOrEmpty
            & $Compared ([pscustomobject]@{ tier = 'ControlPlane'; protectionTier = $null; source = 'groupWithoutMembers' }) | Should -BeNullOrEmpty
            & $Compared ([pscustomobject]@{ tier = 'ControlPlane'; protectionTier = $null; source = 'direct'; noMembers = $true }) | Should -BeNullOrEmpty
            & $Compared ([pscustomobject]@{ tier = 'ControlPlane'; protectionTier = 'UserAccess'; source = 'direct' }) | Should -Be 'UserAccess'
            # Approvers without a protection tier (older data) keep their tier.
            & $Compared ([pscustomobject]@{ tier = 'ManagementPlane' }) | Should -Be 'ManagementPlane'
        }

        It 'is an unresolved approver of source emptyGroup in the Access Package Flow context' {
            $ReportData = New-EmptyGroupReportData
            $ReportData | Add-Member -NotePropertyName ObjectUpnIndex -NotePropertyValue (& $script:NewIndex)
            $ReportData | Add-Member -NotePropertyName AccessPackageData -NotePropertyValue $null
            $Blob = @{ properties = [ordered]@{
                    Id = 'pol1'; DisplayName = 'Policy'; AccessPackageId = 'Package'
                    RequestorSettings = @{ ScopeType = 'SpecificDirectorySubjects'; AcceptRequests = $true }
                    RequestApprovalSettings = @{ IsApprovalRequired = $true; ApprovalStages = @(@{ PrimaryApprovers = @(
                                @{ odataType = '#microsoft.graph.groupMembers'; Id = 'empty'; IsBackup = $false }
                                @{ odataType = '#microsoft.graph.singleUser'; Id = 'cp'; IsBackup = $true }
                            ) }) }
                } }
            $ReportData | Add-Member -NotePropertyName ConfigurationAnalyzer -NotePropertyValue @{ blobs = @{ h1 = $Blob } }
            $ReportData | Add-Member -NotePropertyName Snapshots -NotePropertyValue @([ordered]@{ key = 'k'; hasDetail = $true; resources = @([ordered]@{ p = 'x/pol1.json'; h = 'h1'; type = 'microsoft.entra.entitlementmanagementaccesspackageassignmentpolicy'; name = 'pol1' }) })
            $Context = & (Get-Module EntraOps) { param($ReportData) New-EntraOpsAccessPackageFlowFindingContext -ReportData $ReportData } $ReportData
            $Approvers = @($Context.Flows[0].approvers)
            $Approvers[0].source | Should -Be 'emptyGroup'
            $Approvers[0].resolved | Should -BeFalse
            $Approvers[0].noMembers | Should -BeTrue
            $Approvers[0].isBackup | Should -BeFalse
            # The fallback approver is carried through and compared.
            $Approvers[1].isBackup | Should -BeTrue
            $Approvers[1].resolved | Should -BeTrue
            $Context.Flows[0].livePolicy | Should -BeFalse
            $Context.Flows[0].approvalTier | Should -Be 'ControlPlane'
        }

        It 'leaves a policy whose only approver is an empty group out of the evaluation and names the group' {
            $Empty = New-Approver -Label 'Members of: Empty Approvers' -Tier 'ControlPlane' -ProtectionTier $null -Resolved $false -Source 'emptyGroup' -NoMembers $true
            $Flow = New-Flow -Id 'p1' -Approvers @($Empty) -PackageName 'CP Package'
            $Flow.checks.approverLowerTier.Applies | Should -BeFalse
            $Results = @(Invoke-Rule @($Flow) 'approverLowerTier')
            @($Results | Where-Object { -not $_.NoteOnly }).Count | Should -Be 0
            $Note = @($Results | Where-Object NoteOnly).Note -join ' '
            $Note | Should -Be "Approver group 'Empty Approvers' of the policy 'CP Package / Policy' has no members, so nobody can approve through it; the policy has no other resolved approver and was not evaluated."
            $Note | Should -Not -BeLike '*no approver resolved*'
        }

        It 'compares a policy with an empty group by its other approvers' {
            $Empty = New-Approver -Label 'Members of: Empty Approvers' -Tier 'ControlPlane' -ProtectionTier $null -Resolved $false -Source 'emptyGroup' -NoMembers $true
            $User = New-Approver -Label 'User: UA User' -Tier 'UserAccess' -ProtectionTier 'UserAccess' -SubjectType 'singleUser'
            $Flow = New-Flow -Id 'p1' -Approvers @($Empty, $User) -PackageName 'CP Package'
            $Flow.checks.approverLowerTier.Failed | Should -BeTrue
            $Results = @(Invoke-Rule @($Flow) 'approverLowerTier')
            (@($Results | Where-Object NoteOnly).Note -join ' ') | Should -Be "Approver group 'Empty Approvers' of the policy 'CP Package / Policy' has no members, so nobody can approve through it; the policy is compared by its other approvers."
        }
    }

    Context 'fallback approvers' {
        It 'compares fallback approvers and marks them in the messages' {
            $Fallback = New-Approver -Label 'Members of: Helpdesk' -Tier 'ControlPlane' -ProtectionTier 'UserAccess' -IsBackup $true -Member 'Regular User'
            $Assigned = @([pscustomobject]@{ resolved = $true; tierName = 'ControlPlane'; name = 'CP Admin' })
            $Flow = New-Flow -Id 'p1' -Approvers @($Fallback) -Assigned $Assigned
            $Flow.checks.approverLowerTier.Text | Should -Be 'Approver(s) are classified at a lower privilege tier (User Access) than the resource being granted (Control Plane): Members of: Helpdesk (fallback) (least protected member: Regular User).'
            $Flow.checks.assignedMorePrivileged.Text | Should -Be "Currently assigned principal(s) have a higher privilege tier (the more privileged of their classification and their access) than this policy's approver(s) are protected for (User Access: Members of: Helpdesk (fallback) (least protected member: Regular User)): CP Admin."
            $Result = @(Invoke-Rule @($Flow) 'approverLowerTier' | Where-Object Failed)[0]
            $Result.Evidence.Approvers[0].IsBackup | Should -BeTrue
        }
    }

    Context 'notes of the policies that were not evaluated' {
        It 'names the access packages without live data apart from the approvers that could not be resolved' {
            $NoId = { New-Approver -Label 'Group members (id not captured by snapshot)' -Tier $null -ProtectionTier $null -Resolved $false -Source $null -Id $null }
            $Flows = @(foreach ($Number in 1..7) { New-Flow -Id "nolive$Number" -Approvers @(& $NoId) -PackageName "Package $Number" -LivePolicy $false })
            $Flows += New-Flow -Id 'unresolved' -Approvers @(New-Approver -Label 'Members of group (g9)' -Tier $null -ProtectionTier $null -Resolved $false -Source $null -Id 'g9') -PackageName 'Other'
            foreach ($Key in 'approverLowerTier', 'assignedMorePrivileged') {
                $Notes = @(Invoke-Rule $Flows $Key | Where-Object NoteOnly | ForEach-Object Note)
                $Notes | Should -Contain '7 assignment policies with approval are not in the live access package data and the Tenant Governance snapshot has no approver IDs, so their approvers could not be resolved and they were not evaluated (generate the Access Package Flow data again with New-EntraOpsAccessPackageFlowData). Access packages: Package 1, Package 2, Package 3, Package 4, Package 5 and 2 more.'
                $Notes | Should -Contain '1 assignment policy with approval has no approver resolved against the Privileged EAM data and was not evaluated.'
            }
        }
    }

    Context 'objects of the same display name' {
        It 'adds the start of the object ID when another known object has the name' {
            $ReportData = [pscustomobject]@{ DisplayNameObjectIds = (& $script:NewIndex) }
            $Ids = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
            $null = $Ids.Add('11111111-1111-1111-1111-111111111111'); $null = $Ids.Add('22222222-2222-2222-2222-222222222222')
            $ReportData.DisplayNameObjectIds['ADELE VANCE'] = $Ids
            $Unique = { param($Name, $Id) & (Get-Module EntraOps) { param($ReportData, $Name, $Id) Get-EntraOpsUniqueDisplayName -ReportData $ReportData -Name $Name -Id $Id } $ReportData $Name $Id }
            & $Unique 'Adele Vance' '11111111-1111-1111-1111-111111111111' | Should -Be 'Adele Vance (11111111)'
            & $Unique 'CP Admin' 'cp' | Should -Be 'CP Admin'
            # Without the index (older report data), the name is kept.
            & (Get-Module EntraOps) { Get-EntraOpsUniqueDisplayName -ReportData ([pscustomobject]@{}) -Name 'Adele Vance' -Id '11111111' } | Should -Be 'Adele Vance'
        }

        It 'knows the names of group members outside the Privileged EAM data and names the least protected member uniquely' {
            $Root = Join-Path $TestDrive 'names'
            $Write = { param($Path, $Variable, $Data) New-Item -ItemType Directory -Path (Split-Path -Parent $Path) -Force | Out-Null; "window.$Variable = $($Data | ConvertTo-Json -Depth 20 -Compress);" | Set-Content -LiteralPath $Path }
            # A classified guest and a regular member account of the same name; only the group lists the member account.
            & $Write "$Root/ConfigurationAnalyzer/data/configuration-analyzer-data.js" 'ENTRAOPS_CONFIG_ANALYZER' ([ordered]@{
                    generatedAt = '2026-11-13T00:00:00Z'; snapshots = @(); blobs = @{}
                    resolvedGroupTiers = @{ 'g1' = @{ tierName = 'ControlPlane'; displayName = 'Approvers'; members = @(@{ id = '11111111-1111-1111-1111-111111111111'; displayName = 'Adele Vance'; objectType = 'user' }); totalMembers = 1 } }
                })
            & $Write "$Root/EamDashboard/data/eam-dashboard-data.js" 'ENTRAOPS_EAM_DASHBOARD' ([ordered]@{
                    generatedAt = '2026-11-13T00:00:00Z'
                    objects = @(@{ objectId = '22222222-2222-2222-2222-222222222222'; objectType = 'user'; objectDisplayName = 'Adele Vance'; objectAdminTierLevelName = 'ManagementPlane'; classification = @(); roleAssignments = @() })
                })
            $ReportData = & (Get-Module EntraOps) { param($Root) Import-EntraOpsReportFindingData -ReportPath $Root } $Root
            $ReportData.DisplayNameObjectIds['ADELE VANCE'].Count | Should -Be 2
            $Detail = & (Get-Module EntraOps) { param($ReportData) Get-EntraOpsApproverProtectionTier -ReportData $ReportData -Id 'g1' -Detail } $ReportData
            $Detail.Member | Should -Be 'Adele Vance (11111111)'
            $Detail.Tier | Should -Be 'UserAccess'
        }
    }

    Context 'date of the access drift' {
        It 'tells the date of the drift report in the message (EO.6003, EO.6004)' {
            $Drift = [System.Collections.Generic.Dictionary[string, object]]::new([System.StringComparer]::Ordinal)
            $Drift['T1'] = [System.Collections.Generic.List[object]]::new()
            # A date the JSON reader converted (older PowerShell) is formatted like ISO text.
            $Drift['T1'].Add(@{ resourceId = 't1'; resourceType = 'group'; catalogId = 'cat'; catalogName = 'Catalog'; total = 2; unauthorized = 1; missing = 1; createdDateTime = [datetime]::new(2026, 11, 8, 3, 3, 43, [System.DateTimeKind]::Utc); details = @() })
            $Flow = [pscustomobject]@{ accessPackageName = 'CP Package'; targets = @([pscustomobject]@{ originId = 't1'; resourceName = 'CP Group'; tier = 'ControlPlane'; catalogId = 'cat' }) }
            $Context = [pscustomobject]@{ Flows = @($Flow); AccessDrift = [pscustomobject]@{ Status = 'collected' }; DriftByResource = $Drift; SnapshotKey = 'k' }
            foreach ($Case in @(@{ Key = 'unauthorizedAccess'; Expected = "'CP Group' (Control Plane) has 1 member(s) or app role assignment(s) without an access package assignment as of 2026-11-08. Access package(s): CP Package." }, @{ Key = 'missingAccess'; Expected = "'CP Group' (Control Plane) misses the membership or app role assignment of 1 access package assignment(s) as of 2026-11-08. Access package(s): CP Package." })) {
                $Result = & (Get-Module EntraOps) { param($Context, $Key) Get-EntraOpsAccessPackageFlowDriftEvaluation -Context $Context -Rule ([pscustomobject]@{ Key = $Key }) } $Context $Case.Key
                $Result.Message | Should -Be $Case.Expected
                $Result.Evidence.ReportDateTime | Should -Be '2026-11-08T03:03:43Z'
            }
        }
    }
}
