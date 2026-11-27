#Requires -Modules Pester

Describe 'Finding data gaps' {
    BeforeAll {
        $script:TestRepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
        Import-Module (Join-Path $script:TestRepositoryRoot 'EntraOps/EntraOps.psd1') -Force -WarningAction SilentlyContinue

        $script:HomeTenant = '11111111-1111-1111-1111-111111111111'
        $script:ManagingTenant = '44444444-4444-4444-4444-444444444444'
        $script:OtherTenant = '55555555-5555-5555-5555-555555555555'

        function Get-TestId([int]$Number) { '{0:d8}-0000-0000-0000-{1:d12}' -f $Number, $Number }
        function New-TestAssignment([string]$Name, [string]$Tier, [hashtable]$Property = @{}) {
            $Assignment = [ordered]@{
                RoleAssignmentId = "ra-$Name"; RoleAssignmentInstanceId = "i-$Name"; RoleDefinitionName = $Name; RoleDefinitionId = "rd-$Name"; RoleType = 'BuiltInRole'
                RoleAssignmentType = 'Direct'; PIMAssignmentType = 'Eligible'; RoleAssignmentScopeId = '/'
                Classification = $(if ($Tier) { @(@{ AdminTierLevelName = $Tier; Service = "S-$Tier" }) } else { @() })
            }
            foreach ($Key in $Property.Keys) { $Assignment[$Key] = $Property[$Key] }
            $Assignment
        }
        function New-TestObject([int]$Number, [string]$Type, [string]$SubType, [string]$Tier, [object[]]$Assignments, [hashtable]$Property = @{}) {
            $Object = [ordered]@{
                ObjectId = (Get-TestId $Number); ObjectType = $Type; ObjectSubType = $SubType; ObjectDisplayName = "Object $Number"; ObjectTenantId = $script:HomeTenant
                ObjectAdminTierLevelName = $Tier; RoleAssignments = $Assignments; OriginType = 'Cloud'; OriginTenantId = $script:HomeTenant; OriginId = (Get-TestId $Number)
            }
            foreach ($Key in $Property.Keys) { $Object[$Key] = $Property[$Key] }
            $Object
        }
        function Write-TestExport([string]$Root, [object[]]$Objects, [string]$System = 'EntraID') {
            New-Item -ItemType Directory -Path "$Root/$System" -Force | Out-Null
            ConvertTo-Json -Depth 10 -InputObject @($Objects) | Set-Content -LiteralPath "$Root/$System/$System.json"
        }
        function Invoke-TestEvaluation([string]$Root, [hashtable]$Config = @{}) {
            $ConfigPath = Join-Path $Root 'EntraOpsConfig.json'
            ConvertTo-Json -Depth 5 -InputObject $Config | Set-Content -LiteralPath $ConfigPath
            $Results = @{}
            foreach ($Result in Invoke-EntraOpsFindingEvaluation -Area PrivilegedEAM, PrivilegedAssets -ImportPath $Root -ReportPath (Join-Path $TestDrive 'noreports') -ConfigFilePath $ConfigPath -WarningAction SilentlyContinue) { $Results[$Result.RuleId] = $Result }
            $Results
        }
        $script:ControlPlane = { New-TestAssignment 'Global Administrator' 'ControlPlane' }
    }

    Context 'groups whose origin is unknown' {
        It 'notes the groups without origin in EO.4010 (all groups) and EO.4011 (Control Plane groups), and still evaluates the users' {
            $Root = Join-Path $TestDrive 'origin'
            Write-TestExport $Root @(
                # Without originTenantInfo (Group-XTenantIdentitySync.Read.All missing): no origin.
                New-TestObject 1 'group' 'Role-assignable' 'ControlPlane' @(& $script:ControlPlane) @{ ObjectDisplayName = 'Tier0 Admins'; OriginType = $null; OriginTenantId = $null; OriginId = $null }
                New-TestObject 2 'group' 'Security' 'ManagementPlane' @(New-TestAssignment 'User Administrator' 'ManagementPlane') @{ ObjectDisplayName = 'Helpdesk'; OriginType = $null; OriginTenantId = $null; OriginId = $null }
                # A group with origin and a local user.
                New-TestObject 3 'group' 'Role-assignable' 'ControlPlane' @(& $script:ControlPlane)
                New-TestObject 4 'user' 'Member' 'ControlPlane' @(& $script:ControlPlane)
            )
            $Results = Invoke-TestEvaluation $Root

            $Rule = $Results['EO.4011']
            # A note, not a skip: the users and the groups are still evaluated.
            $Rule.Status | Should -Be 'Passed'
            $Rule.EvaluatedCount | Should -Be 3
            $Rule.ReasonCode | Should -Be 'Note'
            $Rule.Reason | Should -Be 'The origin of 1 group(s) with Control Plane access (Tier0 Admins) is unknown (permission Group-XTenantIdentitySync.Read.All missing?); groups synchronized from other tenants are not recognized.'
            $Inventory = $Results['EO.4010']
            $Inventory.Status | Should -Be 'Passed'
            $Inventory.Reason | Should -Be 'The origin of 2 group(s) with role assignments (Helpdesk, Tier0 Admins) is unknown (permission Group-XTenantIdentitySync.Read.All missing?); groups synchronized from other tenants are not recognized.'

            @($Rule.DataGaps.Code) | Should -Be @('GroupOriginUnknown')
            @($Inventory.DataGaps.Code) | Should -Be @('GroupOriginUnknown')
            $Rule.DataGaps[0].Count | Should -Be 2
            @($Rule.DataGaps[0].RuleIds) | Should -Be @('EO.4010', 'EO.4011')
            @($Results['EO.3001'].DataGaps).Count | Should -Be 0
        }

        It 'names an export without any origin as data of EntraOps before 1.2.0' {
            $Root = Join-Path $TestDrive 'legacy'
            Write-TestExport $Root @(
                New-TestObject 1 'group' 'Role-assignable' 'ControlPlane' @(& $script:ControlPlane) @{ OriginType = $null; OriginTenantId = $null; OriginId = $null }
                New-TestObject 2 'user' 'Member' 'ControlPlane' @(& $script:ControlPlane) @{ OriginType = $null; OriginTenantId = $null; OriginId = $null }
            )
            (Invoke-TestEvaluation $Root)['EO.4011'].Reason | Should -BeLike '*is unknown (Privileged EAM data of EntraOps before 1.2.0?); groups synchronized from other tenants are not recognized.'
        }

        It 'adds no note and no data gap when every group has an origin' {
            $Root = Join-Path $TestDrive 'known'
            Write-TestExport $Root @(
                New-TestObject 1 'group' 'Role-assignable' 'ControlPlane' @(& $script:ControlPlane)
                New-TestObject 2 'user' 'Member' 'ControlPlane' @(& $script:ControlPlane)
            )
            $Results = Invoke-TestEvaluation $Root
            foreach ($Id in 'EO.4010', 'EO.4011') {
                $Results[$Id].Reason | Should -BeNullOrEmpty
                @($Results[$Id].DataGaps).Count | Should -Be 0
            }
        }
    }

    Context 'groups of other tenants whose members were not collected' {
        BeforeAll {
            # A remote group of Tenant Governance with Control Plane access, one with Management Plane access only.
            function New-TestRemoteGroup([int]$Number, [string]$Name, [string]$Tenant, [string]$Tier = 'ControlPlane', [hashtable]$Property = @{}) {
                $Assignment = if ($Tier -eq 'ControlPlane') { & $script:ControlPlane } else { New-TestAssignment 'Exchange Administrator' $Tier }
                $Values = @{ ObjectDisplayName = $Name; ObjectTenantId = $Tenant; OutsideOfHomeTenant = $true; OriginType = 'TenantGovernance'; OriginTenantId = $Tenant }
                foreach ($Key in $Property.Keys) { $Values[$Key] = $Property[$Key] }
                New-TestObject $Number 'group' 'Role-assignable' $Tier @($Assignment) $Values
            }
            # Local users, so the home tenant is known.
            $script:LocalUsers = @(
                New-TestObject 20 'user' 'Member' 'ControlPlane' @(& $script:ControlPlane)
                New-TestObject 21 'user' 'Member' 'ControlPlane' @(& $script:ControlPlane)
            )
        }

        It 'names the groups without ManagingTenantId and how to collect their members (EO.4011, EO.4010)' {
            $Root = Join-Path $TestDrive 'remote-unconfigured'
            Write-TestExport $Root (@(
                    New-TestRemoteGroup 1 'pag - Global Administrator' $script:ManagingTenant
                    New-TestRemoteGroup 2 'pag - Exchange Administrator' $script:ManagingTenant 'ManagementPlane'
                ) + $script:LocalUsers)
            $Results = Invoke-TestEvaluation $Root

            $Rule = $Results['EO.4011']
            $Rule.Status | Should -Be 'Failed'
            # The note of Tenant Governance stays first.
            $Rule.Reason | Should -BeLike '1 of the reported principals have access through Tenant Governance.*'
            $Rule.Reason | Should -BeLike '*The members of 1 group(s) of other tenants with Control Plane access are not in the Privileged EAM data, so their access is not evaluated: pag - Global Administrator. ManagingTenantId is not set in EntraOpsConfig.json, and EntraOps reads the members of groups of other tenants only in the managing tenant: set it to the governing tenant and collect the Privileged EAM data again.'
            $Results['EO.4010'].Reason | Should -BeLike 'The members of 2 group(s) of other tenants with Control Plane or Management Plane access are not in the Privileged EAM data, so their access is not evaluated: pag - Exchange Administrator, pag - Global Administrator. ManagingTenantId is not set*'

            $Gap = @($Rule.DataGaps | Where-Object Code -EQ 'RemoteGroupMembersMissing')
            $Gap.Count | Should -Be 1
            $Gap[0].Count | Should -Be 2
            @($Gap[0].RuleIds) | Should -Be @('EO.4010', 'EO.4011')
        }

        It 'tells groups of another tenant than the managing tenant apart, and accepts the groups of the managing tenant' {
            $Root = Join-Path $TestDrive 'remote-configured'
            Write-TestExport $Root (@(
                    # Data without the mark: a group of the managing tenant counts as expanded (it may be empty).
                    New-TestRemoteGroup 1 'pag - Global Administrator' $script:ManagingTenant
                    New-TestRemoteGroup 2 'Remote Global Admin' $script:OtherTenant
                ) + $script:LocalUsers)
            $Results = Invoke-TestEvaluation $Root @{ ManagingTenantId = $script:ManagingTenant }
            $Results['EO.4011'].Reason | Should -BeLike "*The members of 1 group(s) of other tenants with Control Plane access are not in the Privileged EAM data, so their access is not evaluated: Remote Global Admin. The group belongs to a tenant other than the managing tenant $script:ManagingTenant, where EntraOps cannot read members: review its members in its tenant."
            $Results['EO.4011'].Reason | Should -Not -BeLike '*pag - Global Administrator,*'
        }

        It 'reads the mark of the export: a failed expansion is named, an expanded group is not' {
            $Root = Join-Path $TestDrive 'remote-marked'
            Write-TestExport $Root (@(
                    New-TestRemoteGroup 1 'pag - Global Administrator' $script:ManagingTenant 'ControlPlane' @{ CrossTenantMembersExpanded = $false }
                    New-TestRemoteGroup 2 'pag - Security Administrator' $script:ManagingTenant 'ControlPlane' @{ CrossTenantMembersExpanded = $true }
                    # The mark wins over the heuristic: no member, but expanded (an empty group).
                    New-TestRemoteGroup 3 'Remote Global Admin' $script:OtherTenant 'ControlPlane' @{ CrossTenantMembersExpanded = $true }
                ) + $script:LocalUsers)
            $Reason = (Invoke-TestEvaluation $Root @{ ManagingTenantId = $script:ManagingTenant })['EO.4011'].Reason
            # After the note of the managing tenant, which names its groups.
            $Reason | Should -BeLike '2 principal(s) of the managing tenant *'
            $Reason.Substring($Reason.IndexOf('The members of')) | Should -Be 'The members of 1 group(s) of other tenants with Control Plane access are not in the Privileged EAM data, so their access is not evaluated: pag - Global Administrator. The group belongs to the managing tenant, but its members could not be read during the collection (see the warnings of the Privileged EAM collection).'
        }

        It 'counts a group without the mark as expanded when a member holds a role through it' {
            $Root = Join-Path $TestDrive 'remote-members'
            $GroupId = Get-TestId 1
            Write-TestExport $Root (@(
                    New-TestRemoteGroup 1 'pag - Global Administrator' $script:ManagingTenant
                    New-TestObject 30 'user' 'Member' 'ControlPlane' @(New-TestAssignment 'Global Administrator' 'ControlPlane' @{ RoleAssignmentType = 'Transitive'; TransitiveByObjectId = $GroupId; TransitiveByObjectDisplayName = 'pag - Global Administrator' }) @{ ObjectTenantId = $script:ManagingTenant; OriginType = 'TenantGovernance'; OriginTenantId = $script:ManagingTenant }
                ) + $script:LocalUsers)
            $Results = Invoke-TestEvaluation $Root
            $Results['EO.4011'].Reason | Should -Not -BeLike '*are not in the Privileged EAM data*'
            @($Results['EO.4011'].DataGaps | Where-Object Code -EQ 'RemoteGroupMembersMissing').Count | Should -Be 0
        }

        It 'warns in the collection about the privileged groups whose members were not read' {
            $Warning = & (Get-Module EntraOps) {
                $Entries = @(
                    [pscustomobject]@{ ObjectId = 'g1'; ObjectType = 'group'; ObjectTenantId = 't-managing' }
                    [pscustomobject]@{ ObjectId = 'g2'; ObjectType = 'group'; ObjectTenantId = 't-managing' }
                    [pscustomobject]@{ ObjectId = 'g3'; ObjectType = 'group'; ObjectTenantId = 't-other' }
                    [pscustomobject]@{ ObjectId = 'g4'; ObjectType = 'group'; ObjectTenantId = 't-other' }
                )
                $Classification = @(
                    [pscustomobject]@{ ObjectId = 'g1'; RoleAssignmentType = 'Direct'; Classification = @([pscustomobject]@{ AdminTierLevelName = 'ControlPlane' }) }
                    [pscustomobject]@{ ObjectId = 'g2'; RoleAssignmentType = 'Direct'; Classification = @([pscustomobject]@{ AdminTierLevelName = 'ControlPlane' }) }
                    [pscustomobject]@{ ObjectId = 'g3'; RoleAssignmentType = 'Direct'; Classification = @([pscustomobject]@{ AdminTierLevelName = 'ManagementPlane' }) }
                    # User Access only: no privileged role.
                    [pscustomobject]@{ ObjectId = 'g4'; RoleAssignmentType = 'Direct'; Classification = @([pscustomobject]@{ AdminTierLevelName = 'UserAccess' }) }
                )
                $Details = @{ g1 = [pscustomobject]@{ ObjectDisplayName = 'pag - Global Administrator' }; g3 = [pscustomobject]@{ ObjectDisplayName = 'Remote Exchange Admins' } }
                # g2 was expanded.
                @{
                    Unconfigured = Get-EntraOpsCrossTenantExpansionWarning -CrossTenantGroupEntries $Entries -MembersExpanded @{ g1 = $false; g2 = $true; g3 = $false; g4 = $false } -RbacClassification $Classification -ObjectDetailsCache $Details -ManagingTenantId ''
                    Configured   = Get-EntraOpsCrossTenantExpansionWarning -CrossTenantGroupEntries $Entries -MembersExpanded @{ g1 = $true; g2 = $true; g3 = $false; g4 = $false } -RbacClassification $Classification -ObjectDetailsCache $Details -ManagingTenantId 't-managing'
                    None         = Get-EntraOpsCrossTenantExpansionWarning -CrossTenantGroupEntries $Entries -MembersExpanded @{ g1 = $true; g2 = $true; g3 = $true; g4 = $false } -RbacClassification $Classification -ObjectDetailsCache $Details -ManagingTenantId 't-managing'
                }
            }
            $Warning.Unconfigured | Should -Be "The members of 2 group(s) of other tenants with Control or Management Plane roles were not collected, so their access is missing in the Privileged EAM data and its findings (EO.4010, EO.4011): 'pag - Global Administrator' (tenant t-managing), 'Remote Exchange Admins' (tenant t-other). Set ManagingTenantId in EntraOpsConfig.json to the governing tenant (Tenant Governance) and collect again to read the members of its groups."
            $Warning.Configured | Should -BeLike "*: 'Remote Exchange Admins' (tenant t-other). Members are read only in the managing tenant 't-managing'*"
            $Warning.None | Should -BeNullOrEmpty
        }
    }

    Context 'Object Classification File and findings.json' {
        It 'reports an enabled Object Classification File that does not exist, and saves the data gaps in findings.json' {
            $Root = Join-Path $TestDrive 'classification-file'
            Write-TestExport $Root @(
                New-TestObject 1 'group' 'Role-assignable' 'ControlPlane' @(& $script:ControlPlane) @{ OriginType = $null; OriginTenantId = $null; OriginId = $null }
                New-TestObject 2 'user' 'Member' 'ControlPlane' @(& $script:ControlPlane)
            )
            $Config = @{ ObjectClassificationFile = @{ Enabled = $true; FilePath = './Classification/ObjectClassification.json' } }
            $Results = Invoke-TestEvaluation $Root $Config
            $Gap = @($Results['EO.2001'].DataGaps | Where-Object Code -EQ 'ObjectClassificationFileMissing')
            $Gap.Count | Should -Be 1
            $Gap[0].Message | Should -BeLike 'The Object Classification File is enabled (ObjectClassificationFile of EntraOpsConfig.json), but ./Classification/ObjectClassification.json does not exist*'
            @($Gap[0].RuleIds) | Should -Contain 'EO.2001'
            @($Gap[0].RuleIds) | Should -Contain 'EO.1002'
            @($Results['EO.4011'].DataGaps | Where-Object Code -EQ 'ObjectClassificationFileMissing').Count | Should -Be 0

            $Out = Join-Path $Root 'out'
            $Results.Values | Where-Object { $_.RuleId -in 'EO.2001', 'EO.4010', 'EO.4011', 'EO.3001' } | Sort-Object RuleId | Save-EntraOpsFindingJson -ExportFolder $Out -ConfigFilePath (Join-Path $Root 'EntraOpsConfig.json') -TenantId 't' -TenantName 't' 6> $null
            $Saved = Get-Content -LiteralPath "$Out/findings.json" -Raw | ConvertFrom-Json
            @($Saved.DataGaps.Code) | Should -Be @('GroupOriginUnknown', 'ObjectClassificationFileMissing')
            $SavedGap = @($Saved.DataGaps | Where-Object Code -EQ 'ObjectClassificationFileMissing')[0]
            @($SavedGap.RuleIds) | Should -Be @('EO.2001')
            $SavedGap.Count | Should -Be 1
            @(@($Saved.DataGaps | Where-Object Code -EQ 'GroupOriginUnknown')[0].RuleIds) | Should -Be @('EO.4010', 'EO.4011')
            # The rules keep their fields: the data gaps are listed once, at the top.
            $Saved.Rules[0].PSObject.Properties['DataGaps'] | Should -BeNullOrEmpty
            (Get-Content -LiteralPath "$Out/findings.js" -Raw) | Should -BeLike '*"DataGaps":`[{"Code":"GroupOriginUnknown"*'
        }

        It 'reports no data gap for an existing or disabled Object Classification File, and saves an empty list' {
            $Root = Join-Path $TestDrive 'classification-present'
            Write-TestExport $Root @(New-TestObject 2 'user' 'Member' 'ControlPlane' @(& $script:ControlPlane))
            New-Item -ItemType Directory -Path "$Root/Classification" -Force | Out-Null
            '[]' | Set-Content -LiteralPath "$Root/Classification/ObjectClassification.json"
            # The user has no PAW and no work account: those gaps are tested on their own.
            $AttributeGaps = 'PawAssociationNotPopulated', 'WorkAccountNotPopulated'
            $Present = Invoke-TestEvaluation $Root @{ ObjectClassificationFile = @{ Enabled = $true; FilePath = './Classification/ObjectClassification.json' } }
            @($Present.Values | ForEach-Object { $_.DataGaps } | Where-Object { $_.Code -notin $AttributeGaps }).Count | Should -Be 0
            $Disabled = Invoke-TestEvaluation $Root @{ ObjectClassificationFile = @{ Enabled = $false; FilePath = './Classification/Missing.json' } }
            @($Disabled.Values | ForEach-Object { $_.DataGaps } | Where-Object { $_.Code -notin $AttributeGaps }).Count | Should -Be 0

            $Out = Join-Path $Root 'out'
            foreach ($Result in $Disabled.Values) { $Result.DataGaps = @($Result.DataGaps | Where-Object { $_.Code -notin $AttributeGaps }) }
            $Disabled.Values | Save-EntraOpsFindingJson -ExportFolder $Out -ConfigFilePath (Join-Path $Root 'EntraOpsConfig.json') -TenantId 't' -TenantName 't' 6> $null
            $Json = Get-Content -LiteralPath "$Out/findings.json" -Raw
            $Json | Should -BeLike '*"DataGaps": `[`]*'
            # Rule results of earlier versions (without DataGaps) are saved as well.
            $Legacy = [pscustomobject]@{ RuleId = 'EO.3001'; Key = 'permanentControlPlaneAssignment'; Area = 'PrivilegedEAM'; Status = 'Passed'; Results = @() }
            $Legacy | Save-EntraOpsFindingJson -ExportFolder $Out -ConfigFilePath (Join-Path $Root 'EntraOpsConfig.json') -TenantId 't' -TenantName 't' 6> $null
            @((Get-Content -LiteralPath "$Out/findings.json" -Raw | ConvertFrom-Json).DataGaps).Count | Should -Be 0
        }
    }

    Context 'app roles the resource application no longer offers (EO.2002)' {
        It 'says why an unresolved app role has no classification and to remove the assignment' {
            $Root = Join-Path $TestDrive 'retired-app-role'
            Write-TestExport $Root @(
                New-TestObject 1 'serviceprincipal' 'ManagedIdentity' 'ControlPlane' @(
                    New-TestAssignment '' $null @{ RoleDefinitionName = $null; RoleDefinitionId = 'f20584af-9290-4153-9280-ff8bb2c0ea7f'; RoleType = 'Application'; RoleAssignmentScopeName = 'Microsoft Graph'; PIMAssignmentType = 'Permanent' }
                    New-TestAssignment 'User.Test' $null @{ RoleType = 'Application'; RoleAssignmentScopeName = 'My API'; PIMAssignmentType = 'Permanent' }
                    # Default access to an application without app roles: valid, not retired.
                    New-TestAssignment '' $null @{ RoleAssignmentId = 'ra-default'; RoleAssignmentInstanceId = 'i-default'; RoleDefinitionName = $null; RoleDefinitionId = '00000000-0000-0000-0000-000000000000'; RoleType = 'Application'; RoleAssignmentScopeName = 'Roleless API'; PIMAssignmentType = 'Permanent' }
                ) @{ ObjectDisplayName = 'automation-msi'; OriginType = 'InternalApplication' }
            ) 'ResourceApps'
            $Rule = (Invoke-TestEvaluation $Root)['EO.2002']
            $Rule.Status | Should -Be 'Failed'
            $Retired = @($Rule.Results | Where-Object { $_.Message -like "'unresolved app role*" })[0]
            $Retired.Message | Should -Be "'unresolved app role f20584af-9290-4153-9280-ff8bb2c0ea7f of Microsoft Graph' (ResourceApps) of 'automation-msi' has no tier classification. The resource application no longer offers this app role (for example, it was removed from the application or retired by Microsoft), so no classification can match it: remove the assignment."
            # The detail without the object keeps the explanation.
            $Retired.Detail | Should -Be "'unresolved app role f20584af-9290-4153-9280-ff8bb2c0ea7f of Microsoft Graph' (ResourceApps) has no tier classification. The resource application no longer offers this app role (for example, it was removed from the application or retired by Microsoft), so no classification can match it: remove the assignment."
            # An app role with a name is a classification gap, without the explanation.
            @($Rule.Results | Where-Object { $_.Message -like "'User.Test'*" })[0].Message | Should -Be "'User.Test' (ResourceApps) of 'automation-msi' has no tier classification."
            # The default access is not called retired and its removal is not recommended.
            $Default = @($Rule.Results | Where-Object { $_.Message -like '*00000000-0000-0000-0000-000000000000*' })
            $Default.Count | Should -Be 1
            $Default[0].Message | Should -Not -Match 'no longer offers|remove the assignment'
        }
    }

    Context 'classification coverage and account attributes' {
        It 'notes a low classification coverage of the privileged users and service principals on the tier rules' {
            $Root = Join-Path $TestDrive 'coverage-low'
            Write-TestExport $Root @(
                New-TestObject 1 'user' 'Member' 'ControlPlane' @(& $script:ControlPlane)
                New-TestObject 2 'user' 'Member' 'Unclassified' @(& $script:ControlPlane)
                New-TestObject 3 'serviceprincipal' 'Application' 'Unclassified' @(New-TestAssignment 'User Administrator' 'ManagementPlane')
            )
            $Results = Invoke-TestEvaluation $Root
            # EO.1002: the tier rule of the Privileged Assets area (the tests evaluate PrivilegedEAM and PrivilegedAssets).
            $Gap = @($Results['EO.1002'].DataGaps | Where-Object Code -eq 'ObjectTierCoverageLow')
            $Gap.Count | Should -Be 1
            $Gap[0].Message | Should -BeLike '2 of 3 users and service principals of the tenant with Control or Management Plane access have no classification*'
            @($Results['EO.2001'].DataGaps.Code) | Should -Contain 'ObjectTierCoverageLow'
            @($Results['EO.4002'].DataGaps.Code) | Should -Not -Contain 'ObjectTierCoverageLow'
        }

        It 'raises no coverage gap when most privileged principals are classified' {
            $Root = Join-Path $TestDrive 'coverage-ok'
            Write-TestExport $Root @(
                New-TestObject 1 'user' 'Member' 'ControlPlane' @(& $script:ControlPlane)
                New-TestObject 2 'user' 'Member' 'ControlPlane' @(& $script:ControlPlane)
                New-TestObject 3 'serviceprincipal' 'Application' 'Unclassified' @(New-TestAssignment 'User Administrator' 'ManagementPlane')
            )
            $Results = Invoke-TestEvaluation $Root
            @($Results.Values | ForEach-Object { $_.DataGaps } | Where-Object Code -eq 'ObjectTierCoverageLow').Count | Should -Be 0
        }

        It 'notes PAW and work account attributes that no user of the tenant has, and not when one user has them' {
            $Root = Join-Path $TestDrive 'attributes-missing'
            Write-TestExport $Root @(New-TestObject 1 'user' 'Member' 'ControlPlane' @(& $script:ControlPlane))
            $Results = Invoke-TestEvaluation $Root
            @($Results['EO.4008'].DataGaps.Code) | Should -Contain 'PawAssociationNotPopulated'
            @($Results['EO.4009'].DataGaps.Code) | Should -Contain 'WorkAccountNotPopulated'
            ($Results['EO.4009'].DataGaps | Where-Object Code -eq 'WorkAccountNotPopulated').Message | Should -BeLike 'No user of the tenant has an associated work account*so all 1 privileged user(s) in the scope of EO.4009 are all reported*'

            $Root = Join-Path $TestDrive 'attributes-present'
            Write-TestExport $Root @(
                New-TestObject 1 'user' 'Member' 'ControlPlane' @(& $script:ControlPlane)
                New-TestObject 2 'user' 'Member' 'ManagementPlane' @(New-TestAssignment 'User Administrator' 'ManagementPlane') @{ AssociatedWorkAccount = @('worker@contoso.com') }
            )
            $Results = Invoke-TestEvaluation $Root
            @($Results['EO.4009'].DataGaps.Code) | Should -Not -Contain 'WorkAccountNotPopulated'
        }

        It 'does not report users of other tenants for a missing PAW or work account' {
            $Root = Join-Path $TestDrive 'attributes-foreign'
            Write-TestExport $Root @(
                New-TestObject 1 'user' 'Member' 'ControlPlane' @(& $script:ControlPlane) @{ ObjectDisplayName = 'Synchronized admin'; OriginType = 'CrossTenantSync'; OriginTenantId = $script:OtherTenant }
                New-TestObject 2 'user' 'Member' 'ControlPlane' @(& $script:ControlPlane) @{ ObjectDisplayName = 'Local admin' }
            )
            $Results = Invoke-TestEvaluation $Root
            @($Results['EO.4008'].Results.Instance.DisplayName) | Should -Be @('Local admin')
            @($Results['EO.4009'].Results.Instance.DisplayName) | Should -Be @('Local admin')
        }
    }
}
