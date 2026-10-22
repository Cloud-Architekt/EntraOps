#Requires -Modules Pester

BeforeAll {
    $script:TestRepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
    Import-Module (Join-Path $script:TestRepositoryRoot 'EntraOps') -Force
    $script:PreviousDefaultFolderClassification = $Global:DefaultFolderClassification
    $script:PreviousTenantNameContext = $Global:TenantNameContext

    $script:TenantId = '99999999-9999-9999-9999-999999999999'
    $script:UserId = '33333333-3333-3333-3333-333333333333'
    $script:DeletedId = '44444444-4444-4444-4444-444444444444'
    $script:Yesterday = [datetime]::UtcNow.Date.AddDays(-1).ToString('yyyy-MM-dd')

    function New-ExposureManagementBlock {
        param(
            [string]$Status = 'Succeeded',
            [string]$Date = $script:Yesterday,
            [string]$TenantId = $script:TenantId,
            [string]$CriticalityLevel = '<1',
            [int]$QueryVersion = 1,
            [object[]]$Results = @()
        )
        [ordered]@{
            Status                   = $Status
            LastSuccessfulQueryDate  = $Date
            TenantId                 = $TenantId
            ExposureCriticalityLevel = $CriticalityLevel
            QueryVersion             = $QueryVersion
            Results                  = @($Results)
        }
    }

    function New-XspmResult {
        param([string]$ObjectId = $script:UserId, [string[]]$Targets = @('Global Administrator'))
        [ordered]@{
            ObjectId             = $ObjectId
            ObjectType           = 'user'
            ObjectDisplayName    = "Admin $ObjectId"
            ClassificationReason = @($Targets | ForEach-Object { [ordered]@{ EdgeLabel = 'has role on'; TargetNodeName = $_ } })
        }
    }

    function Set-ReasoningFile {
        param([string]$Path, [object]$Content)
        $Content | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $Path
    }

    function New-GraphFailure {
        param([int]$StatusCode)
        $Exception = [System.InvalidOperationException]::new("Microsoft Graph query '/beta/security/runHuntingQuery' failed: Response status code does not indicate success: $StatusCode.")
        $Exception.Data['StatusCode'] = $StatusCode
        $Exception
    }

    function New-ResolvedUser {
        param([string]$ObjectId)
        [pscustomobject]@{
            ObjectId                      = $ObjectId
            ObjectType                    = 'User'
            ObjectSubType                 = 'Member'
            ObjectDisplayName             = "Admin $ObjectId"
            ObjectSignInName              = 'admin@contoso.com'
            ObjectTenantId                = $script:TenantId
            AssignedAdministrativeUnits   = $null
            RestrictedManagementByRAG     = $false
            RestrictedManagementByAadRole = $true
            RestrictedManagementByRMAU    = $false
            OwnedDevices                  = $null
            AssociatedPawDevice           = $null
        }
    }

    function Invoke-ExposureManagementObjects {
        param([string]$BaselineFile, [object]$Sources = 'PrivilegedEdgesFromExposureManagement')
        $Result = @{}
        $Objects = @(Get-EntraOpsClassificationControlPlaneObjects -PrivilegedObjectClassificationSource $Sources `
                -EntraOpsEamFolder '' -TenantId $script:TenantId -EnableParallelProcessing $false `
                -ExposureManagementBaselineFile $BaselineFile -ExposureManagementResult $Result -WarningAction SilentlyContinue 6>$null)
        [pscustomobject]@{ Objects = $Objects; Result = $Result }
    }
}

AfterAll {
    $Global:DefaultFolderClassification = $script:PreviousDefaultFolderClassification
    $Global:TenantNameContext = $script:PreviousTenantNameContext
}

Describe 'Get-EntraOpsExposureManagementBaseline' {
    BeforeEach {
        $script:File = Join-Path $TestDrive 'ScopeReasoning_ControlPlane.json'
        Remove-Item -LiteralPath $script:File -ErrorAction SilentlyContinue
    }

    It 'has nothing to protect without a previous file' {
        $Baseline = InModuleScope EntraOps -Parameters @{ File = $script:File; TenantId = $script:TenantId } {
            param($File, $TenantId)
            Get-EntraOpsExposureManagementBaseline -Path $File -TenantId $TenantId -ExposureCriticalityLevel '<1' -QueryVersion 1
        }
        $Baseline.FileExists | Should -BeFalse
        $Baseline.IsValid | Should -BeFalse
        $Baseline.HasUnusablePreviousResults | Should -BeFalse
    }

    It 'returns the recorded results of a successful query' {
        Set-ReasoningFile $script:File @{ ExposureManagement = (New-ExposureManagementBlock -Results @((New-XspmResult))) }
        $Baseline = InModuleScope EntraOps -Parameters @{ File = $script:File; TenantId = $script:TenantId } {
            param($File, $TenantId)
            Get-EntraOpsExposureManagementBaseline -Path $File -TenantId $TenantId -ExposureCriticalityLevel '<1' -QueryVersion 1
        }
        $Baseline.IsValid | Should -BeTrue
        $Baseline.LastSuccessfulQueryDate.ToString('yyyy-MM-dd') | Should -Be $script:Yesterday
        @($Baseline.Results).Count | Should -Be 1
    }

    It 'keeps a successful query without results as valid baseline' {
        Set-ReasoningFile $script:File @{ ExposureManagement = (New-ExposureManagementBlock) }
        $Baseline = InModuleScope EntraOps -Parameters @{ File = $script:File; TenantId = $script:TenantId } {
            param($File, $TenantId)
            Get-EntraOpsExposureManagementBaseline -Path $File -TenantId $TenantId -ExposureCriticalityLevel '<1' -QueryVersion 1
        }
        $Baseline.IsValid | Should -BeTrue
        @($Baseline.Results).Count | Should -Be 0
    }

    It 'never uses a file without recorded query as baseline (<Case>)' -ForEach @(
        @{ Case = 'with Exposure Management objects'; Sources = @('EntraOps', 'XSPM'); Expected = $true }
        @{ Case = 'without Exposure Management objects'; Sources = @('EntraOps'); Expected = $false }
    ) {
        Set-ReasoningFile $script:File @{ PrivilegedObjects = @(@{ ObjectId = $script:UserId; ClassificationSource = $Sources }) }
        $Baseline = InModuleScope EntraOps -Parameters @{ File = $script:File; TenantId = $script:TenantId } {
            param($File, $TenantId)
            Get-EntraOpsExposureManagementBaseline -Path $File -TenantId $TenantId -ExposureCriticalityLevel '<1' -QueryVersion 1 -GetLegacyResults {
                param($Content)
                @($Content.PrivilegedObjects | Where-Object { @($_.ClassificationSource) -contains 'XSPM' })
            }
        }
        $Baseline.IsValid | Should -BeFalse
        $Baseline.HasUnusablePreviousResults | Should -Be $Expected
    }

    It 'treats an unreadable file as previous results that cannot be verified' {
        Set-Content -LiteralPath $script:File -Value '{ "ExposureManagement": '
        $Baseline = InModuleScope EntraOps -Parameters @{ File = $script:File; TenantId = $script:TenantId } {
            param($File, $TenantId)
            Get-EntraOpsExposureManagementBaseline -Path $File -TenantId $TenantId -ExposureCriticalityLevel '<1' -QueryVersion 1
        }
        $Baseline.IsValid | Should -BeFalse
        $Baseline.HasUnusablePreviousResults | Should -BeTrue
    }

    It 'has nothing to protect when the query never succeeded' {
        $Block = New-ExposureManagementBlock -Status 'Failed'
        $Block.LastSuccessfulQueryDate = $null
        Set-ReasoningFile $script:File @{ ExposureManagement = $Block }
        $Baseline = InModuleScope EntraOps -Parameters @{ File = $script:File; TenantId = $script:TenantId } {
            param($File, $TenantId)
            Get-EntraOpsExposureManagementBaseline -Path $File -TenantId $TenantId -ExposureCriticalityLevel '<1' -QueryVersion 1
        }
        $Baseline.IsValid | Should -BeFalse
        $Baseline.HasUnusablePreviousResults | Should -BeFalse
    }

    It 'rejects results of a different <Mismatch>' -ForEach @(
        @{ Mismatch = 'tenant'; Block = @{ TenantId = '88888888-8888-8888-8888-888888888888' } }
        @{ Mismatch = 'criticality level'; Block = @{ CriticalityLevel = '<2' } }
        @{ Mismatch = 'query version'; Block = @{ QueryVersion = 0 } }
    ) {
        Set-ReasoningFile $script:File @{ ExposureManagement = (New-ExposureManagementBlock @Block -Results @((New-XspmResult))) }
        $Baseline = InModuleScope EntraOps -Parameters @{ File = $script:File; TenantId = $script:TenantId } {
            param($File, $TenantId)
            Get-EntraOpsExposureManagementBaseline -Path $File -TenantId $TenantId -ExposureCriticalityLevel '<1' -QueryVersion 1
        }
        $Baseline.IsValid | Should -BeFalse
        $Baseline.InvalidReason | Should -Match $Mismatch
        $Baseline.HasUnusablePreviousResults | Should -BeTrue
    }
}

Describe 'Invoke-EntraOpsExposureManagementQuery' {
    BeforeAll {
        $script:ValidBaseline = [pscustomobject]@{
            FileExists                 = $true
            IsValid                    = $true
            HasUnusablePreviousResults = $false
            InvalidReason              = $null
            LastSuccessfulQueryDate    = [datetime]::new(2026, 10, 15, 0, 0, 0, [System.DateTimeKind]::Utc)
            Results                    = @([pscustomobject]@{ ObjectId = 'a' }, [pscustomobject]@{ ObjectId = 'b' })
        }
        function Invoke-TestQuery {
            param([object]$Baseline, [datetime]$UtcNow = [datetime]::new(2026, 10, 19, 6, 51, 0, [System.DateTimeKind]::Utc))
            InModuleScope EntraOps -Parameters @{ Baseline = $Baseline; UtcNow = $UtcNow } {
                param($Baseline, $UtcNow)
                Invoke-EntraOpsExposureManagementQuery -Query 'ExposureGraphNodes' -Context 'Control Plane objects' -Baseline $Baseline `
                    -TenantId 'tenant' -ExposureCriticalityLevel '<1' -QueryVersion 1 -UtcNow $UtcNow
            }
        }
    }

    It 'records the day of a successful query and fails instead of returning an empty result' {
        Mock -ModuleName EntraOps Invoke-EntraOpsMsGraphQuery { [pscustomobject]@{ results = @([pscustomobject]@{ ObjectId = 'live' }) } }

        $Outcome = Invoke-TestQuery -Baseline $script:ValidBaseline

        $Outcome.Status | Should -Be 'Succeeded'
        $Outcome.Metadata.LastSuccessfulQueryDate | Should -Be '2026-10-19'
        @($Outcome.Results).ObjectId | Should -Be @('live')
        @($Outcome.Warnings).Count | Should -Be 0
        Should -Invoke -ModuleName EntraOps Invoke-EntraOpsMsGraphQuery -Times 1 -Exactly -ParameterFilter { $ThrowOnFailure -and $Uri -eq '/beta/security/runHuntingQuery' }
    }

    It 'returns a successful query without results as success' {
        Mock -ModuleName EntraOps Invoke-EntraOpsMsGraphQuery { [pscustomobject]@{ results = @() } }

        $Outcome = Invoke-TestQuery -Baseline $script:ValidBaseline

        $Outcome.Status | Should -Be 'Succeeded'
        @($Outcome.Results).Count | Should -Be 0
    }

    It 'carries forward the last successful results with their original date' {
        Mock -ModuleName EntraOps Invoke-EntraOpsMsGraphQuery { throw (New-GraphFailure -StatusCode 502) }

        $Outcome = Invoke-TestQuery -Baseline $script:ValidBaseline

        $Outcome.Status | Should -Be 'CarriedForward'
        @($Outcome.Results).ObjectId | Should -Be @('a', 'b')
        $Outcome.Metadata.LastSuccessfulQueryDate | Should -Be '2026-10-15'
        $Outcome.Metadata.LastFailure.Category | Should -Be 'Unavailable'
        $Outcome.Metadata.LastFailure.StatusCode | Should -Be 502
        $Outcome.Warnings[0].Type | Should -Be 'ExposureManagementUnavailable'
        $Outcome.Warnings[0].Message | Should -Match 'HTTP 502.*Kept 2 result\(s\) of the last successful query from 2026-10-15'
    }

    It 'reports missing permission or license as access denied and keeps the baseline' {
        Mock -ModuleName EntraOps Invoke-EntraOpsMsGraphQuery { throw (New-GraphFailure -StatusCode 403) }

        $Outcome = Invoke-TestQuery -Baseline $script:ValidBaseline

        $Outcome.Status | Should -Be 'CarriedForward'
        $Outcome.Warnings[0].Type | Should -Be 'ExposureManagementAccessDenied'
        $Outcome.Warnings[0].Message | Should -Match 'ThreatHunting\.Read\.All'
    }

    It 'escalates the warning when the carried forward results are older than seven days' {
        Mock -ModuleName EntraOps Invoke-EntraOpsMsGraphQuery { throw (New-GraphFailure -StatusCode 503) }

        $Outcome = Invoke-TestQuery -Baseline $script:ValidBaseline -UtcNow ([datetime]::new(2026, 10, 22, 0, 0, 0, [System.DateTimeKind]::Utc))

        $Outcome.Status | Should -Be 'CarriedForward'
        $Outcome.Warnings[0].Type | Should -Be 'ExposureManagementStale'
        $Outcome.Warnings[0].Message | Should -Match '7 days old'
    }

    It 'fails without a valid baseline and passes on whether previous results would be lost' -ForEach @(
        @{ Unusable = $true }
        @{ Unusable = $false }
    ) {
        Mock -ModuleName EntraOps Invoke-EntraOpsMsGraphQuery { throw (New-GraphFailure -StatusCode 502) }
        $Baseline = [pscustomobject]@{ FileExists = $true; IsValid = $false; HasUnusablePreviousResults = $Unusable; InvalidReason = 'legacy file'; LastSuccessfulQueryDate = $null; Results = @() }

        $Outcome = Invoke-TestQuery -Baseline $Baseline

        $Outcome.Status | Should -Be 'Failed'
        @($Outcome.Results).Count | Should -Be 0
        $Outcome.Metadata.LastSuccessfulQueryDate | Should -BeNullOrEmpty
        $Outcome.HasUnusablePreviousResults | Should -Be $Unusable
        $Outcome.Warnings[0].Message | Should -Match '\(legacy file\)'
    }
}

Describe 'Get-EntraOpsClassificationControlPlaneObjects during an Exposure Management outage' {
    BeforeEach {
        $Global:DefaultFolderClassification = Join-Path $TestDrive 'Classification'
        $Global:TenantNameContext = 'contoso.onmicrosoft.com'
        $script:BaselineFile = Join-Path $TestDrive 'ScopeReasoning_ControlPlane.json'
        Set-ReasoningFile $script:BaselineFile @{
            ExposureManagement = (New-ExposureManagementBlock -Results @(
                    (New-XspmResult -Targets @('Global Administrator', 'Tier0 Server')),
                    (New-XspmResult -ObjectId $script:DeletedId)
                ))
        }
        Mock -ModuleName EntraOps Invoke-EntraOpsMsGraphQuery { throw (New-GraphFailure -StatusCode 502) }
        Mock -ModuleName EntraOps Invoke-EntraOpsParallelObjectResolution {
            @{
                $script:UserId    = New-ResolvedUser -ObjectId $script:UserId
                $script:DeletedId = [pscustomobject]@{ ObjectId = $script:DeletedId; ObjectType = 'unknown'; ResolutionStatus = 'NotFound' }
            }
        }
    }

    It 're-resolves the carried forward objects and removes deleted ones' {
        $Run = Invoke-ExposureManagementObjects -BaselineFile $script:BaselineFile

        @($Run.Objects).ObjectId | Should -Be @($script:UserId)
        @($Run.Objects[0].Classification.ClassificationSource) | Should -Be @('XSPM')
        @($Run.Objects[0].Classification.ClassificationReason).TargetNodeName | Should -Be @('Global Administrator', 'Tier0 Server')
        $Run.Objects[0].RestrictedManagementByAadRole | Should -BeTrue

        $Run.Result.Status | Should -Be 'CarriedForward'
        $Run.Result.Metadata.LastSuccessfulQueryDate | Should -Be $script:Yesterday
        @($Run.Result.Results).ObjectId | Should -Be @($script:UserId)
        @($Run.Result.Warnings).Type | Should -Contain 'ExposureManagementUnavailable'
        @($Run.Result.Warnings | Where-Object Type -eq 'ExposureManagementObjectRemoved').Message | Should -Match $script:DeletedId
    }

    It 'stops instead of dropping a carried forward object whose lookup failed' {
        Mock -ModuleName EntraOps Invoke-EntraOpsParallelObjectResolution {
            @{ $script:UserId = [pscustomobject]@{ ObjectId = $script:UserId; ObjectType = 'unknown'; ResolutionStatus = 'Unresolved' } }
        }

        { Invoke-ExposureManagementObjects -BaselineFile $script:BaselineFile } | Should -Throw "*could not be resolved*$($script:UserId)*"
    }

    It 'records only the Exposure Management edges of an object that another source also found' {
        Mock -ModuleName EntraOps Invoke-EntraOpsAzGraphQuery {
            @([pscustomobject]@{ PrincipalId = $script:UserId; PrincipalType = 'user'; RoleScope = '/'; RoleName = 'Owner' })
        }

        $Run = Invoke-ExposureManagementObjects -BaselineFile $script:BaselineFile -Sources @('PrivilegedRolesFromAzGraph', 'PrivilegedEdgesFromExposureManagement')

        @($Run.Objects[0].Classification.ClassificationSource | Sort-Object) | Should -Be @('Azure Resource Graph', 'XSPM')
        $RecordedReasons = @($Run.Result.Results[0].ClassificationReason)
        $RecordedReasons.Count | Should -Be 2
        @($RecordedReasons | Where-Object { $null -ne $_.PSObject.Properties['RoleName'] }).Count | Should -Be 0
    }

    It 'keeps the date of the last successful query across repeated failures and marks the objects' {
        $FirstRun = Invoke-ExposureManagementObjects -BaselineFile $script:BaselineFile
        $Payload = InModuleScope EntraOps -Parameters @{ Objects = $FirstRun.Objects; Result = $FirstRun.Result } {
            param($Objects, $Result)
            ConvertTo-EntraOpsControlPlaneScopeReasoning -PrivilegedObjects $Objects -PrivilegedObjectClassificationSource 'All' -ExposureManagementResult $Result
        }
        $Payload | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $script:BaselineFile

        $Written = Get-Content -LiteralPath $script:BaselineFile -Raw | ConvertFrom-Json
        $Written.PrivilegedObjects[0].XspmLastSuccessfulQueryDate | Should -Be $script:Yesterday
        $Written.ExposureManagement.Status | Should -Be 'CarriedForward'
        $Written.ExposureManagement.LastFailure.StatusCode | Should -Be 502

        $SecondRun = Invoke-ExposureManagementObjects -BaselineFile $script:BaselineFile

        $SecondRun.Result.Status | Should -Be 'CarriedForward'
        $SecondRun.Result.Metadata.LastSuccessfulQueryDate | Should -Be $script:Yesterday
        @($SecondRun.Objects).ObjectId | Should -Be @($script:UserId)
    }

    It 'replaces carried forward results after the next successful query' {
        Mock -ModuleName EntraOps Invoke-EntraOpsMsGraphQuery {
            [pscustomobject]@{ results = @([pscustomobject]@{ ObjectDisplayName = 'Admin'; ObjectId = $script:UserId; ObjectType = 'user'; ClassificationReason = '{"EdgeLabel":"has role on","TargetNodeName":"Global Administrator"}' }) }
        }

        $Run = Invoke-ExposureManagementObjects -BaselineFile $script:BaselineFile
        $Payload = InModuleScope EntraOps -Parameters @{ Objects = $Run.Objects; Result = $Run.Result } {
            param($Objects, $Result)
            ConvertTo-EntraOpsControlPlaneScopeReasoning -PrivilegedObjects $Objects -PrivilegedObjectClassificationSource 'All' -ExposureManagementResult $Result
        }

        $Run.Result.Status | Should -Be 'Succeeded'
        $Run.Result.Metadata.LastSuccessfulQueryDate | Should -Be ([datetime]::UtcNow.ToString('yyyy-MM-dd'))
        @($Run.Result.Results[0].ClassificationReason).TargetNodeName | Should -Be @('Global Administrator')
        $Payload.PrivilegedObjects[0].PSObject.Properties['XspmLastSuccessfulQueryDate'] | Should -BeNullOrEmpty
        $Payload.ExposureManagement.PSObject.Properties['LastFailure'] | Should -BeNullOrEmpty
    }

    It 'records the resolved object type and name of a successful query' {
        # Exposure Management shows some service principals by object ID only
        Mock -ModuleName EntraOps Invoke-EntraOpsMsGraphQuery {
            [pscustomobject]@{ results = @([pscustomobject]@{ ObjectDisplayName = $script:UserId; ObjectId = $script:UserId; ObjectType = 'user'; ClassificationReason = '{"EdgeLabel":"has role on","TargetNodeName":"Global Administrator"}' }) }
        }

        $Run = Invoke-ExposureManagementObjects -BaselineFile $script:BaselineFile

        $Run.Result.Results[0].ObjectType | Should -Be 'user'
        $Run.Result.Results[0].ObjectDisplayName | Should -Be "Admin $($script:UserId)"
    }

    It 'names the object type column of the hunting query' {
        Mock -ModuleName EntraOps Invoke-EntraOpsMsGraphQuery { [pscustomobject]@{ results = @() } }

        $null = Invoke-ExposureManagementObjects -BaselineFile $script:BaselineFile

        Should -Invoke -ModuleName EntraOps Invoke-EntraOpsMsGraphQuery -Times 1 -Exactly -ParameterFilter { $Body -match 'ObjectType = tolower\(ObjectType\)' }
    }

    It 'continues without Exposure Management on a first run' {
        $Run = Invoke-ExposureManagementObjects -BaselineFile (Join-Path $TestDrive 'missing.json')

        @($Run.Objects).Count | Should -Be 0
        $Run.Result.Status | Should -Be 'Failed'
        $Run.Result.HasUnusablePreviousResults | Should -BeFalse
    }

    It 'reports previous results that cannot be verified when the file has no recorded query' {
        Set-ReasoningFile $script:BaselineFile @{ PrivilegedObjects = @(@{ ObjectId = $script:UserId; ClassificationSource = @('XSPM') }) }

        $Run = Invoke-ExposureManagementObjects -BaselineFile $script:BaselineFile

        $Run.Result.Status | Should -Be 'Failed'
        $Run.Result.HasUnusablePreviousResults | Should -BeTrue
    }
}

Describe 'Get-EntraOpsClassificationAzureResourceScope during an Exposure Management outage' {
    BeforeEach {
        $script:AzureBaselineFile = Join-Path $TestDrive 'ScopeReasoning_Azure.json'
        $script:KeyVaultId = '/subscriptions/sub1/resourcegroups/rg1/providers/microsoft.keyvault/vaults/kv1'
        Set-ReasoningFile $script:AzureBaselineFile @{
            Tier0Scope         = @('/')
            ScopeDetails       = @()
            ExposureManagement = (New-ExposureManagementBlock -Results @([ordered]@{ NodeName = 'kv1'; ResourceId = $script:KeyVaultId; CriticalityLevel = 0; CriticalityRules = '["KeyVaults"]' }))
        }
        Mock -ModuleName EntraOps Get-AzContext { [pscustomobject]@{ Tenant = [pscustomobject]@{ Id = $script:TenantId } } }
        Mock -ModuleName EntraOps Invoke-EntraOpsAzGraphQuery {
            if ($KqlQuery -match 'managementGroupAncestorsChain') {
                @([pscustomobject]@{ subscriptionId = 'sub1'; managementGroupId = '/providers/microsoft.management/managementgroups/root' })
            } elseif ($KqlQuery -match "type == 'microsoft.resources/subscriptions'") {
                @([pscustomobject]@{ subscriptionId = 'sub1' })
            }
        }
        Mock -ModuleName EntraOps Invoke-EntraOpsMsGraphQuery { throw (New-GraphFailure -StatusCode 502) }
    }

    It 'keeps the critical resources of the last successful query in the Control Plane scope' {
        $Scope = InModuleScope EntraOps -Parameters @{ File = $script:AzureBaselineFile; EamFolder = (Join-Path $TestDrive 'EAM') } {
            param($File, $EamFolder)
            $Warnings = [System.Collections.Generic.List[psobject]]::new()
            Get-EntraOpsClassificationAzureResourceScope -EntraOpsEamFolder $EamFolder -EntraOpsScopes @('Azure') -WarningMessages $Warnings -ExposureManagementBaselineFile $File -WarningAction SilentlyContinue
        }

        $Scope.Tier0ResourceScope | Should -Contain $script:KeyVaultId
        $Scope.Tier0ResourceScope | Should -Contain '/subscriptions/sub1'
        $Detail = @($Scope.ResourceScopeDetails | Where-Object Source -eq 'ExposureManagement')
        $Detail.Count | Should -Be 1
        $Detail[0].XspmLastSuccessfulQueryDate | Should -Be $script:Yesterday
        $Scope.ExposureManagement.Status | Should -Be 'CarriedForward'
        @($Scope.ExposureManagement.Results).ResourceId | Should -Be @($script:KeyVaultId)
    }
}

Describe 'Get-EntraOpsClassificationAzureResourceScope failures' {
    BeforeEach {
        $script:EamFolder = Join-Path $TestDrive 'EAM'
        New-Item -ItemType Directory -Path (Join-Path $script:EamFolder 'Azure') -Force | Out-Null
        @(@{ ObjectId = 'mi-1'; ObjectType = 'serviceprincipal'; ObjectSubType = 'ManagedIdentity'; ObjectDisplayName = 'mi'; ObjectAdminTierLevelName = 'ControlPlane'; Classification = @() }) |
            ConvertTo-Json -Depth 5 -AsArray | Set-Content -LiteralPath (Join-Path $script:EamFolder 'Azure/Azure.json')
        Mock -ModuleName EntraOps Get-AzContext { [pscustomobject]@{ Tenant = [pscustomobject]@{ Id = $script:TenantId } } }
        Mock -ModuleName EntraOps Invoke-EntraOpsMsGraphQuery { [pscustomobject]@{ results = @() } }
        Mock -ModuleName EntraOps Invoke-EntraOpsAzGraphQuery {
            if ($KqlQuery -match 'managementGroupAncestorsChain') {
                @([pscustomobject]@{ subscriptionId = 'sub1'; managementGroupId = '/providers/microsoft.management/managementgroups/root' })
            } elseif ($KqlQuery -match "type == 'microsoft.resources/subscriptions'") {
                @([pscustomobject]@{ subscriptionId = 'sub1' })
            } else {
                throw 'Resource Graph throttled'
            }
        }
    }

    It 'stops instead of dropping the resources that host privileged managed identities' {
        { InModuleScope EntraOps -Parameters @{ EamFolder = $script:EamFolder } {
                param($EamFolder)
                Get-EntraOpsClassificationAzureResourceScope -EntraOpsEamFolder $EamFolder -EntraOpsScopes @('Azure') -WarningAction SilentlyContinue
            } } | Should -Throw '*system-assigned MI query failed*Refusing to generate a narrowed Azure classification scope*'
    }

    It 'stops when an EAM export cannot be read instead of treating it as missing' {
        Set-Content -LiteralPath (Join-Path $script:EamFolder 'Azure/Azure.json') -Value '[ { "ObjectId": '
        { InModuleScope EntraOps -Parameters @{ EamFolder = $script:EamFolder } {
                param($EamFolder)
                Get-EntraOpsClassificationAzureResourceScope -EntraOpsEamFolder $EamFolder -EntraOpsScopes @('Azure') -WarningAction SilentlyContinue
            } } | Should -Throw "*EAM export*Azure.json' could not be read*"
    }
}

Describe 'Get-EntraOpsClassificationControlPlaneObjects with an unreadable EAM export' {
    It 'stops instead of removing the Control Plane objects of the RBAC system' {
        $Global:DefaultFolderClassification = Join-Path $TestDrive 'Classification'
        $Global:TenantNameContext = 'contoso.onmicrosoft.com'
        $EamFolder = Join-Path $TestDrive 'EAM-corrupt'
        New-Item -ItemType Directory -Path (Join-Path $EamFolder 'EntraID') -Force | Out-Null
        Set-Content -LiteralPath (Join-Path $EamFolder 'EntraID/EntraID.json') -Value '<<<<<<< HEAD'

        { Get-EntraOpsClassificationControlPlaneObjects -PrivilegedObjectClassificationSource 'EntraOps' -EntraOpsEamFolder $EamFolder -EntraOpsScopes @('EntraID', 'Azure') -TenantId $script:TenantId -WarningAction SilentlyContinue 6>$null } |
            Should -Throw "*EAM export*EntraID.json' could not be read*previous classification files are kept*"
    }
}

Describe 'Write-EntraOpsPipelineWarning' {
    BeforeEach {
        $script:PreviousGitHubActions = $env:GITHUB_ACTIONS
        $script:PreviousTfBuild = $env:TF_BUILD
        $env:GITHUB_ACTIONS = $null
        $env:TF_BUILD = $null
    }

    AfterEach {
        $env:GITHUB_ACTIONS = $script:PreviousGitHubActions
        $env:TF_BUILD = $script:PreviousTfBuild
    }

    It 'writes a GitHub Actions annotation' {
        $env:GITHUB_ACTIONS = 'true'
        $Output = InModuleScope EntraOps { Write-EntraOpsPipelineWarning -Title 'EntraOps: XSPM' -Message "Kept 100% of`nresults" 6>&1 }
        "$Output" | Should -Be '::warning title=EntraOps%3A XSPM::Kept 100%25 of results'
    }

    It 'writes an Azure DevOps annotation' {
        $env:TF_BUILD = 'True'
        $Output = InModuleScope EntraOps { Write-EntraOpsPipelineWarning -Message 'Kept results' 6>&1 }
        "$Output" | Should -Be '##vso[task.logissue type=warning]Kept results'
    }

    It 'writes nothing outside of a pipeline' {
        $Output = InModuleScope EntraOps { Write-EntraOpsPipelineWarning -Message 'Kept results' 6>&1 }
        $Output | Should -BeNullOrEmpty
    }
}
