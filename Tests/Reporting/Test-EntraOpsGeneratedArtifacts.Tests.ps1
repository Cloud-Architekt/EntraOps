#Requires -Modules Pester

BeforeDiscovery {
    $script:TestRepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
}

BeforeAll {
    $script:TestRepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
    Import-Module (Join-Path $script:TestRepositoryRoot 'EntraOps/EntraOps.psd1') -Force
    $ValidatorPath = Get-Command Test-EntraOpsGeneratedArtifacts

    function New-TestEamArtifact {
        param (
            [Parameter(Mandatory = $true)]
            [string]$Root,

            [string]$TierLevel = '0',

            [string]$TierName = 'ControlPlane',

            [switch]$DuplicateAssignment,

            [switch]$PrivilegedWithoutClassification,

            [switch]$MissingObjectId,

            [switch]$DuplicateObject,

            [switch]$SingleObjectClassification,

            [switch]$ScalarMatchedActions
        )

        $SystemPath = Join-Path $Root 'EntraID'
        New-Item -Path $SystemPath -ItemType Directory -Force | Out-Null
        # Assigned outside of an if-expression: statement output would unwrap a one-element array.
        $AssignmentClassification = @([pscustomobject]@{ AdminTierLevel = '0'; AdminTierLevelName = 'ControlPlane' })
        if ($PrivilegedWithoutClassification) { $AssignmentClassification = @() }
        if ($SingleObjectClassification) { $AssignmentClassification = [pscustomobject]@{ AdminTierLevel = '0'; AdminTierLevelName = 'ControlPlane' } }
        if ($ScalarMatchedActions) { $AssignmentClassification = @([pscustomobject]@{ AdminTierLevel = '0'; AdminTierLevelName = 'ControlPlane'; Service = 'Global'; MatchedActions = 'microsoft.directory/allEntities/allTasks' }) }
        $Assignment = [pscustomobject]@{
            RoleAssignmentInstanceId       = 'EO_RA_test'
            RoleDefinitionName             = 'Global Administrator'
            TransitiveByNestingObjectIds   = @('group-a')
            RoleIsPrivileged               = [bool]$PrivilegedWithoutClassification
            Classification                 = $AssignmentClassification
        }
        $Assignments = @($Assignment)
        if ($DuplicateAssignment) {
            $Assignments += $Assignment.PSObject.Copy()
        }
        $Artifact = [pscustomobject]@{
            ObjectId                    = if ($MissingObjectId) { '' } else { 'aaaaaaaa-0000-0000-0000-000000000001' }
            ObjectAdminTierLevel        = $TierLevel
            ObjectAdminTierLevelName    = $TierName
            RoleAssignments             = $Assignments
        }
        $Artifacts = if ($DuplicateObject) { @($Artifact, $Artifact.PSObject.Copy()) } else { @($Artifact) }
        ConvertTo-Json -InputObject $Artifacts -Depth 10 | Set-Content -LiteralPath (Join-Path $SystemPath 'EntraID.json') -Encoding UTF8
    }

    function New-TestTenantGovernanceArtifact {
        param([string]$Root, [switch]$DuplicateIdentity, [switch]$BadManifestCount, [switch]$EmptyPropertyName, [switch]$OmitManifestCount, [switch]$LeftoverResourceType)
        $Type = 'microsoft.entra.conditionalaccesspolicy'
        $TypePath = Join-Path $Root "$Type/AADConditionalAccessPolicy"
        New-Item -Path $TypePath -ItemType Directory -Force | Out-Null
        $Resource = [ordered]@{
            resourceType = $Type
            displayName  = 'AADConditionalAccessPolicy-Test'
            properties   = [ordered]@{ Id = 'aaaaaaaa-0000-0000-0000-000000000099'; State = 'enabled' }
        }
        if ($EmptyPropertyName) {
            $Resource.properties[''] = 'Graph-emitted value'
        }
        $Resource | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath (Join-Path $TypePath 'first.json') -Encoding UTF8
        if ($DuplicateIdentity) {
            $Resource | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath (Join-Path $TypePath 'second.json') -Encoding UTF8
        }
        if ($LeftoverResourceType) {
            # A resource type removed from ResourcesToInclude keeps its folder on disk; it is not part
            # of the manifest counts and the snapshot report lists it as NotInConfig.
            $LeftoverType = 'microsoft.entra.namedlocation'
            $LeftoverPath = Join-Path $Root "$LeftoverType/General"
            New-Item -Path $LeftoverPath -ItemType Directory -Force | Out-Null
            [ordered]@{ resourceType = $LeftoverType; displayName = 'Office'; properties = [ordered]@{ Id = 'bbbbbbbb-0000-0000-0000-000000000001' } } |
                ConvertTo-Json -Depth 10 | Set-Content -LiteralPath (Join-Path $LeftoverPath 'Office.json') -Encoding UTF8
        }
        $Count = if ($DuplicateIdentity) { 2 } else { 1 }
        $Manifest = [ordered]@{
            SnapshotJobStatus = 'completed'
            CapturedResourceCount = $Count
            PublishedResourceTypeCounts = if ($OmitManifestCount) { [ordered]@{} } else { [ordered]@{ ($Type) = if ($BadManifestCount) { 9 } else { $Count } } }
            IsComplete = $true
        }
        $Manifest | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath (Join-Path $Root '.SnapshotManifest.json') -Encoding UTF8
    }
}

Describe 'Test-EntraOpsGeneratedArtifacts' {
    It 'accepts canonical tiers and unique assignment paths' {
        $ArtifactRoot = Join-Path $TestDrive 'valid'
        New-TestEamArtifact -Root $ArtifactRoot

        & $ValidatorPath -PrivilegedEamPath $ArtifactRoot | Should -Match 'Validated 1 object'
    }

    It 'warns but accepts a contradictory object tier pair by default' {
        $ArtifactRoot = Join-Path $TestDrive 'bad-tier'
        New-TestEamArtifact -Root $ArtifactRoot -TierLevel '0' -TierName 'Unclassified'

        $Warnings = @()
        & $ValidatorPath -PrivilegedEamPath $ArtifactRoot -WarningVariable +Warnings | Should -Match 'Validated 1 object'
        $Warnings.Message | Should -Match 'contradictory tier pair'
    }

    It 'rejects a contradictory object tier pair in strict mode' {
        $ArtifactRoot = Join-Path $TestDrive 'strict-tier'
        New-TestEamArtifact -Root $ArtifactRoot -TierLevel '0' -TierName 'Unclassified'

        { & $ValidatorPath -PrivilegedEamPath $ArtifactRoot -FailOnContradictoryTierPair } | Should -Throw '*contradictory tier pair*'
    }

    It 'rejects a duplicate assignment instance and nesting path' {
        $ArtifactRoot = Join-Path $TestDrive 'duplicate'
        New-TestEamArtifact -Root $ArtifactRoot -DuplicateAssignment

        { & $ValidatorPath -PrivilegedEamPath $ArtifactRoot } | Should -Throw '*duplicate assignment path*'
    }

    It 'warns about a privileged assignment without classification and can enforce it' {
        $ArtifactRoot = Join-Path $TestDrive 'empty-classification'
        New-TestEamArtifact -Root $ArtifactRoot -PrivilegedWithoutClassification

        $Warnings = @()
        & $ValidatorPath -PrivilegedEamPath $ArtifactRoot -WarningVariable +Warnings | Should -Match 'Validated 1 object'
        $Warnings.Message | Should -Match 'has no classification result'
        { & $ValidatorPath -PrivilegedEamPath $ArtifactRoot -FailOnPrivilegedAssignmentWithoutClassification } | Should -Throw '*has no classification result*'
    }

    It 'rejects an assignment classification stored as a single object instead of an array' {
        $ArtifactRoot = Join-Path $TestDrive 'single-object-classification'
        New-TestEamArtifact -Root $ArtifactRoot -SingleObjectClassification

        { & $ValidatorPath -PrivilegedEamPath $ArtifactRoot } | Should -Throw '*single object instead of an array*'
    }

    It 'rejects MatchedActions that collapsed from an array into a single value' {
        $ArtifactRoot = Join-Path $TestDrive 'scalar-matched-actions'
        New-TestEamArtifact -Root $ArtifactRoot -ScalarMatchedActions

        { & $ValidatorPath -PrivilegedEamPath $ArtifactRoot } | Should -Throw '*MatchedActions is stored as a single value instead of an array*'
    }

    It 'only warns about collapsed collections in an unchanged committed export and rejects them once rewritten' {
        # An RBAC system with an empty result keeps the export of an earlier version; failing on it
        # would fail every pull run until that system returns data again.
        $Repository = Join-Path $TestDrive 'committed-legacy-export'
        $ArtifactRoot = Join-Path $Repository 'PrivilegedEAM'
        New-TestEamArtifact -Root $ArtifactRoot -SingleObjectClassification
        & git -C $Repository init --quiet
        & git -C $Repository -c user.email=test@contoso.com -c user.name=Test -c commit.gpgsign=false add --all
        & git -C $Repository -c user.email=test@contoso.com -c user.name=Test -c commit.gpgsign=false commit --quiet -m 'legacy export'
        $LASTEXITCODE | Should -Be 0

        # Throws (and fails the test) if the committed export is rejected
        $Warnings = @()
        & $ValidatorPath -PrivilegedEamPath $ArtifactRoot -WarningVariable +Warnings -WarningAction SilentlyContinue | Out-Null
        @($Warnings.Message | Where-Object { $_ -like '*EntraID.json: 1 collection(s)*committed export of an earlier EntraOps version*' }).Count | Should -Be 1

        # Output of the current run (a changed file) is still rejected
        New-TestEamArtifact -Root $ArtifactRoot -SingleObjectClassification -TierLevel '1' -TierName 'ManagementPlane'
        { & $ValidatorPath -PrivilegedEamPath $ArtifactRoot -WarningAction SilentlyContinue } | Should -Throw '*single object instead of an array*'
    }

    It 'does not warn about an assignment classification array with one entry' {
        $ArtifactRoot = Join-Path $TestDrive 'single-entry-array-classification'
        New-TestEamArtifact -Root $ArtifactRoot

        $Warnings = @()
        & $ValidatorPath -PrivilegedEamPath $ArtifactRoot -WarningVariable +Warnings | Out-Null
        $Warnings.Message | Should -Not -Match 'single object instead of an array'
    }

    It 'rejects an EAM object without an object id' {
        $ArtifactRoot = Join-Path $TestDrive 'missing-object-id'
        New-TestEamArtifact -Root $ArtifactRoot -MissingObjectId

        { & $ValidatorPath -PrivilegedEamPath $ArtifactRoot } | Should -Throw '*missing ObjectId*'
    }

    It 'rejects duplicate objects within one RBAC-system aggregate' {
        $ArtifactRoot = Join-Path $TestDrive 'duplicate-object'
        New-TestEamArtifact -Root $ArtifactRoot -DuplicateObject

        { & $ValidatorPath -PrivilegedEamPath $ArtifactRoot } | Should -Throw '*duplicate object*'
    }

    It 'accepts a unique Tenant Governance tree whose manifest counts match' {
        $ArtifactRoot = Join-Path $TestDrive 'tg-valid'
        New-Item -Path $ArtifactRoot -ItemType Directory -Force | Out-Null
        New-TestTenantGovernanceArtifact -Root $ArtifactRoot

        & $ValidatorPath -PrivilegedEamPath '' -TenantGovernancePath $ArtifactRoot | Should -Match '1 Tenant Governance resource'
    }

    It 'accepts valid Graph JSON containing an empty property name' {
        $ArtifactRoot = Join-Path $TestDrive 'tg-empty-property'
        New-Item -Path $ArtifactRoot -ItemType Directory -Force | Out-Null
        New-TestTenantGovernanceArtifact -Root $ArtifactRoot -EmptyPropertyName

        & $ValidatorPath -PrivilegedEamPath '' -TenantGovernancePath $ArtifactRoot | Should -Match '1 Tenant Governance resource'
    }

    It 'rejects duplicate canonical Tenant Governance resource identities' {
        $ArtifactRoot = Join-Path $TestDrive 'tg-duplicate'
        New-Item -Path $ArtifactRoot -ItemType Directory -Force | Out-Null
        New-TestTenantGovernanceArtifact -Root $ArtifactRoot -DuplicateIdentity

        { & $ValidatorPath -PrivilegedEamPath '' -TenantGovernancePath $ArtifactRoot } | Should -Throw '*is stored in 2 files*'
    }

    It 'rejects a Tenant Governance manifest count that differs from disk' {
        $ArtifactRoot = Join-Path $TestDrive 'tg-count'
        New-Item -Path $ArtifactRoot -ItemType Directory -Force | Out-Null
        New-TestTenantGovernanceArtifact -Root $ArtifactRoot -BadManifestCount

        { & $ValidatorPath -PrivilegedEamPath '' -TenantGovernancePath $ArtifactRoot } | Should -Throw '*manifest count*but 1 JSON file*'
    }

    It 'rejects a complete manifest whose captured count does not match its listed resource types' {
        $ArtifactRoot = Join-Path $TestDrive 'tg-omitted-count'
        New-Item -Path $ArtifactRoot -ItemType Directory -Force | Out-Null
        New-TestTenantGovernanceArtifact -Root $ArtifactRoot -OmitManifestCount

        { & $ValidatorPath -PrivilegedEamPath '' -TenantGovernancePath $ArtifactRoot } | Should -Throw '*captured count is 1, but 0 resource file(s)*'
    }

    It 'warns about a resource type folder that is no longer part of the snapshot manifest instead of failing' {
        $ArtifactRoot = Join-Path $TestDrive 'tg-leftover'
        New-Item -Path $ArtifactRoot -ItemType Directory -Force | Out-Null
        New-TestTenantGovernanceArtifact -Root $ArtifactRoot -LeftoverResourceType

        $Output = & $ValidatorPath -PrivilegedEamPath '' -TenantGovernancePath $ArtifactRoot -WarningVariable Warnings -WarningAction SilentlyContinue
        $Output | Should -Match '2 Tenant Governance resource'
        @($Warnings | Where-Object { $_ -match "microsoft\.entra\.namedlocation.*not part of the current snapshot manifest" }).Count | Should -Be 1
    }

    It 'rejects a call without any artifact path instead of validating nothing' {
        { & $ValidatorPath -PrivilegedEamPath '' } | Should -Throw '*Nothing to validate*'
    }
}

