#Requires -Modules Pester

BeforeAll {
    $script:TestRepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
    function Invoke-EntraOpsMsGraphQuery {
        param($Method, $Uri, $OutputType, $Body, [switch]$SuppressNotFoundWarning, [switch]$ThrowOnFailure, [switch]$DisableCache, $WarningAction, $ConsistencyLevel)
        throw 'Invoke-EntraOpsMsGraphQuery must be mocked'
    }

    . "$script:TestRepositoryRoot/EntraOps/Private/Test-EntraOpsPathWithinRoot.ps1"
    . "$script:TestRepositoryRoot/EntraOps/Private/Import-EntraOpsObjectClassificationFile.ps1"
    . "$script:TestRepositoryRoot/EntraOps/Private/Test-EntraOpsCustomSecurityAttributeClassificationEnabled.ps1"
    . "$script:TestRepositoryRoot/EntraOps/Private/Test-EntraOpsAlternateObjectTierLevelEnabled.ps1"
    . "$script:TestRepositoryRoot/EntraOps/Private/Resolve-EntraOpsAlternateObjectTierLevel.ps1"
    . "$script:TestRepositoryRoot/EntraOps/Public/PrivilegedAccess/Get-EntraOpsPrivilegedEntraObject.ps1"

    $script:UserId = '11111111-1111-1111-1111-111111111111'
    $script:GroupId = '55555555-5555-5555-5555-555555555555'
}

Describe 'Import-EntraOpsObjectClassificationFile' {
    BeforeEach {
        $Script:ObjectClassificationFileCache = $null
        $script:Root = Join-Path $TestDrive ([guid]::NewGuid())
        New-Item -ItemType Directory -Path (Join-Path $script:Root 'Classification') -Force | Out-Null
    }

    It 'loads a JSON file and derives the tier level from the tier name' {
        @(
            @{ ObjectId = $script:UserId.ToUpperInvariant(); ObjectType = 'User'; AdminTierLevelName = 'controlplane'; Justification = 'GA' }
            @{ ObjectId = $script:GroupId; AdminTierLevelName = 'WorkloadPlane' }
        ) | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $script:Root 'Classification/ObjectClassification.json')

        $Entries = Import-EntraOpsObjectClassificationFile -FilePath './Classification/ObjectClassification.json' -RootFolder $script:Root

        $Entries.Count | Should -Be 2
        $Entries[$script:UserId].AdminTierLevelName | Should -Be 'ControlPlane'
        $Entries[$script:UserId].AdminTierLevel | Should -Be '0'
        $Entries[$script:UserId].ObjectType | Should -Be 'user'
        $Entries[$script:GroupId].AdminTierLevel | Should -Be '1'
    }

    It 'loads a CSV file and skips invalid rows with a warning' {
        @(
            '"ObjectId","ObjectType","ObjectDisplayName","AdminTierLevelName","Justification"'
            "`"$script:UserId`",`"user`",`"Admin`",`"UserAccess`",`"`""
            '"not-a-guid","user","X","ControlPlane",""'
            "`"$script:GroupId`",`"group`",`"G`",`"Tier0`",`"`""
            "`"$script:GroupId`",`"device`",`"G`",`"ControlPlane`",`"`""
        ) | Set-Content -LiteralPath (Join-Path $script:Root 'Classification/ObjectClassification.csv')

        $Entries = Import-EntraOpsObjectClassificationFile -FilePath './Classification/ObjectClassification.csv' -RootFolder $script:Root -WarningVariable Warnings -WarningAction SilentlyContinue

        $Entries.Count | Should -Be 1
        $Entries[$script:UserId].AdminTierLevel | Should -Be '2'
        @($Warnings).Count | Should -Be 3
    }

    It 'uses the most privileged tier for conflicting duplicate entries' {
        @(
            @{ ObjectId = $script:UserId; AdminTierLevelName = 'UserAccess' }
            @{ ObjectId = $script:UserId; AdminTierLevelName = 'ControlPlane' }
            @{ ObjectId = $script:UserId; AdminTierLevelName = 'ManagementPlane' }
        ) | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $script:Root 'Classification/ObjectClassification.json')

        $Entries = Import-EntraOpsObjectClassificationFile -FilePath './Classification/ObjectClassification.json' -RootFolder $script:Root -WarningAction SilentlyContinue

        $Entries[$script:UserId].AdminTierLevelName | Should -Be 'ControlPlane'
    }

    It 'returns no entries when the file does not exist' {
        $Entries = Import-EntraOpsObjectClassificationFile -FilePath './Classification/Missing.json' -RootFolder $script:Root -WarningAction SilentlyContinue

        $Entries.Count | Should -Be 0
    }

    It 'rejects paths outside the EntraOps root and unsupported file types' {
        { Import-EntraOpsObjectClassificationFile -FilePath '../outside.json' -RootFolder $script:Root } | Should -Throw '*outside the EntraOps root folder*'
        { Import-EntraOpsObjectClassificationFile -FilePath './Classification/file.ps1' -RootFolder $script:Root } | Should -Throw '*must be a .json or .csv file*'
    }
}

Describe 'Get-EntraOpsPrivilegedEntraObject with Object Classification File' {
    BeforeEach {
        $script:UserId = '11111111-1111-1111-1111-111111111111'
        $script:GroupId = '55555555-5555-5555-5555-555555555555'
        $Script:ObjectClassificationFileCache = $null
        $global:TenantIdContext = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
        $global:EntraOpsConfig = [pscustomobject]@{ CustomSecurityAttributes = [pscustomobject]@{}; AlternateObjectTierLevelAttributes = $null; ObjectClassificationFile = $null }
        $global:EntraOpsBaseFolder = Join-Path $TestDrive ([guid]::NewGuid())
        New-Item -ItemType Directory -Path (Join-Path $global:EntraOpsBaseFolder 'Classification') -Force | Out-Null
        @(
            @{ ObjectId = $script:UserId; ObjectType = 'user'; AdminTierLevelName = 'ManagementPlane' }
            @{ ObjectId = $script:GroupId; ObjectType = 'group'; AdminTierLevelName = 'ControlPlane' }
        ) | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $global:EntraOpsBaseFolder 'Classification/ObjectClassification.json')
        $script:FileSettings = [pscustomobject]@{ Enabled = $true; FilePath = './Classification/ObjectClassification.json' }
        $script:UserCsa = $null

        Mock Invoke-EntraOpsMsGraphQuery {
            if ($Uri -like "/beta/directoryObjects/${script:UserId}?*") {
                return [pscustomobject]@{ '@odata.type' = '#microsoft.graph.user'; id = $script:UserId; displayName = 'Admin A'; userPrincipalName = 'a@contoso.com'; userType = 'Member'; isManagementRestricted = $false }
            }
            if ($Uri -like "/beta/users/${script:UserId}?*") {
                return [pscustomobject]@{ id = $script:UserId; userType = 'Member'; customSecurityAttributes = $script:UserCsa }
            }
            if ($Uri -like "/beta/directoryObjects/${script:GroupId}?*") {
                return [pscustomobject]@{ '@odata.type' = '#microsoft.graph.group'; id = $script:GroupId; displayName = 'PRG-Tier1-Admins'; isAssignableToRole = $false; isManagementRestricted = $false }
            }
            return @()
        }
    }

    It 'classifies a user without custom security attribute tier from the file' {
        $Result = Get-EntraOpsPrivilegedEntraObject -AadObjectId $script:UserId -TenantId $global:TenantIdContext -ObjectClassificationFile $script:FileSettings -WarningAction SilentlyContinue

        $Result.AdminTierLevel | Should -Be '1'
        $Result.AdminTierLevelName | Should -Be 'ManagementPlane'
    }

    It 'ignores the custom security attribute tier when the file is enabled' {
        $script:UserCsa = [pscustomobject]@{ privilegedUser = [pscustomobject]@{ adminTierLevel = '0'; adminTierLevelName = 'ControlPlane' } }

        $Result = Get-EntraOpsPrivilegedEntraObject -AadObjectId $script:UserId -TenantId $global:TenantIdContext -CustomSecurityUserAttribute 'privilegedUser' -ObjectClassificationFile $script:FileSettings -WarningAction SilentlyContinue

        $Result.AdminTierLevelName | Should -Be 'ManagementPlane'
        $Result.AdminTierLevel | Should -Be '1'
    }

    It 'leaves an object without file entry unclassified even with a custom security attribute tier' {
        $script:UserCsa = [pscustomobject]@{ privilegedUser = [pscustomobject]@{ adminTierLevel = '0'; adminTierLevelName = 'ControlPlane' } }
        @(@{ ObjectId = $script:GroupId; ObjectType = 'group'; AdminTierLevelName = 'ControlPlane' }) | ConvertTo-Json -AsArray |
            Set-Content -LiteralPath (Join-Path $global:EntraOpsBaseFolder 'Classification/ObjectClassification.json')

        $Result = Get-EntraOpsPrivilegedEntraObject -AadObjectId $script:UserId -TenantId $global:TenantIdContext -CustomSecurityUserAttribute 'privilegedUser' -ObjectClassificationFile $script:FileSettings -WarningAction SilentlyContinue

        $Result.AdminTierLevelName | Should -Be 'Unclassified'
        $Result.AdminTierLevel | Should -Be 'Unclassified'
    }

    It 'uses the custom security attribute tier when the file is disabled' {
        $script:UserCsa = [pscustomobject]@{ privilegedUser = [pscustomobject]@{ adminTierLevel = '0'; adminTierLevelName = 'ControlPlane' } }
        $Disabled = [pscustomobject]@{ Enabled = $false; FilePath = './Classification/ObjectClassification.json' }

        $Result = Get-EntraOpsPrivilegedEntraObject -AadObjectId $script:UserId -TenantId $global:TenantIdContext -CustomSecurityUserAttribute 'privilegedUser' -ObjectClassificationFile $Disabled -WarningAction SilentlyContinue

        $Result.AdminTierLevelName | Should -Be 'ControlPlane'
    }

    It 'uses the file entry for objects without custom security attribute tier when both are enabled' {
        $Result = Get-EntraOpsPrivilegedEntraObject -AadObjectId $script:UserId -TenantId $global:TenantIdContext -CustomSecurityUserAttribute 'privilegedUser' -ObjectClassificationFile $script:FileSettings -CustomSecurityAttributeClassification $true -WarningAction SilentlyContinue

        $Result.AdminTierLevelName | Should -Be 'ManagementPlane'
    }

    It 'lets the custom security attribute tier win over a file entry when both are enabled' {
        $script:UserCsa = [pscustomobject]@{ privilegedUser = [pscustomobject]@{ adminTierLevel = '0'; adminTierLevelName = 'ControlPlane' } }

        $Result = Get-EntraOpsPrivilegedEntraObject -AadObjectId $script:UserId -TenantId $global:TenantIdContext -CustomSecurityUserAttribute 'privilegedUser' -ObjectClassificationFile $script:FileSettings -CustomSecurityAttributeClassification $true -WarningAction SilentlyContinue

        $Result.AdminTierLevelName | Should -Be 'ControlPlane'
    }

    It 'falls back from an Unclassified custom security attribute tier to the file entry' {
        $script:UserCsa = [pscustomobject]@{ privilegedUser = [pscustomobject]@{ adminTierLevel = 'Unclassified'; adminTierLevelName = 'Unclassified' } }

        $Result = Get-EntraOpsPrivilegedEntraObject -AadObjectId $script:UserId -TenantId $global:TenantIdContext -CustomSecurityUserAttribute 'privilegedUser' -ObjectClassificationFile $script:FileSettings -CustomSecurityAttributeClassification $true -WarningAction SilentlyContinue

        $Result.AdminTierLevelName | Should -Be 'ManagementPlane'
    }

    It 'lets the custom security attribute tier win over matching user filters' {
        $script:UserCsa = [pscustomobject]@{ privilegedUser = [pscustomobject]@{ adminTierLevel = '0'; adminTierLevelName = 'ControlPlane' } }
        $Disabled = [pscustomobject]@{ Enabled = $false; FilePath = './Classification/ObjectClassification.json' }
        $Filters = [pscustomobject]@{ User = [pscustomobject]@{ Enabled = $true; UserAccess = '$true' } }

        $Result = Get-EntraOpsPrivilegedEntraObject -AadObjectId $script:UserId -TenantId $global:TenantIdContext -CustomSecurityUserAttribute 'privilegedUser' -AlternateObjectTierLevelAttributes $Filters -ObjectClassificationFile $Disabled -CustomSecurityAttributeClassification $true -WarningAction SilentlyContinue

        $Result.AdminTierLevelName | Should -Be 'ControlPlane'
    }

    It 'keeps older configs without CustomSecurityAttributes.Enabled: enabled user filters replace custom security attributes' {
        $script:UserCsa = [pscustomobject]@{ privilegedUser = [pscustomobject]@{ adminTierLevel = '0'; adminTierLevelName = 'ControlPlane' } }
        $Filters = [pscustomobject]@{ Enabled = $true; User = [pscustomobject]@{ UserAccess = '$true' } }

        $Result = Get-EntraOpsPrivilegedEntraObject -AadObjectId $script:UserId -TenantId $global:TenantIdContext -CustomSecurityUserAttribute 'privilegedUser' -AlternateObjectTierLevelAttributes $Filters -WarningAction SilentlyContinue

        $Result.AdminTierLevelName | Should -Be 'UserAccess'
    }

    It 'ignores the custom security attribute tier when it is disabled' {
        $script:UserCsa = [pscustomobject]@{ privilegedUser = [pscustomobject]@{ adminTierLevel = '0'; adminTierLevelName = 'ControlPlane' } }
        $Disabled = [pscustomobject]@{ Enabled = $false; FilePath = './Classification/ObjectClassification.json' }

        $Result = Get-EntraOpsPrivilegedEntraObject -AadObjectId $script:UserId -TenantId $global:TenantIdContext -CustomSecurityUserAttribute 'privilegedUser' -ObjectClassificationFile $Disabled -CustomSecurityAttributeClassification $false -WarningAction SilentlyContinue

        $Result.AdminTierLevelName | Should -Be 'Unclassified'
    }

    It 'lets matching group filters win over a file entry' {
        $GroupFilters = [pscustomobject]@{ Enabled = $false; Group = [pscustomobject]@{ ManagementPlane = '$Object.ObjectDisplayName -like "PRG-Tier1-*"' } }

        $Result = Get-EntraOpsPrivilegedEntraObject -AadObjectId $script:GroupId -TenantId $global:TenantIdContext -AlternateObjectTierLevelAttributes $GroupFilters -ObjectClassificationFile $script:FileSettings -WarningAction SilentlyContinue

        $Result.AdminTierLevelName | Should -Be 'ManagementPlane'
        $Result.AdminTierLevel | Should -Be '1'
    }

    It 'falls back from non-matching group filters to the file entry' {
        $GroupFilters = [pscustomobject]@{ Group = [pscustomobject]@{ Enabled = $true; ManagementPlane = '$Object.ObjectDisplayName -like "Other-*"' } }

        $Result = Get-EntraOpsPrivilegedEntraObject -AadObjectId $script:GroupId -TenantId $global:TenantIdContext -AlternateObjectTierLevelAttributes $GroupFilters -ObjectClassificationFile $script:FileSettings -WarningAction SilentlyContinue

        $Result.AdminTierLevelName | Should -Be 'ControlPlane'
        $Result.AdminTierLevel | Should -Be '0'
    }

    It 'falls back to Alternate Tier Level Attributes when the file is disabled' {
        $GroupFilters = [pscustomobject]@{ Enabled = $false; Group = [pscustomobject]@{ ManagementPlane = '$Object.ObjectDisplayName -like "PRG-Tier1-*"' } }
        $Disabled = [pscustomobject]@{ Enabled = $false; FilePath = './Classification/ObjectClassification.json' }

        $Result = Get-EntraOpsPrivilegedEntraObject -AadObjectId $script:GroupId -TenantId $global:TenantIdContext -AlternateObjectTierLevelAttributes $GroupFilters -ObjectClassificationFile $Disabled -WarningAction SilentlyContinue

        $Result.AdminTierLevelName | Should -Be 'ManagementPlane'
    }

    It 'classifies an object without file entry by the filters of its enabled object type' {
        @(@{ ObjectId = $script:UserId; ObjectType = 'user'; AdminTierLevelName = 'ManagementPlane' }) | ConvertTo-Json -AsArray |
            Set-Content -LiteralPath (Join-Path $global:EntraOpsBaseFolder 'Classification/ObjectClassification.json')
        $Filters = [pscustomobject]@{ Group = [pscustomobject]@{ Enabled = $true; ControlPlane = '$Object.ObjectDisplayName -like "PRG-Tier1-*"' } }

        $Result = Get-EntraOpsPrivilegedEntraObject -AadObjectId $script:GroupId -TenantId $global:TenantIdContext -AlternateObjectTierLevelAttributes $Filters -ObjectClassificationFile $script:FileSettings -WarningAction SilentlyContinue

        $Result.AdminTierLevelName | Should -Be 'ControlPlane'
    }

    It 'ignores the filters of an object type that is not enabled' {
        $Disabled = [pscustomobject]@{ Enabled = $false; FilePath = './Classification/ObjectClassification.json' }
        $Filters = [pscustomobject]@{ Group = [pscustomobject]@{ Enabled = $false; ControlPlane = '$true' } }

        $Result = Get-EntraOpsPrivilegedEntraObject -AadObjectId $script:GroupId -TenantId $global:TenantIdContext -AlternateObjectTierLevelAttributes $Filters -ObjectClassificationFile $Disabled -WarningAction SilentlyContinue

        $Result.AdminTierLevelName | Should -Be 'Unclassified'
    }

    It 'ignores a file entry whose object type does not match' {
        @(@{ ObjectId = $script:GroupId; ObjectType = 'user'; AdminTierLevelName = 'ControlPlane' }) | ConvertTo-Json -AsArray |
            Set-Content -LiteralPath (Join-Path $global:EntraOpsBaseFolder 'Classification/ObjectClassification.json')

        $Result = Get-EntraOpsPrivilegedEntraObject -AadObjectId $script:GroupId -TenantId $global:TenantIdContext -ObjectClassificationFile $script:FileSettings -WarningVariable Warnings -WarningAction SilentlyContinue

        $Result.AdminTierLevelName | Should -Be 'Unclassified'
        ($Warnings -join ' ') | Should -Match 'declares ObjectType'
    }
}
