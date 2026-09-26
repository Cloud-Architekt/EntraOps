#Requires -Modules Pester

BeforeAll {
    $script:TestRepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
    function Invoke-EntraOpsMsGraphQuery {
        param($Method, $Uri, $OutputType, $Body, [switch]$SuppressNotFoundWarning, [switch]$ThrowOnFailure, [switch]$DisableCache, $WarningAction)
        throw 'Invoke-EntraOpsMsGraphQuery must be mocked'
    }
    function Invoke-EntraOpsParallelObjectResolution {
        param($UniqueObjects, $TenantId, $EnableParallelProcessing, $ParallelThrottleLimit)
        throw 'Invoke-EntraOpsParallelObjectResolution must be mocked'
    }

    . "$script:TestRepositoryRoot/EntraOps/Public/Core/Get-EntraOpsAgentObject.ps1"
    . "$script:TestRepositoryRoot/EntraOps/Public/PrivilegedAccess/Get-EntraOpsPrivilegedEntraObject.ps1"

    $script:Details = @{
        'id-agent'      = [pscustomobject]@{ ObjectId = 'id-agent'; ObjectType = 'serviceprincipal'; ObjectSubType = 'AgentIdentity'; ObjectDisplayName = 'Agent' }
        'id-blueprint'  = [pscustomobject]@{ ObjectId = 'id-blueprint'; ObjectType = 'application'; ObjectSubType = 'AgentIdentityBlueprint'; ObjectDisplayName = 'Blueprint' }
        'id-principal'  = [pscustomobject]@{ ObjectId = 'id-principal'; ObjectType = 'serviceprincipal'; ObjectSubType = 'AgentIdentityBlueprintPrincipal'; ObjectDisplayName = 'Blueprint' }
        'id-agentuser'  = [pscustomobject]@{ ObjectId = 'id-agentuser'; ObjectType = 'user'; ObjectSubType = 'AgentUser'; ObjectDisplayName = 'Agent user' }
        '11111111-1111-1111-1111-111111111111' = [pscustomobject]@{ ObjectId = '11111111-1111-1111-1111-111111111111'; ObjectType = 'user'; ObjectSubType = 'Member'; ObjectDisplayName = 'Human' }
    }
}

Describe 'Get-EntraOpsAgentObject' {
    BeforeEach {
        Mock Invoke-EntraOpsMsGraphQuery {
            switch -Wildcard ($Uri) {
                '*servicePrincipals/microsoft.graph.agentIdentity[?]*' { return @([pscustomobject]@{ id = 'id-agent' }) }
                '*applications/microsoft.graph.agentIdentityBlueprint[?]*' { return @([pscustomobject]@{ id = 'id-blueprint' }) }
                '*servicePrincipals/microsoft.graph.agentIdentityBlueprintPrincipal[?]*' { return @([pscustomobject]@{ id = 'id-principal' }) }
                '*users/microsoft.graph.agentUser[?]*' { return @([pscustomobject]@{ id = 'id-agentuser' }, [pscustomobject]@{ '@odata.context' = 'envelope' }) }
            }
        }
        Mock Invoke-EntraOpsParallelObjectResolution {
            $result = @{}
            foreach ($object in $UniqueObjects) { $result[$object.ObjectId] = $script:Details[$object.ObjectId] }
            $result
        }
    }

    It 'returns all agent object types regardless of privileged role assignments' {
        $result = @(Get-EntraOpsAgentObject -All -TenantId '' 3>$null 6>$null)

        $result.ObjectId | Should -Be @('id-agent', 'id-blueprint', 'id-principal', 'id-agentuser')
        Should -Invoke Invoke-EntraOpsParallelObjectResolution -Times 1 -Exactly -ParameterFilter { @($UniqueObjects).Count -eq 4 }
    }

    It 'queries only the requested agent object types' {
        $result = @(Get-EntraOpsAgentObject -All -AgentObjectType AgentUser -TenantId '')

        $result.ObjectId | Should -Be @('id-agentuser')
        Should -Invoke Invoke-EntraOpsMsGraphQuery -Times 1 -Exactly
    }

    It 'continues with the other types when one type cannot be listed' {
        Mock Invoke-EntraOpsMsGraphQuery {
            if ($Uri -like '*agentIdentityBlueprint[?]*') { throw 'BadRequest' }
            if ($Uri -like '*agentUser[?]*') { return @([pscustomobject]@{ id = 'id-agentuser' }) }
        }

        $result = @(Get-EntraOpsAgentObject -All -AgentObjectType AgentIdentityBlueprint, AgentUser -TenantId '' -WarningVariable warnings -WarningAction SilentlyContinue)

        $result.ObjectId | Should -Be @('id-agentuser')
        @($warnings | Where-Object { "$_" -like '*AgentIdentityBlueprint*' }).Count | Should -Be 1
    }

    It 'skips objects that are not agent objects when requested by ObjectId' {
        $result = @(Get-EntraOpsAgentObject -ObjectId '11111111-1111-1111-1111-111111111111' -TenantId '' -WarningVariable warnings -WarningAction SilentlyContinue)

        $result.Count | Should -Be 0
        @($warnings | Where-Object { "$_" -like '*not an agent object*' }).Count | Should -Be 1
    }
}

Describe 'Get-EntraOpsPrivilegedEntraObject agent identity blueprint' {
    BeforeEach {
        $global:TenantIdContext = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
        $global:EntraOpsConfig = [pscustomobject]@{
            CustomSecurityAttributes           = [pscustomobject]@{}
            AlternateObjectTierLevelAttributes = $null
        }
    }

    It 'resolves a blueprint application as application with subtype AgentIdentityBlueprint and its sponsors' {
        $blueprintId = '22222222-2222-2222-2222-222222222222'
        Mock Invoke-EntraOpsMsGraphQuery {
            if ($Uri -like "/beta/directoryObjects/$blueprintId[?]*") {
                return [pscustomobject]@{ '@odata.type' = '#microsoft.graph.agentIdentityBlueprint'; id = $blueprintId; displayName = 'Blueprint'; isManagementRestricted = $false }
            }
            if ($Uri -like "/beta/applications/$blueprintId[?]*") { return [pscustomobject]@{ id = $blueprintId; appId = 'app-1'; displayName = 'Blueprint' } }
            if ($Uri -like '*/microsoft.graph.agentIdentityBlueprint/sponsors*') { return @([pscustomobject]@{ id = 'sponsor-1' }) }
            return @()
        }

        $result = Get-EntraOpsPrivilegedEntraObject -AadObjectId $blueprintId -TenantId $global:TenantIdContext 3>$null

        $result.ObjectType | Should -Be 'application'
        $result.ObjectSubType | Should -Be 'AgentIdentityBlueprint'
        $result.ObjectSignInName | Should -Be 'app-1'
        $result.Sponsors | Should -Be @('sponsor-1')
    }
}
