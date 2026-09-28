#Requires -Modules Pester

BeforeDiscovery {
    $script:TestRepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
}

BeforeAll {
    $script:TestRepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
    . "$script:TestRepositoryRoot/EntraOps/Private/Select-EntraOpsAzureRbacPrincipal.ps1"

    $script:DeletedPrincipalId = '4fbcb88a-18b5-42cf-82ac-30ca6d4f6919'
    $script:UnresolvedPrincipalId = '11111111-1111-1111-1111-111111111111'
    $script:ResolvedPrincipalId = '22222222-2222-2222-2222-222222222222'
}

Describe 'Select-EntraOpsAzureRbacPrincipal' {
    BeforeEach {
        $script:UniqueObjects = @(
            [pscustomobject]@{ ObjectId = $script:DeletedPrincipalId; ObjectType = 'unknown' }
            [pscustomobject]@{ ObjectId = $script:UnresolvedPrincipalId; ObjectType = 'user' }
            [pscustomobject]@{ ObjectId = $script:ResolvedPrincipalId; ObjectType = 'group' }
        )
        $script:ObjectDetailsCache = @{
            $script:DeletedPrincipalId = [pscustomobject]@{ ObjectType = 'unknown'; ResolutionStatus = 'NotFound' }
            $script:UnresolvedPrincipalId = [pscustomobject]@{ ObjectType = 'unknown'; ResolutionStatus = 'Unresolved' }
            $script:ResolvedPrincipalId = [pscustomobject]@{ ObjectType = 'group'; ResolutionStatus = 'Resolved' }
        }
    }

    It 'filters only confirmed deleted principals by default' {
        $Result = @(Select-EntraOpsAzureRbacPrincipal -UniqueObjects $script:UniqueObjects -ObjectDetailsCache $script:ObjectDetailsCache)

        $Result.ObjectId | Should -Not -Contain $script:DeletedPrincipalId
        $Result.ObjectId | Should -Contain $script:UnresolvedPrincipalId
        $Result.ObjectId | Should -Contain $script:ResolvedPrincipalId
    }

    It 'keeps every principal when explicitly configured' {
        $Result = @(Select-EntraOpsAzureRbacPrincipal -UniqueObjects $script:UniqueObjects -ObjectDetailsCache $script:ObjectDetailsCache -DeletedPrincipalAssignmentHandling Keep)

        $Result.ObjectId | Should -Be $script:UniqueObjects.ObjectId
    }

    It 'filters only principals confirmed not found' {
        $Result = @(Select-EntraOpsAzureRbacPrincipal -UniqueObjects $script:UniqueObjects -ObjectDetailsCache $script:ObjectDetailsCache -DeletedPrincipalAssignmentHandling Filter)

        $Result.ObjectId | Should -Not -Contain $script:DeletedPrincipalId
        $Result.ObjectId | Should -Contain $script:UnresolvedPrincipalId
        $Result.ObjectId | Should -Contain $script:ResolvedPrincipalId
    }

    It 'retains a null cache entry because it is unresolved rather than confirmed deleted' {
        $script:ObjectDetailsCache[$script:UnresolvedPrincipalId] = $null

        $Result = @(Select-EntraOpsAzureRbacPrincipal -UniqueObjects $script:UniqueObjects -ObjectDetailsCache $script:ObjectDetailsCache -DeletedPrincipalAssignmentHandling Filter)

        $Result.ObjectId | Should -Contain $script:UnresolvedPrincipalId
    }

    It 'accepts an empty principal list and returns an empty result' {
        { Select-EntraOpsAzureRbacPrincipal -UniqueObjects @() -ObjectDetailsCache @{} } | Should -Not -Throw
        @(Select-EntraOpsAzureRbacPrincipal -UniqueObjects @() -ObjectDetailsCache @{}) | Should -BeNullOrEmpty
    }

    It 'returns an empty result when every principal is confirmed deleted' {
        $AllDeletedCache = @{}
        foreach ($Object in $script:UniqueObjects) {
            $AllDeletedCache[$Object.ObjectId] = [pscustomobject]@{ ObjectType = 'unknown'; ResolutionStatus = 'NotFound' }
        }

        @(Select-EntraOpsAzureRbacPrincipal -UniqueObjects $script:UniqueObjects -ObjectDetailsCache $AllDeletedCache -DeletedPrincipalAssignmentHandling Filter) | Should -BeNullOrEmpty
    }
}
