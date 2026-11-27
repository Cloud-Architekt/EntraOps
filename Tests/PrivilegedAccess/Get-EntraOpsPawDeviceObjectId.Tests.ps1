#Requires -Modules Pester

BeforeAll {
    $script:TestRepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
    . "$script:TestRepositoryRoot/EntraOps/Private/Get-EntraOpsPawDeviceObjectId.ps1"
}

Describe 'Get-EntraOpsPawDeviceObjectId' {
    It 'returns the resolved object IDs, not the references of the attribute' {
        $Object = [pscustomobject]@{ AssociatedPawDevice = @('device-id'); AssociatedPawDeviceObjectId = @('object-id') }
        Get-EntraOpsPawDeviceObjectId -Object $Object | Should -Be @('object-id')
    }

    It 'returns nothing when the reference matched no device' {
        $Object = [pscustomobject]@{ AssociatedPawDevice = @('device-id'); AssociatedPawDeviceObjectId = @() }
        @(Get-EntraOpsPawDeviceObjectId -Object $Object).Count | Should -Be 0
    }

    It 'falls back to the references for exports without the resolved field' {
        Get-EntraOpsPawDeviceObjectId -Object ([pscustomobject]@{ AssociatedPawDevice = @('paw-one', '') }) | Should -Be @('paw-one')
        Get-EntraOpsPawDeviceObjectId -Object @{ AssociatedPawDevice = @('paw-two') } | Should -Be @('paw-two')
        Get-EntraOpsPawDeviceObjectId -Object @{ AssociatedPawDevice = @('ref'); AssociatedPawDeviceObjectId = @('id') } | Should -Be @('id')
        @(Get-EntraOpsPawDeviceObjectId -Object $null).Count | Should -Be 0
    }
}
