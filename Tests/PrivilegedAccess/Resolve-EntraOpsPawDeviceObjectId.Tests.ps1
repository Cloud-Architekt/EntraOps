#Requires -Modules Pester

BeforeAll {
    $script:TestRepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
    function Invoke-EntraOpsMsGraphQuery {
        param($Method, $Uri, $OutputType, $Body, [switch]$SuppressNotFoundWarning, [switch]$ThrowOnFailure, [switch]$DisableCache, $WarningAction)
        throw 'Invoke-EntraOpsMsGraphQuery must be mocked'
    }
    . "$script:TestRepositoryRoot/EntraOps/Private/Resolve-EntraOpsPawDeviceObjectId.ps1"
    . "$script:TestRepositoryRoot/EntraOps/Private/Write-EntraOpsWarningOnce.ps1"

    $script:DeviceId = '22222222-2222-2222-2222-222222222222'
    $script:ObjectId = '33333333-3333-3333-3333-333333333333'
    function script:New-GraphError([int]$StatusCode) {
        $Exception = [System.InvalidOperationException]::new("Microsoft Graph query failed ($StatusCode)")
        $Exception.Data['StatusCode'] = $StatusCode
        $Exception
    }
}

Describe 'Resolve-EntraOpsPawDeviceObjectId' {
    BeforeEach {
        # A tenant with one device (SAW3): device ID and object ID differ.
        Mock Invoke-EntraOpsMsGraphQuery {
            if ($Uri -like '/v1.0/devices[?]*') {
                if ($Uri -like "*deviceId eq '$($script:DeviceId)'*") { return @([pscustomobject]@{ id = $script:ObjectId }) }
                return @()
            }
            if ($Uri -like "/v1.0/devices/$($script:ObjectId)*") { return [pscustomobject]@{ id = $script:ObjectId } }
            throw (New-GraphError 404)
        }
    }

    It 'resolves a device ID to the object ID of the device' {
        Resolve-EntraOpsPawDeviceObjectId -Value $script:DeviceId -UserId 'user' | Should -Be $script:ObjectId
        Should -Invoke Invoke-EntraOpsMsGraphQuery -Times 1 -Exactly
    }

    It 'keeps an object ID of a device' {
        Resolve-EntraOpsPawDeviceObjectId -Value $script:ObjectId.ToUpperInvariant() -UserId 'user' | Should -Be $script:ObjectId
    }

    It 'drops a reference that matches no device, with a warning' {
        $Result = Resolve-EntraOpsPawDeviceObjectId -Value '99999999-9999-9999-9999-999999999999' -UserId 'user' -WarningVariable Warnings -WarningAction SilentlyContinue
        $Result | Should -BeNullOrEmpty
        $Warnings[0].Message | Should -Match 'matches no device'
    }

    It 'keeps a reference that cannot be checked' {
        Mock Invoke-EntraOpsMsGraphQuery { throw (New-GraphError 503) }
        Resolve-EntraOpsPawDeviceObjectId -Value $script:DeviceId -UserId 'user' -WarningAction SilentlyContinue | Should -Be $script:DeviceId
    }

    It 'ignores a reference that is no ID, with a warning' {
        Resolve-EntraOpsPawDeviceObjectId -Value 'SAW3' -UserId 'user' -WarningAction SilentlyContinue | Should -BeNullOrEmpty
        Should -Invoke Invoke-EntraOpsMsGraphQuery -Times 0 -Exactly
    }
}
