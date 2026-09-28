#Requires -Modules Pester

BeforeDiscovery {
    $script:TestRepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
}

BeforeAll {
    $script:TestRepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
    function Invoke-EntraOpsMsGraphQuery {
        param($Method, $Uri, $OutputType, $Body, [switch]$SuppressBadRequestWarning, [switch]$ThrowOnFailure, [switch]$DisableCache)
        throw "Invoke-EntraOpsMsGraphQuery must be mocked"
    }
    . "$script:TestRepositoryRoot/EntraOps/Public/PrivilegedAccess/Get-EntraOpsPrivilegedTransitiveGroupMember.ps1"
}

Describe "Get-EntraOpsPrivilegedTransitiveGroupMember PIM capability handling" {
    BeforeEach {
        $global:__EntraOpsSession = [pscustomobject]@{ NonPimGroupIds = @{} }
        $script:ProbeStatusCode = $null
        $script:ProbeResult = @()

        Mock Invoke-EntraOpsMsGraphQuery {
            if ($Uri -match '^/beta/groups/[^/]+\?\$select=') {
                return [pscustomobject]@{ Id = "group-id"; DisplayName = "Test group"; onPremisesSyncEnabled = $false }
            }
            if ($Uri -like "*/eligibilitySchedules?*") {
                if ($null -ne $script:ProbeStatusCode) {
                    $Exception = [System.Exception]::new("Graph capability probe failed")
                    $Exception.Data['StatusCode'] = $script:ProbeStatusCode
                    throw $Exception
                }
                return $script:ProbeResult
            }
            if ($Uri -like "*/transitiveMembers?*") { return @() }
            throw "Unexpected Graph URI: $Uri"
        }
    }

    It "caches HTTP 400 as a non-PIM-capable group and probes only once" {
        $script:ProbeStatusCode = 400

        @(Get-EntraOpsPrivilegedTransitiveGroupMember -GroupObjectId "group-id").Count | Should -Be 0
        @(Get-EntraOpsPrivilegedTransitiveGroupMember -GroupObjectId "group-id").Count | Should -Be 0

        $global:__EntraOpsSession.NonPimGroupIds.ContainsKey("group-id") | Should -BeTrue
        Should -Invoke Invoke-EntraOpsMsGraphQuery -Times 1 -Exactly -ParameterFilter {
            $Uri -like "*/eligibilitySchedules?*" -and $ThrowOnFailure -and $SuppressBadRequestWarning
        }
    }

    It "caches a successful empty capability response" {
        @(Get-EntraOpsPrivilegedTransitiveGroupMember -GroupObjectId "group-id").Count | Should -Be 0

        $global:__EntraOpsSession.NonPimGroupIds.ContainsKey("group-id") | Should -BeTrue
    }

    It "propagates non-capability HTTP failures" -TestCases @(
        @{ StatusCode = 403 }
        @{ StatusCode = 429 }
        @{ StatusCode = 500 }
    ) {
        $script:ProbeStatusCode = $StatusCode

        { Get-EntraOpsPrivilegedTransitiveGroupMember -GroupObjectId "group-id" -ErrorAction SilentlyContinue } |
            Should -Throw "*Validation of Group object with ID group-id*"
        $global:__EntraOpsSession.NonPimGroupIds.ContainsKey("group-id") | Should -BeFalse
    }
}
