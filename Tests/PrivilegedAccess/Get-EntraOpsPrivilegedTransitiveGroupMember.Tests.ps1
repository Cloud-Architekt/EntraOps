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

    It "throws for a failed member query only with -ThrowOnQueryFailure" {
        # Invoke-EntraOpsMsGraphQuery returns $null for a failed query unless -ThrowOnFailure is set
        Mock Invoke-EntraOpsMsGraphQuery {
            if ($Uri -match '^/beta/groups/[^/]+\?\$select=') { return [pscustomobject]@{ Id = "group-id"; DisplayName = "Test group"; onPremisesSyncEnabled = $false } }
            if ($Uri -like "*/eligibilitySchedules?*") { return @() }
            if ($Uri -like "*/transitiveMembers?*") {
                if ($ThrowOnFailure) { throw "HTTP 403 for $Uri" }
                return $null
            }
            throw "Unexpected Graph URI: $Uri"
        }

        @(Get-EntraOpsPrivilegedTransitiveGroupMember -GroupObjectId "group-id").Count | Should -Be 0
        { Get-EntraOpsPrivilegedTransitiveGroupMember -GroupObjectId "group-id" -ThrowOnQueryFailure } | Should -Throw "*HTTP 403*"
    }
}

Describe "Get-EntraOpsPrivilegedTransitiveGroupMember membership types of a PIM for Groups group" {
    BeforeAll {
        function New-Principal([string]$Id, [string]$Type = 'user') { [pscustomobject]@{ Id = $Id; DisplayName = "Name $Id"; '@odata.type' = "#microsoft.graph.$Type" } }
    }
    BeforeEach {
        $global:__EntraOpsSession = [pscustomobject]@{ NonPimGroupIds = @{} }
        Mock Invoke-EntraOpsMsGraphQuery {
            if ($Uri -match '^/beta/groups/([^/?]+)\?\$select=') {
                return [pscustomobject]@{ Id = $Matches[1]; DisplayName = "Group $($Matches[1])"; onPremisesSyncEnabled = $false }
            }
            if ($Uri -like "*/eligibilitySchedules?*") {
                if ($Uri -like "*'group-a'*") {
                    return @(
                        [pscustomobject]@{ status = 'Provisioned'; accessId = 'member'; principal = (New-Principal 'user-eligible') }
                        [pscustomobject]@{ status = 'Provisioned'; accessId = 'member'; principal = (New-Principal 'user-eligible-activated') }
                        [pscustomobject]@{ status = 'Provisioned'; accessId = 'member'; principal = (New-Principal 'group-c' 'group') }
                    )
                }
                return @()
            }
            if ($Uri -like "*/assignmentScheduleInstances?*") {
                return @(
                    [pscustomobject]@{ assignmentType = 'assigned'; accessId = 'member'; endDateTime = $null; principal = (New-Principal 'user-permanent') }
                    [pscustomobject]@{ assignmentType = 'assigned'; accessId = 'member'; endDateTime = '2027-01-01T00:00:00Z'; principal = (New-Principal 'user-timebound') }
                    [pscustomobject]@{ assignmentType = 'activated'; accessId = 'member'; endDateTime = '2026-11-12T18:00:00Z'; principal = (New-Principal 'user-activated') }
                    [pscustomobject]@{ assignmentType = 'activated'; accessId = 'member'; endDateTime = '2026-11-12T18:00:00Z'; principal = (New-Principal 'user-eligible-activated') }
                    [pscustomobject]@{ assignmentType = 'assigned'; accessId = 'owner'; endDateTime = $null; principal = (New-Principal 'user-owner') }
                    [pscustomobject]@{ assignmentType = 'assigned'; accessId = 'member'; endDateTime = $null; principal = (New-Principal 'group-b' 'group') }
                )
            }
            if ($Uri -like "/beta/groups/group-b/transitiveMembers?*") { return @(New-Principal 'user-nested-permanent') }
            if ($Uri -like "/beta/groups/group-c/transitiveMembers?*") { return @(New-Principal 'user-nested-eligible') }
            throw "Unexpected Graph URI: $Uri"
        }
    }

    It "labels each member by the type of its membership" {
        $Members = @(Get-EntraOpsPrivilegedTransitiveGroupMember -GroupObjectId 'group-a')
        $SubType = @{}
        foreach ($Member in $Members) { $SubType[$Member.Id] = $Member.RoleAssignmentSubType }

        $SubType['user-permanent'] | Should -Be 'Permanent member'
        $SubType['user-timebound'] | Should -Be 'Time-bound member'
        $SubType['user-activated'] | Should -Be 'Active member'
        $SubType['user-eligible'] | Should -Be 'Eligible member'
        # An activated eligible member stays eligible (once): its activation is a temporary instance of the eligibility.
        @($Members | Where-Object Id -eq 'user-eligible-activated').RoleAssignmentSubType | Should -Be @('Eligible member')
        # Owners of the group are no members.
        $SubType.ContainsKey('user-owner') | Should -BeFalse
        # Permanent member of a group that is a permanent member: standing access.
        $SubType['user-nested-permanent'] | Should -Be 'Nested Permanent group member'
        # Member of a group that is an eligible member: needs an activation.
        $SubType['user-nested-eligible'] | Should -BeLike 'Nested Eligible*'
    }
}
