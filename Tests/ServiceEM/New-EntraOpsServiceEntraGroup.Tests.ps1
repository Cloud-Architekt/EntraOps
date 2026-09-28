#Requires -Modules Pester
#Requires -Version 7.0

BeforeDiscovery {
    $script:TestRepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
}

<#
.SYNOPSIS
    Unit tests for New-EntraOpsServiceEntraGroup function.

.DESCRIPTION
    Tests payload validation, parameter handling, and error conditions
    for the New-EntraOpsServiceEntraGroup function without requiring
    actual Microsoft Graph API calls.

.NOTES
    Issue 4.6: Create mock testing framework
#>

BeforeAll {
    $script:TestRepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
    # Import the module
    $ModulePath = Join-Path $script:TestRepositoryRoot "EntraOps" "EntraOps.psd1"
    Import-Module $ModulePath -Force -ErrorAction Stop
    
    # Script-scoped storage for mock groups (simulates Graph API state)
    $script:MockGroups = @{}
    
    # Mock Invoke-EntraOpsMsGraphQuery to avoid actual API calls
    function Mock-InvokeEntraOpsMsGraphQuery {
        param(
            [string]$Method,
            [string]$Uri,
            [string]$Body,
            [string]$ConsistencyLevel,
            [string]$OutputType,
            [switch]$DisableCache
        )
        
        if ($Method -eq "GET") {
            # Return groups matching the search criteria from mock storage
            $result = @()
            foreach ($group in $script:MockGroups.Values) {
                if ($Uri -match "mailNickname:([^`"]+)") {
                    $searchNickname = $matches[1]
                    if ($group.MailNickname -like "$searchNickname*") {
                        $result += $group
                    }
                }
            }
            return $result
        } elseif ($Method -eq "POST") {
            # Simulate successful group creation and store in mock
            $bodyObj = $Body | ConvertFrom-Json
            $newGroup = [pscustomobject]@{
                Id                 = [guid]::NewGuid().ToString()
                DisplayName        = $bodyObj.displayName
                MailNickname       = $bodyObj.mailNickname
                GroupTypes         = $bodyObj.groupTypes
                IsAssignableToRole = $bodyObj.isAssignableToRole
            }
            $script:MockGroups[$newGroup.Id] = $newGroup
            return $newGroup
        }
    }
    
    Mock Invoke-EntraOpsMsGraphQuery -ModuleName EntraOps -MockWith ${function:Mock-InvokeEntraOpsMsGraphQuery}
}

Describe "New-EntraOpsServiceEntraGroup" {
    BeforeEach {
        # Reset mock group storage for each test
        $script:MockGroups = @{}
    }
    
    Context "Parameter Validation" {
        It "Should throw when ServiceName is empty" {
            { 
                New-EntraOpsServiceEntraGroup `
                    -ServiceName "" `
                    -WorkloadPlaneAdmin "https://graph.microsoft.com/v1.0/users/12345678-1234-1234-1234-123456789012" `
                    -ServiceRoles @() `
                    -ErrorAction Stop
            } | Should -Throw
        }
        
        It "Should allow no WorkloadPlaneAdmin" {
            $roles = @(
                [pscustomobject]@{accessLevel = ""; name = "Members"; groupType = "Unified" }
            )
            { 
                New-EntraOpsServiceEntraGroup `
                    -ServiceName "TestService" `
                    -ServiceRoles $roles `
                    -ErrorAction Stop
            } | Should -Not -Throw
        }
        
        It "Should accept valid OData URL format for WorkloadPlaneAdmin" {
            $roles = @(
                [pscustomobject]@{accessLevel = ""; name = "Members"; groupType = "Unified" }
            )
            
            { 
                New-EntraOpsServiceEntraGroup `
                    -ServiceName "TestService" `
                    -WorkloadPlaneAdmin "https://graph.microsoft.com/v1.0/users/12345678-1234-1234-1234-123456789012" `
                    -ServiceRoles $roles `
                    -ErrorAction Stop
            } | Should -Not -Throw
        }
        
        It "Should accept GUID format for WorkloadPlaneAdmin and convert to OData URL" {
            $roles = @(
                [pscustomobject]@{accessLevel = ""; name = "Members"; groupType = "Unified" }
            )
            
            { 
                New-EntraOpsServiceEntraGroup `
                    -ServiceName "TestService" `
                    -WorkloadPlaneAdmin "12345678-1234-1234-1234-123456789012" `
                    -ServiceRoles $roles `
                    -ErrorAction Stop
            } | Should -Not -Throw
        }
        
        It "Should throw for invalid WorkloadPlaneAdmin format" {
            $roles = @(
                [pscustomobject]@{accessLevel = ""; name = "Members"; groupType = "Unified" }
            )
            
            { 
                New-EntraOpsServiceEntraGroup `
                    -ServiceName "TestService" `
                    -WorkloadPlaneAdmin "invalid-owner-format" `
                    -ServiceRoles $roles `
                    -ErrorAction Stop
            } | Should -Throw
        }
    }
    
    Context "Payload Validation - DisplayName Length" {
        It "Should throw when DisplayName exceeds 256 characters" {
            $longServiceName = "A" * 250
            $roles = @(
                [pscustomobject]@{accessLevel = "ControlPlane"; name = "Admins"; groupType = "" }
            )
            
            { 
                New-EntraOpsServiceEntraGroup `
                    -ServiceName $longServiceName `
                    -WorkloadPlaneAdmin "https://graph.microsoft.com/v1.0/users/12345678-1234-1234-1234-123456789012" `
                    -ServiceRoles $roles `
                    -ErrorAction Stop
            } | Should -Throw -ExpectedMessage "*exceeds maximum length of 256 characters*"
        }
    }
    
    Context "Payload Validation - MailNickname Length" {
        It "Should throw when MailNickname exceeds 64 characters" {
            $longServiceName = "A" * 70
            $roles = @(
                [pscustomobject]@{accessLevel = ""; name = "Members"; groupType = "Unified" }
            )
            
            { 
                New-EntraOpsServiceEntraGroup `
                    -ServiceName $longServiceName `
                    -WorkloadPlaneAdmin "https://graph.microsoft.com/v1.0/users/12345678-1234-1234-1234-123456789012" `
                    -ServiceRoles $roles `
                    -ErrorAction Stop
            } | Should -Throw -ExpectedMessage "*exceeds maximum length of 64 characters*"
        }
    }
    
    Context "Payload Validation - MailNickname Format" {
        It "Should throw when MailNickname contains invalid characters" {
            $roles = @(
                [pscustomobject]@{accessLevel = ""; name = "Members"; groupType = "Unified" }
            )
            
            { 
                New-EntraOpsServiceEntraGroup `
                    -ServiceName "Test Service!" `
                    -WorkloadPlaneAdmin "https://graph.microsoft.com/v1.0/users/12345678-1234-1234-1234-123456789012" `
                    -ServiceRoles $roles `
                    -ErrorAction Stop
            } | Should -Throw -ExpectedMessage "*invalid characters*"
        }
        
        It "Should accept valid MailNickname with dots and underscores" {
            $roles = @(
                [pscustomobject]@{accessLevel = ""; name = "Members"; groupType = "Unified" }
            )
            
            { 
                New-EntraOpsServiceEntraGroup `
                    -ServiceName "Test.Service_01" `
                    -WorkloadPlaneAdmin "https://graph.microsoft.com/v1.0/users/12345678-1234-1234-1234-123456789012" `
                    -ServiceRoles $roles `
                    -ErrorAction Stop
            } | Should -Not -Throw
        }
    }
    
    Context "Group Creation - Unified Groups" {
        It "Should create Unified group with correct properties" {
            $roles = @(
                [pscustomobject]@{accessLevel = ""; name = "Members"; groupType = "Unified" }
            )
            
            $result = New-EntraOpsServiceEntraGroup `
                -ServiceName "TestService" `
                -WorkloadPlaneAdmin "https://graph.microsoft.com/v1.0/users/12345678-1234-1234-1234-123456789012" `
                -ServiceRoles $roles
            
            $result | Should -Not -BeNullOrEmpty
            $result.MailNickname | Should -Contain "TestService.Members"
        }
    }
    
    Context "Group Creation - Security Groups" {
        It "Should create Security group with correct properties" {
            $roles = @(
                [pscustomobject]@{accessLevel = "ControlPlane"; name = "Admins"; groupType = "" }
            )
            
            $result = New-EntraOpsServiceEntraGroup `
                -ServiceName "TestService" `
                -WorkloadPlaneAdmin "https://graph.microsoft.com/v1.0/users/12345678-1234-1234-1234-123456789012" `
                -ServiceRoles $roles
            
            $result | Should -Not -BeNullOrEmpty
            $result.MailNickname | Should -Contain "TestService.ControlPlane.Admins"
        }
        
        It "Should create PIM staging group when NoPimEscalation is not set" {
            $roles = @(
                [pscustomobject]@{accessLevel = "ManagementPlane"; name = "Admins"; groupType = "" }
            )
            
            $result = New-EntraOpsServiceEntraGroup `
                -ServiceName "TestService" `
                -WorkloadPlaneAdmin "https://graph.microsoft.com/v1.0/users/12345678-1234-1234-1234-123456789012" `
                -ServiceRoles $roles
            
            $result | Should -Not -BeNullOrEmpty
            $result.MailNickname | Should -Contain "PIM.TestService.ManagementPlane.Admins"
        }
        
        It "Should NOT create PIM staging group when NoPimEscalation is set" {
            $roles = @(
                [pscustomobject]@{accessLevel = "ManagementPlane"; name = "Admins"; groupType = "" }
            )
            
            $result = New-EntraOpsServiceEntraGroup `
                -ServiceName "TestService" `
                -WorkloadPlaneAdmin "https://graph.microsoft.com/v1.0/users/12345678-1234-1234-1234-123456789012" `
                -ServiceRoles $roles `
                -NoPimEscalation
            
            $result | Should -Not -BeNullOrEmpty
            $result.MailNickname | Should -Not -Contain "PIM.TestService.ManagementPlane.Admins"
        }
    }
    
    Context "IsAssignableToRole behavior" {
        It "Should set IsAssignableToRole for security groups" {
            $roles = @(
                [pscustomobject]@{accessLevel = "ControlPlane"; name = "Admins"; groupType = "" }
            )
            
            $result = New-EntraOpsServiceEntraGroup `
                -ServiceName "TestService" `
                -WorkloadPlaneAdmin "https://graph.microsoft.com/v1.0/users/12345678-1234-1234-1234-123456789012" `
                -ServiceRoles $roles `
                -ErrorAction Stop

            $result.IsAssignableToRole | Should -Contain $true
        }
    }
}

Describe "New-EntraOpsServiceEntraGroup - Error Handling" {
    Context "API Error Simulation" {
        BeforeEach {
            Mock Invoke-EntraOpsMsGraphQuery -ModuleName EntraOps -MockWith {
                throw "Graph API Error: Group already exists"
            }
        }
        
        It "Should handle API errors gracefully" {
            $roles = @(
                [pscustomobject]@{accessLevel = ""; name = "Members"; groupType = "Unified" }
            )
            
            { 
                New-EntraOpsServiceEntraGroup `
                    -ServiceName "TestService" `
                    -WorkloadPlaneAdmin "https://graph.microsoft.com/v1.0/users/12345678-1234-1234-1234-123456789012" `
                    -ServiceRoles $roles `
                    -ErrorAction Stop
            } | Should -Throw
        }
    }
}

AfterAll {
    # Cleanup
    Remove-Module EntraOps -Force -ErrorAction SilentlyContinue
}

