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
            } | Should -Throw -ExpectedMessage "*ServiceName 'Test Service!' is invalid*"
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
        
        It "Should ignore legacy PIM staging groups returned by the group search" {
            $roles = @(
                [pscustomobject]@{accessLevel = "ManagementPlane"; name = "Admins"; groupType = "" }
            )
            $legacy = [pscustomobject]@{ Id = 'legacy-pim'; DisplayName = 'SG-PIM-TestService-ManagementPlane-Admins'; MailNickname = 'PIM.TestService.ManagementPlane.Admins' }
            $script:MockGroups[$legacy.Id] = $legacy
            # $search matches tokens inside the mailNickname, not only its prefix
            Mock Invoke-EntraOpsMsGraphQuery -ModuleName EntraOps -ParameterFilter { $Method -eq 'GET' } -MockWith { @($script:MockGroups.Values) }
            
            $result = New-EntraOpsServiceEntraGroup `
                -ServiceName "TestService" `
                -WorkloadPlaneAdmin "https://graph.microsoft.com/v1.0/users/12345678-1234-1234-1234-123456789012" `
                -ServiceRoles $roles
            
            $result.MailNickname | Should -Contain "TestService.ManagementPlane.Admins"
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

        It "Should create admin and catalog groups role-assignable, but not WorkloadPlane groups by default" {
            $roles = @(
                [pscustomobject]@{accessLevel = "ControlPlane"; name = "Admins"; groupType = "" },
                [pscustomobject]@{accessLevel = "ManagementPlane"; name = "Admins"; groupType = "" },
                [pscustomobject]@{accessLevel = "CatalogPlane"; name = "Members"; groupType = "" },
                [pscustomobject]@{accessLevel = "WorkloadPlane"; name = "Admins"; groupType = "" },
                [pscustomobject]@{accessLevel = "WorkloadPlane"; name = "Users"; groupType = "" }
            )

            $result = New-EntraOpsServiceEntraGroup -ServiceName "TestService" -ServiceRoles $roles

            @($result | Where-Object IsAssignableToRole | ForEach-Object MailNickname | Sort-Object) |
            Should -Be @('TestService.CatalogPlane.Members', 'TestService.ControlPlane.Admins', 'TestService.ManagementPlane.Admins')
        }

        It "Should create a security group for groupType Security" {
            $roles = @([pscustomobject]@{accessLevel = "WorkloadPlane"; name = "Users"; groupType = "Security" })

            $result = New-EntraOpsServiceEntraGroup -ServiceName "TestService" -ServiceRoles $roles

            @($result).MailNickname | Should -Be @('TestService.WorkloadPlane.Users')
            @($result).DisplayName | Should -Be @('SG-TestService-WorkloadPlane-Users')
            Should -Invoke Invoke-EntraOpsMsGraphQuery -ModuleName EntraOps -Times 1 -Exactly -ParameterFilter { $Method -eq 'POST' -and ($Body | ConvertFrom-Json).groupTypes -eq $null }
        }

        It "Should create WorkloadPlane-Admins role-assignable only with RoleAssignableWorkloadPlaneAdmins" {
            $roles = @(
                [pscustomobject]@{accessLevel = "WorkloadPlane"; name = "Users"; groupType = "" },
                [pscustomobject]@{accessLevel = "WorkloadPlane"; name = "Admins"; groupType = "" }
            )

            $result = New-EntraOpsServiceEntraGroup -ServiceName "TestService" -ServiceRoles $roles -RoleAssignableWorkloadPlaneAdmins

            ($result | Where-Object MailNickname -EQ 'TestService.WorkloadPlane.Admins').IsAssignableToRole | Should -BeTrue
            ($result | Where-Object MailNickname -EQ 'TestService.WorkloadPlane.Users').IsAssignableToRole | Should -BeFalse
        }
    }

    Context "Group naming" {
        It "Should not add a delimiter after a GroupPrefix that ends with a separator" {
            $roles = @([pscustomobject]@{accessLevel = "WorkloadPlane"; name = "Admins"; groupType = "" })

            $underscore = New-EntraOpsServiceEntraGroup -ServiceName "Rg-A" -ServiceRoles $roles -GroupPrefix 'SG_'
            $plain = New-EntraOpsServiceEntraGroup -ServiceName "Rg-B" -ServiceRoles $roles -GroupPrefix 'SG'

            $underscore.DisplayName | Should -Be 'SG_Rg-A-WorkloadPlane-Admins'
            $plain.DisplayName | Should -Be 'SG-Rg-B-WorkloadPlane-Admins'
        }

        It "Should reject a GroupNamingDelimiter that the other ServiceEM cmdlets can't match" {
            $roles = @([pscustomobject]@{accessLevel = "WorkloadPlane"; name = "Admins"; groupType = "" })

            { New-EntraOpsServiceEntraGroup -ServiceName "Rg-A" -ServiceRoles $roles -GroupNamingDelimiter '_' } | Should -Throw '*does not belong to the set*'
        }
    }

    Context "Reuse of existing groups" {
        BeforeEach {
            $script:AdminRoles = @([pscustomobject]@{accessLevel = "ControlPlane"; name = "Admins"; groupType = "" })
            $script:WorkloadRoles = @([pscustomobject]@{accessLevel = "WorkloadPlane"; name = "Users"; groupType = "" })
        }

        It "Should not reuse a pre-created ControlPlane group that isn't role-assignable" {
            $squatted = [pscustomobject]@{ Id = 'squatted'; DisplayName = 'SG-TestService-ControlPlane-Admins'; MailNickname = 'TestService.ControlPlane.Admins'; IsAssignableToRole = $false; SecurityEnabled = $true }
            $script:MockGroups[$squatted.Id] = $squatted

            { New-EntraOpsServiceEntraGroup -ServiceName "TestService" -ServiceRoles $script:AdminRoles } |
            Should -Throw "*'SG-TestService-ControlPlane-Admins' (squatted*isn't a role-assignable security group*"
            Should -Invoke Invoke-EntraOpsMsGraphQuery -ModuleName EntraOps -Times 0 -Exactly -ParameterFilter { $Method -eq 'POST' }
        }

        It "Should reuse an existing role-assignable ControlPlane group" {
            $existing = [pscustomobject]@{ Id = 'existing-cp'; DisplayName = 'SG-TestService-ControlPlane-Admins'; MailNickname = 'TestService.ControlPlane.Admins'; IsAssignableToRole = $true; SecurityEnabled = $true }
            $script:MockGroups[$existing.Id] = $existing

            $result = New-EntraOpsServiceEntraGroup -ServiceName "TestService" -ServiceRoles $script:AdminRoles

            @($result).Id | Should -Be @('existing-cp')
            Should -Invoke Invoke-EntraOpsMsGraphQuery -ModuleName EntraOps -Times 0 -Exactly -ParameterFilter { $Method -eq 'POST' }
        }

        It "Should not reuse a pre-created WorkloadPlane group that isn't a resource of the service catalog" {
            $squatted = [pscustomobject]@{ Id = 'squatted'; DisplayName = 'SG-TestService-WorkloadPlane-Users'; MailNickname = 'TestService.WorkloadPlane.Users'; IsAssignableToRole = $false; SecurityEnabled = $true }
            $script:MockGroups[$squatted.Id] = $squatted

            { New-EntraOpsServiceEntraGroup -ServiceName "TestService" -ServiceRoles $script:WorkloadRoles } |
            Should -Throw "*isn't a resource of the catalog 'Catalog-TestService'*"
            Should -Invoke Invoke-EntraOpsMsGraphQuery -ModuleName EntraOps -Times 0 -Exactly -ParameterFilter { $Method -eq 'POST' }
        }

        It "Should reuse a WorkloadPlane group that is a resource of the service catalog" {
            $existing = [pscustomobject]@{ Id = 'existing-wu'; DisplayName = 'SG-TestService-WorkloadPlane-Users'; MailNickname = 'TestService.WorkloadPlane.Users'; IsAssignableToRole = $false; SecurityEnabled = $true }
            $script:MockGroups[$existing.Id] = $existing
            Mock Invoke-EntraOpsMsGraphQuery -ModuleName EntraOps -ParameterFilter { $Uri -like '*/catalogs?*' } -MockWith {
                @([pscustomobject]@{ Id = 'cat'; DisplayName = 'Catalog-TestService'; Resources = @([pscustomobject]@{ OriginId = 'existing-wu' }) })
            }

            $result = New-EntraOpsServiceEntraGroup -ServiceName "TestService" -ServiceRoles $script:WorkloadRoles

            @($result).Id | Should -Be @('existing-wu')
            Should -Invoke Invoke-EntraOpsMsGraphQuery -ModuleName EntraOps -Times 0 -Exactly -ParameterFilter { $Method -eq 'POST' }
        }

        It "Should not return other groups with the ServiceName mailNickname prefix" {
            $extra = [pscustomobject]@{ Id = 'extra'; DisplayName = 'Evil-ControlPlane-Admins'; MailNickname = 'TestService.Extra'; IsAssignableToRole = $false; SecurityEnabled = $true }
            $script:MockGroups[$extra.Id] = $extra

            $result = New-EntraOpsServiceEntraGroup -ServiceName "TestService" -ServiceRoles $script:AdminRoles

            @($result).MailNickname | Should -Be @('TestService.ControlPlane.Admins')
        }

        It "Should stop without creating groups when the lookup of existing groups fails" {
            Mock Invoke-EntraOpsMsGraphQuery -ModuleName EntraOps -ParameterFilter { $Method -eq 'GET' } -MockWith { if ($ThrowOnFailure) { throw 'Graph unavailable' } }

            { New-EntraOpsServiceEntraGroup -ServiceName "TestService" -ServiceRoles $script:AdminRoles } |
            Should -Throw "*Failed to look up the existing groups of 'TestService'*"
            Should -Invoke Invoke-EntraOpsMsGraphQuery -ModuleName EntraOps -Times 0 -Exactly -ParameterFilter { $Method -eq 'POST' }
        }

        It "Should stop when the mailNickname is ambiguous" {
            foreach ($id in 'dup1', 'dup2') {
                $script:MockGroups[$id] = [pscustomobject]@{ Id = $id; DisplayName = 'SG-TestService-ControlPlane-Admins'; MailNickname = 'TestService.ControlPlane.Admins'; IsAssignableToRole = $true; SecurityEnabled = $true }
            }

            { New-EntraOpsServiceEntraGroup -ServiceName "TestService" -ServiceRoles $script:AdminRoles } | Should -Throw "*Found 2 groups with mailNickname 'TestService.ControlPlane.Admins'*"
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

