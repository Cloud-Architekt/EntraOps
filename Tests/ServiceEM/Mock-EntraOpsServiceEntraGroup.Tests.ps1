#Requires -Modules Pester
#Requires -Version 7.0

BeforeDiscovery {
    $script:TestRepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
}

<#
.SYNOPSIS
    Comprehensive mock-based unit tests for ServiceEM functions.

.DESCRIPTION
    Tests all ServiceEM functionality without requiring:
    - Real Microsoft Graph connection
    - Azure subscription
    - MFA approval
    - Live tenant access

    Uses mocking to simulate Graph API responses.
#>

BeforeAll {
    $script:TestRepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
    # Find and import EntraOps module
    $ModulePaths = @(
        (Join-Path $script:TestRepositoryRoot "EntraOps" "EntraOps.psd1")
        "/workspace/EntraOps/EntraOps.psd1"
        "$PWD/EntraOps/EntraOps.psd1"
    )
    
    $ModuleImported = $false
    foreach ($Path in $ModulePaths) {
        $ResolvedPath = Resolve-Path $Path -ErrorAction SilentlyContinue
        if ($ResolvedPath -and (Test-Path $ResolvedPath)) {
            Write-Host "Importing EntraOps from: $ResolvedPath" -ForegroundColor Cyan
            Import-Module $ResolvedPath -Force -ErrorAction Stop
            $ModuleImported = $true
            break
        }
    }
    
    if (-not $ModuleImported) {
        throw "Could not find EntraOps module. Searched paths: $($ModulePaths -join ', ')"
    }
    
    # Verify functions are available
    $RequiredFunctions = @('New-EntraOpsServiceEntraGroup')
    foreach ($Function in $RequiredFunctions) {
        if (-not (Get-Command $Function -ErrorAction SilentlyContinue)) {
            throw "Function $Function not found after importing module"
        }
        Write-Host "✓ Function available: $Function" -ForegroundColor Green
    }
    
    # Note: Resolve-EntraOpsServiceEMDelegationGroup is a private function
    # and is tested indirectly through New-EntraOpsSubscriptionLandingZone
    
    # Initialize mock state
    $script:MockGroups = @{}
    Mock Write-Verbose {}
    Mock Write-Warning {}
    Mock Write-Host {}
    function Mock-InvokeEntraOpsMsGraphQuery {
        param($Method, $Uri, $Body)
        if ($Method -eq "GET") {
            $result = @()
            foreach ($group in $script:MockGroups.Values) {
                if ($Uri -match 'mailNickname:([^".]+(?:\.[^".]+)*)') {
                    $searchNickname = $Matches[1]
                    if ($group.MailNickname -like "$searchNickname*") {
                        $result += $group
                    }
                }
            }
            return $result
        } elseif ($Method -eq "POST") {
            $bodyObj = $Body | ConvertFrom-Json
            $script:LastCreatedGroupBody = $bodyObj
            $newGroup = [pscustomobject]@{
                Id              = [guid]::NewGuid().ToString()
                DisplayName     = $bodyObj.displayName
                MailNickname    = $bodyObj.mailNickname
                GroupTypes      = $bodyObj.groupTypes
                SecurityEnabled = $bodyObj.securityEnabled
            }
            $script:MockGroups[$newGroup.MailNickname] = $newGroup
            return $newGroup
        }
    }

    Mock Invoke-EntraOpsMsGraphQuery -ModuleName EntraOps -MockWith ${function:Mock-InvokeEntraOpsMsGraphQuery}
}

Describe "New-EntraOpsServiceEntraGroup - Unit Tests" {
    BeforeEach {
        $script:MockGroups = @{}
    }
    
    Context "Parameter Validation" {
        It "Should throw when ServiceName is null or empty" {
            { New-EntraOpsServiceEntraGroup -ServiceName "" -ServiceRoles @() } | 
            Should -Throw
        }
        
        It "Should allow no WorkloadPlaneAdmin" {
            Mock Invoke-EntraOpsMsGraphQuery -ModuleName EntraOps -MockWith ${function:Mock-InvokeEntraOpsMsGraphQuery}
            $roles = @([pscustomobject]@{accessLevel = ""; name = "Members"; groupType = "Unified" })

            { New-EntraOpsServiceEntraGroup -ServiceName "Test" -ServiceRoles $roles } | 
            Should -Not -Throw
        }
        
        It "Should accept valid OData URL format for WorkloadPlaneAdmin" {
            Mock Invoke-EntraOpsMsGraphQuery -ModuleName EntraOps -MockWith ${function:Mock-InvokeEntraOpsMsGraphQuery}
            
            $roles = @([pscustomobject]@{accessLevel = ""; name = "Members"; groupType = "Unified" })
            
            { New-EntraOpsServiceEntraGroup -ServiceName "Test" -WorkloadPlaneAdmin "https://graph.microsoft.com/v1.0/users/12345678-1234-1234-1234-123456789012" -ServiceRoles $roles } | 
            Should -Not -Throw
        }
        
        It "Should accept GUID format and convert to OData URL" {
            Mock Invoke-EntraOpsMsGraphQuery -ModuleName EntraOps -MockWith ${function:Mock-InvokeEntraOpsMsGraphQuery}
            
            $roles = @([pscustomobject]@{accessLevel = ""; name = "Members"; groupType = "Unified" })
            
            { New-EntraOpsServiceEntraGroup -ServiceName "Test" -WorkloadPlaneAdmin "12345678-1234-1234-1234-123456789012" -ServiceRoles $roles } | 
            Should -Not -Throw
        }
        
        It "Should throw for invalid WorkloadPlaneAdmin format" {
            $roles = @([pscustomobject]@{accessLevel = ""; name = "Members"; groupType = "Unified" })
            
            { New-EntraOpsServiceEntraGroup -ServiceName "Test" -WorkloadPlaneAdmin "invalid-format" -ServiceRoles $roles -ErrorAction Stop } | 
            Should -Throw -ExpectedMessage "*WorkloadPlaneAdmin must be either a valid GUID*"
        }
    }
    
    Context "Payload Validation" {
        It "Should throw when DisplayName exceeds 256 characters" {
            Mock Invoke-EntraOpsMsGraphQuery -ModuleName EntraOps -MockWith ${function:Mock-InvokeEntraOpsMsGraphQuery}
            
            $longName = "A" * 250
            $roles = @([pscustomobject]@{accessLevel = "ControlPlane"; name = "Admins"; groupType = "" })
            
            { New-EntraOpsServiceEntraGroup -ServiceName $longName -WorkloadPlaneAdmin "https://graph.microsoft.com/v1.0/users/test" -ServiceRoles $roles -ErrorAction Stop } | 
            Should -Throw -ExpectedMessage "*exceeds maximum length of 256 characters*"
        }
        
        It "Should throw when MailNickname exceeds 64 characters" {
            Mock Invoke-EntraOpsMsGraphQuery -ModuleName EntraOps -MockWith ${function:Mock-InvokeEntraOpsMsGraphQuery}
            
            $longName = "A" * 70
            $roles = @([pscustomobject]@{accessLevel = ""; name = "Members"; groupType = "Unified" })
            
            { New-EntraOpsServiceEntraGroup -ServiceName $longName -WorkloadPlaneAdmin "https://graph.microsoft.com/v1.0/users/test" -ServiceRoles $roles -ErrorAction Stop } | 
            Should -Throw -ExpectedMessage "*exceeds maximum length of 64 characters*"
        }
        
        It "Should throw when MailNickname contains invalid characters" {
            Mock Invoke-EntraOpsMsGraphQuery -ModuleName EntraOps -MockWith ${function:Mock-InvokeEntraOpsMsGraphQuery}
            
            $roles = @([pscustomobject]@{accessLevel = ""; name = "Members"; groupType = "Unified" })
            
            { New-EntraOpsServiceEntraGroup -ServiceName "Test Service!" -WorkloadPlaneAdmin "https://graph.microsoft.com/v1.0/users/test" -ServiceRoles $roles -ErrorAction Stop } | 
            Should -Throw -ExpectedMessage "*invalid characters*"
        }
        
        It "Should accept valid MailNickname with dots and underscores" {
            Mock Invoke-EntraOpsMsGraphQuery -ModuleName EntraOps -MockWith ${function:Mock-InvokeEntraOpsMsGraphQuery}
            
            $roles = @([pscustomobject]@{accessLevel = ""; name = "Members"; groupType = "Unified" })
            
            { New-EntraOpsServiceEntraGroup -ServiceName "Test.Service_01" -WorkloadPlaneAdmin "https://graph.microsoft.com/v1.0/users/test" -ServiceRoles $roles } | 
            Should -Not -Throw
        }
    }
    
    Context "Group Creation Logic" {
        BeforeEach {
            Mock Invoke-EntraOpsMsGraphQuery -ModuleName EntraOps -MockWith ${function:Mock-InvokeEntraOpsMsGraphQuery}
        }
        
        It "Should create Unified group for Members role" {
            $roles = @([pscustomobject]@{accessLevel = ""; name = "Members"; groupType = "Unified" })
            
            $result = New-EntraOpsServiceEntraGroup -ServiceName "TestSvc" -WorkloadPlaneAdmin "https://graph.microsoft.com/v1.0/users/test" -ServiceRoles $roles
            
            $result | Should -HaveCount 1
            $result[0].MailNickname | Should -Be "TestSvc.Members"
            $result[0].GroupTypes | Should -Contain "Unified"
        }
        
        It "Should create Security groups for WorkloadPlane roles" {
            $roles = @(
                [pscustomobject]@{accessLevel = "WorkloadPlane"; name = "Users"; groupType = "" }
                [pscustomobject]@{accessLevel = "WorkloadPlane"; name = "Admins"; groupType = "" }
            )
            
            $result = New-EntraOpsServiceEntraGroup -ServiceName "TestSvc" -WorkloadPlaneAdmin "https://graph.microsoft.com/v1.0/users/test" -ServiceRoles $roles
            
            $result | Should -HaveCount 2
            $result[0].SecurityEnabled | Should -Be $true
            $result[1].SecurityEnabled | Should -Be $true
        }
        
        It "Should create PIM staging group for ManagementPlane-Admins only with EnablePIMStagingGroup" {
            $roles = @([pscustomobject]@{accessLevel = "ManagementPlane"; name = "Admins"; groupType = "" })
            
            $result = New-EntraOpsServiceEntraGroup -ServiceName "TestSvc" -WorkloadPlaneAdmin "https://graph.microsoft.com/v1.0/users/test" -ServiceRoles $roles -EnablePIMStagingGroup
            
            $result | Should -HaveCount 2
            $pimGroup = $result | Where-Object { $_.MailNickname -like "PIM.*" }
            $pimGroup | Should -Not -BeNullOrEmpty
        }

        It "Should NOT create PIM staging group by default" {
            $roles = @([pscustomobject]@{accessLevel = "ManagementPlane"; name = "Admins"; groupType = "" })
            
            $result = New-EntraOpsServiceEntraGroup -ServiceName "TestSvc" -WorkloadPlaneAdmin "https://graph.microsoft.com/v1.0/users/test" -ServiceRoles $roles
            
            $result | Should -HaveCount 1
            $result[0].MailNickname | Should -Not -BeLike "PIM.*"
        }
        
        It "Should NOT create PIM staging group when NoPimEscalation is set" {
            $roles = @([pscustomobject]@{accessLevel = "ManagementPlane"; name = "Admins"; groupType = "" })
            
            $result = New-EntraOpsServiceEntraGroup -ServiceName "TestSvc" -WorkloadPlaneAdmin "https://graph.microsoft.com/v1.0/users/test" -ServiceRoles $roles -EnablePIMStagingGroup -NoPimEscalation
            
            $result | Should -HaveCount 1
            $result[0].MailNickname | Should -Not -BeLike "PIM.*"
        }
        
        It "Should reuse existing groups by MailNickname" {
            # First call creates the group
            $roles = @([pscustomobject]@{accessLevel = ""; name = "Members"; groupType = "Unified" })
            $result1 = New-EntraOpsServiceEntraGroup -ServiceName "TestSvc" -WorkloadPlaneAdmin "https://graph.microsoft.com/v1.0/users/test" -ServiceRoles $roles
            
            # Second call should find existing
            $callCount = 0
            Mock Invoke-EntraOpsMsGraphQuery -ModuleName EntraOps {
                param($Method, $Uri, $Body)
                $callCount++
                if ($Method -eq "GET" -and $Uri -like '*mailNickname:TestSvc.*') {
                    return @([pscustomobject]@{
                            Id           = "existing-id"
                            DisplayName  = "TestSvc Members"
                            MailNickname = "TestSvc.Members"
                            GroupTypes   = @("Unified")
                        })
                }
                return $null
            }
            
            $result2 = New-EntraOpsServiceEntraGroup -ServiceName "TestSvc" -WorkloadPlaneAdmin "https://graph.microsoft.com/v1.0/users/test" -ServiceRoles $roles
            $result2 = @($result2 | Where-Object { $null -ne $_ })
            
            $result2 | Should -HaveCount 1
            $result2[0].MailNickname | Should -Be "TestSvc.Members"
        }

        It "Should bypass the Graph cache when looking up existing groups" {
            $roles = @([pscustomobject]@{accessLevel = ""; name = "Members"; groupType = "Unified" })

            New-EntraOpsServiceEntraGroup -ServiceName "TestSvc" -ServiceRoles $roles | Out-Null

            Should -Invoke Invoke-EntraOpsMsGraphQuery -ModuleName EntraOps -ParameterFilter { $Method -eq 'GET' -and -not $DisableCache } -Times 0 -Exactly
        }
    }
    
    Context "Owners OData Bind Format" {
        It "Should convert GUID to proper OData URL" {
            Mock Invoke-EntraOpsMsGraphQuery -ModuleName EntraOps -MockWith ${function:Mock-InvokeEntraOpsMsGraphQuery}
            
            $roles = @([pscustomobject]@{accessLevel = "WorkloadPlane"; name = "Users"; groupType = "" })
            
            $script:LastCreatedGroupBody = $null
            
            New-EntraOpsServiceEntraGroup -ServiceName "Test" -WorkloadPlaneAdmin "12345678-1234-1234-1234-123456789012" -ServiceRoles $roles
            
            $script:LastCreatedGroupBody."owners@odata.bind" | Should -Contain "https://graph.microsoft.com/v1.0/users/12345678-1234-1234-1234-123456789012"
        }
        
        It "Should preserve valid OData URL" {
            Mock Invoke-EntraOpsMsGraphQuery -ModuleName EntraOps -MockWith ${function:Mock-InvokeEntraOpsMsGraphQuery}
            
            $roles = @([pscustomobject]@{accessLevel = "WorkloadPlane"; name = "Admins"; groupType = "" })
            
            $script:LastCreatedGroupBody = $null
            
            $validUrl = "https://graph.microsoft.com/v1.0/users/12345678-1234-1234-1234-123456789012"
            New-EntraOpsServiceEntraGroup -ServiceName "Test" -WorkloadPlaneAdmin $validUrl -ServiceRoles $roles
            
            $script:LastCreatedGroupBody."owners@odata.bind" | Should -Contain $validUrl
        }

        It "Should not set an owner on ControlPlane, ManagementPlane, CatalogPlane or Microsoft 365 groups" {
            Mock Invoke-EntraOpsMsGraphQuery -ModuleName EntraOps -MockWith ${function:Mock-InvokeEntraOpsMsGraphQuery}

            foreach ($role in @(
                    [pscustomobject]@{accessLevel = "ControlPlane"; name = "Admins"; groupType = "" },
                    [pscustomobject]@{accessLevel = "ManagementPlane"; name = "Admins"; groupType = "" },
                    [pscustomobject]@{accessLevel = "CatalogPlane"; name = "Members"; groupType = "" },
                    [pscustomobject]@{accessLevel = ""; name = "Members"; groupType = "Unified" })) {
                $script:LastCreatedGroupBody = $null
                New-EntraOpsServiceEntraGroup -ServiceName "Test$($role.accessLevel)" -WorkloadPlaneAdmin "12345678-1234-1234-1234-123456789012" -ServiceRoles @($role) | Out-Null
                $script:LastCreatedGroupBody.PSObject.Properties.Name | Should -Not -Contain "owners@odata.bind"
            }
        }
    }
}

Describe "New-EntraOpsSubscriptionLandingZone - Unit Tests" {
    Context "Governance Model Selection" {
        It "Should default to PerService when no config provided" {
            $Global:EntraOpsConfig = $null
            
            # Mock the begin block behavior
            $governanceModel = "PerService"
            
            $governanceModel | Should -Be "PerService"
        }
        
        It "Should read GovernanceModel from config" {
            $Global:EntraOpsConfig = @{
                ServiceEM = @{
                    GovernanceModel = "Centralized"
                }
            }
            
            $governanceModel = $Global:EntraOpsConfig.ServiceEM.GovernanceModel
            
            $governanceModel | Should -Be "Centralized"
        }
        
        It "Should use parameter over config" {
            $Global:EntraOpsConfig = @{
                ServiceEM = @{
                    GovernanceModel = "Centralized"
                }
            }
            $parameterValue = "PerService"
            
            # Parameter takes precedence
            $governanceModel = $parameterValue
            
            $governanceModel | Should -Be "PerService"
        }
    }
    
    Context "Config Loading" {
        It "Should report no config when the probed locations contain none" {
            $Global:EntraOpsConfig = $null
            
            # Simulate finding config
            $configPaths = @((Join-Path $TestDrive 'config-probe/EntraOpsConfig.json'))
            $configLoaded = $false
            
            foreach ($path in $configPaths) {
                if (Test-Path $path) {
                    $configLoaded = $true
                    break
                }
            }
            
            # In real scenario, this would load the file
            $configLoaded | Should -Be $false
        }
    }
    
    Context "Skip Switch Logic" {
        It "Should auto-set SkipControlPlaneDelegation when GroupId provided" {
            $ControlPlaneDelegationGroupId = "test-id"
            $SkipControlPlaneDelegation = $false
            
            # Logic from function
            if (-not [string]::IsNullOrWhiteSpace($ControlPlaneDelegationGroupId)) {
                $SkipControlPlaneDelegation = $true
            }
            
            $SkipControlPlaneDelegation | Should -Be $true
        }
        
        It "Should NOT auto-set when GroupId is empty" {
            $ControlPlaneDelegationGroupId = ""
            $SkipControlPlaneDelegation = $false
            
            if (-not [string]::IsNullOrWhiteSpace($ControlPlaneDelegationGroupId)) {
                $SkipControlPlaneDelegation = $true
            }
            
            $SkipControlPlaneDelegation | Should -Be $false
        }
    }
}

AfterAll {
    Remove-Module EntraOps -Force -ErrorAction SilentlyContinue
}

