#!/usr/bin/env pwsh
#Requires -Version 7.0
#Requires -Modules Microsoft.Graph.Authentication

<#
.SYNOPSIS
    Automated ServiceEM test using Service Principal authentication.

.DESCRIPTION
    Runs ServiceEM tests without interactive login using certificate-based
    service principal authentication. Designed for CI/CD pipelines.

.PARAMETER TenantId
    Azure AD tenant ID (e.g., contoso.onmicrosoft.com)

.PARAMETER ClientId
    Application (client) ID from app registration

.PARAMETER CertificateThumbprint
    Thumbprint of the certificate installed in CurrentUser\My store

.PARAMETER CertificatePath
    Path to .pfx file (alternative to thumbprint)

.PARAMETER CertificatePassword
    Password for .pfx file (if using CertificatePath)

.PARAMETER TestPrefix
    Prefix for test resources (default: AutoTest)

.PARAMETER Cleanup
    Remove test resources after testing

.EXAMPLE
    .\Test-WithServicePrincipal.ps1 `
        -TenantId "contoso.onmicrosoft.com" `
        -ClientId "12345678-1234-1234-1234-123456789012" `
        -CertificateThumbprint "A1B2C3D4E5F6..."

.EXAMPLE
    .\Test-WithServicePrincipal.ps1 `
        -TenantId "contoso.onmicrosoft.com" `
        -ClientId "app-id-here" `
        -CertificatePath "./TestCertificates/EntraOpsTest.pfx" `
        -CertificatePassword (ConvertTo-SecureString "TestCert123!" -AsPlainText)
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$TenantId,

    [Parameter(Mandatory = $true)]
    [string]$ClientId,

    [string]$CertificateThumbprint,

    [string]$CertificatePath,

    [SecureString]$CertificatePassword,

    [string]$TestPrefix = "AutoTest",

    [switch]$Cleanup
)

$ErrorActionPreference = "Stop"
$TestResults = @{
    StartTime = Get-Date
    Tests = @()
    Passed = 0
    Failed = 0
}

function Write-TestResult($Name, $Result, $Duration, $ErrorMessage = $null) {
    $status = if ($Result -eq "PASS") { "✅" } else { "❌" }
    $color = if ($Result -eq "PASS") { "Green" } else { "Red" }
    Write-Host "$status $Name ($($Duration.TotalSeconds.ToString('F2'))s)" -ForegroundColor $color
    if ($ErrorMessage) {
        Write-Host "   Error: $ErrorMessage" -ForegroundColor Red
    }

    $TestResults.Tests += [PSCustomObject]@{
        Name = $Name
        Result = $Result
        Duration = $Duration
        Error = $ErrorMessage
        Timestamp = Get-Date
    }

    if ($Result -eq "PASS") { $TestResults.Passed++ } else { $TestResults.Failed++ }
}

function Write-Section($Title) {
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host $Title -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
}

# ==================== MAIN ====================
Write-Section "ServiceEM Automated Test - Service Principal Auth"

# Authenticate
Write-Section "Authentication"
$authStart = Get-Date

try {
    if ($CertificateThumbprint) {
        Write-Host "Connecting with certificate thumbprint..."
        $cert = Get-ChildItem -Path "Cert:\\CurrentUser\\My\\$CertificateThumbprint" -ErrorAction Stop
        Connect-MgGraph -ClientId $ClientId -TenantId $TenantId -Certificate $cert -ErrorAction Stop
    } elseif ($CertificatePath) {
        Write-Host "Connecting with certificate file..."
        if (-not $CertificatePassword) {
            $CertificatePassword = Read-Host -AsSecureString "Enter certificate password"
        }
        Connect-MgGraph -ClientId $ClientId -TenantId $TenantId -CertificatePath $CertificatePath -CertificatePassword $CertificatePassword -ErrorAction Stop
    } else {
        throw "Either CertificateThumbprint or CertificatePath must be provided"
    }

    $context = Get-MgContext
    Write-Host "✓ Connected successfully as: $($context.AppName)" -ForegroundColor Green
    Write-Host "  Account: $($context.Account)" -ForegroundColor Gray
    Write-Host "  Tenant: $($context.TenantId)" -ForegroundColor Gray
    Write-Host "  AuthType: $($context.AuthType)" -ForegroundColor Gray

    Write-TestResult "Service Principal Authentication" "PASS" ((Get-Date) - $authStart)
} catch {
    Write-TestResult "Service Principal Authentication" "FAIL" ((Get-Date) - $authStart) $_.Exception.Message
    exit 1
}

# Import EntraOps
Write-Section "Module Import"
$importStart = Get-Date
try {
    $modulePath = Join-Path $PSScriptRoot ".." ".." "EntraOps" "EntraOps.psd1"
    Import-Module $modulePath -Force -ErrorAction Stop
    Write-Host "✓ EntraOps module imported" -ForegroundColor Green
    Write-TestResult "Module Import" "PASS" ((Get-Date) - $importStart)
} catch {
    Write-TestResult "Module Import" "FAIL" ((Get-Date) - $importStart) $_.Exception.Message
    exit 1
}

# Generate unique test ID
$TestId = "$TestPrefix$(Get-Random -Minimum 1000 -Maximum 9999)"
Write-Host "`nTest ID: $TestId" -ForegroundColor Yellow

# Track created resources for cleanup
$CreatedGroups = @()
$CreatedCatalogs = @()

# ==================== TEST 1: Group Creation ====================
Write-Section "Test 1: Group Creation"
$testStart = Get-Date

try {
    $ServiceRoles = @(
        [pscustomobject]@{accessLevel = ""; name = "Members"; groupType = "Unified"}
        [pscustomobject]@{accessLevel = "WorkloadPlane"; name = "Users"; groupType = ""}
        [pscustomobject]@{accessLevel = "WorkloadPlane"; name = "Admins"; groupType = ""}
    )

    Write-Host "Creating groups for service: $TestId..."
    $groups = New-EntraOpsServiceEntraGroup `
        -ServiceName $TestId `
        -WorkloadPlaneAdmin "https://graph.microsoft.com/v1.0/users/$ClientId" `
        -ServiceRoles $ServiceRoles `
        -Verbose

    $CreatedGroups = $groups
    Write-Host "✓ Created $($groups.Count) groups" -ForegroundColor Green
    $groups | Select-Object DisplayName, MailNickname, GroupTypes | Format-Table

    # Verify group types
    $membersGroup = $groups | Where-Object { $_.MailNickname -eq "$TestId.Members" }
    if ($membersGroup -and $membersGroup.GroupTypes -contains "Unified") {
        Write-Host "✓ Unified group verified" -ForegroundColor Green
    }

    Write-TestResult "Group Creation" "PASS" ((Get-Date) - $testStart)
} catch {
    Write-TestResult "Group Creation" "FAIL" ((Get-Date) - $testStart) $_.Exception.Message
}

# ==================== TEST 2: Service Bootstrap ====================
Write-Section "Test 2: Service Bootstrap"
$testStart = Get-Date

try {
    $bootstrapRoles = @(
        [pscustomobject]@{accessLevel = ""; name = "Members"; groupType = "Unified"}
        [pscustomobject]@{accessLevel = "WorkloadPlane"; name = "Users"; groupType = ""}
    )

    Write-Host "Running service bootstrap..."
    $result = New-EntraOpsServiceBootstrap `
        -ServiceName "Bootstrap$TestId" `
        -WorkloadPlaneAdmin "https://graph.microsoft.com/v1.0/users/$ClientId" `
        -ServiceRoles $bootstrapRoles `
        -SkipAzureResourceGroup `
        -Verbose

    if ($result.CatalogId) {
        $CreatedCatalogs += $result.CatalogId
        Write-Host "✓ Catalog created: $($result.CatalogId)" -ForegroundColor Green
    }

    Write-TestResult "Service Bootstrap" "PASS" ((Get-Date) - $testStart)
} catch {
    Write-TestResult "Service Bootstrap" "FAIL" ((Get-Date) - $testStart) $_.Exception.Message
}

# ==================== TEST 3: Landing Zone ====================
Write-Section "Test 3: Landing Zone (PerService)"
$testStart = Get-Date

try {
    Write-Host "Creating landing zone..."
    $lzResult = New-EntraOpsSubscriptionLandingZone `
        -DeploymentPrefix "LZ$TestId" `
        -AzureRegion "westus2" `
        -SkipAzureResourceGroup `
        -GovernanceModel "PerService" `
        -Verbose

    Write-Host "✓ Landing zone created" -ForegroundColor Green
    Write-TestResult "Landing Zone Creation" "PASS" ((Get-Date) - $testStart)
} catch {
    Write-TestResult "Landing Zone Creation" "FAIL" ((Get-Date) - $testStart) $_.Exception.Message
}

# ==================== CLEANUP ====================
if ($Cleanup) {
    Write-Section "Cleanup"

    # Remove groups
    foreach ($group in $CreatedGroups) {
        try {
            Write-Host "Removing group: $($group.DisplayName)..."
            Remove-MgGroup -GroupId $group.Id -ErrorAction SilentlyContinue
            Write-Host "  ✓ Removed" -ForegroundColor Gray
        } catch {
            Write-Host "  ⚠️ Failed to remove: $_" -ForegroundColor Yellow
        }
    }

    # Remove catalogs
    foreach ($catalogId in $CreatedCatalogs) {
        try {
            Write-Host "Removing catalog: $catalogId..."
            Remove-MgEntitlementManagementCatalog -AccessPackageCatalogId $catalogId -ErrorAction SilentlyContinue
            Write-Host "  ✓ Removed" -ForegroundColor Gray
        } catch {
            Write-Host "  ⚠️ Failed to remove: $_" -ForegroundColor Yellow
        }
    }
}

# ==================== SUMMARY ====================
Write-Section "Test Summary"
$TestResults.EndTime = Get-Date
$duration = $TestResults.EndTime - $TestResults.StartTime

Write-Host "Total Duration: $($duration.TotalSeconds.ToString('F2')) seconds" -ForegroundColor White
Write-Host "Total Tests: $($TestResults.Tests.Count)" -ForegroundColor White
Write-Host "✅ Passed: $($TestResults.Passed)" -ForegroundColor Green
Write-Host "❌ Failed: $($TestResults.Failed)" -ForegroundColor Red

if ($TestResults.Failed -eq 0) {
    Write-Host "`n🎉 All tests passed!" -ForegroundColor Green
    exit 0
} else {
    Write-Host "`n⚠️ Some tests failed" -ForegroundColor Yellow
    exit 1
}
