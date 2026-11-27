#Requires -Modules Pester

Describe 'Test-EntraOpsMicrosoftFirstParty' {
    BeforeAll {
        $script:TestRepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
        Import-Module (Join-Path $script:TestRepositoryRoot 'EntraOps/EntraOps.psd1') -Force -WarningAction SilentlyContinue
    }

    It '<Case>' -ForEach @(
        @{ Case = 'application of the Microsoft Services tenant'; Owner = 'F8CDEF31-A31E-4B4A-93E4-5F571E91255A'; AppId = ''; Expected = $true }
        @{ Case = 'application of the Microsoft corporate tenant'; Owner = '72f988bf-86f1-41af-91ab-2d7cd011db47'; AppId = ''; Expected = $true }
        @{ Case = 'application of the Microsoft AME tenant (Windows Virtual Desktop)'; Owner = '33e01921-4d64-4f8c-a055-5bdaffd5e33d'; AppId = ''; Expected = $true }
        @{ Case = 'application of the own tenant'; Owner = '11111111-1111-1111-1111-111111111111'; AppId = '01fc33a7-78ba-4d2f-a4b7-768e336e890e'; Expected = $false }
        @{ Case = 'MS-PIM in an export without the application tenant'; Owner = ''; AppId = '01FC33A7-78BA-4D2F-A4B7-768E336E890E'; Expected = $true }
        @{ Case = 'other application in an export without the application tenant'; Owner = $null; AppId = '22222222-2222-2222-2222-222222222222'; Expected = $false }
        @{ Case = 'no data'; Owner = $null; AppId = $null; Expected = $false }
        @{ Case = 'Microsoft Graph Command Line Tools of its Microsoft tenant'; Owner = 'cdc5aeea-15c5-4db6-b079-fcadd2505dc2'; AppId = '14D82EEC-204B-4C2F-B7E8-296A70DAB67E'; Expected = $true }
        @{ Case = 'Graph Explorer in an export without the application tenant'; Owner = ''; AppId = 'de8bc8b5-d9f9-48b1-a8ad-b748da725064'; Expected = $true }
        @{ Case = 'Graph Explorer application ID with another tenant'; Owner = '11111111-1111-1111-1111-111111111111'; AppId = 'de8bc8b5-d9f9-48b1-a8ad-b748da725064'; Expected = $false }
        @{ Case = 'other application of the Graph tools tenant'; Owner = 'cdc5aeea-15c5-4db6-b079-fcadd2505dc2'; AppId = '22222222-2222-2222-2222-222222222222'; Expected = $false }
    ) {
        & (Get-Module EntraOps) { param($Owner, $AppId) Test-EntraOpsMicrosoftFirstParty -AppOwnerOrganizationId $Owner -AppId $AppId } $Owner $AppId | Should -Be $Expected
    }
}

Describe 'Test-EntraOpsMicrosoftConsentClient' {
    BeforeAll {
        $script:TestRepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
        Import-Module (Join-Path $script:TestRepositoryRoot 'EntraOps/EntraOps.psd1') -Force -WarningAction SilentlyContinue
    }

    It '<Case>' -ForEach @(
        @{ Case = 'Microsoft Graph Command Line Tools'; AppId = '14d82eec-204b-4c2f-b7e8-296a70dab67e'; Expected = $true }
        @{ Case = 'Graph Explorer'; AppId = 'DE8BC8B5-D9F9-48B1-A8AD-B748DA725064'; Expected = $true }
        @{ Case = 'Microsoft Intune PowerShell'; AppId = 'd1ddf0e4-d672-4dae-b554-9d5bdfd93547'; Expected = $true }
        @{ Case = 'SharePoint Online Web Client Extensibility'; AppId = '08e18876-6177-487e-b8b5-cf950c1e598c'; Expected = $true }
        @{ Case = 'Microsoft Developer Sample Data Packs'; AppId = 'a1cffbc6-1cb3-44e4-a1d2-cee9cce700f1'; Expected = $true }
        @{ Case = 'Azure AD Assessment'; AppId = '68bc31c0-f891-4f4c-9309-c6104f7be41b'; Expected = $true }
        @{ Case = 'M365 Lighthouse API'; AppId = '4eaa7769-3cf1-458c-a693-e9827e39cc95'; Expected = $true }
        @{ Case = 'MS-PIM (pre-authorized first-party)'; AppId = '01fc33a7-78ba-4d2f-a4b7-768e336e890e'; Expected = $false }
        @{ Case = 'no data'; AppId = $null; Expected = $false }
    ) {
        & (Get-Module EntraOps) { param($AppId) Test-EntraOpsMicrosoftConsentClient -AppId $AppId } $AppId | Should -Be $Expected
    }
}
