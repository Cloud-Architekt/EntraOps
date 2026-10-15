#Requires -Modules Pester

BeforeAll {
    $script:TestRepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
    Import-Module (Join-Path $script:TestRepositoryRoot 'EntraOps') -Force
    $script:PreviousBaseFolder = $Global:EntraOpsBaseFolder

    function Invoke-TestConnect {
        param([hashtable]$Parameters = @{})
        $Output = Connect-EntraOps -AuthenticationType AlreadyAuthenticated -TenantName 'contoso.onmicrosoft.com' -UseInvokeRestMethodOnly @Parameters 6>&1 3>&1
        ($Output | ForEach-Object { "$_" }) -join "`n"
    }
}

AfterAll {
    $Global:EntraOpsBaseFolder = $script:PreviousBaseFolder
    Remove-Variable -Name EntraOpsConfig, TenantIdContext, TenantNameContext, ManagingTenantIdContext, ManagingTenantNameContext, EntraOpsIncludeObjectDetails, XdrAvdHuntingAccess, DefaultFolderClassification, DefaultFolderClassifiedEam -Scope Global -ErrorAction SilentlyContinue
}

Describe 'Connect-EntraOps delegated Microsoft Graph scopes' {
    BeforeAll {
        $script:GetScopes = {
            param($Scope, $ConfigJson)
            $config = if ($ConfigJson) { $ConfigJson | ConvertFrom-Json } else { $null }
            & (Get-Module EntraOps) { param($s, $c) Get-EntraOpsMsGraphDelegatedScope -Scope $s -Config $c 3>$null } $Scope $config
        }
        $script:WriteScopes = 'AdministrativeUnit.ReadWrite.All', 'Group.ReadWrite.All', 'EntitlementManagement.ReadWrite.All'
    }

    It 'requests only read scopes for Report' {
        $scopes = & $script:GetScopes 'Report' '{ "AutomatedElmCatalogProtection": { "ApplyPrivilegedElmCatalogProtection": true } }'

        $scopes | Should -Contain 'Directory.Read.All'
        @($scopes | Where-Object { $_ -like '*ReadWrite*' -or $_ -eq 'Directory.AccessAsUser.All' }) | Should -BeNullOrEmpty
    }

    It 'requests the catalog write scope of ApplyProtection only with catalog protection' {
        @(& $script:GetScopes 'ApplyProtection' $null | Where-Object { $_ -in $script:WriteScopes } | Sort-Object) | Should -Be @('AdministrativeUnit.ReadWrite.All', 'Group.ReadWrite.All')

        $catalog = & $script:GetScopes 'ApplyProtection' '{ "AutomatedElmCatalogProtection": { "ApplyPrivilegedElmCatalogProtection": true } }'
        @($catalog | Where-Object { $_ -in $script:WriteScopes } | Sort-Object) | Should -Be @('AdministrativeUnit.ReadWrite.All', 'EntitlementManagement.ReadWrite.All', 'Group.ReadWrite.All')
    }

    It 'adds AdministrativeUnit.ReadWrite.All to ServiceEM only with configured administrative units' {
        & $script:GetScopes 'ServiceEM' '{ "ServiceEM": { "AdministrativeUnits": { "WorkloadPlane": "", "UserAccess": "" } } }' | Should -Not -Contain 'AdministrativeUnit.ReadWrite.All'
        & $script:GetScopes 'ServiceEM' '{ "ServiceEM": { "AdministrativeUnits": { "UserAccess": "22222222-2222-2222-2222-222222222222" } } }' | Should -Contain 'AdministrativeUnit.ReadWrite.All'
    }
}

Describe 'Connect-EntraOps configuration file detection' {
    BeforeEach {
        $script:WorkFolder = Join-Path $TestDrive ([guid]::NewGuid())
        $script:BaseFolder = Join-Path $TestDrive ([guid]::NewGuid())
        New-Item -ItemType Directory -Path $script:WorkFolder, $script:BaseFolder | Out-Null
        $Global:EntraOpsBaseFolder = $script:BaseFolder
        Push-Location $script:WorkFolder

        Mock Install-EntraOpsRequiredModule -ModuleName EntraOps {}
        Mock Set-AzContext -ModuleName EntraOps {}
        Mock Get-AzContext -ModuleName EntraOps {
            [pscustomobject]@{
                Account      = [pscustomobject]@{ Id = 'sp'; Type = 'ServicePrincipal' }
                Tenant       = [pscustomobject]@{ Id = '00000000-0000-0000-0000-000000000001' }
                Subscription = [pscustomobject]@{ Name = 'sub' }
            }
        }
        Remove-Variable -Name EntraOpsConfig -Scope Global -ErrorAction SilentlyContinue
    }

    AfterEach {
        Pop-Location
    }

    It 'loads EntraOpsConfig.json from the current folder and reports it' {
        '{ "TenantName": "contoso.onmicrosoft.com", "ServiceEM": { "GroupPrefix": "GRP" } }' | Set-Content (Join-Path $script:WorkFolder 'EntraOpsConfig.json')

        $Output = Invoke-TestConnect

        $Global:EntraOpsConfig.ServiceEM.GroupPrefix | Should -Be 'GRP'
        $Output | Should -Match 'Config File\s+: .*EntraOpsConfig\.json \(found automatically\)'
        $Output | Should -Match 'EntraOps Scope\s+: Report'
    }

    It 'falls back to EntraOpsConfig.json in the EntraOps working folder' {
        '{ "TenantName": "contoso.onmicrosoft.com", "ServiceEM": { "GroupPrefix": "BASE" } }' | Set-Content (Join-Path $script:BaseFolder 'EntraOpsConfig.json')

        Invoke-TestConnect | Out-Null

        $Global:EntraOpsConfig.ServiceEM.GroupPrefix | Should -Be 'BASE'
    }

    It 'uses the session working folder for the connection summary and default paths' {
        $Output = Invoke-TestConnect

        $Output | Should -Match "Working Folder\s+: $([regex]::Escape($script:BaseFolder)) \(set in this session\)"
        $Global:DefaultFolderClassification | Should -Be "$script:BaseFolder/Classification/"
        $Global:DefaultFolderClassifiedEam | Should -Be "$script:BaseFolder/PrivilegedEAM/"
    }

    It 'does not use a configuration of another tenant' {
        '{ "TenantName": "fabrikam.onmicrosoft.com", "TenantId": "00000000-0000-0000-0000-000000000002" }' | Set-Content (Join-Path $script:WorkFolder 'EntraOpsConfig.json')

        $Output = Invoke-TestConnect

        Get-Variable -Name EntraOpsConfig -Scope Global -ErrorAction SilentlyContinue | Should -BeNullOrEmpty
        $Output | Should -Match "Config File\s+: Not used - TenantName 'fabrikam.onmicrosoft.com'"
        Should -Invoke Set-AzContext -ModuleName EntraOps -Times 0 -Exactly
    }

    It 'reports when no configuration file exists and drops a configuration of a previous connection' {
        $Global:EntraOpsConfig = @{ TenantName = 'contoso.onmicrosoft.com' }

        $Output = Invoke-TestConnect

        Get-Variable -Name EntraOpsConfig -Scope Global -ErrorAction SilentlyContinue | Should -BeNullOrEmpty
        $Output | Should -Match 'Config File\s+: Not used - no EntraOpsConfig\.json found'
    }

    It 'uses an explicit -ConfigFilePath instead of the detected file' {
        '{ "TenantName": "contoso.onmicrosoft.com", "ServiceEM": { "GroupPrefix": "AUTO" } }' | Set-Content (Join-Path $script:WorkFolder 'EntraOpsConfig.json')
        $ExplicitPath = Join-Path $script:BaseFolder 'Custom.json'
        '{ "ServiceEM": { "GroupPrefix": "EXPLICIT" } }' | Set-Content $ExplicitPath

        $Output = Invoke-TestConnect -Parameters @{ ConfigFilePath = $ExplicitPath }

        $Global:EntraOpsConfig.ServiceEM.GroupPrefix | Should -Be 'EXPLICIT'
        $Output | Should -Match "Config File\s+: $([regex]::Escape($ExplicitPath))"
    }
}
