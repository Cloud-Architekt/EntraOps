function Get-EntraOpsReusableControlPlaneScope {
    <#
    .SYNOPSIS
        Describes the Control Plane scope of an earlier run in the tenant classification folder.

    .DESCRIPTION
        The Control Plane scope update (Update-EntraOpsClassificationControlPlaneScope) writes the tenant
        classification file of each system of the classification parameter scope and ScopeReasoning_ControlPlane.json.
        The scope can be reused when all of them exist. Returns Reusable, the time of the scope update (LastWriteTime
        of ScopeReasoning_ControlPlane.json, UTC), its age in hours and the missing files.

    .PARAMETER ClassificationTenantFolder
        Classification/<TenantName> of the EntraOps working folder.

    .PARAMETER ClassificationParameterScope
        RBAC systems whose tenant classification files the scope update generates.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param (
        [Parameter(Mandatory = $true)]
        [string]$ClassificationTenantFolder,

        [Parameter(Mandatory = $false)]
        [string[]]$ClassificationParameterScope = @('EntraID', 'DeviceManagement', 'Azure')
    )

    # ResourceApps has no tenant-scoped placeholders: its tenant file only exists with overwrites.
    $FileNames = @{
        EntraID            = 'Classification_AadResources.json'
        DeviceManagement   = 'Classification_DeviceManagement.json'
        Azure              = 'Classification_Azure.json'
        Defender           = 'Classification_Defender.json'
        IdentityGovernance = 'Classification_IdentityGovernance.json'
    }
    $ReasoningFile = Join-Path $ClassificationTenantFolder 'ScopeReasoning_ControlPlane.json'
    $RequiredFiles = @($ReasoningFile) + @($ClassificationParameterScope | Where-Object { $FileNames.ContainsKey($_) } | ForEach-Object { Join-Path $ClassificationTenantFolder $FileNames[$_] })
    $MissingFiles = @($RequiredFiles | Where-Object { -not (Test-Path -LiteralPath $_ -PathType Leaf) })
    $UpdatedAt = if (Test-Path -LiteralPath $ReasoningFile -PathType Leaf) { (Get-Item -LiteralPath $ReasoningFile).LastWriteTimeUtc } else { $null }

    [pscustomobject]@{
        Reusable      = $MissingFiles.Count -eq 0
        ReasoningFile = $ReasoningFile
        UpdatedAt     = $UpdatedAt
        AgeInHours    = if ($UpdatedAt) { [math]::Round(((Get-Date).ToUniversalTime() - $UpdatedAt).TotalHours, 1) } else { $null }
        MissingFiles  = $MissingFiles
    }
}
