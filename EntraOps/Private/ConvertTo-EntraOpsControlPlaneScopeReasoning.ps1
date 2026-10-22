function ConvertTo-EntraOpsControlPlaneScopeReasoning {
    <#
    .SYNOPSIS
        Builds the content of ScopeReasoning_ControlPlane.json.
    .DESCRIPTION
        Records why each privileged object was identified and whether it is protected. Carried forward Exposure
        Management classifications are marked with XspmLastSuccessfulQueryDate.
    .PARAMETER ExposureManagementResult
        Exposure Management outcome filled by Get-EntraOpsClassificationControlPlaneObjects. Empty when the source
        is not enabled.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [object[]]$PrivilegedObjects,
        [Parameter(Mandatory = $false)]
        [object]$PrivilegedObjectClassificationSource,
        [Parameter(Mandatory = $false)]
        [object]$ClassificationParameterScope,
        [Parameter(Mandatory = $false)]
        [object]$AzureHighPrivilegedRoles,
        [Parameter(Mandatory = $false)]
        [object]$AzureHighPrivilegedScopes,
        [Parameter(Mandatory = $false)]
        [hashtable]$ExposureManagementResult = @{}
    )

    $XspmCarriedForwardDate = if ($ExposureManagementResult['Status'] -eq 'CarriedForward') { $ExposureManagementResult['Metadata'].LastSuccessfulQueryDate }
    $Payload = [PSCustomObject]@{
        PrivilegedObjectClassificationSource = $PrivilegedObjectClassificationSource
        ClassificationParameterScope         = $ClassificationParameterScope
        AzureResourceGraphCriteria           = [PSCustomObject]@{
            SourceEnabled        = [bool]($PrivilegedObjectClassificationSource -eq "All" -or $PrivilegedObjectClassificationSource -contains "PrivilegedRolesFromAzGraph")
            HighPrivilegedRoles  = @($AzureHighPrivilegedRoles)
            HighPrivilegedScopes = @($AzureHighPrivilegedScopes)
            ScopeMatch           = "Exact assignment scope; child scopes are not included unless listed explicitly."
            WildcardScopeMatch   = "All assignment scopes"
        }
        # ObjectId breaks ties for objects sharing the same ObjectType/ObjectDisplayName (duplicate display names are allowed in Entra ID).
        PrivilegedObjects                    = @($PrivilegedObjects | Where-Object { $null -ne $_ } | Sort-Object ObjectType, ObjectDisplayName, ObjectId | ForEach-Object {
                $ScopeReasoningObject = [ordered]@{
                    ObjectId                      = $_.ObjectId
                    ObjectDisplayName             = $_.ObjectDisplayName
                    ObjectType                    = $_.ObjectType
                    ObjectSubType                 = $_.ObjectSubType
                    ClassificationSource          = @($_.Classification.ClassificationSource | Select-Object -Unique | Sort-Object)
                    ClassificationReason          = $_.Classification.ClassificationReason
                    RestrictedManagementByRAG     = [bool]$_.RestrictedManagementByRAG
                    RestrictedManagementByAadRole = [bool]$_.RestrictedManagementByAadRole
                    RestrictedManagementByRMAU    = [bool]$_.RestrictedManagementByRMAU
                }
                # Marks an Exposure Management classification taken from the last successful query
                if ($null -ne $XspmCarriedForwardDate -and @($_.Classification.ClassificationSource) -contains 'XSPM') {
                    $ScopeReasoningObject['XspmLastSuccessfulQueryDate'] = $XspmCarriedForwardDate
                }
                [PSCustomObject]$ScopeReasoningObject
            })
    }
    if ($ExposureManagementResult.ContainsKey('Status')) {
        Add-EntraOpsExposureManagementBlock -Payload $Payload -Metadata $ExposureManagementResult['Metadata'] -Results $ExposureManagementResult['Results']
    }
    $Payload
}
