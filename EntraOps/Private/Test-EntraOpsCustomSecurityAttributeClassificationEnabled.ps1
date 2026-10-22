function Test-EntraOpsCustomSecurityAttributeClassificationEnabled {
    <#
    .SYNOPSIS
        Returns $true when the tier of the given object type is read from Custom Security Attributes.
    .DESCRIPTION
        CustomSecurityAttributes.Enabled decides. Without it, older config files keep their behavior: Custom
        Security Attributes are used unless the Object Classification File is enabled or, for users and service
        principals, the Alternate Tier Level Attributes of the object type are enabled (both replaced them).
        Only the tier is affected; the PAW device and work account attributes are always read.
    .PARAMETER ObjectType
        The EntraOps object type. One of 'User', 'ServicePrincipal' or 'Application'.
    .PARAMETER Enabled
        The value of CustomSecurityAttributes.Enabled in EntraOpsConfig.json (or $null when absent).
    .PARAMETER ObjectClassificationFile
        The "ObjectClassificationFile" section of EntraOpsConfig.json (or $null when absent).
    .PARAMETER AlternateObjectTierLevelAttributes
        The "AlternateObjectTierLevelAttributes" section of EntraOpsConfig.json (or $null when absent).
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateSet('User', 'ServicePrincipal', 'Application')]
        [string]$ObjectType,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]$Enabled,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [PSObject]$ObjectClassificationFile,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [PSObject]$AlternateObjectTierLevelAttributes
    )

    if ($null -ne $Enabled) {
        return $Enabled -eq $true
    }
    if ($null -ne $ObjectClassificationFile -and $ObjectClassificationFile.Enabled -eq $true -and -not [string]::IsNullOrWhiteSpace($ObjectClassificationFile.FilePath)) {
        return $false
    }
    if ($ObjectType -ne 'Application' -and (Test-EntraOpsAlternateObjectTierLevelEnabled -ObjectType $ObjectType -AlternateObjectTierLevelAttributes $AlternateObjectTierLevelAttributes)) {
        return $false
    }
    return $true
}
