function Get-EntraOpsPropertyValue {
    <#
    .SYNOPSIS
        Safe property access for objects from ConvertFrom-Json whose schema can vary between RBAC systems.
    .DESCRIPTION
        Returns the value of the property, or $null when the object or the property is missing (also
        strict-mode proof). A simple function without CmdletBinding: the Findings context builders call it
        for every property of every exported object.
    #>
    param($Object, [string]$Name)

    if ($null -eq $Object) { return $null }
    $Property = $Object.PSObject.Properties[$Name]
    if ($null -ne $Property) { return $Property.Value }
    return $null
}
