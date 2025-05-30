<#
.SYNOPSIS
    Creates catalog resource roles

.DESCRIPTION
    Creates the roles available for the catalog resources

.PARAMETER ServiceCatalogId
    The Service Catalog GUID

.PARAMETER ServiceGroups
    The Graph Group objects

.PARAMETER logPrefix
    Defines the text to prepend for any verbose messages

.EXAMPLE
    New-EntraOpsServiceEMCatalogResourceRole -ServiceGroups $groups -ServiceCatalogId "<GUID>"

#>
function New-EntraOpsServiceEMCatalogResourceRole {
    [OutputType([psobject[]])]
    [cmdletbinding()]
    param(
        [Parameter(Mandatory)]
        [psobject[]]$ServiceGroups,

        [Parameter(Mandatory)]
        [string]$ServiceCatalogId,

        [string]$logPrefix = "[$($MyInvocation.MyCommand)]"
    )

    begin {
        $catalogAssignments = @()
        $catalogRolesSplat = @{
            Filter = "AppScopeId eq '/AccessPackageCatalog/$($ServiceCatalogId)'"
        }

        try{
            Write-Verbose "$logPrefix Looking up catalog role assignments"
            $catalogAssignments += Get-MgRoleManagementEntitlementManagementRoleAssignment @catalogRolesSplat
        }catch{
            Write-Verbose "$logPrefix Failed to find catalog role assignments"
            Write-Error $_
        }

        $catalogRoles = @"
displayName,id,filter
Owner,ae79f266-94d4-4dab-b730-feca7e132178,*Entitlement
Reader,44272f93-9762-48e8-af59-1b5351b1d6b3,* Members
"@|ConvertFrom-Csv
    }

    process {
        Write-Verbose "$logPrefix Processing $(($catalogRoles|Measure-Object).Count) catalog resource role assignments"
        foreach($catalogRole in $catalogRoles){
            $catalogRoleParams = @{
                PrincipalId = ($ServiceGroups|Where-Object{$_.DisplayName -like "$($catalogRole.filter)"}).Id
                RoleDefinitionId = $catalogRole.id
                AppScopeId = "/AccessPackageCatalog/$($ServiceCatalogId)"
            }

            try{
                if(($ServiceGroups|Where-Object{$_.id -eq $catalogRoleParams.PrincipalId}).DisplayName -like $catalogRole.filter){
                    $nr = $catalogRoleParams.PrincipalId+"_"+$catalogRoleParams.RoleDefinitionId
                    $er = $catalogAssignments|ForEach-Object{$_.PrincipalId+"_"+$_.RoleDefinitionId}
                    if($nr -notin $er){
                        $catalogAssignments += New-MgRoleManagementEntitlementManagementRoleAssignment -BodyParameter $catalogRoleParams
                    }
                }
            }catch{
                Write-Verbose "$logPrefix Failed to assign catalog roles"
                Write-Error $_
            }
        }
    }

    end {
        $confirmed = $false
        $i = 0
        while(-not $confirmed){
            Start-Sleep -Seconds ([Math]::Pow(2,$i)-1)
            $checkCatalogAssignments = @()
            $checkCatalogAssignments = Get-MgRoleManagementEntitlementManagementRoleAssignment @catalogRolesSplat
            if((Compare-Object $catalogAssignments $checkCatalogAssignments|Measure-Object).Count -eq 0){
                Write-Verbose "$logPrefix Graph consistency found confirming"
                $confirmed = $true
                continue
            }
            $i++
            if($i -gt 5){
                throw "Catalog Resource Role Assignment consistency with Entra not achieved"
            }
            Write-Verbose "$logPrefix Graph objects are not available, sleeping $([Math]::Pow(2,$i)-1) seconds"
        }
        return [psobject[]]$checkCatalogAssignments
    }
}