<#
.SYNOPSIS
    Creates the necessary authorization structure for a new service

.DESCRIPTION
    Creates the foundation for handling authorization of a new service
    in alignment with the Microsoft Enterprise Access Model.

.PARAMETER ServiceName
    The Name of the Service

.PARAMETER ServiceMembers
    The UserId (i.e., UPN) of the Service members
    Will default to the identity logged on to Graph

.PARAMETER ServiceOwner
    The UserId (i.e., UPN) of the Service owner
    Will default to the identity logged on to Graph

.PARAMETER OwnerIsNotMember
    Set this flag to not include the Service owner as a member of the service

.PARAMETER ProhibitDirectElevation
    Set this flag to skip configuration of Entra Priviliged Identity Management

.PARAMETER SkipAzureResourceGroup
    Set this flag to skip configuration of Azure Resource Group

.PARAMETER AzureRegion
    Set this to the preferred Azure Region for the Resource Group

.PARAMETER ServiceRoles
    Define the functional roles of the Service as an object with the columns
    name,type,groupType. Where name is the functional purpose (e.g., Admins), 
    type is the EAM classification (e.g., Workload) (an unset value is the 
    default group), and groupType is the Entra group type (e.g., Unified) (an 
    unset value will default to a security group). The default value will 
    create one unified members group, one security management group, one security
    user workload group, three security admin groups for workload, entitlement,
    and management.

.PARAMETER logPrefix
    Defines the text to prepend for any verbose messages

.EXAMPLE
    New-EntraOpsServiceBootstrap

#>
function New-EntraOpsServiceBootstrap {
    [OutputType([System.String])]
    [cmdletbinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ServiceName,

        [string[]]$ServiceMembers,

        [string]$ServiceOwner,

        [switch]$OwnerIsNotMember,  

        [switch]$ProhibitDirectElevation,

        [switch]$SkipAzureResourceGroup,

        [string]$AzureRegion = "eastus",

        [psobject[]]$ServiceRoles,

        [string]$logPrefix = "[$($MyInvocation.MyCommand)]"
    )

    begin {
        <#
        $graphModules = "Users,Authentication,Groups,Identity.Governance,Identity.SignIns,Identity.Governance".Split(",")
        $graphModules|%{Install-Module "Microsoft.Graph.$_"}
        $azModules = "Accounts,Resources".Split(",")
        $azModules|%{Install-Module "Az.$_"}
        #Connect-MgGraph -UseDeviceCode -Scopes Directory.AccessAsUser.All, EntitlementManagement.ReadWrite.All, RoleManagementPolicy.ReadWrite.AzureADGroup, RoleManagementPolicy.ReadWrite.Directory, RoleManagement.ReadWrite.Directory, PrivilegedEligibilitySchedule.ReadWrite.AzureADGroup, PrivilegedAccess.ReadWrite.AzureADGroup
        #Connect-AzAccount -UseDeviceAuthentication
        #>

        #todo update all variables to just use this hashtable
        $report = @{}

        #todo move regions to cmdlets
        #region ServiceOwner
        try{
            #$serviceOwner = Get-MgUser -UserId "adelev@M365x15606866.onmicrosoft.com"
            Write-Verbose "$logPrefix Service Owner Graph API Lookup"
            if(-not $PSBoundParameters.ContainsKey("ServiceOwner")){
                Write-Verbose "$logPrefix ServiceOwner not specified, looking up $((Get-MgContext).Account)"
                $graphOwner = Get-MgUser -UserId (Get-MgContext).Account
            }else{
                Write-Verbose "$logPrefix ServiceOwner set, looking up $ServiceOwner"
                $graphOwner = Get-MgUser -UserId $ServiceOwner
            }
            $owner = "https://graph.microsoft.com/v1.0/users/$($graphOwner.Id)"
            Write-Verbose "$logPrefix Setting owner as $owner"
        }catch{
            Write-Verbose "$logPrefix Failed to process Service Owner"
            Write-Error $_
        }
        #endregion

        #region ServiceMembers
        try{
            Write-Verbose "$logPrefix Service Members Graph API Lookup"
            $graphMembers = @()
            if(-not $PSBoundParameters.ContainsKey("ServiceMembers")){
                $ServiceMembers = @(
                    $(Get-MgUser -UserId (Get-MgContext).Account)
                )
            }else{
                foreach($serviceMember in $ServiceMembers){
                    $graphMembers += Get-MgUser -UserId $serviceMember
                }
            }
            if($graphOwner.Id -notin $graphMembers.Id -and -not $OwnerIsNotMember){
                $graphMembers += $graphOwner
            }
        }catch{
            Write-Verbose "$logPrefix Failed to process Service Members"
            Write-Error $_
        }
        #endregion

        #region ServiceRoles
        Write-Verbose "$logPrefix Service Roles validation"
        if(-not $PSBoundParameters.ContainsKey("ServiceRoles")){
            $ServiceRoles = @"
name,type,groupType
Members,,Unified
Members,Management,
Users,Workload,
Admins,Workload,
Admins,Entitlement,
Admins,Management,
"@|ConvertFrom-Csv
        }else{
            if(($ServiceRoles|Measure-Object).Count -lt 1){
                throw "`$ServiceRoles was supplied, but did not have any objects defined"
            }

            foreach($ServiceRole in $ServiceRoles){
                if(@("Users","Admins","Members") -inotcontains $ServiceRole.name){
                    throw "$($ServiceRole.name) is not in accepted values of 'Users', 'Admins', or 'Members'"
                }
                if(@("Workload","Entitlement","Management","") -inotcontains $ServiceRole.type){
                    throw "$($ServiceRole.type) is not in accepted values of 'Workload', 'Entitlement', 'Management', or ''"
                }
                if(@("Unified","Security","") -inotcontains $ServiceRole.groupType){
                    throw "$($ServiceRole.groupType) is not in accepted values of 'Unified' or ''"
                }
                if($ServiceRole.name -ieq "Users" -and $ServiceRole.type -ine "Workload"){
                    throw "Users should only be for Workload access"
                }
            }
        }
        #endregion
    }

    process {
        Write-Verbose "$logPrefix Processing Roles to Groups"
        $ServiceEntraGroupOptions = @{
            ServiceName  = $ServiceName
            ServiceOwner = $owner
            ServiceRoles = $ServiceRoles
        }
        $ServiceGroups = New-EntraOpsServiceEntraGroup @ServiceEntraGroupOptions
        $report.Groups = $ServiceGroups
        Write-Verbose "$logPrefix Service Groups IDs: $($report.Groups.Id|ConvertTo-Json -Compress)"

        Write-Verbose "$logPrefix Processing Catalog"
        $ServiceEMCatalogOptions = @{
            ServiceName  = $ServiceName
        }
        $ServiceEMCatalog = New-EntraOpsServiceEMCatalog @ServiceEMCatalogOptions
        $report.Catalog = $ServiceEMCatalog
        Write-Verbose "$logPrefix Service Catalog ID: $($report.Catalog.Id)"

        Write-Verbose "$logPrefix Processing Catalog Resources"
        $ServiceEMCatalogResourceOptions = @{
            ServiceGroup     = $ServiceGroups
            ServiceCatalogId = $ServiceEMCatalog.Id
        }
        $ServiceEMCatalogResources = New-EntraOpsServiceEMCatalogResource @ServiceEMCatalogResourceOptions
        $report.CatalogResources = $ServiceEMCatalogResources
        Write-Verbose "$logPrefix Service Catalog Resource IDs: $($report.CatalogResources.Id|ConvertTo-Json -Compress)"

        Write-Verbose "$logPrefix Processing Catalog Role Assignments"
        $ServiceEMCatalogResourceRolesOptions = @{
            ServiceCatalogId = $ServiceEMCatalog.Id
            ServiceGroups    = $ServiceGroups
        }
        $ServiceEMCatalogResourceRoles = New-EntraOpsServiceEMCatalogResourceRole @ServiceEMCatalogResourceRolesOptions
        $report.CatalogResourceRoles = $ServiceEMCatalogResourceRoles
        Write-Verbose "$logPrefix Service Catalog Resource Role IDs: $($report.CatalogResourceRoles.Id|ConvertTo-Json -Compress)"

        Write-Verbose "$logPrefix Processing Access Packages"
        $ServiceEMAccessPackagesOptions = @{
            ServiceName      = $ServiceName
            ServiceCatalogId = $ServiceEMCatalog.Id
            ServiceRoles     = $ServiceRoles
        }
        $ServiceEMAccessPackages = New-EntraOpsServiceEMAccessPackage @ServiceEMAccessPackagesOptions
        $report.AccessPackages = $ServiceEMAccessPackages
        Write-Verbose "$logPrefix Service Access Package IDs: $($report.AccessPackages.Id|ConvertTo-Json -Compress)"

        Write-Verbose "$logPrefix Processing assignment of Entra Groups to Access Packages"
        $ServiceEMAccessPackageResourceAssignmentOptions = @{
            ServicePackages         = $ServiceEMAccessPackages
            ServiceGroups           = $ServiceGroups
            ServiceCatalogResources = $ServiceEMCatalogResources
            ServiceCatalogId        = $ServiceEMCatalog.Id
        }
        $ServiceEMAccessPackageAssignments = New-EntraOpsServiceEMAccessPackageResourceAssignment @ServiceEMAccessPackageResourceAssignmentOptions
        $report.AccessPackageAssignments = $ServiceEMAccessPackageAssignments
        Write-Verbose "$logPrefix Service Access Package Assignment IDs: $($report.AccessPackageAssignments.Id|ConvertTo-Json -Compress)"

        Write-Verbose "$logPrefix Processing access package policy assignment"
        $ServiceEMAssignmentPolicyOptions = @{
            ServiceCatalogId = $ServiceEMCatalog.Id
            ServicePackages  = $ServiceEMAccessPackages
            ServiceGroups    = $ServiceGroups
            ServiceName      = $ServiceName
        }
        $ServiceEMAssignmentPolicies = New-EntraOpsServiceEMAssignmentPolicy @ServiceEMAssignmentPolicyOptions
        $report.AssignmentPolicies = $ServiceEMAssignmentPolicies
        Write-Verbose "$logPrefix Service Access Package Assignment Policy IDs: $($report.AssignmentPolicies.Id|ConvertTo-Json -Compress)"

        Write-Verbose "$logPrefix Processing access package assignments"
        $ServiceEMAssignmentOptions = @{
            ServiceCatalogId          = $ServiceEMCatalog.Id
            ServiceMembers            = $graphMembers
            ServiceAssignmentPolicies = $ServiceEMAssignmentPolicies
            ServicePackages           = $ServiceEMAccessPackages
        }
        $ServiceEMAssignments = New-EntraOpsServiceEMAssignment @ServiceEMAssignmentOptions
        $report.Assignments = $ServiceEMAssignments
        Write-Verbose "$logPrefix Service Access Package Assignment IDs: $($report.ASsignments.Id|ConvertTo-Json -Compress)"

        if(-not $ProhibitDirectElevation){
            Write-Verbose "$logPrefix Processing PIM policies"
            $ServicePIMPolicyOptions = @{
                ServiceGroups = $ServiceGroups
            }
            $ServicePIMPolicies = New-EntraOpsServicePIMPolicy @ServicePIMPolicyOptions
            $report.PimPolicies = $ServicePIMPolicies
            Write-Verbose "$logPrefix Service PIM Policy IDs: $($report.PimPolicies.Id|ConvertTo-Json -Compress)"

            Write-Verbose "$logPrefix Processing PIM assignments"
            $ServicePIMAssignmentOptions = @{
                ServiceGroups = $ServiceGroups
            }
            $ServicePIMAssignments = New-EntraOpsServicePIMAssignment @ServicePIMAssignmentOptions
            $report.PimAssignments = $ServicePIMAssignments
            Write-Verbose "$logPrefix Service PIM Assignment IDs: $($report.PimAssignments.Id|ConvertTo-Json -Compress)"
        }

        if(-not $SkipAzureResourceGroup){
            Write-Verbose "$logPrefix Processing Azure Container"
            $ServiceAZContainerOptions = @{
                ServiceName   = $ServiceName
                ServiceGroups = $ServiceGroups
                Location      = $AzureRegion
            }
            $ServiceAzContainer = New-EntraOpsServiceAZContainer @ServiceAZContainerOptions
            $report.AzContainer = $ServiceAzContainer
            Write-Verbose "$logPrefix Service Az Container ID: $($report.AzContainer.ResourceId|ConvertTo-Json -Compress)"
        }

        return $report
    }
}

#Fix Docs
#Fix Try/Catches
#Add Bootstrap for LZ

##Extras
#Created KV
#KV IAM Role Assignments
#Created Bastion
#Created VM
#Set managed identity
#Assign managed identity to member management and user workload
#Reader on Sub
#Peered Bastion and VM
#Install pwsh
#Set-AzKeyVaultSecret -VaultName "kv-Transacation" -Name "key-vm-Transaction" -SecretValue $(ConvertTo-SecureString (gc ./.key.pem -Raw) -AsPlainText -Force)