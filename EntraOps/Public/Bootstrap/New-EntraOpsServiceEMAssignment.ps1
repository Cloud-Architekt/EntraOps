<#
.SYNOPSIS
    Creates access package resource assignments

.DESCRIPTION
    Assigns catalog resources with access packages

.PARAMETER ServiceCatalogId
    The Service Catalog GUID

.PARAMETER Service Members
    The Graph User URIs object
    
.PARAMETER ServicePackages
    The Graph Access Package objects

.PARAMETER ServiceAssignmentPolicies
    The Graph Assignment Policy objects

.PARAMETER logPrefix
    Defines the text to prepend for any verbose messages

.EXAMPLE
    New-EntraOpsServiceEMAssignment -ServiceCatalogId "<GUID>" -ServiceMembers $members -ServicePackages $packages -ServiceAssignmentPolicies $policies

#>
function New-EntraOpsServiceEMAssignment {
    [OutputType([psobject[]])]
    [cmdletbinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ServiceCatalogId,

        [Parameter(Mandatory)]
        [psobject[]]$ServiceMembers,

        [Parameter(Mandatory)]
        [psobject[]]$ServiceAssignmentPolicies,
        
        [Parameter(Mandatory)]
        [psobject[]]$ServicePackages,

        [string]$logPrefix = "[$($MyInvocation.MyCommand)]"
    )

    begin {
        $assignmentRequests = @()
        $assignments = @()

        $assignmentRequestsSplat = @{
            ExpandProperty = "Assignment(`$expand=Target),AccessPackage,Assignment"
            Filter = "State eq 'submitted'"
        }
        try{
            Write-Verbose "$logPrefix Looking up Assignment Requests"
            $assignmentRequests += Get-MgEntitlementManagementAssignmentRequest @assignmentRequestsSplat
        }catch{
            Write-Verbose "$logPrefix Failed to find Assignment Requests"
            Write-Error $_
        }

        $assignmentsSplat = @{
            ExpandProperty = "AccessPackage(`$expand=Catalog),AccessPackage,Target"
            Filter = "AccessPackage/Catalog/Id eq '$ServiceCatalogId' and State eq 'delivered'"
        }
        Write-Verbose "$logPrefix $($assignmentsSplat|ConvertTo-Json -Compress)"
        try{
            $assignments += Get-MgEntitlementManagementAssignment @assignmentsSplat
            if(($assignments|Measure-Object).Count -gt 0){
                Write-Verbose "$logPrefix Found Access Package Assignment IDs: $($assignments.Id|ConvertTo-Json -Compress)"
            }
        }catch{
            Write-Verbose "$logPrefix Failed to find Assignments"
            Write-Error $_
        }

        $assignmentParams = @{
            requestType = "adminAdd"
            assignment = @{
                targetId = ""
                assignmentPolicyId = ($ServiceAssignmentPolicies|Where-Object{$_.DisplayName -like "*Members*"}).Id
                accessPackageId = ($ServicePackages|Where-Object{$_.DisplayName -like "*Members*"}).Id
            }
        }
    }

    process {
        foreach($member in $ServiceMembers){
            Write-Verbose "$logPrefix Processing Service Member ID: $($member.Id)"
            $assignmentParams.assignment.targetId = $member.Id
            if($member.Id -notin $assignments.Target.ObjectId -and $member.Id -notin $assignmentRequests.Assignment.Target.ObjectId){
                try{
                    Write-Verbose "$logPrefix Creating Assignment Request"
                    $assignmentRequests += New-MgEntitlementManagementAssignmentRequest -BodyParameter $assignmentParams
                }catch{
                    Write-Verbose "$logPrefix Failed to create Assignment Request"
                    Write-Error $_
                }
            }
        }
    }

    end {
        $confirmed = $false
        $i = 0
        while(-not $confirmed){
            Start-Sleep -Seconds ([Math]::Pow(2,$i)-1)
            $checkAssignments = @()
            $checkAssignments += Get-MgEntitlementManagementAssignment @assignmentsSplat
            Write-Verbose "$logPrefix Service Member IDs: $($ServiceMembers.Id|ConvertTo-Json -Compress)"
            Write-Verbose "$logPrefix Assignment Target IDs: $($checkAssignments.Target.ObjectId|ConvertTo-Json -Compress)"
            if(-not ($null -eq $checkAssignments.Target.ObjectId)){
                if((Compare-Object $ServiceMembers.Id $checkAssignments.Target.ObjectId|Measure-Object).Count -eq 0){
                    Write-Verbose "$logPrefix Graph consistency found confirming"
                    $confirmed = $true
                    continue
                }
            }else{
                Write-Verbose "$logPrefix No assignments available skipping comparison"
            }
            $i++
            if($i -eq 5){
                Write-Warning "$logPrefix Fulfillment can take minutes to complete"
            }
            if($i -gt 9){
                throw "Access Package Assignment consistency with Entra not achieved"
            }
            Write-Verbose "$logPrefix Graph objects not available, sleeping $([Math]::Pow(2,$i)-1) seconds"
        }
        return [psobject[]]$checkAssignments
    }
}