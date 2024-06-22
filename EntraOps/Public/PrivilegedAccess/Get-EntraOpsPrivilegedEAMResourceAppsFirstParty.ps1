<#
.SYNOPSIS
    Get a list of privileged first party apps with classification based on the defined Enterprise Access Model.

.DESCRIPTION
    Use a list of defined first party apps and get activities as result from a Microsoft Sentinel log query.
    Activities from Microsoft Graph Activity Log includes permission scope which can be used for matching definition of Tiering Level.
    Other sources to identify first party apps can be also used but can't be used for permission classification.

.PARAMETER TenantId
    Tenant ID of the Microsoft Entra ID tenant. Default is the current tenant ID.

.PARAMETER SentinelWorkspaceId
    Workspace ID of the Microsoft Sentinel workspace.

.PARAMETER SentinelWorkspaceSubscriptionId
    Subscription ID of the Microsoft Sentinel workspace.

.PARAMETER Source
    Source of the data. Default is MsGraphActivity. Possible values are MsGraphActivity, AuditLogActivity, UnknownIdentityType.

.EXAMPLE
    Get a list of first party applications and activity from MicrosoftGraphActivity log and classify the audited permission scope.
    Get-EntraOpsPrivilegedEamResourceAppsFirstParty -Source MsGraphActivity -SentinelWorkspaceId "sentinel-la-123" -SentinelWorkspaceId "3f72a077-c32a-423c-8503-41b93d3b0737"
#>

function Get-EntraOpsPrivilegedEamResourceAppsFirstParty {

    [cmdletbinding()]
    param (
        [Parameter(Mandatory = $false)]
        [System.String]$TenantId = (Get-AzContext).Tenant.Id
        ,
        [Parameter(Mandatory = $true)]
        [System.String]$SentinelWorkspaceId
        ,
        [Parameter(Mandatory = $true)]
        [System.String]$SentinelWorkspaceSubscriptionId
        ,
        [Parameter(Mandatory = $false)]
        [ValidateSet("MsGraphActivity", "AuditLogActivity", "UnknownIdentityType")]
        [System.String]$Source = "MsGraphActivity"
    )

    Set-AzContext -SubscriptionId $SentinelWorkspaceSubscriptionId | Out-Null
    $TenantId = (Get-AzContext).Tenant.Id
    $AppRolesClassification = Invoke-RestMethod -Method Get -Uri "https://raw.githubusercontent.com/Cloud-Architekt/AzurePrivilegedIAM/main/Classification/Classification_AppRoles.json"
    $FirstPartyGraphActivitiyQuery = Invoke-RestMethod -Method GET -Uri "https://raw.githubusercontent.com/Cloud-Architekt/AzureSentinel/main/Hunting%20Queries/EID-WorkloadIdentities/GraphActivityFromFirstPartyApps.kusto" | Out-String
    $FirstPartyGraphActivitiyQuery = Invoke-RestMethod -Method GET -Uri "https://raw.githubusercontent.com/Cloud-Architekt/AzureSentinel/main/Hunting%20Queries/EID-WorkloadIdentities/GraphActivityFromFirstPartyApps.kusto"
    $FirstPartyGraphActivities = (Invoke-AzOperationalInsightsQuery -WorkspaceId $SentinelWorkspaceId -Query $FirstPartyGraphActivitiyQuery).Results | ConvertTo-Json | ConvertFrom-Json

    switch ($Source) {
        MsGraphActivity {
            $FirstPartyApps = foreach ($FirstPartyGraphActivity in $FirstPartyGraphActivities) {
                $AppRoles = $FirstPartyGraphActivity.AppRoleScope | ConvertFrom-Json
                $AppRoleClassifiedAssignments = foreach ($AppRole in $AppRoles) {
                    # Filter for Graph API (00000003-0000-0000-c000-000000000000)
                    $AppRoleClassification = $AppRolesClassification | where-object { $_.AppRoleDisplayName -in $AppRole -and $_.AppId -eq "00000003-0000-0000-c000-000000000000" }

                    $Classification = @()

                    if (($AppRoleClassification.Count -gt 0)) {
                        $ClassifiedAppRole = @()
                        $ClassifiedAppRole += $AppRoleClassification | select-object -Unique EAMTierLevelName, EAMTierLevelTagValue, Category
                        $Classification += $ClassifiedAppRole | ForEach-Object {
                            [PSCustomObject]@{
                                'AdminTierLevel'     = $_.EAMTierLevelTagValue
                                'AdminTierLevelName' = $_.EAMTierLevelName
                                'Service'            = $_.Category
                                'TaggedBy'           = "JSONwithAction"
                            }
                        }
                    }
                    else {
                        $Classification += [PSCustomObject]@{
                            'AdminTierLevel'     = "Unclassified"
                            'AdminTierLevelName' = "Unclassified"
                            'Service'            = "Unclassified"
                        }
                    }

                    [pscustomobject]@{
                        RoleAssignmentId              = $null
                        RoleAssignmentScopeId         = $null
                        RoleAssignmentScopeName       = "Microsoft Graph"
                        RoleAssignmentType            = "Direct"
                        PIMManagedRole                = $False
                        PIMAssignmentType             = "Permanent"
                        RoleDefinitionName            = $AppRoleClassification.AppRoleDisplayName
                        RoleDefinitionId              = $AppRoleClassification.AppRoleId
                        RoleType                      = "Application"
                        RoleIsPrivileged              = ""
                        Classification                = $Classification
                        ObjectId                      = $FirstPartyGraphActivity.ServicePrincipalObjectId
                        ObjectType                    = "serviceprincipal"
                        TransitiveByObjectId          = $null
                        TransitiveByObjectDisplayName = $null
                    }
                }

                try {
                    #$ObjectDetails = Get-AzADServicePrincipal -ObjectId $($FirstPartyGraphActivity.ServicePrincipalObjectId)
                    $ObjectDetails = Get-EntraOpsPrivilegedEntraObject -AadObjectId $($FirstPartyGraphActivity.ServicePrincipalObjectId) -TenantId $TenantId
                }
                catch {
                    Write-Warning "Service Principal Object for $($FirstPartyGraphActivity.AppDisplayName) not found!"
                }

                $AppRoleClassification = $($AppRoleClassifiedAssignments).Classification | select-object -Unique AdminTierLevel, AdminTierLevelName, Service | Sort-Object AdminTierLevel, AdminTierLevelName, Service

                # Classification
                $Classification = @()
                $Classification += $AppRoleClassification
                if ($Classification.Count -eq 0) {
                    $Classification += [PSCustomObject]@{
                        'AdminTierLevel'     = "Unclassified"
                        'AdminTierLevelName' = "Unclassified"
                        'Service'            = "Unclassified"
                    }
                }


                [PSCustomObject]@{
                    'ObjectId'                      = $FirstPartyGraphActivity.ServicePrincipalObjectId
                    'ObjectType'                    = $ObjectDetails.ObjectType.toLower()
                    'ObjectSubType'                 = $ObjectDetails.ObjectSubType
                    'ObjectDisplayName'             = $FirstPartyGraphActivity.AppDisplayName
                    'ObjectUserPrincipalName'       = $ObjectDetails.ObjectSignInName
                    'ObjectAdminTierLevel'          = $ObjectDetails.AdminTierLevel
                    'ObjectAdminTierLevelName'      = $ObjectDetails.AdminTierLevelName
                    'OnPremSynchronized'            = $ObjectDetails.OnPremSynchronized
                    'AssignedAdministrativeUnits'   = $ObjectDetails.AssignedAdministrativeUnits
                    'RestrictedManagementByRAG'     = $ObjectDetails.RestrictedManagementByRAG
                    'RestrictedManagementByAadRole' = $ObjectDetails.RestrictedManagementByAadRole
                    'RestrictedManagementByRMAU'    = $ObjectDetails.RestrictedManagementByRMAU
                    'RoleSystem'                    = "FirstPartyResourceApp"
                    'Classification'                = $Classification
                    'RoleAssignments'               = $AppRoleClassifiedAssignments
                    'OwnedObjects'                  = $ObjectDetails.OwnedObjects
                    'OwnedDevices'                  = $ObjectDetails.OwnedDevices
                    'AssociatedWorkAccount'         = $ObjectDetails.AssociatedWorkAccount
                    'AssociatedPawDevice'           = $ObjectDetails.AssociatedPawDevice
                    'Audience'                      = $FirstPartyGraphActivity.AzureADMultipleOrgs
                }
            }
            $FirstPartyApps
        }
        AuditLogActivity {
            $FirstPartyAadActivitiyQuery = Invoke-RestMethod -Method GET -Uri "https://raw.githubusercontent.com/Cloud-Architekt/AzureSentinel/main/Hunting%20Queries/EID-WorkloadIdentities/AadAuditEventFromFirstPartyApps.kusto" | Out-String
            $FirstPartyAadActivities = (Invoke-AzOperationalInsightsQuery -WorkspaceId $SentinelWorkspaceId -Query $FirstPartyAadActivitiyQuery).Results | ConvertTo-Json | ConvertFrom-Json
            $FirstPartyAadActivities | Where-Object { $_.ServicePrincipalObjectId -notin $FirstPartyApps.ObjectId }
        }

        UnknownIdentityType {
            $FirstPartyUnknownIdentityType = 'AuditLogs | where TimeGenerated >ago(365d) | where InitiatedBy == "{}" | summarize make_set( OperationName ) by Identity'
            $FirstPartyUnknownIdentityActivities = (Invoke-AzOperationalInsightsQuery -WorkspaceId $SentinelWorkspaceId -Query $FirstPartyUnknownIdentityType).Results | ConvertTo-Json | ConvertFrom-Json
            $FirstPartyUnknownIdentityActivities
        }
    }
}