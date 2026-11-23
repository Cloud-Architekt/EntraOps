<#
.SYNOPSIS
    Build the CloudSet entries of ScopeReasoning_Defender.json from the Defender CloudSet role assignments.

.DESCRIPTION
    Groups the Defender for Cloud CloudSet role assignments by CloudSet and maps each CloudSet's member
    subscriptions onto the Tier0/Tier1 Azure resource scopes.

    ResolutionStatus describes whether the CloudSet's subscription membership is known:
    - 'Resolved'  : at least one member subscription was collected.
    - 'Unresolved': no member subscription was collected. This covers an app scope Defender could not resolve
                    at all and a CloudSet that resolved by id/name but returned zero Azure subscriptions (for
                    example a failed Security Exposure Management zone lookup or a zone without Azure
                    subscriptions). Both cases are kept as a bounded scope of unknown membership
                    (ResultingScope 'UnknownBoundedScope'), never as 'Unclassified', because an empty membership
                    cannot prove that no Tier0 subscription is in scope. The Reason names the case.

.PARAMETER CloudSetAssignments
    Objects with CloudSetId, CloudSetName, SubscriptionScopes and ResolutionStatus (the ScopeResolutionStatus
    collected by Get-EntraOpsPrivilegedDefenderRoles).

.PARAMETER Tier0IncludedResourceScope
    Tier0 (ControlPlane) Azure resource scopes.

.PARAMETER Tier1IncludedResourceScope
    Tier1 (ManagementPlane) Azure resource scopes.

.PARAMETER ResourceScopeDetails
    Azure resource scope details (ResourceId, Source, EAMTier, Reason, ExpandedScopePaths) used as evidence.
#>
function ConvertTo-EntraOpsDefenderCloudSetScopeReasoning {
    [CmdletBinding()]
    [OutputType([psobject[]])]
    param (
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [AllowEmptyCollection()]
        [object[]]$CloudSetAssignments = @(),

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [AllowEmptyCollection()]
        [object[]]$Tier0IncludedResourceScope = @(),

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [AllowEmptyCollection()]
        [object[]]$Tier1IncludedResourceScope = @(),

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [AllowEmptyCollection()]
        [object[]]$ResourceScopeDetails = @()
    )

    $Tier0IncludedResourceScope = @($Tier0IncludedResourceScope | Where-Object { $null -ne $_ })
    $Tier1IncludedResourceScope = @($Tier1IncludedResourceScope | Where-Object { $null -ne $_ })
    $ResourceScopeDetails = @($ResourceScopeDetails | Where-Object { $null -ne $_ })

    return @(@($CloudSetAssignments | Where-Object { $null -ne $_ }) | Group-Object CloudSetId | Sort-Object Name | ForEach-Object {
            $Assignments = @($_.Group)
            $SubscriptionScopes = @($Assignments | ForEach-Object { @($_.SubscriptionScopes) } | Where-Object { -not [string]::IsNullOrWhiteSpace("$_") } | ForEach-Object { "$_" } | Sort-Object -Unique)
            $Tier0SubscriptionScopes = @($SubscriptionScopes | Where-Object { $Tier0IncludedResourceScope -contains $_ })
            $Tier1SubscriptionScopes = @($SubscriptionScopes | Where-Object { $_ -notin $Tier0SubscriptionScopes -and $Tier1IncludedResourceScope -contains $_ })
            $ResolutionStatus = if ($SubscriptionScopes.Count -gt 0) { 'Resolved' } else { 'Unresolved' }
            $ResultingScope = if ($Tier0SubscriptionScopes.Count -gt 0) { 'Tier0' } elseif ($Tier1SubscriptionScopes.Count -gt 0) { 'Tier1' } elseif ($ResolutionStatus -eq 'Resolved') { 'Unclassified' } else { 'UnknownBoundedScope' }

            $Reason = if ($ResolutionStatus -eq 'Resolved') {
                "CloudSet contains $($SubscriptionScopes.Count) subscription(s); $($Tier0SubscriptionScopes.Count) map to Tier0 Azure reasoning and $($Tier1SubscriptionScopes.Count) map only to Tier1 Azure reasoning."
            } elseif (@($Assignments | Where-Object { "$($_.ResolutionStatus)" -eq 'Resolved' }).Count -gt 0) {
                "CloudSet was resolved by Defender, but no Azure subscription could be determined for it (Security Exposure Management zone lookup failed or the zone contains no Azure subscriptions). Membership is unknown, so it is kept as a bounded scope instead of being treated as unclassified."
            } else {
                "CloudSet could not be resolved by Defender, so its subscription membership is unknown. It is kept as a bounded scope instead of being treated as unclassified."
            }

            $AzureScopeEvidence = foreach ($SubscriptionScope in $SubscriptionScopes) {
                $ResourceEvidence = @($ResourceScopeDetails | Where-Object { @($_.ExpandedScopePaths) -contains $SubscriptionScope } | Sort-Object Source, ResourceName, ResourceId)
                [PSCustomObject]@{
                    SubscriptionScope = $SubscriptionScope
                    ResultingScope    = if ($Tier0SubscriptionScopes -contains $SubscriptionScope) { 'Tier0' } elseif ($Tier1SubscriptionScopes -contains $SubscriptionScope) { 'Tier1' } else { 'Unclassified' }
                    ScopeDetails      = @($ResourceEvidence | ForEach-Object {
                            [PSCustomObject]@{
                                ScopeId = $_.ResourceId
                                Source  = $_.Source
                                EAMTier = $_.EAMTier
                                Reason  = $_.Reason
                            }
                        })
                }
            }

            [PSCustomObject]@{
                CloudSetId              = $_.Name
                # A string, not an array: the first non-empty name in sort order keeps the output deterministic.
                CloudSetName            = "$(@($Assignments.CloudSetName | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Sort-Object -Unique) | Select-Object -First 1)"
                ResolutionStatus        = $ResolutionStatus
                SubscriptionScopes      = $SubscriptionScopes
                Tier0SubscriptionScopes = $Tier0SubscriptionScopes
                Tier1SubscriptionScopes = $Tier1SubscriptionScopes
                ResultingScope          = $ResultingScope
                Reason                  = $Reason
                AzureScopeEvidence      = @($AzureScopeEvidence)
            }
        })
}
