function New-EntraOpsFindingResult {
    <#
    .SYNOPSIS
        Creates one finding result record (one affected instance of a finding rule).
    .DESCRIPTION
        Shared shape of all finding results, aligned with the instances of a Maester test family:
        Instance.Id identifies the affected instance within the rule (an object ID or a path ID) and
        Evidence holds the rule-specific details the reports and the Maester Pack show.
    .PARAMETER Rule
        The finding rule (from Get-EntraOpsFindingRule).
    .PARAMETER InstanceId
        Identifier of the affected instance, unique within the rule.
    .PARAMETER Severity
        Severity of this result. Defaults to the severity of the rule.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [object]$Rule,

        [Parameter(Mandatory = $true)]
        [string]$InstanceId,

        [Parameter(Mandatory = $false)]
        [string]$ObjectId,

        [Parameter(Mandatory = $false)]
        [string]$ObjectType,

        [Parameter(Mandatory = $false)]
        [string]$DisplayName,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [Nullable[int]]$AdminTierLevel,

        # The tier name of the object (ControlPlane ... UserAccess, or Unclassified), when the rule knows it: an
        # unclassified object has the AdminTierLevel 2 of User Access, its tier name tells it apart.
        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string]$AdminTierLevelName,

        [Parameter(Mandatory = $false)]
        [string]$Message,

        [Parameter(Mandatory = $false)]
        [System.Collections.IDictionary]$Evidence = [ordered]@{},

        [Parameter(Mandatory = $false)]
        [ValidateSet('Critical', 'High', 'Medium', 'Low', 'Info')]
        [string]$Severity
    )

    [pscustomobject]@{
        PSTypeName = 'EntraOps.Finding'
        RuleId     = $Rule.Id
        Key        = $Rule.Key
        Area       = $Rule.Area
        Severity   = $(if ($Severity) { $Severity } else { $Rule.Severity })
        Status     = 'Failed'
        Instance   = [pscustomobject]@{
            PSTypeName     = 'EntraOps.FindingInstance'
            Id             = $InstanceId
            ObjectId       = $ObjectId
            ObjectType     = $ObjectType
            DisplayName    = $DisplayName
            AdminTierLevel = $AdminTierLevel
            AdminTierLevelName = $(if ($AdminTierLevelName) { $AdminTierLevelName } else { $null })
        }
        Evidence   = $Evidence
        Message    = $Message
        # The message without its subject (object and tier), for views that show the object next to it.
        Detail     = (Get-EntraOpsFindingDetail -Message $Message -DisplayName $DisplayName -ObjectId $ObjectId -ObjectType $ObjectType -AdminTierLevelName $AdminTierLevelName)
    }
}
