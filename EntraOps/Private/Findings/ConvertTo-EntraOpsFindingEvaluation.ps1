function ConvertTo-EntraOpsFindingEvaluation {
    <#
    .SYNOPSIS
        Converts the evaluated instances of a finding rule to its evaluation (evaluated count and results).
    .DESCRIPTION
        The one place where the evaluated instances of every rule evaluator (Invoke-EntraOps<Area>FindingRule)
        become results (Invoke-EntraOpsFindingRuleSet). Each instance is an object with Failed and the fields
        of New-EntraOpsFindingResult (InstanceKey, ObjectId, ObjectType, DisplayName, AdminTierLevel, Message,
        Evidence). InstanceKey identifies the instance within the rule; it becomes a finding instance ID
        (ConvertTo-EntraOpsFindingInstanceId). Instances are de-duplicated by instance ID like the reports
        (for example a flow id that occurs twice): only the first instance of an ID is evaluated.
        An instance with NoteOnly set is no instance: it only carries a Note of the rule (see
        Invoke-EntraOpsFindingRuleSet), for example why some data was not evaluated.
        A failed instance with Unclassified set (an unclassified object, whose tier is unknown) becomes an
        unclassified result (UnclassifiedResults) instead of a result: the rule reports it only as a count.
    .PARAMETER Rule
        The finding rule (from Get-EntraOpsFindingRule).
    .PARAMETER Instance
        The evaluated instances of the rule.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [object]$Rule,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [AllowEmptyCollection()]
        [object[]]$Instance = @()
    )

    $EvaluatedCount = 0
    $Results = [System.Collections.Generic.List[object]]::new()
    $UnclassifiedResults = [System.Collections.Generic.List[object]]::new()
    $InstanceIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
    foreach ($Item in @($Instance)) {
        if ($null -eq $Item) { continue }
        if ($null -ne $Item.PSObject.Properties['NoteOnly'] -and $Item.NoteOnly) { continue }
        $InstanceKey = "$($Item.InstanceKey)"
        # Fast path for keys that are valid instance IDs already (object IDs, path IDs, flow ids).
        $InstanceId = if ($InstanceKey -match '^[A-Za-z0-9][A-Za-z0-9._|-]{0,127}$') { $InstanceKey.Replace('|', '.') } else { ConvertTo-EntraOpsFindingInstanceId -Value $InstanceKey }
        if (-not $InstanceIds.Add($InstanceId)) { continue }
        $EvaluatedCount++
        if (-not $Item.Failed) { continue }

        $Parameters = @{
            Rule        = $Rule
            InstanceId  = $InstanceId
            ObjectId    = "$($Item.ObjectId)"
            ObjectType  = "$($Item.ObjectType)"
            DisplayName = "$($Item.DisplayName)"
            Message     = "$($Item.Message)"
            Evidence    = $(if ($Item.Evidence -is [System.Collections.IDictionary]) { $Item.Evidence } else { [ordered]@{} })
        }
        if ($null -ne $Item.PSObject.Properties['AdminTierLevel'] -and $null -ne $Item.AdminTierLevel) { $Parameters.AdminTierLevel = $Item.AdminTierLevel }
        if ($null -ne $Item.PSObject.Properties['AdminTierLevelName'] -and $Item.AdminTierLevelName) { $Parameters.AdminTierLevelName = "$($Item.AdminTierLevelName)" }
        if ($null -ne $Item.PSObject.Properties['Unclassified'] -and $Item.Unclassified) {
            $UnclassifiedResults.Add((New-EntraOpsFindingResult @Parameters))
        } else {
            $Results.Add((New-EntraOpsFindingResult @Parameters))
        }
    }

    [pscustomobject]@{
        EvaluatedCount      = $EvaluatedCount
        Results             = $Results
        UnclassifiedResults = $UnclassifiedResults
    }
}
