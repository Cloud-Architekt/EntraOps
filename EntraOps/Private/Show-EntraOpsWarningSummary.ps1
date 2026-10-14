function Show-EntraOpsWarningSummary {
    <#
    .SYNOPSIS
        Displays a formatted warning summary grouped by type with occurrence counts.
    .DESCRIPTION
        Shared helper that replaces the ~15-line warning display block duplicated
        across all EAM cmdlets. Groups warnings by Type, then by GUID-normalized Message so
        near-identical messages that only differ by an embedded GUID (e.g. one line per deleted
        Access Package Catalog ID) collapse into a summarized line with an occurrence count.
        Object IDs remain visible; other object-specific details are omitted unless IncludeObjectDetails is enabled.
    .PARAMETER WarningMessages
        The List[psobject] of warning messages collected during processing.
        Each item should have Type and Message properties.
    .PARAMETER IncludeObjectDetails
        Include full warning messages in addition to object IDs. Defaults to
        ConsoleOutput.IncludeObjectDetails from EntraOpsConfig.json.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [System.Collections.Generic.List[psobject]]$WarningMessages,
        [Parameter(Mandatory = $false)]
        [Alias('IncludeIdentifiers')]
        [boolean]$IncludeObjectDetails = [bool]$Global:EntraOpsIncludeObjectDetails
    )

    if ($WarningMessages.Count -eq 0) {
        return
    }

    $GuidPattern = '[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}'
    $PrincipalNamePattern = '(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b'

    Write-Host ""
    Write-Host "═══════════════════════════════════════════════════════════════════════════════" -ForegroundColor Yellow
    Write-Host "  ⚠ Warnings Summary" -ForegroundColor Yellow
    Write-Host "═══════════════════════════════════════════════════════════════════════════════" -ForegroundColor Yellow
    
    # Group by Type first, then by GUID-normalized message within each type
    $GroupedByType = $WarningMessages | Group-Object Type
    foreach ($TypeGroup in $GroupedByType) {
        Write-Host "  $($TypeGroup.Name):" -ForegroundColor Yellow

        # Group by the message with any embedded GUID stripped out, so near-identical warnings
        # collapse while their first complete message remains available for display.
        $NormalizedGroups = [ordered]@{}
        foreach ($WarningMessage in $TypeGroup.Group) {
            $Message = $WarningMessage.Message
            $NormalizedMessage = [regex]::Replace([regex]::Replace($Message, $GuidPattern, '{id}'), $PrincipalNamePattern, '{principal}')
            if (-not $NormalizedGroups.Contains($NormalizedMessage)) {
                $NormalizedGroups[$NormalizedMessage] = [PSCustomObject]@{
                    NormalizedMessage = $NormalizedMessage
                    Count             = 0
                    DistinctIds       = [System.Collections.Generic.List[string]]::new()
                    SampleMessage     = $Message
                }
            }
            $Entry = $NormalizedGroups[$NormalizedMessage]
            $Entry.Count++
            foreach ($Id in ([regex]::Matches($Message, $GuidPattern) | ForEach-Object { $_.Value } | Select-Object -Unique)) {
                if (-not $Entry.DistinctIds.Contains($Id)) {
                    $Entry.DistinctIds.Add($Id)
                }
            }
        }

        # Without object details only the IDs are shown, so messages that differ only in hidden text
        # (e.g. the same object reported from two contexts) would print identical lines - merge those.
        $IdOnlyWarningCounts = @{}
        if (-not $IncludeObjectDetails) {
            foreach ($Entry in $NormalizedGroups.Values) {
                if ($Entry.DistinctIds.Count -eq 0) { continue }
                $IdSetKey = (@($Entry.DistinctIds | ForEach-Object { $_.ToLowerInvariant() } | Sort-Object -Unique)) -join ','
                $IdOnlyWarningCounts[$IdSetKey] = [int]$IdOnlyWarningCounts[$IdSetKey] + $Entry.Count
            }
        }
        $PrintedIdSets = [System.Collections.Generic.HashSet[string]]::new()

        foreach ($Entry in $NormalizedGroups.Values) {
            $DistinctIdCount = $Entry.DistinctIds.Count
            if (-not $IncludeObjectDetails -and $DistinctIdCount -gt 0) {
                $IdSetKey = (@($Entry.DistinctIds | ForEach-Object { $_.ToLowerInvariant() } | Sort-Object -Unique)) -join ','
                if (-not $PrintedIdSets.Add($IdSetKey)) { continue }
                $SampleIds = $Entry.DistinctIds | Select-Object -First 3
                $SampleText = $SampleIds -join ", "
                if ($DistinctIdCount -gt $SampleIds.Count) {
                    $SampleText += " (+$($DistinctIdCount - $SampleIds.Count) more)"
                }
                Write-Host "    - Object ID(s): $SampleText [$DistinctIdCount distinct ID(s) in $($IdOnlyWarningCounts[$IdSetKey]) warning(s)]" -ForegroundColor DarkYellow
                continue
            }

            $DisplayMessage = if ($IncludeObjectDetails) { $Entry.SampleMessage } else { $Entry.NormalizedMessage }
            if ($DistinctIdCount -le 1 -and $Entry.Count -le 1) {
                Write-Host "    - $DisplayMessage" -ForegroundColor DarkYellow
            } elseif ($DistinctIdCount -le 1) {
                Write-Host "    - $DisplayMessage [$($Entry.Count) occurrences]" -ForegroundColor DarkYellow
            } else {
                $SampleIds = $Entry.DistinctIds | Select-Object -First 3
                $SampleText = $SampleIds -join ", "
                if ($DistinctIdCount -gt $SampleIds.Count) {
                    $SampleText += " (+$($DistinctIdCount - $SampleIds.Count) more)"
                }
                Write-Host "    - $($Entry.SampleMessage) [$DistinctIdCount distinct ID(s) in $($Entry.Count) warning(s)] IDs: $SampleText" -ForegroundColor DarkYellow
            }
        }
    }
    Write-Host "═══════════════════════════════════════════════════════════════════════════════" -ForegroundColor Yellow
}
