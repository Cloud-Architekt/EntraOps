function Show-EntraOpsWarningSummary {
    <#
    .SYNOPSIS
        Displays a formatted warning summary grouped by type with occurrence counts.
    .DESCRIPTION
        Shared helper that replaces the ~15-line warning display block duplicated
        across all EAM cmdlets. Groups warnings by Type, then by distinct Message,
        showing occurrence counts for duplicate messages.
    .PARAMETER WarningMessages
        The List[psobject] of warning messages collected during processing.
        Each item should have Type and Message properties.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [System.Collections.Generic.List[psobject]]$WarningMessages
    )

    if ($WarningMessages.Count -eq 0) {
        return
    }

    Write-Host ""
    Write-Host "═══════════════════════════════════════════════════════════════════════════════" -ForegroundColor Yellow
    Write-Host "  ⚠ Warnings Summary" -ForegroundColor Yellow
    Write-Host "═══════════════════════════════════════════════════════════════════════════════" -ForegroundColor Yellow
    
    # Group by Type first, then by distinct message within each type
    $GroupedByType = $WarningMessages | Group-Object Type
    foreach ($TypeGroup in $GroupedByType) {
        Write-Host "  $($TypeGroup.Name):" -ForegroundColor Yellow
        
        # Group messages by distinct message pattern to avoid duplicates
        $GroupedByMessage = $TypeGroup.Group | Group-Object Message
        foreach ($MessageGroup in $GroupedByMessage) {
            if ($MessageGroup.Count -eq 1) {
                Write-Host "    - $($MessageGroup.Name)" -ForegroundColor DarkYellow
            } else {
                Write-Host "    - $($MessageGroup.Name) [$($MessageGroup.Count) occurrences]" -ForegroundColor DarkYellow
            }
        }
    }
    Write-Host "═══════════════════════════════════════════════════════════════════════════════" -ForegroundColor Yellow
}
