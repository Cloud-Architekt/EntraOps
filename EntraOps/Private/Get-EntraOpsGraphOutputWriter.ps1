function Get-EntraOpsGraphOutputWriter {
    # Resolve only an already-loaded SDK type so REST-only installations stay independent of it.
    $GraphSessionType = 'Microsoft.Graph.PowerShell.Authentication.GraphSession' -as [type]
    if ($null -ne $GraphSessionType -and $GraphSessionType::Exists) {
        $GraphSessionType::Instance.OutputWriter
    }
}
