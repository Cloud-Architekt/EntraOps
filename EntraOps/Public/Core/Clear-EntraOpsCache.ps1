<#
.SYNOPSIS
    Resets the local cache of Graph API calls. Use this if you need to force a refresh of the cache in the current session.

.DESCRIPTION
    By default all graph responses are cached and re-used for the duration of the session.
    Use this function to clear the cache and force a refresh of the data from Microsoft Graph.
    This function has been written by Merill Fernando as part of Maester Framework.

.EXAMPLE
    This example clears the cache of all Graph API calls in EntraOps.
    Clear-EntraOpsCache
#>

function Clear-EntraOpsCache {
    Write-Verbose -Message "Clearing the results cached from Graph API calls in this session"
    $__EntraOpsSession.GraphCache = @{}
}