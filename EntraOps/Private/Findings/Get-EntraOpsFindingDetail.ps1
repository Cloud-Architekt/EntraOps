function Get-EntraOpsFindingDetail {
    <#
    .SYNOPSIS
        The message of a finding result without its subject, for views that show the object next to it.
    .DESCRIPTION
        The Message of a result is a full sentence that names its object and tier ("Management Plane object
        'admThom1' reaches ..."), so it stands on its own in the console, exports and Sentinel. A table that shows
        the object, its type and its tier in a column of its own (the Maester Pack) repeats them with each finding.
        Detail is the rest of the sentence, starting with a capital letter ("Reaches ...").

        Only a known subject at the start of the message is removed, and only when it names the object of the result
        (its display name) with the tier of the result: "<tier> object '<name>'", "Unclassified object (counted as
        User Access) '<name>'", "<tier> workload identity '<name>'", "The <tier> role '<name>'", "User '<name>'",
        "Service principal '<name>'", "Group '<name>'", "Custom role '<name>'", "The Conditional Access policy
        '<name>'", "The administrative unit '<name>'" or "'<name>'". The object inside the message ("the <tier> role
        '<name>'", "the policy '<policy>' of the access package '<package>'") becomes "the role" or "the policy". A following "(<object type>)" or "(<tier>)" is
        removed with it; other details in parentheses are kept as a label ("Azure: grants ...", "Block access: ...").
        Any other message, or a rest that would not read as a sentence, is returned unchanged.
    .PARAMETER Message
        The message of the result.
    .PARAMETER DisplayName
        The display name of the object of the result.
    .PARAMETER ObjectType
        The object type of the result (user, group, serviceprincipal ...).
    .PARAMETER AdminTierLevelName
        The tier name of the result (ControlPlane ... UserAccess, or Unclassified).
    .EXAMPLE
        Get-EntraOpsFindingDetail -Message "Management Plane object 'admThom1' (user) is not linked to a work account." -DisplayName 'admThom1' -ObjectType 'user' -AdminTierLevelName 'ManagementPlane'

        Returns "Is not linked to a work account."
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param (
        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string]$Message,

        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string]$DisplayName,

        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string]$ObjectType,

        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string]$AdminTierLevelName
    )

    if ([string]::IsNullOrWhiteSpace($Message) -or [string]::IsNullOrWhiteSpace($DisplayName)) { return $Message }

    $TierNames = @{ ControlPlane = 'Control Plane'; ManagementPlane = 'Management Plane'; WorkloadPlane = 'Workload Plane'; UserAccess = 'User Access' }
    $Tier = if ($TierNames.ContainsKey($AdminTierLevelName)) { $TierNames[$AdminTierLevelName] } else { $null }
    # The object named inside the message, with its tier: "the role", "the policy" ("The activation of the role ...",
    # "Assignments of the policy do not expire.").
    if ($Tier) { $Message = $Message.Replace("the $Tier role '$DisplayName'", 'the role') }
    if ($ObjectType -eq 'accessPackageAssignmentPolicy' -and $DisplayName -match '^(.+) / ([^/]+)$') {
        $Message = $Message.Replace("the policy '$($Matches[2])' of the access package '$($Matches[1])'", 'the policy')
    }
    if ($ObjectType -eq 'accessPackageAssignmentPolicy' -and $DisplayName -match '^(.+) / ([^/]+)$') {
        # The policy as the subject: "The policy '<policy>' of the access package '<package>' has no access review."
        $PolicySubject = "The policy '$($Matches[2])' of the access package '$($Matches[1])' "
        if ($Message.StartsWith($PolicySubject, [System.StringComparison]::Ordinal) -and $Message.Length -gt $PolicySubject.Length + 2) {
            $Rest = $Message.Substring($PolicySubject.Length)
            return $Rest.Substring(0, 1).ToUpperInvariant() + $Rest.Substring(1)
        }
    }
    # A role assignment of the object: "'<role>' (<system>) of '<name>' has no tier classification.", maybe followed by
    # why (an app role the resource application no longer offers).
    $OfObject = " of '$DisplayName' has no tier classification."
    $OfIndex = $Message.IndexOf($OfObject, [System.StringComparison]::Ordinal)
    if ($Message -cmatch "^'[^']+' \([^()]+\) of '" -and $OfIndex -gt 0 -and ($OfIndex + $OfObject.Length -eq $Message.Length -or $Message[$OfIndex + $OfObject.Length] -eq ' ')) {
        return $Message.Substring(0, $OfIndex) + ' has no tier classification.' + $Message.Substring($OfIndex + $OfObject.Length)
    }
    # A workload identity named with the tier of its access, which is not the tier of the object: the tier stays.
    if ($Message -cmatch "^(Control Plane|Management Plane|Workload Plane|User Access) workload identity '$([regex]::Escape($DisplayName))' (.{3,})$" -and $Matches[1] -ne $Tier) {
        return "With $($Matches[1]) access, $($Matches[2])"
    }
    # Longest subjects first: "Unclassified object (counted as User Access) " before "Unclassified object ", and the
    # bare name last. The tier of a subject must be the tier of the result, which the reports show with the object.
    $Subjects = @(
        if ($AdminTierLevelName -eq 'Unclassified') { 'Unclassified object (counted as User Access) '; 'Unclassified object ' }
        if ($Tier) { "$Tier object "; "$Tier workload identity "; "The $Tier role " }
        'The Conditional Access policy '
        'The administrative unit '
        'Service principal '
        'Custom role '
        'Group '
        'User '
        ''
    )
    foreach ($Subject in $Subjects) {
        $Start = "$Subject'$DisplayName'"
        if (-not $Message.StartsWith($Start, [System.StringComparison]::Ordinal)) { continue }
        $Rest = $Message.Substring($Start.Length)
        # The object type or tier in parentheses, which the reports show with the object.
        foreach ($Shown in @($ObjectType, $Tier) | Where-Object { $_ }) {
            if ($Rest.StartsWith(" ($Shown)", [System.StringComparison]::OrdinalIgnoreCase)) { $Rest = $Rest.Substring($Shown.Length + 3); break }
        }
        $Rest = $Rest.TrimStart()
        # A rest that describes the object further ("of the application of tenant ...") keeps the subject without the
        # name: "Service principal of the application of tenant ...".
        if ($Subject -and $Rest -cmatch '^of\b') { return "$($Subject.Trim()) $Rest" }
        # A rest that does not start a sentence ("and ...", "'s owners") stays in the message.
        if ($Rest.Length -lt 3 -or $Rest -cmatch '^(of|and|or|to|in)\b' -or $Rest -notmatch '^[\p{L}(]') { return $Message }
        # "with Management Plane role assignments owns ..." describes the object first: a comma separates it.
        $Rest = $Rest -creplace '^(with [\w ]+? role assignments) (?=\p{Ll})', '$1, '
        # A detail of the object in parentheses ("(Azure) grants ...", "(block access) does not apply ...") is a label.
        $Rest = $Rest -creplace '^\(([^()]+)\)\s+(?=\S)', '$1: '
        return $Rest.Substring(0, 1).ToUpperInvariant() + $Rest.Substring(1)
    }
    $Message
}
