<#
.SYNOPSIS
    Generate (refresh) the embedded dataset for the EntraOps Privileged Assets static web app.

.DESCRIPTION
    Builds one inventory record per privileged object (users, groups, service principals and
    applications incl. all object sub types) from the Privileged EAM export and merges the object
    across all RBAC systems. The inventory focuses on object details that are not visible in the
    role-assignment centric views: owners, sponsors, owned objects and devices, identity parent,
    associated work account and PAW device, administrative units, restricted management and the
    object tier compared with the classification of its role assignments.

    Related object IDs are resolved against the export first. IDs outside the export are resolved
    to display name and object type through Microsoft Graph (directoryObjects/getByIds) when
    -ResolveRelatedObjectIds is enabled; unresolved IDs stay visible as raw IDs.

    The dataset also embeds the Custom Security Attribute field names (for the PowerShell script
    generator of the app) and the current Object Classification File entries (so the app can edit
    the file). Generates data/privileged-assets-data.js exposing `window.ENTRAOPS_PRIVILEGED_ASSETS_DATA`.

.PARAMETER RepoRoot
    Path to the EntraOps repository root that contains the PrivilegedEAM export folder and
    EntraOpsConfig.json (alias: -Path). Defaults to the repository this module lives in.

.PARAMETER ImportPath
    Folder with the Privileged EAM export. Defaults to <RepoRoot>/PrivilegedEAM.

.PARAMETER AppRoot
    Path to the PrivilegedAssets app folder. Defaults to Reports/PrivilegedAssets.

.PARAMETER OutFile
    Output file. Defaults to <AppRoot>/data/privileged-assets-data.js.

.PARAMETER ConfigFilePath
    EntraOpsConfig.json used for the Custom Security Attribute and Object Classification File
    settings. Defaults to <RepoRoot>/EntraOpsConfig.json.

.PARAMETER ResolveRelatedObjectIds
    Resolve related object IDs outside the export through Microsoft Graph. Defaults to the
    PrivilegedAssets.ResolveRelatedObjectIds config setting, or $true.

.PARAMETER MaesterTestResultPath
    Location of the Maester test results used to enrich the inventory with failed Maester tests. Accepts
    a Maester result JSON file, the file path without the .json extension, or a folder; for a folder the
    latest TestResults-<yyyy-MM-dd-HHmmss>.json is used. Failed tests and the affected objects
    (AffectedObjects, or AssetInventory in older Maester versions) are matched to the privileged objects by
    object id, app id of app registrations or user principal name. Optional: without the parameter, or if no
    result file is found, the Maester integration is skipped (a warning is shown for an explicit path that
    does not exist).

.PARAMETER PassThru
    Emit the generated payload object to the pipeline.

.EXAMPLE
    New-EntraOpsPrivilegedAssetsData

    Regenerates the Privileged Assets dataset from the PrivilegedEAM folder of this repository.

.EXAMPLE
    New-EntraOpsPrivilegedAssetsData -ResolveRelatedObjectIds $false -WhatIf

    Shows what would be generated without Microsoft Graph lookups and without changing any files.
#>

function New-EntraOpsPrivilegedAssetsData {

    [CmdletBinding(SupportsShouldProcess = $true)]
    param (
        [Parameter(Mandatory = $false)]
        [Alias('Path')]
        [System.String]$RepoRoot,

        [Parameter(Mandatory = $false)]
        [System.String]$ImportPath,

        [Parameter(Mandatory = $false)]
        [System.String]$AppRoot,

        [Parameter(Mandatory = $false)]
        [System.String]$OutFile,

        [Parameter(Mandatory = $false)]
        [System.String]$ConfigFilePath,

        [Parameter(Mandatory = $false)]
        [System.Boolean]$ResolveRelatedObjectIds = $true,

        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [System.String]$MaesterTestResultPath = '',

        [Parameter(Mandatory = $false)]
        [switch]$PassThru
    )

    $ModuleRoot = $MyInvocation.MyCommand.Module.ModuleBase
    if ([string]::IsNullOrWhiteSpace($ModuleRoot) -and -not [string]::IsNullOrWhiteSpace($PSScriptRoot)) {
        $ModuleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    }
    if ([string]::IsNullOrWhiteSpace($ModuleRoot)) {
        throw "Unable to resolve the EntraOps module location. Import the module with 'Import-Module <path-to-EntraOps> -Force' and try again."
    }
    $RepositoryRoot = if (-not [string]::IsNullOrWhiteSpace($Global:EntraOpsBaseFolder)) { $Global:EntraOpsBaseFolder } else { Split-Path -Parent $ModuleRoot }

    if ([string]::IsNullOrWhiteSpace($RepoRoot)) { $RepoRoot = $RepositoryRoot }
    if ([string]::IsNullOrWhiteSpace($AppRoot)) { $AppRoot = Join-Path $RepoRoot 'Reports/PrivilegedAssets' }
    if (-not (Test-Path -LiteralPath $AppRoot -PathType Container)) {
        throw "Privileged Assets app folder not found: $AppRoot. Run Initialize-EntraOpsWorkspace -Content Reports -Force or Install-EntraOpsReportingFolder -Force to install or repair the reporting apps in the working folder (use -Ref to match the module version). Generated report data is preserved. If you passed -AppRoot, check that path instead."
    }
    if ([string]::IsNullOrWhiteSpace($ImportPath)) { $ImportPath = Join-Path $RepoRoot 'PrivilegedEAM' }
    if ([string]::IsNullOrWhiteSpace($OutFile)) { $OutFile = Join-Path $AppRoot 'data/privileged-assets-data.js' }
    if ([string]::IsNullOrWhiteSpace($ConfigFilePath)) { $ConfigFilePath = Join-Path $RepoRoot 'EntraOpsConfig.json' }

    if (-not (Test-Path -LiteralPath $ImportPath)) {
        throw "Privileged EAM import path not found: $ImportPath. Run Invoke-EntraOpsPrivilegedEAM (or Save-EntraOpsPrivilegedEAMJson) first, or pass -ImportPath."
    }

    $Config = $null
    if (Test-Path -LiteralPath $ConfigFilePath -PathType Leaf) {
        try {
            $Config = Get-Content -LiteralPath $ConfigFilePath -Raw | ConvertFrom-Json
        } catch {
            Write-Warning "Failed to read ${ConfigFilePath}: $($_.Exception.Message). Default Custom Security Attribute names are used and the Object Classification File is not loaded."
        }
    }
    if (-not $PSBoundParameters.ContainsKey('ResolveRelatedObjectIds') -and $null -ne $Config.PrivilegedAssets -and $null -ne $Config.PrivilegedAssets.ResolveRelatedObjectIds) {
        $ResolveRelatedObjectIds = [bool]$Config.PrivilegedAssets.ResolveRelatedObjectIds
    }

    function Get-PropValue {
        param($Object, [string]$Name)
        if ($null -eq $Object) { return $null }
        $Property = $Object.PSObject.Properties[$Name]
        if ($null -ne $Property) { return $Property.Value }
        return $null
    }

    function ConvertTo-StringArray {
        param($Value)
        if ($null -eq $Value) { return @() }
        return @(@($Value) | Where-Object { $null -ne $_ -and "$_" -ne '' } | ForEach-Object { "$_" })
    }

    function Get-ConfigValue {
        param($Section, [string]$Name, [string]$Default)
        $Value = "$(Get-PropValue $Section $Name)"
        if ([string]::IsNullOrWhiteSpace($Value)) { return $Default }
        return $Value
    }

    $GuidPattern = '^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$'

    # The object inventory is shared with the Findings rules (Invoke-EntraOpsFindingEvaluation).
    $Context = New-EntraOpsPrivilegedAssetsFindingContext -ImportPath $ImportPath
    $Files = $Context.Files
    $ObjectsById = $Context.ObjectsById
    $Objects = $Context.Objects
    $RelatedObjects = $Context.RelatedObjects
    $UnresolvedIds = $Context.UnresolvedIds
    $HomeTenantId = $Context.HomeTenantId

    if ($ResolveRelatedObjectIds -and $UnresolvedIds.Count -gt 0) {
        Write-Verbose "Resolving $($UnresolvedIds.Count) related object id(s) outside the Privileged EAM export via Microsoft Graph..."
        $IdsToResolve = @($UnresolvedIds | Sort-Object)
        $GraphBatchSize = 999 # directoryObjects/getByIds accepts up to 1000 IDs per request.
        for ($Index = 0; $Index -lt $IdsToResolve.Count; $Index += $GraphBatchSize) {
            $IdBatch = @($IdsToResolve[$Index..([Math]::Min($Index + $GraphBatchSize - 1, $IdsToResolve.Count - 1))])
            $Body = @{ ids = $IdBatch } | ConvertTo-Json
            try {
                foreach ($Resolved in @(Invoke-EntraOpsMsGraphQuery -Method POST -Uri '/v1.0/directoryObjects/getByIds' -Body $Body -OutputType PSObject)) {
                    $ResolvedId = "$(Get-PropValue $Resolved 'id')".ToLowerInvariant()
                    if (-not $ResolvedId) { continue }
                    $ResolvedType = "$(Get-PropValue $Resolved '@odata.type')" -replace '^#microsoft\.graph\.', ''
                    $RelatedObjects[$ResolvedId] = [ordered]@{
                        objectId          = $ResolvedId
                        displayName       = "$(Get-PropValue $Resolved 'displayName')"
                        objectType        = $ResolvedType.ToLowerInvariant()
                        userPrincipalName = "$(Get-PropValue $Resolved 'userPrincipalName')"
                        operatingSystem   = "$(Get-PropValue $Resolved 'operatingSystem')"
                        isCompliant       = Get-PropValue $Resolved 'isCompliant'
                        isManaged         = Get-PropValue $Resolved 'isManaged'
                        trustType         = "$(Get-PropValue $Resolved 'trustType')"
                        tierName          = ''
                        source            = 'Microsoft Graph'
                    }
                }
            } catch {
                Write-Warning "Failed to resolve $($IdBatch.Count) related object id(s) via Microsoft Graph: $($_.Exception.Message)"
            }
        }
    }

    # Maester failed tests: TestResults JSON (tests) joined with its AffectedObjects (assets) per privileged object.
    $MaesterPayload = $null
    if (-not [string]::IsNullOrWhiteSpace($MaesterTestResultPath)) {
        $MaesterFile = $null
        if (Test-Path -LiteralPath $MaesterTestResultPath -PathType Container) {
            $MaesterFile = Get-ChildItem -LiteralPath $MaesterTestResultPath -File -Filter 'TestResults-*.json' |
            Where-Object { $_.Name -match '^TestResults-\d{4}-\d{2}-\d{2}-\d{6}\.json$' } |
            Sort-Object -Property Name -Descending | Select-Object -First 1
        } elseif (Test-Path -LiteralPath $MaesterTestResultPath -PathType Leaf) {
            $MaesterFile = Get-Item -LiteralPath $MaesterTestResultPath
        } elseif (Test-Path -LiteralPath "$MaesterTestResultPath.json" -PathType Leaf) {
            $MaesterFile = Get-Item -LiteralPath "$MaesterTestResultPath.json"
        }

        if ($null -eq $MaesterFile) {
            $MaesterMessage = "No Maester test result found at '$MaesterTestResultPath'. Maester findings are not added to the Privileged Assets dataset."
            if ($PSBoundParameters.ContainsKey('MaesterTestResultPath')) { Write-Warning $MaesterMessage } else { Write-Verbose $MaesterMessage }
        } else {
            Write-Host "Maester test result: $($MaesterFile.FullName)"
            try {
                $MaesterResult = [System.IO.File]::ReadAllText($MaesterFile.FullName) | ConvertFrom-Json
            } catch {
                throw "Failed to read or parse Maester test result '$($MaesterFile.FullName)': $($_.Exception.Message)"
            }

            function Limit-MaesterText {
                param($Value, [int]$Length = 12000)
                $Text = "$Value"
                if ($Text.Length -le $Length) { return $Text }
                return $Text.Substring(0, $Length) + "`n`n... (truncated, see the Maester report for the full result)"
            }

            $MaesterAssets = @(@(Get-PropValue $MaesterResult 'AffectedObjects') + @(Get-PropValue $MaesterResult 'AssetInventory') | Where-Object { $null -ne $_ })
            $FailedTests = @{}
            foreach ($MaesterTest in @(Get-PropValue $MaesterResult 'Tests')) {
                # The tests of the EntraOps Maester Pack (MP.EOPS.*) report these findings, which the inventory shows already.
                if ($null -ne $MaesterTest -and "$(Get-PropValue $MaesterTest 'Result')" -eq 'Failed' -and "$(Get-PropValue $MaesterTest 'Id')" -notlike 'MP.EOPS.*') { $FailedTests["$(Get-PropValue $MaesterTest 'Id')"] = $MaesterTest }
            }

            $ObjectIdsByAppId = @{}
            $ObjectIdsByUpn = @{}
            foreach ($Object in $ObjectsById.Values) {
                if ($Object.objectType -eq 'application' -and $Object.userPrincipalName -match $GuidPattern) { $ObjectIdsByAppId[$Object.userPrincipalName.ToLowerInvariant()] = $Object.objectId }
                if ($Object.objectType -eq 'user' -and $Object.userPrincipalName -like '*@*') { $ObjectIdsByUpn[$Object.userPrincipalName.ToLowerInvariant()] = $Object.objectId }
            }

            $UsedTestIds = [System.Collections.Generic.HashSet[string]]::new()
            $MatchedObjectIds = [System.Collections.Generic.HashSet[string]]::new()
            foreach ($Asset in $MaesterAssets) {
                $FailedIds = @(ConvertTo-StringArray (Get-PropValue $Asset 'Tests') | Where-Object { $FailedTests.ContainsKey($_) })
                if ($FailedIds.Count -eq 0) { continue }

                $AssetId = "$(Get-PropValue $Asset 'Id')".ToLowerInvariant()
                $AssetUpn = "$(Get-PropValue $Asset 'UserPrincipalName')".ToLowerInvariant()
                $TargetId = $null
                if ($ObjectsById.Contains($AssetId)) { $TargetId = $AssetId }
                elseif ("$(Get-PropValue $Asset 'Type')" -eq 'AppRegistration' -and $ObjectIdsByAppId.ContainsKey($AssetId)) { $TargetId = $ObjectIdsByAppId[$AssetId] }
                elseif ($AssetUpn -and $ObjectIdsByUpn.ContainsKey($AssetUpn)) { $TargetId = $ObjectIdsByUpn[$AssetUpn] }
                if (-not $TargetId) { continue }

                if (-not $ObjectsById[$TargetId].Contains('maesterAssets')) { $ObjectsById[$TargetId]['maesterAssets'] = [System.Collections.Generic.List[object]]::new() }
                $ObjectsById[$TargetId]['maesterAssets'].Add([ordered]@{
                        system            = "$(Get-PropValue $Asset 'System')"
                        anchorKind        = "$(Get-PropValue $Asset 'AnchorKind')"
                        type              = "$(Get-PropValue $Asset 'Type')"
                        id                = "$(Get-PropValue $Asset 'Id')"
                        uniqueId          = "$(Get-PropValue $Asset 'UniqueId')"
                        displayName       = "$(Get-PropValue $Asset 'DisplayName')"
                        userPrincipalName = "$(Get-PropValue $Asset 'UserPrincipalName')"
                        portalLink        = "$(Get-PropValue $Asset 'PortalLink')"
                        sources           = @(ConvertTo-StringArray (Get-PropValue $Asset 'Sources'))
                        tests             = @($FailedIds)
                    })
                $MatchedObjectIds.Add($TargetId) | Out-Null
                foreach ($FailedId in $FailedIds) { $UsedTestIds.Add($FailedId) | Out-Null }
            }

            $MaesterTests = [ordered]@{}
            foreach ($TestId in @($UsedTestIds | Sort-Object)) {
                $MaesterTest = $FailedTests[$TestId]
                $Detail = Get-PropValue $MaesterTest 'ResultDetail'
                $Severity = "$(Get-PropValue $MaesterTest 'Severity')"
                if ([string]::IsNullOrWhiteSpace($Severity)) { $Severity = "$(Get-PropValue $Detail 'Severity')" }
                $MaesterTests[$TestId] = [ordered]@{
                    index       = Get-PropValue $MaesterTest 'Index'
                    id          = $TestId
                    title       = "$(Get-PropValue $MaesterTest 'Title')"
                    name        = "$(Get-PropValue $MaesterTest 'Name')"
                    severity    = $Severity
                    result      = "$(Get-PropValue $MaesterTest 'Result')"
                    tags        = @(ConvertTo-StringArray (Get-PropValue $MaesterTest 'Tag'))
                    helpUrl     = "$(Get-PropValue $MaesterTest 'HelpUrl')"
                    block       = "$(Get-PropValue $MaesterTest 'Block')"
                    service     = "$(Get-PropValue $Detail 'Service')"
                    description = Limit-MaesterText (Get-PropValue $Detail 'TestDescription')
                    testResult  = Limit-MaesterText (Get-PropValue $Detail 'TestResult')
                }
            }

            $ExecutedAt = $null
            try { $ExecutedAt = ([datetime](Get-PropValue $MaesterResult 'ExecutedAt')).ToUniversalTime().ToString('o') } catch { Write-Verbose "Maester ExecutedAt could not be parsed: $($_.Exception.Message)" }
            $MaesterTenantId = "$(Get-PropValue $MaesterResult 'TenantId')"
            if ($HomeTenantId -and $MaesterTenantId -and $MaesterTenantId -ne $HomeTenantId) {
                Write-Warning "The Maester test result belongs to tenant $MaesterTenantId, but the Privileged EAM export belongs to $HomeTenantId."
            }
            $MaesterPayload = [ordered]@{
                sourceFile          = $MaesterFile.Name
                executedAt          = $ExecutedAt
                tenantId            = $MaesterTenantId
                tenantName          = "$(Get-PropValue $MaesterResult 'TenantName')"
                totals              = [ordered]@{
                    total   = [int](Get-PropValue $MaesterResult 'TotalCount')
                    failed  = [int](Get-PropValue $MaesterResult 'FailedCount')
                    passed  = [int](Get-PropValue $MaesterResult 'PassedCount')
                    skipped = [int](Get-PropValue $MaesterResult 'SkippedCount')
                }
                affectedObjectCount = $MaesterAssets.Count
                matchedObjectCount  = $MatchedObjectIds.Count
                tests               = $MaesterTests
            }
            Write-Verbose "Maester: $($MaesterTests.Count) failed test(s) on $($MatchedObjectIds.Count) privileged object(s) from $($MaesterFile.FullName)"
        }
    }

    $CsaConfig = Get-PropValue $Config 'CustomSecurityAttributes'
    $AlternateConfig = Get-PropValue $Config 'AlternateObjectTierLevelAttributes'
    $FileConfig = Get-PropValue $Config 'ObjectClassificationFile'
    $FilePath = Get-ConfigValue $FileConfig 'FilePath' './Classification/ObjectClassification.json'
    $FileEntries = @()
    $FileError = ''
    try {
        $FileEntries = @((Import-EntraOpsObjectClassificationFile -FilePath $FilePath -RootFolder $RepoRoot -WarningAction SilentlyContinue).Values | Sort-Object ObjectId | ForEach-Object {
                [ordered]@{
                    objectId           = $_.ObjectId
                    objectType         = $_.ObjectType
                    objectDisplayName  = $_.ObjectDisplayName
                    adminTierLevelName = $_.AdminTierLevelName
                    justification      = $_.Justification
                }
            })
    } catch {
        $FileError = $_.Exception.Message
        Write-Warning "Object Classification File could not be loaded for Privileged Assets: $FileError"
    }

    $SortedRelatedObjects = [ordered]@{}
    foreach ($Key in @($RelatedObjects.Keys | Sort-Object)) { $SortedRelatedObjects[$Key] = $RelatedObjects[$Key] }

    # Findings of the inventory (EO.1xxx) from the Findings rules; the app re-evaluates them only for What-if.
    # Rules excluded in EntraOpsConfig.json (Findings.ExcludedRules) are not shown.
    $FindingSetting = Get-EntraOpsFindingSetting -ConfigFilePath $ConfigFilePath
    $FindingRuleResults = @(Invoke-EntraOpsFindingRuleSet -Context $Context -ExcludeRule $FindingSetting.ExcludedRules -Setting $FindingSetting)
    $FindingsByObject = [ordered]@{}
    foreach ($RuleResult in $FindingRuleResults) {
        foreach ($Result in $RuleResult.Results) {
            $FindingObjectId = $Result.Instance.ObjectId
            if (-not $FindingsByObject.Contains($FindingObjectId)) { $FindingsByObject[$FindingObjectId] = [System.Collections.Generic.List[string]]::new() }
            # A rule can report one object several times (EO.4010 reports each assignment): list each rule once per object.
            if (-not $FindingsByObject[$FindingObjectId].Contains($RuleResult.Key)) { $FindingsByObject[$FindingObjectId].Add($RuleResult.Key) }
        }
    }
    $FindingsPayload = [ordered]@{
        rules    = @($FindingRuleResults | ConvertTo-EntraOpsFindingRuleSummary)
        byObject = $FindingsByObject
    }

    $RepoRootFull = (Resolve-Path -LiteralPath $RepoRoot).Path
    $Payload = [ordered]@{
        tenantName             = Get-EntraOpsReportingTenantName -RepoRoot $RepoRoot
        generatedAt            = (Get-Date).ToUniversalTime().ToString('o')
        generatedFrom          = @($Files | ForEach-Object {
                if ($_.FullName.StartsWith($RepoRootFull)) { $_.FullName.Substring($RepoRootFull.Length).TrimStart('\', '/') -replace '\\', '/' } else { $_.Name }
            })
        homeTenantId           = "$HomeTenantId"
        maester                = $MaesterPayload
        classificationSettings = [ordered]@{
            customSecurityAttributes           = [ordered]@{
                enabledFor                         = [ordered]@{
                    user             = Test-EntraOpsCustomSecurityAttributeClassificationEnabled -ObjectType User -Enabled (Get-PropValue $CsaConfig 'Enabled') -ObjectClassificationFile $FileConfig -AlternateObjectTierLevelAttributes $AlternateConfig
                    servicePrincipal = Test-EntraOpsCustomSecurityAttributeClassificationEnabled -ObjectType ServicePrincipal -Enabled (Get-PropValue $CsaConfig 'Enabled') -ObjectClassificationFile $FileConfig -AlternateObjectTierLevelAttributes $AlternateConfig
                    application      = Test-EntraOpsCustomSecurityAttributeClassificationEnabled -ObjectType Application -Enabled (Get-PropValue $CsaConfig 'Enabled') -ObjectClassificationFile $FileConfig -AlternateObjectTierLevelAttributes $AlternateConfig
                }
                userAttributeSet                   = Get-ConfigValue $CsaConfig 'PrivilegedUserAttribute' 'privilegedUser'
                userTierLevelAttribute             = Get-ConfigValue $CsaConfig 'PrivilegedUserAdminTierLevelAttribute' 'adminTierLevel'
                userTierNameAttribute              = Get-ConfigValue $CsaConfig 'PrivilegedUserAdminTierLevelNameAttribute' 'adminTierLevelName'
                servicePrincipalAttributeSet       = Get-ConfigValue $CsaConfig 'PrivilegedServicePrincipalAttribute' 'privilegedWorkloadIdentity'
                servicePrincipalTierLevelAttribute = Get-ConfigValue $CsaConfig 'PrivilegedServicePrincipalAdminTierLevelAttribute' 'adminTierLevel'
                servicePrincipalTierNameAttribute  = Get-ConfigValue $CsaConfig 'PrivilegedServicePrincipalAdminTierLevelNameAttribute' 'adminTierLevelName'
            }
            alternateObjectTierLevelAttributes = [ordered]@{
                user             = Test-EntraOpsAlternateObjectTierLevelEnabled -ObjectType User -AlternateObjectTierLevelAttributes $AlternateConfig
                servicePrincipal = Test-EntraOpsAlternateObjectTierLevelEnabled -ObjectType ServicePrincipal -AlternateObjectTierLevelAttributes $AlternateConfig
                group            = Test-EntraOpsAlternateObjectTierLevelEnabled -ObjectType Group -AlternateObjectTierLevelAttributes $AlternateConfig
            }
            objectClassificationFile           = [ordered]@{
                enabled  = [bool](Get-PropValue $FileConfig 'Enabled')
                filePath = $FilePath
                error    = $FileError
                entries  = @($FileEntries)
            }
        }
        objects                = @($Objects | Sort-Object { $_.displayName })
        relatedObjects         = $SortedRelatedObjects
        findings               = $FindingsPayload
    }

    $Json = $Payload | ConvertTo-Json -Depth 10 -Compress
    $Content = "// Auto-generated by New-EntraOpsPrivilegedAssetsData - do not edit by hand.`n" +
    "window.ENTRAOPS_PRIVILEGED_ASSETS_DATA = $Json;`n"

    if ($PSCmdlet.ShouldProcess($OutFile, 'Write Privileged Assets dataset')) {
        Save-EntraOpsReportDataFile -Content $Content -LiteralPath $OutFile
        Write-Host "Privileged objects: $($Objects.Count)"
        Write-Host "Related objects:    $($SortedRelatedObjects.Count) resolved, $([Math]::Max(0, $UnresolvedIds.Count - @($SortedRelatedObjects.Values | Where-Object { $_.source -eq 'Microsoft Graph' }).Count)) unresolved"
        if ($null -ne $MaesterPayload) { Write-Host "Maester findings:   $($MaesterPayload.tests.Count) failed test(s) on $($MaesterPayload.matchedObjectCount) privileged object(s) ($($MaesterPayload.sourceFile))" }
        Write-Host "Wrote $OutFile"
    }

    if ($PassThru) { $Payload }
}
