function Export-EntraOpsClassificationDirectoryRolesFromMsftDocs {

    <#
    .SYNOPSIS
        Get a JSON file with all classified Entra ID Directory roles by parsing the public Microsoft Docs reference.

    .DESCRIPTION
        Parses the "Microsoft Entra built-in roles" permissions reference markdown from the MicrosoftDocs/entra-docs
        repository and all of its include pages. For every role it reads the role template ID and privileged label
        from the "All roles" table, the role description text below the metadata header of the include page, and the
        list of role actions from the include page table. The role actions are classified with the EntraOps
        classification (Classification_AadResources.json) in the same way as Export-EntraOpsClassificationDirectoryRoles.ps1
        and the result is exported in the schema of Classification_EntraIdDirectoryRoles.json.

        This script does not require a connection to Microsoft Graph, it only needs internet access to raw.githubusercontent.com.

    .PARAMETER PermissionsReferenceUri
        Raw URI of the permissions-reference.md file. Default points to the main branch of MicrosoftDocs/entra-docs.

    .PARAMETER ClassificationFilePath
        Path to the EntraOps classification source file. Default is "./EntraOps_Classification/Classification_AadResources.json".

    .PARAMETER OutputFilePath
        Path of the JSON file to write. Default is "./Classification/Classification_EntraIdDirectoryRolesFromMsftDocs.json".

    .PARAMETER SingleClassification
        Use the highest tier level classification only for each role definition. Default is $True.

    .PARAMETER RoleDefinitionOverwritesFilePath
        Path to the EntraOps role definition overwrites file. Roles listed there (RbacSystem "EntraID") are pinned
        to the overwrite tier because their sensitivity is not visible in their role actions.
        Default is "./EntraOps_Classification/Classification_RoleDefinitionOverwrites.json".

    .EXAMPLE
        Export all classified Entra ID Directory roles parsed from Microsoft Docs.
        Export-EntraOpsClassificationDirectoryRolesFromMsftDocs
    #>

    [cmdletbinding()]
    param
    (
        [Parameter(Mandatory = $false)]
        [string]$PermissionsReferenceUri = "https://raw.githubusercontent.com/MicrosoftDocs/entra-docs/refs/heads/main/docs/identity/role-based-access-control/permissions-reference.md"
        ,
        [Parameter(Mandatory = $false)]
        [string]$ClassificationFilePath = "./EntraOps_Classification/Classification_AadResources.json"
        ,
        [Parameter(Mandatory = $false)]
        [string]$OutputFilePath = "./Classification/Classification_EntraIdDirectoryRolesFromMsftDocs.json"
        ,
        [Parameter(Mandatory = $false)]
        $SingleClassification = $True
        ,
        [Parameter(Mandatory = $false)]
        [string]$RoleDefinitionOverwritesFilePath = "./EntraOps_Classification/Classification_RoleDefinitionOverwrites.json"
    )

    # Roles whose sensitivity is not visible in their role actions (same source EntraOps applies at runtime)
    $RoleDefinitionOverwrites = Get-EntraOpsRoleDefinitionOverwrites -Path $RoleDefinitionOverwritesFilePath -RbacSystem 'EntraID'

    #region Helper functions
    function Get-RawWebContent {
        param ([Parameter(Mandatory = $true)][string]$Uri)
        try {
            return (Invoke-WebRequest -Uri $Uri -UseBasicParsing -ErrorAction Stop).Content
        } catch {
            Write-Warning "Unable to download '$Uri': $($_.Exception.Message)"
            return $null
        }
    }
    #endregion

    # Get EntraOps Classification
    if (-not (Test-Path -Path $ClassificationFilePath)) {
        throw "Classification file '$ClassificationFilePath' not found."
    }
    $Classification = Get-Content -Path $ClassificationFilePath | ConvertFrom-Json -Depth 10

    # Build base URI for the include pages (same folder as the reference markdown + /includes/)
    $BaseUri = $PermissionsReferenceUri.Substring(0, $PermissionsReferenceUri.LastIndexOf("/"))
    $IncludesBaseUri = "$BaseUri/includes"

    Write-Output "Downloading permissions reference markdown from $PermissionsReferenceUri"
    $ReferenceMarkdown = Get-RawWebContent -Uri $PermissionsReferenceUri
    if ([string]::IsNullOrEmpty($ReferenceMarkdown)) {
        throw "Unable to download the permissions reference markdown."
    }
    $ReferenceLines = $ReferenceMarkdown -split "`r?`n"

    #region Parse the "All roles" table to map role name, template ID and privileged flag
    Write-Output "Parsing the 'All roles' table for role template IDs and privileged labels"
    $RoleTableRegex = '^\s*>?\s*\|\s*\[(?<name>[^\]]+)\]\(#(?<anchor>[^\)]+)\)\s*\|\s*(?<desc>.*?)\s*\|\s*(?<id>[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})\s*\|\s*$'
    $RolesFromTable = @{}
    foreach ($Line in $ReferenceLines) {
        $Match = [regex]::Match($Line, $RoleTableRegex)
        if ($Match.Success) {
            $Anchor = $Match.Groups['anchor'].Value.Trim()
            $RolesFromTable[$Anchor] = [PSCustomObject]@{
                RoleName     = ($Match.Groups['name'].Value -replace '\s+', ' ').Trim()
                RoleId       = $Match.Groups['id'].Value.Trim()
                Anchor       = $Anchor
                isPrivileged = ($Match.Groups['desc'].Value -match 'Privileged label|privileged-roles-permissions')
            }
        }
    }
    Write-Output "Found $($RolesFromTable.Count) roles in the 'All roles' table"
    #endregion

    #region Parse INCLUDE references to map roles to their include pages
    # Example: [!INCLUDE [entra-backup-administrator](includes/entra-backup-administrator.md)]
    $IncludeRegex = '\[!INCLUDE\s*\[[^\]]+\]\(includes/(?<file>[^\)]+\.md)\)\]'
    $IncludeFiles = New-Object System.Collections.Generic.List[string]
    foreach ($Match in [regex]::Matches($ReferenceMarkdown, $IncludeRegex)) {
        $FileName = $Match.Groups['file'].Value.Trim()
        if (-not $IncludeFiles.Contains($FileName)) {
            $IncludeFiles.Add($FileName) | Out-Null
        }
    }
    Write-Output "Found $($IncludeFiles.Count) include pages referenced in the markdown"
    #endregion

    $DirectoryRoles = New-Object System.Collections.Generic.List[object]

    foreach ($IncludeFile in $IncludeFiles) {

        $Anchor = [System.IO.Path]::GetFileNameWithoutExtension($IncludeFile)

        # Only process roles that are listed with a template ID in the "All roles" table (built-in roles)
        if (-not $RolesFromTable.ContainsKey($Anchor)) {
            Write-Verbose "Skipping include page '$IncludeFile' because it has no template ID in the 'All roles' table"
            continue
        }

        $RoleMetadata = $RolesFromTable[$Anchor]
        $IncludeUri = "$IncludesBaseUri/$IncludeFile"
        Write-Output "Processing role '$($RoleMetadata.RoleName)' ($IncludeFile)"

        $IncludeContent = Get-RawWebContent -Uri $IncludeUri
        if ([string]::IsNullOrEmpty($IncludeContent)) {
            Write-Warning "Skipping role '$($RoleMetadata.RoleName)' because the include page could not be downloaded"
            continue
        }
        $IncludeLines = $IncludeContent -split "`r?`n"

        #region Extract the description (text below the metadata header, before the autogenerated content)
        $FrontmatterDelimiters = 0
        $DescriptionLines = New-Object System.Collections.Generic.List[string]
        foreach ($IncludeLine in $IncludeLines) {
            $Trimmed = $IncludeLine.Trim()

            # Skip the YAML frontmatter delimited by ---
            if ($FrontmatterDelimiters -lt 2) {
                if ($Trimmed -eq '---') { $FrontmatterDelimiters++ }
                continue
            }

            # Stop when the autogenerated actions table starts
            if ($Trimmed -match 'autogenerated content starts here' -or $Trimmed -match '^>?\s*\[!div' -or $Trimmed -match '^>?\s*\|\s*Actions\s*\|') {
                break
            }

            $DescriptionLines.Add($IncludeLine) | Out-Null
        }
        $RichDescription = ($DescriptionLines -join "`n").Trim()
        #endregion

        #region Extract the role actions from the include page table
        $RolePermissionActions = New-Object System.Collections.Generic.List[string]
        foreach ($IncludeLine in $IncludeLines) {
            # Normalize blockquote prefix
            $TableLine = ($IncludeLine -replace '^\s*>\s?', '').Trim()
            if (-not $TableLine.StartsWith('|')) { continue }

            $Cells = $TableLine.Trim('|').Split('|')
            if ($Cells.Count -lt 1) { continue }
            $Action = $Cells[0].Trim()

            # Skip header and separator rows and anything that is not an actual action
            if ($Action -eq '' -or $Action -eq 'Actions' -or $Action -match '^[-: ]+$') { continue }
            if ($Action -notmatch '^[a-zA-Z0-9]+\.[a-zA-Z]') { continue }

            if (-not $RolePermissionActions.Contains($Action)) {
                $RolePermissionActions.Add($Action) | Out-Null
            }
        }
        #endregion

        #region Classify the role actions (same logic as Export-EntraOpsClassificationDirectoryRoles.ps1)
        $ClassifiedDirectoryRolePermissions = New-Object System.Collections.ArrayList
        foreach ($RolePermission in $RolePermissionActions) {
            $EntraRolePermissionTierLevelClassification = $Classification | Where-Object { $_.TierLevelDefinition.RoleDefinitionActions -contains $($RolePermission) } | Select-Object EAMTierLevelName, EAMTierLevelTagValue
            $EntraRolePermissionServiceClassification = $Classification | Select-Object -ExpandProperty TierLevelDefinition | Where-Object { $_.RoleDefinitionActions -contains $($RolePermission) } | Select-Object Service

            if ($EntraRolePermissionTierLevelClassification.Count -gt 1 -and $EntraRolePermissionServiceClassification.Count -gt 1) {
                Write-Warning "Multiple Tier Level Classification found for $($RolePermission)"
            }

            if ($null -eq $EntraRolePermissionTierLevelClassification) {
                $EntraRolePermissionTierLevelClassification = [PSCustomObject]@{
                    "EAMTierLevelName"     = "Unclassified"
                    "EAMTierLevelTagValue" = "Unclassified"
                }
            }

            if ($null -eq $EntraRolePermissionServiceClassification) {
                $EntraRolePermissionServiceClassification = [PSCustomObject]@{
                    "Service" = "Unclassified"
                }
            }

            $ClassifiedDirectoryRolePermission = (
                [PSCustomObject]@{
                    "AuthorizedResourceAction" = $RolePermission
                    "Category"                 = $EntraRolePermissionServiceClassification.Service
                    "EAMTierLevelName"         = $EntraRolePermissionTierLevelClassification.EAMTierLevelName
                    "EAMTierLevelTagValue"     = $EntraRolePermissionTierLevelClassification.EAMTierLevelTagValue
                }
            )
            $ClassifiedDirectoryRolePermissions.Add($ClassifiedDirectoryRolePermission) | Out-Null
        }
        $ClassifiedDirectoryRolePermissions = $ClassifiedDirectoryRolePermissions | Sort-Object EAMTierLevelTagValue, Category, AuthorizedResourceAction

        if ($SingleClassification -eq $True) {
            $RoleDefinitionClassification = ($ClassifiedDirectoryRolePermissions | Select-Object -ExcludeProperty AuthorizedResourceAction, Category -Unique | Sort-Object EAMTierLevelTagValue | Select-Object -First 1)
        } else {
            $FilteredRoleClassifications = ($ClassifiedDirectoryRolePermissions | Select-Object -ExcludeProperty AuthorizedResourceAction -Unique | Sort-Object EAMTierLevelTagValue, Category)
            $RoleDefinitionClassification = [System.Collections.Generic.List[object]]::new()
            $RoleDefinitionClassification.Add($FilteredRoleClassifications)
        }

        if ($RoleDefinitionOverwrites.ContainsKey([string]$RoleMetadata.RoleId)) {
            $RoleDefinitionClassification = $RoleDefinitionOverwrites[[string]$RoleMetadata.RoleId]
        }

        if ($null -eq $RoleDefinitionClassification) {
            $RoleDefinitionClassification = [PSCustomObject]@{
                "EAMTierLevelName"     = "Unclassified"
                "EAMTierLevelTagValue" = "Unclassified"
            }
        }
        #endregion

        # Derive the role categories from the distinct service classifications of the role actions.
        # Match the Microsoft Graph representation: a scalar string with multiple values comma-delimited.
        $Categories = @($ClassifiedDirectoryRolePermissions | Select-Object -ExpandProperty Category -Unique | Where-Object { $_ -ne "Unclassified" } | Sort-Object)
        if ($Categories.Count -eq 0) {
            $Categories = "Unclassified"
        } else {
            $Categories = $Categories -join ','
        }

        $DirectoryRoles.Add(
            [PSCustomObject]@{
                "RoleId"                  = $RoleMetadata.RoleId
                "RoleName"                = $RoleMetadata.RoleName
                "isPrivileged"            = $RoleMetadata.isPrivileged
                "AssignmentMode"          = $null
                "InheritsPermissionsFrom" = $null
                "Categories"              = $Categories
                "RichDescription"         = $RichDescription
                "RolePermissions"         = @($ClassifiedDirectoryRolePermissions)
                "Classification"          = $RoleDefinitionClassification
            }
        ) | Out-Null
    }

    $DirectoryRoles = $DirectoryRoles | Sort-Object RoleName, RoleId

    $OutputDirectory = Split-Path -Path $OutputFilePath -Parent
    if (-not [string]::IsNullOrEmpty($OutputDirectory) -and -not (Test-Path -Path $OutputDirectory)) {
        New-Item -Path $OutputDirectory -ItemType Directory -Force | Out-Null
    }

    Write-Output "Exporting $($DirectoryRoles.Count) classified directory roles to $OutputFilePath"
    $DirectoryRoles | ConvertTo-Json -Depth 10 | Out-File $OutputFilePath -Force
}
