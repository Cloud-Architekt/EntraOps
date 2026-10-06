# EntraOps Privileged Assets

Object-centric view of privileged users, groups, service principals and applications from the
EntraOps Privileged EAM export. The static web app works offline from `file://`; no web server or
backend is required.

## Generate the dataset

```powershell
Import-Module ./EntraOps -Force
New-EntraOpsPrivilegedAssetsData
```

The generator reads `PrivilegedEAM/<RbacSystem>/<RbacSystem>.json`, merges each object across RBAC
systems and writes `data/privileged-assets-data.js` (`window.ENTRAOPS_PRIVILEGED_ASSETS_DATA`).
Related object IDs outside the export are resolved through Microsoft Graph unless
`-ResolveRelatedObjectIds $false` or `PrivilegedAssets.ResolveRelatedObjectIds = false` is set. The
dataset also contains the Custom Security Attribute names and the current Object Classification File
entries from `EntraOpsConfig.json`.

## Views

### Overview (`index.html`)

| Section    | Content                                                                                                                                                  |
| ---------- | -------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Metrics    | Object count per tier, tier breaches by object tier, relationship findings and worklist changes. Tiles filter the inventory or open the worklist.        |
| Inventory  | Objects with type, sub type, object tier, assignment tier summary, relationships, administrative units and findings. Filterable and sortable, CSV export. Selected objects can be added to the worklist with a target tier. |
| Side panel | Identity, classification, findings, related objects with their tier, and all role assignments with links to the EAM Dashboard and Access Path Map.       |

Deep link to an object: `index.html#asset=<objectId>`.

### Object Classification (`index.html?view=classification`)

| Section           | Content                                                                                                                                                                                |
| ----------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Worklist          | Objects with their current tier, the role assignments with the highest classification (linked to the EAM Dashboard), an editable target tier and justification, and their change status. Add objects by name or object ID and import/export CSV or JSON. With the Object Classification File enabled, the worklist starts from the repository file and can be downloaded as the file or reset to it. |
| PowerShell Script | Only with Custom Security Attributes enabled (`CustomSecurityAttributes.Enabled`): generates a script that sets both tier custom security attributes for users, service principals and applications in the worklist. Custom security attributes win over the other classification sources. |

## Findings

| Finding                             | Condition                                                                                            |
| ----------------------------------- | ---------------------------------------------------------------------------------------------------- |
| Object tier below role assignments  | The object tier is less privileged than its most privileged role assignment classification.         |
| Unclassified object                 | No object tier is defined.                                                                           |
| Owner with lower tier               | An owner is less privileged than the object (owners not in the export count as User Access).         |
| Owns higher-tier object             | The object owns a privileged object with a more privileged tier.                                     |
| Identity parent with lower tier     | The agent identity blueprint or agent identity parent is less privileged than the object.            |
| No sponsor                          | Agent identity or agent user without a sponsor (not applied to regular users).                       |
| Owns non-PAW devices                | Control or Management Plane user owning devices that aren't its associated PAW device.               |
| No associated PAW                   | Control Plane user without an associated PAW device.                                                 |
| No associated work account          | Control or Management Plane member user without an associated work account.                          |
| Synchronized Control Plane identity | Control Plane object synchronized from Active Directory.                                             |
| Restricted management not applied   | Control or Management Plane user or group without restricted management (or with a conflict).        |
| Outside home tenant                 | Object from another tenant.                                                                          |

The tier used for the relationship findings is the more privileged of the object tier and its role
assignment tier. With *What-if*, the worklist target tiers are used instead of the current object
tiers.

## Object Classification File and script

The view follows the enabled classification sources: the file download with
`ObjectClassificationFile.Enabled`, the script with `CustomSecurityAttributes.Enabled`, or both. The
worklist is stored in the browser's local storage. Download the Object Classification File and
commit it to the path configured in `ObjectClassificationFile.FilePath` to apply it with the next
Privileged EAM pull; a file entry only applies to objects that custom security attributes and
Alternate Tier Level Attributes don't classify. Apply custom security attribute
tiers with the generated script.

The generated PowerShell script is never executed by the app. It uses `Invoke-MgGraphRequest`,
checks that the configured attributes are single-valued attributes (tier level as Integer or String, tier name as String), shows the current values,
and supports `-WhatIf`. It requires the delegated permissions
`CustomSecAttributeAssignment.ReadWrite.All` and `CustomSecAttributeDefinition.Read.All`,
and the Microsoft Entra role Attribute Assignment Administrator. Only validated object IDs, tier
names and sanitized display names are embedded in the script. Objects of another tenant are not
included because their custom security attributes can't be modified from the home tenant; the view
lists them in a warning above the script.
