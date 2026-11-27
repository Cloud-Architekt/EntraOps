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

### Maester findings

`-MaesterTestResultPath` points to the Maester test results: a `TestResults-<yyyy-MM-dd-HHmmss>.json`
file, the same path without `.json`, or a folder (the latest `TestResults-*.json` is used). The
parameter is optional: without it, or when no result file is found, the Maester integration is skipped.

```powershell
New-EntraOpsPrivilegedAssetsData -MaesterTestResultPath ~/maester/test-results
```

The generator reads the failed tests (`Tests`) and their affected objects (`AffectedObjects`, or
`AssetInventory` in older Maester versions) and matches them to privileged objects by object ID, app
ID (app registrations) or user principal name. Failed Maester tests count as findings of the object
(with the same severity scale) and are listed in its side panel; a test opens a blade with the test
description, result, affected object, tags and the other privileged objects with the same finding. The
Findings filter and the metrics tile select objects with Maester findings.

## Views

### Overview (`index.html`)

| Section    | Content                                                                                                                                                                                                                     |
| ---------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Metrics    | Object count per tier (Unclassified included), objects with findings counted once by their most severe finding (EntraOps checks and Maester tests, Low, Info and Maester tests without a known severity included), objects with Maester findings and worklist changes; a tooltip on each tile says what it counts. Tiles filter the inventory or open the worklist; tier breaches and relationship findings are selected with the Findings filter.                                                                                                              |
| Inventory  | Objects with type, sub type, object tier, assignment tier summary, relationships, administrative units and findings (highest severity, count and the most severe finding; on phones under the object name). Search by name, UPN, app ID, object ID, rule ID or finding; pills filter by object type, sub type and classification with live counts; the Findings filter selects findings by check (grouped by category), by severity or by Maester test; **More filters** has the assignment tier, administrative unit, restricted management, sync source and worklist filters. Sortable, CSV export. Selected objects can be added to the worklist with a target tier. |
| Side panel | Identity, classification, findings grouped by category with their results and a link to the report that shows them, related objects with their tier, and all role assignments with links to the EAM Dashboard and Access Path Map.                                                                                                                              |

Deep link to an object: `index.html#asset=<objectId>`. The side panels are modal dialogs (focus moves into the
panel, Escape closes it and returns the focus); Back closes them and restores the previous view and panel.

### Findings (`index.html?view=findings`)

The results of all EntraOps checks, with remediation action, effort and user impact for each finding: tiles and a bar with the number of failed,
error, passed, skipped and excluded checks (failed checks by severity), filters by status, severity and
category, and search by check, rule ID, Maester test ID or affected object. The checks are grouped by
category (catalog title and order) with their status, severity, affected objects (the number of objects, and
below it the number of results when an object has several - for example one per role assignment - and the
evaluated instances) and source; the source column is hidden below 1280 px. The *Failed* tile counts checks by
the severity of the check, not affected objects.
A category collapses to its status summary by its title (*Collapse all* / *Expand all* for all listed
categories); the browser remembers collapsed categories. Checks without a result (*Error*: the evaluation failed, *Skipped*, *Excluded* or deprecated) show their
reason under the title; skipped checks with nothing in scope say *Not applicable*, skipped checks without
their data *Data missing* (`ReasonCode` of the saved result). A note of an evaluated check (its `Reason`, for
example excluded groups that could not be resolved) shows under its title and in its panel. A check opens a
panel with the affected objects, results and evaluated instances, its description, remediation, implementation
effort and user impact, resources (Microsoft Learn, Microsoft Graph and EntraOps documentation of the rule),
settings, the reason when it was not evaluated, links to the source report and the Maester test, and the
affected objects: one row per object with its tier (the tier name of the result for objects outside the
inventory); an object with several results shows their number (for example *18 role assignments*) and the
first message and expands to the results. Each result has its details and the evidence of the evaluation
(*Evidence*: readable labels, tier names, durations such as *8 hours*, dates, lists of objects as a table and
object IDs with their name; fields that repeat others are left out and internal IDs and hashes are under
*Technical details*). The search of the panel filters the results. Objects of the inventory open their side
panel. Checks that
don't report unclassified objects (`EO.1003`) show their number as *+N unclassified* and in an info bar of
the panel, which lists them on request (*Show unclassified objects in the list*). Each affected
object links to the report that shows it, opened at that object: the PIM role setting in PIM Request Flow,
the assignment policy in Access Package Flow, the policy in Conditional Access Analysis, the tier breach path
in Tier Breach Analyzer, the role assignment and object in the EAM Dashboard, the object in the Access Path
Map and the Tenant Governance resource in Configuration Analyzer (`#object=`). The side panel of an object
links each of its findings to the check (*All affected objects*; Back returns to the object) and each result
to its source report. Deep link to a check:
`index.html?view=findings#rule=<RuleId>` (`#rule=` alone also opens the Findings view; the rule ID is matched
in any casing, and an unknown check is reported also when no check is loaded).

**Finding exceptions** dismiss a finding (false positive) or accept its risk until a date. *Accept…* at an
affected object in the panel of a check adds one, for this finding or for all findings of the check for the
object, with state, expiry date (required for an accepted risk, at most `Findings.ExceptionMaxDays`; optional
and empty for a dismissed finding), justification, accepted by and reference. Several findings get exceptions
at once: select them (*Select*, *Select all* of an object or *Select all shown*) and use *Accept selected…*,
which adds one exception per finding or one per object. The panel shows the exception that applies like the
evaluation picks it: of the finding, else of the object, the first that has not expired. *Finding exceptions* below the checks lists the exceptions of the Finding Exceptions File
(`Findings.ExceptionsFilePath`) with their status (*Active*, *Expired*, *No finding*, *Not evaluated*) and
the changes of this browser (*Added*, *Changed*, *Removed*), which are kept in localStorage until the next
evaluation brings them in the file: when the page loads, changes the file already has are dropped. When the
file changed since the pending changes were made (for example an exception a teammate renewed), a notice asks
to keep or discard them, so an export doesn't undo the changes of the file. Imported files are checked like
`Read-EntraOpsFindingExceptionFile`: impossible dates are rejected, an accepted risk longer than
`Findings.ExceptionMaxDays` is shortened (with a note), and values are kept as they are. *Export FindingExceptions.json* downloads the file to save at the path
of the setting (commit it, or keep it in a local EntraOps folder), *Import JSON* adds the exceptions of a
file, and *Discard local changes* returns to the file. Accepted findings are not counted: the check shows
*+N risk accepted* and *+N dismissed* and lists them on request (*Show accepted findings in the list*). A check
that passes only because risks are accepted is marked *Risk accepted*: its control is not met, and the EntraOps
Maester Pack skips its test with the accepted risks. The *Exceptions* tile
counts the active (with those expiring within 30 days), expired, no longer matching (*without finding*) and
pending exceptions. Managing exceptions needs the saved
results (`findings.js`), which name the exceptions of the file.

The view shows the saved results (`../Findings/data/findings.js`). Without them, it shows the Privileged
Assets checks of the data file, and for data files without findings the Privileged Assets checks evaluated
in the browser. Without any result it shows the command to run (`New-EntraOpsReportingData`, or
`Invoke-EntraOpsAssessment` for a first run).

### Object Classification (`index.html?view=classification`)

| Section           | Content                                                                                                                                                                                                                                                                                                                                                                                              |
| ----------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Worklist          | Objects with their current tier, the role assignments with the highest classification (linked to the EAM Dashboard), an editable target tier and justification, and their change status. Add objects by name or object ID and import/export CSV or JSON. With the Object Classification File enabled, the worklist starts from the repository file and can be downloaded as the file or reset to it. |
| PowerShell Script | Only with Custom Security Attributes enabled (`CustomSecurityAttributes.Enabled`): generates a script that sets both tier custom security attributes for users, service principals and applications in the worklist. Custom security attributes win over the other classification sources.                                                                                                           |

## Findings

| Finding                             | Condition                                                                                     |
| ----------------------------------- | --------------------------------------------------------------------------------------------- |
| Object tier below role assignments  | The object tier is less privileged than its most privileged role assignment classification.   |
| Unclassified object                 | No object tier is defined.                                                                    |
| Owner with lower tier               | An owner is less privileged than the object (owners not in the export count as User Access).  |
| Owns higher-tier object             | The object owns a privileged object with a more privileged tier.                              |
| Identity parent with lower tier     | The agent identity blueprint or agent identity parent is less privileged than the object (parents not in the export count as User Access). |
| No sponsor                          | Agent identity or agent user without a sponsor (not applied to regular users).                |
| Owns non-PAW devices                | Control or Management Plane user owning devices that aren't its associated PAW device.        |
| No associated PAW                   | Control Plane user without an associated PAW device.                                          |
| No associated work account          | Control or Management Plane member user without an associated work account.                   |
| Synchronized Control Plane identity | Control Plane object synchronized from Active Directory.                                      |
| Restricted management not applied   | Control or Management Plane user or group without restricted management (a role-assignable group in a restricted management administrative unit, shown as *Conflict*, is protected by the group). |
| Role assignment of a principal managed by another tenant | One result per role assignment (Control Plane first) of a guest or external user, a user or group of cross-tenant synchronization, a service principal of a multi-tenant application of another organization (not of Microsoft), or an object of another tenant with access through Tenant Governance (for example a remote group). |

The tier used for the relationship findings is the more privileged of the object tier and its role
assignment tier. With *What-if*, the worklist target tiers are used instead of the current object
tiers.

The findings are EntraOps finding rules (`Get-EntraOpsFindingRule -Area PrivilegedAssets`).
`New-EntraOpsPrivilegedAssetsData` evaluates them in PowerShell and embeds the results; the report
evaluates them in the browser only for *What-if* (`js/findings.js`) and for data generated without
findings. `Invoke-EntraOpsFindingEvaluation` returns the same results outside the report, for example
for the [EntraOps Maester Pack](../../Integrations/Maester/README.md).

With the saved results loaded, the inventory and the side panel show the saved Privileged Assets results
outside *What-if* - accepted findings are left out, and the side panel shows their messages and related
objects - instead of the findings block of the data file. The CSV export names the tiers (*Control Plane*) and
the most severe finding of the EntraOps checks and Maester tests.

The inventory also shows the findings of the other EntraOps finding rules that concern its objects:
Privileged EAM (for example permanent Control Plane assignments, owners of privileged objects, nested
groups), Tier Breach Analyzer paths, new Control Plane access of the Privilege History and the access
drift of access package resources. They are matched by object ID from `../Findings/data/findings.js`,
which `Save-EntraOpsFindingJson` writes with `findings.json` (`New-EntraOpsReportingData` saves both
with the report data). These findings show the saved evaluation: *What-if* re-evaluates only the
Privileged Assets findings above. Findings of roles, access packages, policies or the tenant are
counted in a notice and shown by the PIM Request Flow, Access Package Flow and Configuration Analyzer
reports. Saved findings of another tenant are not shown.

## Object Classification File and script

The view follows the enabled classification sources: the file download with
`ObjectClassificationFile.Enabled`, the script with `CustomSecurityAttributes.Enabled`, or both. The
worklist is stored in the browser's local storage as changes (additions, edits and removals) on top of
the repository file. When the repository file changed since these changes were saved (for example by
another operator or `Update-EntraOpsServiceEMObjectClassificationFile`), the view applies the local
changes to the current file entries and shows a notice with *Reset to repository file*. Download the Object Classification File and
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
