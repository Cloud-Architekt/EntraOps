# Reportings

The static EntraOps Reporting apps, Microsoft Sentinel/Unified SecOps Platform integration, and the
BloodHound OpenGraph integration for attack path management.

## Reporting apps {#entraops-reporting-apps}

EntraOps ships a small portal of **static, self-contained web apps** (`Reports/`) to explore
classification data, analyze tier boundary violations and review privileged identities - no
backend, database or web server required; each app embeds its generated data as a JavaScript
bundle and works offline from `file://`. Open [Reports/index.html](../../Reports/index.html) as
the landing page, which links to all apps and their cross-navigation.

![EntraOps reporting portal with links to the reporting apps](../assets/reporting/reporting-portal.png)

Generate or refresh the data for all apps in one call:

```powershell
Import-Module ./EntraOps -Force
New-EntraOpsReportingData
```

> [!NOTE]
> Most apps are built from a Privileged EAM export in `PrivilegedEAM/`. Create it first with
> `Save-EntraOpsPrivilegedEAMJson -RbacSystems @("EntraID", "Azure")` (accepted values: `Azure`, `EntraID`,
> `IdentityGovernance`, `DeviceManagement`, `ResourceApps`, `Defender`) or `Invoke-EntraOpsPrivilegedEAM`.
> `New-EntraOpsReportingData` prints the generated data files and the path of `Reports/index.html` to open.

The generators write into the `Reports` folder of the EntraOps working folder (the repository
checkout, or the folder described in
[Working folder](../get-started/index.html#working-folder)).
If the reporting apps are missing (module-only installation), `New-EntraOpsReportingData` stops with
an error. Install them first with `Initialize-EntraOpsWorkspace` or
`Install-EntraOpsReportingFolder`, or pass `New-EntraOpsReportingData -InstallMissingReportingFolder`. They
install the apps of the module version: from the repository clone of the module, otherwise from the `main` branch
of the EntraOps repository (its head, the release tag or the newest commit whose `EntraOps.psd1` has the module
version). The repository is `AutomatedEntraOpsUpdate.Repository` of `EntraOpsConfig.json` (the release channel of
the deployment), otherwise the public `EntraOps` repository; `-Repository` selects another one. For a module newer
than `main` (Insiders or pre-release), pass `-Ref` with its branch or commit (and `-Repository EntraOps-Insiders`);
otherwise the apps of `main` are installed with a warning. The installed source and version are recorded in
`Reports/.EntraOpsContent.json`. Without
classification templates (e.g. after `Invoke-EntraOpsPrivilegedEAM` without
`-KeepClassificationFiles`), the Classification Explorer is skipped with a warning. Generated report data in an existing
`Reports` folder is never overwritten; updating an existing folder requires `-Force`.

An older or incomplete `Reports` folder can contain the portal but lack a newer app such as
Privileged Assets. Repair it with `Initialize-EntraOpsWorkspace -Content Reports -Force` or
`Install-EntraOpsReportingFolder -Force`. These installers
preserve existing generated report data. `-InstallMissingReportingFolder` also repairs missing apps
before generation starts.

Report generation resolves linked identities and related objects outside the export through
Microsoft Graph by default. Keep the connection active until reporting finishes.
`Invoke-EntraOpsPrivilegedEAM` disconnects during teardown, including with `-KeepClassificationFiles`,
so run `Connect-EntraOps` again before `New-EntraOpsReportingData` if you want this enrichment, or use
`Invoke-EntraOpsPrivilegedEAM -KeepConnection`. [`Invoke-EntraOpsAssessment`](../get-started/index.html#complete-assessment)
runs the collection, a Tenant Governance snapshot and the report generation in one session.
To generate from saved data without Graph lookups, use:

```powershell
New-EntraOpsReportingData `
  -EamDashboardResolveLinkedIdentityObjectIds $false `
  -PrivilegedAssetsResolveRelatedObjectIds $false `
  -AccessPathMapResolveObjectIdsOutsidePrivilegedEAM $false `
  -SkipAccessPackageFlow
```

Objects outside the export remain unresolved, and live Access Package Flow enrichment is skipped.
The generated apps can still be opened offline.

For configuration-driven automation on any CI platform, use the higher-level command:

```powershell
Import-Module ./EntraOps -Force
Invoke-EntraOpsReportingGeneration -ConfigFilePath ./EntraOpsConfig.json `
  -AuthenticationType AlreadyAuthenticated
```

It reads the `AutomatedReportingGeneration` settings, reuses one Graph connection for the selected
reports, applies the configured object-resolution and history options, and fails the automation run
when a selected generator fails. Checkout, workload-identity bootstrap, report testing, artifact
upload, and release publication remain responsibilities of the surrounding GitHub Actions, GitLab CI,
Azure Pipelines, or local runner. If no Tenant Governance snapshot manifest exists, Configuration
Analyzer is skipped with a warning, matching the shipped workflow behavior.

- `New-EntraOpsClassificationExplorerData` / `New-EntraOpsTierBreachAnalyzerData` / `New-EntraOpsPrivilegedEamDashboardData` / `New-EntraOpsPrivilegedAssetsData` / `New-EntraOpsPrivilegedEamPrivilegeHistoryData` / `New-EntraOpsAccessPathMapData` / `New-EntraOpsTenantGovernanceConfigurationAnalyzerData` generate the data bundle for the individual apps. `New-EntraOpsReportingData` is a convenience wrapper that runs them in one call and can also generate Access Package Flow enrichment. It forwards parameters such as `-ClassificationExplorerRepoRoot`, `-TierBreachImportPath`, `-EamDashboardImportPath`, `-AccessPathMapImportPath`, `-SkipClassificationExplorer`, `-SkipTierBreachAnalyzer`, `-SkipEamDashboard`, `-SkipPrivilegedAssets`, `-SkipPrivilegeHistory`, `-SkipAccessPathMap`, `-SkipConfigurationAnalyzer`, and `-SkipAccessPackageFlow`.
- `Remove-EntraOpsReportingData` deletes the generated data bundles again (`Remove-EntraOpsData` also removes the Privileged EAM export, tenant classification files, Tenant Governance snapshots and the cache) (`-WhatIf`, the same eight `-Skip*` switches, and `-PassThru` are supported). Run it before sharing or committing a checkout to remove tenant-specific reporting data.
- Reporting generation can be automated with the `AutomatedReportingGeneration` section in `EntraOpsConfig.json` (set with `New-EntraOpsConfigFile -ApplyAutomatedReportingGeneration`) and the `Push-EntraOpsPrivilegedReporting` GitHub workflow or the `entraops-push-reporting.yml` Azure DevOps pipeline. Both regenerate the selected apps and publish the `EntraOps-Reporting` artifact (30 days on GitHub) only in a private repository or project.
  - **Report tests (`RunGeneratedReportTests`, disabled by default):** when enabled, a separate job without the workload identity and without write access installs the npm packages (`npm ci --ignore-scripts`, no dependency cache) and Playwright and runs the offline browser smoke suite against the generated reports. Any request to a non-local URL fails the tests. The reports reach that job through a short-lived `EntraOps-Reporting-Untested` hand-over artifact. A separate publishing job, which never runs the npm packages, verifies the hand-over against the SHA-256 content digest recorded at generation and only then publishes `EntraOps-Reporting`. A failing test fails the run and produces neither the artifact nor a release. GitHub deletes the hand-over artifact at the end of every run; Azure DevOps cannot delete pipeline artifacts, so it stays with the run. On Azure DevOps the npm steps also run with restricted logging commands. The setting is disabled by default. A manual run can override it with the `runGeneratedReportTests` input (GitHub) or parameter (Azure DevOps).
  - **Test diagnostics (`UploadReportTestDiagnostics`, disabled by default):** uploads the Playwright traces of failed report tests as the 1-day `EntraOps-Reporting-TestDiagnostics` artifact (Azure DevOps keeps it with the run). Traces contain tenant report data.
  - **GitHub Releases (`PublishReportsAsRelease`, GitHub only, disabled by default):** additionally stores the verified `EntraOps-Reporting` bundle as a private-repository release, after the tests pass when they are enabled. Only the release job gets `contents: write`. `ReportingReleasesToKeep` limits retained `reporting-*` releases because each release contains a full tenant-data snapshot. Azure DevOps publishes the pipeline artifact only and ignores both settings.
  - Each run reports whether the published artifact was tested: in the GitHub job summary, and as the `reports-tested`, `reports-untested` or `reports-test-failed` build tag in Azure DevOps.
  - Both pipelines read `RunGeneratedReportTests`, `UploadReportTestDiagnostics` and `PublishReportsAsRelease` from `EntraOpsConfig.json` at runtime; changing them does not require re-running `Update-EntraOpsRequiredWorkflowParameters`.

### History source {#history-source}

Privilege History and Configuration Analyzer build their history from the git commits of the Privileged EAM
export and of the Tenant Governance snapshots. `-HistorySource` of `New-EntraOpsReportingData`,
`New-EntraOpsPrivilegedEamPrivilegeHistoryData` and `New-EntraOpsTenantGovernanceConfigurationAnalyzerData`
selects the source:

| Value            | Behavior                                                                                                                                                                                  |
| ---------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `Auto` (default) | The git history when the working folder is a git repository with git installed and the data has commits, otherwise the current folder (with a notice, not a warning).                     |
| `Git`            | The git history; stops with an error without git or repository.                                                                                                                           |
| `Folder`         | Only the current files: one snapshot from the export (dated by its newest file) and from the snapshot folder (dated by `CapturedDateTime` of its manifest), also inside a git repository. |

With git, an export or snapshot that differs from the newest commit (or was never committed) is added as the
newest snapshot, `(working tree)`, so the reports and the findings include data that is not committed yet.

Without git history, both reports show a single point in time: no trend, no comparison between snapshots and no
changes; the Privilege History findings (`EO.8001` to `EO.8003`) need two snapshots and are skipped. The data records
the source (`historySource`: `git` or `folder`). Content hashes are computed like git (`git hash-object`), so the
data of both sources has the same format. Commit the export and the snapshots, as the GitHub and Azure DevOps
pipelines do, to build up the history.

### Classification Explorer

[Reports/ClassificationExplorer](../../Reports/ClassificationExplorer/README.md) lets you browse
and understand the Enterprise Access Model classification of roles, role actions and permissions
across Microsoft Entra ID, Azure and Intune RBAC systems: an overview dashboard, roles, role
actions, API permissions, scope-aware tiering, role overwrites and a library of documented attack
paths (with an interactive, BloodHound-style graph). A **Template Comparison** view diffs the
repository's tenant classification against the upstream `Classification/Templates`, highlighting
reclassified role actions/scopes and access-level distribution changes. Entra ID roles are also
compared against the public Microsoft Learn role reference to flag documentation mismatches, and a
**Customize Overwrites** editor lets you build `Classification_RoleDefinitionOverwrites.json` /
`Classification_RoleActionOverwrites.json` / `Classification_ApiPermissionOverwrites.json`
interactively. It imports and exports several files at once, including tagged files such as
`Classification_RoleDefinitionOverwrites_PAW.json`, and shows the origin of every entry: *Base*
(base file) or the tag (tagged file), prefixed with *Custom* once the entry is added, edited or removed
in the editor. Export writes every entry back to its origin file; a new entry goes to the target file
chosen in the entry dialog. See
[Split overwrites into tagged files](../privileged-eam/index.html#split-overwrites-into-tagged-files).

The **Change History** view and its notifications are derived from a git log over the
classification sources. Because those sources live in the sparsely checked out
AzurePrivilegedIAM repository, generation is disabled by default. Set
`ClassificationExplorer.GenerateChangeHistory` in `EntraOpsConfig.json` to `true` (or run
`New-EntraOpsClassificationExplorerData -SkipHistory:$false`) to generate it. A missing setting or
configuration file also skips the history.

The reporting workflow uses this setting only to select checkout depth: a shallow checkout when
history is disabled, or the full git history when it is enabled. The cmdlet reads the configuration
itself, so an existing workflow continues to produce the configured result after an EntraOps module
update. Because workflow files are excluded from automated updates by default, refresh
`Push-EntraOpsPrivilegedReporting.yaml` manually to gain the shallow-checkout optimization in an
existing deployment.

![Classification Explorer overview showing role, action, API permission, and tier classification summaries](../assets/reporting/classification-explorer-overview.png)

### EAM Dashboard

[Reports/EamDashboard](../../Reports/EamDashboard/README.md) is the static-web counterpart of the
*EntraOps Privileged EAM - Overview* Azure workbook, built entirely from your Privileged EAM
export - no Log Analytics workspace or Azure subscription required. It offers the same filters
(RBAC system, tier level, service, principal type, linked identity, privileged type - Tenant
Governance / Multi-Tenant Apps / B2B Collaboration / Local Identities - and free-text search),
cross-filterable sync-source, restricted-management, assignment-type and classification tiles, and
three drill-down grids (privileged assets, related role assignments, related role classification),
all with CSV export.

The dashboard's drill-down view keeps privileged assets, assignments, and their classification
evidence together for investigation and export.

**Change notifications** list privileged assets and role assignments that were added, removed, or
changed tier since the previous dataset. Local runs compare with the existing dataset. Generated
report data is never committed, so without one, the comparison uses the Privileged EAM export in
git history: the commit of the latest `reporting-*` release (`PublishReportsAsRelease`), otherwise
the export before its latest change. This needs the full git history, which the
`Push-EntraOpsPrivilegedReporting` workflow and the Azure DevOps pipeline already check out. The
first export, or an unreadable or other-tenant baseline, produces no notifications and never fails
the run.

![EAM Dashboard example showing privileged identity metrics and drill-down tables](../assets/examples/eam-dashboard.png)

### Privileged Assets {#privileged-assets}

[Reports/PrivilegedAssets](../../Reports/PrivilegedAssets/README.md) is an object-centric view of
privileged users, groups, service principals and applications (all object sub types, including
agent identities and guests), merged across RBAC systems. It has three views.

**Findings** (`index.html?view=findings`, a check opens with `#rule=<id>`) shows the results of all
EntraOps checks, grouped by category with their status, severity and affected objects and filtered by status,
severity and category. A panel per check shows its description, remediation action, effort and user impact,
resources, the reason when it wasn't evaluated, and all affected objects. Without saved results, it shows the Privileged Assets checks evaluated in the browser.
A category collapses to its status summary (*Collapse all* / *Expand all*). The view also maintains the
[finding exceptions](#finding-exceptions): *Accept* at an affected object dismisses the finding or accepts
its risk, and *Finding exceptions* exports the file to commit.

Each affected object links to the report that shows it, opened at that object:

| Affected object                  | Deep links                                                                                            |
| -------------------------------- | ----------------------------------------------------------------------------------------------------- |
| PIM role setting                 | PIM Request Flow (`#flow=` with the role and path), Configuration Analyzer (`#object=`)               |
| Access package assignment policy | Access Package Flow (`#flow=<policy ID>`), Configuration Analyzer (`#object=`)                        |
| Conditional Access policy        | Conditional Access Analysis (`#flow=<policy ID>`), Configuration Analyzer (`#object=`)                |
| Administrative unit              | Configuration Analyzer (`#object=`)                                                                   |
| Tier breach path                 | Tier Breach Analyzer (`#sel=`), EAM Dashboard (`#assignment=`, `#asset=`), Access Path Map (`#node=`) |
| Role assignment                  | EAM Dashboard (`#assignment=`, `#asset=`), Access Path Map (`#node=`)                                 |
| Privileged object                | EAM Dashboard (`#asset=`), Access Path Map (`#node=`)                                                 |
| Custom role                      | EAM Dashboard (`#assignment=` of its Control Plane assignments)                                       |

**Overview** shows metrics and the inventory with the object details that the assignment-centric
views don't show:

- **Relationships**: owners, sponsors, owned objects and devices, identity parent, associated work
  account and PAW device, each with its display name, type and tier. IDs outside the export are
  resolved through Microsoft Graph (`PrivilegedAssets.ResolveRelatedObjectIds`).
- **Tier**: the object tier next to a per-tier summary of its role assignment classification.
- **Findings**: the findings of every check that concerns the object, for example object tier below
  its role assignments, owners with a lower tier, non-PAW devices, missing sponsors or restricted
  management, Tier Breach Analyzer paths, new Control Plane access and access drift. The inventory
  shows their highest severity and count, the side panel all of them by category.
- **Filters**: search (including rule IDs and findings), pills for object type, sub type and
  classification with live counts, a Finding filter by rule, category, severity or Maester test, and
  more filters for the assignment tier, administrative unit, restricted management, sync source and
  worklist status.
- **Maester findings** (optional): `New-EntraOpsPrivilegedAssetsData -MaesterTestResultPath <file|folder>`
  (or `New-EntraOpsReportingData -PrivilegedAssetsMaesterTestResultPath`) reads the failed tests of a
  Maester `TestResults-*.json` and matches them to privileged objects by object ID, app ID or user
  principal name. They are counted with the other findings of the object. Without the parameter, or
  without a result file, the integration is skipped. See the
  [Privileged Assets README](../../Reports/PrivilegedAssets/README.md#maester-findings).

The side panel lists all role assignments of an object and links each assignment to the EAM
Dashboard (`#assignment=`), the object to the EAM Dashboard (`#asset=`) and to the Access Path Map
(`#node=`).

**Object Classification** (`index.html?view=classification`) maintains target tiers with the
enabled [classification sources](../core/index.html#classification-sources). The
worklist shows each object's current tier, the role assignments with the highest classification
(linked to the EAM Dashboard), an editable target tier and justification, and its change status.
Add objects by name or object ID, or select them in the Overview; import or export the list as CSV
or JSON. The *what-if* option in the Overview evaluates the findings with the target tiers. The
worklist is stored in the browser only.

When the [Object Classification File](../core/index.html#classify-by-object-classification-file)
is enabled, the worklist starts from the repository file and is downloaded as the file to commit it.
When Custom Security Attributes are enabled, the view generates a
reviewable PowerShell script for users, service principals and applications that sets both tier custom security attributes (names from
`CustomSecurityAttributes`) through Microsoft Graph. With both enabled, the view offers both:
custom security attributes win, file entries only apply to objects that the other sources don't
classify. The script checks the attribute definitions
first, supports `-WhatIf`, and needs `CustomSecAttributeAssignment.ReadWrite.All` and the
Attribute Assignment Administrator role. Groups are skipped because they don't support custom
security attributes, and objects of another tenant are skipped (and listed in a warning) because
their attributes can't be modified from the governed/managed tenant. When [Alternate Tier Level Attributes](../core/index.html#classify-by-alternate-tier-level-attributes)
are enabled for users or service principals, the view warns that the filters, not the script
values, determine the tier of these object types.

```powershell
Import-Module ./EntraOps -Force
New-EntraOpsPrivilegedAssetsData
```

### Access Path Map

[Reports/AccessPathMap](../../Reports/AccessPathMap/README.md) renders the OpenGraph model consumed
by the [BloodHound integration](#bloodhound-integration), plus Azure RBAC role and assignment data
synthesized from `PrivilegedEAM/Azure/Azure.json`, as an interactive, APM-style, force-directed
graph. It offers Tier 0 / all-tier-breach / full-graph views (matching the Tier Breach Analyzer's
tiering rules), a curated **known/documented attack path** filter
cross-referenced with the Classification Explorer's attack-path catalog, scope and
classification-provenance drill-down ("Other privileged objects sharing this scope", "Show full
context in graph"), a right-click context menu on graph nodes, bookmarkable node/edge selections
via URL hash, and a CSV-exportable attack path table.

Azure RBAC assignments are fully represented in Access Path Map as `EO_AzureRole` and
`EO_AzureRoleAssignment` nodes with active, eligible, assignment, ownership and scope-reasoning
edges. This Azure-specific synthesis is performed by `New-EntraOpsAccessPathMapData`; it is
additional to the payload produced by the standalone BloodHound exporter.

Object ids referenced only via ownership/sponsor/device edges (e.g. a regular work account that
owns a privileged group) are resolved by default through a batched live Microsoft Graph lookup.
This requires an active Graph connection when the data is generated (e.g. via
`Connect-EntraOps`/`Connect-MgGraph`). Resolution is best-effort: objects that Graph cannot return
remain explicit unresolved placeholders, and their graph edges are preserved. Set
`AccessPathMap.ResolveObjectIdsOutsidePrivilegedEAM` to `false` to disable the lookup. The generator
reports the lookup duration and recommends disabling it when resolution takes 30 seconds or longer.

![Access Path Map example showing an interactive privileged-access graph and path details](../assets/examples/access-path-map.png)

### Tier Breach Analyzer

[Reports/TierBreachAnalyzer](../../Reports/TierBreachAnalyzer/README.md) visualizes Enterprise
Access Model **tier boundary violations** from a Privileged EAM export
(`Save-EntraOpsPrivilegedEAMJson`) as a Sankey flow - `Object Tier -> Object -> Role -> Service ->
Service Tier`. It highlights Tier 0 breaches (a Tier 1/Tier 2 object reaching a Control Plane
service), and offers filterable views (Tier 0 breaches, all tier breaches, all assignment paths),
a detailed breach table with PIM/transitivity context, and CSV export for follow-up.

The detailed analysis view connects the selected tier-breach path to its underlying assignments
and classification context for follow-up.

![Tier Breach Analyzer example showing assignment paths and breach details](../assets/examples/tier-breach-analyzer.png)

### Privilege History

[Reports/PrivilegeHistory](../../Reports/PrivilegeHistory/README.md) shows historic trends of
privileged assets, role assignments and tier breaches over time, built entirely from the git
history of your Privileged EAM export - no separate time-series store required. Filter by RBAC
system, tier level and role, pick a time range, inspect any snapshot and compare two points in time
(or a point vs. today's live data via the EAM Dashboard).

Select a snapshot to review its tier totals and assignments, then compare it directly with today's
live data in the EAM Dashboard to identify changes requiring investigation.

![Privilege History snapshot detail showing tier totals and classified assignments](../assets/reporting/privilegehistory2.png)

The history view also summarizes how privileged identity and assignment counts change across the
selected time range.

![Privilege History example showing privileged identity and assignment trends over time](../assets/examples/privilege-history.png)

The reporting workflow is controlled by
`AutomatedReportingGeneration.GeneratePrivilegeHistory`. For direct calls to
`New-EntraOpsReportingData`, `PrivilegeHistory.EnablePrivilegeHistory` (default enabled) turns
generation on or off, `PrivilegeHistory.TimeRangeInDays` limits how far back into the git history
it samples (default: unlimited), and `PrivilegeHistory.SnapshotInterval` sets how often a snapshot
is sampled (default `P2W`, an ISO 8601 duration for every 2 weeks).

### Configuration Analyzer

[Reports/ConfigurationAnalyzer](../../Reports/ConfigurationAnalyzer/README.md) analyzes the
[Tenant Governance Snapshots](../tenant-governance/index.html#tenant-governance-snapshots) captured under
`TenantGovernance/Snapshots` - like Privilege History, it is built entirely from the **git
history** of your repository, so every committed snapshot becomes a point in time you can inspect
and compare:

![Configuration Analyzer example showing snapshot history and configuration changes](../assets/examples/configuration-analyzer.png)

- **Change timeline**: how many resources were added, modified or removed per snapshot, filterable
  by resource type. Click a snapshot to list every changed resource, and drill into a modified
  resource to see a property-level diff (old vs. new value).
- **Compare two snapshots**: pick any baseline and current snapshot (e.g. "before/after the
  change window last month") and get the same change list and property-level diffs between exactly
  those two points in time. Use this to validate an intended configuration deployment or investigate
  drift after an incident without maintaining a separate historical configuration store.
- **Snapshot Resource Explorer**: browse captured resources in expandable resource-type folders,
  search by name, category, or type, and move between matching resources without leaving the detail
  pane. The grouped property view presents nested collections as **Entries** and structured values
  as **Fields**, with controls to expand or collapse the complete property tree. `#object=<id>` (or
  `#object=<resource type>|<id>`) opens the resource with this `Id` in the newest detailed snapshot,
  for example from the links of the EntraOps findings.
- **Conditional Access Sankey**: visualizes how the tenant's Conditional Access policy set is
  configured as a flow of `Assignments → Policy → Target resources → Network → Conditions → Grant
  controls`. Every aspect can be filtered (policy state, included/excluded users, groups and roles,
  apps, platforms, client app types, named locations, risk levels, grant controls), columns can be
  toggled on and off, and clicking a node traces every policy path through it. Report-only and
  disabled policies are visually separated from enforced ones, so it is immediately visible which
  access paths end in **no enforced control**.
- **Coverage gap checks**: a built-in analysis of the Conditional Access policy set flags common
  gaps - policies stuck in report-only or disabled state, legacy authentication not blocked, no
  MFA policy covering all users or privileged roles, no sign-in/user-risk-based policy, no device
  compliance requirement, and the accumulated exclusion surface (groups/users excluded across
  policies) - to help identify access paths without Conditional Access coverage.
- **EIDSCA recommendations**: evaluates the curated [Entra ID Security Config Analyzer
  (EIDSCA)](https://github.com/Cloud-Architekt/AzureAD-Attack-Defense) controls supported by the
  snapshot's captured properties. Review the recommendations alongside your tenant requirements;
  they provide configuration guidance rather than an automatic compliance determination.
- **Privileged Assets**: identifies captured resources that explicitly target Control Plane,
  Management Plane, or User Access identities. Included Conditional Access and authentication
  method policy groups are expanded through nested, PIM-aware membership by default; exclusions
  are not evaluated. Disable this Graph-backed enrichment with
  `ConfigurationAnalyzer.ResolveGroupMembersForPrivilegedAssets: false` when generating the
  dataset offline.

![Configuration Analyzer privileged assets example with tier and resource filters](../assets/examples/configuration-privileged-assets.png)

The Snapshot Resource Explorer exposes the captured resource hierarchy and its property details
without requiring direct inspection of the underlying JSON files.

![Configuration Analyzer snapshot resource explorer with captured resource details](../assets/examples/configuration-snapshot-resources.png)

The reporting workflow accepts partially successful UTCM snapshots by default. Resource types whose
backing workload failed during the capture retain their last known data and are marked stale in the
manifest; types with per-resource export errors are published with the resources that did export
and keep the previous file of every resource the job did not return (`PublishedWithErrors`). Set
`ConfigurationAnalyzer.AllowPartialTenantGovernanceSnapshot: false` when the report must use only
a complete point-in-time snapshot. Every report that consumes Configuration Analyzer data displays
a permanent partial-snapshot warning with the capture time and the source snapshot for each stale
resource type, the retained-resource count of each type published with errors, plus the sanitized
capture diagnostics and remediation hints retained in the
manifest. Structural duplication or a manifest/file-count mismatch blocks report publication.

A snapshot older than `ConfigurationAnalyzer.MaxTenantGovernanceSnapshotAgeHours` is stale. When the
setting is not configured, the limit follows the snapshot schedule: 30 hours for a daily, 174 hours
for a weekly and 750 hours for a monthly `TenantGovernanceSnapshot.SnapshotScheduledCron`. The
reporting run checks the age before it connects to Microsoft Graph and applies
`ConfigurationAnalyzer.StaleTenantGovernanceSnapshotAction`: `Warn` (default) generates the reports
and shows an outdated-snapshot banner with the snapshot age, `Skip` publishes all other reports
without the Configuration Analyzer, and `Fail` stops the run. The dataset includes the snapshots of
the last `ConfigurationAnalyzer.TimeRangeInDays` (default 365) with at most one snapshot per
`ConfigurationAnalyzer.SnapshotInterval` (default `P1W`). A manual run of the reporting workflow or
pipeline can bypass the age check for that run with the `allowStaleTenantGovernance` input; scheduled
and pull-triggered runs always apply the configured action.

Generate or refresh the dataset with `New-EntraOpsTenantGovernanceConfigurationAnalyzerData` (or
as part of `New-EntraOpsReportingData`). The app requires the Tenant Governance Snapshot feature
to be enabled and at least one snapshot committed to the repository - see
[Tenant Governance](../tenant-governance/index.html#tenant-governance-snapshots).

### Configuration Analyzer companion reports

Four focused reports are available from the Configuration Analyzer tile in the reporting portal:

- [**Conditional Access Analysis**](../../Reports/ConditionalAccessAnalysis/README.md) presents the policy-flow Sankey, filters, and coverage-gap checks
  as a dedicated view.
- [**EIDSCA Findings**](../../Reports/EidscaCoverage/README.md) presents the supported Entra ID Security Config Analyzer recommendations
  from the same snapshot data.
- [**PIM Request Flow**](../../Reports/PimRequestFlow/README.md) visualizes PIM role settings and approval paths from the captured tenant
  configuration.
- [**Access Package Flow**](../../Reports/AccessPackageFlow/README.md) visualizes entitlement-management access-package policies, requestors,
  approvers, and resource targets. Its baseline view uses the snapshot dataset. Run
  `New-EntraOpsAccessPackageFlowData` (or leave Access Package Flow enabled in
  `New-EntraOpsReportingData`) to add live Microsoft Graph enrichment for current assignments,
  resource-role scopes, and group tier/member details.

The Conditional Access overview combines policy coverage findings with filters and summary counts;
the flow view then traces assignments through conditions and grant controls.

![Conditional Access Analysis overview showing coverage findings and policy summaries](../assets/examples/conditional-access-analysis-overview.png)

![Conditional Access Analysis flow details showing policy paths and grant controls](../assets/examples/conditional-access-analysis-flow.png)

EIDSCA Findings groups the supported checks by result and control area so failed or informational
findings can be reviewed with their captured evidence.

![EIDSCA Findings example showing checks grouped by result and control area](../assets/examples/eidsca-findings.png)

PIM Request Flow makes activation and assignment requirements visible from role through approval
and notification, while Access Package Flow traces requestors through policies to resource roles.

![PIM Request Flow example showing role activation requirements and approvals](../assets/examples/pim-request-flow.png)

![Access Package Flow example showing requestor, policy, package, and resource paths](../assets/examples/access-package-flow.png)

Conditional Access Analysis, EIDSCA Findings, and PIM Request Flow share the Configuration
Analyzer dataset. All four companion reports therefore require Tenant Governance snapshots; only
the optional Access Package Flow enrichment requires an active Microsoft Graph connection.

### Analyst workflow

The four companion reports show the dataset generation time and selected snapshot, a live count of
the currently filtered results, and **Reset filters** / **Export filtered** controls. Export creates
both CSV and JSON files locally; it never uploads tenant data. Finding rows support browser-local
review statuses (`Open`, `Reviewed: accepted`, and `Reviewed: remediated`) so analysts can triage a report without
changing its source snapshots or configured exclusions. They are saved in this browser only; to accept or
dismiss a finding for everyone, add a finding exception (see [Findings and Maester Pack](#findings)). PIM Request Flow and Access Package Flow
also link each concrete finding to its captured source resource in Configuration Analyzer.

When a flow node represents a resolved Entra object, Access Package Flow and Conditional Access
Analysis open the shared object-details panel. These selections are bookmarkable as
`#object=<object-id>` and restore the panel when the URL is opened. The panel combines available
Privileged EAM classification, role assignments, group relationships, API permissions, and related
flow context. Configuration resources continue to use Configuration Analyzer's
`#resource=<snapshot>|<path>` link; aggregate coverage checks deliberately remain evidence lists
rather than being presented as a link to one arbitrary object. EIDSCA Findings provides an
**Inspect source resource** action for each evaluated, resource-backed check; it opens the same
panel with the captured resource, evaluated value, and recommendation.

## Findings and Maester Pack {#findings}

The findings of Privileged Assets, Tier Breach Analyzer, PIM Request Flow and Access Package Flow are
EntraOps finding rules, evaluated in PowerShell. The reports show their results, and the same results
are available outside the reports, for example as Maester tests.

- `Get-EntraOpsFindingRule` lists the rules: a stable ID (`EO.<n>`), the key the report uses (for
  example `tierBreach`), the finding title of the reports, the check title that states the expected
  state (the title of the Maester test), description, remediation, severity and the Maester test ID
  (`MP.EOPS.<n>`). `Effort` and `UserImpact` rate the remediation as `Low`, `Medium` or `High`, each
  explained in one sentence (`EffortDescription`, `UserImpactDescription`), to plan and prioritize it.
  `References` lists the resources of the rule (Microsoft Learn, the Microsoft Graph reference and the
  EntraOps documentation), which the Findings view and the Maester test descriptions link.
- The rules are grouped in categories; the first digit of the rule ID is the category. IDs never
  change once released: a new rule gets the next number of its category.

  | ID        | Category                      | Checks                                                                                        |
  | --------- | ----------------------------- | --------------------------------------------------------------------------------------------- |
  | `EO.1xxx` | Tier boundaries               | Lower tiers that control objects, services or access of a more privileged tier                |
  | `EO.2xxx` | Classification                | Objects, role assignments and approvers without a tier; custom roles to review                |
  | `EO.3xxx` | Just-in-time access           | Standing access and the PIM settings of eligible assignments and activations                  |
  | `EO.4xxx` | Account protection            | Restricted management, cloud-only and member accounts, PAW, Conditional Access                |
  | `EO.5xxx` | Workload and agent identities | Service principals, applications and agents with privileged access                            |
  | `EO.6xxx` | Access governance             | Access packages: approval, requestor scope, expiration, access reviews and access drift       |
  | `EO.7xxx` | Ownership and delegation      | Owners of privileged objects, role assignment delegation, nested groups, administrative units |
  | `EO.8xxx` | Drift                         | Changes of privileged access between Privileged EAM snapshots                                 |

- `Invoke-EntraOpsFindingEvaluation` evaluates the rules and returns one result per rule (`Failed`,
  `Passed`, `Skipped`, `Excluded` or `Error`, with the reason for the last three) with the affected
  objects. `ReasonCode` classifies the reason (`NotApplicable`: nothing in scope, `MissingData`,
  `Unclassified`, `Excluded`, `Deprecated`, `Error`, or `Note` for a hint on a `Failed` or `Passed` rule,
  for example that all results exclude the same group). `Error` means the evaluation of the rule failed; deprecated rules are `Excluded`. Privileged
  Assets, Privileged EAM and Tier Breach rules read the Privileged EAM export. The PIM Request Flow,
  Access Package Flow, Tenant Governance and Privilege History rules read the generated report data, so
  run `New-EntraOpsReportingData` first; without it, they are skipped with the reason.
- `EO.1001` and `EO.1003` report one result per role assignment of an object, with the services it
  reaches (`Services` in the evidence); an assignment that reaches a Control Plane service is reported
  by `EO.1001` only. Delegated permissions are reported by `EO.5005` (the application acts within the
  rights of the signed-in user), and service principals of Microsoft first-party applications aren't
  reported. The Tier Breach Analyzer still flags every path that crosses a tier, including these.
- Delegated permissions are role assignments of their own tier, not access of the object: the
  application acts within the rights of the signed-in user. The checks of an object (`EO.1002`,
  `EO.1004`, `EO.1005`, `EO.1007`, `EO.5001`, `EO.5002`, `EO.5004`, `EO.7001`) compare the tier of its
  other role assignments (`assignmentSummary.highestAccessTierName` of the Privileged Assets data), and
  `EO.8001`/`EO.8002` leave delegated permissions out. They are reported as role assignments: `EO.5005`
  (Control Plane), `EO.2002` (without tier classification; the sign-in scopes `openid`, `profile`,
  `email`, `offline_access` and `user_impersonation` aren't reported) and `EO.8003` (new since the
  previous snapshot).
- Drift (`EO.8xxx`) compares the two newest snapshots of the Privilege History, and lists only what is
  new: `EO.8001` new Control Plane role assignments, `EO.8002` new tier breaches (counted like `EO.1001`
  and `EO.1003`: no delegated permissions, no Microsoft first-party applications, no PIM activations,
  unclassified objects apart; it fails on any new breach, also when the number of breaches stays the same) and `EO.8003` new
  delegated Control or Management Plane permissions (consents to review). The tier breach chart of the
  Privilege History still counts every assignment above the object tier. Privilege History data of
  versions before this one has no role types: regenerate it (`New-EntraOpsReportingData`), otherwise
  `EO.8003` is skipped.
- `EO.1003` (an object below Management Plane reaches a Management Plane service) doesn't report
  unclassified objects: their tier is unknown, so the check can't tell a tier breach from a missing
  classification. It counts them apart (`UnclassifiedCount`, `UnclassifiedResults`), and is `Skipped`
  when only unclassified objects are affected, with the reason to classify them (`EO.2001`). The
  Privileged Assets Findings view shows the number in the panel of the check and lists the unclassified
  objects on request (*Show unclassified objects in the list*).
- The `Findings` section of `EntraOpsConfig.json` (`New-EntraOpsConfigFile -Findings*` or the
  Configuration Wizard) configures the evaluation. The reports, `findings.json` and the Maester Pack use
  the same settings:

  | Setting                          | Default                                   | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
  | -------------------------------- | ----------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
  | `ExcludedRules`                  | none                                      | Rules to exclude, by ID (`EO.4008`) or `<Area>.<Key>` (`PrivilegedAssets.pawMissing`). They are returned as `Excluded`.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
  | `ControlPlaneActivationMaxHours` | `4`                                       | `EO.3013`: maximum activation duration of Control Plane roles.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
  | `EligibleAssignmentMaxDays`      | `365`                                     | `EO.3012`: maximum expiration of eligible assignments of Control and Management Plane roles.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
  | `EmergencyAccessAccounts`        | none                                      | `EO.4003`: object IDs, user principal names or group display names that Conditional Access policies may exclude. `EO.3001`, `EO.4008`, `EO.4009`: the accounts (object ID or user principal name, not display names or groups) that keep permanent Control Plane role assignments, have no associated PAW, or have no linked personal work account without a finding. When empty, nothing counts as emergency access: excluded Control Plane users are reported, and `EO.4003` names the users excluded from every enabled policy (with at least two enabled policies) in a note as candidates for the setting. When the failed policies mostly exclude the same identity, the result of `EO.4003` names it in a note. |
  | `ExceptionsFilePath`             | `./Classification/FindingExceptions.json` | The [Finding Exceptions File](#finding-exceptions), relative to the EntraOps folder.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
  | `ExceptionMaxDays`               | `180`                                     | Longest time a risk can be accepted, in days; `0` for no limit.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |

  `ConfigurationAnalyzer.PimRequestFlowExcludedRiskFlags` and `AccessPackageFlowExcludedRiskFlags` are
  deprecated aliases of `ExcludedRules`.

  The rules about principals of other tenants also read `ManagingTenantId` and `ManagingTenantName` from the root of
  `EntraOpsConfig.json`, the governing tenant of
  [Tenant Governance](../tenant-governance/index.html#cross-tenant-delegated-administration). Principals of this
  tenant are informational only: `EO.4002` (guests), `EO.4011` (members and groups) and `EO.5001` (applications)
  don't report them and name them in a note. `EO.4010` (Role assignment of a principal managed by another tenant)
  still lists their role assignments, named as the managing tenant and marked with `ManagingTenant` in the
  evidence. `ManagingTenantId` must be a tenant ID (GUID); the tenant name is
  only shown. Without it, no tenant is accepted.
- Service principals of Microsoft first-party applications are operated by Microsoft, so `EO.1001`,
  `EO.1003`, `EO.1006`, `EO.2001`, `EO.3003`, `EO.4010`, `EO.5001`, `EO.5004`, `EO.5005`, `EO.7001`,
  `EO.7003` and `EO.8002` don't report them. `EO.1002` and `EO.1004` do: the classification and the owners
  of these service principals are still managed by the tenant. The Privileged EAM export names the tenant of the application of a
  service principal (`OriginTenantId`, its `appOwnerOrganizationId`, EntraOps 1.2.0 or later); an application of a
  Microsoft tenant is first-party, and so are Microsoft Graph Command Line Tools and Graph Explorer.
  `EO.5005` still reports the delegated permissions of these two clients, Microsoft Intune PowerShell,
  SharePoint Online Web Client Extensibility, Microsoft Developer Sample Data Packs, Azure AD Assessment and M365 Lighthouse API:
  they exist only by consent of the tenant, which can revoke them. Older exports recognize only MS-PIM, the service of PIM for Azure
  resources, by its application ID.
- The approver checks (`EO.1008`, `EO.1009`, `EO.1010`) compare the classification of an approver, not
  the tier of its access: an approver with access above its classification isn't protected for that
  access. A group approver counts as its least protected member, and members without privileged access
  as User Access, because any member can approve. Management and Workload Plane are both Tier 1, like in
  the tier breach checks. An approval policy without a resolved approver isn't evaluated by `EO.1009` and
  `EO.1010`; the note of the rule counts them.
- `EO.4003` evaluates the members of excluded groups, which `New-EntraOpsReportingData` resolves when
  it generates the Configuration Analyzer data. Excluded groups without member data are named in the
  reason of the result instead of passing. Three or more policies whose only reported exclusion is the
  same user or group (typically the emergency access accounts) are one result for that user or group,
  with the policies in its evidence.
- `EO.3004` (permanent eligible assignments allowed) and `EO.3007` (activation without approval) ask for
  a review of their results instead of failing (severity Info). `EO.3007` evaluates Control Plane roles
  only: approval is not expected for every privileged role.
- `EO.3006` and `EO.3009` count an authentication context that a role requires on activation only when
  an enabled Conditional Access policy of the Tenant Governance snapshot targets it; report-only
  policies don't count. Whether that policy applies to every holder of the role isn't evaluated.
  Without Conditional Access policies in the snapshot the configured context counts, and the reason of
  the rule says so.
- `Save-EntraOpsFindingJson` writes the results to `Reports/Findings/data/findings.json` (and
  `findings.js`, from which Privileged Assets shows the findings of its objects).
  `New-EntraOpsReportingData` saves them after the report data (`-SkipFindings` turns it off), so the
  reporting pipelines publish them in the `EntraOps-Reporting` artifact (`Findings/data`). Like the other
  report data, the file is ignored by git and removed by `Remove-EntraOpsReportingData`.
- Data gaps: data that is missing in the evaluation, so that rules evaluate less than they seem to, are listed in
  `DataGaps` of `findings.json` (`Code`, `Message`, `Count` and the affected `RuleIds`; files of earlier versions have
  none), and the Findings view of Privileged Assets shows them in a box above the results:
  `GroupOriginUnknown` (groups whose origin is unknown, mostly because `Group-XTenantIdentitySync.Read.All` is
  missing, so a group synchronized from another tenant looks local), `RemoteGroupMembersMissing` (groups of other
  tenants with Control or Management Plane access whose members were not collected: without `ManagingTenantId`, the
  members of remote groups aren't read, and for groups of other tenants than the managing tenant they can't be read)
  `ObjectClassificationFileMissing` (`ObjectClassificationFile` is enabled, but the file doesn't exist),
  `ObjectTierCoverageLow` (at least half of the users and service principals of the tenant with Control or
  Management Plane access have no classification, so the tier rules mostly ask for a classification),
  `PawAssociationNotPopulated` and `WorkAccountNotPopulated` (no user of the tenant has an associated PAW or work
  account, so EO.4007/EO.4008 or EO.4009 report every privileged user), and the gaps of the Tenant Governance
  snapshot that the rules read: `TenantGovernanceSnapshotOutdated` (older than its maximum age),
  `TenantGovernanceResourceTypeStale` (a type that could not be captured and comes from an earlier snapshot) and
  `TenantGovernanceResourceTypeIncomplete` (a type exported with errors, for example a Conditional Access policy
  whose excluded group no longer exists). `EO.4010` and `EO.4011` also name the first two in their note. The Privileged EAM collection warns about remote groups whose
  members it didn't read and marks them in the export (`CrossTenantMembersExpanded`).
- `New-EntraOpsReportFindingData` writes the PIM Request Flow and Access Package Flow risk flags and
  tiers of every snapshot for the reports. `New-EntraOpsReportingData` runs it as its last step; the
  two reports show only these risk flags and tiers, and a notice when they are missing or were
  evaluated from other report data. Each risk flag names its rule (ID and title, linked to the Findings
  view); a flag accepted by a [finding exception](#finding-exceptions) is shown as accepted and isn't
  counted.

```powershell
Invoke-EntraOpsFindingEvaluation | Format-Table RuleId, CheckTitle, Status, FailedCount
Invoke-EntraOpsFindingEvaluation -Category JustInTimeAccess | Where-Object Status -eq 'Failed'
Invoke-EntraOpsFindingEvaluation | Save-EntraOpsFindingJson
```

The EntraOps Maester Pack (Maester 3.0 or later, code `EOPS`) reports one Maester test per rule from
`findings.json`. It needs no connection or permission, and reads `Reports/Findings/data` of the EntraOps
working folder (`ENTRAOPS_ROOT`, `<home>/EntraOps` or the current folder) unless `EntraOps.FindingsPath` in
`maester-config.json` points elsewhere, for example to the `EntraOps-Reporting` artifact:

```powershell
Install-MtPack Cloud-Architekt/EntraOps-MaesterPack
Invoke-Maester -Pack EOPS -SkipBuiltIn -SkipGraphConnect
```

A rule with the status `Error` is a Maester error, and excluded or skipped rules are skipped tests. A failed test
links each affected object to the Microsoft Entra admin center and to these reports, with the same deep links as
the Findings view, and every result links its rule in the Findings view (`#rule=`); the pack finds the reports
next to `findings.json` or uses `EntraOps.ReportsPath`. The affected users, groups, service principals and
Conditional Access policies are listed on Maester's Affected objects page with their EntraOps tier (by default
since Maester 3.0.0-rc73), and each result shows the settings of the check and its finding exceptions. See the
[EntraOps Maester Pack](https://github.com/Cloud-Architekt/EntraOps-MaesterPack) repository for its settings and
results.

### Finding exceptions {#finding-exceptions}

**Finding exceptions** dismiss a finding (a false positive) or accept its
risk until a date, without excluding the whole rule. The Finding Exceptions File
(`Findings.ExceptionsFilePath`, default `./Classification/FindingExceptions.json`) lists them; the
evaluation reads it also without `EntraOpsConfig.json`. The Privileged Assets Findings view maintains it:
*Accept* at an affected object of a check adds an exception, which is kept in the browser until
*Export FindingExceptions.json* downloads the file. Save it at the path of the setting, committed to the
repository or in a local EntraOps folder; the next evaluation (`New-EntraOpsReportingData`) applies it.

```json
[
  {
    "RuleId": "EO.3001",
    "InstanceId": "EO_RA_ga1",
    "ObjectId": "11111111-1111-1111-1111-111111111111",
    "DisplayName": "Break Glass 01",
    "State": "RiskAccepted",
    "Justification": "Emergency access account, monitored by an alert",
    "AcceptedBy": "secops@contoso.com",
    "AcceptedOn": "2026-10-29",
    "ExpiresOn": "2027-04-27",
    "Reference": "CHG-1234"
  }
]
```

An exception with `InstanceId` accepts this result of the rule (`Instance.Id`); without it, `ObjectId`
accepts all results of the rule for the object. `State` is `RiskAccepted` (needs `AcceptedOn` and
`ExpiresOn`, at most `ExceptionMaxDays` apart) or `Dismissed` (`ExpiresOn` is optional); a
`Justification` is required. Accepted results are not failures: the rule result counts them apart
(`AcceptedCount`, `AcceptedResults` with the exception), a rule whose results are all accepted is
`Passed`, and the reports don't show them as findings of the object. A `Passed` rule with risk-accepted
results doesn't meet the control: the Findings view marks it *Risk accepted*, and the Maester Pack skips its
test with the accepted risks as the reason. With dismissed results only (false positives), the test passes;
with open results, it fails and names the accepted ones apart. An exception that expired after the evaluation no longer accepts its result in the Maester Pack and the flow reports either: the result is open again. `Exceptions` lists the exceptions of a rule with their status: `Active`, `Expired` (expired
since `ExpiresOn`: its findings are reported again, with a warning), `Stale` (no result matches, for
example the finding was fixed; remove it) or `NotEvaluated`. Invalid entries and entries of unknown
rules are skipped with a warning, and an `ExpiresOn` before `AcceptedOn` or an `AcceptedOn` in the future
is reported. An active exception of either scope accepts a result, also when the other one has expired. The
Findings view accepts or dismisses several selected results at once; changes in the browser that the file
already contains are dropped when the page loads, and a notice warns when the file changed while changes
were pending. Use `ExcludedRules` to turn off a rule for the whole tenant.

## GitHub Copilot Agents

EntraOps ships two GitHub Copilot custom agents (`.github/agents/`) that analyze your
`PrivilegedEAM` export directly in chat, applying the same Enterprise Access Model tiers and
hygiene rules used throughout EntraOps. Pick either agent from the Copilot Chat agent picker in
VS Code or on github.com.

![EntraOps-QA in VS Code Copilot Chat explaining the Control Plane classification of a privileged identity](../assets/reporting/github-custom-agent.png)

### EntraOps-Report

Generates a comprehensive markdown report (`Overview.md`) from the full `PrivilegedEAM` export:
access-level mismatches (role tier higher than the member's own tier), permanent privileges on
Control/Management Plane roles, on-premises-synced or guest accounts holding privileged roles,
privileged objects owned by lower-tier identities, and simplified attack paths (transitive access,
cross-RBAC-system lateral movement). When available, it also queries Microsoft Sentinel for
`UserRiskEvents`/`ServicePrincipalRiskEvents` and recent `SecurityIncident` data for any privileged
objects found.

### EntraOps-QA

Answers focused, chat-based questions about a single identity, group, service principal or role -
without scanning the whole export. It locates only the relevant JSON file(s) for the requested
entity, then reports its role/tier assignments (including PIM eligible vs. permanent), hygiene
flags (on-premises/guest, ownership), and a simplified attack path explanation, optionally enriched
with Microsoft Sentinel risk/incident data.

Both agents read `EntraOpsConfig.json` to identify the tenant and configured RBAC systems, and
expect the `PrivilegedEAM` export folder to already exist (see
[Collecting and exporting data](../privileged-eam/index.html#collecting-and-exporting-data) or
[Try it with zero configuration](../get-started/index.html#try-it-with-zero-configuration)).

## Microsoft Sentinel integration

### Parser for Custom Tables and WatchLists

A parser ensures a standardized schema for EntraOps data across the various ingestion options.
This allows you to use the same queries and workbooks, regardless of whether you have used
WatchLists or a Custom Table.

Deploy the parser matching your ingestion option (choose the Custom Table parser if you have
enabled ingestion to both targets):

- [Deploy the Custom Table parser to Azure](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2FCloud-Architekt%2FEntraOps%2Fmain%2FParsers%2FPrivilegedEAM_CustomTable.json)
- [Deploy the WatchLists parser to Azure](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2FCloud-Architekt%2FEntraOps%2Fmain%2FParsers%2FPrivilegedEAM_WatchLists.json)

The Custom Table parser returns the latest completed ingestion run of each RBAC system within the last
14 days, so objects stay visible between weekly collections and objects removed in the latest run don't
reappear. `Save-EntraOpsPrivilegedEAMInsightsCustomTable` writes the same `TimeGenerated` for all records
of a run and, after the last record of each RBAC system, a completion marker (a record with `ObjectType`
`EntraOpsIngestionRun`). A run that failed part-way has no marker and never replaces the last complete run.
A run limited with `-PrincipalTypeFilter` to some object types writes no marker either, so the parser keeps
returning the last run with all object types.
The parser doesn't return the marker records; exclude them when you query `PrivilegedEAM_CL` directly.
If your data collection rule sets `TimeGenerated` itself (e.g. `extend TimeGenerated = now()`), the records
between the previous and the latest marker belong to the latest run, which can include the records of a
failed run in between. Until the first run with markers, the parser returns the latest ingestion.
For a collection interval longer than 14 days, increase `LookbackPeriod` in the parser. The WatchLists
parser also returns role assignments without classification, with an empty `Classification`.
Redeploy the parser after updating EntraOps when the changelog lists parser changes.

### Ingest classification and enrichment data

> **One writing deployment per tenant.** Let only one deployment (one GitHub repository or one Azure DevOps
> pipeline) per tenant ingest and write: the WatchLists, the `PrivilegedEAM_CL` table through the data collection
> rule and the `Apply*` automation (Administrative Units, RMAU, Conditional Access groups, catalogs) are shared, so
> a second deployment replaces or mixes its data with the first on every run. The WatchList description records the
> tenant and the deployment that wrote it (`EntraOps | Tenant: … | Deployment: …`), and
> `Save-EntraOpsPrivilegedEAMWatchLists` warns with both names when another deployment wrote a WatchList last.
> After each upload it checks that the WatchList exists and has rows, and reports missing or empty WatchLists as
> an error at the end of the run. The GitHub workflow and Azure Pipeline fail the push run for such an error, after
> the other push operations have run. The WatchList cmdlets install and use SentinelEnrichment 0.2.2.

- `Save-EntraOpsPrivilegedEAMInsightsCustomTable` ingests classified Privileged EAM data into a Log Analytics/Sentinel custom table (`IngestToLogAnalytics` in `EntraOpsConfig.json`).
- `Save-EntraOpsPrivilegedEAMWatchLists` ingests the same data as Sentinel WatchLists (`IngestToWatchLists`/`WatchListTemplates`), and can also generate the workload-identity enrichment WatchLists described below via `-WatchListWorkloadIdentity`.
- `Save-EntraOpsPrivilegedEAMEnrichmentToWatchLists` generates the "VIP Users", "High Value Assets" and "Identity Correlation" WatchLists (`-WatchListTemplates`) that correlate privileged and regular work accounts using the custom security attributes described in [Core &rarr; Classify by Custom Security Attributes](../core/index.html#classify-by-custom-security-attributes).

> **`RbacSystems` default.** Both cmdlets default `-RbacSystems` to `Azure`, `EntraID`,
> `IdentityGovernance`, `DeviceManagement`, `ResourceApps` - the five systems generated by the
> standard EntraOps configuration. `AzureBilling` and `Defender` are **not** included by default;
> pass them explicitly via `-RbacSystems` if you need their WatchLists. The generated
> `EntraOpsConfig.json`'s `SentinelWatchLists` section does not set `RbacSystems`, so
> `Push-EntraOpsPrivilegedEAM` relies on this default - if you need `AzureBilling`/`Defender`
> WatchLists, add an explicit `RbacSystems` array (including the systems you already rely on) to
> the `SentinelWatchLists` section of your `EntraOpsConfig.json`.

### Examples: EntraOps data in the Unified SecOps Platform (Sentinel and XDR)

**Devices in Exposure Management with authentication from Control Plane users:**

```kusto
let ClassifiedTier0User = PrivilegedEAM
                | where Classification contains "ControlPlane"
                | where ObjectType == "user"
                | summarize arg_max(TimeGenerated, *) by ObjectId
                | project tostring(ObjectId), tostring(ObjectAdminTierLevel);
let Tier0Nodes = ExposureGraphNodes
                | where NodeLabel == "user"
                | mv-expand parse_json(EntityIds)
                | where parse_json(EntityIds).type == "AadObjectId"
                | extend NodeId = tostring(NodeId)
                | extend AadObjectId = tostring(parse_json(EntityIds).id)
                | extend TenantId = extract("tenantid=([\\w-]+)", 1, AadObjectId)
                | extend ObjectId = tostring(extract("objectid=([\\w-]+)", 1, AadObjectId))
                | where ObjectId in (ClassifiedTier0User);
let SensitiveRelation = dynamic(["can authenticate as","has credentials of","can authenticate as", "frequently logged in by"]);                
ExposureGraphEdges
| where TargetNodeId in (Tier0Nodes) and EdgeLabel in (SensitiveRelation)
| where SourceNodeLabel == "device"
// Get details of devices
| join kind = inner ( ExposureGraphNodes ) on $left.SourceNodeId == $right.NodeId
// Get ObjectId of Target (Tier0) Nodes
| join kind = inner ( Tier0Nodes ) on $left.TargetNodeId == $right.NodeId
| mv-expand parse_json(NodeProperties)
| summarize make_list(EdgeLabel) by SourceNodeName, SourceNodeLabel, tostring(SourceNodeCategories), TargetNodeId, TargetNodeName, TargetNodeLabel, tostring(TargetNodeCategories),
    VulnerableToPrivilegeEscalation = tostring(parse_json(tostring(parse_json(tostring(NodeProperties.rawData)).highRiskVulnerabilityInsights)).vulnerableToPrivilegeEscalation),
    MdeExpsoureScore = tostring(parse_json(NodeProperties).rawData.exposureScore),
    MdeRiskScore = tostring(parse_json(NodeProperties).rawData.riskScore),
    MdeSensorHealth = tostring(parse_json(NodeProperties).rawData.sensorHealthState),
    MdeMachineGroup = tostring(parse_json(NodeProperties).rawData.machineGroup)
```

**Resources with access or authentication to classified privileges in EntraOps:**

```kusto
let SensitiveRelation = dynamic(["can authenticate as","has credentials of","affecting", "can authenticate as", "frequently logged in by"]);
let ClassifiedTier0Assets = PrivilegedEAM
                | summarize arg_max(TimeGenerated, *) by tostring(ObjectId);
let Tier0Nodes = ExposureGraphNodes
                | mv-expand parse_json(EntityIds)
                | where parse_json(EntityIds).type == "AadObjectId"
                | extend NodeId = tostring(NodeId)
                | extend AadObjectId = tostring(parse_json(EntityIds).id)
                | extend TenantId = extract("tenantid=([\\w-]+)", 1, AadObjectId)
                | extend ObjectId = extract("objectid=([\\w-]+)", 1, AadObjectId)
                | where ObjectId in (ClassifiedTier0Assets);
let ExposedEdges = ExposureGraphEdges
            | where EdgeLabel in (SensitiveRelation)
            | extend TargetNodeId = tostring(TargetNodeId)
            | join kind=inner ( Tier0Nodes ) on $left.TargetNodeId == $right.NodeId;
ClassifiedTier0Assets
| join kind=inner ( ExposedEdges ) on ObjectId
| project Type2, SourceNodeName, SourceNodeLabel, SourceNodeCategories, EdgeLabel, TargetNodeId, TargetNodeLabel, TargetNodeCategories, Classification, RoleAssignments, Categories
```

### Workbooks for visualizing EntraOps classification data

These workbooks visualize users, workload identities, groups and their classified role
assignments. Pre-requisite: EntraOps data has been ingested to a WatchList or Custom Table and the
associated parser has been deployed.

- [Deploy "EntraOps Privileged EAM - Overview"](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2FCloud-Architekt%2FEntraOps%2Fmain%2FWorkbooks%2FEntraOps%20Privileged%20EAM%20-%20Overview.json)
- [Deploy "EntraOps Privileged EAM - Agent Identities"](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2FCloud-Architekt%2FEntraOps%2Fmain%2FWorkbooks%2FEntraOps%20Privileged%20EAM%20-%20Agent%20Identities.json)
- [Deploy "EntraOps Privileged EAM - Workload Identities"](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2FCloud-Architekt%2FEntraOps%2Fmain%2FWorkbooks%2FEntraOps%20Privileged%20EAM%20-%20Workload%20Identities.json)

### Workload Identity enrichment

The "EntraOps Privileged EAM - Workload Identities" workbook is powered by four dedicated
WatchLists, refreshed together by `Save-EntraOpsWorkloadIdentityEnrichmentWatchLists` (requires the
[SentinelEnrichment](https://www.powershellgallery.com/packages/SentinelEnrichment) module and a
Sentinel workspace) or individually via its `-WatchLists` parameter:

| WatchList                           | Cmdlet                                        | Data                                                                                                                             |
| ----------------------------------- | --------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------- |
| `ManagedIdentityAssignedResourceId` | `Get-EntraOpsManagedIdentityAssignments`      | System- and user-assigned managed identities mapped to the Azure resource(s) that consume them (via Azure Resource Graph).       |
| `WorkloadIdentityAttackPaths`       | `Get-EntraOpsWorkloadIdentityAttackPaths`     | Attack paths from Microsoft Defender for Cloud CSPM involving a service principal or managed identity entity.                    |
| `WorkloadIdentityInfo`              | `Get-EntraOpsWorkloadIdentityInfo`            | Service principal/application metadata, enriched with the `privilegedWorkloadIdentity` custom security attribute classification. |
| `WorkloadIdentityRecommendations`   | `Get-EntraOpsWorkloadIdentityRecommendations` | Microsoft Entra recommendations impacting applications, filtered by `-StatusFilter`.                                             |

`Save-EntraOpsWorkloadIdentityInfo` is a self-contained variant of `Get-EntraOpsWorkloadIdentityInfo`
that authenticates with a system-assigned managed identity (e.g. for a scheduled Azure Automation
runbook) and pushes directly to the `WorkloadIdentityInfo` WatchList.

## BloodHound integration

EntraOps can export its Privileged EAM classification data as a [BloodHound OpenGraph](https://bloodhound.specterops.io/opengraph/overview)
JSON payload, enriching an existing AzureHound-ingested tenant graph with EntraOps node types and
tier classifications. This makes Enterprise Access Model tier-boundary violations - including
cloud-managed PAW paths - demoable as attack paths directly in BloodHound CE or Enterprise.

The exporter is modeled as an AzureHound enrichment layer. It reuses AzureHound-compatible node
and edge kinds for principals, devices, service principals, groups, and Entra ID role definitions,
while adding `EO_`-prefixed kinds for EntraOps-owned context: concrete role assignments, assignment
scope, classification evidence, PAW relationships, sponsor links, identity parent links, and Intune
device permissions.

**Key cmdlets:**

- `Export-EntraOpsPrivilegedEAMBloodHound` - converts per-RBAC-system EAM export files (produced by `Save-EntraOpsPrivilegedEAMJson`) into a BloodHound-compatible OpenGraph JSON file, ready for upload alongside the custom extension schema.
- `Save-EntraOpsPrivilegedEAMJson` / `Update-EntraOpsClassificationControlPlaneScope` - must run first to generate classified EAM JSON. The scope update step also writes `DeviceManagement_ScopeGroupDeviceMembers.json`, which the exporter uses to build traversable `EO_IntuneRolePermission` edges from Intune role assignments to concrete `AZDevice` nodes.

**Graph model highlights:**

- Entra ID, Intune, Identity Governance, Defender, and App Role assignments are all represented as first-class `EO_*RoleAssignment` nodes, preserving scope, PIM state, and classification evidence without replacing native AzureHound paths.
- For DeviceManagement, `EO_IntuneRolePermission` edges connect role assignments and their principals to scoped `AZDevice` nodes when matched Intune actions indicate device-impacting capability, making PAW tier-boundary paths visible and traversable.
- Classification decisions are linked via `EO_ClassifiedViaObject` edges, showing exactly which object drove an Enterprise Access Model tier assignment.

For detailed setup steps, schema documentation, Cypher query examples, and privilege zone rules,
see the [BloodHound Integration README](https://github.com/Cloud-Architekt/EntraOps/tree/main/Integrations/BloodHound).
