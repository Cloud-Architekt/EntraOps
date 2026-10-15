# EntraOps Configuration Analyzer

Static, self-contained web app to analyze **EntraOps Tenant Governance snapshots** over time -
no backend, database or web server required. Works offline from `file://` or any static web
server, like the other EntraOps Reporting apps.

The **Conditional Access policy flow / coverage gaps** and **EIDSCA findings** views that used to
live here moved to their own apps - [Conditional Access Analysis](../ConditionalAccessAnalysis)
and [EIDSCA Findings](../EidscaCoverage) - which reuse this app's dataset and the shared parsing
model in `js/core.js`. [Access Package Flow](../AccessPackageFlow) visualizes Entra ID Governance
entitlement management the same way.

## What it shows

- **Change timeline** - how many resources were added, modified or removed compared to the
  previous capture, filterable by resource type. The default view keeps the latest 12 committed
  snapshots readable; weekly and monthly views aggregate the latest 12 captured periods for trend
  analysis, while the all-snapshots view retains the complete history. Click a snapshot bar, or an
  aggregated period bar, to inspect the applicable latest snapshot's changes.
- **Snapshot changes & compare** - list of every added/modified/removed resource between two
  snapshots (the selected one vs. its predecessor, or any two snapshots of your choice), with
  **property-level diffs** (old vs. new value) for snapshots with embedded content.
- **Snapshot Resources** - a synchronized, keyboard-navigable snapshot browser. Select a
  timeline point or snapshot to set its baseline automatically, then browse all, changed, added,
  modified, or removed resources by type, category, name, privilege tier, or classification. Each
  resource shows its presence and content-change history across the captured snapshots.
- **Configuration Assets** - per captured resource type, which resources reference a Control Plane /
  Management Plane / User Access identity (directly, or via a group's resolved transitive
  membership - see `-ResolveGroupMembersForPrivilegedAssets` below), from the specific fields
  documented to carry a user/group id (Administrative Unit members, Conditional Access
  IncludeUsers/IncludeGroups and authentication method policy IncludeTargets, access package
  requestors/approvers, role schedule request principals, group owners/members and Intune
  assignment targets). Excluded users, groups and targets are not evaluated. Intune targets that
  use an Entra device ID resolve through the privileged users' owned and PAW device associations
  in the EntraOps export. An Administrative Unit inherits every tier found among its members; an
  id not classified by EntraOps is treated as User Access. **Resource Overview** summarizes the
  classified resource types; selecting one opens **Related assets**, an expandable
  resource-to-tier-to-asset tree. The shared search matches resource types, snapshot resources,
  identities, UPNs, object types, and classification services and removes unrelated asset leaves.
  Resource and access-tier branches are collapsed by default. Selecting a tier count in
  **Classified Resource Types** filters to that resource type and tier and expands those matching
  branches for immediate review. Asset names link to EAM Dashboard, while snapshot objects open a
  structured property drawer with resolvable identity and resource references shown as deep links.

## Refresh the data

The app reads `data/configuration-analyzer-data.js`, generated from the **git history** of the
snapshot folder (git history is the only source of historic data - there is no separate
time-series store):

```powershell
Import-Module ./EntraOps -Force
New-EntraOpsTenantGovernanceConfigurationAnalyzerData
```

or as part of refreshing all reporting apps with `New-EntraOpsReportingData`. Useful parameters:

- `-TimeRangeInDays 90` - only walk the last 90 days of history.
- `-SnapshotInterval P1W` - keep at most one snapshot per week (default: every commit).
- `-MaxDetailedSnapshots 30` - how many snapshots embed full resource content (needed for
  property-level diffs and the Conditional Access views). Content blobs are de-duplicated by git
  blob hash, so unchanged resources are stored once regardless of the snapshot count.
- `-AllowPartialSnapshot` - explicitly include the current mixed tree after a partially successful
  Tenant Governance capture. Preserved resource types remain marked stale. Historical partially
  successful commits that published resource files are part of the timeline regardless of this
  switch; manifest-only commits (no resource type published) are excluded. The GitHub reporting workflow enables this by default
  through `ConfigurationAnalyzer.AllowPartialTenantGovernanceSnapshot`; set it to `false` for a
  strict complete-snapshot-only report. Manual workflow dispatch can still override the setting.
- `-AllowStaleSnapshot` - bypass only the snapshot age check. Combine it with
  `-AllowPartialSnapshot` when the current mixed tree is also older than the configured limit.
- `-ResolveGroupMembersForPrivilegedAssets` - for Configuration Assets: resolve the
  transitive membership of groups referenced in the latest detailed snapshot (via Microsoft
  Graph, PIM-for-Groups aware) so a group can be attributed a tier from its members instead of
  being treated as User Access. Enabled by default; set
  `ConfigurationAnalyzer.ResolveGroupMembersForPrivilegedAssets` to `false` in
  `EntraOpsConfig.json` or pass `-ResolveGroupMembersForPrivilegedAssets:$false` to skip the
  Microsoft Graph calls. It requires an active `Connect-EntraOps` session and a Privileged EAM
  export, and expands nested and PIM-managed group membership.

The generated bundle contains tenant-specific configuration and object identifiers. It is ignored
by Git and should not be committed or shared. Run `Remove-EntraOpsReportingData` to remove it and
the other generated reporting datasets from a repository checkout.

The Tenant Governance Snapshot feature itself is configured via the `TenantGovernanceSnapshot`
section of `EntraOpsConfig.json` - see [Tenant Governance](https://www.entraops.com/docs/tenant-governance/index.html).
