# EntraOps Dashboard

A **static web app** with the **Enterprise Access Model Dashboard**: the
static-web counterpart of the *EntraOps Privileged EAM - Overview* Azure
workbook, built entirely from your
[EntraOps](https://github.com/cloud-architekt/entraops) Privileged EAM export —
no Log Analytics workspace or Azure subscription required.

Part of **Privileged EAM Reporting** (see [`Reports/index.html`](../index.html)) and
styled after the Microsoft **Fluent UI / Azure Portal** design, matching the
[Classification Explorer](../ClassificationExplorer/README.md),
[Access Path Map](../AccessPathMap/README.md), the
[Tier Breach Analyzer](../TierBreachAnalyzer/README.md) and
[Privilege History](../PrivilegeHistory/README.md).

## What you can do

All views, filters and drill-downs of the Overview workbook are available:

- **Filters (workbook parameters)** – RBAC System, RBAC Tier Level, Service
  (dependent on the selected systems/tiers), Principal Type, Linked Identity
  (`AssociatedWorkAccount`), Privileged Type (Tenant Governance /
  Multi-Tenant Apps / B2B Collaboration / Local Identities, i.e. local users,
  groups and single-tenant applications) and a free-text search across
  principal display name, role name, scope name and role actions.
- **Sync source of privileged identities** – Cloud-Only vs. Hybrid tiles;
  click a tile to cross-filter every other view (the workbook's `SyncSource`
  export).
- **Restricted management of privileged identities** – donut chart of the
  Applied / Conflict / Not applied / Not available status derived from
  `RestrictedManagementByAadRole` / `...ByRAG` / `...ByRMAU` with the same case
  logic as the workbook grid; click a segment to filter the asset list.
- **Assignments of privileged roles** – donut chart of
  `RoleAssignmentType + PIMAssignmentType` combinations (Direct/Transitive ×
  Permanent/Eligible); click a segment to filter the asset list.
- **Classification of privileged identities** – tier tiles
  (Control Plane / Management Plane / Workload Plane / User Access /
  Unclassified) counting distinct non-group objects by
  `ObjectAdminTierLevelName`; click to cross-filter.
- **Classification of privileged access** – tier tiles counting distinct
  (object, classification-tier) pairs; click to cross-filter.
- **List of Privileged Assets** – grid with the workbook's threshold icons
  (principal type, tier level, restricted management), administrative units and
  restricted-management context blades, sync source, linked identity and the
  RBAC-system set per object. Click a row to drill down.
- **Related privileged role assignments** – aggregated assignment grid for the
  selected asset (or all assets) with RBAC-system icons, tier badges, scope,
  PIM assignment type, `EligibilityBy`, transitivity and service context.
  Select rows (checkboxes) to filter the classification grid below — the
  workbook's `SelectedRoleAssignmentIds` export.
- **Related role classification** – per-classification rows incl. `TaggedBy`,
  `TaggedByObjectDisplayNames` (expanded, `N/A` when empty) and
  `TaggedByRoleSystem`.
- **Detail blades (&#187; column)** – every row of the three grids ends with a
  &#187; icon (right of the review star) that opens a context blade (same
  sidebar as the services / restricted-management blades) with *all* details
  of the row: full principal properties (ids, UPN, privileged type,
  restricted-management flags,
  administrative units, linked identities, object & access classification) for
  assets; role/assignment/scope/transitivity properties, the assigned
  principals and every classification entry incl. matched role actions for
  role assignments; and scope ids, tagged-by object ids, matched role actions
  and holding principals for classification rows.
- **CSV export** for all three grids.
- **Review list / bookmarking** – star a privileged asset or role assignment directly
  from its grid row to add it to the same cross-tool **Review list** used by the
  Classification Explorer, Access Path Map and Tier Breach Analyzer (shared via
  `localStorage`). Every starred item and grid row keeps a deep link that jumps
  straight back to the same selection on reload.
  Individual matched role actions can also be starred in the classification evidence
  blades for assets, assignments and classification rows. Each bookmark retains its
  RBAC system, assignment scope and observed tier; the same action at different scopes
  stays separate. Its link reopens the source assignment's evidence at that action.
  The evidence of a classification row lists up to five assignment scopes per action
  (starred scopes first); star further scopes in the classification reasoning of their
  role assignment.
  In **Classification Explorer > Customize Overwrites > Role Actions > Add entry**,
  use **From your Review list > Add action**, then explicitly enter the overwrite
  scope, tier and justification. The observed scope and tier are context, not an
  automatically applied overwrite. Cross-app sharing requires the apps to be served
  from the same origin; sharing `localStorage` between `file://` pages is browser-dependent.

### Deep links and hand-over parameters

- `#asset=<objectId>` and `#assignment=<instance ID or assignment ID>` scroll to and highlight the row. When the
  current filters hide it, all filters are cleared first (like the Tier Breach Analyzer); the notice appears only for
  an ID that is not in the Privileged EAM data. Asset IDs match case-insensitively.
- `#assignment=<encoded assignment ID>&action=<encoded action>` opens the assignment's
  classification evidence and focuses the bookmarked action.
- `?rs=<systems|*>&objectTier=<tier[,tier]|*>&q=<text>` (from the Privilege History) sets the RBAC systems, one or
  several identity classifications and the search.

## Computed columns

The dataset generator applies the same computed columns as the
`PrivilegedEAM` parsers (`Parsers/PrivilegedEAM_WatchLists`,
`Parsers/PrivilegedEAM_CustomTable`) and the Overview workbook:

- **`EligibilityBy`** – "PIM for Entra ID Roles and Groups",
  "PIM for Entra ID Roles", "PIM for Azure Roles", "PIM for Groups" or "N/A",
  derived from `RoleSystem`, `PIMAssignmentType` and `RoleAssignmentSubType`.
- **`RestrictedManagement`** – "Applied", "Conflict", "Not applied" or
  "Not available", derived from the object type/sub-type and the three
  `RestrictedManagementBy*` flags.
- **`SyncSource`** – "Cloud-Only" / "Hybrid" from `OnPremSynchronized`.

## Run it

The app is fully self-contained: it embeds its dataset as a script file, so it
works **offline from `file://`** — no web server, no internet connection, no
backend.

1. Export your Privileged EAM data with the EntraOps module
   (`Save-EntraOpsPrivilegedEAMJson`), producing
   `PrivilegedEAM/<RbacSystem>/<RbacSystem>.json`.
2. Generate the dataset:

   ```powershell
   Import-Module ./EntraOps -Force
   New-EntraOpsPrivilegedEamDashboardData
   ```

3. Open `index.html` in a browser (double-click works), or serve the folder
   with any static web server / Azure Static Web Apps.

> [!WARNING]
> The generated `data/` bundle contains your tenant's privileged inventory (UPNs, object IDs,
> role assignments, PIM state). Azure Static Web Apps — like most static hosts — serves every
> route **anonymously by default**. Do not publish this folder without putting authentication in
> front of it (e.g. `allowedRoles` in a `staticwebapp.config.json`, Entra ID authentication, or
> another access control).

To use a Privileged EAM export from another location, pass `-ImportPath`:

```powershell
New-EntraOpsPrivilegedEamDashboardData -ImportPath "C:\Exports\PrivilegedEAM"
```

Use `Remove-EntraOpsReportingData` to clear the generated (tenant-specific)
dataset again, or `New-EntraOpsReportingData` to refresh all reporting apps in
one call.

## UI regression checks

After changing dashboard CSS, table rendering, or the generated data contract,
regenerate the dataset and check the three grids at a desktop width with the
navigation expanded and at a mobile width. Dense grids intentionally preserve
their column widths; horizontal viewport scrolling is preferred to truncating
or overlapping operational data. Open a classified asset's information drawer
and confirm that each contributing assignment and its Control Plane reasoning
are visible.

See the separate [Privilege History](../PrivilegeHistory/README.md) app for historic
trends of privileged assets, role assignments and tier breaches over time,
built from the git history of your Privileged EAM export; its "Open in EAM
Dashboard Overview" button jumps back here with the same RBAC System / Tier
Level filters applied.

## Folder structure

```
EamDashboard/
├── index.html                    App shell (portal-style app bar + navigation)
├── css/styles.css                Fluent / Azure Portal design system + app styles
├── js/app.js                     Filters, tiles, donuts, grids, drill-down, CSV export
├── data/eam-dashboard-data.js    Generated dataset (window.ENTRAOPS_EAM_DATA)
└── assets/                       Logo
```

The folder is independent by design: copy `Reports/EamDashboard/` anywhere
(together with its generated `data/` bundle) and it keeps working. The
"Privileged EAM Reporting" navigation links to the landing page and the other
apps only resolve inside the full repository layout.
