# EntraOps Privilege History

A **static web app** with historic trends of privileged assets, role
assignments and tier breaches over time, built entirely from the **git
history** of your [EntraOps](https://github.com/cloud-architekt/entraops)
Privileged EAM export — no Log Analytics workspace, Azure subscription or
separate time-series store required.

Part of **Privileged EAM Reporting** (see [`Reports/index.html`](../index.html))
and styled after the Microsoft **Fluent UI / Azure Portal** design, matching
the [Classification Explorer](../ClassificationExplorer/README.md),
[EAM Dashboard](../EamDashboard/README.md), [Access Path Map](../AccessPathMap/README.md)
and the [Tier Breach Analyzer](../TierBreachAnalyzer/README.md).

## What you can do

- **Trend charts** – unique privileged assets, users assigned and unique role
  assignments per Enterprise Access Model tier over time, plus tier breaches
  (an object whose own tier is less privileged than a role assignment it
  holds) over time. Charts show totals across every RBAC system and tier
  (that's what is aggregated at generation time).
- **Filters** – RBAC System and RBAC Tier Level pills (any combination of values,
  with the number of matching privileged assets of the selected snapshot, or of
  the latest snapshot of the time range) and a free-text Role search apply to the
  snapshot detail below the charts.
- **Time range** – pick a "from"/"to" snapshot in the search bar to zoom the
  trend charts into a specific window, or reset back to the full history.
- **Snapshot detail** – click a point on any chart to inspect that snapshot:
  totals (with deltas vs. today's live data, when the EAM Dashboard dataset is
  present) plus filtered privileged asset and role assignment tables.
- **Open in EAM Dashboard Overview** – jump from a snapshot straight into the
  [EAM Dashboard](../EamDashboard/README.md) with the same RBAC System / Tier
  Level filters (one or several tiers) and the Role search applied (handed off via
  URL query parameters `rs`, `objectTier` and `q`, since the two apps are separate
  static-web pages). The EAM Dashboard lists privileged groups too, while the
  Privilege History counts privileged assets without groups.
- **Deltas vs. today** – the snapshot totals are compared with the EAM Dashboard
  data counted like the generator (assets without groups, a role assignment once
  per instance ID), so the snapshot of today's export shows *no change*.
- **Tier breaches** – the chart counts every role assignment above the object tier,
  including delegated permissions and Microsoft first-party apps. The finding
  `EO.8002` (new tier breaches) follows the rules of `EO.1001`/`EO.1003` instead
  (without delegated permissions and Microsoft apps, unclassified objects apart),
  so its numbers can be lower; the chart says so.
- **Without git history** (`-HistorySource Folder`, or `Auto` outside a repository)
  the only snapshot is labelled *current export*, and a note says that trends and
  comparisons need the exports in a git repository.
- **Compare two points in time** – pick a baseline and a current point (any
  two snapshots, or a snapshot vs. today's live data) to see which privileged
  assets were added, removed or changed tier, and how the totals moved.

## Data source: git history, not a separate time-series store

Every commit that changed `PrivilegedEAM/<RbacSystem>/<RbacSystem>.json`
(written by `Save-EntraOpsPrivilegedEAMJson` and committed by the
`Pull-EntraOpsPrivilegedEAM` workflow) becomes one snapshot. There is no
additional data collection or storage — the git history *is* the time series.

The app is **disabled** in the sense that this page shows setup instructions
instead of failing when its dataset hasn't been generated yet.

## Run it

The app is fully self-contained: it embeds its dataset as a script file, so it
works **offline from `file://`** — no web server, no internet connection, no
backend.

1. Make sure the repository is a git working copy with history of
   `PrivilegedEAM/` (the normal result of the `Pull-EntraOpsPrivilegedEAM`
   workflow).
2. Generate the dataset:

   ```powershell
   Import-Module ./EntraOps -Force
   New-EntraOpsPrivilegedEamPrivilegeHistoryData
   ```

3. Open `index.html` in a browser (double-click works), or serve the folder
   with any static web server / Azure Static Web Apps.

> [!WARNING]
> The generated `data/` bundle contains your tenant's privileged inventory (UPNs, object IDs,
> role assignments, PIM state) across its full history. Azure Static Web Apps — like most static
> hosts — serves every route **anonymously by default**. Do not publish this folder without
> putting authentication in front of it (e.g. `allowedRoles` in a `staticwebapp.config.json`,
> Entra ID authentication, or another access control).

Use `-TimeRangeInDays` to only walk recent history (default: the full
history). Use `-SnapshotInterval` to control how far apart two consecutive
snapshots must be, as an ISO 8601 duration: `P1D` (daily), `P1W` (weekly),
`P2W` (bi-weekly, the **default**), `P1M` (monthly), `P3M` (quarterly), `P1Y`
(yearly), or any other combination of years/months/weeks/days (e.g. `P10D`).
Months and years use real calendar arithmetic, not a fixed day count, so
"monthly" always lines up with the same day of the following month regardless
of length. The oldest and the most recent commit in range are always kept
regardless of spacing, so the dataset always covers the full requested window
and reflects the latest state. Pass `-SnapshotInterval P0D` (or `None`) to
keep every commit (no thinning) - the previous behavior. Only up to
`-MaxDetailedSnapshots` (default 60, evenly spread across the full range) keep
their per-object detail (used by snapshot detail/compare); older/thinned-out
snapshots keep their trend numbers but drop object-level detail, so the
generated file stays a reasonable size regardless of how far back the git
history goes.

`New-EntraOpsReportingData` generates this dataset automatically (and
`Remove-EntraOpsReportingData` removes it again) based on the `PrivilegeHistory`
section of `EntraOpsConfig.json`:

```jsonc
"PrivilegeHistory": {
  "EnablePrivilegeHistory": true, // set to false to skip Privilege History generation
  "TimeRangeInDays": null,   // null = full history, or a number of days
  "SnapshotInterval": "P2W"  // minimum spacing between snapshots (ISO 8601 duration)
}
```

To see "then vs. now" deltas and use "Live (now)" in the compare view, also
generate the EAM Dashboard dataset (`New-EntraOpsPrivilegedEamDashboardData`)
alongside this app — Privilege History loads
`../EamDashboard/data/eam-dashboard-data.js` if present and silently skips
those comparisons if it isn't.

## Folder structure

```
PrivilegeHistory/
├── index.html                  App shell (portal-style app bar + navigation)
├── css/styles.css               Fluent / Azure Portal design system + app styles
├── js/app.js                    Trend charts, filters, snapshot detail, compare
├── data/privilege-history-data.js    Generated dataset (window.ENTRAOPS_PRIVILEGEHISTORY_DATA)
└── assets/                      Logo
```

The folder is independent by design: copy `Reports/PrivilegeHistory/` anywhere
(together with its generated `data/` bundle) and it keeps working (the
"then vs. now" comparisons and "Open in EAM Dashboard Overview" link need the
EAM Dashboard app alongside it). The "Privileged EAM Reporting" navigation
links to the landing page and the other apps only resolve inside the full
repository layout.
