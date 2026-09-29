# EntraOps Tier Breach Analyzer

A **static web app** that visualizes Enterprise Access Model **tier boundary
violations** from your [EntraOps](https://github.com/cloud-architekt/entraops)
Privileged EAM export: which lower-tier users and service principals reach
higher-tier (Control Plane) services through role assignments.

Part of **Privileged EAM Reporting** (see [`Reports/index.html`](../index.html)) and
styled after the Microsoft **Fluent UI / Azure Portal** design, matching the
[Classification Explorer](../ClassificationExplorer/README.md),
[EAM Dashboard](../EamDashboard/README.md), [Access Path Map](../AccessPathMap/README.md)
and [Privilege History](../PrivilegeHistory/README.md).

## What you can do

- **Sankey flow** – assignment paths modeled left to right as
  `Object Tier → Object → Role → Service → Service Tier` with selectable
  columns. Tier breaches are drawn in the Enterprise Access Model palette
  (Tier 0 red, Tier 1 amber, Tier 2 green); click a node to trace its
  connections and filter the breach table.
- **Views** – switch between *Tier 0 breaches* (the headline case: a Tier 1 /
  Tier 2 object reaching a Tier 0 service), *all tier breaches* and *all
  assignment paths* from the left navigation.
- **Filters** – RBAC systems, object types (users / service principals) and a
  free-text search over object, role and service names.
- **Breach table** – every breach path with scope, assignment type, PIM and
  transitivity context; expand a row for the full assignment detail
  (assignment id, scope id, classification source, inherited-via, ...).
- **CSV export** – download the current breach list for follow-up.
- **Review list / bookmarking** – star a breach row directly from the table to add it
  to the same cross-tool **Review list** used by the Classification Explorer, EAM
  Dashboard and Access Path Map (shared via `localStorage`). Every starred item
  keeps a deep link that jumps straight back to the same selection on reload.

## How tiering is evaluated

- An object's designated tier comes from `ObjectAdminTierLevel`.
- Objects without a classification (empty / `Unclassified`) are treated as
  **Tier 2 (User Access)**, the least privileged tier.
- A **tier breach** is a path where the object's tier is *less* privileged
  (higher tier number) than the tier of a service it can reach through a role
  assignment. A **Tier 0 breach** is any Tier 1 / Tier 2 object reaching a
  Tier 0 (Control Plane) service.

## Run it

The app is fully self-contained: it ships vendored copies of d3 / d3-sankey and
embeds its dataset as a script file, so it works **offline from `file://`** —
no web server, no internet connection, no backend.

1. Export your Privileged EAM data with the EntraOps module
   (`Save-EntraOpsPrivilegedEAMJson`), producing
   `PrivilegedEAM/<RbacSystem>/<RbacSystem>.json`.

   Accepted `-RbacSystems` values are `Azure`, `EntraID`, `IdentityGovernance`,
   `DeviceManagement`, `ResourceApps`, and `Defender`.

   ```powershell
   Save-EntraOpsPrivilegedEAMJson -RbacSystems @("EntraID", "Azure")
   ```
2. Generate the dataset:

   ```powershell
   Import-Module ./EntraOps -Force
   New-EntraOpsTierBreachAnalyzerData
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
New-EntraOpsTierBreachAnalyzerData -ImportPath "C:\Exports\PrivilegedEAM"
```

## Folder structure

```
TierBreachAnalyzer/
├── index.html                  App shell (portal-style app bar + navigation)
├── css/styles.css              Fluent / Azure Portal design system + app styles
├── js/app.js                   Sankey, filters, breach table, CSV export
├── data/tier-breach-data.js    Generated dataset (window.ENTRAOPS_TB_DATA)
└── assets/                     Logo and vendored d3 / d3-sankey libraries
```

The folder is independent by design: copy `Reports/TierBreachAnalyzer/`
anywhere (together with its generated `data/` bundle) and it keeps working.
The "Privileged EAM Reporting" navigation links to the landing page and the
Classification Explorer only resolve inside the full repository layout.
