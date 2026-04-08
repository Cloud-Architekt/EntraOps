# Getting Started

A single guide from fresh fork to browser dashboard to dry-run Apply to Entra.
No prior EntraOps knowledge required.

## Prerequisites

Before beginning, ensure the following are in place:

- [ ] **Fork and clone this repository** — you need your own copy to commit classified data
- [ ] **[Node.js 22+](https://nodejs.org)** — the GUI development server requires Node 22 or later (v20 reached end-of-life March 2026)
- [ ] **[PowerShell 7+](https://github.com/PowerShell/PowerShell)** — required for the EntraOps module and all cmdlets
- [ ] **Az and Microsoft.Graph PowerShell modules** — install from the PowerShell Gallery:
  ```powershell
  Install-Module Az -Scope CurrentUser
  Install-Module Microsoft.Graph -Scope CurrentUser
  ```
- [ ] **Global Administrator role** (or equivalent) on the target Entra tenant — required for the Connect and Apply steps

## Installation

**1. What this does:** Clones your fork and imports the EntraOps module so cmdlets are available in your session.

```powershell
git clone https://github.com/<your-org>/<your-entraops-fork>
cd <your-entraops-fork>
Import-Module ./EntraOps
```

> You should see: the PowerShell prompt returns with no errors. Run `Get-Command -Module EntraOps` — you should see a list of `Connect-EntraOps`, `Save-EntraOpsPrivilegedEAMJson`, and related cmdlets.

**2. What this does:** Installs GUI dependencies.

```sh
cd gui && npm install
```

> You should see: npm outputs package install progress and ends with `added N packages` with no errors.

## First Run

### Quick Dashboard

No tenant connection required. The repository ships with sample classified data in `PrivilegedEAM/` that populates the dashboard immediately.

**3. What this does:** Starts the GUI development server (client at port 5173, API at port 3001).

```sh
npm run dev
```

(Run this from the `gui/` directory, or `cd gui && npm run dev` from the repo root.)

> You should see: the terminal prints `EntraOps GUI server running at http://127.0.0.1:3001` and Vite reports `Local: http://localhost:5173`. Open `http://localhost:5173` in a browser — the Dashboard loads with **ControlPlane**, **ManagementPlane**, and **UserAccess** KPI cards populated from the sample data.

You can explore all screens from here. The Object Browser, Classification Templates, and other screens all read from the `PrivilegedEAM/` and `Classification/` directories already in the repo.

> **Stopping here?** If you only want to explore the GUI with sample data, you can stop at this point. The remaining steps connect the GUI to a real Entra tenant and are required before performing an Apply to Entra operation.

### Connect Your Tenant

**4. What this does:** Edits the configuration file to point at your Entra tenant.

Open `EntraOpsConfig.json` in the repo root and update these fields:

```json
{
  "TenantId": "<your-tenant-id>",
  "TenantName": "<your-tenant>.onmicrosoft.com",
  "AuthenticationType": "UserInteractive",
  "ClientId": "<your-app-registration-client-id>"
}
```

> You should see: the file saves without syntax errors. The `TenantId` and `TenantName` fields reflect your actual tenant. (`ClientId` is only required for non-interactive / service principal authentication — leave as-is for interactive sign-in.)

**5. What this does:** Authenticates to your tenant and classifies all privileged identities, writing real data to `PrivilegedEAM/`.

```powershell
Connect-EntraOps -AuthenticationType "UserInteractive" -TenantName "<your-tenant>.onmicrosoft.com"
Save-EntraOpsPrivilegedEAMJson -RbacSystems @("EntraID", "IdentityGovernance", "ResourceApps")
```

> You should see: a browser sign-in prompt for your tenant. After authenticating, the terminal outputs classification progress per RBAC system and writes JSON files to `PrivilegedEAM/`. Refresh the Dashboard at `http://localhost:5173` — the KPI cards now reflect your tenant's actual privileged identity counts.

The `-RbacSystems` parameter accepts one or more of: `EntraID`, `IdentityGovernance`, `ResourceApps`, `Defender`, `DeviceManagement`. The three systems in the example above are the most commonly classified; adjust the list to match your deployment scope.

## Dry-Run / Preview Mode

Before applying any changes to Entra, understand what dry-run mode does.

**What dry-run mode does:** When dry-run is enabled, all Apply to Entra cmdlets run with `-SampleMode`. The cmdlets execute their full logic and produce streaming output, but no changes are written to Entra ID. This is a simulation — your tenant is unaffected.

**Why always dry-run first:** The simulation output shows exactly what EntraOps would create, update, or assign (Administrative Units, Restricted Management AUs, Conditional Access groups). Reviewing this output before a live run prevents unexpected changes.

**How to enable it:** Navigate to the **Apply to Entra** screen in the GUI. In the configuration panel, toggle the **Dry-run mode** switch. The badge **◈ Simulation active** appears to confirm the toggle is on.

**What actions does Apply to Entra run?** The screen lists four actions you can enable individually:

- **Administrative Units** — creates and updates Restricted Management AUs for each classification tier
- **Conditional Access Groups** — creates groups used as targets in Conditional Access policies
- **Unprotected Administrative Units** — identifies AUs that exist outside tier protection
- **ControlPlane Scope** — updates the ControlPlane classification scope

Select all four for a complete simulation, or choose individual actions to preview specific changes.

**6. What this does:** Runs a complete simulated Apply to Entra with no Entra changes.

Navigate to the **Apply to Entra** screen → enable the **Dry-run mode** toggle → select the actions to run → click **Run**.

> You should see: streaming output in the terminal panel with each line prefixed `[DRY RUN]`. When complete, the result panel shows **Dry-run complete — no changes were made**. No Administrative Units or Conditional Access groups were created or modified in your tenant.

---

The guide ends here. You have:
- Viewed the dashboard with sample data (no tenant required)
- Connected a real tenant and classified its identities
- Performed a dry-run Apply to Entra simulation

To continue, see [Feature Walkthroughs](feature-walkthroughs/index.md) for a screen-by-screen guide to each GUI view, or [Configuration Reference](../configuration/configuration-reference.md) for a full description of `EntraOpsConfig.json` fields.

