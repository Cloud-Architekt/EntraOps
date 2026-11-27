# EntraOps Conditional Access Analysis

Static, self-contained web app that visualizes the **Conditional Access policy set** of a
captured EntraOps Tenant Governance snapshot - no backend, database or web server required.
Works offline from `file://` or any static web server, like the other EntraOps Reporting apps.

This app reuses the [Configuration Analyzer](../ConfigurationAnalyzer)'s dataset
(`../ConfigurationAnalyzer/data/configuration-analyzer-data.js`) and shared snapshot/blob parsing
model (`../ConfigurationAnalyzer/js/core.js`) instead of duplicating them - generate the data
there first.

## What it shows

- **CA Policy Flow** - a Sankey visualization of how the Conditional Access policy set is
  configured: `Assignments → Policy → Target resources → Network → Conditions → Grant controls`.
  Columns can be toggled, and every aspect can be filtered: policy state (one or more states),
  grant control, client app type and assignment access level are pills that show how many
  policies each would match;
  snapshot, assignment, target resource, network and condition are dropdowns next to the free-text
  search across users/groups/roles/apps/locations. Click any node to trace
  every policy path through it; click a policy node to open its full detail (including exclusions
  and session controls). Link colors separate blocked (red), controlled (green), session-only
  (blue), report-only (dashed amber) and disabled/uncontrolled (grey) paths, so access paths
  without enforced Conditional Access coverage stand out.
- **CA Coverage Gaps** - heuristics over the policy set of the selected snapshot: policies stuck
  in report-only/disabled state, legacy authentication not blocked, missing MFA coverage for all
  users or privileged roles, missing risk-based/device-based policies, guest coverage, client app
  types not covered by any all-user policy, and the accumulated exclusion surface.

A `#flow=<policyId>` deep link (case-insensitive) traces the policy and clears the filters that would hide it.
Without the EAM Dashboard dataset the assignment access level pills can't count users and roles, and a note says so.

### Finding exclusions

Set `ConfigurationAnalyzer.ConditionalAccessAnalysisExcludedFindings` to an array of finding
IDs to omit from the report. Supported IDs are `policyNotEnforced`, `legacyAuthentication`,
`allUserMfa`, `privilegedRoleControls`, `riskBasedPolicies`, `deviceControls`, `guestCoverage`,
`clientAppCoverage`, and `exclusionSurface`. It defaults to `[]`, which reports every finding.

## Refresh the data

```powershell
Import-Module ./EntraOps -Force
New-EntraOpsTenantGovernanceConfigurationAnalyzerData
```

or as part of `New-EntraOpsReportingData`. See the
[Configuration Analyzer README](../ConfigurationAnalyzer/README.md) for parameters.
