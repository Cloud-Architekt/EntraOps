# EntraOps PIM Request Flow

Static, self-contained web app that visualizes Entra ID **Privileged Identity Management (PIM)
role settings** from a captured EntraOps Tenant Governance snapshot as a filterable Sankey flow -
no backend, database or web server required. Mirrors the
[Conditional Access Analysis](../ConditionalAccessAnalysis) app's CA Policy Flow and the
[Access Package Flow](../AccessPackageFlow) app.

This app reuses the [Configuration Analyzer](../ConfigurationAnalyzer)'s dataset
(`../ConfigurationAnalyzer/data/configuration-analyzer-data.js`) and shared snapshot/blob parsing
model (`../ConfigurationAnalyzer/js/core.js`) instead of duplicating them - generate the data there
first. That dataset already embeds every captured resource type generically, including
`microsoft.entra.roleSetting` and `microsoft.entra.roleDefinition` (both are included in the
default `TenantGovernanceSnapshot.ResourcesToInclude`), so **no dedicated data generator is needed
for this app**.

## What it shows

Every captured `microsoft.entra.roleSetting` resource (one per Entra ID directory role) is expanded
into up to three **assignment paths** - the three ways a principal ends up holding the role, each
governed by its own slice of PIM role settings:

- **Activate eligible role** - the self-service PIM request: an eligible member activates the role
  for a limited time, optionally requiring MFA, justification, a ticket number, an authentication
  context and/or approval (`ActivationReq*` / `ApprovaltoActivate` / `ActivateApprover` /
  `AuthenticationContext*`).
- **Assign eligible role** - an administrator grants a principal eligibility for the role
  (`ElegibilityAssignmentReq*` / `ExpireEligibleAssignment` /
  `PermanentEligibleAssignmentisExpirationRequired`).
- **Assign active role** - an administrator grants a principal the role directly as an active
  (non-eligible) assignment (`AssignmentReq*` / `ExpireActiveAssignment` /
  `PermanentActiveAssignmentisExpirationRequired`).

The Sankey clusters each of these into **Role &rarr; Assignment path &rarr; Requirement &rarr;
Approval &rarr; Notification**:

- **Role** - colored by access tier (Control Plane / Management Plane / User Access), resolved from
  the generated Classification Explorer role catalog and enriched by the optional [EAM Dashboard](../EamDashboard) dataset. Specifically, every privileged
  object's `roleAssignments[].classification[]` already carries the Enterprise Access Model tier of
  every Entra ID role assignment (computed by the EntraOps classification engine) - reusing that
  avoids re-implementing the role-action classification rule engine
  (`Classification_AadResources.json` matching). EntraOps PowerShell (`New-EntraOpsReportFindingData`)
  resolves the tiers and writes them with the risk flags; the report shows them as written. Use the
  **Role access level** filter to show only roles at a given tier.
- **Requirement** - which of MFA, justification, a ticket number or an authentication context is
  required for that path (or "No additional requirement"). Use the **Requirement** filter to find
  every role/path missing a specific control.
- **Approval** - whether activation requires approval, and (in the detail panel) who the configured
  approver(s) are, each resolved to their own access tier (`ActivateApprover` entries are plain
  UPNs, resolved via the same EAM Dashboard cross-reference).
- **Notification** - which audiences (admin, approver, requestor/assignee) are notified for that
  path, derived from the matching `Eligible*`/`EligibleAssignment*`/`Active*Notification*` settings.

Click a node to trace it (filter the whole diagram down to flows touching it); click an **assignment
path** node specifically to open its full detail panel (role description, requirement(s), tiered
approver list, notifications, activation duration/expiration and any risk flags). Click the
background to clear the trace.

The filters with few values (**Assignment path**, **Role access level**, **Activation approval**) are
pills that show how many assignment paths match each value together with the other filters; the
snapshot, **Requirement** and **Risk flag** filters stay dropdowns next to the search field. Several
assignment paths can be selected at once (none selected shows all), and **Columns** switches the
columns of the flow. The groups of the Risk Flags list collapse by their title and are remembered in
the browser.

### Risk Flags

| Risk flag ID           | Detected condition                                                                                                         |
| ---------------------- | -------------------------------------------------------------------------------------------------------------------------- |
| `noMfaActivation`      | A Control Plane or Management Plane role can be activated without MFA and without an authentication context.               |
| `noApprovalActivation` | A Control Plane role can be activated without approval.                                                                    |
| `approverNotEnforced`  | `ActivateApprover` has entries while `ApprovaltoActivate` is disabled, so the approver list has no effect.                 |
| `approverLowerTier`    | An activation approver has a lower access tier than the role being activated.                                              |
| `approverUnclassified` | An activation approver could not be resolved against the EAM Dashboard data, so its tier cannot be compared with the role. |
| `authContextMissing`   | An authentication context is required but no context is configured.                                                        |
| `permanentEligible`    | A permanent, non-expiring eligible assignment is allowed for a privileged role.                                            |
| `permanentActive`      | A permanent, non-expiring active assignment is allowed for a privileged role.                                              |
| `noMfaActiveAssign`    | A privileged role can be directly assigned as Active without MFA at assignment time.                                       |

The risk flags are EntraOps finding rules with the IDs above as keys (`Get-EntraOpsFindingRule -Area
PimRequestFlow`). `New-EntraOpsReportFindingData` evaluates them in PowerShell for every snapshot with
embedded content and writes `data/pim-request-flow-findings.js`; `New-EntraOpsReportingData` runs it after
the report data. The report shows only these risk flags and tiers: without this file, or when it was evaluated from
other report data than the report shows, it shows one notice at the top of the page that the risk flags were not
evaluated, and the flow details show *Tier not evaluated* instead of a tier or a "no risk" border
(`../shared/flow-findings.js`, shared with the Access Package Flow). Run
`New-EntraOpsReportFindingData` again after regenerating single report data. `Invoke-EntraOpsFindingEvaluation` returns the results
of the newest snapshot outside the report, for example for the
[EntraOps Maester Pack](../../Integrations/Maester/README.md).

Each risk flag shows its check under the text: the rule ID (it opens the check, with description and remediation,
in the Privileged Assets Findings view) and the rule title. The risk flag filter is labelled by these rules, and the
exports have the rule ID, rule title and exception state of every flag. A flag that a finding exception accepts
(Finding Exceptions File, *Risk accepted until …* or *Dismissed*) is listed muted with its state and expiry and does
not count as flagged. Without evaluated findings the role access level pills are hidden (they would count every role
as Unclassified), the metric tiles are no filters, and the exports write *not evaluated* instead of an access level and
risk flags; the notice names the dataset that differs, with both generation times, and the excluded checks (tiles
of excluded checks say *excluded*). The approver of a flow shows its access tier and, when its least protected member
is classified lower, the tier it is protected as (the tier the approver check compares). The review status of a flag
(*Open*, *Reviewed: accepted*, *Reviewed: remediated*) is saved in the browser only; it is no finding exception.

A `#flow=<roleId>|<path>` deep link (case-insensitive) opens the path in the newest snapshot that has it and clears
the filters that would hide it.

Set `Findings.ExcludedRules` to rule IDs or `PimRequestFlow.<key>` to omit specific risk flags (also in the
**Configuration Wizard**). It defaults to `[]`, so all risk flags are reported. `ConfigurationAnalyzer.PimRequestFlowExcludedRiskFlags`
of EntraOps 1.1.0 is still read as a deprecated alias.

## Refresh the data

```powershell
Import-Module ./EntraOps -Force
New-EntraOpsTenantGovernanceConfigurationAnalyzerData
```

Optionally, also generate the EAM Dashboard dataset so roles and approvers are enriched with their
access tier and tier-dependent risk flags can be computed:

```powershell
New-EntraOpsPrivilegedEamDashboardData
```

Then evaluate the role tiers and risk flags (`New-EntraOpsReportFindingData`); without them, the report
shows the role settings without tiers and risk flags. All of them run as part of
`New-EntraOpsReportingData`, which evaluates the role tiers and risk flags as its last step.
