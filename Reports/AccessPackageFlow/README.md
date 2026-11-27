# EntraOps Access Package Flow

Static, self-contained web app that visualizes Entra ID Governance **entitlement management**
(access packages) from a captured EntraOps Tenant Governance snapshot as a filterable Sankey flow
- no backend, database or web server required. Mirrors the
[Conditional Access Analysis](../ConditionalAccessAnalysis) app's CA Policy Flow.

This app reuses the [Configuration Analyzer](../ConfigurationAnalyzer)'s dataset
(`../ConfigurationAnalyzer/data/configuration-analyzer-data.js`) and shared snapshot/blob parsing
model (`../ConfigurationAnalyzer/js/core.js`) instead of duplicating them - generate the data
there first (the entitlement management resource types must be included in
`TenantGovernanceSnapshot.ResourcesToInclude`).

## What it shows

- **Access Package Flow** - `Requestor scope → Assignment policy → Access package → Target
  resource role`. Every requestor, approver and target resource that resolves to a known object id
  is cross-referenced against the optional [EAM Dashboard](../EamDashboard) dataset to show its
  access tier (Control Plane / Management Plane / User Access), the same tier coloring used across
  EntraOps Reporting. EntraOps PowerShell (`New-EntraOpsReportFindingData`) resolves these tiers and
  writes them with the risk flags; the report shows them as written, and without them it shows the
  policies without tiers and risk flags.
  - A requestor/approver group not itself classified by EntraOps is resolved via its transitive
    membership instead (same mechanism as the Configuration Analyzer's Privileged Assets section) -
    a member without any EntraOps classification defaults to User Access, and a group with zero
    resolvable members is User Access overall.
  - A target resource is classified by the access it grants: the more privileged of its Identity
    Governance resource role scope classification and its own EntraOps classification. A target
    group is never resolved via its members - the other access of its current members is not
    granted by the access package. Its members are still listed when you click it.
  - A target group without any role assignment (not in the Privileged EAM data) takes the tier
    declared for it, in the order of the Privileged EAM classification: the Group filters of the
    Alternate Tier Level Attributes (`AlternateObjectTierLevelAttributes.Group`), else the Object
    Classification File (`ObjectClassificationFile` of `EntraOpsConfig.json`); both are read by
    `New-EntraOpsAccessPackageFlowData`. Without a declared tier it is
    **Unclassified**: such groups often control access outside of role-based access control
    (Conditional Access exclusions, app assignments, Intune targeting), which EntraOps cannot see. An
    ⓘ info bubble next to the target explains which of the two applies.
  - The policy detail is classified by the most privileged tier of its target resources (what the
    policy grants). Its **Approval tier** is the tier the approval is protected for, compared like
    the approver risk flag: an approver group counts as its least protected member, a stage as its
    least protected approver, and a multi-stage approval as its strongest stage.
  - A broad "any directory member can request" requestor scope is classified as User Access too
    (rather than left unclassified), since it isn't a specific privileged identity.
  - Hover a requestor/approver/target chip (in the policy detail panel) or a Sankey node for a
    tooltip explaining *why* it got that tier (direct EntraOps classification, resolved via group
    membership, defaulted, or broad self-service scope). Use the **Requestor access level** filter
    to show only policies whose requestor scope resolves to a given tier.
  - A group-resolved entry additionally shows a **View members** button/node click that opens a
    panel listing every resolved member and its individual access tier.
- **Risk Flags** - policies where:
  - approval is **not required** to obtain a Control Plane / Management Plane resource on request;
  - **any directory member** (or external user) can request a Control Plane / Management Plane
    resource without a narrower requestor scope (both only for policies that accept requests, not for
    policies that only administrators assign);
  - the **approver(s)** are classified at a *lower* privilege tier than the resource being
    approved;
  - (when the optional assignment dataset below is generated) a **currently assigned** principal
    is classified at a *higher* privilege tier than the policy's own approver(s);
  - a Control Plane / Management Plane group or application of the access package has **access
    drift** in the access drift report of Microsoft Entra ID Governance (Access Guardian > Reports >
    Access Drift): members or application role assignments without an access package assignment
    (`unauthorizedAccess`, access granted outside of governance), or access package assignments
    without the expected membership or application role assignment (`missingAccess`, warning).
    `New-EntraOpsAccessPackageFlowData` reads the drift (Microsoft Graph beta, preview; needs
    Microsoft Entra ID Governance or Microsoft Entra Suite and `EntitlementManagement.Read.All`). The
    drift is the current state, refreshed by Microsoft about once a day, so these flags are shown for
    the newest snapshot only.
  - a target group of the access package is **unclassified** (`unclassifiedTarget`, information,
    EO.2005): no role assignment and no declared tier (Group filter or Object Classification File). Informational flags
    are listed with the risk flags but don't mark the policy as flagged.
- Click a policy node in the Sankey to open its full detail: applicable (requestor) scope,
  approver(s), target resource role(s), currently assigned principals (if generated) and
  duration/extension/access-review settings.
- Filter policies by catalog, target resource type (Groups, Azure RBAC, API permissions, Directory
  roles or Other), approval requirement and fixed expiration. Use Search for individual access packages or
  target resource names instead of loading high-cardinality selectors. The filters with few values
  (approval, expiration, requestor and group member access level, target resource type) are pills that
  show how many policies match each value together with the other filters; snapshot, catalog and risk
  flag stay dropdowns next to the search field. The groups of the Risk Flags list collapse by their title
  and are remembered in the browser.

### Risk flag exclusions

Set `Findings.ExcludedRules` to rule IDs or `AccessPackageFlow.<key>` (`noApproval`, `broadRequestor`,
`approverLowerTier`, `assignedMorePrivileged`, `unauthorizedAccess`, `missingAccess`, `unclassifiedTarget`) to omit those findings, also in the
**Configuration Wizard**. It defaults to `[]`, which reports every Access Package Flow risk flag.
`ConfigurationAnalyzer.AccessPackageFlowExcludedRiskFlags` of EntraOps 1.1.0 is still read as a deprecated alias.

The risk flags are EntraOps finding rules with the keys above (`Get-EntraOpsFindingRule -Area
AccessPackageFlow`). `New-EntraOpsReportFindingData` evaluates them in PowerShell for every snapshot
with embedded content and writes `data/access-package-flow-findings.js`; `New-EntraOpsReportingData` runs it
after the report data. The report shows only these risk flags and tiers: without this file, or when it was evaluated
from other report data than the report shows, it shows one notice at the top of the page that the risk flags were
not evaluated, and the flow details show *Tier not evaluated* instead of a "no risk" border
(`../shared/flow-findings.js`, shared with the PIM Request Flow). Run
`New-EntraOpsReportFindingData` again after regenerating single report data. `Invoke-EntraOpsFindingEvaluation` returns the results
of the newest snapshot outside the report, for example for the
[EntraOps Maester Pack](../../Integrations/Maester/README.md).

Each risk flag shows its check under the text: the rule ID (linked to the check in the Privileged Assets Findings
view, with description and remediation) and the rule title; the risk flag filter is labelled by these rules, and the
exports have the rule ID, rule title and exception state. A flag accepted by a finding exception (*Risk accepted
until …* or *Dismissed*) is listed muted and does not count as flagged. Without evaluated findings the requestor access
level pills are hidden, the risk tile is no filter and the exports write *not evaluated*; the notice names the dataset
that differs, with both generation times, and the excluded checks. A group approver shows the tier it is protected as
(its least protected member) next to its access tier. A `#flow=<policyId>` deep link (case-insensitive) clears the
filters that would hide the policy.

## Requestor/approver group resolution ("access package cannot be resolved")

The Tenant Governance Snapshot's captured `AADEntitlementManagementAccessPackageAssignmentPolicy`
resource never serializes the object `id` of a `groupMembers` requestor/approver subject (only
`odataType`/`IsBackup`) - a M365DSC/UTCM capture limitation, not something fixable client-side.
`New-EntraOpsAccessPackageFlowData` recovers the real id with a small live Microsoft Graph query
against the assignment policies themselves and, when `-ResolveRequestorApproverTiers` is enabled
(defaults to the same `ConfigurationAnalyzer.ResolveGroupMembersForPrivilegedAssets` setting as the
Configuration Analyzer), resolves that group's tier and member breakdown too. Without this, a
`groupMembers` subject whose id was never captured shows as "Group members (id not captured by
snapshot)".

The same enrichment also restores a requestor scope type that a snapshot serialized as `Unknown`.
For example, `AllExistingDirectorySubjects` is shown as users, service principals, and agent
identities in the directory being eligible to request access.

## Refresh the data

The Sankey itself (requestor/policy/package/target) needs only the Configuration Analyzer dataset:

```powershell
Import-Module ./EntraOps -Force
New-EntraOpsTenantGovernanceConfigurationAnalyzerData
```

Complete target resource names and resource-role classifications, the optional "currently
assigned" enrichment, the "assigned principal more privileged than approver" flag, and
requestor/approver group id recovery + tier resolution additionally need live Microsoft Graph
queries (the Tenant Governance Snapshot has no resource type for actual assignments, never
captures a `groupMembers` subject's group id, and can serialize a target's root scope instead of
its resource name):

```powershell
New-EntraOpsAccessPackageFlowData -ResolveRequestorApproverTiers $true
```

Both run as part of `New-EntraOpsReportingData`, which then evaluates the risk flags
(`New-EntraOpsReportFindingData`) as its last step. The generated
`data/access-package-assignments-data.js` is tenant-specific and ignored by git, same as the other
generated reporting datasets - run `Remove-EntraOpsReportingData` to remove it.
