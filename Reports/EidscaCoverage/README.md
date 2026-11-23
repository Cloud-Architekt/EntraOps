# EntraOps EIDSCA Findings

Static, self-contained web app that evaluates
[EIDSCA (Entra ID Security Config Analyzer)](https://github.com/Cloud-Architekt/AzureAD-Attack-Defense)
checks against the properties already captured by an EntraOps Tenant Governance snapshot - no
backend, database or web server required. Works offline from `file://` or any static web server,
like the other EntraOps Reporting apps.

This app reuses the [Configuration Analyzer](../ConfigurationAnalyzer)'s dataset
(`../ConfigurationAnalyzer/data/configuration-analyzer-data.js`) and shared snapshot/blob parsing
model (`../ConfigurationAnalyzer/js/core.js`) instead of duplicating them - generate the data
there first. The curated EIDSCA control catalog (`js/eidsca-controls.js`) is a fixed reference
dataset checked into this repository, not a generated build artifact.

## What it shows

Pick a detailed snapshot and see, per EIDSCA control area, which checks pass/fail/are informational
based on the resource content the Tenant Governance Snapshot already captured, plus which EIDSCA
checks are not yet evaluable because their Graph endpoint has no matching UTCM resource type.
Status and severity pills filter the results and show how many checks each would match, counted like the
tiles: the checks of an area whose resource type is not captured (or whose content is not embedded) count as
*Unknown*, and its gap row is listed only under the filters it matches (never under *Passing*). Failing checks are red,
as failed checks in the other reports. The area navigation dot is red for failing, grey for unknown, green for passing
and blue for an area with informational checks only. Every control area collapses to its summary, and the collapsed
areas are remembered in the browser.

## Finding exclusions

Set `ConfigurationAnalyzer.EidscaExcludedFindings` to an array of EIDSCA check IDs, such as
`["EIDSCA.AP01"]`, to omit those findings from the generated report. It defaults to `[]`, which
reports every supported check. Exclusions are applied before the dashboard counts and grouped
finding areas are rendered.

## Refresh the data

```powershell
Import-Module ./EntraOps -Force
New-EntraOpsTenantGovernanceConfigurationAnalyzerData
```

or as part of `New-EntraOpsReportingData`. See the
[Configuration Analyzer README](../ConfigurationAnalyzer/README.md) for parameters.
