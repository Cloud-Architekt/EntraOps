# Phase 14: Getting Started Guide - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-04-08
**Phase:** 14-getting-started-guide
**Areas discussed:** Prerequisites scope, Dashboard reachability path, Step depth and format, Dry-run section structure

---

## Prerequisites Scope

| Option | Description | Selected |
|--------|-------------|----------|
| Tools only | Node.js 22+, PS 7+, EntraOps PS module. Fork/clone assumed. | |
| Tools + Azure access | Tools above plus Global Admin, Az + Microsoft.Graph PS modules. | |
| Full zero-to-hero | Start from fork: fork, clone, install Node deps, PS tools, Azure permissions. | ✓ |
| Lean: fork, clone, Node 22, PS 7, module import | No Az/Graph separate. | |
| Full: all deps explicit including Az/Graph/admin role | Az + Microsoft.Graph + Global Admin called out explicitly. | ✓ |
| Checklist with install links | Each prerequisite item links to install source. | ✓ (Claude's pick) |

**User's choice:** "You pick, prioritise user simplicity" → Full list with install links.
**Notes:** Node.js version resolved as 22+ (not 20+ per GS-02) because STATE.md global decisions note v20 EOL March 2026.

---

## Dashboard Reachability Path

| Option | Description | Selected |
|--------|-------------|----------|
| Sample data: immediate dashboard | npm run dev → PrivilegedEAM/ JSON → dashboard visible immediately. | ✓ (Claude's pick) |
| Live tenant: full Connect & Classify first | Requires real tenant + Global Admin before dashboard is visible. | |
| Dual track: quick-start + full live tenant | Both paths in one guide. | |

**User's choice:** "You pick, prioritise user simplicity" → Sample data path for quick dashboard, then optional Connect your tenant section for dry-run Apply.
**Notes:** Two-stage approach: quick dashboard first (no PS needed), then connect section required before dry-run Apply step. Live tenant setup for deeper feature use belongs in Phase 15 Connect Wizard walkthrough.

---

## Step Depth and Format

| Option | Description | Selected |
|--------|-------------|----------|
| Minimal: command + outcome | Command block + "You should see" callout only. | |
| Detailed: annotated command, sample output, outcome prose | Full inline comments + expected output code block + prose outcome. | |
| Middle: brief intent + command + outcome | "What this does:" line + command + "You should see…" | ✓ (Claude's pick) |

**User's choice:** "You pick, prioritise user simplicity" → Middle format.
**Notes:** Annotate only params that could trip up a reader (env-specific values like TenantId). No exhaustive annotation.

---

## Dry-Run Section Structure

| Option | Description | Selected |
|--------|-------------|----------|
| Explain concept, guide ends without Apply step | Concept-only section; reader knows about dry-run but doesn't perform it. | |
| Explain concept, then guide ends with dry-run Apply step | Standalone section explains concept, then final numbered step performs dry-run Apply. | ✓ (Claude's pick) |

**User's choice:** "You pick, prioritise user simplicity" → Guide ends with dry-run Apply step.
**Notes:** Satisfies STATE.md "terminates at a dry-run Apply" + SC4 (dry-run explained before Apply step is described). The concept section comes before the Apply step description, satisfying GS-03.

---

## Claude's Discretion

- Exact heading wording and command formatting
- Callout/note style for "you should see" confirmations
- Exact npm path invocation (`cd gui && npm install && npm run dev`)
- Optional note in "Connect your tenant" section for readers who only want the quick dashboard

## Deferred Ideas

None.
