---
gsd_state_version: 1.0
milestone: v1.3
milestone_name: Updated UI Documentation
status: verifying
last_updated: "2026-04-09T15:40:17.342Z"
last_activity: 2026-04-09
progress:
  total_phases: 6
  completed_phases: 4
  total_plans: 8
  completed_plans: 8
  percent: 100
---

# Project State

## Project Reference

See: .planning/PROJECT.md (updated 2026-04-05 after v1.3 start)

**Core value:** A user who has run `Save-EntraOpsPrivilegedEAMJson` can open a browser and immediately understand who holds ControlPlane access in their tenant — without writing a KQL query, opening Azure Portal, or reading raw JSON.
**Current state:** v1.3 ROADMAP CREATED. Run `/gsd-plan-phase 13` to begin.

## Current Position

Phase: 17
Plan: Not started
Status: Phase complete — ready for verification
Last activity: 2026-04-09

Progress: `█░░░░░░░░░` 17% (1/6 phases complete, 3/3 plans done)

## v1.3 Phase Overview

| Phase | Goal | Requirements | Status |
|-------|------|--------------|--------|
| 13. Documentation Foundation & Concepts | Navigable docs hub + locked shared vocabulary | DOCS-01, CONC-01, CONC-02 | Not started |
| 14. Getting Started Guide | Zero-to-dashboard guide for new security admins | GS-01, GS-02, GS-03 | ✓ Complete (2026-04-08) |
| 15. Feature Walkthroughs & Screenshots | 10-screen walkthroughs with real localhost:5173 screenshots | FEAT-01, FEAT-02, FEAT-03, DOCS-02 | Not started |
| 16. Configuration & Architecture Reference | EntraOpsConfig.json reference + data-flow overview | CONF-01, CONF-02, ARCH-01 | Not started |
| 17. Troubleshooting / FAQ | 10+ symptom-first troubleshooting entries | TRBL-01 | Not started |
| 18. Root Updates & Cross-Link Audit | Root README Documentation section + verified hub nav | ROOT-01 | Not started |

## v1.2 Phase Overview (for reference)

| Phase | Goal | Requirements | Status |
|-------|------|--------------|--------|
| 9. Exclusions Management | Admins manage Global.json from browser | EXCL-01, EXCL-02, EXCL-03 | ✓ Complete (2026-03-31) |
| 10. Inline Exclude Actions | Exclude objects from existing screens | EXCL-04, EXCL-05 | ✓ Complete (2026-04-02) |
| 11. Implementation Workflow | Apply to Entra with confirmation + SSE | IMPL-01–04, IMPL-06–07 | ✓ Complete (2026-04-04) |
| 12. Dry-run / Preview Mode | -SampleMode simulation toggle | IMPL-05 | ✓ Complete (2026-04-04) |

## Accumulated Context

### Decisions

Decisions are logged in PROJECT.md Key Decisions table. Key decisions affecting Phase 1:

- **Tailwind v4** (not v3): CSS-first config, `@theme` block replaces `tailwind.config.js` — different setup than most tutorials
- **Express v5** (not v4): async middleware, different error handler signature
- **Zod v4** (not v3): current npm default; 14× faster; API is slightly different from v3 examples
- **Node.js 22 minimum**: v20 EOL as of March 2026
- **React Router v7 required**: PRD omitted this; needed for OBJ-04 (URL-reflected filter state) — must be in Phase 1
- **shadcn/ui instead of Fluent UI v9**: Fluent's Griffel CSS-in-JS conflicts with Tailwind; Fluent aesthetic via CSS custom properties in `@theme` block
- **Server-side pagination**: browser never receives the full dataset; all filtering/slicing in Express — required for large tenants
- **Atomic template writes**: temp file → rename pattern to avoid partial writes on crash
- [Phase 02-classification-template-editor]: DiffDialog cosmetic overflow is non-blocking: affects large templates in small windows, captured as polish todo
- [Phase 02-classification-template-editor]: All 7 TMPL requirements human-verified in browser before Phase 2 closed
- [Phase 04-connect-classify-setup]: Each pwsh spawn is isolated: Az/MgGraph tokens must be forwarded to classify process via AlreadyAuthenticated env vars
- [Phase 04-connect-classify-setup]: Import-Module and subsequent cmdlet calls must be separated by semicolon — missing separator causes cmdlet name to be parsed as Import-Module argument
- [Phase 05]: useCompare aggregates 5 parallel compare API calls (per-system endpoint requires rbac param)
- [Phase 08-01]: Import Select from 'radix-ui' unified package consistent with all other ui/ components
- [Phase 08-object-reclassification-screen]: fs.mkdir recursive guard in POST protects against missing Classification/ directory

### v1.2 Context

- **Global.json format**: `[{ "ExcludedPrincipalId": ["guid1", "guid2", ...] }]` — array with one object; reads/writes must preserve this structure
- **Name resolution source**: `PrivilegedEAM/**/*.json` files — scan all JSON files and match on GUID fields to resolve display names
- **Implementation cmdlets on allowlist**: Update-EntraOpsPrivilegedAdministrativeUnit, Update-EntraOpsPrivilegedConditionalAccessGroup, Update-EntraOpsPrivilegedUnprotectedAdministrativeUnit, Update-EntraOpsClassificationControlPlaneScope
- **Dry-run flag**: `-SampleMode` parameter on all 4 implementation cmdlets
- **SSE streaming**: pattern established in Phase 4 (Connect wizard) — reuse same SSE infrastructure for implementation runner

### v1.3 Context

- **Docs location**: `docs/` at repo root (not `gui/docs/`) — reads on GitHub, no static site generator
- **10 GUI screens**: Dashboard, Object Browser, Template Editor, PowerShell Runner, Connect & Classify, Git History, Settings, Reclassify, Exclusions, Apply to Entra
- **Screenshot source**: real captures from `localhost:5173` live app; stored as committed PNGs under `docs/assets/screenshots/<screen>/`
- **Concepts before content**: glossary (CONC-01, CONC-02) must be authored in Phase 13 before any feature walkthrough references terminology
- **Config reference source**: generate from the actual committed `EntraOpsConfig.json` — not from memory — to avoid field/default drift (research pitfall D5)
- **Getting-started ends at dry-run**: guide terminates at a dry-run Apply, not a live Entra write (GS-03)
- **Phase 15 dependency**: requires the live app running at localhost:5173 to capture real screenshots (FEAT-02)
