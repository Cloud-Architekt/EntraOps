---
gsd_state_version: 1.0
milestone: v1.3
milestone_name: Updated UI Documentation
status: active
last_updated: "2026-04-05T00:00:00Z"
last_activity: 2026-04-05 -- Milestone v1.3 started
progress:
  total_phases: 0
  completed_phases: 0
  total_plans: 0
  completed_plans: 0
  percent: 0
---

# Project State

## Project Reference

See: .planning/PROJECT.md (updated 2026-04-05 after v1.3 start)

**Core value:** A user who has run `Save-EntraOpsPrivilegedEAMJson` can open a browser and immediately understand who holds ControlPlane access in their tenant — without writing a KQL query, opening Azure Portal, or reading raw JSON.
**Current state:** v1.3 DEFINING REQUIREMENTS. Run `/gsd-plan-phase [N]` after roadmap is created.

## Current Position

Phase: Not started (defining requirements)
Plan: —
Status: Defining requirements
Last activity: 2026-04-05 — Milestone v1.3 started

## v1.2 Phase Overview

| Phase | Goal | Requirements | Status |
|-------|------|--------------|--------|
| 9. Exclusions Management | Admins manage Global.json from browser | EXCL-01, EXCL-02, EXCL-03 | ✓ Complete (2026-03-31) |
| 10. Inline Exclude Actions | Exclude objects from existing screens | EXCL-04, EXCL-05 | ✓ Complete (2026-04-02) |
| 11. Implementation Workflow | Apply to Entra with confirmation + SSE | IMPL-01–04, IMPL-06–07 | ✓ Complete (2026-04-04) |
| 12. Dry-run / Preview Mode | -SampleMode simulation toggle | IMPL-05 | ✓ Complete (2026-04-04) |

**By Phase:**

| Phase | Plans | Total | Avg/Plan |
|-------|-------|-------|----------|
| 02 (partial) | 2/5 | ~50 min | ~25 min |
| 11 | 2 | - | - |

**Recent Trend:**

- Last 5 plans: 02-01 (25 min), 02-02 (25 min)
- Trend: Consistent

*Updated after each plan completion*
| Phase 02-classification-template-editor P03 | 20 | 2 tasks | 4 files |
| Phase 02-classification-template-editor P05 | 5 | 2 tasks | 1 files |
| Phase 04-connect-classify-setup P04 | 45 | 1 tasks | 1 files |
| Phase 05 P04 | 20 | 2 tasks | 5 files |
| Phase 08-object-reclassification-screen P01 | 2 | 3 tasks | 3 files |
| Phase 08-object-reclassification-screen P02 | 8 | 2 tasks | 2 files |
| Phase 08-object-reclassification-screen P03 | 2 | 2 tasks | 2 files |

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
