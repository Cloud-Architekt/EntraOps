# EntraOps GUI

## Current State

**Active: v1.3 Updated UI Documentation** 🚧 (started 2026-04-05)

**Shipped: v1.2 Self-Service Implementation Workflow** ✅ (2026-04-04)

The GUI is fully functional and shipped through three milestones. A user who forks EntraOps and runs `Save-EntraOpsPrivilegedEAMJson` can then `cd gui && npm install && npm run dev` to get a working local browser dashboard with:
- Tier dashboard (ControlPlane / ManagementPlane / UserAccess KPI cards, applied + suggested counts, RBAC breakdown, PIM chart)
- Filterable/sortable/paginated object browser with URL-bookmarkable state, detail panel, and dashed computed-tier badge for unclassified objects
- Safe in-browser classification template editor with Zod validation and diff preview
- PowerShell command runner (13 allowlisted cmdlets, real-time SSE streaming)
- Connect & Classify wizard (device code auth → classification → dashboard)
- Git change history browser (commit list, structured diffs, any-two-commit compare)
- Settings page for `EntraOpsConfig.json` editing
- Object Reclassification screen — inline tier overrides with atomic persistence to classification config files
- **Exclusions Management** — dedicated Exclusions page (sidebar nav) with display-name resolution, click-to-copy, and Remove; inline Exclude actions on Object Browser and Reclassify screens
- **Apply to Entra workflow** — full 4-state implementation workflow (select → confirm → SSE stream → outcomes); 4 action toggles (AU, CA Groups, Unprotected AUs, ControlPlane Scope); real-time SSE log; per-cmdlet pass/fail summary
- **Dry-run / Preview Mode** — -SampleMode toggle on Apply screen; amber visual indicators across all 4 states; server-side history exclusion guard

See [.planning/milestones/v1.2-ROADMAP.md](.planning/milestones/v1.2-ROADMAP.md) for full v1.2 milestone archive.

## Current Milestone: v1.3 Updated UI Documentation

**Goal:** Create a comprehensive `docs/` folder covering the EntraOps GUI for both end users (security admins) and contributors (developers).

**Target deliverables:**
- Getting started / installation guide (fork → run `Save-EntraOpsPrivilegedEAMJson` → `npm run dev` → open browser)
- Feature walkthrough with screenshot references for each screen
- Troubleshooting / FAQ
- Configuration reference (EntraOpsConfig.json, API endpoints, environment variables)
- Architecture / integration overview (GUI ↔ PowerShell module data flow)
- Separate sections for end users and contributors

## What This Is

EntraOps GUI is a locally-hosted web application that gives security administrators a visual interface for the EntraOps PowerShell module. It enables users to explore classified privileged identity data, edit tier classification rules, trigger automation, and track changes over time — all without leaving the repo or requiring a Microsoft Sentinel workspace. It ships in the same repository so any user who forks EntraOps gets the GUI automatically.

## Core Value

A user who has run `Save-EntraOpsPrivilegedEAMJson` can open a browser and immediately understand who holds ControlPlane access in their tenant — without writing a KQL query, opening Azure Portal, or reading raw JSON.

## Requirements

### Validated (v1.0)

All 29 v1 requirements delivered. See [.planning/milestones/v1.0-REQUIREMENTS.md](.planning/milestones/v1.0-REQUIREMENTS.md) for full traceability.
Additionally delivered 17 originally-deferred v2 requirements (RUN-01–06, CONN-01–04, HIST-01–04, SETT-01–03).

### Validated (v1.1)

- ✓ DASH-01: Dashboard applied + suggested tier counts side-by-side — v1.1
- ✓ DASH-02: Computed tier derived from lowest `AdminTierLevel` in `Classification[]` — v1.1
- ✓ DASH-03: Dashboard "Applied" / "Suggested" labels clearly distinguish counts — v1.1
- ✓ OBJ-01: Unclassified objects show computed tier in Object Browser — v1.1
- ✓ OBJ-02: Computed tier badge uses dashed outline style — v1.1
- ✓ OBJ-03: Applied-tier objects unchanged in Object Browser — v1.1
- ✓ RECL-01: Object Reclassification screen navigable from sidebar — v1.1
- ✓ RECL-02: Per-row inline tier override select — v1.1
- ✓ RECL-03: Pending overrides highlighted with amber dirty-row style — v1.1
- ✓ RECL-04: Save All persists overrides to classification config files atomically — v1.1
- ✓ RECL-05: Discard resets pending overrides with no server calls — v1.1

### Validated (v1.2)

- ✓ EXCL-01: Dedicated Exclusions page navigable from sidebar — v1.2
- ✓ EXCL-02: Exclusions page shows resolved display names (not raw GUIDs) — v1.2
- ✓ EXCL-03: Remove exclusion persists deletion to Global.json atomically — v1.2
- ✓ EXCL-04: One-click Exclude from Object Browser, persists to Global.json — v1.2
- ✓ EXCL-05: One-click Exclude from Reclassify screen, persists to Global.json — v1.2
- ✓ IMPL-01: "Apply to Entra" screen navigable from sidebar — v1.2
- ✓ IMPL-02: Implementation screen reachable via CTA from Object Browser and Reclassify — v1.2
- ✓ IMPL-03: Pre-run confirmation screen with cmdlets + parameters — v1.2
- ✓ IMPL-04: Select any combination of 4 implementation actions — v1.2
- ✓ IMPL-05: Dry-run / preview mode with -SampleMode, no Entra writes, history guard — v1.2
- ✓ IMPL-06: Real-time SSE streaming progress log during implementation run — v1.2
- ✓ IMPL-07: Outcome summary with pass/fail per cmdlet after run completes — v1.2

### Active (v1.3)

_(Requirements to be defined — see `.planning/REQUIREMENTS.md`)_

### Deferred to Future (removed from v1.2 short-list)

- [ ] Pre-install prerequisite PowerShell modules (Az.Accounts, Az.Resources, Az.ResourceGraph) in UI setup gate — still requires manual install
- [ ] Fix terminal line spacing in ConnectPage SSE output (ansi-to-html block-level wrapper injection)
- [ ] Alerting / notifications — flag new ControlPlane identities after classification run
- [ ] Attack path analysis — privilege chain tracing, blast radius, exposure scoring
- [ ] AI/Copilot integration — plain-English tier explanations, remediation suggestions, natural language search

### Out of Scope (v1)

- **Cloud hosting / SaaS** — local developer tool only; no hosted deployment
- **Real-time Graph API calls** — GUI reads from files; does not call Microsoft Graph directly
- **User authentication / multi-tenancy** — single-user, single-tenant, trusted local tool; no login
- **PDF/CSV export** — deferred to v2+
- **Mobile/tablet** — desktop browser only
- **Replacing Azure Monitor Workbooks** — complementary local tool, not a Sentinel replacement
- **PowerShell command runner (v1)** — deferred to Phase 3 post-MVP
- **Git change history browser** — deferred to Phase 4 post-MVP
- **Settings page** — deferred to Phase 5 post-MVP

### Future (Post-MVP Roadmap Candidates)

- **PowerShell command runner** — trigger and stream EntraOps cmdlets from the browser (Phase 3)
- **Git change history** — browse EAM diffs, object-level changes between runs (Phase 4)
- **Settings page** — structured editor for EntraOpsConfig.json (Phase 5)
- **Alerting / notifications** — flag new ControlPlane identities after a classification run (delivery mechanism TBD)
- **Attack path analysis** — privilege chain tracing, blast radius analysis, exposure scoring
- **AI/Copilot integration** — explain tier classifications in plain English, suggest remediation, natural language search
- **Exposure management** — quantified risk scoring for identities based on tier, assignment type, and protection status

## Context

EntraOps is a PowerShell module that classifies privileged identities in Microsoft Entra ID using an Enterprise Access Model (EAM) tier framework. It produces structured JSON output in `PrivilegedEAM/` covering multiple RBAC systems: EntraID, ResourceApps, IdentityGovernance, DeviceManagement, and Defender.

Currently, consuming this data requires reading raw JSON, running KQL in Azure Sentinel, or opening pre-built Azure Monitor Workbooks — all of which require either technical knowledge or cloud infrastructure. There is no UI for editing classification templates; users hand-edit JSON files risking schema corruption.

The primary users are:
- **Security Administrators / Identity Engineers** — want quick local review without Azure Portal
- **Security Architects / Auditors** — review ControlPlane access, may not have Sentinel access
- **EntraOps Contributors** — customise classification templates, want a safer editing experience

The codebase is a PowerShell module. The GUI will live in a `gui/` subdirectory and must not disturb the existing module structure.

## Constraints

- **Tech Stack**: React + TypeScript + Vite + Tailwind CSS + Express.js backend — established in PRD; no cloud SDK dependencies
- **Runtime**: Node.js 20+ is the only additional prerequisite beyond PowerShell 7
- **Design Language**: Microsoft / Fluent-inspired aesthetic — familiar to Azure users
- **Security**: Command runner must use a strict allowlist; no arbitrary code execution; all file writes validated via Zod schema
- **Cross-platform**: Must work on Windows, macOS, and Linux
- **Fork-friendly**: Lives in `gui/` subdirectory; `npm run dev` starts everything; no extra setup beyond `npm install`
- **No auth**: Local tool, single user, no login screen

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| React + TypeScript + Vite for frontend | Component model suits data-heavy dashboard; strong TypeScript ecosystem; fast dev server | — Pending |
| Tailwind CSS for styling | Utility-first, no design system lock-in, matches Fluent design direction | — Pending |
| TanStack Query v5 for data fetching | Loading/error states; cache invalidation after command runs | — Pending |
| TanStack Table v8 for object browser | Headless; handles sort/filter/pagination on large object sets | — Pending |
| Express.js backend (TypeScript via tsx) | Minimal bridge between React and filesystem, git, PowerShell | — Pending |
| simple-git for git access | Passes args as arrays; no shell injection risk | — Pending |
| Zod for schema validation | Runtime validation of JSON files before writing to disk | — Pending |
| MVP = Phases 1–2 only | Dashboard + object browser + template editor is enough to validate core value | — Pending |
| Attack path / AI features deferred post-MVP | Ambitious scope; need core data exploration working first | — Pending |
| Multi-tenancy explicitly out of scope | EntraOps is self-contained to a single org tenant for security reasons | — Pending |

## Context

Current codebase: ~12,201 LOC TypeScript across `gui/client`, `gui/server`, `gui/shared`.
Tech stack: React + Vite + Tailwind CSS + shadcn/ui (client); Express.js + TypeScript (server); Zod validation; vitest for server tests.
Three milestones shipped: v1.0 (6 phases, 30 plans) → v1.1 (2 phases, 6 plans) → v1.2 (4 phases, 10 plans).
Key tech debt: GlobalExclusionsTab fetches raw GUIDs (WARN-1); IMPL-03 tier scope not explicit column (WARN-2); ConnectPage terminal double-space (todo filed); Nyquist VALIDATION.md absent for v1.2 phases.

---
*Last updated: 2026-04-05 after v1.3 milestone start*
