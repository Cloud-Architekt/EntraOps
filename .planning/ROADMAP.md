# Roadmap: EntraOps GUI

## Milestones

- [x] **v1.0 MVP** ✅ SHIPPED 2026-03-26 — Full GUI: dashboard, object browser, template editor, PowerShell runner, Connect wizard, git history, settings (6 phases, 30 plans, 338 files) — [archive](.planning/milestones/v1.0-ROADMAP.md)
- [x] **v1.1 Pre-Apply Intelligence** ✅ SHIPPED 2026-03-29 — Computed tier surfaces in Dashboard & Object Browser; Object-Level Reclassification screen (2 phases, 6 plans) — [archive](.planning/milestones/v1.1-ROADMAP.md)
- [x] **v1.2 Self-Service Implementation Workflow** ✅ SHIPPED 2026-04-04 — GUI Exclusions Management + guided Apply to Entra workflow with real-time SSE streaming (4 phases, 10 plans) — [archive](.planning/milestones/v1.2-ROADMAP.md)
- [ ] **v1.3 Updated UI Documentation** 🚧 IN PROGRESS — Comprehensive `docs/` folder: concepts, getting started, 10-screen walkthroughs with real screenshots, config reference, architecture overview, troubleshooting (6 phases)

## Phases

<details>
<summary>✅ v1.0 MVP (Phases 1–6) — SHIPPED 2026-03-26</summary>

See [archive](.planning/milestones/v1.0-ROADMAP.md) for full phase details.

</details>

<details>
<summary>✅ v1.1 Pre-Apply Intelligence (Phases 7–8) — SHIPPED 2026-03-29</summary>

- [x] Phase 7: Computed Tier Surfaces (2/2 plans) — completed 2026-03-26
- [x] Phase 8: Object Reclassification Screen (4/4 plans) — completed 2026-03-28

See [archive](.planning/milestones/v1.1-ROADMAP.md) for full phase details.

</details>

<details>
<summary>✅ v1.2 Self-Service Implementation Workflow (Phases 9–12) — SHIPPED 2026-04-04</summary>

- [x] Phase 9: Exclusions Management (3/3 plans) — completed 2026-03-31
- [x] Phase 10: Inline Exclude Actions (3/3 plans) — completed 2026-04-02
- [x] Phase 11: Implementation Workflow (2/2 plans) — completed 2026-04-04
- [x] Phase 12: Dry-run / Preview Mode (2/2 plans) — completed 2026-04-04

See [archive](.planning/milestones/v1.2-ROADMAP.md) for full phase details.

</details>

### v1.3 Updated UI Documentation (Phases 13–18)

- [ ] **Phase 13: Documentation Foundation & Concepts** - docs/ scaffold, README.md navigation hub, concepts page, glossary
- [ ] **Phase 14: Getting Started Guide** - Zero-to-dashboard guide with prerequisites, numbered steps, dry-run intro
- [ ] **Phase 15: Feature Walkthroughs & Screenshots** - One walkthrough per GUI screen with real screenshots from localhost:5173
- [ ] **Phase 16: Configuration & Architecture Reference** - EntraOpsConfig.json field reference, env vars, architecture data-flow
- [ ] **Phase 17: Troubleshooting / FAQ** - 10+ symptom-first entries covering all common failure modes
- [ ] **Phase 18: Root Updates & Cross-Link Audit** - Documentation section in root README, verified hub navigation

## Phase Details

### Phase 13: Documentation Foundation & Concepts
**Goal**: Users have a navigable docs hub and a locked shared vocabulary before any feature content is authored
**Depends on**: Nothing (first phase)
**Requirements**: DOCS-01, CONC-01, CONC-02
**Success Criteria** (what must be TRUE):
  1. User opening `docs/README.md` in GitHub sees a table of contents with working links to every doc section
  2. User reads `docs/concepts.md` and can distinguish ControlPlane, ManagementPlane, and UserAccess tiers from each other
  3. Glossary contains all 7 defined terms: ControlPlane, ManagementPlane, UserAccess, applied tier, computed tier, exclusion, override
  4. Full `docs/` folder hierarchy exists (user-guide/, configuration/, architecture/, troubleshooting/, assets/screenshots/) so all subsequent phases write to agreed paths
**Plans**: 2 plans

Plans:
- [ ] 13-01-PLAN.md — docs/ folder hierarchy with all stub files (user-guide, configuration, architecture, troubleshooting, assets/screenshots)
- [ ] 13-02-PLAN.md — docs/README.md navigation hub + docs/concepts.md EAM tier model and glossary

### Phase 14: Getting Started Guide
**Goal**: A security admin can go from zero (fresh fork) to a visible browser dashboard by following a single guide
**Depends on**: Phase 13
**Requirements**: GS-01, GS-02, GS-03
**Success Criteria** (what must be TRUE):
  1. User with no prior EntraOps knowledge follows the guide and reaches a working dashboard without consulting any other doc
  2. Prerequisites block states Node.js 20+, PowerShell 7+, and EntraOps PS module explicitly before any steps begin
  3. Each numbered step ends with a "you should see…" outcome line confirming success before proceeding
  4. Guide recommends dry-run / preview mode and explains what it does before describing any Apply to Entra step
**Plans**: TBD

### Phase 15: Feature Walkthroughs & Screenshots
**Goal**: Every GUI screen has a discoverable, illustrated walkthrough page with real screenshots captured from the running app
**Depends on**: Phase 14
**Requirements**: FEAT-01, FEAT-02, FEAT-03, DOCS-02
**Success Criteria** (what must be TRUE):
  1. Each of the 10 GUI screens has a dedicated markdown walkthrough page under `docs/user-guide/`
  2. Every walkthrough page includes at least one real screenshot captured from the live app at `localhost:5173`
  3. All screenshots are stored under `docs/assets/screenshots/<screen>/` with relative links from each walkthrough page
  4. Apply to Entra walkthrough explicitly depicts and describes all 4 workflow states: select, confirm, streaming, outcomes
**Plans**: TBD
**UI hint**: yes

### Phase 16: Configuration & Architecture Reference
**Goal**: Users and contributors can look up any configuration field and understand the full GUI data pipeline
**Depends on**: Phase 13
**Requirements**: CONF-01, CONF-02, ARCH-01
**Success Criteria** (what must be TRUE):
  1. Configuration reference lists every field in `EntraOpsConfig.json` with its type, default value, and which screen exposes it
  2. Startup environment variables and API port options are documented with correct defaults
  3. Architecture overview explains the PS module → PrivilegedEAM JSON → Express → React data pipeline in plain language
  4. A data-flow table or diagram shows which GUI action writes to which file (classification configs, Global.json, etc.)
**Plans**: TBD

### Phase 17: Troubleshooting / FAQ
**Goal**: Users can diagnose and resolve common problems without developer assistance
**Depends on**: Phase 15
**Requirements**: TRBL-01
**Success Criteria** (what must be TRUE):
  1. Troubleshooting section contains 10 or more entries structured by symptom (not error code or log message)
  2. Entries cover all major failure categories: PowerShell prerequisites, empty dashboard (no data), port 3001 conflict, device-code auth timeout, template validation errors, and classification changes not persisting
  3. Every entry includes a resolution step the user can take, not just a description of the problem
**Plans**: TBD

### Phase 18: Root Updates & Cross-Link Audit
**Goal**: Root `README.md` points users to the docs; the docs hub is accurate and fully consistent with committed files
**Depends on**: Phase 13, Phase 14, Phase 15, Phase 16, Phase 17
**Requirements**: ROOT-01
**Success Criteria** (what must be TRUE):
  1. Root `README.md` contains a "Documentation" section with a link to `docs/README.md`
  2. Every link in `docs/README.md` resolves to an actual file committed to the repo
  3. No doc file exists without a corresponding entry (or back-link path) in `docs/README.md`
**Plans**: TBD

## Progress Table

| Phase | Milestone | Plans Complete | Status | Completed |
|-------|-----------|----------------|--------|-----------|
| 1–6 (v1.0 phases) | v1.0 | 30/30 | Complete | 2026-03-26 |
| 7. Computed Tier Surfaces | v1.1 | 2/2 | Complete | 2026-03-26 |
| 8. Object Reclassification Screen | v1.1 | 4/4 | Complete | 2026-03-28 |
| 9. Exclusions Management | v1.2 | 3/3 | Complete | 2026-03-31 |
| 10. Inline Exclude Actions | v1.2 | 3/3 | Complete | 2026-04-02 |
| 11. Implementation Workflow | v1.2 | 2/2 | Complete | 2026-04-04 |
| 12. Dry-run / Preview Mode | v1.2 | 2/2 | Complete | 2026-04-04 |
| 13. Documentation Foundation & Concepts | v1.3 | 0/2 | Ready to execute | - |
| 14. Getting Started Guide | v1.3 | 0/TBD | Not started | - |
| 15. Feature Walkthroughs & Screenshots | v1.3 | 0/TBD | Not started | - |
| 16. Configuration & Architecture Reference | v1.3 | 0/TBD | Not started | - |
| 17. Troubleshooting / FAQ | v1.3 | 0/TBD | Not started | - |
| 18. Root Updates & Cross-Link Audit | v1.3 | 0/TBD | Not started | - |
