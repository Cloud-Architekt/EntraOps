# Project Research Summary

**Project:** EntraOps GUI — v1.3 Updated UI Documentation
**Domain:** Markdown documentation for a locally-hosted security administration GUI (fork-and-run model)
**Researched:** 2026-04-05
**Confidence:** HIGH

## Executive Summary

EntraOps GUI v1.3 is a documentation milestone, not a feature milestone. The product is fully shipped (11 screens across v1.0–v1.2); the task is creating a comprehensive `docs/` folder that serves two distinct audiences: security administrators who use the GUI and contributors who extend it. Research across ArgoCD, Grafana, Portainer, and HashiCorp Vault confirms the pattern: the best documentation for a locally-hosted developer tool is plain Markdown files committed to the repo, organized as a hub-and-spoke hierarchy, with one file per screen and audience separation enforced by folder structure — not by any static site generator.

The recommended approach is deliberate plain Markdown at `docs/` (repo root, not `gui/docs/`), with relative links, `docs/assets/screenshots/<screen>/` storage, and a `docs/README.md` navigation hub. No VitePress, Starlight, or Docusaurus is warranted at this scale: the fork-and-run audience reads docs on GitHub or in their editor, not on a localhost docs site. The architecture is designed to be forward-compatible — if a hosted site becomes a future milestone goal, VitePress can be bolted on top of the same folder with zero content restructuring.

The primary risks are documentation quality risks, not technical ones. Screenshot drift, audience mismatch (writing for the developer, not the security admin), missing security context (why the tier model matters), and config docs that diverge from the actual `EntraOpsConfig.json` are the recurring failure modes in tools of this type. Mitigating them requires establishing structure and a glossary before any content is authored, sourcing config docs from the live file rather than memory, and treating the getting-started guide as a first-run safety path that ends at a dry-run Apply — not a deep feature tour.

---

## Key Findings

### Recommended Stack

Plain Markdown files with no tooling additions are the correct choice for this milestone. The fork-and-run deployment model makes this clear: GitHub's native Markdown renderer is the delivery surface. Relative `.md` link paths work identically in GitHub, VSCode preview, and any future VitePress site, so zero refactoring is needed if a hosted docs site becomes a future goal.

**Core technologies:**
- **Plain `.md` files** — All documentation content. Native GitHub rendering, zero tooling, editor-readable.
- **Relative path links** — All internal cross-references. Forward-compatible with VitePress if added later. Absolute URLs break after repo forks.
- **`docs/assets/screenshots/<screen>/`** — Screenshot storage. Committed PNGs with relative references; GitHub renders inline, no tooling required.
- **`markdownlint-cli2 ^0.17`** — Optional root `devDependency`. Enforces consistent heading levels and formatting; zero runtime cost.

VitePress (for a future hosted site) can be added as a root `devDependency` without touching `gui/` at all — its Vue runtime does not enter the React client. That decision belongs to a future milestone.

### Expected Features

Research from ArgoCD, Portainer, Grafana, and Vault identifies a clear set of documentation sections that security admins expect to find. Missing any table-stakes section makes the tool feel unfinished or untrustworthy.

**Must have (table stakes — users expect these):**
- Prerequisites list with explicit `pwsh`, Node.js, EntraOps module version requirements
- Numbered getting-started steps, each ending with an expected visual outcome
- Quick-start box (3-command path: fork → `Save-EntraOpsPrivilegedEAMJson` → `npm run dev`)
- One page per GUI screen (11 screens = 11 pages)
- Screenshot for every "you should see" instruction
- Troubleshooting / FAQ structured by symptom, not error code
- Configuration reference sourced from live `EntraOpsConfig.json`
- Architecture / data-flow narrative (PS module → JSON → Express → React)
- Explicit "no auth = local only" safety callout in getting-started
- "What this tool is NOT" scope disclaimer

**Should have (differentiators — elevate docs from present to excellent):**
- Concepts / domain glossary covering ControlPlane, ManagementPlane, UserAccess, EAM, AdminTierLevel, Classification Template, Applied vs Computed tier, Exclusion, dry-run, PrivilegedEAM — before any screen docs
- Architecture data-flow diagram (Mermaid or ASCII)
- "Before you start" security posture callout on Apply to Entra page
- Dry-run walkthrough as the recommended first-run path (leads with `-SampleMode`)
- Step-outcome pairings: every instruction ends with "You should see..."
- Annotated screenshots for the 3 most complex screens (Apply workflow, Object Browser, Template Editor)
- FAQ entries phrased as user questions ("Why is X...?", "What happens if...?")
- "See also" cross-links at the bottom of each screen page

**Defer (v2+):**
- VitePress / static site generator — only when a hosted public docs site is a milestone goal
- Versioned docs — no audience for v1.2 vs v1.3 distinction in a forked repo model
- Changelog doc page — GitHub Releases tab is the right surface for this
- JSDoc/TSDoc auto-generated API docs — no external API consumers; data model docs are more valuable
- Video walkthroughs — stale with every UI change; cannot live in git

### Architecture Approach

The docs folder uses a hub-and-spoke navigation model: `docs/README.md` is the single authoritative navigation hub; every sub-section has its own `README.md` (rendered automatically by GitHub); every leaf file has back-links to its section index and the hub. The folder structure enforces audience separation — `user-guide/`, `configuration/`, `troubleshooting/` for security admins; `contributing/`, `architecture/` for developers. No content crosses audience boundaries within a single file.

**Major components:**
1. `docs/README.md` — Navigation hub; table of contents for all docs; updated whenever a file is added
2. `docs/user-guide/` — One `.md` per GUI screen; end-user walkthroughs; purpose + navigation + screenshots + "see also" back-links
3. `docs/configuration/` — `entraops-config.md`, `environment-variables.md`, `api-endpoints.md`; lookup reference mode
4. `docs/architecture/` — `overview.md`, `data-flow.md`, `tech-stack.md`; explains the PS module → JSON → backend → browser pipeline
5. `docs/troubleshooting/` — `faq.md` structured by symptom; covers the 5 most common setup failures
6. `docs/contributing/` — `dev-setup.md`, `project-structure.md`, `adding-features.md`; developer audience only
7. `docs/assets/screenshots/<screen>/` — PNG binaries organized by screen subfolder; relative-linked from user-guide files

The root `README.md` is modified to add a "GUI Documentation" section linking to `docs/README.md`. `IMPLEMENTATION_GUIDE.md`, `CHANGELOG.md`, and `SECURITY.md` remain at root and are cross-referenced but not modified.

### Critical Pitfalls

**Top 5 pitfalls with prevention strategies (full list in [PITFALLS.md](PITFALLS.md)):**

1. **Screenshot Drift (D1)** — Screenshots become stale within 2 months as UI evolves. Mitigation: limit screenshots to structural/orientation views; avoid transient states (SSE streaming, loading skeletons); add `<!-- screenshot: <file>, taken v1.x -->` comments for staleness traceability.

2. **Audience Mismatch (D2)** — Writing for the developer when the primary reader is a security admin. Mitigation: assign every doc section to exactly one persona (Security Admin or Contributor) before writing; measure end-user docs by whether someone with zero React/Node knowledge can complete the task.

3. **Missing "Why" Behind the Tier Model (D3)** — Dashboard docs that say "KPI cards show ControlPlane counts" without explaining what ControlPlane means or why tier separation matters. Mitigation: author a Concepts page first (300–500 words, tier comparison table); link to it from every screen that uses tier terminology.

4. **Config Docs Diverging from Reality (D5)** — `EntraOpsConfig.json` has ~40 fields; docs written from memory miss fields, misstate defaults, or describe fields as optional when omitting them causes startup errors. Mitigation: generate the config reference by reading the actual committed file; flag every field with "requires restart" vs "hot-reloaded".

5. **Missing Quick-Start Path (D6)** — Feature-complete docs with no clear "zero to dashboard" flow. Users read about templates before understanding what the dashboard shows. Mitigation: author the getting-started guide first; limit it to a single happy path (fork → classify → run dev → dashboard); hard-stop under 500 words; terminate at a dry-run Apply, not a live run.

---

## Implications for Roadmap

Based on combined research, the docs phases must be ordered by dependency: foundation before content, content before reference, critical path (getting-started) before comprehensive feature walkthroughs. The biggest risk is writing screen docs before a glossary exists — terminology inconsistency (D10) then permeates every doc and requires a global find-and-replace pass to fix.

### Phase 1: Documentation Foundation — Structure, Glossary, and Concepts

**Rationale:** Every subsequent phase depends on this. The glossary locks terminology before any content is authored. The docs folder skeleton means every subsequent phase can be developed independently without restructuring. The Concepts page is referenced by every feature doc — it must exist first.
**Delivers:** `docs/` folder scaffold (all directories and placeholder READMEs), `docs/README.md` navigation hub, `docs/concepts.md` (glossary of ~15 terms: ControlPlane, ManagementPlane, UserAccess, EAM, AdminTierLevel, Classification Template, Applied vs Computed tier, Exclusion, dry-run, PrivilegedEAM), screenshot naming and viewport convention
**Addresses:** Must-have doc structure; arises from features research folder structure recommendation
**Avoids:** Pitfalls D3 (missing concepts), D10 (terminology drift), D2 (audience mismatch via persona assignment)

### Phase 2: Getting Started Guide

**Rationale:** The single highest-value doc. New users need a smooth zero-to-dashboard path before reading about any feature. Must be authored from the user's perspective, not the developer's memory. Pitfall D6 is the most likely failure mode.
**Delivers:** `docs/user-guide/getting-started.md` — prerequisites (PowerShell 7, EntraOps module, Node.js), 5-step numbered flow, quick-start box, expected visual outcome per step, "what to do next" link section; reference from root `README.md`
**Addresses:** Table-stakes prerequisites, numbered steps, quick-start box, "no auth = local only" callout
**Avoids:** Pitfalls D6 (no quick-start path), D11 (missing PowerShell prerequisite gate), D8 (GUI docs not integrated with PowerShell context)
**Research flag:** Low — Portainer/ArgoCD getting-started patterns are well-documented; no research-phase needed

### Phase 3: Feature Walkthrough — All 11 GUI Screens

**Rationale:** Largest content phase. Each screen follows a standard template (navigation path → overview screenshot → action sections → behavior notes → see also). Apply to Entra is the most complex and highest-stakes screen; dry-run must lead (D9). Dashboard and Object Browser are the "first view" screens and must be polished.
**Delivers:** `docs/user-guide/dashboard.md`, `object-browser.md`, `reclassify.md`, `exclusions.md`, `apply-to-entra.md`, `connect-classify.md`, `templates.md`, `history.md`, `run-commands.md`, `settings.md`; screenshots in `docs/assets/screenshots/<screen>/`
**Addresses:** One-page-per-screen (table stakes), screenshot per instruction, annotated screenshots for Apply/Object Browser/Templates
**Avoids:** Pitfalls D1 (structural screenshots only), D2 (security admin language throughout), D7 (outcome-first framing), D9 (dry-run prominently documented on Apply page), D13 (SSE streaming output annotated), D14 (Classification Template schema reference)
**Research flag:** Moderate for Apply to Entra (4-state SSE workflow) and Templates (Zod schema reference); all others follow standard patterns

### Phase 4: Configuration Reference

**Rationale:** Lookup reference for `EntraOpsConfig.json` schema, environment variables, and Express API endpoints. Must be sourced from the live file — not written from memory — to avoid pitfall D5.
**Delivers:** `docs/configuration/entraops-config.md` (full field reference: type, default, which screen exposes it, restart vs hot-reload), `environment-variables.md`, `api-endpoints.md`
**Addresses:** Configuration reference (table stakes), API endpoint inventory (contributor table stakes)
**Avoids:** Pitfalls D5 (config defaults mismatch), D12 (JSON file paths not matching real paths)
**Research flag:** Low — source from live `EntraOpsConfig.json`; no research needed

### Phase 5: Architecture and Integration Overview

**Rationale:** Explains the non-obvious data pipeline (PS module → JSON → Express → React) that underlies everything the GUI does. Without this, users don't understand why data looks "stale" or what triggers a refresh. Must include the file-write map.
**Delivers:** `docs/architecture/overview.md`, `data-flow.md` (Mermaid diagram), `tech-stack.md`; JSON file write map table (which GUI action writes to which JSON)
**Addresses:** Architecture/data-flow diagram (differentiator), integration narrative
**Avoids:** Pitfalls D8 (GUI and PowerShell docs not integrated), D13 (SSE streaming undocumented at system level), D12 (JSON file paths)
**Research flag:** Low — architecture is a direct description of the built system

### Phase 6: Troubleshooting / FAQ

**Rationale:** Authored after feature walkthroughs because the most valuable FAQ entries come from knowing what each screen's empty/error states look like. Structure by symptom, not error code.
**Delivers:** `docs/troubleshooting/README.md` (symptom quick-list), `docs/troubleshooting/faq.md` (10+ entries: dashboard zeros, port 3001 conflict, missing `pwsh`, empty PrivilegedEAM dir, device code auth timeout, stream stalled, classification changes not persisting)
**Addresses:** Troubleshooting/FAQ (table stakes)
**Avoids:** Pitfall D4 (troubleshooting structured by symptoms, not error codes)
**Research flag:** Low — Grafana symptom-first pattern applies directly

### Phase 7: Contributor Docs

**Rationale:** Authored last — contributor audience is smaller; `adding-features.md` must reference the final project structure established after all feature walkthroughs stabilize.
**Delivers:** `docs/contributing/dev-setup.md`, `project-structure.md`, `adding-features.md` (conventions: new page → sidebar → server route → shared type); link to `configuration/api-endpoints.md` for backend reference
**Addresses:** Contributor table stakes (local dev setup, project structure map, how to add a cmdlet, API endpoint inventory, data model explanation)
**Avoids:** Pitfall D2 (developer framing isolated to this section only)
**Research flag:** Low — standard OSS contributor doc patterns

### Phase 8: Root README Update and Cross-Link Audit

**Rationale:** Final pass — add "GUI Documentation" section to root `README.md`, verify all `docs/README.md` nav links are accurate, confirm no orphan files.
**Delivers:** Updated root `README.md`; verified `docs/README.md` with all cross-links functional; no orphan doc files
**Addresses:** Navigation from README to docs (table stakes)
**Avoids:** Hub-and-spoke navigation degrading if a file was added without updating the hub

---

### Phase Ordering Rationale

- **Foundation before content (Phase 1 first):** Terminology established in the glossary is used everywhere. Folder structure must exist before file paths can be referenced.
- **Getting-started before walkthrough (Phase 2 before Phase 3):** The getting-started guide is the entry point; feature docs that cross-link back to it need the target to exist.
- **Feature walkthroughs before config/troubleshooting (Phase 3 before 4, 5, 6):** Config reference and FAQ entries need to reference canonical screen names; screen docs establish those names.
- **Contributor docs last (Phase 7):** Developer docs can reference the final file structure only after it stabilizes.
- **README update as final gate (Phase 8):** Hub navigation updated when all spokes are in place.

### Research Flags

Phases likely needing deeper research during planning:
- **Phase 3 (Apply to Entra screen):** 4-state SSE workflow and `-SampleMode` integration warrant planning against the live implementation before writing.
- **Phase 3 (Templates screen):** Zod validation schema and diff-preview mechanics should be read from source before authoring.
- **Phase 4 (Config reference):** Must be generated from `EntraOpsConfig.json` directly — planning phase should include a file audit step.

Phases with standard patterns (research-phase not needed):
- **Phase 1:** Folder scaffold and glossary — straightforward structure work
- **Phase 2:** Getting-started — Portainer/ArgoCD patterns apply directly
- **Phase 5:** Architecture overview — describes the built system; no research needed
- **Phase 6:** FAQ/troubleshooting — Grafana symptom-first pattern applies directly
- **Phase 7:** Contributor docs — standard OSS patterns
- **Phase 8:** README update — mechanical cross-link verification

---

## Confidence Assessment

| Area | Confidence | Notes |
|------|------------|-------|
| Stack | HIGH | Official npm registry + direct codebase inspection + official generator docs all checked. Plain Markdown verdict is unambiguous given the fork-and-run constraint. |
| Features | HIGH | Verified against 4 live comparable tools (ArgoCD, Grafana, Portainer, Vault). Section structure recommendations directly sourced from their doc patterns. |
| Architecture | HIGH | Folder structure derived from codebase inspection (existing root files, `gui/` structure) + established Markdown-only nav patterns. No speculative architecture. |
| Pitfalls | HIGH | Codebase analysis (actual `EntraOpsConfig.json` complexity, SSE streaming, PowerShell boundary) + Diátaxis framework + Write the Docs conventions. |

**Overall confidence:** HIGH

### Gaps to Address

- **Screenshots require a running instance:** The feature walkthrough phase (Phase 3) requires a live working install to capture screenshots. Schedule the screenshot pass when a working tenant connection is available.
- **`EntraOpsConfig.json` field inventory needs a live read before Phase 4:** Config reference must be generated from the actual committed file. A pre-phase file audit is a required planning step.
- **13 allowlisted cmdlets need enumeration:** The Run Commands screen doc requires listing all 13 cmdlets with their user-facing purpose. Read from the server-side allow-list array, not estimated during planning.

---

## Sources

### Primary (HIGH confidence)
- `gui/client/package.json` — Direct inspect: React 19, Vite 5.x, Tailwind CSS v4, Vitest
- `EntraOpsConfig.json` — Direct codebase inspection confirming ~40 fields across nested sections
- ArgoCD official docs — user-guide structure, FAQ format, screenshot placement patterns
- Portainer official docs — install guide pattern, numbered steps with expected outcomes
- Grafana official docs — troubleshooting structure, symptom-first organization
- HashiCorp Vault official docs — config reference structure, field-level documentation

### Secondary (MEDIUM confidence)
- VitePress 1.6.4 — npm registry + vitepress.dev/guide/getting-started (verified forward-compatibility of `.md` relative links)
- Diátaxis documentation framework — tutorials/how-to/reference/explanation separation applied to docs architecture
- Write the Docs community conventions — symptom-first troubleshooting and persona-audience separation patterns

### Tertiary (informational only)
- Starlight (Astro) — reviewed and rejected; self-labeled beta, separate framework
- Docusaurus v3.9.2 — reviewed and rejected; separate project build pipeline not justified at this scale

---
*Research completed: 2026-04-05*
*Ready for roadmap: yes*
