# Phase 13: Documentation Foundation & Concepts - Context

**Gathered:** 2026-04-05 (updated 2026-04-08)
**Status:** Ready for planning

<domain>
## Phase Boundary

Create the `docs/` folder scaffold for the EntraOps GUI, establish the navigation hub (`docs/README.md`), write the concepts page explaining the EAM tier model with GUI-anchored examples, and define the glossary of 7 required terms. This is the structural and vocabulary foundation that every subsequent docs phase (14–18) writes into.

**In scope:** `docs/` folder hierarchy, `docs/README.md`, `docs/concepts.md` (including glossary), stub files for sections authored in later phases.
**Out of scope:** Getting-started guide (Phase 14), screen walkthroughs (Phase 15), config reference (Phase 16), troubleshooting (Phase 17), root README update (Phase 18).

</domain>

<decisions>
## Implementation Decisions

### Concepts Page (docs/concepts.md)

- **D-01:** Audience is **both** newcomers and returning users — start with accessible context, then add technical depth. Do not assume EAM familiarity.
- **D-02:** Structure is **GUI-anchored** — link each concept (tier, applied tier, computed tier, etc.) to the specific GUI screen where it appears (e.g., "ControlPlane objects appear in the ControlPlane KPI card on the Dashboard"). This grounds abstract model concepts in what the reader can actually open and see.
- **D-03:** Tone is **professional / technical** — document style, not onboarding guide style. Concise and precise, no unnecessary warmup prose.
- **D-04:** Explain **why tiers exist** (separation of privilege, EAM framework rationale) as part of the accessible intro, then transition to what each tier is and how it manifests in the GUI.

### Glossary

- **D-05:** Placement and format are at **Claude's discretion**. Recommended approach: a dedicated `## Glossary` section at the bottom of `concepts.md` using a Markdown table with `Term | Definition | Where in GUI` columns — keeps glossary co-located with concept explanations, keeps it linkable, and the GUI column reinforces the GUI-anchored theme.
- **D-06:** All 7 required terms must be present: `ControlPlane`, `ManagementPlane`, `UserAccess`, `applied tier`, `computed tier`, `exclusion`, `override`.

### docs/README.md Navigation Hub

- **D-07:** Style prioritises **user simplicity** — lean index with minimal intro text and a clear table of contents. A lean navigation table (Section | File | Description) preferred over a narrative landing page. Get the reader to the right file as fast as possible.
- **D-09:** The `docs/` folder is **GUI-specific additional documentation only**. Existing PowerShell module documentation in root `README.md` must remain in place and is out of scope for this phase. `docs/README.md` intro must not duplicate or replace the root README — it introduces the GUI docs section only.
- **D-10:** `docs/README.md` intro is one sentence scoped to GUI: "Documentation for the EntraOps GUI — browse by section below." (exact wording at Claude's discretion; user simplicity is the principle).

### Scaffold / Placeholder Strategy

- **D-08:** Placement and approach at **Claude's discretion**. Recommended approach: create stub `.md` files with empty section headers (no "coming soon" prose) for all sections authored in later phases. This ensures no broken links from `docs/README.md` and makes the structure visible on GitHub immediately.
- **D-11:** File naming principle: **flat and simple, one file per purpose**. Prefer `getting-started.md` over `getting-started/index.md`, one config reference file over split files. User simplicity is the guiding constraint. Exact names at Claude's discretion.

### Concepts Page — EAM External Reference

- **D-12:** `concepts.md` must include a **one-sentence intro callout linking to Microsoft's Enterprise Access Model** at `https://aka.ms/SPA`. Placement: opening intro section (not glossary, not footer). This adds authoritative external context and is consistent with the root README which already cites this link.

### Concepts Page — Applied vs Computed Tier

- **D-13:** Depth and format of the applied vs computed tier explanation is **Claude's discretion, user simplicity first**. Key content that must be present: what "applied tier" means, what "computed tier" means, how to visually distinguish them in the GUI (dashed badge = computed, solid badge = applied). Claude may choose a dedicated subsection, inline paragraph, or glossary-only based on what reads most clearly.

### Claude's Discretion
- Glossary placement (section in concepts.md vs standalone glossary.md) — use whichever keeps reading flow clean and cross-linking simple.
- Exact folder nesting within `user-guide/`, `configuration/`, `architecture/`, `troubleshooting/` — follow success criteria folder names from ROADMAP.md; internal file naming is Claude's call (flat and simple, one file per purpose).
- Stub file content — empty headers preferred over placeholder prose.
- Applied vs computed tier explanation depth — user simplicity first; ensure visual badge distinction (dashed = computed, solid = applied) is communicated.

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Phase Scope & Success Criteria
- `.planning/ROADMAP.md` §Phase 13 — Goal, depends-on, requirements, 4 success criteria (folder hierarchy, concepts.md, glossary 7 terms, docs/ structure)

### Requirements
- `.planning/REQUIREMENTS.md` §DOCS-01, §CONC-01, §CONC-02 — Source requirements this phase closes

### Project Context
- `.planning/PROJECT.md` §v1.3 Current Milestone — Documentation target deliverables and audience descriptions

### External References
- `https://aka.ms/SPA` — Microsoft Enterprise Access Model (EAM) framework — must be linked in concepts.md intro callout (D-12)

No additional external specs — all requirements captured in decisions and roadmap above.

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- No existing `docs/` directory — full greenfield creation
- `gui/` subdirectory is the application root — docs live at repo root in `docs/`

### Established Patterns
- Project uses Markdown throughout `.planning/` — consistent with plain Markdown docs (no MDX, no static site generator)
- Requirements explicitly defer VitePress/static site generation to v1.4+ — plain `.md` files only

### Integration Points
- `docs/README.md` will be linked from root `README.md` in Phase 18 (ROOT-01) — ensure path is stable
- `docs/assets/screenshots/` hierarchy created here is the target for Phase 15 screenshots (DOCS-02)
- All subsequent phases (14–17) write into specific sub-paths created by this scaffold — naming must match what downstream phases expect

</code_context>

<specifics>
## Specific Ideas

- Concepts page should anchor each tier to the GUI: e.g., "ControlPlane identities appear in the ControlPlane KPI card on the Dashboard. If you click through, the Object Browser filters to ControlPlane objects."
- The 3-tier model (ControlPlane > ManagementPlane > UserAccess) is a privilege hierarchy — the concepts page should communicate this ordering/importance relationship, not just list definitions.
- "Applied tier" vs "computed tier" distinction is a key GUI concept (dashed badge = computed, solid = applied) — the glossary and/or explanation must make this visually distinguishable in prose.
- EAM link placement: "EntraOps implements Microsoft's Enterprise Access Model (EAM) — [see the full framework (aka.ms/SPA)](https://aka.ms/SPA)" as the opening callout sentence before the tier explanation.
- `docs/` is GUI-specific — scope it as supplementary to the existing root README, not a replacement. Root README PS module docs must be unchanged by this phase.

</specifics>

<deferred>
## Deferred Ideas

None — discussion stayed within phase scope.

</deferred>

---

*Phase: 13-documentation-foundation-concepts*
*Context gathered: 2026-04-05*
