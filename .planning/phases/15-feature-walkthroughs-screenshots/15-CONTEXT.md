# Phase 15: Feature Walkthroughs & Screenshots - Context

**Gathered:** 2026-04-09
**Status:** Ready for planning

<domain>
## Phase Boundary

Fill all 10 GUI screen stub pages under `docs/user-guide/` with illustrated walkthrough content, and capture real screenshots from the running app at `localhost:5173` using VS Code browser automation tools. Screenshots are stored under `docs/assets/screenshots/<screen>/` with relative links from each walkthrough page.

**In scope:** The 10 existing stub `.md` files (dashboard, connect-wizard, object-browser, object-reclassification, exclusions, apply-to-entra, git-history, settings, template-editor, powershell-runner), real screenshot capture, `docs/assets/screenshots/` folder population.
**Out of scope:** Configuration reference (Phase 16), troubleshooting (Phase 17), root README update (Phase 18), any feature modifications to the GUI itself.

</domain>

<decisions>
## Implementation Decisions

### Screenshot Capture

- **D-01:** Screenshots are captured using **VS Code browser automation tools** (Playwright via the VS Code Copilot interface) against the already-running app at `localhost:5173`. The app is confirmed to be running — the agent does not need to start it.
- **D-02:** Screenshots are saved as PNG files under `docs/assets/screenshots/<screen>/` using a consistent kebab-case naming convention (e.g., `docs/assets/screenshots/dashboard/dashboard-overview.png`). Each screen folder gets at least one screenshot; Apply to Entra gets four.
- **D-03:** All screenshots must be **real captures from the live app** — no placeholder images or placeholder references. FEAT-02 requires this explicitly.

### Walkthrough Page Structure

- **D-04:** Every walkthrough page follows this **consistent structure**:
  1. H1 heading (screen name — already in each stub)
  2. 1–2 paragraph intro explaining what the screen does and when a user would use it
  3. Screenshot (relative link to `docs/assets/screenshots/<screen>/`)
  4. Bullet list of key features/capabilities on that screen
- **D-05:** Tone is **professional/technical** — document style, concise and precise (consistent with Phase 13 D-03 and Phase 14 D-11). No onboarding warmup prose.
- **D-06:** User simplicity is the guiding constraint — shortest path to understanding what the screen does (consistent with Phase 14 D-12).
- **D-07:** Cross-links between walkthrough pages only when **directly relevant** — no "Related screens" boilerplate. Exception: Apply to Entra may mention Connect Wizard since the workflow depends on it.

### Apply to Entra: 4-State Coverage (FEAT-03)

- **D-08:** The Apply to Entra walkthrough includes **4 separate screenshots**, one per workflow state: select, confirm, streaming, outcomes. Each screenshot is followed by a short description of what that state represents and what the user does there.
- **D-09:** Screenshots for Apply to Entra: `apply-select.png`, `apply-confirm.png`, `apply-streaming.png`, `apply-outcomes.png` — stored in `docs/assets/screenshots/apply-to-entra/`.

### Screen Coverage & Depth

- **D-10:** All 10 screens receive **equal depth** — same structure, same level of detail. No tiered treatment. Consistent structure aids navigation and avoids reader confusion about why some pages are more detailed than others.
- **D-11:** The 10 screens (and their stub files) are:
  1. `dashboard.md` — Dashboard
  2. `connect-wizard.md` — Connect & Classify Wizard
  3. `object-browser.md` — Object Browser
  4. `template-editor.md` — Classification Template Editor
  5. `powershell-runner.md` — PowerShell Command Runner
  6. `git-history.md` — Git Change History
  7. `settings.md` — Settings
  8. `object-reclassification.md` — Object Reclassification
  9. `exclusions.md` — Exclusions Management
  10. `apply-to-entra.md` — Apply to Entra

### Claude's Discretion

- Exact alt text for screenshot image tags — use descriptive but concise alt text
- Bullet list length per screen — 4–8 bullets, no hard cap; include all meaningful capabilities
- Whether to include a "**Navigation:** Sidebar → [Screen Name]" line at the top of each page — recommended for discoverability (Claude's call on whether to include)
- Screenshot filename for screens other than Apply to Entra (e.g., `dashboard-overview.png` vs `dashboard.png`) — flat and simple preferred

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Phase Scope & Success Criteria
- `.planning/ROADMAP.md` §Phase 15 — Goal, depends-on, requirements FEAT-01/FEAT-02/FEAT-03/DOCS-02, 4 success criteria

### Requirements
- `.planning/REQUIREMENTS.md` §FEAT-01, §FEAT-02, §FEAT-03, §DOCS-02 — Source requirements this phase closes

### Project Context
- `.planning/PROJECT.md` §v1.3 Current Milestone — Documentation target deliverables and audience
- `.planning/STATE.md` — Current status and prior completed phases

### Upstream Phase Context
- `.planning/phases/13-documentation-foundation-concepts/13-CONTEXT.md` — Tone decisions (D-03 professional/technical), user simplicity principle (D-07), flat file naming (D-11), docs/ folder hierarchy
- `.planning/phases/14-getting-started-guide/14-CONTEXT.md` — Tone (D-11), step format patterns, cross-linking decisions

### Existing Stub Files (to be filled)
- `docs/user-guide/dashboard.md` — stub: heading only
- `docs/user-guide/connect-wizard.md` — stub: heading only
- `docs/user-guide/object-browser.md` — stub: heading only
- `docs/user-guide/template-editor.md` — stub: heading only
- `docs/user-guide/powershell-runner.md` — stub: heading only
- `docs/user-guide/git-history.md` — stub: heading only
- `docs/user-guide/settings.md` — stub: heading only
- `docs/user-guide/object-reclassification.md` — stub: heading only
- `docs/user-guide/exclusions.md` — stub: heading only
- `docs/user-guide/apply-to-entra.md` — stub: heading only

### Screenshot Target Directory
- `docs/assets/screenshots/` — root of all screen folders (exists, currently empty)

No additional external specs — all requirements captured in decisions and roadmap above.

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- 10 stub `.md` files in `docs/user-guide/` each with a single H1 heading — ready to fill
- `docs/assets/screenshots/` — directory exists, empty, ready for PNG files
- `docs/README.md` — navigation hub already links to all 10 walkthrough pages (Phase 13 output)

### Established Patterns
- All docs are plain Markdown (no MDX, no static site generator) — consistent with prior phases
- Phase 13 scaffold established the `docs/` folder hierarchy — paths are fixed and must be respected
- `docs/concepts.md` and `docs/user-guide/getting-started.md` set the tone and style baseline

### Integration Points
- `docs/README.md` links to all 10 walkthrough files — paths must remain stable
- Apply to Entra walkthrough may cross-link to `connect-wizard.md` (workflow dependency)
- Getting-started guide (Phase 14) cross-links to these walkthrough pages for deeper detail — paths must match

</code_context>

<specifics>
## Specific Ideas

- Screenshot capture: use VS Code browser automation (Playwright) pointing at `localhost:5173` — app is already running
- Apply to Entra: navigate to each of the 4 states before capturing (dry-run mode is safe — no Entra writes)
- Each page intro should answer: "What is this screen for? When does a user come here?"
- Key features list should describe what the user can **do** on the screen, not just list UI elements
- Screenshot naming for Apply to Entra: `apply-select.png`, `apply-confirm.png`, `apply-streaming.png`, `apply-outcomes.png`
- For screens requiring tenant connection (Connect Wizard), capture in the initial (not-yet-connected) state if a live connection isn't available — or use the dry-run flow

</specifics>

<deferred>
## Deferred Ideas

- "Pre-install prerequisite PowerShell modules in UI setup" todo — this is a feature change to the Connect flow, not a docs change. Out of scope for Phase 15. Remains as a backlog todo.

</deferred>

---

*Phase: 15-feature-walkthroughs-screenshots*
*Context gathered: 2026-04-09*
