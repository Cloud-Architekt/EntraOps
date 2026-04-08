# Phase 14: Getting Started Guide - Context

**Gathered:** 2026-04-08
**Status:** Ready for planning

<domain>
## Phase Boundary

Write `docs/user-guide/getting-started.md` — a single, self-contained guide that takes a security admin from a fresh fork to a visible browser dashboard, then through a dry-run Apply to Entra. The guide must work without consulting any other doc.

**In scope:** `docs/user-guide/getting-started.md` (filling the Phase 13 stub). The guide covers prerequisites, fork/clone/install, launching the GUI with sample data, connecting a real tenant, and performing a dry-run Apply.
**Out of scope:** Feature walkthroughs for individual screens (Phase 15), configuration reference (Phase 16), troubleshooting entries (Phase 17), root README update (Phase 18).

</domain>

<decisions>
## Implementation Decisions

### Prerequisites Block

- **D-01:** Prerequisites are **fully explicit** — list every dependency before step 1. No hidden requirements.
  - Fork the repo and clone locally
  - Node.js 22+ (v20 EOL as of March 2026 — doc as 22+, *not* 20+)
  - PowerShell 7+
  - `Az` and `Microsoft.Graph` PowerShell modules
  - Global Admin role (or equivalent) on the target Entra tenant
- **D-02:** Each prerequisite item links to its install source (e.g., nodejs.org, PowerShell on GitHub) so the reader never has to search. Format and exact wording at Claude's discretion; checklist style preferred.
- **D-03:** Node.js version is **22+** throughout the guide. GS-02 in REQUIREMENTS.md says 20+ but STATE.md global decisions override this (v20 EOL March 2026).

### Dashboard Reachability Path

- **D-04:** The guide uses a **two-stage approach**:
  1. **Quick dashboard** — fork → `npm install` in `gui/` → `npm run dev` → dashboard populated immediately with the existing `PrivilegedEAM/` sample JSON data committed to the repo. This achieves SC1 fast (no PowerShell, no tenant needed at this point).
  2. **Connect your tenant** — a clearly labelled section after the quick dashboard: edit `EntraOpsConfig.json`, import the PS module, run Connect & Classify. This is required before the dry-run Apply step can be performed.
- **D-05:** The guide does **not** require a live tenant connection to see the dashboard. Readers who only want to explore the GUI can stop after the quick dashboard section; the connect + dry-run steps are clearly marked as the next stage.

### Step Format

- **D-06:** Each numbered step follows the pattern:
  1. One-sentence "What this does:" intent line
  2. Command block (with any relevant inline comments)
  3. "You should see…" outcome line confirming success before proceeding
- **D-07:** No exhaustive parameter annotations — keep commands readable. Only annotate params that a reader might not recognise or that could be wrong for their environment (e.g., the `-Path` to `EntraOpsConfig.json`).

### Dry-Run / Preview Mode

- **D-08:** The stub's "Dry-Run / Preview Mode" section is a **standalone concept section** placed *before* any description of running Apply to Entra. It explains:
  - What dry-run mode does (sends `-SampleMode` to cmdlets — simulates changes without writing to Entra)
  - How to enable it in the GUI (the toggle in the Apply to Entra screen)
  - Why to always use it first
- **D-09:** After the concept explanation, the guide's **final numbered step** is: "Enable dry-run mode → navigate to Apply to Entra → click Run → confirm you see streaming simulation output." Guide ends here. No live Entra write is performed in the guide.
- **D-10:** This placement satisfies GS-03 (dry-run introduced before any Apply step) and STATE.md ("guide terminates at a dry-run Apply, not a live Entra write").

### Tone and Style

- **D-11:** Professional/technical tone (consistent with Phase 13 D-03). Document style, not onboarding warmup prose. Concise and precise.
- **D-12:** User simplicity is the guiding constraint. Shortest path to each success checkpoint; no filler text.

### Claude's Discretion

- Exact heading names and command wording (follow patterns in IMPLEMENTATION_GUIDE.md where they exist)
- Whether to use a callout-box style (e.g., `> **Note:**`) for the "you should see" confirmations or inline prose
- Exact npm invocation path (guide should specify `cd gui && npm install && npm run dev` or equivalent)
- Section for "Connect your tenant" may use a note like "Optional: skip to Dry-Run if you're exploring" to help readers who only want the quick dashboard

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Phase Scope & Success Criteria
- `.planning/ROADMAP.md` §Phase 14 — Goal, depends-on, requirements GS-01/GS-02/GS-03, 4 success criteria

### Requirements
- `.planning/REQUIREMENTS.md` §GS-01, §GS-02, §GS-03 — Source requirements this phase closes

### Project Context
- `.planning/PROJECT.md` §v1.3 Current Milestone — Documentation target deliverables and audience
- `.planning/STATE.md` §v1.3 Context — Key decisions: Node.js 22+ override, guide terminates at dry-run, 10 GUI screens list

### Upstream Phase Context
- `.planning/phases/13-documentation-foundation-concepts/13-CONTEXT.md` — Tone decisions (D-03 professional/technical), user simplicity principle (D-07), file naming convention (D-11 flat/simple)
- `docs/user-guide/getting-started.md` — The Phase 13 stub being filled (headers: Prerequisites, Installation, First Run, Dry-Run / Preview Mode)

### Existing Content for Reference
- `IMPLEMENTATION_GUIDE.md` — Step 1–3 of the PS-module setup flow; prerequisite list pattern to build from (PS 7+, Az, Microsoft.Graph, fork)
- `EntraOpsConfig.json` — Real config structure (TenantId, TenantName, AuthenticationType, ClientId) — use actual field names

No additional external specs — all requirements captured in decisions and roadmap above.

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- `docs/user-guide/getting-started.md` — Phase 13 stub with 4 section headers to fill: Prerequisites, Installation, First Run, Dry-Run / Preview Mode
- `PrivilegedEAM/` — Sample JSON data committed to the repo; populates the dashboard without a live tenant connection
- `IMPLEMENTATION_GUIDE.md` — Existing prerequisite list and PS module workflow to adapt/reference (not duplicate)

### Established Patterns
- All docs are plain Markdown (no MDX, no static site generator) — consistent with Phase 13
- Command blocks use standard fenced code blocks with shell/powershell language hints
- Phase 13: stub headers use title-case (`## Prerequisites`)

### Integration Points
- `docs/README.md` already links to `user-guide/getting-started.md` — path must remain stable
- The Connect & Classify step in the guide connects to the Connect Wizard screen (Phase 15 walkthrough); the guide can cross-link there for deeper detail
- Dry-run Apply step connects to the Apply to Entra screen (Phase 15 walkthrough); guide can cross-link

</code_context>

<specifics>
## Specific Ideas

- Quick dashboard path: `cd gui && npm install && npm run dev` → browser opens at `localhost:5173` → dashboard shows sample data immediately
- The "Connect your tenant" section should reference editing `EntraOpsConfig.json` by its actual fields: `TenantId`, `TenantName`, `AuthenticationType`, `ClientId`
- Dry-run toggle: in the Apply to Entra screen — enable before clicking Run; the guide should name the toggle as it appears in the GUI
- "You should see…" confirmations should describe what the browser/terminal shows (not abstract outcomes): e.g., "You should see the Dashboard with ControlPlane, ManagementPlane, and UserAccess KPI cards populated"

</specifics>

<deferred>
## Deferred Ideas

None — discussion stayed within phase scope.

</deferred>

---

*Phase: 14-getting-started-guide*
*Context gathered: 2026-04-08*
