# Architecture Research

**Domain:** Markdown-only docs/ folder for a monorepo GUI project
**Researched:** 2026-04-05
**Confidence:** HIGH

## Standard Architecture

### System Overview

```
EntraOps/ (repo root)
├── docs/                         ← NEW: all user-facing and contributor docs
│   ├── README.md                 ← navigation hub (entry point)
│   ├── assets/
│   │   └── screenshots/          ← one subdirectory per screen
│   ├── user-guide/               ← end user audience (security admins)
│   ├── configuration/            ← config reference (EntraOpsConfig.json, env vars, API)
│   ├── architecture/             ← GUI ↔ PowerShell data flow, tech stack
│   ├── troubleshooting/          ← FAQ, common errors
│   └── contributing/             ← developer audience (dev setup, project structure)
├── gui/                          ← unchanged; links to docs/ via gui/README.md
├── README.md                     ← updated: add "GUI Documentation" section with link to docs/
├── IMPLEMENTATION_GUIDE.md       ← unchanged; cross-referenced from docs/user-guide/getting-started.md
├── SECURITY.md                   ← unchanged; stays at root
└── CHANGELOG.md                  ← unchanged; stays at root
```

### Component Responsibilities

| Component | Responsibility | Owner |
|-----------|----------------|-------|
| `docs/README.md` | Authoritative navigation hub; table of contents for all docs | Updated every time a new doc is added |
| `docs/user-guide/` | End-user walkthroughs tied 1:1 to GUI screens | One `.md` per screen/page |
| `docs/configuration/` | Reference material for config files, env vars, API endpoints | Versioned alongside code changes |
| `docs/architecture/` | System integration narrative (GUI ↔ PowerShell data flow) | Updated at milestone boundaries |
| `docs/troubleshooting/` | Searchable symptom → fix content | Grows incrementally |
| `docs/contributing/` | Developer orientation: dev setup, structure, adding features | Updated when tech stack changes |
| `docs/assets/screenshots/` | Screenshot binaries; one subfolder per screen | Replaced when UI changes |

## Recommended Project Structure

```
docs/
├── README.md                           # Navigation hub — table of contents for everything
│
├── assets/
│   └── screenshots/
│       ├── dashboard/                  # dashboard-overview.png, dashboard-kpi-cards.png
│       ├── object-browser/             # object-browser-filters.png, object-browser-detail.png
│       ├── reclassify/                 # reclassify-pending-overrides.png
│       ├── exclusions/                 # exclusions-list.png, exclusions-add-from-browser.png
│       ├── apply-to-entra/             # apply-select-actions.png, apply-dry-run.png, apply-streaming.png
│       ├── connect-classify/           # connect-device-code.png, connect-wizard-complete.png
│       ├── templates/                  # templates-editor.png, templates-diff-preview.png
│       ├── history/                    # history-commit-list.png, history-compare.png
│       ├── run-commands/               # run-commands-streaming.png
│       └── settings/                  # settings-config-editor.png
│
├── user-guide/
│   ├── README.md                       # Section index with one-line description of each page
│   ├── getting-started.md              # Fork → Save-EntraOpsPrivilegedEAMJson → npm run dev → open browser
│   ├── dashboard.md                    # KPI cards, tier breakdowns, PIM chart
│   ├── object-browser.md               # Filter/sort/paginate, URL-bookmarkable state, detail panel
│   ├── reclassify.md                   # Inline tier overrides, Save All, Discard
│   ├── exclusions.md                   # Exclusions page, remove, add from Object Browser/Reclassify
│   ├── apply-to-entra.md               # 4-step workflow, 4 action toggles, dry-run mode, SSE log
│   ├── connect-classify.md             # Device code auth wizard, classification run
│   ├── templates.md                    # Classification template editor, Zod validation, diff preview
│   ├── history.md                      # Commit list, structured diffs, any-two-commit compare
│   ├── run-commands.md                 # Allowlisted cmdlets, real-time SSE streaming
│   └── settings.md                    # EntraOpsConfig.json editor
│
├── configuration/
│   ├── README.md                       # Section index
│   ├── entraops-config.md              # Full EntraOpsConfig.json field reference with types + defaults
│   ├── environment-variables.md        # PORT, VITE_API_URL, and any other env vars
│   └── api-endpoints.md                # Express server endpoint listing (for contributors + advanced users)
│
├── architecture/
│   ├── README.md                       # Section index
│   ├── overview.md                     # High-level: PowerShell module → PrivilegedEAM/ → GUI reads files
│   ├── data-flow.md                    # Classification JSON → server API → React client; SSE flow
│   └── tech-stack.md                   # React + Vite, Express.js, shared types, PowerShell boundary
│
├── troubleshooting/
│   ├── README.md                       # Section index + quick symptom list
│   └── faq.md                          # Symptom → cause → fix; covers npm, PS module, auth, data refresh
│
└── contributing/
    ├── README.md                       # Section index + quick start for contributors
    ├── development-setup.md            # Prerequisites, npm install, npm run dev, environment setup
    ├── project-structure.md            # gui/client/, gui/server/, gui/shared/, EntraOps/, Classification/
    └── adding-features.md              # Conventions: new page → sidebar → server route → shared type
```

### Structure Rationale

- **`docs/` at repo root, not `gui/docs/`:** The documentation covers both PowerShell module context (prerequisites, `Save-EntraOpsPrivilegedEAMJson`, `EntraOpsConfig.json`) and GUI features. Scoping it under `gui/` would make PowerShell-side content feel misplaced and would hide docs from users browsing the repo root. Root-level `docs/` matches where existing root docs (`README.md`, `IMPLEMENTATION_GUIDE.md`) already live.

- **`docs/README.md` as the navigation hub:** GitHub renders this automatically when a user browses to `docs/`. Every section and file should appear here with a one-line description. This is the single file a user must find to navigate everything else.

- **One file per GUI screen in `user-guide/`:** Matches how users think ("I'm on the Dashboard, show me that page"). Avoids one massive doc that's hard to link into.

- **Section `README.md` files:** Each subfolder has its own `README.md` so GitHub auto-renders an index for that folder. The index lists every file with a one-line description and links back to `docs/README.md`.

- **`assets/screenshots/<screen-name>/`:** A subdirectory per screen keeps the assets folder from becoming a flat pile. Enables relative links like `../assets/screenshots/dashboard/overview.png` from user-guide files. When a screen's UI changes, only that screen's subfolder needs updating.

- **`configuration/` as its own section:** Config reference is a different reading mode (lookup, not tutorial). Keeping it separate from user-guide lets users find `entraops-config.md` without reading a walkthrough.

- **`contributing/` separated from `user-guide/`:** Prevents developer content from cluttering the security admin reading path.

## Architectural Patterns

### Pattern 1: Hub-and-Spoke Navigation

**What:** `docs/README.md` is the single hub. All other docs are spokes. Every spoke file has a back-link to its section index, and every section index back-links to `docs/README.md`.
**When to use:** Always — this is the primary navigation model for Markdown-only docs with no sidebar framework.
**Trade-offs:** Requires `docs/README.md` to be kept in sync. If a file is added without updating the hub, it becomes orphaned. Mitigate by making "update `docs/README.md`" a checklist item in the contributing guide.

**Link chain example:**
```
docs/README.md
  → user-guide/README.md
      → user-guide/dashboard.md
          (bottom of file) ← [Back to User Guide](README.md) | [Back to Docs](../README.md)
```

### Pattern 2: Relative Links Only

**What:** All cross-references use relative paths (e.g., `[Getting Started](user-guide/getting-started.md)` from `docs/README.md`; `[EntraOpsConfig reference](../configuration/entraops-config.md)` from a user-guide file).
**When to use:** Always — absolute URLs break when the repo is forked; relative links work in GitHub UI, local editors, and any static site generator if one is added later.
**Trade-offs:** Requires knowing the relative path between two files. Convention: from any file, `../` navigates up one folder level.

### Pattern 3: Screenshot Naming Convention

**What:** `<state-or-action>.png` within `docs/assets/screenshots/<screen>/` subfolder.
**When to use:** All screenshots.
**Trade-offs:** Predictable names make it easy to update screenshots when UI changes. The subfolder removes the need to repeat the screen name as a prefix on every file.

**Examples:**
```
docs/assets/screenshots/dashboard/overview.png
docs/assets/screenshots/dashboard/kpi-cards.png
docs/assets/screenshots/apply-to-entra/select-actions.png
docs/assets/screenshots/apply-to-entra/dry-run-amber.png
docs/assets/screenshots/apply-to-entra/streaming-log.png
docs/assets/screenshots/apply-to-entra/outcome-summary.png
```

Reference from markdown:
```markdown
![Apply to Entra — outcome summary](../assets/screenshots/apply-to-entra/outcome-summary.png)
```

### Pattern 4: Audience Separation via Folder, Not File

**What:** End-user content lives in `user-guide/`, `configuration/`, `troubleshooting/`. Contributor content lives in `contributing/` and `architecture/`. Do not mix audiences within a file.
**When to use:** When the same feature has both user-facing and developer-facing facets (e.g., SSE streaming), write two separate files: one explaining what the user sees and one explaining how it works.
**Trade-offs:** Some content appears in both paths (e.g., the API endpoint list appears in `configuration/api-endpoints.md` for advanced users and in `contributing/adding-features.md` for developers). This is intentional — each audience file should be self-contained.

## Data Flow

### Navigation Flow (Reading)

```
User opens docs/README.md (GitHub or local)
    ↓
Finds section link → opens section/README.md
    ↓
Finds feature link → opens feature.md
    ↓
Feature.md references screenshots → docs/assets/screenshots/<screen>/
    ↓
Feature.md has cross-references → relative link to related doc
    ↓
Bottom of file: back-links to section index and docs hub
```

### Update Flow (Writing)

```
UI screen changes
    ↓
Replace docs/assets/screenshots/<screen>/ PNGs
    ↓
Update docs/user-guide/<screen>.md prose + screenshot refs
    ↓
If config changes: update docs/configuration/entraops-config.md
    ↓
If new file added: update docs/README.md and section README.md
```

### Relationship to Existing Root Files

| Existing File | Action | Integration |
|---------------|--------|-------------|
| `README.md` | **Modify** | Add "GUI Documentation" section with link to `docs/README.md` |
| `IMPLEMENTATION_GUIDE.md` | **Keep as-is** | Referenced from `docs/user-guide/getting-started.md`: "For PowerShell setup, see [IMPLEMENTATION_GUIDE.md](../IMPLEMENTATION_GUIDE.md)" |
| `CHANGELOG.md` | **Keep as-is** | Not referenced from docs/ (audience mismatch) |
| `SECURITY.md` | **Keep as-is** | Not referenced from docs/ |
| `GUI-PRD.md` | **Keep as-is** | Planning artifact; not linked from docs/ |

## Scaling Considerations

| Scale | Docs Adjustments |
|-------|------------------|
| Current (12 screens) | Flat files in `user-guide/` — no subfolders needed |
| +configuration reference sections | Add pages to `configuration/` — no structural change |
| +static site generator (future) | Structure is already compatible with Docusaurus/VitePress (folder = category, README.md = index) |
| +versioned docs (future) | Add `docs/v1.2/` snapshots — current structure supports it without refactoring |

## Anti-Patterns

### Anti-Pattern 1: Nested per-feature subfolders in user-guide/

**What people do:** Create `user-guide/dashboard/overview.md`, `user-guide/dashboard/kpi-cards.md`, etc.
**Why it's wrong:** Most GUI screens don't need multiple pages. Adds path depth without benefit. Users expect one link → one page for feature reference.
**Do this instead:** Keep `user-guide/dashboard.md` as a single file covering the whole screen. Use H2/H3 headings within the file for sub-topics. Only introduce subfolders if a single file exceeds ~400 lines.

### Anti-Pattern 2: Duplicating PowerShell setup instructions

**What people do:** Copy the full PowerShell prerequisites/setup from `IMPLEMENTATION_GUIDE.md` into `docs/user-guide/getting-started.md`.
**Why it's wrong:** Creates two sources of truth that will diverge.
**Do this instead:** `getting-started.md` covers GUI-specific steps only (npm install, npm run dev, opening browser). Opens with a single link to `IMPLEMENTATION_GUIDE.md` for PowerShell setup.

### Anti-Pattern 3: Absolute URLs for internal cross-references

**What people do:** `[Dashboard](https://github.com/org/repo/blob/main/docs/user-guide/dashboard.md)`
**Why it's wrong:** Breaks for forked repos, doesn't work in local editors, ties docs to a specific branch.
**Do this instead:** `[Dashboard](user-guide/dashboard.md)` — relative paths work everywhere.

### Anti-Pattern 4: Screenshot assets in a flat directory

**What people do:** `docs/assets/screenshots/dashboard-overview.png`, `docs/assets/screenshots/object-browser-filters.png` — 30 files in one folder.
**Why it's wrong:** Makes it hard to identify which files belong to which screen for replacement.
**Do this instead:** `docs/assets/screenshots/<screen>/` — one folder per screen, filenames omit the screen prefix.

## Integration Points

### Files Modified (Not Created)

| File | Change |
|------|--------|
| `README.md` | Add "GUI Documentation" section pointing to `docs/README.md` |

### Files Created

| File | Purpose |
|------|---------|
| `docs/README.md` | Navigation hub |
| `docs/user-guide/README.md` | Section index |
| `docs/user-guide/getting-started.md` | Primary end-user entry point |
| `docs/user-guide/dashboard.md` | Dashboard screen walkthrough |
| `docs/user-guide/object-browser.md` | Object browser walkthrough |
| `docs/user-guide/reclassify.md` | Reclassification screen walkthrough |
| `docs/user-guide/exclusions.md` | Exclusions screen walkthrough |
| `docs/user-guide/apply-to-entra.md` | Apply-to-Entra workflow walkthrough |
| `docs/user-guide/connect-classify.md` | Connect & Classify wizard walkthrough |
| `docs/user-guide/templates.md` | Template editor walkthrough |
| `docs/user-guide/history.md` | Git history browser walkthrough |
| `docs/user-guide/run-commands.md` | Run commands walkthrough |
| `docs/user-guide/settings.md` | Settings page walkthrough |
| `docs/configuration/README.md` | Section index |
| `docs/configuration/entraops-config.md` | EntraOpsConfig.json full field reference |
| `docs/configuration/environment-variables.md` | Dev env var reference |
| `docs/configuration/api-endpoints.md` | Express endpoint listing |
| `docs/architecture/README.md` | Section index |
| `docs/architecture/overview.md` | GUI ↔ PowerShell integration narrative |
| `docs/architecture/data-flow.md` | Classification JSON → API → React + SSE details |
| `docs/architecture/tech-stack.md` | React + Vite, Express, shared/ types |
| `docs/troubleshooting/README.md` | Section index + quick symptom lookup |
| `docs/troubleshooting/faq.md` | Symptom → cause → fix |
| `docs/contributing/README.md` | Developer onboarding hub |
| `docs/contributing/development-setup.md` | Prerequisites, npm workflow, dev server |
| `docs/contributing/project-structure.md` | gui/client, gui/server, gui/shared, EntraOps/, Classification/ |
| `docs/contributing/adding-features.md` | Conventions for new screen → sidebar → API route → shared type |
| `docs/assets/screenshots/<screen>/` × 10 | Screenshot subfolders (dashboard, object-browser, reclassify, exclusions, apply-to-entra, connect-classify, templates, history, run-commands, settings) |

### Build Order (Creation Sequence)

1. `docs/README.md` — skeleton hub first; fills in as other files are created
2. `docs/user-guide/getting-started.md` — highest-priority; unblocks all other user-guide work
3. `docs/user-guide/<screen>.md` — sidebar order: dashboard → object-browser → reclassify → exclusions → apply-to-entra → connect-classify → templates → history → run-commands → settings
4. `docs/troubleshooting/faq.md` — after user-guide; captures gaps discovered during walkthroughs
5. `docs/configuration/entraops-config.md` — reference content; alongside or after user-guide
6. `docs/configuration/environment-variables.md` + `api-endpoints.md`
7. `docs/architecture/` — written last; benefits from having written all user-guide content first
8. `docs/contributing/` — written last; describes conventions already visible in codebase
9. Modify `README.md` — add GUI docs link last so the link resolves correctly
10. Screenshots — populated progressively during or after prose authoring; PNG files are independent of structure

## Sources

- Existing project structure: `gui/client/src/pages/` (12 page components), `gui/server/`, `gui/shared/`
- Existing root docs: `README.md`, `IMPLEMENTATION_GUIDE.md`, `SECURITY.md`, `CHANGELOG.md`
- Project context: `.planning/PROJECT.md` (v1.3 milestone goals)
- GitHub rendering behaviour: `docs/` and `README.md` within subfolders auto-render as browsable indexes
- Comparable open-source pattern: VS Code, Tailwind CSS (all use `docs/` at repo root with per-feature files and relative links)
