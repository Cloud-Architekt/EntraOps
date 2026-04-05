# Feature Research — EntraOps GUI Documentation

**Domain:** Technical documentation for a locally-hosted security administration GUI
**Researched:** 5 April 2026
**Confidence:** HIGH — patterns drawn from live docs of ArgoCD, Grafana, Portainer, and HashiCorp Vault (verified against official sources)

---

## Research Context

This research covers what documentation sections and features to include in the `docs/` folder for the v1.3 milestone. The product is already built (11 screens shipped across v1.0–v1.2). The research question is: **what does great documentation look like for a tool of this type, at this scale, for this audience?**

**Comparable tools studied:**
- **ArgoCD** — strongest model: clear user/operator/developer separation, screenshot-per-action pattern, FAQ as user-phrased Q&A
- **Grafana** — best troubleshooting structure: topics-first, then logs, then community
- **Portainer** — best install guide: tabbed options, explicit prerequisites, numbered steps with expected output
- **HashiCorp Vault** — best configuration reference: field-level docs, use-case entry point

---

## Feature Landscape

### Table Stakes — User Docs (Users Expect These)

Documentation sections a security admin expects when they clone the repo. Missing one = the tool feels unfinished or untrustworthy.

| Feature | Why Expected | Complexity | Notes |
|---------|--------------|------------|-------|
| **Prerequisites list** | Every admin tool lists what must already be running; hitting an undocumented dependency mid-install kills trust | LOW | PowerShell module version, Node.js version, git, tenant permissions |
| **Numbered getting-started steps** | Portainer, ArgoCD, Grafana all use numbered steps ending with "you should see X"; users pattern-match to this | LOW | Must end each step with the expected outcome (what the browser shows) |
| **Quick-start box at page top** | Security admins are time-poor; they skim; a 3-command box earns trust before they read the detail | LOW | Fork → `Save-EntraOpsPrivilegedEAMJson` → `npm run dev` → open browser |
| **One page per GUI screen** | ArgoCD and Portainer each dedicate a page per feature; users search by screen name | MEDIUM | 11 screens = 11 pages; each needs purpose, navigation path, and key actions |
| **Screenshot for every screen** | Portainer and ArgoCD include a screenshot at every "you should see" point; text-only walkthroughs feel abstract for GUI tools | MEDIUM | PNG per screen; placed immediately after the instruction that triggers it |
| **Troubleshooting / FAQ** | Every tool studied has a FAQ; ArgoCD phrases entries as user questions ("Why is X happening?"); symptom → cause → fix | LOW | At least 10 entries covering real failure modes |
| **Configuration reference** | Vault and ArgoCD dedicate a page to config file fields; every field that affects behavior needs documentation | MEDIUM | `EntraOpsConfig.json` fields, env variables (`PORT`, `VITE_API_URL`) |
| **"What this tool is NOT" section** | Vault and ArgoCD explicitly disclaim scope; prevents support requests for non-features | LOW | Not a replacement for Sentinel, no real-time Graph API, desktop-only |
| **Navigation from README to docs** | GitHub README is the first touch; it must link into docs rather than duplicate them | LOW | `docs/` link in root README |
| **Explicit "no auth = local only" safety note** | Security admins will immediately ask "is this exposed to the network?"; answer must be proactive | LOW | Single callout box in getting-started; repeated in architecture overview |

---

### Table Stakes — Contributor Docs (Developers Expect These)

A developer who forks EntraOps and wants to extend the GUI needs these. Missing = they read source instead of docs.

| Feature | Why Expected | Complexity | Notes |
|---------|--------------|------------|-------|
| **Local dev setup steps** | Every OSS project documents how to run in dev mode with hot reload | LOW | `npm run dev` vs `npm run build`; separate frontend/backend concerns |
| **Project structure map** | Portainer contributor docs include a directory breakdown; developers need to know where to find things | LOW | `gui/src/`, `gui/server/`, key file purposes |
| **How to add a new allowed cmdlet** | PowerShell allow-list is a custom security mechanism; contributors need to know where to change it | LOW | Points to allow-list array in `server.js` or equivalent |
| **API endpoint inventory** | Internal REST + SSE endpoints are called by frontend; documenting them prevents accidental breakage | MEDIUM | GET/POST/SSE endpoints, request/response shapes |
| **Data file format explanation** | `PrivilegedEAM/*.json` structure is the root of all data; contributors extending the GUI must understand it | MEDIUM | EAM object schema, which fields the GUI uses |
| **How to run tests (if any)** | Standard expectation; even if minimal | LOW | "Currently no automated tests; manual verification steps in CONTRIBUTING.md" is acceptable |

---

### Differentiators — Documentation Features That Go Beyond Baseline

These elevate the docs from "present" to "excellent."

| Feature | Value Proposition | Complexity | Notes |
|---------|-------------------|------------|-------|
| **Concepts / domain glossary page** | ArgoCD has "Understand the Basics" before getting started; EntraOps uses EAM jargon (ControlPlane, AdminTierLevel, RoleDefinitionActions) that admins outside the Identiverse community don't know | MEDIUM | Define: ControlPlane/ManagementPlane/UserAccess, EAM, AdminTierLevel, Classification Template, Exclusions |
| **Architecture / data-flow diagram** | Vault has component diagrams; Grafana has data source flow diagrams. The GUI ↔ PowerShell module ↔ local JSON ↔ browser data flow is non-obvious | MEDIUM | ASCII or Mermaid diagram: PS module → JSON files → Express backend → React frontend |
| **"Before you start" security posture note** | This tool applies changes to Entra (AUs, CA Groups); a callout box stating "dry-run first" before Apply to Entra is a trust-builder | LOW | Callout box at top of Apply to Entra screen walkthrough |
| **Annotated screenshots** | Only worth doing for the 3 most complex screens (Apply workflow, Object Browser, Template Editor). Numbered callout zones make walkthroughs significantly clearer | HIGH | Numbered circles ①②③ + legend table; keeps annotation in markdown-maintainable form |
| **Step-outcome pairings** | ArgoCD's getting-started pairs every action with an expected visual outcome ("a panel will be opened"); reduces "did it work?" uncertainty | LOW | Every step ends with: "You should see [description of state]" |
| **"What happens when you..." for irreversible actions** | Security tools that make Entra writes must explain the blast radius before first use | LOW | Prose paragraph in Apply to Entra page: what changes, what doesn't, how to undo |
| **Dry-run walkthrough as first example** | Leading with dry-run as the recommended first run de-risks the first user experience; comparable to Vault's "dev mode" getting started | LOW | Getting-started path terminates at dry-run Apply, not a live run |
| **FAQ phrased as user questions** | ArgoCD FAQ works because entries are "Why is X...?" not "X behavior." Users surface FAQs by symptom, not feature name | LOW | Style guide: each FAQ heading starts with "Why...", "How do I...", "What happens if..." |
| **"See also" cross-links at page bottom** | Grafana and ArgoCD link related docs pages at the bottom of each page | LOW | Each screen page links to: upstream screen, downstream screen, related FAQ entries |

---

### Anti-Features — Commonly Expected, Usually Problematic

Documentation patterns that seem useful but create more problems than they solve for a tool at this scale.

| Feature | Why Requested | Why Problematic | Alternative |
|---------|---------------|-----------------|-------------|
| **Changelog / release notes doc page** | Users want to know what changed | Requires discipline to maintain; gets stale immediately; becomes a liability when outdated | GitHub Releases tab; link from README |
| **Internal API reference (Swagger / OpenAPI)** | Developers expect API docs for any backend | No external API consumers; it's a coupled frontend+backend. Formal spec adds maintenance burden with zero audience | Document 6–8 endpoints inline in contributor docs as markdown tables |
| **JSDoc / TSDoc auto-generated docs** | Modern JS projects sometimes ship generated docs | Domain complexity is in the data model and security logic, not function signatures. JSDoc generates noise, not insight | Document the EAM JSON data model instead; that's where contributors get lost |
| **Video walkthroughs embedded in docs** | Every GUI tool benefits from video | Videos can't live in a git repo, go stale with every UI change, require hosting | Prefer annotated screenshots; they version-control with the code |
| **Versioned docs site** | Large OSS tools version their docs | EntraOps GUI ships in a forked repo; users are always on their fork's version. No distinct "v1.2 docs" audience | Single docs folder; encourage users to read from their fork |
| **Interactive playground / sandbox** | Some tools offer live demos | Requires a running backend, Microsoft device code auth, or mock data; cannot be safely public-facing | Screenshot walkthroughs + dry-run mode serve this purpose |
| **Per-API-call curl examples** | Vault, Stripe document every API call | No external API consumers; curl examples would only document internal plumbing | Document user workflows (task-based), not API calls (implementation-based) |
| **Community / forum links** | Grafana, Portainer include community links | No GUI-specific community exists | Link to parent EntraOps GitHub Discussions instead |
| **Accessibility / localization documentation** | Enterprise tools document a11y and l10n | Single-user local tool; narrow audience; a11y/l10n docs are maintenance overhead with no realistic audience | Single note confirming desktop browser support; nothing further |

---

## Section Structure Recommendations

### docs/ Folder Structure

Based on ArgoCD's separation of concerns and Portainer's install-first entry point:

```
docs/
├── README.md                  # Landing page / nav index
├── getting-started.md         # Quick-start + detailed install steps
├── concepts.md                # EAM tiers, classification templates, exclusions glossary
├── features/
│   ├── dashboard.md           # Tier dashboard
│   ├── object-browser.md      # Object browser + detail panel
│   ├── connect-classify.md    # Connect & Classify wizard
│   ├── template-editor.md     # Classification template editor
│   ├── reclassification.md    # Object reclassification screen
│   ├── exclusions.md          # Exclusions management
│   ├── apply-to-entra.md      # Apply to Entra workflow + dry-run
│   ├── command-runner.md      # PowerShell command runner
│   ├── git-history.md         # Git change history browser
│   └── settings.md            # Settings page
├── configuration.md           # EntraOpsConfig.json reference + env variables
├── architecture.md            # Data flow: PS module → JSON → backend → browser
├── troubleshooting.md         # FAQ + common errors
└── contributing/
    ├── dev-setup.md           # Local dev environment setup
    ├── project-structure.md   # Directory map + key files
    ├── api-reference.md       # Backend endpoints inventory
    └── data-model.md          # PrivilegedEAM JSON schema explained
```

### Getting Started Page Structure

Pattern from ArgoCD + Portainer (consistently effective):

```
1. Prerequisites (explicit version numbers)
2. Quick Start (3 commands to first browser view)
3. Step 1: Fork EntraOps and run classification
4. Step 2: Start the GUI server
5. Step 3: Open the dashboard
6. Step 4: Run a dry-run Apply to Entra (recommended first action)
7. Next Steps (links to each feature page)
```

Each step: instruction → code block → expected outcome ("You should see the Tier Dashboard with your tenant's data.")

### Feature Walkthrough Page Structure

Based on ArgoCD user-guide pages:

```
# [Screen Name]

> One-sentence purpose statement

## Navigation
How to reach this screen from the sidebar / previous screen.

## Overview
[Screenshot of full screen — immediately here, not at end]

## [Action 1 Name]
What the action does → How to do it → Screenshot of result

## Behavior Notes
Edge cases, limitations, what triggers state changes

## See Also
- [Related screen link]
- [Relevant FAQ entry]
```

### Troubleshooting Entry Format

Each FAQ entry (ArgoCD FAQ pattern — verified effective):

```
## Why is [symptom]?

**Cause:** [short prose explanation]

**Fix:**
[step or code block]

**See also:** [link]
```

---

## Screenshot Guidance

| Trigger | Screenshot? | Notes |
|---------|-------------|-------|
| "You should see X after step N" | YES | Placed immediately after the instruction |
| Overview of a new screen | YES | Full-screen, no annotation needed |
| Each stage of a multi-step wizard | YES | 4 Apply stages = 4 screenshots |
| Configuration file example | NO | Use a code block instead |
| Error message (first reference) | YES | Helps users recognize it |
| Real-time SSE stream / animation | NO | Describe in prose; GIFs are a maintenance liability |

**Standards from comparable tools (ArgoCD, Portainer):**

1. Screenshot placed immediately after the sentence that produces the state — not end-of-section
2. Alt text always descriptive: `![Dashboard showing ControlPlane KPI cards]` not `![Dashboard]`
3. File naming: `docs/assets/[screen-name]-[action].png` e.g., `apply-confirm-stage.png`
4. Full-browser-width at 1280px minimum; no partial crops unless annotating a specific zone
5. Use dummy tenant data — never real UPNs, GUIDs, or tenant IDs in screenshots
6. Stale screenshots are worse than no screenshots; update with each UI change

**Annotation (complex screens only — Object Browser, Apply workflow, Template Editor):**
- Numbered circles (①②③) overlaid
- Legend table immediately below: `| ① | Label | What this zone does |`
- Keeps annotation in markdown-maintainable form rather than raster-embedded arrows

---

## Audience Separation Pattern

Based on ArgoCD's three-audience model (strongest example studied):

| ArgoCD Section | EntraOps GUI Equivalent | Framing |
|----------------|------------------------|---------|
| User Guide | `docs/features/` + `docs/getting-started.md` | "How do I..." (task-based) |
| Operator Manual | `docs/configuration.md` + `docs/architecture.md` | "How does it work..." (behavior-based) |
| Developer Guide | `docs/contributing/` | "How do I extend..." (internals-based) |

**Key principles:**

1. **Audience signal at section entry** — "For security admins" vs "For developers extending the GUI" at top of each section
2. **Task framing (user) vs implementation framing (contributor)** — User docs ask "What do I want to do?"; contributor docs ask "How does the system do it?"
3. **Depth inversion** — User docs go wide (all 11 screens) and shallow (no source file references); contributor docs go narrow (key extension points) and deep (file paths, endpoint schemas)
4. **One-directional cross-audience links** — User docs MAY link to architecture for curious users; contributor docs should NOT reference user tasks

---

## Feature Dependencies

```
Getting Started
    └──requires──> Prerequisites list
    └──references──> Concepts page (EAM terms used in walkthrough)

Feature Walkthroughs (11 pages)
    └──require──> Screenshots (no placeholder; ship with images)
    └──reference──> Troubleshooting (each page links to relevant FAQ entries)
    └──reference──> Configuration reference (settings-dependent features)

Troubleshooting
    └──enhanced by──> Architecture (data flow understanding aids diagnosis)
    └──references──> Configuration reference (many fixes involve config changes)

Architecture overview
    └──requires──> Concepts page (data flow uses EAM terms)

Contributing / dev-setup
    └──references──> Architecture
    └──references──> API endpoint inventory
```

---

## MVP for v1.3

### Must Ship

- [ ] `getting-started.md` — fork → classify → run → dashboard (with screenshots)
- [ ] 11 feature pages in `docs/features/` — one per screen, with at least one screenshot each
- [ ] `troubleshooting.md` — FAQ covering 10+ known failure modes
- [ ] `configuration.md` — `EntraOpsConfig.json` field reference

### Should Ship

- [ ] `concepts.md` — EAM glossary; new users need this before feature pages make sense
- [ ] `architecture.md` — data flow diagram; answers top contributor question
- [ ] `contributing/dev-setup.md` — current CONTRIBUTING.md is minimal

### Defer to v1.4+

- [ ] `contributing/api-reference.md` — correct but low urgency; no external consumers yet
- [ ] `contributing/data-model.md` — valuable but requires deep source reading
- [ ] Annotated screenshots (complex screens) — plain screenshots first; annotate in v1.4

---

## Sources

- ArgoCD official docs: https://argo-cd.readthedocs.io/en/stable/ — numbered getting-started, screenshot-per-action, user/operator/developer separation (HIGH — verified April 2026)
- ArgoCD FAQ: https://argo-cd.readthedocs.io/en/stable/faq/ — Q&A format, symptom → cause → fix pattern (HIGH)
- Grafana OSS docs: https://grafana.com/docs/grafana/latest/ — section structure, troubleshooting topics (HIGH)
- Portainer CE install guide: https://docs.portainer.io/start/install-ce/server/docker/linux — prerequisites, numbered steps with expected output (HIGH)
- HashiCorp Vault docs: https://developer.hashicorp.com/vault/docs — use-case entry point, config reference structure (HIGH)
