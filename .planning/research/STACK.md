# Stack Research — docs/ Tooling

**Domain:** Documentation folder for a locally-hosted developer tool (fork-and-run model)
**Researched:** 2026-04-05
**Confidence:** HIGH

---

## Recommendation: Plain Markdown — No Generator Needed

**Verdict:** Stay with well-structured `.md` files. Do **not** add VitePress, Starlight, or Docusaurus for this milestone.

The fork-and-run audience constraint makes this clear: users who have just run `cd gui && npm install && npm run dev` are not going to run a separate `npm run docs:dev`. They will read docs on GitHub or in their editor. GitHub's native Markdown renderer is the delivery surface, not a localhost docs site.

---

## Why Not the Generators

| Tool | Showstopper | Notes |
|------|-------------|-------|
| **VitePress 1.6.4** | Vue runtime in a React project | Even as a devDep only, introduces `vue` dependency to a React codebase; creates contributor confusion. 415k weekly downloads — mature, but wrong ecosystem match. |
| **Starlight (Astro)** | Entirely separate Astro framework; self-labeled beta | Requires a new `src/content/docs/` structure, Astro config, and its own `npm run dev`. "Because Starlight is beta software, there will be frequent updates and improvements." Zero overlap with existing Vite/React setup. |
| **Docusaurus v3.9.2** | Separate React website project, Webpack-based | React-based (good alignment), but creates a fully standalone `package.json` with its own build pipeline distinct from `gui/`. Heavy for companion docs in a local developer tool. |

---

## Recommended Stack

### Core Technologies

| Technology | Version | Purpose | Why Recommended |
|------------|---------|---------|-----------------|
| Plain Markdown (`.md`) | — | All documentation files | Native GitHub rendering, zero tooling, editor-readable, forward-compatible with VitePress if requirements change |
| Relative path links | — | Internal doc navigation | `[text](./other-page.md)` works identically in GitHub, VSCode preview, and VitePress — no refactoring if a generator is added later |
| `docs/screenshots/` folder | — | Screenshot storage | Committed PNGs/JPGs with relative references (`![alt](./screenshots/foo.png)`); GitHub renders inline, no tooling required |

### Supporting Libraries

| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| `markdownlint-cli2` | `^0.17` | Lint Markdown for consistent style | Optional — add as a `devDependency` in the root `package.json` if contributors will write docs; zero runtime cost |

> **markdownlint is optional.** It enforces heading levels, line lengths, link formatting. Worth adding if more than one contributor writes docs. Not a blocker for the docs sprint.

### Development Tools

| Tool | Purpose | Notes |
|------|---------|-------|
| VSCode Markdown preview (`Cmd+Shift+V`) | Author-time rendering | Built-in; relative image paths and links work natively |
| GitHub Markdown renderer | Primary end-user reading surface | Renders inline images, tables, code blocks, relative `.md` links automatically |

---

## Installation

```bash
# Nothing required for plain Markdown.

# Optional: Markdown linter as root devDep
npm install -D markdownlint-cli2

# Add to root package.json scripts:
# "docs:lint": "markdownlint-cli2 docs/**/*.md"
```

---

## Screenshot Management

No tooling additions needed. Use this convention:

```
docs/
  screenshots/
    dashboard/
      dashboard-overview.png
      dashboard-kpi-cards.png
    object-browser/
      object-browser-filter.png
    ...
```

Reference in Markdown:

```markdown
![Dashboard overview](./screenshots/dashboard/dashboard-overview.png)
```

This path syntax works unchanged in: GitHub web UI, VSCode Markdown preview, and VitePress (if added later). Organize by feature area so screenshots are reusable across multiple doc pages.

**Screenshot capture:** Use browser DevTools device toolbar at a consistent viewport (1440×900 recommended) for uniform sizing. Commit as PNGs. No compression tooling needed at this scale.

---

## Internal Links

Use `.md` extension in all cross-doc links:

```markdown
[Getting Started](./getting-started.md)
[Troubleshooting](./troubleshooting.md#common-errors)
```

**Critical for forward-compatibility:** VitePress 1.6.4 converts `.md` link extensions to `.html` routes at build time, so the exact same Markdown works in both GitHub and a future VitePress site with zero changes to content.

---

## Alternatives Considered

| Recommended | Alternative | When to Use Alternative |
|-------------|-------------|-------------------------|
| Plain Markdown | VitePress 1.6.4 | If a public GitHub Pages / hosted docs site becomes a future milestone goal — bolt VitePress on top of the same `docs/` folder with zero content restructuring |
| Plain Markdown | Docusaurus 3.9 | If docs grow to 50+ pages and need versioning, full-text search, or i18n. Separate project setup is then justified. |
| Plain Markdown | Starlight | If the project moves to Astro for the main frontend — not applicable here |

---

## What NOT to Use

| Avoid | Why | Use Instead |
|-------|-----|-------------|
| `.mdx` files | Requires a renderer (Docusaurus / Next.js) to process — GitHub renders them as raw text | Plain `.md` |
| Absolute URLs for internal links | Breaks after repo forks/renames | Relative `.md` paths |
| HTML `<img>` tags for screenshots | Not portable across renderers | `![alt](./path.png)` Markdown syntax |
| GitBook / Notion / Confluence | External service; breaks fork model entirely | Committed Markdown files |

---

## Stack Pattern for This Project

**Because users fork the repo and read docs locally or on GitHub:**
- Use plain `.md` files, relative links, `docs/screenshots/` folder
- No additional dependencies

**If a hosted docs site becomes a future milestone goal:**
- Add `vitepress@^1.6.4` as a root `devDependency` (not inside `gui/`)
- Run `npx vitepress init` pointing at `./docs` — zero content restructuring needed
- Existing `.md` files and relative-path links work unchanged
- Add `docs:dev` / `docs:build` scripts to root `package.json`
- Install would be ~2.75 MB, Node 20+ required, Vite/Vue isolated from `gui/client`

---

## Version Compatibility

| Package | Compatible With | Notes |
|---------|-----------------|-------|
| VitePress 1.6.4 (future opt-in) | Node 20+, existing `.md` files | Root-level devDep only; completely isolated from `gui/client` (Vite 5.x) — no version conflicts possible |
| markdownlint-cli2 0.17 | Node 18+ | Zero runtime/build dependency; lints only |

---

## Sources

- VitePress 1.6.4: https://www.npmjs.com/package/vitepress (published ~17 days before research date; 415k weekly downloads)
- VitePress getting started: https://vitepress.dev/guide/getting-started (updated 26 Mar 2026)
- Starlight getting started: https://starlight.astro.build/getting-started/ (updated Oct 15, 2025; self-labeled beta)
- Docusaurus v3.9.2: https://docusaurus.io/docs (updated Mar 6, 2026)
- Existing stack verified via `gui/client/package.json` inspection (React 19, Vite, Tailwind CSS v4, vitest)
- Confidence: HIGH — official docs + npm registry + direct codebase inspection
