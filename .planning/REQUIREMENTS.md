# Requirements — v1.3 Updated UI Documentation

## Active Requirements

### DOCS — Structure & Navigation

- [ ] **DOCS-01**: User finds a `docs/README.md` index with links to all documentation sections
- [ ] **DOCS-02**: `docs/assets/screenshots/<screen>/` hierarchy stores captured screenshots per GUI screen

### GS — Getting Started

- [ ] **GS-01**: User can follow a getting-started guide from zero (fork) to a working browser dashboard
- [ ] **GS-02**: Getting-started guide clearly states prerequisites (Node.js 20+, PowerShell 7+, EntraOps PS module)
- [ ] **GS-03**: Getting-started guide introduces dry-run / preview mode before any Apply-to-Entra steps

### FEAT — Feature Walkthroughs

- [ ] **FEAT-01**: User finds a dedicated walkthrough page for each of the 10 GUI screens
- [ ] **FEAT-02**: Each walkthrough page includes a real screenshot captured from the live app at localhost:5173
- [ ] **FEAT-03**: Apply to Entra walkthrough covers all 4 workflow states (select, confirm, streaming, outcomes)

### CONC — Concepts & Glossary

- [ ] **CONC-01**: User reads a concepts page explaining the EAM tier model before exploring the GUI
- [ ] **CONC-02**: Glossary defines ControlPlane, ManagementPlane, UserAccess, applied tier, computed tier, exclusion, override

### ARCH — Architecture Overview

- [ ] **ARCH-01**: User reads an architecture overview showing how the GUI reads from PrivilegedEAM/ JSON and writes to Classification/ files

### TRBL — Troubleshooting

- [ ] **TRBL-01**: User finds 10+ symptom-first troubleshooting entries covering PowerShell prereqs, first-run data issues, auth failures, and template validation errors

### CONF — Configuration Reference

- [ ] **CONF-01**: User finds a configuration reference with all EntraOpsConfig.json fields, types, and defaults
- [ ] **CONF-02**: Configuration reference documents startup environment variables and API port options

### ROOT — Root Updates

- [ ] **ROOT-01**: User finds a Documentation section in root README.md linking to `docs/README.md`

---

## Deferred to Future

- Contributor / developer guide (dev environment setup, adding features, testing patterns) — deferred to v1.4
- API reference for server routes (auto-generated or manual) — deferred to v1.4
- Versioned documentation / changelog-as-doc-page — out of scope (single-repo, no hosted site)
- VitePress or static site generation — out of scope for v1.3 (plain Markdown; upgrade path exists)

## Out of Scope (v1.3)

- **Hosted documentation site** — docs are read on GitHub or in-editor; no GitHub Pages / Netlify deployment
- **Auto-generated API docs** — no JSDoc or OpenAPI generation tooling
- **Video walkthroughs** — prose + screenshots only
- **Mobile/tablet docs layout** — desktop reading experience only
- **Developer-facing architecture internals** — contributor docs deferred to v1.4

---

## Traceability

_(Filled by roadmapper — maps each REQ-ID to a phase)_
