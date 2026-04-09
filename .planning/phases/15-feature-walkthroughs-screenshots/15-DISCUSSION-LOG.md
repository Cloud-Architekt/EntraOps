# Phase 15: Feature Walkthroughs & Screenshots - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-04-09
**Phase:** 15-feature-walkthroughs-screenshots
**Areas discussed:** Screenshot capture approach, Walkthrough structure & depth, Apply to Entra 4-state coverage, Screen priority & coverage depth

---

## Screenshot Capture Approach

| Option | Description | Selected |
|--------|-------------|----------|
| Playwright automation | Agent launches app and captures PNGs programmatically — fully autonomous | |
| Manual placeholders | Agent writes prose, leaves placeholder references for human to fill | |
| Mixed | Playwright for non-auth screens, placeholders for auth-required screens | |
| VS Code integrated browser | Agent uses VS Code browser automation tools against already-running app | ✓ |

**User's choice:** Use the integrated browser in VS Code — clarified as agent captures automatically using VS Code browser tools (Playwright) against `localhost:5173` which is already running.
**Notes:** App is confirmed running — agent does not need to start it.

---

## Walkthrough Structure & Depth

| Option | Description | Selected |
|--------|-------------|----------|
| Screenshot + overview + key features | 1–2 paragraph intro, screenshot, bullet list of capabilities | ✓ |
| Screenshot + how-to steps | Numbered steps per key action | |
| Screenshot + feature table | Screenshot + two-column Feature/Description table | |

**User's choice:** Screenshot + overview + key features (1–2 paragraph intro, screenshot, bullet list of key features/capabilities).
**Notes on cross-linking:** No "Related screens" boilerplate — cross-links only when directly relevant.

---

## Apply to Entra: 4-State Coverage

| Option | Description | Selected |
|--------|-------------|----------|
| 4 separate screenshots | One per state (select, confirm, streaming, outcomes) with short description | ✓ |
| 1 screenshot + prose | Select-state screenshot + prose description of remaining 3 states | |
| Annotated composite | All 4 states shown top-to-bottom as a workflow strip | |

**User's choice:** Claude's discretion — prioritise user simplicity. Selected 4 separate screenshots (one per state) as the clearest approach that directly satisfies FEAT-03.
**Notes:** Screenshots named `apply-select.png`, `apply-confirm.png`, `apply-streaming.png`, `apply-outcomes.png`.

---

## Screen Priority & Coverage Depth

| Option | Description | Selected |
|--------|-------------|----------|
| Equal depth | All 10 screens get same treatment | ✓ |
| Tiered depth | Core screens get extra detail, utility screens get standard treatment | |

**User's choice:** Claude's discretion — prioritise user simplicity. Selected equal depth across all 10 screens for consistent structure and easier navigation.

---

## Claude's Discretion

- Apply to Entra state coverage format (chose 4 separate screenshots)
- Screen priority approach (chose equal depth for all 10)
- Exact alt text for screenshots
- Navigation breadcrumb line inclusion (recommended)

## Deferred Ideas

- Pre-install prerequisite PowerShell modules in UI setup — feature change, out of phase scope
