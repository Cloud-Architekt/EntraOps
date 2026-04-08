# Phase 13: Documentation Foundation & Concepts - Discussion Log

**Session date:** 2026-04-05 (updated 2026-04-08)
**Workflow:** discuss-phase

---

## Gray Areas Selected

All 4 areas selected for discussion:
1. Concepts page depth & tone
2. Glossary format & placement
3. docs/README.md style
4. Scaffold placeholder strategy

---

## Discussion Transcript

### Area: Concepts Page Depth & Tone

**Q:** Who is the primary reader of concepts.md?
**Options:** Security admin new to EntraOps / EntraOps user who knows the PS module / Both
**A:** Both — start accessible, add depth

**Q:** How should concepts.md structure its explanation?
**Options:** Model-first / Tier-first / GUI-anchored
**A:** GUI-anchored — link each concept to where it appears in the app

**Q:** What tone should the concepts page strike?
**Options:** Professional / technical / Friendly / approachable / Match existing README tone
**A:** Professional / technical — document style

---

### Area: Glossary Format & Placement

**Q:** Where should the glossary live?
**Options:** Section in concepts.md / Separate glossary.md / Claude's discretion
**A:** Claude's discretion

**Q:** What format should the glossary entries use?
**Options:** Table with GUI cross-reference / Definition-list style / Claude's discretion
**A:** Claude's discretion

---

### Area: docs/README.md Style

**Q:** What style should docs/README.md use?
**Options:** Lean index / Welcoming landing page / Claude's discretion
**A:** (freetext) "You pick, prioritise user simplicity" → Lean index selected

---

### Area: Scaffold Placeholder Strategy

**Q:** How should folders filled by later phases be handled?
**Options:** Stub files / Content-only / Annotated stubs
**A:** (freetext) "You decide" → Stub files with empty headers selected

---

## Summary

- Concepts page: accessible intro + technical depth, GUI-anchored structure, professional tone
- Glossary: Claude's discretion on format and placement (recommended: section in concepts.md, table format)
- README: lean, user-simplicity-first navigation index
- Stubs: empty-header stub files for all sections authored in later phases

---

## Update Session — 2026-04-08

**Areas discussed:** Scaffold file names, External EAM reference, Applied vs computed tier depth, docs/README.md intro scope

---

### Area: Scaffold File Names

| Option | Description | Selected |
|--------|-------------|----------|
| Flat files per feature in user-guide/ | one file per major feature | |
| Subfolders within user-guide/ | nested structure | |
| Leave naming to each downstream phase | defer entirely | |
| **Claude's discretion — flat and simple, user simplicity** | one file per purpose | ✓ |

**User's choice:** "You pick, prioritise user simplicity"
**Notes:** File naming principle = flat and simple, one file per purpose. Claude chooses exact names guided by user simplicity.

---

### Area: External EAM Reference

| Option | Description | Selected |
|--------|-------------|----------|
| Yes — link to Microsoft SPA/EAM docs | link to https://aka.ms/SPA | ✓ |
| No — self-contained only | no external links | |
| Footnote/further reading section only | optional at end | |

**User's choice:** Yes — link to Microsoft SPA/EAM docs
**Placement follow-up:** Intro callout — one sentence up front

---

### Area: Applied vs Computed Tier Depth

| Option | Description | Selected |
|--------|-------------|----------|
| Dedicated subsection — full explanation | prose section with badge descriptions | |
| Glossary entries only | define in table only | |
| Inline paragraph within tier explanation | brief mention in context | |
| **Claude's discretion — user simplicity first** | | ✓ |

**User's choice:** "You pick, prioritise user simplicity"
**Notes:** Must communicate dashed badge = computed, solid badge = applied. Depth is Claude's call.

---

### Area: docs/README.md Intro Scope

| Option | Description | Selected |
|--------|-------------|----------|
| GUI-only, minimal — just navigate | one line, no PS context | |
| Include PowerShell context | explain GUI's place | |
| Short project summary + what docs covers | two sentences | |
| **Clarification: GUI-only, PS module docs stay in root README** | | ✓ |

**User's choice:** "You pick, prioritise user simplicity, original documentation relating to powershell module must remain with additional documentation for the gui"
**Notes:** `docs/` is GUI-specific supplementary documentation. Root README PS module docs must not be touched. docs/README.md intro is GUI-scoped only.
