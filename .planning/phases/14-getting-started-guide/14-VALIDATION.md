---
phase: 14
slug: getting-started-guide
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-04-08
---

# Phase 14 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.
> **Note:** This is a documentation-only phase. There is no application code.
> Verification is structural/content-based rather than unit/integration test based.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | Shell / grep assertions (no test runner — docs phase) |
| **Config file** | none |
| **Quick run command** | `grep -c "You should see" docs/user-guide/getting-started.md` |
| **Full suite command** | `cat docs/user-guide/getting-started.md` |
| **Estimated runtime** | ~1 second |

---

## Sampling Rate

- **After every task commit:** Run `grep -c "You should see" docs/user-guide/getting-started.md`
- **After every plan wave:** Verify all 4 section headers present and non-empty
- **Before `/gsd-verify-work`:** Full content check against all D-XX decisions

---

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirement | Threat Ref | Secure Behavior | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|------------|-----------------|-----------|-------------------|-------------|--------|
| 14-01-01 | 01 | 1 | GS-01, GS-02, GS-03 | — | N/A (docs, no secrets/inputs) | content | `grep -E "Node.js 22\|PowerShell 7\|Microsoft.Graph\|Az " docs/user-guide/getting-started.md` | ❌ stub only | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

Existing infrastructure covers all phase requirements. No test scaffolding needed — content verification uses grep assertions in task `<verify>` blocks.

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| Dashboard shows KPI cards with ControlPlane, ManagementPlane, UserAccess after `npm run dev` | GS-01 | Requires running the GUI locally | `cd gui && npm run dev`, open `http://localhost:5173`, confirm dashboard cards visible |
| Dry-run toggle exists on Apply to Entra screen | GS-03 | Requires running the GUI | Navigate to Apply to Entra screen, confirm "Dry-run mode" switch present |

---

## Validation Sign-Off

- [x] All tasks have `<automated>` verify using grep assertions
- [x] Sampling continuity: single task phase — no gaps
- [ ] Wave 0 covers all MISSING references (N/A — no missing tests)
- [x] No watch-mode flags
- [x] Feedback latency < 2s
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending
