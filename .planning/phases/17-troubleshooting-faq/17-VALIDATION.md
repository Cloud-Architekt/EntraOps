---
phase: 17
slug: troubleshooting-faq
status: draft
nyquist_compliant: true
wave_0_complete: true
created: 2026-04-09
---

# Phase 17 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | shell content checks (docs-focused) |
| **Config file** | none — repository does not define a dedicated docs test framework |
| **Quick run command** | `grep -c '^### ' docs/troubleshooting/troubleshooting.md` |
| **Full suite command** | `grep -c '^### ' docs/troubleshooting/troubleshooting.md && rg -n 'PowerShell|No privileged identity data yet|3001|device|template|override|Save-EntraOpsPrivilegedEAMJson' docs/troubleshooting/troubleshooting.md` |
| **Estimated runtime** | ~2 seconds |

---

## Sampling Rate

- **After every task commit:** Run `grep -c '^### ' docs/troubleshooting/troubleshooting.md`
- **After every plan wave:** Run `grep -c '^### ' docs/troubleshooting/troubleshooting.md && rg -n 'PowerShell|No privileged identity data yet|3001|device|template|override|Save-EntraOpsPrivilegedEAMJson' docs/troubleshooting/troubleshooting.md`
- **Before `/gsd-verify-work`:** Full suite must be green
- **Max feedback latency:** 5 seconds

---

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirement | Threat Ref | Secure Behavior | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|------------|-----------------|-----------|-------------------|-------------|--------|
| 17-01-01 | 01 | 1 | TRBL-01 | T-17-01 | Troubleshooting advice avoids exposing sensitive token values and uses local-only operational guidance | docs | `grep -c '^### ' docs/troubleshooting/troubleshooting.md` | ✅ | ⬜ pending |
| 17-01-02 | 01 | 1 | TRBL-01 | T-17-02 | All mandatory failure categories are covered with actionable remediation steps | docs | `rg -n 'PowerShell|No privileged identity data yet|3001|device|template|override' docs/troubleshooting/troubleshooting.md` | ✅ | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

- Existing infrastructure covers all phase requirements.

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| User can follow a listed fix and recover in UI | TRBL-01 | Requires interactive GUI + PowerShell environment state | Start GUI, reproduce one symptom, follow documented steps, confirm expected success state |

---

## Validation Sign-Off

- [x] All tasks have `<automated>` verify or Wave 0 dependencies
- [x] Sampling continuity: no 3 consecutive tasks without automated verify
- [x] Wave 0 covers all MISSING references
- [x] No watch-mode flags
- [x] Feedback latency < 5s
- [x] `nyquist_compliant: true` set in frontmatter

**Approval:** pending
