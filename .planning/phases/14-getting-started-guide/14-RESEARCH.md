# Phase 14: Getting Started Guide — Research

**Phase:** 14 — Getting Started Guide
**Researched:** 2026-04-08
**Discovery Level:** 0 (pure documentation; all implementation facts confirmed from codebase)

---

## Summary

Phase 14 writes `docs/user-guide/getting-started.md`, filling the Phase 13 stub. This is a documentation-only phase. All design decisions are locked in CONTEXT.md (D-01–D-12). Research confirmed concrete implementation facts needed to write accurate commands and UI descriptions.

---

## Confirmed Implementation Facts

### GUI Dev Server

- **Command:** `cd gui && npm run dev`
- **What it starts:** Uses `concurrently` to run both:
  - Vite client dev server → `http://localhost:5173`
  - Express API server → `http://127.0.0.1:3001` (API only, proxied via Vite)
- **User-visible URL:** `http://localhost:5173` (Vite handles the browser client in dev mode)
- **Source:** `gui/package.json` → `"dev": "concurrently \"npm run dev -w client\" \"npm run dev -w server\""`, `gui/server/index.ts:46`, `gui/client/vite.config.ts:33`

### Sample Data (Quick Dashboard)

- **Path:** `PrivilegedEAM/` — committed to the repo with real-structured subdirectories
- **Structure:** Subdirectories per RBAC system: `EntraID/`, `Defender/`, `DeviceManagement/`, `IdentityGovernance/`, `ResourceApps/`
- **Effect:** Dashboard populates with tier data on first `npm run dev` — no live tenant required
- **KPI cards confirmed:** ControlPlane, ManagementPlane, UserAccess (from STATE.md and CONTEXT.md D-specifics)

### Dry-Run Toggle (Apply to Entra Screen)

- **File:** `gui/client/src/pages/ApplyPage.tsx`
- **Label:** **"Dry-run mode"** (exact UI label from `Label` component at line 417)
- **Sub-label:** "Simulate changes without writing to Entra. Cmdlets run with -SampleMode."
- **ID attribute:** `dry-run-toggle`
- **When enabled badge shows:** "◈ Simulation active" (sky-blue badge)
- **Mechanism:** Sets `parameters.SampleMode = true` on each cmdlet call
- **Output prefix:** `[DRY RUN]` prepended to each run separator in streaming output

### EntraOpsConfig.json Fields

Actual fields (from `EntraOpsConfig.json` in root):
- `TenantId` — GUID
- `TenantName` — e.g., `contoso.onmicrosoft.com`
- `AuthenticationType` — e.g., `"UserInteractive"`
- `ClientId` — GUID (app registration for non-interactive auth)
- `DevOpsPlatform`, `RbacSystems`, `WorkflowTrigger` — advanced options, not required for quick start

### PowerShell Connect & Classify Commands

From `IMPLEMENTATION_GUIDE.md` (Step 5):
```powershell
Connect-EntraOps -AuthenticationType "UserInteractive" -TenantName "contoso.onmicrosoft.com"
Save-EntraOpsPrivilegedEAMJson -RbacSystems @("EntraID", "IdentityGovernance", "ResourceApps")
```

### Install Command

From `IMPLEMENTATION_GUIDE.md` (Step 2):
```powershell
git clone https://github.com/<your-org>/<your-entraops-fork>
cd <your-entraops-fork>
Import-Module ./EntraOps
```

---

## Prerequisite Install Sources (for D-02 links)

| Dependency | Install URL |
|------------|------------|
| Node.js 22+ | https://nodejs.org |
| PowerShell 7+ | https://github.com/PowerShell/PowerShell |
| Az module | `Install-Module Az` (PSGallery) |
| Microsoft.Graph module | `Install-Module Microsoft.Graph` (PSGallery) |

---

## Stub Structure (Phase 13 Headers)

`docs/user-guide/getting-started.md` currently has 4 empty headers:
```markdown
# Getting Started
## Prerequisites
## Installation
## First Run
## Dry-Run / Preview Mode
```

The guide will fill all 4 sections plus potentially add sub-sections for the two-stage approach (D-04).

---

## Validation Architecture

No automated testing applies to documentation. Verification is human-driven:

- All prerequisites listed before step 1
- Every numbered step has a "You should see…" confirmation line
- `http://localhost:5173` opens and shows dashboard populated with sample data
- Dry-run section appears before any Apply step
- All D-XX decisions are implemented

---

## Standard Stack

- Plain Markdown (no MDX, no static site generator — per Phase 13 conventions)
- Fenced code blocks with `sh` or `powershell` language hints
- Title-case section headings (e.g., `## Prerequisites`)
- Professional/technical tone (per D-11)

---

## Common Pitfalls to Avoid

1. **DO NOT** say Node.js 20+ — CONTEXT.md D-03 overrides REQUIREMENTS.md: use **22+**
2. **DO NOT** use `localhost:3001` in commands — users browse `localhost:5173` (Vite client port)
3. **DO NOT** describe a live Entra write in the guide — guide ends at dry-run (D-09, D-10)
4. **DO NOT** duplicate IMPLEMENTATION_GUIDE.md — reference it for advanced config; guide gives minimal steps only
5. **DO NOT** skip the "You should see…" outcome line on any numbered step (ROADMAP SC3)
