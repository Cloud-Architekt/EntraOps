---
phase: 17-troubleshooting-faq
type: research
created: 2026-04-09
requirement_ids:
  - TRBL-01
---

# Phase 17 Research: Troubleshooting / FAQ

## Objective
Create a practical troubleshooting guide in docs/troubleshooting/troubleshooting.md with symptom-first entries that map to real GUI and PowerShell behaviors in this repository.

## Inputs Reviewed
- .planning/ROADMAP.md (Phase 17 goal/success criteria)
- .planning/REQUIREMENTS.md (TRBL-01)
- docs/user-guide/*.md and docs/configuration/configuration-reference.md
- gui/server/index.ts (server port/bind behavior)
- gui/client/src/pages/Dashboard.tsx (empty dashboard symptom text)
- gui/client/src/pages/ConnectPage.tsx (device-code UX and classify flow)
- gui/server/services/commands.ts and gui/server/services/connect.ts (token/session behavior)
- gui/server/routes/templates.ts and gui/client/src/pages/TemplatesPage.tsx (template validation paths)
- gui/server/routes/overrides.ts and gui/client/src/pages/ReclassifyPage.tsx (override persistence path)

## Confirmed Troubleshooting Domains (must cover)
1. PowerShell prerequisites and module availability
2. Empty dashboard/no data generated yet
3. Port 3001 conflicts at GUI server start
4. Device-code authentication and sign-in timeout/failure paths
5. Template validation failures when editing/saving
6. Classification overrides appear not to persist

## Code-Backed Signals To Use In Troubleshooting Entries

### No Data / Empty Dashboard
- Dashboard empty state explicitly instructs running Save-EntraOpsPrivilegedEAMJson before refreshing.
- Reclassify screen also shows no-objects guidance to run Save-EntraOpsPrivilegedEAMJson.

### Port Conflicts
- Server default is PORT=3001 (process.env.PORT ?? 3001).
- Server binds to 127.0.0.1 and logs the concrete URL after successful startup.
- Docs should include both default and override path (PORT env var) to resolve collisions.

### Device-Code Auth Failures
- Connect UI defaults to DeviceAuthentication and parses microsoft.com/devicelogin plus one-time code from command output.
- If auth/classify process exits non-zero, UI surfaces failed state and instructs user to inspect stream output.
- Token reuse path exists (refreshAuthTokens + AlreadyAuthenticated) but depends on successful prior connect session.

### Template Validation Failures
- /api/templates/:name validates tier payload with zod schemas.
- Invalid payload returns 400 with schema errors; unknown template names return 400.
- Troubleshooting should steer users toward fixing JSON structure/content, not retry loops.

### Overrides Not Persisting
- Reclassify writes to /api/overrides which persists Classification/Overrides.json.
- UI labels changes as display-layer only; users still need classification/apply flows for downstream enforcement visibility.
- Exclusions and overrides can affect what appears in table rows; stale data guidance exists in exclusions UX.

## Documentation Patterns To Reuse
- Symptom-first headings with immediate action steps.
- "You should see" verification language from prior docs phases.
- Concrete command examples and file paths rooted at repository root.
- Cross-links to existing user-guide pages for deeper workflows.

## Recommended Entry Template
For each FAQ item:
1. Symptom (what user sees in UI/terminal)
2. Likely cause (1-2 concise causes)
3. Resolution steps (numbered and actionable)
4. Verify success (explicit observable outcome)
5. Related doc link (optional but preferred)

## Risks / Pitfalls
- Writing generic troubleshooting advice not tied to actual EntraOps behavior.
- Listing errors by stack trace instead of user-observable symptom (violates phase goal).
- Omitting resolution verification criteria.
- Not covering all mandatory categories in ROADMAP success criteria.

## Validation Architecture
- Add an automated docs gate in the plan: script/check that troubleshooting.md has >=10 H3 symptom entries and includes key category keywords.
- Keep checks lightweight (shell + grep/wc) so verification runs in seconds.
- Include one markdown lint/style check if already available in repository; otherwise use deterministic content checks only.

## Recommendation
Proceed with a single execute plan for phase 17 focused on:
- Defining troubleshooting document structure and mandatory category coverage
- Authoring 10+ symptom-first entries with actionable steps
- Running automated content verification commands to enforce count and coverage
