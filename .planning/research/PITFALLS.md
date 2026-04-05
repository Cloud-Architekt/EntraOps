# Domain Pitfalls: Documentation for EntraOps GUI

**Domain:** Writing/adding documentation to an existing security administration GUI (local-first, PowerShell-backed, JSON-driven)
**Researched:** 2026-04-05
**Confidence:** HIGH — codebase analysis + Diátaxis framework + Write the Docs community conventions

---

## Critical Pitfalls

### PITFALL-D1: Screenshot Drift

**What goes wrong:**
Screenshots captured during documentation authoring become stale as the UI evolves. EntraOps ships frequently (3 milestones, 12+ screens). A screenshot of ObjectBrowser showing v1.0 columns, or ApplyPage without the dry-run amber indicators, actively misleads users and erodes trust in the docs.

**Why it happens:**
Screenshots are expensive to maintain. Writers take them once during authoring and never update them because there is no process to flag staleness when UI changes ship.

**How to avoid:**
- Use alt-text as a self-check: the description should remain accurate even if the image is stale ("Object Browser showing filterable tier column with dashed computed-tier badge")
- Avoid screenshots of transient/state-heavy UI (SSE streaming log mid-run, empty states, loading skeletons) — these are impossible to keep current
- Prefer annotated screenshots over raw UI dumps — annotations survive minor visual changes
- Add a comment like `<!-- screenshot: screens/object-browser.png, taken v1.2 -->` so staleness is traceable
- Limit screenshots to structural orientation (sidebar nav, top-level page layout) — not pixel-precise feature walkthroughs

**Warning signs:**
- Screenshot shows fewer sidebar items than the current app (e.g., missing Exclusions or Apply nav items)
- Badge/chip styles in screenshot don't match the current amber/dashed visual system
- Settings page screenshot shows fewer config fields than `EntraOpsConfig.json` actually has

**Phase to address:** Getting Started + Feature Walkthrough phases. Establish screenshot policy before any screenshots are taken.

---

### PITFALL-D2: Audience Mismatch — Writing for the Developer, Not the Security Admin

**What goes wrong:**
Documentation written by the developer reads as if the audience is another developer. It explains component hierarchy, API endpoints, and internal architecture — when the real primary audience is a security administrator who knows Entra ID, RBAC, and Conditional Access deeply but doesn't care about the Express server or React state management.

**Why it happens:**
The author knows the internals and keeps reaching for familiar language. "The client calls `/api/objects` which reads from `PrivilegedEAM/*.json`" is developer-framing. The security admin wants: "The dashboard reads the classification data that EntraOps produced the last time you ran `Save-EntraOpsPrivilegedEAMJson`."

**How to avoid:**
- Define two distinct personas before writing a single sentence: Security Admin (end user) and Contributor (developer). Assign every doc section to exactly one persona.
- End-user docs: measure success by whether someone with zero React/Node knowledge can complete the task described
- Use Entra/RBAC terminology the admin already knows: "ControlPlane principal", "PIM eligible assignment", "Administrative Unit scope" — not "row data" or "JSON object"
- Never surface internal routes, component names, or server file paths in end-user docs
- Contributor docs can and should reference internals — but only in contributor-labelled sections

**Warning signs:**
- A sentence contains both "the user" and "the server" in the same step
- API endpoints appear in getting-started content
- File paths like `gui/server/routes/objects.ts` appear outside the Architecture section
- A Troubleshooting entry explains a React error boundary instead of a user-visible symptom

**Phase to address:** All phases — establish persona assignment in doc structure before any content is authored.

---

### PITFALL-D3: Missing the "Why" Behind Tier Model and Security Concepts

**What goes wrong:**
Docs describe what each screen does ("The Dashboard shows KPI cards for each tier") without explaining why the tier model matters. A new user who doesn't understand why ControlPlane is dangerous can't evaluate what they're seeing, can't make classification decisions, and can't understand why the Apply workflow exists.

**Why it happens:**
The author assumes the reader is already familiar with EntraOps concepts. The README and upstream PowerShell module docs exist but aren't part of the GUI docs. Users who forked the repo specifically for the GUI may never read them.

**How to avoid:**
- Include a Concepts or Background section early in the docs covering: ControlPlane / ManagementPlane / UserAccess tier definitions, why tier separation matters, what "applied" vs "suggested" means, and what `Save-EntraOpsPrivilegedEAMJson` produces
- This section doesn't explain button mechanics — it explains the mental model the entire GUI is built around
- Link to it from every screen doc that uses tier terminology
- Keep it short: 300-500 words with a tier comparison table. Not a thesis.

**Warning signs:**
- Dashboard docs say "KPI cards show ControlPlane counts" without explaining what ControlPlane means or why it matters
- Classification Template docs describe the JSON syntax without explaining what a "classification template" is in identity governance terms
- A user could follow all doc steps perfectly and still not know whether what they see in the UI is a problem or expected

**Phase to address:** Concepts/Background doc — must be the first authored section, referenced everywhere else.

---

### PITFALL-D4: Poor Troubleshooting Content — Symptoms Not Covered

**What goes wrong:**
Troubleshooting section covers error codes and technical exceptions, but not the symptom a security admin actually experiences. The most common failure modes for this tool are invisible to technical docs:
- Dashboard shows zeros / "No data" after running the wizard
- PowerShell command runner hangs or shows no output
- Classification changes "saved" but don't appear on restart
- Port 3001 already in use on startup

None of these produce an obvious error code — they present as UI states.

**Why it happens:**
Writers document errors they encountered during development (Node exceptions, Zod validation failures) rather than failure modes that surface to the end user. Real troubleshooting trees come from user testing, not solo dev experience.

**How to avoid:**
- Structure troubleshooting by symptom ("Dashboard shows zeros", "Apply screen progress bar stopped") not by technical cause
- For each screen, ask: "What does this page look like when something is wrong?" — document each empty/error state
- Cover the five most common setup failures: missing `pwsh` binary, PrivilegedEAM directory empty, `EntraOpsConfig.json` missing/invalid, port conflict on 3001, device code auth timeout
- Add a diagnosis flowchart for the getting-started path: data exists? servder started? port accessible? browser pointed at correct URL?

**Warning signs:**
- Troubleshooting section starts with "Run npm install" — that is setup, not troubleshooting
- No entries that mention empty states (empty object browser, empty dashboard, empty history list)
- PowerShell cmdlets appear in troubleshooting without explaining how to check if `pwsh` is installed
- No mention of the PrivilegedEAM directory or how to verify it is populated

**Phase to address:** Troubleshooting/FAQ doc — requires review of the actual page empty-state components to enumerate real failure modes.

---

### PITFALL-D5: Configuration Docs That Don't Match Actual Defaults

**What goes wrong:**
`EntraOpsConfig.json` has ~40 fields across nested sections (workflow triggers, RBAC system arrays, classification update config, scope update config). Docs that describe defaults from memory diverge from what the actual committed file contains. Users follow the docs, configure incorrectly, and don't know why the app behaves differently.

**Why it happens:**
Config docs are written once and forgotten. The config file evolves (new fields added, defaults changed) but docs don't update because there is no coupling between config schema and docs.

**How to avoid:**
- Source truth from the actual file: generate the config reference by reading `EntraOpsConfig.json` and `Classification/Global.json` directly — don't write it from memory
- List every top-level field with: current default value, type, which GUI screen exposes it (Settings page / Classification editor / not exposed), and what happens if omitted
- Explicitly call out GUI-only fields vs PowerShell module fields vs shared fields — users want to know which config changes require a GUI restart
- Note that `EntraOpsConfig.json` is both read by the PowerShell module and the GUI server — changes made via the Settings page are immediately visible to both

**Warning signs:**
- Config docs show fewer fields than the actual `EntraOpsConfig.json`
- Docs describe a field as "optional" but omitting it causes a server startup error
- `RbacSystems` default in docs doesn't match the committed version
- No distinction between "requires app restart" and "hot-reloaded"

**Phase to address:** Configuration Reference doc. Audit against live `EntraOpsConfig.json` before publishing.

---

### PITFALL-D6: Missing Quick-Start Path — No Clear "Zero to Dashboard" Flow

**What goes wrong:**
Comprehensive docs cover every feature in depth but the user who just forked the repo can't find the five-step path to a working dashboard. They read about classification templates before they've started the server. They arrive at "Apply to Entra" before understanding what tier classification means.

**Why it happens:**
Feature-complete docs are organized by feature, not by user journey. The writer documents what they built, not what the user needs to do first.

**How to avoid:**
- Make the getting-started guide the only entry point for new users — it should take someone from `git clone` to seeing real data in the Dashboard in under 10 minutes
- The quick-start path has exactly one happy path: fork → `Save-EntraOpsPrivilegedEAMJson` → `cd gui && npm install && npm run dev` → open `http://localhost:3001` → authenticate → Dashboard loads
- Everything else (Classification, Reclassify, Apply, History) is reachable from the Dashboard — the quick-start doesn't need to cover them
- Add a "What to do next" section at the end of quick-start that links to feature docs in a recommended order
- Do not put troubleshooting, prerequisites, or architecture in the quick-start path — link out to those

**Warning signs:**
- Quick-start page exceeds 500 words
- PowerShell module installation is placed after the npm steps (it must come first)
- Quick-start requires the reader to make decisions (e.g., which RBAC systems to enable) before they have a working install
- No visual confirmation step ("You should see the Dashboard with KPI cards for each tier")

**Phase to address:** Getting Started guide — must be authored first, from scratch, without referencing any other doc section.

---

## Moderate Pitfalls

### PITFALL-D7: Over-Documenting "How" Instead of Outcomes

**What goes wrong:**
Docs describe UI mechanics ("Click the dropdown, select a tier, click Save All") instead of outcomes ("Reclassify a principal to a lower-privilege tier so it no longer triggers ControlPlane alerts"). Process docs that map every click produce rote walkthroughs that users stop reading after the first paragraph.

**Why it happens:**
The writer is thinking about the UI they built, not the task the admin is trying to accomplish. This is especially common in GUI tools where every screen has a clear interaction sequence.

**How to avoid:**
- Start each screen doc with: "Use this screen when you want to [outcome]"
- Document the intent of a workflow before the mechanics — the admin must understand why before they understand how
- Reserve click-by-click instructions for complex workflows (Connect and Classify wizard, Apply to Entra 4-state flow) where sequence matters
- For simple screens (History, Exclusions), a 2-sentence description plus one representative screenshot is sufficient

**Warning signs:**
- Every screen documentation section is the same length regardless of complexity
- Docs say "click the button to save" rather than "changes are persisted atomically to `Classification/Overrides.json`"
- No outcome described — just mechanics

**Phase to address:** Feature Walkthrough docs — enforce outcome-first framing per section.

---

### PITFALL-D8: GUI Docs and PowerShell Docs Not Integrated

**What goes wrong:**
GUI docs and PowerShell cmdlet docs are treated as separate domains. End-user docs never explain what `Save-EntraOpsPrivilegedEAMJson` actually produces, so users don't understand what the Dashboard is showing them. Developer/contributor docs don't explain which server routes call which cmdlets from the allowlist.

**Why it happens:**
EntraOps has two surfaces (PowerShell module and GUI) developed independently. Documentation authors silo each surface.

**How to avoid:**
- The Architecture / Integration Overview doc must map the data flow: `Save-EntraOpsPrivilegedEAMJson` produces `PrivilegedEAM/*.json` → Express server reads those files → React renders data
- In end-user docs, reference PowerShell cmdlets by name where relevant ("running `Save-EntraOpsPrivilegedEAMJson` refreshes the data shown in Dashboard")
- In the PowerShell Command Runner screen docs, list the 13 allowlisted cmdlets and their GUI-level purpose — not their implementation, just what the user can expect them to trigger
- Document the data freshness concept: the GUI shows the last-run results. If data looks stale, the fix is to re-run the PowerShell cmdlet, not to refresh the browser.

**Warning signs:**
- Docs describe Dashboard data without mentioning how or when it was generated
- Command Runner docs list cmdlets without explaining what they do to the tenant
- No mention of "data freshness" anywhere in end-user docs
- Getting Started assumes the user already knows what `Save-EntraOpsPrivilegedEAMJson` does

**Phase to address:** Architecture/Integration Overview + Getting Started guide.

---

### PITFALL-D9: Dry-Run / Sample Mode Not Prominently Documented

**What goes wrong:**
The Apply to Entra workflow has a `-SampleMode` toggle ("Dry Run / Preview Mode") that prevents writes to the Entra tenant. Docs bury or skip this entirely. Security admins doing a first run don't know whether clicking "Apply" will immediately modify their production tenant.

**Why it happens:**
The feature seems obvious to the builder (it's a toggle with amber indicators). To a security admin reading about the Apply screen for the first time, the distinction between a dry run and a live run is critical and non-obvious.

**How to avoid:**
- Apply screen docs must lead with a clear statement: "Dry Run mode runs all cmdlets with `-SampleMode` — no changes are written to your Entra tenant"
- Document what the amber visual indicators mean before describing the workflow steps
- Include a callout: "Always run in Dry Run mode first when applying to a new tenant or after major classification changes"
- Explain what the SSE log shows differently in dry-run vs live mode

**Warning signs:**
- Apply screen docs don't mention `-SampleMode` or dry-run at all
- No warning about irreversible tenant changes
- Dry-run is documented as an "advanced feature" rather than a first-run safety mechanism

**Phase to address:** Apply to Entra screen docs — must be reviewed by someone who hasn't used the tool before.

---

### PITFALL-D10: Organic Growth Creates Inconsistent Terminology

**What goes wrong:**
Features added across 3 milestones use slightly different naming. The GUI says "Reclassify" in the sidebar but "Override" in the code. Docs may call the same screen "Classification Override" in one section and "Reclassification" in another. Admin searches fail because the term they encountered in one doc section doesn't appear in the troubleshooting section.

**Why it happens:**
Milestone-by-milestone development accumulates naming drift. v1.0 used one term, v1.1 extended it, v1.2 added a different-sounding feature that does something adjacent.

**How to avoid:**
- Create a glossary of 15-20 key terms before writing any docs, aligned with what appears in the UI (nav labels, button text, page headings)
- Lock in: "Reclassify" not "Override" (or vice versa — whichever matches the sidebar), "Applied tier" vs "Computed tier", "Exclusion" vs "Excluded object"
- Use find-in-files across drafted docs to catch inconsistent usage before publish
- Screen names in docs must match Sidebar nav labels exactly

**Warning signs:**
- Same screen referred to by two different names in the same doc page
- "Override" used in troubleshooting but "Reclassify" used in feature walkthrough
- "Classification file" vs "template file" vs "classification template" used interchangeably

**Phase to address:** Glossary — author before any feature docs. Apply consistently throughout.

---

## Technical-Integration Pitfalls (PowerShell + JSON Specifics)

### PITFALL-D11: Missing PowerShell Prerequisite Gate

**What goes wrong:**
Installation docs don't clearly state which PowerShell prerequisites must be installed before the GUI will work. The `pwsh` binary must exist, the EntraOps PowerShell module must be installed, and Az.Accounts / MSAL must be available for device code auth. Missing any of these produces confusing errors in the GUI (Connect page hangs, streaming output is empty, or Node process crashes with non-obvious errors).

**How to avoid:**
- Prerequisites section lists: `pwsh` (PowerShell 7+), EntraOps module, any Az.* module dependencies
- Include a pre-flight check the user can run: `pwsh -Command "Get-Module -ListAvailable"` showing required modules
- Document that `pwsh` must be on PATH (not `powershell.exe`) — this matters on macOS and Linux
- Explain the server's behavior when `pwsh` is unavailable: does it fail on startup or at first cmdlet invocation?

**Warning signs:**
- Prerequisites section says "Node.js 18+" and stops there
- Run Commands or Connect screen docs don't mention PowerShell prerequisites
- No guidance for macOS/Linux users about installing PowerShell 7

---

### PITFALL-D12: JSON File Location Docs Don't Match Real Path Structure

**What goes wrong:**
Config docs refer to JSON files by relative paths that don't match where the user's files actually are. The docs might say `./Classification/Global.json` but the server resolves paths relative to the repo root, not the `gui/` directory. A user editing the wrong file won't see changes reflected.

**How to avoid:**
- Always use repo-root-relative paths in docs: `Classification/Global.json`, `Classification/Overrides.json`, `EntraOpsConfig.json`, `PrivilegedEAM/`
- State explicitly: "All JSON files are relative to the repo root, not the `gui/` subfolder"
- Include a file map in the Architecture doc showing which GUI action writes to which JSON file:

| GUI action | JSON file written |
|---|---|
| Save settings | `EntraOpsConfig.json` |
| Save reclassification override | `Classification/Overrides.json` |
| Add / remove exclusion | `Classification/Global.json` |
| Save classification template | `Classification/Templates/*.json` |

**Warning signs:**
- Docs use relative paths that change depending on working directory
- No mention of which GUI actions are read-only vs write
- Settings page docs don't mention `EntraOpsConfig.json` by name

---

### PITFALL-D13: SSE Streaming Output Is Undocumented

**What goes wrong:**
Both the Connect & Classify wizard and the Apply to Entra screen use SSE (Server-Sent Events) for real-time streaming output from PowerShell. Users who see the log stop mid-run, show an error, or produce unexpected output don't know how to interpret it or what "normal" looks like.

**How to avoid:**
- Include an annotated example of a successful SSE log for both screens (Connect flow output, Apply flow output per cmdlet)
- Document what a stalled stream looks like vs a normal completion
- Explain that the SSE log reflects raw PowerShell stdout — warnings and verbose output are expected and not errors
- Document the per-cmdlet pass/fail outcome summary on the Apply screen and what each state means

**Warning signs:**
- Connect and Apply screen docs show a screenshot of the empty log pane rather than an in-progress or completed run
- No guidance on interpreting stream content
- Troubleshooting doesn't cover "stream stopped / no output"

---

### PITFALL-D14: Classification Template Format Undocumented for Security Admins

**What goes wrong:**
The Templates screen exposes a JSON editor for classification template files. Security admins need to understand the schema to make useful edits. Docs that say "edit the JSON" without explaining what `AdminTierLevel`, `Classifications`, `RoleDefinitionId`, or `ExcludedPrincipalIds` mean leave admins unable to use the feature.

**How to avoid:**
- Include a Classification Template Schema Reference — even a minimal one covering the key fields an admin would change
- Show a before/after example: "to add a custom ControlPlane classification for a custom role..."
- Reference the Zod validation so admins know what errors mean when the diff preview rejects their changes
- Distinguish between the Templates editor (structural changes to classification rules) and the Reclassify screen (per-object tier overrides) — these are commonly confused

**Warning signs:**
- Templates screen docs just say "edit classification templates here"
- No field-level explanation for `AdminTierLevel`, `Classifications`, or `RoleDefinitionId`
- No mention that the editor validates against a schema before saving

---

## Technical Debt Patterns (Documentation-Specific)

| Shortcut | Immediate Benefit | Long-term Cost | When Acceptable |
|---|---|---|---|
| Copy README intro into Getting Started | Fast first draft | README is code-focused; security admin audience is lost immediately | Never — rewrite for the audience |
| Screenshot every screen state | Feels thorough | 80% of screenshots are stale within 2 months | Structural/orientation screenshots only |
| Single long REFERENCE.md for all config | Easy to create | Impossible to maintain and cross-reference | Never — split by audience and function |
| Skip the Concepts section ("users already know Entra") | Saves time | Users who don't know tier model can't use Reclassify or Apply correctly | Never — Concepts doc is 300 words, not a chapter |
| Document GUI and PowerShell module in the same page | Everything in one place | GUI audience drowns in PowerShell detail they don't need | Never — link between them instead |
| Rely on tooltips/UI labels as documentation | Low maintenance | UI text changes break the implicit documentation contract | Only for simple confirmations |

---

## Integration Gotchas

| Integration | Common Mistake | Correct Approach |
|---|---|---|
| PowerShell data flow | Documenting PS cmdlets and GUI as separate silos | Architecture doc explains the handoff: PS cmdlets write JSON, Express reads JSON, React renders |
| `EntraOpsConfig.json` vs Settings page | Documenting all fields as "GUI settings" | Flag fields the GUI doesn't expose (module-only fields) so admins know to edit JSON directly |
| Classification files vs Reclassify screen | Implying all classification changes happen via Templates | Reclassify writes `Overrides.json`; Templates writes `Templates/*.json` — different files, different effects |
| SSE streaming vs user instructions | Treating streaming log as a terminal | Streaming log is read-only output — admins cannot type into it |
| Git history vs classification changes | "History shows all changes" | History shows git commits to `PrivilegedEAM/` — if user hasn't committed after changes, history is stale |

---

## "Looks Done But Isn't" Checklist

- [ ] **Getting Started:** Does it work on macOS with `pwsh` on PATH? Test on a clean terminal session.
- [ ] **Config Reference:** Does every field in `EntraOpsConfig.json` appear in the docs? Audit with `jq 'keys' EntraOpsConfig.json`.
- [ ] **Apply screen docs:** Does dry-run / sample mode appear in the first paragraph?
- [ ] **Troubleshooting:** Does every screen have a documented empty-state / "no data" failure mode?
- [ ] **Concepts section:** Does it explain ControlPlane / ManagementPlane / UserAccess in plain language without assuming prior EntraOps reading?
- [ ] **Terminology:** Is "Reclassify" vs "Override" consistent with sidebar nav labels throughout?
- [ ] **PowerShell prerequisites:** Are `pwsh` + EntraOps module listed before `npm install` in setup sequence?
- [ ] **JSON file paths:** Are all paths repo-root-relative (not `gui/`-relative)?
- [ ] **SSE streaming:** Is there an annotated example of a successful Apply run output?
- [ ] **Audience assignment:** Has every doc section been labeled "Security Admin" or "Contributor"?

---

## Phase-Specific Warnings

| Doc Section | Likely Pitfall | Mitigation |
|---|---|---|
| Getting Started | Missing PowerShell prereqs before npm steps | Prerequisite gate section first |
| Dashboard walkthrough | Skipping data freshness | Lead with "data reflects last `Save-EntraOpsPrivilegedEAMJson` run" |
| Templates screen | JSON schema opacity without field reference | Include minimal schema table for the fields admins change |
| Connect & Classify | Device code auth flow not sequenced correctly | Step-by-step with expected screen state at each step |
| Apply to Entra | Dry-run not explained before the 4-action toggles | Dry-run callout must appear before action selection UI |
| Reclassify screen | Confusion between "computed tier" and "applied tier" | Reference Concepts section at top of screen doc |
| Troubleshooting | Node stack traces documented instead of user-visible symptoms | Every entry starts with "You see: [symptom]" |
| Configuration Reference | Settings page docs conflated with full EntraOpsConfig schema | Split: "Settings page fields" and "Full config schema" as separate sections |
| Contributor Architecture | GUI-internal routes documented without explaining data flow | Lead with the data flow diagram before any implementation detail |

---

*Sources: Codebase analysis (gui/client/src/pages/, Classification/ files, EntraOpsConfig.json), Diataxis documentation framework (diataxis.fr), Write the Docs community conventions, security tooling documentation patterns.*
