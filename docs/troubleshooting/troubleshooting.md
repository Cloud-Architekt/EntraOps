# Troubleshooting and FAQ

Use this page when the EntraOps GUI, classification workflow, or template persistence does not behave as expected.
Each entry is symptom-first so you can quickly match what you see to a concrete recovery path.

## Fast Triage (Start Here)

1. Confirm both processes are running from the repo root:
   - GUI client: `http://localhost:5173`
   - API server log: `EntraOps GUI server running at http://127.0.0.1:3001`
2. Confirm PowerShell prerequisites are available in your current session:
   - `pwsh --version`
   - `Get-Command Save-EntraOpsPrivilegedEAMJson`
3. If the dashboard is empty, run classification once:
   - `Connect-EntraOps -AuthenticationType "DeviceAuthentication" -TenantName "<tenant>.onmicrosoft.com"`
   - `Save-EntraOpsPrivilegedEAMJson`
4. If you changed templates, overrides, or exclusions, run classification again to regenerate files consumed by the GUI.
5. If a step fails, match your symptom below and follow the numbered resolution steps.

## Symptom-First Entries

### 1) Symptom: `Save-EntraOpsPrivilegedEAMJson` is not recognized

**Likely cause**
- The EntraOps module is not imported in the current PowerShell session.
- You are running in a shell that is not PowerShell 7+.

**Resolution steps**
1. Open a PowerShell 7+ terminal (`pwsh`).
2. From the repo root, run `Import-Module ./EntraOps`.
3. Verify module commands are available with `Get-Command -Module EntraOps`.
4. Run `Save-EntraOpsPrivilegedEAMJson` again.

**Verify success**
- `Get-Command -Module EntraOps` returns EntraOps cmdlets including `Save-EntraOpsPrivilegedEAMJson`.
- Classification output streams instead of command-not-found errors.

### 2) Symptom: Connect/classification fails with missing Az or Microsoft.Graph module errors

**Likely cause**
- Required PowerShell dependencies are not installed for the current user/profile.

**Resolution steps**
1. In PowerShell, install prerequisites:
   - `Install-Module Az -Scope CurrentUser`
   - `Install-Module Microsoft.Graph -Scope CurrentUser`
2. Restart PowerShell.
3. Re-import EntraOps: `Import-Module ./EntraOps`.
4. Retry connect and classification.

**Verify success**
- Connect flow reaches authentication prompts.
- Classification starts without module import errors.

### 3) Symptom: Dashboard shows "No privileged identity data yet"

**Likely cause**
- No classified output has been generated yet for this repository.
- Classification wrote files in a different working directory than the GUI expects.

**Resolution steps**
1. From the same repo root used by the GUI, run `Save-EntraOpsPrivilegedEAMJson`.
2. Wait for the command to complete.
3. In the dashboard, click **Check Again**.
4. If still empty, confirm `PrivilegedEAM/` contains current JSON output and rerun classification.

**Verify success**
- KPI cards populate for ControlPlane, ManagementPlane, and UserAccess.
- Empty-state text is replaced by charts and recent data widgets.

### 4) Symptom: API server does not start because port 3001 is already in use

**Likely cause**
- Another process is bound to API port `3001`.

**Resolution steps**
1. Stop the conflicting process if it belongs to an old dev server instance.
2. Or start EntraOps API on another port:
   - macOS/Linux: `PORT=3002 npm run dev`
   - PowerShell: `$env:PORT=3002; npm run dev`
3. Keep using `http://localhost:5173` for the client.
4. Confirm the server banner shows the selected API port.

**Verify success**
- Terminal prints `EntraOps GUI server running at http://127.0.0.1:<port>`.
- GUI loads data/API calls without connection-refused errors.

### 5) Symptom: Device sign-in code never appears in the Connect Wizard

**Likely cause**
- Authentication type is not set to DeviceAuthentication.
- Stream output has not yet produced the `microsoft.com/devicelogin` prompt.

**Resolution steps**
1. In **Connect**, choose **Device Code** authentication.
2. Start connect again.
3. Wait for the output panel to emit `https://microsoft.com/devicelogin` and a one-time code.
4. Use that code in a browser session to complete sign-in.

**Verify success**
- Connect step advances past authentication.
- Review & Classify step becomes available.

### 6) Symptom: Device code flow starts but authentication times out or fails

**Likely cause**
- Device code expired before completion.
- Sign-in was completed in the wrong tenant/account context.

**Resolution steps**
1. Cancel the current connect run.
2. Start a new DeviceAuthentication run to get a fresh code.
3. Complete sign-in promptly at `microsoft.com/devicelogin`.
4. Ensure you sign in with the intended tenant account.

**Verify success**
- Connect shows authentication completed.
- Classification can be launched from the same flow without auth failure.

### 7) Symptom: Template save fails with validation error (HTTP 400)

**Likely cause**
- Template JSON no longer matches required tier schema.
- A template name outside supported values was requested.

**Resolution steps**
1. Open the template in **Template Editor** and review tier blocks/entries.
2. Ensure `EAMTierLevelName` values are valid (`ControlPlane`, `ManagementPlane`, `UserAccess`).
3. Ensure required arrays and fields are present in each definition.
4. Save again after correcting structure.

**Verify success**
- Save returns success in the UI.
- Reload shows updated template values without validation errors.

### 8) Symptom: Template changes appear to save but behavior does not change

**Likely cause**
- Template edits were saved, but classification was not rerun.

**Resolution steps**
1. Confirm template changes are present in the editor after reload.
2. Run `Save-EntraOpsPrivilegedEAMJson` to regenerate classification output.
3. Refresh affected screens (Dashboard/Object Browser/Reclassify).

**Verify success**
- Updated classification outcomes align with revised template rules.
- Data views reflect newly generated PrivilegedEAM output.

### 9) Symptom: Override changes do not appear to persist

**Likely cause**
- Overrides were not saved, or save failed.
- Changes were made but not reflected in downstream classification/apply steps.

**Resolution steps**
1. In **Reclassify Objects**, make changes and click **Save All**.
2. Confirm no error appears in the save area.
3. Verify `Classification/Overrides.json` was updated.
4. Rerun classification if you need regenerated output to reflect override decisions.

**Verify success**
- Reloading Reclassify shows the selected override values.
- `Classification/Overrides.json` contains the expected object entries.

### 10) Symptom: Excluded object still appears classifiable or keeps old tier in views

**Likely cause**
- Exclusion changed, but classification has not been rerun yet.
- Existing data reflects previous run output.

**Resolution steps**
1. Confirm the object is listed in **Exclusions** and in `Classification/Global.json` (`ExcludedPrincipalId`).
2. Run classification again.
3. Refresh Object Browser/Reclassify screens.

**Verify success**
- Excluded object shows exclusion indicators and is not treated as a normal classifiable target.
- New run output reflects exclusion changes.

### 11) Symptom: Connect succeeds but classification immediately fails in the final step

**Likely cause**
- Connect authentication completed, but the classification cmdlet run returned non-zero.
- Tenant or system selection is incomplete for this run.

**Resolution steps**
1. Review classification output in the **Classifying** step for first failure line.
2. Retry with default selected systems first, then narrow scope if needed.
3. Confirm tenant name is correct in configuration and connect form.
4. Rerun after fixing any command-level error shown in output.

**Verify success**
- Classification step finishes as completed.
- Dashboard and object data refresh with current run results.

### 12) Symptom: Dashboard still looks stale after a successful run

**Likely cause**
- Browser/session still displays cached state from before the latest classification output.

**Resolution steps**
1. Use in-app refresh actions (for example, **Check Again** on Dashboard).
2. Hard refresh the browser tab.
3. Confirm run completed and produced updated files under `PrivilegedEAM/`.

**Verify success**
- KPIs and object counts reflect the most recent classification execution.
- Recent data indicators match the latest run timing.

## Security and Safety Notes

- Do not paste access tokens, device codes, or secrets into issue trackers, chat logs, or screenshots.
- Use the Connect Wizard and local terminal output for diagnostics instead of sharing sensitive command output publicly.
- Keep troubleshooting actions limited to known EntraOps commands and repository files.

## Related Documentation

- [Getting Started](../user-guide/getting-started.md)
- [Connect Wizard](../user-guide/connect-wizard.md)
- [Classification Template Editor](../user-guide/template-editor.md)
- [Object Reclassification](../user-guide/object-reclassification.md)
- [Exclusions Management](../user-guide/exclusions.md)
- [Apply to Entra](../user-guide/apply-to-entra.md)
- [Configuration Reference](../configuration/configuration-reference.md)
