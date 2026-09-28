import { expect, test } from "@playwright/test";
import { fileURLToPath, pathToFileURL } from "node:url";

const guideUrl = pathToFileURL(fileURLToPath(new URL("index.html", import.meta.url))).href;

test("opens the expert guide from its sidebar URL", async ({ page }) => {
    await page.goto(`${guideUrl}?guide=expert#detailed-guide`);

    await expect(page.getByRole("heading", { name: "Detailed setup and adoption guide" })).toBeVisible();
    await expect(page.locator('img[src="../assets/automation/adoption-roadmap.svg"]')).toBeVisible();
    await expect(page.locator("#setup-guide")).toBeHidden();
    await expect(page.locator('[data-guide-mode="expert"]')).toHaveClass(/active/);
});

test("builds a zero-configuration express quickstart", async ({ page }) => {
    await page.goto(guideUrl);

    await expect(page.getByRole("heading", { name: "How do you want to use EntraOps?" })).toBeVisible();
    await page.getByRole("button", { name: "Continue" }).click();
    await expect(page.locator("#setupWizard")).toBeFocused();
    await expect(page.getByRole("heading", { name: "Sign in interactively" })).toBeVisible();
    const readAccessNote = page.locator(".setup-note").filter({ hasText: "Required read access" });
    const graphConsentNote = page.locator(".setup-note").filter({ hasText: "Microsoft Graph consent" });
    await expect(readAccessNote).toContainText("Global Reader");
    await expect(readAccessNote).toContainText("Reader");
    await expect(readAccessNote).toContainText("-ApplicationId");
    await expect(readAccessNote).not.toContainText("-SignInName");
    await expect(graphConsentNote).toContainText("Microsoft Graph consent");
    await expect(page.getByRole("link", { name: "baseline collection permissions" })).toHaveAttribute("href", "../core/index.html#service-principal-permissions");
    await expect(page.getByRole("link", { name: "New-AzRoleAssignment reference" })).toBeVisible();
    await page.getByRole("button", { name: "Continue" }).click();
    await expect(page.getByRole("alert")).toHaveText("Enter your Microsoft Entra tenant domain.");
    await page.locator("#tenantName").fill("contoso.onmicrosoft.com");

    await page.getByRole("button", { name: "Continue" }).click();
    await expect(page.locator('label.setup-choice:has(input[value="ResourceApps"]) .setup-choice-title')).toHaveText("Workload Identities");
    await expect(page.locator('label.setup-choice:has(input[value="ResourceApps"]) .setup-choice-desc')).toHaveText("(Agents and Enterprise Apps)");
    await expect(page.locator('label.setup-choice:has(input[value="Defender"]) .setup-choice-title')).toHaveText("Microsoft Defender XDR");
    await expect(page.locator('label.setup-choice:has(input[value="Defender"]) .setup-choice-desc')).toHaveText("Unified RBAC");
    await page.locator('label.setup-choice:has(input[value="Defender"])').click();
    await page.getByRole("button", { name: "Continue" }).click();
    await page.getByRole("button", { name: "Continue" }).click();

    await expect(page.getByRole("heading", { name: "Your EntraOps setup" })).toBeVisible();
    const commands = page.locator(".setup-command");
    await expect(commands.filter({ hasText: "Connect-EntraOps -AuthenticationType 'UserInteractive' -TenantName 'contoso.onmicrosoft.com'" })).toHaveCount(1);
    await expect(commands.filter({ hasText: "Invoke-EntraOpsPrivilegedEAM" })).toHaveCount(1);
    await expect(commands.filter({ hasText: "New-EntraOpsReportingData" })).toHaveCount(1);
});

test("collects integration details and carries them into the expert config", async ({ page }) => {
    await page.goto(guideUrl);
    await page.locator('label.setup-choice:has(input[value="local"])').click();
    await page.getByRole("button", { name: "Continue" }).click();

    await page.getByRole("button", { name: "Continue" }).click();
    await expect(page.getByRole("alert")).toHaveText("Enter a valid Microsoft Entra tenant ID.");
    await page.locator("#tenantId").fill("00000000-0000-0000-0000-000000000000");
    await page.locator("#tenantName").fill("contoso.onmicrosoft.com");
    await page.getByRole("button", { name: "Continue" }).click();
    await page.locator('label.setup-choice:has(input[value="DeviceManagement"])').click();
    await page.getByRole("button", { name: "Continue" }).click();

    await page.locator('label.setup-choice:has(input[value="logAnalytics"])').click();
    await page.locator("#dcrName").fill("entraops-dcr");
    await page.locator("#dcrSubscriptionId").fill("00000000-0000-0000-0000-000000000000");
    await page.locator("#dcrResourceGroup").fill("rg-monitoring");
    await page.getByRole("button", { name: "Continue" }).click();

    const download = page.waitForEvent("download");
    await page.getByRole("button", { name: "Download EntraOpsConfig.json" }).click();
    await expect((await download).suggestedFilename()).toBe("EntraOpsConfig.json");

    const configLink = page.locator("#openConfigDraft");
    await expect(configLink).toHaveAttribute("href", /#onboarding=/);
    const href = await configLink.getAttribute("href");
    const draft = JSON.parse(decodeURIComponent(href.split("#onboarding=")[1]));
    expect(draft.AutomatedControlPlaneScopeUpdate.EntraOpsScopes).toEqual(draft.RbacSystems);
    expect(draft.AutomatedControlPlaneScopeUpdate.ClassificationParameterScope).toEqual(draft.RbacSystems);
    expect(draft.AzureRbacClassification.DeletedPrincipalAssignmentHandling).toBe("Filter");
    expect(draft.ConsoleOutput.IncludeObjectDetails).toBe(false);
    expect(draft.AutomatedEntraOpsUpdate.ApplyAutomatedEntraOpsUpdate).toBe(false);
    expect(draft.AutomatedEntraOpsUpdate.UpdateScheduledTrigger).toBe(false);
    expect(draft.AutomatedEntraOpsUpdate.ValidationFrequency).toBe("OnChange");
    expect(draft.AutomatedEntraOpsUpdate.RunBrowserTests).toBe(true);
    expect(draft.AutomatedEntraOpsUpdate.TargetUpdateFolders).not.toContain("./.github/workflows");
    expect(draft.AutomatedReportingGeneration.PublishReportsAsRelease).toBe(false);
    expect(draft.GeneratedArtifactValidation.FailOnPrivilegedAssignmentWithoutClassification).toBe(false);
    expect(draft.ClassificationExplorer.GenerateChangeHistory).toBe(false);
    expect(draft.CustomSecurityAttributes.PrivilegedUserAdminTierLevelAttribute).toBe("adminTierLevel");
    expect(draft.CustomSecurityAttributes.PrivilegedUserAdminTierLevelNameAttribute).toBe("adminTierLevelName");
    expect(draft.CustomSecurityAttributes.PrivilegedServicePrincipalAdminTierLevelAttribute).toBe("adminTierLevel");
    expect(draft.CustomSecurityAttributes.PrivilegedServicePrincipalAdminTierLevelNameAttribute).toBe("adminTierLevelName");
    expect(draft.AutomatedAdministrativeUnitManagement.RemovalSafetyThreshold).toBe(0.5);
    expect(draft.TenantGovernanceSnapshot.ResourcesToInclude).toEqual([]);
    expect(draft.TenantGovernanceSnapshot.SnapshotScheduledTrigger).toBe(false);
    await configLink.click();
    await expect(page.locator("#wizImportStatus")).toHaveText("Setup answers applied");
    await expect(page.locator('[data-key="TenantId"]')).toHaveValue("00000000-0000-0000-0000-000000000000");
    await expect(page.locator('[data-key="TenantName"]')).toHaveValue("contoso.onmicrosoft.com");
    await expect(page.locator("#wizPreview")).toContainText('"DataCollectionRuleName": "entraops-dcr"');
});

test("collects automated protection and Tenant Governance scope choices", async ({ page }) => {
    await page.goto(guideUrl);
    await page.locator('label.setup-choice:has(input[value="local"])').click();
    await page.getByRole("button", { name: "Continue" }).click();
    await page.locator("#tenantId").fill("00000000-0000-0000-0000-000000000000");
    await page.locator("#tenantName").fill("contoso.onmicrosoft.com");
    await page.getByRole("button", { name: "Continue" }).click();
    await page.getByRole("button", { name: "Continue" }).click();

    await page.locator('label.setup-choice:has(input[value="protection"])').click();
    await expect(page.getByRole("heading", { name: "Automated protection scope" })).toBeVisible();
    await expect(page.getByText("Entitlement Management catalogs", { exact: true })).toHaveCount(0);
    await expect(page.getByText(/Restricted Management Administrative Units \(RMAUs\)/)).toBeVisible();
    await page.locator('label.setup-choice:has(input[value="conditionalAccess"])').click();
    await page.locator('label.setup-choice:has(input[value="tenantGovernance"])').click();
    await expect(page.getByRole("heading", { name: "Tenant Governance scope" })).toBeVisible();
    await page.locator('label.setup-choice:has(input[value="categories"])').click();
    await expect(page.getByRole("heading", { name: "Select categories" })).toBeVisible();
    await expect(page.locator('input[name="tenantGovernanceCategories"]')).toHaveCount(3);
    await page.locator('label.setup-choice:has(input[name="tenantGovernanceCategories"][value="intune"])').click();
    await page.getByRole("button", { name: "Continue" }).click();

    const href = await page.locator("#openConfigDraft").getAttribute("href");
    const draft = JSON.parse(decodeURIComponent(href.split("#onboarding=")[1]));
    expect(draft.AutomatedConditionalAccessTargetGroups.ApplyConditionalAccessTargetGroups).toBe(false);
    expect(draft.AutomatedAdministrativeUnitManagement.ApplyAdministrativeUnitAssignments).toBe(true);
    expect(draft.AutomatedElmCatalogProtection.ApplyPrivilegedElmCatalogProtection).toBe(false);
    expect(draft.TenantGovernanceSnapshot.EnableTenantGovernanceSnapshot).toBe(true);
    expect(draft.TenantGovernanceSnapshot.SnapshotScheduledTrigger).toBe(true);
    expect(draft.TenantGovernanceSnapshot.ResourcesToInclude.some(resource => resource.startsWith("microsoft.entra."))).toBe(true);
    expect(draft.TenantGovernanceSnapshot.ResourcesToInclude.some(resource => resource.startsWith("microsoft.intune."))).toBe(false);
    expect(draft.TenantGovernanceSnapshot.ResourcesToInclude.some(resource => resource.startsWith("microsoft.securityandcompliance."))).toBe(true);
});

test("includes every required GitHub deployment and verification step", async ({ page }) => {
    await page.goto(guideUrl);
    await page.locator('label.setup-choice:has(input[value="github"])').click();
    await expect(page.getByRole("heading", { name: "Which DevOps platform?" })).toBeVisible();
    await page.locator('label.setup-choice:has(input[name="devOpsPlatform"][value="GitHub"])').click();
    await page.getByRole("button", { name: "Continue" }).click();
    await page.locator("#tenantId").fill("00000000-0000-0000-0000-000000000000");
    await page.locator("#tenantName").fill("contoso.onmicrosoft.com");
    await page.getByRole("button", { name: "Continue" }).click();
    await page.getByRole("button", { name: "Continue" }).click();
    const githubOrg = page.locator("#githubOrg");
    const githubRepo = page.locator("#githubRepo");
    const githubBranch = page.locator("#githubBranch");
    await expect(githubOrg).toBeVisible();
    await page.locator(".setup-step").evaluate(async element => {
        await Promise.all(element.getAnimations().map(animation => animation.finished));
    });
    const inputPositions = await page.locator(".setup-details").evaluate(element => ({
        organization: element.querySelector("#githubOrg").getBoundingClientRect().y,
        repository: element.querySelector("#githubRepo").getBoundingClientRect().y
    }));
    expect(Math.abs(inputPositions.organization - inputPositions.repository)).toBeLessThanOrEqual(2);
    await page.locator("#githubOrg").fill("contoso");
    await page.locator("#githubRepo").fill("EntraOps-Contoso");
    await githubBranch.fill("production");
    await page.getByRole("button", { name: "Continue" }).click();

    const steps = page.locator(".setup-run-list");
    await expect(steps).toContainText("Create a private repository");
    await expect(steps).toContainText("New-EntraOpsWorkloadIdentity");
    await expect(steps).toContainText("-ConfigFile './EntraOpsConfig.json'");
    await expect(steps).toContainText("-FederatedEntityName 'production'");
    await expect(steps.locator(".setup-command").filter({ hasText: "-GrantArmRootScopeReader" })).toHaveCount(0);
    await expect(steps).toContainText("Update-EntraOpsRequiredWorkflowParameters");
    await expect(steps).toContainText("git push");
    await expect(steps).toContainText("Pull-EntraOpsPrivilegedEAM");
    await expect(page.getByRole("link", { name: "Open GitHub Actions" })).toHaveAttribute("href", "https://github.com/contoso/EntraOps-Contoso/actions");
});

test("builds an Azure DevOps deployment with managed schedules and all pipelines", async ({ page }) => {
    await page.goto(guideUrl);
    await page.locator('label.setup-choice:has(input[value="github"])').click();
    await page.getByRole("button", { name: "Continue" }).click();
    await expect(page.getByRole("alert")).toHaveText("Choose GitHub or Azure DevOps.");
    await page.locator('label.setup-choice:has(input[name="devOpsPlatform"][value="AzureDevOps"])').click();
    await page.getByRole("button", { name: "Continue" }).click();
    await page.locator("#tenantId").fill("00000000-0000-0000-0000-000000000000");
    await page.locator("#tenantName").fill("contoso.onmicrosoft.com");
    await page.getByRole("button", { name: "Continue" }).click();
    await page.getByRole("button", { name: "Continue" }).click();

    await expect(page.getByRole("heading", { name: "Private Azure DevOps repository" })).toBeVisible();
    await page.locator("#adoOrg").fill("contoso");
    await page.locator("#adoProject").fill("Identity Operations");
    await page.locator("#adoRepo").fill("EntraOps-Contoso");
    await page.locator("#adoBranch").fill("production");
    await page.locator("#adoServiceConnection").fill("EntraOps-WIF");
    await page.getByRole("button", { name: "Continue" }).click();

    const configLink = page.locator("#openConfigDraft");
    const href = await configLink.getAttribute("href");
    const draft = JSON.parse(decodeURIComponent(href.split("#onboarding=")[1]));
    expect(draft.DevOpsPlatform).toBe("AzureDevOps");
    expect(draft.AutomatedEntraOpsUpdate.PublicationMode).toBe("DirectPush");
    expect(draft.AutomatedEntraOpsUpdate.TargetUpdateFolders).toContain("./.azure-pipelines");
    expect(draft.AutomatedEntraOpsUpdate.TargetUpdateFolders).not.toContain("./.github/workflows");

    const steps = page.locator(".setup-run-list");
    await expect(steps).toContainText("Workload Identity Federation (manual)");
    await expect(steps).toContainText("EntraOps-WIF");
    await expect(steps).toContainText("Update-EntraOpsAzureDevOpsSchedules");
    await expect(steps).toContainText("azure-pipelines-pull-tenant-governance");
    await expect(steps).toContainText("reporting");
    await expect(page.getByRole("link", { name: "Open Azure Pipelines" })).toHaveAttribute("href", "https://dev.azure.com/contoso/Identity%20Operations/_build");
});

test("lists selected local integrations only after the read-only review step", async ({ page }) => {
    await page.goto(guideUrl);
    await page.locator('label.setup-choice:has(input[value="local"])').click();
    await page.getByRole("button", { name: "Continue" }).click();
    await page.locator("#tenantId").fill("00000000-0000-0000-0000-000000000000");
    await page.locator("#tenantName").fill("contoso.onmicrosoft.com");
    await page.getByRole("button", { name: "Continue" }).click();
    await page.getByRole("button", { name: "Continue" }).click();
    await page.locator('label.setup-choice:has(input[value="watchlists"])').click();
    await page.locator("#sentinelWorkspace").fill("law-security");
    await page.locator("#sentinelSubscriptionId").fill("00000000-0000-0000-0000-000000000000");
    await page.locator("#sentinelResourceGroup").fill("rg-security");
    await page.getByRole("button", { name: "Continue" }).click();

    const steps = page.locator(".setup-run-list");
    await expect(steps).toContainText("Open and review the reports");
    await expect(steps).toContainText("Prepare and run selected integrations");
    const integrationCommand = steps.locator(".setup-command").filter({ hasText: "Save-EntraOpsPrivilegedEAMWatchLists" });
    await expect(integrationCommand).toContainText("Connect-EntraOps");
    await expect(integrationCommand).toContainText("Disconnect-EntraOps");
    await expect(steps).toContainText("write operations require a pre-provisioned workload or managed identity");
});

test("switches between the guided setup and expert guide", async ({ page }) => {
    await page.goto(guideUrl);
    await page.getByRole("button", { name: "Expert guide" }).click();
    await expect(page.locator("#setup-guide")).toBeHidden();
    await expect(page.locator("#detailed-guide")).toBeVisible();
});

test("preserves Tenant Governance setup step numbers", async ({ page }) => {
    await page.goto(new URL("../tenant-governance/index.html", guideUrl).href);

    await expect(page.locator(".prose ol").evaluateAll(lists => lists.map(list => ({
        start: list.start,
        text: list.textContent.trim()
    })))).resolves.toEqual(expect.arrayContaining([
        expect.objectContaining({ start: 1, text: expect.stringContaining("Enable snapshots") }),
        expect.objectContaining({ start: 2, text: expect.stringContaining("Create or update the EntraOps workload identity") }),
        expect.objectContaining({ start: 3, text: expect.stringContaining("Validate the result") }),
        expect.objectContaining({ start: 4, text: expect.stringContaining("Apply the updated settings") })
    ]));
});
