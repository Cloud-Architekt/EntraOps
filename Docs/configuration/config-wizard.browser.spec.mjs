import { expect, test } from "@playwright/test";
import { fileURLToPath, pathToFileURL } from "node:url";

const wizardUrl = pathToFileURL(fileURLToPath(new URL("index.html", import.meta.url))).href;

test("shows the live JSON preview below the configuration form", async ({ page }) => {
    await page.goto(wizardUrl);

    const panelsBox = await page.locator("#wizPanels").boundingBox();
    const previewBox = await page.locator("#wizPreviewSection").boundingBox();
    expect(previewBox.y).toBeGreaterThanOrEqual(panelsBox.y + panelsBox.height);
    await expect(page.getByRole("heading", { name: "Live JSON preview" })).toBeVisible();
    await expect(page.locator("#wizPreview")).toContainText('"TenantName"');
    await expect(page.locator("#wizPreview")).not.toContainText('"./.github/workflows"');
});

test("Tenant Governance provider selection and clearing update the live configuration preview", async ({ page }) => {
    await page.goto(wizardUrl);
    await page.getByRole("button", { name: /Tenant Governance/ }).click();

    const picker = page.locator('[data-key="TgResourcesToInclude"]');
    const options = picker.locator('input[data-tg-resource]');
    const providerOptionCount = await options.count();

    await picker.getByRole("button", { name: "Clear all" }).click();
    await expect(picker.locator(".tg-resource-summary strong")).toHaveText("0 of 56 selected");

    await picker.getByRole("button", { name: "Select provider" }).click();
    await expect(picker.locator('input[data-tg-resource]:checked')).toHaveCount(providerOptionCount);
    await expect(picker.locator(".tg-resource-summary strong")).toHaveText(`${providerOptionCount} of 56 selected`);
    await expect(page.locator("#wizPreview")).toContainText('"ResourcesToInclude": [');

    await picker.getByRole("button", { name: "Clear all" }).click();
    await expect(options.locator(":checked")).toHaveCount(0);
    await expect(picker.locator(".tg-resource-summary strong")).toHaveText("0 of 56 selected");
    await expect(page.locator("#wizPreview")).toContainText('"ResourcesToInclude": []');
});

test("navigates Tenant Governance resources by provider and family", async ({ page }) => {
    await page.goto(wizardUrl);
    await page.getByRole("button", { name: /Tenant Governance/ }).click();

    const authenticationFamily = page.locator('[data-tg-family="microsoft.entra|Authentication method policy"]');
    await expect(authenticationFamily.getByText("Authentication Method Policy Email", { exact: true })).toBeVisible();

    await authenticationFamily.locator('[data-tg-family-select="microsoft.entra|Authentication method policy"]').check();
    await expect(page.locator("#wizPreview")).toContainText('"microsoft.entra.authenticationMethodPolicyEmail"');

    await page.locator('[data-tg-provider="microsoft.intune"]').click();
    await expect(page.getByRole("button", { name: /Device compliance/ })).toBeVisible();
    await page.locator('[data-tg-search]').fill("deviceCompliancePolicyIos");
    await expect(page.getByText("Device Compliance Policy Ios", { exact: true })).toBeVisible();
    await expect(page.getByText("Device Compliance Policy Android", { exact: true })).toBeHidden();
});

test("exports every Tenant Governance snapshot retry schedule", async ({ page }) => {
    await page.goto(wizardUrl);
    await page.getByRole("button", { name: /Tenant Governance/ }).click();

    await expect(page.locator('[data-field="TgSnapshotScheduledCronCompleteRetry1"] [data-cron-preview]')).toHaveText("30 7 * * *");
    await expect(page.locator('[data-field="TgSnapshotScheduledCronCompleteRetry2"] [data-cron-preview]')).toHaveText("0 8 * * *");
    await expect(page.locator("#wizPreview")).toContainText('"SnapshotScheduledCronCompleteRetry1": "30 7 * * *"');
    await expect(page.locator("#wizPreview")).toContainText('"SnapshotScheduledCronCompleteRetry2": "0 8 * * *"');
});

test("exports Service EM defaults and preserves imported Service EM settings", async ({ page }) => {
    await page.goto(wizardUrl);
    await page.getByRole("button", { name: /Service EM/ }).click();

    await expect(page.locator('[data-key="SemGovernanceModel"]')).toHaveValue("Centralized");
    await expect(page.locator('[data-field="SemGovernanceModel"] .wiz-field-default')).toHaveText("Default: Centralized");
    await expect(page.locator('[data-field="SemMpExcludedRoleDefinitionIds"] .wiz-field-default')).toHaveText("Default: Owner, User Access Administrator, Role Based Access Control Administrator");
    let preview = JSON.parse(await page.locator("#wizPreview").textContent());
    expect(preview.ServiceEM.ControlPlaneGroupName).toBe("PRG-Tenant-ControlPlane-IdentityOps");
    expect(preview.ServiceEM.ConstrainedDelegation.ManagementPlane.ExcludedRoleDefinitionIds).toHaveLength(3);
    expect(preview.ServiceEM.ConstrainedDelegation.WorkloadPlane.AllowedRoleDefinitionIds).toHaveLength(16);
    expect(preview.ServiceEM.PIMAuthenticationContext.EnableAuthenticationContext).toBe(false);
    expect(preview.ServiceEM.DefaultAzureRegion).toBe("");
    expect(preview.ServiceEM.SkipCatalogOwnerAssignment).toBe(false);
    expect(preview.ServiceEM.CreateM365Group).toBe(false);
    expect(preview.ServiceEM.AddWorkloadPlaneAdminToUsers).toBe(false);
    expect(preview.ServiceEM.GroupPrefix).toBe("SG");
    expect(preview.ServiceEM.PIMForGroups).toEqual({ MaximumActivationDuration: "PT10H", MaximumActiveAssignmentDuration: "P15D" });
    expect(preview.ServiceEM.AssignmentPolicies.BaselinePolicy).toEqual({ Expiration: "P365D", ApprovalTimeout: "P2D", AllowExtension: true });
    expect(preview.ServiceEM.AssignmentPolicies.WorkloadPlaneUsers.RequestorScope).toBe("AllMemberUsers");
    expect(preview.ServiceEM.AssignmentPolicies.ManagementPlaneAdmins.ApprovalTimeout).toBe("P1D");
    expect(preview.ServiceEM.AssignmentPolicies.InitialWorkloadUsers.Expiration).toBe("P365D");
    expect(preview.ServiceEM.AccessReviews).toMatchObject({ EnableAccessReviews: true, RecurrenceIntervalInMonths: 3, StartAfterDays: 4, ReviewDuration: "P25D" });
    expect(Object.keys(preview.ServiceEM.AccessReviews.Policies)).toHaveLength(9);
    expect(preview.ServiceEM.AccessReviews.Policies.WorkloadPlaneUsers).toEqual({ ReviewerType: "Group", Reviewers: ["WorkloadPlane-Admins"] });
    expect(preview.ServiceEM.AccessReviews.Policies.BaselinePolicy).toEqual({ ReviewerType: "Group", Reviewers: ["ManagementPlane-Admins"] });

    await page.locator("#wizImportFile").setInputFiles({
        name: "EntraOpsConfig.json",
        mimeType: "application/json",
        buffer: Buffer.from(JSON.stringify({
            ServiceEM: {
                GovernanceModel: "PerService",
                ControlPlaneDelegationGroupId: "11111111-1111-1111-1111-111111111111",
                ConstrainedDelegation: { WorkloadPlane: { AllowedRoleDefinitionIds: ["00482a5a-887f-4fb3-b363-3b7fe8e74483"] } },
                PIMAuthenticationContext: { EnableAuthenticationContext: true, ControlPlane: { AuthenticationContextClassReferenceId: "c1" } },
                DefaultAzureRegion: "swedencentral",
                CreateM365Group: true,
                PIMForGroups: { MaximumActivationDuration: "PT8H" },
                AssignmentPolicies: { WorkloadPlaneUsers: { RequestorScope: "CatalogPlaneMembers" } },
                AccessReviews: { RecurrenceIntervalInMonths: 6, Policies: { WorkloadPlaneAdmins: { ReviewerType: "SpecificReviewers", Reviewers: ["admin@contoso.com"] } } }
            }
        }))
    });

    await expect(page.locator('[data-key="SemGovernanceModel"]')).toHaveValue("PerService");
    await expect(page.locator('[data-key="SemEnableAuthenticationContext"]')).toBeChecked();
    await page.locator('[data-key="SemMpExcludedRoleDefinitionIds"]').fill("8e3af657-a8ff-443c-a75c-2fe8c4bcb635,\n18d7d88d-d35e-4fb5-a5c3-7773c20a72d9");
    preview = JSON.parse(await page.locator("#wizPreview").textContent());
    expect(preview.ServiceEM.ControlPlaneDelegationGroupId).toBe("11111111-1111-1111-1111-111111111111");
    expect(preview.ServiceEM.ConstrainedDelegation.WorkloadPlane.AllowedRoleDefinitionIds).toEqual(["00482a5a-887f-4fb3-b363-3b7fe8e74483"]);
    expect(preview.ServiceEM.ConstrainedDelegation.ManagementPlane.ExcludedRoleDefinitionIds).toEqual(["8e3af657-a8ff-443c-a75c-2fe8c4bcb635", "18d7d88d-d35e-4fb5-a5c3-7773c20a72d9"]);
    expect(preview.ServiceEM.PIMAuthenticationContext.ControlPlane.AuthenticationContextClassReferenceId).toBe("c1");
    expect(preview.ServiceEM.DefaultAzureRegion).toBe("swedencentral");
    expect(preview.ServiceEM.CreateM365Group).toBe(true);
    await expect(page.locator('[data-key="SemCreateM365Group"]')).toBeChecked();
    expect(preview.ServiceEM.PIMForGroups.MaximumActivationDuration).toBe("PT8H");
    expect(preview.ServiceEM.PIMForGroups.MaximumActiveAssignmentDuration).toBe("P15D");
    expect(preview.ServiceEM.AssignmentPolicies.WorkloadPlaneUsers.RequestorScope).toBe("CatalogPlaneMembers");
    expect(preview.ServiceEM.AccessReviews.RecurrenceIntervalInMonths).toBe(6);
    await expect(page.locator('[data-key="SemArWorkloadPlaneAdminsReviewerType"]')).toHaveValue("SpecificReviewers");
    expect(preview.ServiceEM.AccessReviews.Policies.WorkloadPlaneAdmins).toEqual({ ReviewerType: "SpecificReviewers", Reviewers: ["admin@contoso.com"] });
    expect(preview.ServiceEM.AccessReviews.Policies.InitialWorkloadUsers.Reviewers).toEqual(["WorkloadPlane-Admins"]);
    await page.locator('[data-key="SemArBaselinePolicyReviewerType"]').selectOption("SelfReview");
    preview = JSON.parse(await page.locator("#wizPreview").textContent());
    expect(preview.ServiceEM.AccessReviews.Policies.BaselinePolicy.ReviewerType).toBe("SelfReview");
});

test("preserves EIDSCA finding exclusions through import and export", async ({ page }) => {
    await page.goto(wizardUrl);
    await page.locator("#wizImportFile").setInputFiles({
        name: "EntraOpsConfig.json",
        mimeType: "application/json",
        buffer: Buffer.from(JSON.stringify({
            ConfigurationAnalyzer: { EidscaExcludedFindings: ["EIDSCA.AP01", "EIDSCA.AP02"] }
        }))
    });
    await page.getByRole("button", { name: /Reporting & Ingestion/ }).click();

    await expect(page.locator('[data-key="EidscaExcludedFindings"]')).toHaveValue("EIDSCA.AP01, EIDSCA.AP02");
    await expect(page.locator("#wizPreview")).toContainText('"EidscaExcludedFindings": [');
    await expect(page.locator("#wizPreview")).toContainText('"EIDSCA.AP02"');
});

test("preserves updater, advanced CSA and unknown settings through import and export", async ({ page }) => {
    await page.goto(wizardUrl);
    const imported = {
        TenantId: "00000000-0000-0000-0000-000000000000",
        TenantName: "contoso.onmicrosoft.com",
        AutomatedEntraOpsUpdate: {
            Repository: "EntraOps-Insiders",
            Branch: "0123456789012345678901234567890123456789",
            ValidationFrequency: "Never",
            RunBrowserTests: false,
            TargetUpdateFolders: ["./EntraOps", "./Reports", "./package.json"],
            FutureUpdateSetting: "preserve-me"
        },
        CustomSecurityAttributes: {
            PrivilegedUserAdminTierLevelAttribute: "customUserTier",
            PrivilegedUserAdminTierLevelNameAttribute: "customUserTierName",
            PrivilegedServicePrincipalAdminTierLevelAttribute: "customSpTier",
            PrivilegedServicePrincipalAdminTierLevelNameAttribute: "customSpTierName"
        },
        FutureSection: { Enabled: true, Nested: { Value: 42 } }
    };
    await page.locator("#wizImportFile").setInputFiles({
        name: "EntraOpsConfig.json",
        mimeType: "application/json",
        buffer: Buffer.from(JSON.stringify(imported))
    });

    const preview = page.locator("#wizPreview");
    await expect(preview).toContainText('"Repository": "EntraOps-Insiders"');
    await expect(preview).toContainText('"ValidationFrequency": "Never"');
    await expect(preview).toContainText('"RunBrowserTests": false');
    await expect(preview).toContainText('"./package.json"');
    await expect(preview).toContainText('"FutureUpdateSetting": "preserve-me"');
    await expect(preview).toContainText('"PrivilegedUserAdminTierLevelAttribute": "customUserTier"');
    await expect(preview).toContainText('"FutureSection"');
    await expect(preview).toContainText('"Value": 42');
});

test("keeps Group filters of older configs enabled while Custom Security Attributes stay active", async ({ page }) => {
    await page.goto(wizardUrl);
    await page.locator("#wizImportFile").setInputFiles({
        name: "EntraOpsConfig.json",
        mimeType: "application/json",
        buffer: Buffer.from(JSON.stringify({
            AlternateObjectTierLevelAttributes: {
                Enabled: false,
                Group: { ControlPlane: '$Object.ObjectDisplayName -like "PRG-Tier0-*"', ManagementPlane: "", UserAccess: "" }
            }
        }))
    });
    await page.getByRole("button", { name: /Object Classification/ }).click();

    await expect(page.locator('.wiz-method-card[data-method="csa"]')).toHaveClass(/selected/);
    await expect(page.locator('.wiz-method-card[data-method="alternate"]')).toHaveClass(/selected/);
    await expect(page.locator('.wiz-tier-block[data-objtype="User"]')).toHaveCount(0);
    await page.locator('[data-objtab="Group"]').click();
    await expect(page.locator('[data-key="AlternateGroupEnabled"]')).toBeChecked();
    await expect(page.locator('.wiz-tier-block[data-objtype="Group"]')).toHaveCount(3);

    const alternate = JSON.parse(await page.locator("#wizPreview").innerText()).AlternateObjectTierLevelAttributes;
    expect(alternate.Enabled).toBeUndefined();
    expect(alternate.User.Enabled).toBe(false);
    expect(alternate.ServicePrincipal.Enabled).toBe(false);
    expect(alternate.Group.Enabled).toBe(true);
    expect(alternate.Group.ControlPlane).toContain("PRG-Tier0-*");
});

test("enables Alternate Tier Level Attributes per object type", async ({ page }) => {
    await page.goto(wizardUrl);
    await page.locator("#wizImportFile").setInputFiles({
        name: "EntraOpsConfig.json",
        mimeType: "application/json",
        buffer: Buffer.from(JSON.stringify({
            AlternateObjectTierLevelAttributes: {
                Enabled: true,
                User: { ControlPlane: '$Object.ObjectDisplayName -like "*-tier0-*"' },
                ServicePrincipal: { ControlPlane: '$Object.ObjectDisplayName -like "*-tier0-*"' }
            }
        }))
    });
    await page.getByRole("button", { name: /Object Classification/ }).click();
    const exported = () => page.locator("#wizPreview").innerText().then((text) => JSON.parse(text).AlternateObjectTierLevelAttributes);

    await expect(page.locator('[data-key="AlternateUserEnabled"]')).toBeChecked();
    await expect(page.locator('.wiz-method-card[data-method="csa"]')).not.toHaveClass(/selected/);
    expect(JSON.parse(await page.locator("#wizPreview").innerText()).CustomSecurityAttributes.Enabled).toBe(false);
    await expect(page.locator('.wiz-tier-block[data-objtype="User"]')).toHaveCount(3);
    expect((await exported()).Enabled).toBeUndefined();
    expect((await exported()).User.Enabled).toBe(true);
    expect((await exported()).Group.Enabled).toBe(false);

    await page.locator('[data-objtab="ServicePrincipal"]').click();
    await page.locator('[data-key="AlternateServicePrincipalEnabled"]').uncheck();
    await expect(page.locator('.wiz-tier-block[data-objtype="ServicePrincipal"]')).toHaveCount(0);
    expect((await exported()).ServicePrincipal.Enabled).toBe(false);
    expect((await exported()).ServicePrincipal.ControlPlane).toContain("*-tier0-*");
    expect((await exported()).User.Enabled).toBe(true);

    await page.locator('.wiz-method-card[data-method="alternate"]').click();
    await expect(page.locator(".wiz-object-tabs")).toHaveCount(0);
    expect((await exported()).User.Enabled).toBe(false);
    expect((await exported()).User.ControlPlane).toContain("*-tier0-*");
});

test("combines the Object Classification File with Custom Security Attributes", async ({ page }) => {
    await page.goto(wizardUrl);
    await page.locator("#wizImportFile").setInputFiles({
        name: "EntraOpsConfig.json",
        mimeType: "application/json",
        buffer: Buffer.from(JSON.stringify({
            ObjectClassificationFile: { Enabled: true, FilePath: "./Classification/Tiers.csv" },
            PrivilegedAssets: { ResolveRelatedObjectIds: false }
        }))
    });
    await page.getByRole("button", { name: /Object Classification/ }).click();

    await expect(page.locator(".wiz-method-card")).toHaveCount(3);
    await expect(page.locator('.wiz-method-card[data-method="file"]')).toHaveClass(/selected/);
    await expect(page.locator('.wiz-method-card[data-method="csa"]')).not.toHaveClass(/selected/);
    await expect(page.locator('[data-key="ObjectClassificationFilePath"]')).toHaveValue("./Classification/Tiers.csv");
    await expect(page.locator('[data-key="PrivilegedUserAdminTierLevelAttribute"]')).toHaveCount(0);

    const preview = page.locator("#wizPreview");
    await expect(preview).toContainText('"FilePath": "./Classification/Tiers.csv"');
    await expect(preview).toContainText('"ResolveRelatedObjectIds": false');
    await expect(preview).toContainText('"GeneratePrivilegedAssets": true');
    const exported = () => page.locator("#wizPreview").innerText().then((text) => JSON.parse(text));
    expect((await exported()).ObjectClassificationFile.Enabled).toBe(true);
    expect((await exported()).CustomSecurityAttributes.Enabled).toBe(false);

    await page.locator('.wiz-method-card[data-method="csa"]').click();
    await expect(page.locator('[data-key="PrivilegedUserAdminTierLevelAttribute"]')).toHaveCount(1);
    expect((await exported()).CustomSecurityAttributes.Enabled).toBe(true);
    expect((await exported()).ObjectClassificationFile.Enabled).toBe(true);

    await page.locator('.wiz-method-card[data-method="file"]').click();
    await expect(page.locator('[data-key="ObjectClassificationFilePath"]')).toHaveCount(0);
    expect((await exported()).ObjectClassificationFile.Enabled).toBe(false);
    expect((await exported()).ObjectClassificationFile.FilePath).toBe("./Classification/Tiers.csv");
});

test("minimizes panels to their headline and keeps them minimized across re-renders", async ({ page }) => {
    await page.goto(wizardUrl);
    await page.getByRole("button", { name: /Object Classification/ }).click();
    const sourcesTitle = page.locator(".wiz-group-title", { hasText: "Classification sources" });

    await expect(sourcesTitle).toHaveAttribute("aria-expanded", "true");
    await sourcesTitle.click();
    await expect(sourcesTitle).toHaveAttribute("aria-expanded", "false");
    await expect(page.locator(".wiz-method-cards")).toBeHidden();

    await page.getByRole("button", { name: /Tenant & Auth/ }).click();
    await page.getByRole("button", { name: /Object Classification/ }).click();
    await expect(page.locator(".wiz-method-cards")).toBeHidden();

    await sourcesTitle.focus();
    await page.keyboard.press("Enter");
    await expect(page.locator(".wiz-method-cards")).toBeVisible();
});

test("exports and imports deleted Azure RBAC principal handling", async ({ page }) => {
    await page.goto(wizardUrl);
    await page.getByRole("button", { name: /Control Plane Scope/ }).click();

    await expect(page.locator('[data-key="DeletedPrincipalAssignmentHandling"]')).toHaveValue("Filter");
    await expect(page.locator("#wizPreview")).toContainText('"DeletedPrincipalAssignmentHandling": "Filter"');

    await page.locator("#wizImportFile").setInputFiles({
        name: "EntraOpsConfig.json",
        mimeType: "application/json",
        buffer: Buffer.from(JSON.stringify({
            AzureRbacClassification: { DeletedPrincipalAssignmentHandling: "Keep" }
        }))
    });

    await expect(page.locator('[data-key="DeletedPrincipalAssignmentHandling"]')).toHaveValue("Keep");
    await expect(page.locator("#wizPreview")).toContainText('"DeletedPrincipalAssignmentHandling": "Keep"');
});

test("imports legacy nested automated reporting configuration", async ({ page }) => {
    await page.goto(wizardUrl);
    await page.locator("#wizImportFile").setInputFiles({
        name: "EntraOpsConfig.json",
        mimeType: "application/json",
        buffer: Buffer.from(JSON.stringify({
            AutomatedRmauAssignmentsForUnprotectedObjects: {
                AutomatedReportingGeneration: {
                    ApplyAutomatedReportingGeneration: true,
                    GenerateAccessPathMap: false
                }
            }
        }))
    });

    await expect(page.locator("#wizPreview")).toContainText('"ApplyAutomatedReportingGeneration": true');
    await expect(page.locator("#wizPreview")).toContainText('"GenerateAccessPathMap": false');
});

test("normalizes a removal threshold from any automation section", async ({ page }) => {
    await page.goto(wizardUrl);
    await page.locator("#wizImportFile").setInputFiles({
        name: "EntraOpsConfig.json",
        mimeType: "application/json",
        buffer: Buffer.from(JSON.stringify({
            AutomatedElmCatalogProtection: { RemovalSafetyThreshold: 0.25 }
        }))
    });

    const preview = JSON.parse(await page.locator("#wizPreview").textContent());
    expect(preview.AutomatedConditionalAccessTargetGroups.RemovalSafetyThreshold).toBe(0.25);
    expect(preview.AutomatedAdministrativeUnitManagement.RemovalSafetyThreshold).toBe(0.25);
    expect(preview.AutomatedRmauAssignmentsForUnprotectedObjects.RemovalSafetyThreshold).toBe(0.25);
    expect(preview.AutomatedElmCatalogProtection.RemovalSafetyThreshold).toBe(0.25);
});

test("requires tenant identity before downloading the configuration", async ({ page }) => {
    await page.goto(wizardUrl);

    const tenantId = page.locator('[data-key="TenantId"]');
    const tenantName = page.locator('[data-key="TenantName"]');
    await expect(tenantId).toHaveAttribute("required", "");
    await expect(tenantName).toHaveAttribute("required", "");
    await expect(page.locator('[data-field="TenantName"] .wiz-field-required')).toHaveText("Required");

    page.once("dialog", (dialog) => dialog.accept());
    await page.getByRole("button", { name: /Download EntraOpsConfig\.json/ }).click();
    await expect(tenantId).toBeFocused();

    await tenantId.fill("00000000-0000-0000-0000-000000000000");
    await tenantName.fill("contoso.onmicrosoft.com");
    const download = page.waitForEvent("download");
    await page.getByRole("button", { name: /Download EntraOpsConfig\.json/ }).click();
    await (await download).cancel();
});

test("keeps report release publishing opt-in and exports its retention setting", async ({ page }) => {
    await page.goto(wizardUrl);
    await page.getByRole("button", { name: /Reporting & Ingestion/ }).click();

    await expect(page.locator('[data-key="PublishReportsAsRelease"]')).not.toBeChecked();
    await expect(page.locator('[data-key="ReportingReleasesToKeep"]')).toHaveValue("10");
    const preview = JSON.parse(await page.locator("#wizPreview").textContent());
    expect(preview.AutomatedReportingGeneration.PublishReportsAsRelease).toBe(false);
    expect(preview.AutomatedReportingGeneration.ReportingReleasesToKeep).toBe(10);
    expect(preview.ClassificationExplorer.GenerateChangeHistory).toBe(false);
});

test("preserves enabled Classification Explorer change history through import and export", async ({ page }) => {
    await page.goto(wizardUrl);
    await page.locator("#wizImportFile").setInputFiles({
        name: "EntraOpsConfig.json",
        mimeType: "application/json",
        buffer: Buffer.from(JSON.stringify({
            ClassificationExplorer: { GenerateChangeHistory: true }
        }))
    });
    await page.getByRole("button", { name: /Reporting & Ingestion/ }).click();

    await expect(page.locator('[data-key="ClassificationExplorerGenerateChangeHistory"]')).toBeChecked();
    const preview = JSON.parse(await page.locator("#wizPreview").textContent());
    expect(preview.ClassificationExplorer.GenerateChangeHistory).toBe(true);
});

test("preserves explicitly empty report release retention through import and export", async ({ page }) => {
    await page.goto(wizardUrl);
    await page.locator("#wizImportFile").setInputFiles({
        name: "EntraOpsConfig.json",
        mimeType: "application/json",
        buffer: Buffer.from(JSON.stringify({
            AutomatedReportingGeneration: {
                PublishReportsAsRelease: true,
                ReportingReleasesToKeep: ""
            }
        }))
    });
    await page.getByRole("button", { name: /Reporting & Ingestion/ }).click();

    await expect(page.locator('[data-key="ReportingReleasesToKeep"]')).toHaveValue("");
    const preview = JSON.parse(await page.locator("#wizPreview").textContent());
    expect(preview.AutomatedReportingGeneration.ReportingReleasesToKeep).toBe("");
});

test("hydrates a partial draft from the beginner setup guide", async ({ page }) => {
    const draft = {
        TenantId: "00000000-0000-0000-0000-000000000000",
        TenantName: "contoso.onmicrosoft.com",
        AuthenticationType: "UserInteractive",
        ConsoleOutput: { IncludeObjectDetails: true },
        DevOpsPlatform: "None",
        RbacSystems: ["Azure", "EntraID"],
        LogAnalytics: {
            IngestToLogAnalytics: true,
            DataCollectionRuleName: "entraops-dcr"
        }
    };

    await page.goto(`${wizardUrl}#onboarding=${encodeURIComponent(JSON.stringify(draft))}`);

    await expect(page.locator("#wizImportStatus")).toHaveText("Setup answers applied");
    await expect(page.locator('[data-key="TenantName"]')).toHaveValue("contoso.onmicrosoft.com");
    await expect(page.locator('[data-key="AuthenticationType"]')).toHaveValue("UserInteractive");
    await expect(page.locator('[data-key="IncludeObjectDetails"]')).toBeChecked();
    await expect(page.locator("#wizPreview")).toContainText('"IncludeObjectDetails": true');
    await expect(page.locator("#wizPreview")).toContainText('"DataCollectionRuleName": "entraops-dcr"');
});
