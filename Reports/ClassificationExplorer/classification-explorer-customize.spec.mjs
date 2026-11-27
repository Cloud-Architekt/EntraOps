import { expect, test } from "@playwright/test";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const appUrl = pathToFileURL(join(fileURLToPath(new URL(".", import.meta.url)), "index.html")).href;
const base = "Classification_RoleDefinitionOverwrites";

const entry = (name, tier, justification, extra = {}) => ({
    RbacSystem: "EntraID",
    RoleDefinitionName: name,
    EAMTierLevelName: tier,
    Justification: justification,
    ...extra
});

function jsonFile(name, entries) {
    return { name, mimeType: "application/json", buffer: Buffer.from(JSON.stringify(entries)) };
}

async function setClassificationFixture(page, fixture) {
    await page.addInitScript(({ tenants, data }) => {
        // Generated deployment bundles load after init scripts and assign these globals.
        // Keep each test's fixture in place when that bundle exists, including after reload.
        Object.defineProperties(window, {
            EOCE_TENANTS: { get: () => tenants, set() { } },
            EOCE_DATA: { get: () => data, set() { } }
        });
    }, fixture);
}

async function openCustomize(page) {
    const pageErrors = [];
    page.on("pageerror", (error) => pageErrors.push(error.message));
    await page.goto(`${appUrl}#customize/roledef`);
    await page.evaluate(() => window.localStorage.clear());
    await page.reload();
    await expect(page.locator("#custTable")).toBeVisible();
    return pageErrors;
}

function row(page, text) {
    return page.locator("#custTable tbody tr", { hasText: text });
}

function originOf(page, text) {
    return row(page, text).locator(".cust-origin");
}

async function exportFiles(page) {
    const downloads = [];
    page.on("download", (download) => downloads.push(download));
    const expected = await page.locator("#custStatus .chip.brand").count();
    await page.locator("#custExport").click();
    await expect.poll(() => downloads.length).toBe(expected);
    if (expected > 1) await page.locator("#custDownloadDone").click();
    const files = {};
    for (const download of downloads) {
        files[download.suggestedFilename()] = JSON.parse(await readFile(await download.path(), "utf8"));
    }
    return files;
}

// Replaces the File System Access pickers with in-page fakes that record the written files.
async function fakeDirectoryPicker(page, { deny = false, failOn = null, pauseOn = null } = {}) {
    await page.evaluate(({ deny, failOn, pauseOn }) => {
        window.__written = {};
        const getFileHandle = async (name) => ({
            createWritable: async () => ({
                write: async (text) => {
                    if (name === failOn) throw new DOMException("disk full", "InvalidStateError");
                    window.__written[name] = text;
                    if (name === pauseOn) await new Promise((resolve) => { window.__resumeSave = resolve; });
                },
                close: async () => { }
            })
        });
        window.showDirectoryPicker = async () => {
            if (deny) throw new DOMException("denied", "NotAllowedError");
            return { getFileHandle };
        };
        window.showSaveFilePicker = async ({ suggestedName }) => {
            if (deny) throw new DOMException("denied", "NotAllowedError");
            return getFileHandle(suggestedName);
        };
    }, { deny, failOn, pauseOn });
}

test.describe("Classification Explorer: Customize Overwrites with tagged files", () => {
    test.beforeEach(async ({ page }) => {
        // Customize is an EntraOps deployment feature. Exercise the same shared source in
        // that mode when this suite runs from the standalone AzurePrivilegedIAM checkout.
        await page.addInitScript(() => {
            let manifest;
            Object.defineProperties(window, {
                EOCE_MODE: { get: () => "entraops", set() { } },
                EOCE_DATA_MANIFEST: {
                    get: () => manifest,
                    set(value) { manifest = value ? { ...value, mode: "entraops" } : value; }
                }
            });
        });
    });

    test("labels entries by origin and exports every file back to its origin", async ({ page }) => {
        const pageErrors = await openCustomize(page);

        await page.locator("#custImportFile").setInputFiles([
            jsonFile(`${base}.json`, [entry("Base Role", "ControlPlane", "base"), entry("Removed Role", "ControlPlane", "base")]),
            jsonFile(`${base}_PAW.json`, [entry("PAW Role", "ManagementPlane", "paw")])
        ]);

        await expect(originOf(page, "Base Role")).toHaveText("Base");
        await expect(originOf(page, "PAW Role")).toHaveText("PAW");

        // Editing keeps the origin file, removing keeps the row visible until export
        await row(page, "PAW Role").getByRole("button", { name: "Edit" }).click();
        await page.locator("#cfJust").fill("paw edited");
        await page.locator("#cfApply").click();
        await row(page, "Removed Role").getByTitle("Remove this entry").click();

        await expect(originOf(page, "PAW Role")).toHaveText("Custom - PAW");
        await expect(originOf(page, "Removed Role")).toHaveText("Custom - Base");
        await expect(page.locator("#custTable tbody tr.cust-removed", { hasText: "Removed Role" })).toBeVisible();
        await expect(originOf(page, "Base Role")).toHaveText("Base");

        await page.locator("#custOriginFilter").selectOption("custom");
        await expect(page.locator("#custTable tbody tr[data-idx]")).toHaveCount(2);
        await page.locator("#custOriginFilter").selectOption(`file:${base}_PAW.json`);
        await expect(page.locator("#custTable tbody tr[data-idx]")).toHaveCount(1);
        await page.locator("#custOriginFilter").selectOption("");

        const files = await exportFiles(page);
        expect(Object.keys(files).sort()).toEqual([`${base}.json`, `${base}_PAW.json`]);
        expect(files[`${base}.json`].map((e) => e.RoleDefinitionName)).toEqual(["Base Role"]);
        expect(files[`${base}_PAW.json`]).toEqual([
            expect.objectContaining({ RoleDefinitionName: "PAW Role", Justification: "paw edited", EAMTierLevelTagValue: "1" })
        ]);
        await expect(row(page, "Removed Role")).toHaveCount(0);
        expect(pageErrors).toEqual([]);
    });

    test("picks Azure role definitions and reuses starred roles without changing their system", async ({ page }) => {
        const role = {
            RoleId: "b24988ac-6180-42a0-ab88-20f7382dd24c",
            RoleName: "Contributor",
            Classification: { EAMTierLevelName: "ManagementPlane" },
            RolePermissions: []
        };
        await setClassificationFixture(page, {
            tenants: [],
            data: { "Classification/Classification_AzureResources.json": [role] }
        });
        const pageErrors = await openCustomize(page);
        await page.locator("#custAdd").click();
        await expect(page.locator("#cfSys option[value=Azure]")).toHaveCount(1);
        await page.locator("#cfSys").selectOption("Azure");
        await page.locator("#cfRoleResults [data-pick]", { hasText: role.RoleName }).click();
        await expect(page.locator("#cfRoleId")).toHaveValue(role.RoleId);
        await expect(page.locator("#cfRoleName")).toHaveValue(role.RoleName);
        await expect(page.locator("#cfCurrentTier")).toContainText("Management");
        await page.locator("#cfCancel").click();

        await page.evaluate((role) => window.EOReview.toggle({
            id: `role|Azure|${role.RoleId}`, kind: "Role", system: "Azure",
            name: role.RoleName, hash: `#roles/Azure/${role.RoleId}`
        }), role);
        await page.reload();
        await page.locator("#custAdd").click();
        await page.locator("#cfReview").getByRole("button", { name: "Use role" }).click();
        await expect(page.locator("#cfSys")).toHaveValue("Azure");
        await expect(page.locator("#cfRoleId")).toHaveValue(role.RoleId);
        await page.locator("#cfTier").selectOption("ControlPlane");
        await page.locator("#cfJust").fill("Pin Azure role classification");
        await page.locator("#cfApply").click();

        const files = await exportFiles(page);
        expect(files[`${base}.json`]).toEqual([{
            RbacSystem: "Azure", RoleDefinitionId: role.RoleId, RoleDefinitionName: role.RoleName,
            EAMTierLevelName: "ControlPlane", EAMTierLevelTagValue: "0", Justification: "Pin Azure role classification"
        }]);
        await row(page, role.RoleName).getByRole("button", { name: "Edit" }).click();
        await expect(page.locator("#cfSys")).toHaveValue("Azure");
        expect(pageErrors).toEqual([]);
    });

    for (const tenantSource of [false, true]) {
        test(`picks Azure actions from the ${tenantSource ? "tenant" : "built-in"} classification and exports scopes`, async ({ page }) => {
            const action = "Microsoft.Authorization/roleAssignments/write";
            const templateAction = "Microsoft.Resources/subscriptions/read";
            const tenant = "contoso.onmicrosoft.com";
            const tenantPath = `Classification/${tenant}/Classification_Azure.json`;
            const definition = (action) => [{
                EAMTierLevelName: "ControlPlane",
                TierLevelDefinition: [{ Service: "Authorization", RoleDefinitionActions: [action] }]
            }];
            await setClassificationFixture(page, {
                tenants: tenantSource ? [{ name: tenant, files: [tenantPath] }] : [],
                data: {
                    "Classification/Templates/Classification_Azure.json": definition(tenantSource ? templateAction : action),
                    ...(tenantSource ? { [tenantPath]: definition(action) } : {})
                }
            });
            const pageErrors = await openCustomize(page);
            await page.locator("#custTypeSeg [data-type=roleaction]").click();
            await page.locator("#custAdd").click();
            await expect(page.locator("#cfSys option[value=Azure]")).toHaveCount(1);
            await page.locator("#cfSys").selectOption("Azure");
            await expect(page.locator("#cfActionSourceNote")).toContainText(tenantSource ? tenant : "built-in template");
            await page.locator("#cfActionResults [data-pick]", { hasText: action }).click();
            await expect(page.locator("#cfActionResults")).not.toContainText(templateAction);
            await page.locator("#cfScopes").fill("<Tier0IncludedResourceScope>, /subscriptions/test/*");
            await page.locator("#cfTier").selectOption("ControlPlane");
            await page.locator("#cfJust").fill("Keep Azure authorization privileged");
            await page.locator("#cfApply").click();

            const files = await exportFiles(page);
            expect(files["Classification_RoleActionOverwrites.json"]).toEqual([{
                RbacSystem: "Azure", RoleDefinitionActions: [action],
                RoleAssignmentScopeName: ["<Tier0IncludedResourceScope>", "/subscriptions/test/*"],
                EAMTierLevelName: "ControlPlane", EAMTierLevelTagValue: "0",
                Justification: "Keep Azure authorization privileged"
            }]);
            expect(pageErrors).toEqual([]);
        });
    }

    test("adds starred Azure actions and all actions of a starred Azure role", async ({ page }) => {
        const actions = ["Microsoft.Storage/storageAccounts/write", "Microsoft.Storage/storageAccounts/listKeys/action"];
        const roleId = "17d1049b-9a84-46fb-8f53-869881c3d3ab";
        await setClassificationFixture(page, {
            tenants: [],
            data: {
                "Classification/Classification_AzureResources.json": [{
                    RoleId: roleId, RoleName: "Storage Account Contributor",
                    RolePermissions: actions.map((action) => ({ AuthorizedResourceAction: action }))
                }]
            }
        });
        const pageErrors = await openCustomize(page);
        await page.evaluate(({ actions, roleId }) => {
            window.EOReview.toggle({
                id: `action|Azure|${actions[0]}`, kind: "Role action", system: "Azure",
                name: actions[0], hash: `#actions/Azure/${encodeURIComponent(actions[0])}`
            });
            window.EOReview.toggle({
                id: `role|Azure|${roleId}`, kind: "Role", system: "Azure",
                name: "Storage Account Contributor", hash: `#roles/Azure/${roleId}`
            });
        }, { actions, roleId });
        await page.locator("#custTypeSeg [data-type=roleaction]").click();
        await page.locator("#custAdd").click();
        // An empty entry takes the system of the starred role; the starred action of the same
        // system then joins it without a duplicate.
        await expect(page.locator("#cfSys")).toHaveValue("EntraID");
        await page.locator("#cfReview").getByRole("button", { name: "Add all role actions" }).click();
        await expect(page.locator("#cfSys")).toHaveValue("Azure");
        await expect(page.locator("#cfActionChips .cust-chip")).toHaveCount(2);
        await page.locator("#cfReview").getByRole("button", { name: "Add action", exact: true }).click();
        await expect(page.locator("#cfActionChips .cust-chip")).toHaveCount(2);
        await expect(page.locator("#cfError")).toBeEmpty();
        await page.locator("#cfTier").selectOption("ManagementPlane");
        await page.locator("#cfJust").fill("Azure workload operations");
        await page.locator("#cfApply").click();
        const files = await exportFiles(page);
        expect(files["Classification_RoleActionOverwrites.json"]).toEqual([{
            RbacSystem: "Azure", RoleDefinitionActions: actions, RoleAssignmentScopeName: ["/*"],
            EAMTierLevelName: "ManagementPlane", EAMTierLevelTagValue: "1", Justification: "Azure workload operations"
        }]);
        expect(pageErrors).toEqual([]);
    });

    test("keeps files that share a tag apart and exports them under their own names", async ({ page }) => {
        const pageErrors = await openCustomize(page);

        await page.locator("#custImportFile").setInputFiles([
            jsonFile(`${base}_Tier0_PAW.json`, [entry("Tier0 Role", "ControlPlane", "t0")]),
            jsonFile(`${base}_Tier1_PAW.json`, [entry("Tier1 Role", "ManagementPlane", "t1")])
        ]);

        await expect(originOf(page, "Tier0 Role")).toHaveText("Tier0_PAW");
        await expect(originOf(page, "Tier1 Role")).toHaveText("Tier1_PAW");
        await expect(page.locator("#custError")).toBeEmpty();

        const files = await exportFiles(page);
        expect(Object.keys(files).sort()).toEqual([`${base}_Tier0_PAW.json`, `${base}_Tier1_PAW.json`]);
        expect(files[`${base}_Tier0_PAW.json`].map((e) => e.RoleDefinitionName)).toEqual(["Tier0 Role"]);
        expect(files[`${base}_Tier1_PAW.json`].map((e) => e.RoleDefinitionName)).toEqual(["Tier1 Role"]);
        expect(pageErrors).toEqual([]);
    });

    test("rejects unsupported and mixed-system action bookmarks without changing the draft", async ({ page }) => {
        const pageErrors = await openCustomize(page);
        const scope = '<img src=x onerror="window.__scopeXss = true">';
        await page.evaluate((scope) => {
            localStorage.setItem("entraops.reviewList.v1", JSON.stringify([
                { id: "unknown", kind: "Role action", system: "Unknown", name: "unknown/action", scope, app: "EamDashboard" },
                { id: "azure", kind: "Role action", system: "Azure", name: "Microsoft.Authorization/roleAssignments/write", scope, app: "EamDashboard" },
                { id: "entra", kind: "Role action", system: "EntraID", name: "microsoft.directory/users/delete", scope, app: "EamDashboard" }
            ]));
        }, scope);
        await page.locator("#custTypeSeg [data-type=roleaction]").click();
        await page.locator("#custAdd").click();
        const add = (name) => page.locator("#cfReview .action-row", { hasText: name }).getByRole("button", { name: "Add action" });
        await expect(page.locator("#cfReview")).toContainText(scope);
        await expect(page.locator("#cfReview [onerror]")).toHaveCount(0);
        await add("unknown/action").click();
        await expect(page.locator("#cfError")).toContainText("no supported RBAC system");
        await expect(page.locator("#cfActionChips .cust-chip")).toHaveCount(0);
        await add("Microsoft.Authorization/roleAssignments/write").click();
        await expect(page.locator("#cfSys")).toHaveValue("Azure");
        await page.locator("#cfScopes").fill("/subscriptions/reviewed");
        await add("Microsoft.Authorization/roleAssignments/write").click();
        await expect(page.locator("#cfScopes")).toHaveValue("/subscriptions/reviewed");
        await add("microsoft.directory/users/delete").click();
        await expect(page.locator("#cfError")).toContainText("separate overwrite entry");
        await expect(page.locator("#cfSys")).toHaveValue("Azure");
        await expect(page.locator("#cfActionChips .cust-chip")).toHaveCount(1);
        expect(await page.evaluate(() => window.__scopeXss)).toBeUndefined();
        expect(pageErrors).toEqual([]);
    });

    test("applies the system and scope checks to all actions of a starred role", async ({ page }) => {
        const actions = ["Microsoft.Storage/storageAccounts/write", "Microsoft.Storage/storageAccounts/listKeys/action"];
        const entraAction = "microsoft.directory/users/delete";
        await setClassificationFixture(page, {
            tenants: [],
            data: {
                "Classification/Classification_AzureResources.json": [{
                    RoleId: "17d1049b-9a84-46fb-8f53-869881c3d3ab", RoleName: "Storage Account Contributor",
                    RolePermissions: actions.map((action) => ({ AuthorizedResourceAction: action }))
                }]
            }
        });
        const pageErrors = await openCustomize(page);
        await page.evaluate((entraAction) => {
            localStorage.setItem("entraops.reviewList.v1", JSON.stringify([
                {
                    id: `action|EntraID|${entraAction}`, kind: "Role action", system: "EntraID",
                    name: entraAction, hash: `#actions/EntraID/${encodeURIComponent(entraAction)}`
                },
                {
                    id: "role|Azure|assignment-1", kind: "Role", system: "Azure", name: "Storage Account Contributor",
                    scope: "/subscriptions/s1", tier: "ManagementPlane", hash: "#assignment=assignment-1", app: "EamDashboard"
                }
            ]));
        }, entraAction);
        await page.locator("#custTypeSeg [data-type=roleaction]").click();
        await page.locator("#custAdd").click();
        await page.locator("#cfReview").getByRole("button", { name: "Add action", exact: true }).click();
        await expect(page.locator("#cfSys")).toHaveValue("EntraID");
        await expect(page.locator("#cfScopes")).toHaveValue("/*");

        // The role's actions belong to another system: the entry stays unchanged.
        const addRole = page.locator("#cfReview").getByRole("button", { name: "Add all role actions" });
        await addRole.click();
        await expect(page.locator("#cfError")).toContainText("separate overwrite entry");
        await expect(page.locator("#cfSys")).toHaveValue("EntraID");
        await expect(page.locator("#cfActionChips .cust-chip")).toHaveCount(1);

        // On an empty entry, the role of the EAM Dashboard sets the system and clears the default scope.
        await page.locator("#cfActionChips .cust-chip", { hasText: entraAction }).locator(".cust-chip-x").click();
        await addRole.click();
        await expect(page.locator("#cfError")).toBeEmpty();
        await expect(page.locator("#cfSys")).toHaveValue("Azure");
        await expect(page.locator("#cfActionChips .cust-chip")).toHaveCount(2);
        await expect(page.locator("#cfScopes")).toHaveValue("");
        await page.locator("#cfTier").selectOption("ManagementPlane");
        await page.locator("#cfJust").fill("Storage operators");
        await page.locator("#cfApply").click();
        await expect(page.locator("#cfError")).toContainText("Enter the overwrite scope explicitly");

        await page.locator("#cfScopes").fill("/subscriptions/s1/*");
        await page.locator("#cfApply").click();
        const files = await exportFiles(page);
        expect(files["Classification_RoleActionOverwrites.json"]).toEqual([{
            RbacSystem: "Azure", RoleDefinitionActions: actions, RoleAssignmentScopeName: ["/subscriptions/s1/*"],
            EAMTierLevelName: "ManagementPlane", EAMTierLevelTagValue: "1", Justification: "Storage operators"
        }]);
        expect(pageErrors).toEqual([]);
    });

    test("requires an explicit scope only while a bookmarked action remains in the entry", async ({ page }) => {
        const bookmarked = "microsoft.directory/users/delete";
        const picked = "microsoft.directory/users/password/update";
        const pageErrors = await openCustomize(page);
        await page.evaluate(({ bookmarked, picked }) => {
            localStorage.setItem("entraops.reviewList.v1", JSON.stringify([
                {
                    id: `action|EntraID|${bookmarked}|/administrativeUnits/au1`, kind: "Role action", system: "EntraID",
                    name: bookmarked, scope: "/administrativeUnits/au1", tier: "ControlPlane",
                    hash: `#assignment=assignment-1&action=${encodeURIComponent(bookmarked)}`, app: "EamDashboard"
                },
                {
                    id: `action|EntraID|${picked}`, kind: "Role action", system: "EntraID",
                    name: picked, hash: `#actions/EntraID/${encodeURIComponent(picked)}`
                }
            ]));
        }, { bookmarked, picked });
        await page.locator("#custTypeSeg [data-type=roleaction]").click();
        await page.locator("#custAdd").click();
        const add = (name) => page.locator("#cfReview .action-row", { hasText: name }).getByRole("button", { name: "Add action" });
        const remove = (name) => page.locator("#cfActionChips .cust-chip", { hasText: name }).locator(".cust-chip-x");
        await add(bookmarked).click();
        await add(picked).click();
        await expect(page.locator("#cfScopes")).toHaveValue("");
        await page.locator("#cfTier").selectOption("ManagementPlane");
        await page.locator("#cfJust").fill("Helpdesk password resets");

        // Removing the other action keeps the requirement of the bookmarked one.
        await remove(picked).click();
        await page.locator("#cfApply").click();
        await expect(page.locator("#cfError")).toContainText("Enter the overwrite scope explicitly");

        // The RBAC system can't change while the entry has actions.
        await page.locator("#cfSys").selectOption("Azure");
        await expect(page.locator("#cfSys")).toHaveValue("EntraID");
        await expect(page.locator("#cfError")).toContainText("Remove them to change the RBAC system");

        // Without a bookmarked action, the empty scope falls back to all scopes.
        await add(picked).click();
        await remove(bookmarked).click();
        await expect(page.locator("#cfActionChips .cust-chip")).toHaveCount(1);
        await page.locator("#cfApply").click();
        const files = await exportFiles(page);
        expect(files["Classification_RoleActionOverwrites.json"]).toEqual([{
            RbacSystem: "EntraID", RoleDefinitionActions: [picked], RoleAssignmentScopeName: ["/*"],
            EAMTierLevelName: "ManagementPlane", EAMTierLevelTagValue: "1", Justification: "Helpdesk password resets"
        }]);
        expect(pageErrors).toEqual([]);
    });

    test("renders imported names and justifications as text without executing HTML", async ({ page }) => {
        const pageErrors = await openCustomize(page);
        const payload = '<img src=x onerror="window.__importXss = true">';
        const fileName = `${base}_<svg onload=window.__importXss=true>.json`;
        await page.locator("#custImportFile").setInputFiles([
            jsonFile(fileName, [entry(payload, "ControlPlane", payload)])
        ]);

        await expect(row(page, payload)).toBeVisible();
        await expect(page.locator("#custStatus")).toContainText(fileName);
        await expect(page.locator("#custTable [onerror], #custTable [onload], #custStatus [onload]")).toHaveCount(0);
        expect(await page.evaluate(() => window.__importXss)).toBeUndefined();
        const files = await exportFiles(page);
        // Browsers sanitize characters such as angle brackets in download filenames.
        expect(Object.values(files)[0][0]).toEqual(expect.objectContaining({ RoleDefinitionName: payload, Justification: payload }));
        expect(pageErrors).toEqual([]);
    });

    test("lists items overwritten in more than one file", async ({ page }) => {
        const pageErrors = await openCustomize(page);

        await page.locator("#custImportFile").setInputFiles([
            jsonFile(`${base}.json`, [entry("Shared Role", "ControlPlane", "base")]),
            jsonFile(`${base}_PAW.json`, [entry("Shared Role", "ManagementPlane", "paw"), entry("Other Role", "UserAccess", "paw", { Service: "Global" })])
        ]);

        await expect(page.locator("#custOverlaps")).toContainText("1 item is overwritten in more than one file");
        await expect(page.locator("#custOverlaps")).toContainText(`Shared Role (whole role): ${base}.json, ${base}_PAW.json`);
        await expect(page.locator("#custOverlaps")).toContainText("RoleDefinitionId takes precedence");
        expect(pageErrors).toEqual([]);
    });

    test("writes a new entry to the target file chosen in the entry dialog", async ({ page }) => {
        const pageErrors = await openCustomize(page);

        await page.locator("#custImportFile").setInputFiles([jsonFile(`${base}.json`, [entry("Base Role", "ControlPlane", "base")])]);
        await row(page, "Base Role").getByRole("button", { name: "Edit" }).click();
        await page.locator("#cfTarget").selectOption("__new");
        await page.locator("#cfNewTag").fill("PAW");
        await page.locator("#cfApply").click();

        await expect(originOf(page, "Base Role")).toHaveText("Custom - PAW");
        const files = await exportFiles(page);
        expect(files[`${base}.json`]).toEqual([]);
        expect(files[`${base}_PAW.json`].map((e) => e.RoleDefinitionName)).toEqual(["Base Role"]);
        expect(pageErrors).toEqual([]);
    });

    test("loads the tenant base file together with its tagged files", async ({ page }) => {
        const tenantFolder = "Classification/contoso.onmicrosoft.com";
        await setClassificationFixture(page, {
            tenants: [{
                name: "contoso.onmicrosoft.com",
                files: [`${tenantFolder}/Classification_AadResources.json`, `${tenantFolder}/Classification_RoleDefinitionOverwrites.json`,
                    `${tenantFolder}/Classification_RoleDefinitionOverwrites_PAW.json`, `${tenantFolder}/Classification_RoleActionOverwrites_PAW.json`]
            }],
            data: {
                [`${tenantFolder}/Classification_RoleDefinitionOverwrites.json`]: [entry("Tenant Role", "ControlPlane", "tenant")],
                [`${tenantFolder}/Classification_RoleDefinitionOverwrites_PAW.json`]: [entry("PAW Role", "ControlPlane", "paw")]
            }
        });
        const pageErrors = await openCustomize(page);

        await expect(page.locator("#custSource option", { hasText: "contoso.onmicrosoft.com" })).toHaveText("contoso.onmicrosoft.com (tenant-specific, tags: PAW)");
        await page.locator("#custSource").selectOption("tenant:contoso.onmicrosoft.com");
        await page.locator("#custLoad").click();

        await expect(originOf(page, "Tenant Role")).toHaveText("Base");
        await expect(originOf(page, "PAW Role")).toHaveText("PAW");
        await expect(page.locator("#custStatus")).toContainText(`${base}_PAW.json (1)`);
        expect(pageErrors).toEqual([]);
    });

    test("loads the template base file for a tenant that only has tagged role definition files", async ({ page }) => {
        const tenantFolder = "Classification/contoso.onmicrosoft.com";
        await setClassificationFixture(page, {
            tenants: [{ name: "contoso.onmicrosoft.com", files: [`${tenantFolder}/Classification_RoleDefinitionOverwrites_PAW.json`] }],
            data: {
                "Classification/Templates/Classification_RoleDefinitionOverwrites.json": [entry("Template Role", "ControlPlane", "template")],
                [`${tenantFolder}/Classification_RoleDefinitionOverwrites_PAW.json`]: [entry("PAW Role", "ControlPlane", "paw")]
            }
        });
        const pageErrors = await openCustomize(page);

        await expect(page.locator("#custSource option", { hasText: "contoso.onmicrosoft.com" })).toHaveText("contoso.onmicrosoft.com (tenant-specific, tags: PAW, base from template)");
        await page.locator("#custSource").selectOption("tenant:contoso.onmicrosoft.com");
        await page.locator("#custLoad").click();
        await expect(originOf(page, "Template Role")).toHaveText("Base");
        await expect(originOf(page, "PAW Role")).toHaveText("PAW");

        // Saving a new entry creates the tenant base file; it must keep the template entries it replaces
        await page.locator("#custAdd").click();
        await page.locator("#cfRoleName").fill("New Role");
        await page.locator("#cfTier").selectOption("UserAccess");
        await page.locator("#cfJust").fill("new");
        await page.locator("#cfApply").click();
        await expect(originOf(page, "New Role")).toHaveText("Custom - Base");
        const exported = await exportFiles(page);
        expect(exported[`${base}.json`].map((e) => e.RoleDefinitionName)).toEqual(["Template Role", "New Role"]);
        expect(pageErrors).toEqual([]);
    });

    test("reuses the spelling of an existing file for a new tag that differs only by case", async ({ page }) => {
        const pageErrors = await openCustomize(page);

        await page.locator("#custImportFile").setInputFiles([jsonFile(`${base}_PAW.json`, [entry("PAW Role", "ControlPlane", "paw")])]);
        await page.locator("#custAdd").click();
        await page.locator("#cfRoleName").fill("New Role");
        await page.locator("#cfTier").selectOption("UserAccess");
        await page.locator("#cfJust").fill("new");
        await page.locator("#cfTarget").selectOption("__new");
        await page.locator("#cfNewTag").fill("paw");
        await page.locator("#cfApply").click();

        await expect(originOf(page, "New Role")).toHaveText("Custom - PAW");
        await expect(page.locator("#custStatus .chip.brand", { hasText: "_PAW" })).toHaveText(`${base}_PAW.json (2)`);
        await expect(page.locator("#custStatus .chip.brand", { hasText: /_paw\.json/ })).toHaveCount(0);

        // An imported file that differs only by case also merges into the existing file
        page.once("dialog", (dialog) => dialog.accept());
        await page.locator("#custImportFile").setInputFiles([jsonFile(`${base}_paw.json`, [entry("Imported Role", "ControlPlane", "imported")])]);
        await expect(originOf(page, "Imported Role")).toHaveText("PAW");
        await expect(page.locator("#custStatus .chip.brand", { hasText: /_paw\.json/ })).toHaveCount(0);
        expect(pageErrors).toEqual([]);
    });

    test("keeps the draft unsaved after a multi-file download until the files are confirmed", async ({ page }) => {
        const pageErrors = await openCustomize(page);

        await page.locator("#custImportFile").setInputFiles([
            jsonFile(`${base}.json`, [entry("Base Role", "ControlPlane", "base"), entry("Removed Role", "ControlPlane", "base")]),
            jsonFile(`${base}_PAW.json`, [entry("PAW Role", "ManagementPlane", "paw")])
        ]);
        await row(page, "Removed Role").getByTitle("Remove this entry").click();

        const downloads = [];
        page.on("download", (download) => downloads.push(download));
        await page.locator("#custExport").click();
        await expect.poll(() => downloads.length).toBe(2);

        // Not finalized yet: the removed entry can still be restored
        await expect(page.locator("#custDownloadConfirm")).toBeVisible();
        await expect(page.locator("#custStatus")).toContainText("unsaved changes");
        await expect(row(page, "Removed Role").getByRole("button", { name: "Restore" })).toBeVisible();

        // A change after the download invalidates the confirmation
        await row(page, "Removed Role").getByRole("button", { name: "Restore" }).click();
        await page.locator("#custExport").click();
        await expect.poll(() => downloads.length).toBe(4);
        await row(page, "Base Role").getByTitle("Remove this entry").click();
        await page.locator("#custDownloadDone").click();
        await expect(page.locator("#custError")).toContainText("The draft changed after the download");
        await expect(page.locator("#custStatus")).toContainText("unsaved changes");

        await page.locator("#custExport").click();
        await expect.poll(() => downloads.length).toBe(6);
        await page.locator("#custDownloadDone").click();
        await expect(page.locator("#custStatus")).not.toContainText("unsaved changes");
        await expect(row(page, "Base Role")).toHaveCount(0);
        expect(pageErrors).toEqual([]);
    });

    test("reports a denied or failed folder save instead of downloading the files", async ({ page }) => {
        const pageErrors = await openCustomize(page);
        const downloads = [];
        page.on("download", (download) => downloads.push(download));

        await page.locator("#custImportFile").setInputFiles([
            jsonFile(`${base}.json`, [entry("Base Role", "ControlPlane", "base")]),
            jsonFile(`${base}_PAW.json`, [entry("PAW Role", "ManagementPlane", "paw")])
        ]);

        await fakeDirectoryPicker(page, { deny: true });
        await page.locator("#custSave").click();
        await expect(page.locator("#custError")).toContainText("Nothing was saved: write access was not granted");

        await fakeDirectoryPicker(page, { failOn: `${base}_PAW.json` });
        await page.locator("#custSave").click();
        await expect(page.locator("#custError")).toContainText("Saving stopped after 1 of 2 files");
        await expect(page.locator("#custError")).toContainText(`Not written: ${base}_PAW.json`);
        await expect(page.locator("#custStatus")).toContainText("unsaved changes");
        expect(downloads).toHaveLength(0);

        await fakeDirectoryPicker(page);
        await page.locator("#custSave").click();
        await expect(page.locator("#custStatus")).not.toContainText("unsaved changes");
        expect(Object.keys(await page.evaluate(() => window.__written)).sort()).toEqual([`${base}.json`, `${base}_PAW.json`]);
        expect(downloads).toHaveLength(0);
        expect(pageErrors).toEqual([]);
    });

    for (const tagged of [false, true]) {
        test(`keeps edits made during a ${tagged ? "folder" : "single-file"} save unsaved and restorable`, async ({ page }) => {
            const pageErrors = await openCustomize(page);
            const files = [jsonFile(`${base}.json`, [entry("Base Role", "ControlPlane", "base")])];
            if (tagged) files.push(jsonFile(`${base}_PAW.json`, [entry("PAW Role", "ManagementPlane", "paw")]));
            await page.locator("#custImportFile").setInputFiles(files);

            await fakeDirectoryPicker(page, { pauseOn: `${base}.json` });
            await page.locator("#custSave").click();
            await expect.poll(() => page.evaluate(() => typeof window.__resumeSave)).toBe("function");
            await row(page, "Base Role").getByTitle("Remove this entry").click();
            await page.evaluate(() => window.__resumeSave());

            await expect(page.locator("#custError")).toContainText("The draft changed while saving");
            await expect(page.locator("#custStatus")).toContainText("unsaved changes");
            await expect(row(page, "Base Role").getByRole("button", { name: "Restore" })).toBeVisible();
            const saved = await page.evaluate((name) => JSON.parse(window.__written[name]), `${base}.json`);
            expect(saved.map((e) => e.RoleDefinitionName)).toEqual(["Base Role"]);

            // The pending removal survives a reload and is written only by the next save.
            await page.reload();
            await expect(page.locator("#custStatus")).toContainText("unsaved changes");
            await expect(row(page, "Base Role").getByRole("button", { name: "Restore" })).toBeVisible();
            await fakeDirectoryPicker(page);
            await page.locator("#custSave").click();
            await expect(page.locator("#custStatus")).not.toContainText("unsaved changes");
            await expect(row(page, "Base Role")).toHaveCount(0);
            expect(await page.evaluate((name) => JSON.parse(window.__written[name]), `${base}.json`)).toEqual([]);
            expect(pageErrors).toEqual([]);
        });
    }

    test("routes a file of another overwrite type to its own tab and maps unknown names to a tagged file", async ({ page }) => {
        const pageErrors = await openCustomize(page);

        await page.locator("#custImportFile").setInputFiles([
            jsonFile("Classification_ApiPermissionOverwrites_Graph.json", [
                { PermissionValue: "Mail.Read", EAMTierLevelName: "ManagementPlane", Justification: "graph" }
            ])
        ]);
        await expect(page.locator("#custTypeSeg .seg.active")).toHaveText("API Permissions");
        await expect(originOf(page, "Mail.Read")).toHaveText("Graph");

        await page.locator("#custTypeSeg [data-type=roledef]").click();
        await page.locator("#custImportFile").setInputFiles([jsonFile("my_Tier0.json", [entry("Tier0 Role", "ControlPlane", "t0")])]);
        await expect(originOf(page, "Tier0 Role")).toHaveText("Tier0");
        await expect(page.locator("#custError")).toContainText(`my_Tier0.json → ${base}_Tier0.json`);
        expect(pageErrors).toEqual([]);
    });

    // Roles of the same name in two RBAC systems: a bookmark without role ID (for example from the EAM Dashboard)
    // must resolve within its own system, not to the first role of that name.
    const sameNameRoles = {
        tenants: [],
        data: {
            "Classification/Classification_AzureResources.json": [{
                RoleId: "acdd72a7-3385-48ef-bd42-f606fba81ae7", RoleName: "Reader",
                RolePermissions: [{ AuthorizedResourceAction: "*/read" }]
            }],
            "Classification/Classification_DeviceManagementRoles.json": [{
                RoleId: "a9f2c3c1-0000-4000-8000-000000000001", RoleName: "Reader",
                RolePermissions: [{ AuthorizedResourceAction: "Microsoft.Intune_ManagedDevices_Read" }]
            }]
        }
    };
    const starIntuneReader = (page) => page.evaluate(() => window.EOReview.toggle({
        id: "role|Intune|Reader", kind: "Role", system: "Intune", name: "Reader", hash: ""
    }));

    test("uses the role of the starred role's RBAC system when the name exists in another system", async ({ page }) => {
        await setClassificationFixture(page, sameNameRoles);
        const pageErrors = await openCustomize(page);
        await starIntuneReader(page);
        await page.reload();
        await page.locator("#custAdd").click();
        await page.locator("#cfReview").getByRole("button", { name: "Use role" }).click();
        await expect(page.locator("#cfSys")).toHaveValue("DeviceManagement");
        await expect(page.locator("#cfRoleId")).toHaveValue("a9f2c3c1-0000-4000-8000-000000000001");
        await page.locator("#cfTier").selectOption("ManagementPlane");
        await page.locator("#cfJust").fill("Intune read access");
        await page.locator("#cfApply").click();

        const files = await exportFiles(page);
        expect(files[`${base}.json`]).toEqual([{
            RbacSystem: "DeviceManagement", RoleDefinitionId: "a9f2c3c1-0000-4000-8000-000000000001", RoleDefinitionName: "Reader",
            EAMTierLevelName: "ManagementPlane", EAMTierLevelTagValue: "1", Justification: "Intune read access"
        }]);
        expect(pageErrors).toEqual([]);
    });

    test("adds all role actions of the starred role's RBAC system when the name exists in another system", async ({ page }) => {
        await setClassificationFixture(page, sameNameRoles);
        const pageErrors = await openCustomize(page);
        await starIntuneReader(page);
        await page.locator("#custTypeSeg [data-type=roleaction]").click();
        await page.locator("#custAdd").click();
        await page.locator("#cfReview").getByRole("button", { name: "Add all role actions" }).click();
        await expect(page.locator("#cfSys")).toHaveValue("DeviceManagement");
        await expect(page.locator("#cfActionChips .cust-chip")).toHaveCount(1);
        await expect(page.locator("#cfActionChips")).toContainText("Microsoft.Intune_ManagedDevices_Read");
        await expect(page.locator("#cfActionChips")).not.toContainText("*/read");
        expect(pageErrors).toEqual([]);
    });

    test("keeps the RBAC system of a starred role that is not in the classified role exports", async ({ page }) => {
        await setClassificationFixture(page, sameNameRoles);
        const pageErrors = await openCustomize(page);
        await page.evaluate(() => window.EOReview.toggle({
            id: "role|Azure|Custom Operator", kind: "Role", system: "Azure", name: "Custom Operator", hash: ""
        }));
        await page.reload();
        await page.locator("#custAdd").click();
        await expect(page.locator("#cfSys")).toHaveValue("EntraID");
        await page.locator("#cfReview").getByRole("button", { name: "Use role" }).click();
        await expect(page.locator("#cfSys")).toHaveValue("Azure");
        await expect(page.locator("#cfRoleName")).toHaveValue("Custom Operator");
        expect(pageErrors).toEqual([]);
    });

    test("asks for the RBAC system of a starred role whose name exists in several systems", async ({ page }) => {
        await setClassificationFixture(page, sameNameRoles);
        const pageErrors = await openCustomize(page);
        await page.evaluate(() => window.EOReview.toggle({ id: "role||Reader", kind: "Role", system: "", name: "Reader", hash: "" }));
        await page.locator("#custTypeSeg [data-type=roleaction]").click();
        await page.locator("#custAdd").click();
        await page.locator("#cfReview").getByRole("button", { name: "Add all role actions" }).click();
        await expect(page.locator("#cfError")).toContainText("Several RBAC systems have a role named \"Reader\"");
        await expect(page.locator("#cfActionChips .cust-chip")).toHaveCount(0);
        expect(pageErrors).toEqual([]);
    });
});
