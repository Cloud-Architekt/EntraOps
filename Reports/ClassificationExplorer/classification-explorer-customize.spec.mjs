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

// Replaces the File System Access directory picker with an in-page fake that records the written files.
async function fakeDirectoryPicker(page, { deny = false, failOn = null } = {}) {
    await page.evaluate(({ deny, failOn }) => {
        window.__written = {};
        window.showDirectoryPicker = async () => {
            if (deny) throw new DOMException("denied", "NotAllowedError");
            return {
                getFileHandle: async (name) => ({
                    createWritable: async () => ({
                        write: async (text) => {
                            if (name === failOn) throw new DOMException("disk full", "InvalidStateError");
                            window.__written[name] = text;
                        },
                        close: async () => { }
                    })
                })
            };
        };
    }, { deny, failOn });
}

test.describe("Classification Explorer: Customize Overwrites with tagged files", () => {
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
});
