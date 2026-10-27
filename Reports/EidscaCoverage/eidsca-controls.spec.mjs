import { expect, test } from "@playwright/test";
import { fileURLToPath, pathToFileURL } from "node:url";

const appUrl = pathToFileURL(fileURLToPath(new URL("index.html", import.meta.url))).href;
const self = "ManagePermissionGrantsForSelf.";
const low = self + "microsoft-user-default-low";
const recommended = self + "microsoft-user-default-recommended";
const legacy = self + "microsoft-user-default-legacy";
const ownedResource = "ManagePermissionGrantsForOwnedResource.microsoft-dynamically-managed-permissions-for-team";

async function openSnapshot(page, properties) {
    const errors = [];
    page.on("pageerror", (error) => errors.push(error.message));
    await page.route((url) => !["file:", "data:", "blob:", "about:"].includes(url.protocol), (route) => route.abort());
    await page.addInitScript((props) => {
        const data = {
            snapshots: [{
                commitSha: "eidsca-fixture", commitDate: "2026-10-26T10:00:00Z", hasDetail: true,
                resources: [{ p: "microsoft.entra.authorizationPolicy/General/Policy.json", h: "policy" }]
            }],
            blobs: { policy: { properties: props } }
        };
        // Keep the fixture even when a locally generated deployment bundle exists.
        Object.defineProperty(window, "ENTRAOPS_CONFIGANALYZER_DATA", { get: () => data, set() {} });
    }, properties);
    await page.goto(appUrl);
    await expect(page.locator("#eidscaChecksView")).toBeVisible();
    return errors;
}

function finding(page, checkId) {
    return page.locator(".ca-gap-row").filter({ hasText: `(${checkId})` });
}

const consentCases = [
    { name: "disabled consent", values: [], status: "ok", count: 0 },
    { name: "low baseline", values: [low], status: "ok", count: 0 },
    { name: "recommended baseline", values: [recommended], status: "ok", count: 0 },
    { name: "both accepted baselines", values: [low, recommended], status: "ok", count: 0 },
    { name: "resource-specific consent only", values: [ownedResource], status: "ok", count: 0 },
    { name: "baseline and resource-specific consent", values: [recommended, ownedResource], status: "ok", count: 0 },
    { name: "legacy unrestricted consent", values: [legacy], status: "warn", count: 1 },
    { name: "legacy mixed with a restrictive policy", values: [low, legacy], status: "warn", count: 1 },
    { name: "legacy mixed with a custom policy", values: [legacy, self + "custom"], status: "warn", count: 2 },
    { name: "custom self-consent policy", values: [self + "custom"], status: "info" },
    { name: "mail-client exception policy", values: [self + "microsoft-user-default-allow-consent-apps"], status: "info" },
    { name: "baseline mixed with a custom policy", values: [low, self + "custom"], status: "info" },
    { name: "missing assignments", status: "unknown" },
    { name: "null assignments", values: null, status: "unknown" },
    { name: "case-insensitive assignments", values: [recommended.toUpperCase()], status: "ok", count: 0 }
];

for (const { name, values, status, count } of consentCases) {
    test(`AP08 evaluates ${name}`, async ({ page }) => {
        const props = values === undefined ? {} : { PermissionGrantPolicyIdsAssignedToDefaultUserRole: values };
        const errors = await openSnapshot(page, props);
        const row = finding(page, "EIDSCA.AP08");
        await expect(row.locator(`.ca-gap-icon.${status}`)).toHaveCount(1);
        if (count !== undefined) await expect(row).toContainText(`Current: ${count}`);
        if (status === "info" || status === "unknown") await expect(row).toContainText("Manual review required");
        await expect(row).toContainText("Recommended: 0");
        expect(errors).toEqual([]);
    });
}

for (const allowed of [false, true]) {
    test(`AP12 evaluates the captured tenant-creation restriction (${allowed})`, async ({ page }) => {
        const errors = await openSnapshot(page, { DefaultUserRoleAllowedToCreateTenants: allowed });
        await expect(finding(page, "EIDSCA.AP12").locator(`.ca-gap-icon.${allowed ? "warn" : "ok"}`)).toHaveCount(1);
        expect(errors).toEqual([]);
    });
}

const blueprintCases = [
    { name: "restricted snapshot setting", props: { DefaultUserRoleAllowedToCreateAgentIdentityBlueprints: false }, status: "ok" },
    { name: "permissive snapshot setting", props: { DefaultUserRoleAllowedToCreateAgentIdentityBlueprints: true }, status: "warn" },
    { name: "nested Graph setting", props: { defaultUserRolePermissions: { allowedToCreateAgentIdentityBlueprints: false } }, status: "ok" },
    { name: "direct setting", props: { allowedToCreateAgentIdentityBlueprints: false }, status: "ok" },
    { name: "missing setting", props: {}, status: "unknown" },
    { name: "null setting", props: { DefaultUserRoleAllowedToCreateAgentIdentityBlueprints: null }, status: "unknown" }
];

for (const { name, props, status } of blueprintCases) {
    test(`AP15 evaluates ${name}`, async ({ page }) => {
        const errors = await openSnapshot(page, props);
        const row = finding(page, "EIDSCA.AP15");
        await expect(row.locator(`.ca-gap-icon.${status}`)).toHaveCount(1);
        if (status === "unknown") await expect(row).toContainText("No compliance conclusion is made");
        expect(errors).toEqual([]);
    });
}

test("refreshed controls retain snapshot mappings and upstream severities", async ({ page }) => {
    const errors = await openSnapshot(page, {
        AllowedToUseSSPR: true,
        GuestUserRole: "RestrictedGuest",
        DefaultUserRoleAllowedToCreateApps: false
    });
    await expect(finding(page, "EIDSCA.AP01").locator(".eidsca-severity")).toHaveText("High");
    await expect(finding(page, "EIDSCA.AP07").locator(".ca-gap-icon.ok")).toHaveCount(1);
    await expect(finding(page, "EIDSCA.AP07").locator(".eidsca-severity")).toHaveText("Medium");
    await expect(finding(page, "EIDSCA.AP10").locator(".ca-gap-icon.ok")).toHaveCount(1);
    await expect(finding(page, "EIDSCA.AP10").locator(".eidsca-severity")).toHaveText("Medium");
    expect(errors).toEqual([]);
});
