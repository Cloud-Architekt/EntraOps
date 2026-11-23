import { expect, test } from "@playwright/test";
import { readFile } from "node:fs/promises";
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

// ---- Filters: status and severity pills, snapshot dropdowns, collapsible areas ----------------------------
const filterProps = {
    AllowedToUseSSPR: true,
    GuestUserRole: "RestrictedGuest",
    DefaultUserRoleAllowedToCreateApps: false,
    DefaultUserRoleAllowedToCreateTenants: true,
    PermissionGrantPolicyIdsAssignedToDefaultUserRole: [legacy]
};

async function openSnapshots(page, propertySets) {
    const errors = [];
    page.on("pageerror", (error) => errors.push(error.message));
    await page.route((url) => !["file:", "data:", "blob:", "about:"].includes(url.protocol), (route) => route.abort());
    await page.addInitScript((sets) => {
        const data = {
            generatedAt: "2026-10-28T08:00:00Z",
            snapshots: sets.map((props, index) => ({
                commitSha: "eidsca-fixture-" + index, commitDate: `2026-10-2${index}T10:00:00Z`, hasDetail: true,
                resources: [{ p: "microsoft.entra.authorizationPolicy/General/Policy.json", h: "policy" + index }]
            })),
            blobs: Object.fromEntries(sets.map((props, index) => ["policy" + index, { properties: props }]))
        };
        Object.defineProperty(window, "ENTRAOPS_CONFIGANALYZER_DATA", { get: () => data, set() {} });
    }, propertySets);
    await page.goto(appUrl);
    await expect(page.locator("#eidscaChecksView")).toBeVisible();
    return errors;
}

// The status and severity of the check rows in the list (the rows of collapsed areas included).
function controlRows(page) {
    return page.locator("#eidscaBody .ca-gap-row").filter({ hasText: "(EIDSCA." }).evaluateAll((rows) => rows.map((row) => ({
        status: row.querySelector(".ca-gap-icon").classList[1],
        severity: row.querySelector(".eidsca-severity") ? row.querySelector(".eidsca-severity").textContent : "Unspecified"
    })));
}

function tally(rows, key) {
    return rows.reduce((counts, row) => ({ ...counts, [row[key]]: (counts[row[key]] || 0) + 1 }), {});
}

const statusPill = (page, value) => page.locator(`#eidscaStatusPills .eo-pill[data-value="${value}"]`);
const severityPill = (page, value) => page.locator(`#eidscaSeverityPills .eo-pill[data-value="${value}"]`);

// The checks of areas that could not be evaluated (resource type not captured) are Unknown: the tiles and the pills
// count them, the list shows one gap row per area instead of a row per check. Returns the status counts of the
// rendered check rows plus these gap checks, as the tiles and the status pills show them.
async function statusCountsWithGaps(page, rows) {
    const unknownTile = Number(await page.locator('#eidscaDashboard [data-eidsca-status="unknown"] .stat-value').textContent());
    const counts = tally(rows, "status");
    const gaps = unknownTile - (counts.unknown || 0);
    expect(gaps).toBeGreaterThanOrEqual(0);
    if (gaps) counts.unknown = (counts.unknown || 0) + gaps;
    return { counts, total: rows.length + gaps, gaps };
}

async function expectPillCounts(page, containerId, counts, total) {
    await expect(page.locator(`#${containerId} .eo-pill[data-value=""] .eo-pill-count`)).toHaveText(String(total));
    for (const [value, count] of Object.entries(counts)) {
        await expect(page.locator(`#${containerId} .eo-pill[data-value="${value}"] .eo-pill-count`)).toHaveText(String(count));
    }
}

test("status and severity pills show faceted counts and filter the check list", async ({ page }) => {
    const errors = await openSnapshots(page, [filterProps]);
    const all = await controlRows(page);
    expect(all.length).toBeGreaterThan(5);
    // The pills count like the tiles: the evaluated checks and the Unknown checks of the gap rows.
    const withGaps = await statusCountsWithGaps(page, all);
    expect(withGaps.gaps).toBeGreaterThan(0);
    await expect(page.locator("#eidscaFilterSummary")).toHaveText(` · ${withGaps.total} check result(s) shown`);
    await expectPillCounts(page, "eidscaStatusPills", withGaps.counts, withGaps.total);
    await expect(page.locator('#eidscaSeverityPills .eo-pill[data-value=""] .eo-pill-count')).toHaveText(String(withGaps.total));
    for (const [severity, count] of Object.entries(tally(all, "severity"))) {
        expect(Number(await severityPill(page, severity).locator(".eo-pill-count").textContent())).toBeGreaterThanOrEqual(count);
    }
    await expect(page.locator("#eidscaStatusPills .eo-pill")).toHaveCount(5);
    await expect(page.locator("#eidscaStatusPills .eo-pill.active")).toHaveAttribute("data-value", "");

    // A status pill filters the list; the severity pills count the failing checks only.
    const failing = all.filter((row) => row.status === "warn");
    expect(failing.length).toBeGreaterThan(0);
    await statusPill(page, "warn").click();
    await expect(statusPill(page, "warn")).toHaveAttribute("aria-pressed", "true");
    await expect(page.locator("#eidscaFilterSummary")).toHaveText(` · ${failing.length} check result(s) shown`);
    expect(await controlRows(page)).toEqual(failing);
    await expectPillCounts(page, "eidscaSeverityPills", tally(failing, "severity"), failing.length);
    await expectPillCounts(page, "eidscaStatusPills", withGaps.counts, withGaps.total);
    // The gap rows are Unknown: a Failing filter does not list them.
    await expect(page.locator("#eidscaBody .ca-gap-row").filter({ hasText: "is not captured in this snapshot" })).toHaveCount(0);
    for (const severity of ["High", "Medium", "Low", "Informational"]) {
        if (tally(all, "severity")[severity] && !tally(failing, "severity")[severity]) await expect(severityPill(page, severity)).toBeDisabled();
    }

    // The severity pill combines with the status pill, and the status pills follow it.
    const severity = failing[0].severity;
    await severityPill(page, severity).click();
    const both = all.filter((row) => row.status === "warn" && row.severity === severity);
    expect(await controlRows(page)).toEqual(both);
    await expect(statusPill(page, "warn").locator(".eo-pill-count")).toHaveText(String(both.length));

    // A second click on a pill shows all again.
    await statusPill(page, "warn").click();
    await severityPill(page, severity).click();
    await expect(page.locator("#eidscaFilterSummary")).toHaveText(` · ${withGaps.total} check result(s) shown`);
    expect(await controlRows(page)).toHaveLength(all.length);
    expect(errors).toEqual([]);
});

test("status tiles, reset and the CSV export use the pill filters", async ({ page }) => {
    const errors = await openSnapshots(page, [filterProps]);
    const all = await controlRows(page);
    const passing = all.filter((row) => row.status === "ok");

    await page.locator('[data-eidsca-status="ok"]').click();
    await expect(statusPill(page, "ok")).toHaveAttribute("aria-pressed", "true");
    expect(await controlRows(page)).toEqual(passing);

    const downloadPromise = page.waitForEvent("download");
    await page.locator("#eidscaExportFiltered").click();
    const csv = await readFile(await (await downloadPromise).path(), "utf8");
    expect(csv.trim().split("\n")).toHaveLength(passing.length + 1);

    await severityPill(page, passing[0].severity).focus();
    await page.keyboard.press("Enter");
    await expect(severityPill(page, passing[0].severity)).toHaveAttribute("aria-pressed", "true");
    await page.locator("#eidscaResetFilters").click();
    await expect(page.locator("#eidscaFacets .eo-pill.active")).toHaveCount(2);
    await expect(page.locator('[data-eidsca-status="ok"]')).toHaveAttribute("aria-pressed", "false");
    expect(await controlRows(page)).toHaveLength(all.length);
    expect(errors).toEqual([]);
});

test("control areas collapse, start collapsed and remember the state", async ({ page }) => {
    const errors = await openSnapshots(page, [filterProps]);
    const area = page.locator(".eo-group").filter({ hasText: "Default Authorization Settings" });
    const toggle = area.locator(".eo-group-toggle");
    await expect(area).toHaveClass(/collapsed/);
    await expect(toggle).toHaveAttribute("aria-expanded", "false");
    await expect(area.locator(".eo-group-body")).toBeHidden();
    await expect(page.locator("#eidscaCollapseAll")).toHaveText("Expand all");

    await toggle.click();
    await expect(area.locator(".eo-group-body")).toBeVisible();
    await expect(toggle).toHaveAttribute("aria-expanded", "true");
    await expect(page.locator(".eo-group-toggle").filter({ hasText: "Default Authorization Settings" })).toBeFocused();
    await expect(page.locator("#eidscaCollapseAll")).toHaveText("Collapse all");

    // The expanded area stays expanded after a reload and after a filter change.
    await page.reload();
    await expect(area.locator(".eo-group-body")).toBeVisible();
    await statusPill(page, "warn").click();
    await expect(area.locator(".eo-group-body")).toBeVisible();

    await page.locator("#eidscaCollapseAll").click();
    await expect(page.locator(".eo-group:not(.collapsed)")).toHaveCount(0);
    await page.locator("#eidscaCollapseAll").click();
    await expect(page.locator(".eo-group.collapsed")).toHaveCount(0);
    expect(errors).toEqual([]);
});

test("snapshot dropdowns sit in the search bar and switch the evaluated snapshot", async ({ page }) => {
    const errors = await openSnapshots(page, [{}, filterProps]);
    await expect(page.locator(".eo-searchbar .eo-select #eidscaSnapshot")).toBeVisible();
    await expect(page.locator("#eidscaSnapshot")).toHaveValue("1");
    const latest = await controlRows(page);
    const latestCounts = await statusCountsWithGaps(page, latest);
    await expectPillCounts(page, "eidscaStatusPills", latestCounts.counts, latestCounts.total);

    await statusPill(page, "warn").click();
    await page.locator("#eidscaSnapshot").selectOption("0");
    const older = await controlRows(page);
    expect(older.every((row) => row.status === "warn")).toBe(true);
    await statusPill(page, "warn").click();
    const olderAll = await controlRows(page);
    expect(tally(olderAll, "status")).not.toEqual(tally(latest, "status"));
    const olderCounts = await statusCountsWithGaps(page, olderAll);
    await expectPillCounts(page, "eidscaStatusPills", olderCounts.counts, olderCounts.total);

    // Compare shows its two dropdowns; the check filters and the collapse button belong to the Checks view.
    await page.locator('.eidsca-view-mode[data-view="compare"]').click();
    await expect(page.locator("#eidscaCompareA")).toBeVisible();
    await expect(page.locator("#eidscaCompareB")).toBeVisible();
    await expect(page.locator("#eidscaSnapshot")).toBeHidden();
    await expect(page.locator("#eidscaFacets")).toBeHidden();
    await expect(page.locator("#eidscaCollapseAll")).toBeHidden();
    await page.locator('.eidsca-view-mode[data-view="checks"]').click();
    await expect(page.locator("#eidscaFacets")).toBeVisible();
    expect(errors).toEqual([]);
});

test("the area navigation dot is failing, else unknown, else passing, else informational", async ({ page }) => {
    const errors = await openSnapshots(page, [filterProps]);
    // Without filters the navigation and the list show the same areas in the same order.
    const dots = await page.locator(".eidsca-navlink .eidsca-navdot").evaluateAll((items) => items.map((item) => item.classList[1]));
    const expected = await page.locator("#eidscaBody .eidsca-area").evaluateAll((areas) => areas.map((area) => {
        const has = (status) => !!area.querySelector(`.eidsca-stat-pill.${status}`);
        return has("warn") ? "warn" : has("unknown") ? "unknown" : has("ok") ? "ok" : "info";
    }));
    expect(dots).toEqual(expected);
    expect(errors).toEqual([]);
});
