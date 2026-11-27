// Evaluates the Privileged Assets findings of a report data file with the report's own rules
// (Reports/PrivilegedAssets/js/findings.js) and prints them as JSON: { "<objectId>": ["<key>", ...] }.
// Used by PrivilegedAssetsFindingParity.Tests.ps1 to compare the report rules with the PowerShell rules.
// Usage: node Get-PrivilegedAssetsReportFinding.cjs <privileged-assets-data.js> [<tier-overrides.json>] [--applies]
// The optional tier overrides ({ "<objectId>": "<tierName>" }) are applied like the worklist in the What-if view.
// With --applies, it prints the number of objects each rule evaluates instead: { "<key>": <count> } (rules.applies).
"use strict";
const fs = require("node:fs");
const path = require("node:path");
const rules = require(path.join(__dirname, "../../Reports/PrivilegedAssets/js/findings.js"));

const args = process.argv.slice(2);
const countApplies = args.includes("--applies");
const files = args.filter((arg) => arg !== "--applies");
const overrides = files[1] ? JSON.parse(fs.readFileSync(files[1], "utf8")) : {};
const content = fs.readFileSync(files[0], "utf8");
const data = JSON.parse(content.slice(content.indexOf("=") + 1, content.lastIndexOf(";")));
const objectsById = {};
data.objects.forEach((object) => {
    object.objectId = String(object.objectId).toLowerCase();
    object.assignmentSummary = object.assignmentSummary || { highestTierName: "Unclassified" };
    objectsById[object.objectId] = object;
});
const env = { objectsById, related: data.relatedObjects || {}, tierOverride: (id) => overrides[id] || null };
const result = {};
if (countApplies) {
    rules.RULES.forEach((rule) => { result[rule.key] = data.objects.filter((object) => rules.applies(rule.key, object, env)).length; });
    process.stdout.write(JSON.stringify(result));
    process.exit(0);
}
data.objects.forEach((object) => {
    const found = rules.compute(object, env);
    if (found.length) result[object.objectId] = found;
});
process.stdout.write(JSON.stringify(result));
