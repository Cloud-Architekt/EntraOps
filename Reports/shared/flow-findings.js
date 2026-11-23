/*
 * Shared findings handling of the flow reports (PIM Request Flow, Access Package Flow).
 *
 * Risk flags and tiers are evaluated in PowerShell (New-EntraOpsReportFindingData) per snapshot. Without findings,
 * or with findings evaluated from other datasets than the page shows (for example after only one generator ran
 * again), a report shows no risk flags and tiers but one notice at the top of the page.
 *
 * The findings file (schemaVersion 2) holds per snapshot the risk flags of each flow (flags[flowId]) and, since the
 * finding exceptions are applied, the flags accepted by an exception (accepted[flowId], with state and expiry).
 * Its rules list (id, key, title, status) names the flags; older files without these properties still work.
 */
(function () {
    "use strict";

    var SCHEMA_VERSION = 2;
    var TIER_LABELS = { ControlPlane: "Control Plane", ManagementPlane: "Management Plane", WorkloadPlane: "Workload Plane", UserAccess: "User Access", Unclassified: "Unclassified" };
    var SOURCE_LABELS = { configurationAnalyzer: "Configuration Analyzer data", eam: "EAM Dashboard data", tierMap: "Classification Explorer tier map", accessPackage: "access package assignments" };
    var FINDINGS_VIEW = "../PrivilegedAssets/index.html?view=findings#rule=";

    function escapeHtml(value) {
        return String(value == null ? "" : value).replace(/[&<>"']/g, function (c) {
            return { "&": "&amp;", "<": "&lt;", ">": "&gt;", "\"": "&quot;", "'": "&#39;" }[c];
        });
    }

    // Display name of a tier ("ControlPlane" -> "Control Plane"); other values are returned as they are.
    function tierLabel(tier) {
        return tier && Object.prototype.hasOwnProperty.call(TIER_LABELS, tier) ? TIER_LABELS[tier] : (tier || "");
    }

    // Flag texts of older findings files name tiers as "ControlPlane": shown with their display names.
    function displayText(text) {
        return String(text == null ? "" : text).replace(/\b(ControlPlane|ManagementPlane|WorkloadPlane|UserAccess)\b/g, function (tier) { return TIER_LABELS[tier]; });
    }

    function formatTime(value) {
        if (!value) return "not recorded";
        var date = new Date(value);
        if (isNaN(date.getTime())) return String(value);
        return date.toISOString().slice(0, 16).replace("T", " ") + " UTC";
    }

    // findings: the findings file of the report; current: the generation times of the datasets the page shows,
    // by source key; subject: what the file evaluates, e.g. "risk flags and tiers".
    function create(findings, current, subject) {
        var sources = findings && findings.schemaVersion === SCHEMA_VERSION && findings.sources;
        var differing = sources ? Object.keys(current).filter(function (key) { return (sources[key] || null) !== (current[key] || null); }) : [];
        var matches = !!sources && !differing.length;
        var report = matches ? findings : null;
        var Subject = subject.charAt(0).toUpperCase() + subject.slice(1);

        // Rules of the findings file by key (the flag id) and by rule ID. The names apply even to stale findings.
        // Maps without prototype: a key like "constructor" is not a rule.
        var rulesByKey = Object.create(null), rulesById = Object.create(null);
        (findings && Array.isArray(findings.rules) ? findings.rules : []).forEach(function (rule) {
            if (!rule) return;
            if (rule.key) rulesByKey[rule.key] = rule;
            if (rule.id) rulesById[String(rule.id).toUpperCase()] = rule;
        });

        function forSnapshot(snapshotKey) {
            var snapshots = report && report.snapshots;
            return snapshots && Object.prototype.hasOwnProperty.call(snapshots, snapshotKey) ? snapshots[snapshotKey] : null;
        }

        // The rule of a flag (by its ruleId, else its id = rule key), or null for findings without rules.
        function ruleFor(flag) {
            if (!flag) return null;
            if (flag.ruleId && rulesById[String(flag.ruleId).toUpperCase()]) return rulesById[String(flag.ruleId).toUpperCase()];
            return rulesByKey[flag.id || flag.key] || null;
        }

        function ruleId(flag) {
            var rule = ruleFor(flag);
            return (flag && flag.ruleId) || (rule && rule.id) || "";
        }

        // Label of a flag kind for filters and group headers: "EO.3006 · Title", else the first sentence of the text.
        function flagLabel(flag) {
            var rule = ruleFor(flag);
            if (rule && rule.title) return (rule.id ? rule.id + " · " : "") + rule.title;
            var text = displayText(flag && flag.text);
            var sentence = /^(.+?\.)(\s|$)/.exec(text);
            return sentence ? sentence[1].replace(/\.$/, "") : text;
        }

        // Link to the check in the Privileged Assets Findings view (description, remediation, all results).
        function ruleLinkHtml(flag) {
            var id = ruleId(flag);
            return id ? '<a class="cell-link flow-rule-link" href="' + escapeHtml(FINDINGS_VIEW + encodeURIComponent(id)) + '" title="Description and remediation of the check">' + escapeHtml(id) + "</a>" : "";
        }

        // The line under a flag: the check (ID linked to the Findings view, and its title) and, for a flag accepted by
        // a finding exception, its state and expiry. Empty for findings files without rules and without exception.
        function ruleRefHtml(flag) {
            var rule = ruleFor(flag);
            var link = ruleLinkHtml(flag);
            var title = rule && rule.title ? '<span class="flow-rule-title">' + escapeHtml(rule.title) + "</span>" : "";
            var exception = flag && flag.state ? '<span class="flow-exception-state" title="' + escapeHtml(flag.justification || "") + '">' + escapeHtml(exceptionLabel(flag)) + "</span>" : "";
            // The exception expired since the evaluation: the flag is open again, and the saved results are outdated.
            var expired = flag && flag.expiredException ? '<span class="flow-exception-state flow-exception-expired" title="' + escapeHtml(flag.expiredException.justification || "") + '">' + escapeHtml(exceptionLabel(flag)) + "</span>" +
                '<span class="flow-exception-stale">Accepted at the last evaluation: run New-EntraOpsReportingData to evaluate the findings again.</span>' : "";
            return link || title || exception || expired ? '<div class="flow-rule-ref">' + link + title + exception + expired + "</div>" : "";
        }

        // Rules that are not evaluated (Findings.ExcludedRules or deprecated): their tiles say "excluded", not 0.
        function isExcluded(key) {
            var rule = rulesByKey[key];
            return !!rule && (rule.excluded === true || rule.status === "Excluded");
        }

        function excludedRules() {
            return Object.keys(rulesByKey).map(function (key) { return rulesByKey[key]; }).filter(function (rule) { return rule.excluded === true || rule.status === "Excluded"; });
        }

        function acceptedEntries(snapshotKey, flowId) {
            var snapshot = forSnapshot(snapshotKey);
            var accepted = (snapshot && snapshot.accepted) || (report && report.accepted) || null;
            var list = accepted && Object.prototype.hasOwnProperty.call(accepted, flowId) ? accepted[flowId] : null;
            return Array.isArray(list) ? list.filter(Boolean) : [];
        }

        // Flags of a flow that a finding exception accepted (risk accepted or dismissed): shown muted, not counted.
        // Without the ones whose exception has expired by today (expiredFor).
        function acceptedFor(snapshotKey, flowId) {
            return acceptedEntries(snapshotKey, flowId).filter(function (entry) { return !exceptionExpired(entry); });
        }

        // Flags accepted at the evaluation by an exception that has expired since then: open flags again (no state, so
        // they are counted and not muted), with the expired exception for the note under the flag.
        function expiredFor(snapshotKey, flowId) {
            return acceptedEntries(snapshotKey, flowId).filter(exceptionExpired).map(function (entry) {
                var flag = {};
                Object.keys(entry).forEach(function (name) { if (name !== "state" && name !== "expiresOn" && name !== "justification") flag[name] = entry[name]; });
                if (flag.severity !== "fail" && flag.severity !== "info") flag.severity = "warn";
                flag.expiredException = { state: entry.state, expiresOn: String(entry.expiresOn).slice(0, 10), justification: entry.justification || "" };
                return flag;
            });
        }

        function exceptionLabel(entry) {
            if (!entry) return "";
            if (entry.expiredException) return "Exception expired " + entry.expiredException.expiresOn;
            if (!entry.state) return "";
            if (entry.state === "Dismissed") return "Dismissed" + (entry.expiresOn ? " until " + String(entry.expiresOn).slice(0, 10) : "");
            return "Risk accepted" + (entry.expiresOn ? " until " + String(entry.expiresOn).slice(0, 10) : "");
        }

        // Why the risk flags and tiers of a snapshot are not shown, or null when they are.
        function notice(snap) {
            if (!findings) return Subject + " were not evaluated for this data. Run New-EntraOpsReportingData, or New-EntraOpsReportFindingData after generating the report data, to evaluate them.";
            if (findings.schemaVersion !== SCHEMA_VERSION) return "The " + subject + " were written by another EntraOps version. Run New-EntraOpsReportFindingData again to evaluate them for this report.";
            if (!report) {
                var details = differing.map(function (key) {
                    return (SOURCE_LABELS[key] || key) + " (evaluated: " + formatTime(sources[key]) + ", shown: " + formatTime(current[key]) + ")";
                }).join("; ");
                return "The " + subject + " were evaluated from other report data than this page shows" + (details ? ": " + details : "") + ". Run New-EntraOpsReportFindingData again to evaluate them for this data.";
            }
            if (snap && !forSnapshot(snap.commitSha + "|" + snap.commitDate)) return Subject + " were not evaluated for this snapshot. Run New-EntraOpsReportFindingData again to evaluate them.";
            return null;
        }

        // The page-level notice (element with data-risk-flag-notice): why the flags are not shown, and the rules
        // that are not evaluated (excluded), so a missing flag is not read as "no risk".
        function renderNotice(element, text) {
            if (!element) return;
            var excluded = excludedRules();
            var excludedText = excluded.length ? "Not evaluated (excluded in Findings.ExcludedRules or deprecated): " + excluded.map(function (rule) { return (rule.id ? rule.id + " " : "") + (rule.title || rule.key); }).join(", ") + "." : "";
            element.hidden = !text && !excludedText;
            if (text) {
                element.innerHTML = '<span class="ca-gap-icon warn" aria-hidden="true">!</span><div><div class="ca-gap-title">Risk flags not evaluated</div><div class="ca-gap-detail">' + escapeHtml(text) + "</div>" +
                    (excludedText ? '<div class="ca-gap-detail">' + escapeHtml(excludedText) + "</div>" : "") + "</div>";
            } else if (excludedText) {
                element.innerHTML = '<span class="ca-gap-icon info" aria-hidden="true">i</span><div><div class="ca-gap-title">Excluded checks</div><div class="ca-gap-detail">' + escapeHtml(excludedText) + "</div></div>";
            } else {
                element.innerHTML = "";
            }
        }

        // The row in the risk flag list that points to the page-level notice.
        function listPlaceholder() {
            return '<div class="ca-gap-row"><span class="ca-gap-icon warn" aria-hidden="true">!</span><div><div class="ca-gap-title">Risk flags not evaluated</div><div class="ca-gap-detail">See the notice at the top of the page.</div></div></div>';
        }

        return {
            report: report, forSnapshot: forSnapshot, notice: notice, renderNotice: renderNotice, listPlaceholder: listPlaceholder,
            ruleFor: ruleFor, ruleId: ruleId, flagLabel: flagLabel, ruleLinkHtml: ruleLinkHtml, ruleRefHtml: ruleRefHtml, isExcluded: isExcluded, excludedRules: excludedRules,
            acceptedFor: acceptedFor, expiredFor: expiredFor, exceptionLabel: exceptionLabel
        };
    }

    // Today as UTC calendar date (yyyy-MM-dd), like the evaluation in PowerShell ((Get-Date).ToUniversalTime().Date).
    function utcToday() {
        return new Date().toISOString().slice(0, 10);
    }

    // An accepted flag whose exception expired before today (UTC): the evaluation would report it again.
    function exceptionExpired(entry) {
        var expires = entry && entry.state && entry.expiresOn ? String(entry.expiresOn).slice(0, 10) : "";
        return /^\d{4}-\d{2}-\d{2}$/.test(expires) && expires < utcToday();
    }

    // Case-insensitive lookup of a flow by its ID (deep links may carry upper-case GUIDs).
    function sameId(a, b) {
        return String(a == null ? "" : a).toLowerCase() === String(b == null ? "" : b).toLowerCase();
    }

    window.EntraOpsFlowFindings = { SCHEMA_VERSION: SCHEMA_VERSION, create: create, tierLabel: tierLabel, displayText: displayText, sameId: sameId, utcToday: utcToday, exceptionExpired: exceptionExpired };
})();
