// EntraOps Docs - minimal, dependency-free Markdown -> HTML renderer.
//
// Scope is intentionally limited to what the EntraOps Docs content actually
// uses (see Docs/content/*.md and the repository root CHANGELOG.md):
// headings (# .. ######, optional explicit `{#id}`), paragraphs, bold/italic/
// inline code/links/images, fenced code blocks, blockquotes (incl. GitHub-style
// `> [!NOTE]` / `[!TIP]` / `[!IMPORTANT]` / `[!WARNING]` / `[!CAUTION]` alerts),
// unordered/ordered lists (with simple one-level-deeper nesting), GFM pipe
// tables, and horizontal rules. It is not a full CommonMark implementation.
//
// All documentation content is authored/maintained as Markdown in
// Docs/content/*.md (and the repository root CHANGELOG.md for the Changelog
// page). Docs/Update-EntraOpsDocsContent.ps1 embeds that Markdown as a plain
// JS string bundle (Docs/data/content.js, window.EODOCS_CONTENT) so every Docs
// page keeps working fully offline from file:// with no fetch()/build step at
// view time - only DocsMD.render() (this file) turns it into HTML in the
// browser. Re-run that script after editing any Markdown source file.
var DocsMD = (function () {
    "use strict";

    var slugCounts;

    // Quotes must be escaped as well: every esc() result below is interpolated into a
    // double-quoted HTML attribute (href/src/alt/class), where an unescaped " or ' breaks
    // out of the attribute and allows injecting event handlers (e.g. onmouseover=).
    function esc(s) {
        return String(s == null ? "" : s)
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#39;");
    }

    // Scheme allowlist rather than a URL/domain allowlist: checked against the RAW string's own
    // explicit scheme prefix (if any), not a browser-resolved URL - resolving a relative link
    // against document.baseURI would report protocol "file:" when these self-contained pages are
    // opened straight from disk (a core, documented use case), which isn't in the allowlist and
    // would wrongly break every #anchor and ../page.html link. A relative reference (no scheme
    // prefix in the original text) never carries an attacker-choosable scheme, so it's inherently
    // safe to pass through unchanged regardless of what it resolves against.
    var SAFE_URL_SCHEMES = { "http:": true, "https:": true, "mailto:": true };

    function safeUrl(url) {
        var raw = String(url == null ? "" : url);
        // Browsers ignore leading/embedded whitespace and C0 controls when resolving a scheme, so strip
        // them before testing - otherwise "java\tscript:alert(1)" would pass a naive scheme check.
        var probe = raw.replace(/[\u0000-\u0020]/g, "");
        var scheme = /^([a-z][a-z0-9+.\-]*):/i.exec(probe);
        if (!scheme) return raw;
        return SAFE_URL_SCHEMES[scheme[1].toLowerCase() + ":"] ? raw : "#";
    }

    function decodeEntities(s) {
        var named = {
            amp: "&",
            apos: "'",
            copy: "\u00a9",
            gt: ">",
            hellip: "\u2026",
            lt: "<",
            mdash: "\u2014",
            nbsp: " ",
            ndash: "\u2013",
            quot: '"',
            rarr: "\u2192",
            larr: "\u2190",
            reg: "\u00ae",
            trade: "\u2122"
        };
        return String(s == null ? "" : s).replace(/&(?:#(x[0-9a-f]+|\d+)|([a-z]+));/gi, function (match, numeric, name) {
            if (numeric) {
                var value = numeric.charAt(0).toLowerCase() === "x" ? parseInt(numeric.slice(1), 16) : parseInt(numeric, 10);
                return isNaN(value) || value < 0 || value > 0x10ffff ? match : String.fromCodePoint(value);
            }
            return Object.prototype.hasOwnProperty.call(named, name.toLowerCase()) ? named[name.toLowerCase()] : match;
        });
    }

    function slugify(text) {
        var s = text
            .toLowerCase()
            .replace(/[`*_~]/g, "")
            .replace(/[^\w\- ]+/g, "")
            .trim()
            .replace(/\s+/g, "-");
        if (!s) s = "section";
        var n = slugCounts[s] || 0;
        slugCounts[s] = n + 1;
        return n === 0 ? s : s + "-" + n;
    }

    function renderInline(raw) {
        var codes = [];
        var text = raw.replace(/`([^`]+)`/g, function (m, code) {
            codes.push(esc(code));
            return "\u0000C" + (codes.length - 1) + "\u0000";
        });
        text = esc(decodeEntities(text));
        text = text.replace(/!\[([^\]]*)\]\(([^)]+)\)/g, function (m, alt, url) {
            var safe = esc(safeUrl(url));
            return '<a class="docs-image-zoom" href="' + safe + '" target="_blank" rel="noopener" aria-label="Open image at full size"><img alt="' + esc(alt) + '" src="' + safe + '"></a>';
        });
        text = text.replace(/\[([^\]]+)\]\(([^)]+)\)/g, function (m, label, url) {
            var external = /^https?:\/\//.test(url);
            return '<a href="' + esc(safeUrl(url)) + '"' + (external ? ' target="_blank" rel="noopener noreferrer"' : "") + ">" + label + "</a>";
        });
        text = text.replace(/\*\*\*([^*]+)\*\*\*/g, "<strong><em>$1</em></strong>");
        text = text.replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>");
        text = text.replace(/__([^_]+)__/g, "<strong>$1</strong>");
        text = text.replace(/\*([^*]+)\*/g, "<em>$1</em>");
        text = text.replace(/(^|[^\w])_([^_]+)_(?!\w)/g, "$1<em>$2</em>");
        text = text.replace(/\u0000C(\d+)\u0000/g, function (m, i) {
            return "<code>" + codes[+i] + "</code>";
        });
        return text;
    }

    function isBlockStart(line) {
        return (
            /^\s*$/.test(line) ||
            /^\s{0,3}#{1,6}\s+/.test(line) ||
            /^\s*(```+|~~~+)/.test(line) ||
            /^\s*>/.test(line) ||
            /^\s*([-*_])\s*(\1\s*){2,}$/.test(line) ||
            /^(\s*)(?:[-*+]|\d+\.)\s+/.test(line) ||
            /^\s*\|/.test(line)
        );
    }

    function splitRow(line) {
        var t = line.trim().replace(/^\|/, "").replace(/\|$/, "");
        return t.split("|").map(function (c) { return c.trim(); });
    }

    function parseList(lines, start, baseIndent) {
        var i = start;
        var ordered = /^\s*\d+\./.test(lines[i]);
        var orderedStart = ordered ? parseInt(lines[i].match(/^\s*(\d+)\./)[1], 10) : 1;
        var items = [];
        while (i < lines.length) {
            var m = lines[i].match(/^(\s*)(?:[-*+]|\d+\.)\s+(.*)$/);
            if (!m || m[1].length !== baseIndent) break;
            var text = m[2];
            i++;
            var nestedLines = [];
            while (i < lines.length) {
                var m2 = lines[i].match(/^(\s*)(?:[-*+]|\d+\.)\s+(.*)$/);
                if (m2 && m2[1].length > baseIndent) {
                    nestedLines.push(lines[i]);
                    i++;
                } else break;
            }
            var sub = "";
            if (nestedLines.length) {
                var nestedIndent = nestedLines[0].match(/^(\s*)/)[1].length;
                sub = parseList(nestedLines, 0, nestedIndent).html;
            }
            items.push("<li>" + renderInline(text) + sub + "</li>");
        }
        var tag = ordered ? "ol" : "ul";
        var startAttribute = ordered && orderedStart !== 1 ? ' start="' + orderedStart + '"' : "";
        return { html: "<" + tag + startAttribute + ">" + items.join("") + "</" + tag + ">\n", next: i };
    }

    function parseBlocks(lines) {
        var html = "";
        var i = 0;
        while (i < lines.length) {
            var line = lines[i];
            if (/^\s*$/.test(line)) { i++; continue; }

            var fence = line.match(/^(\s*)(```+|~~~+)(.*)$/);
            if (fence) {
                var fenceChar = fence[2][0], fenceLen = fence[2].length;
                var lang = fence[3].trim();
                var closeRe = new RegExp("^\\s*" + (fenceChar === "`" ? "`" : "~") + "{" + fenceLen + ",}\\s*$");
                var body = [];
                i++;
                while (i < lines.length && !closeRe.test(lines[i])) { body.push(lines[i]); i++; }
                i++;
                if (lang.toLowerCase() === "mermaid") {
                    html += '<div class="mermaid">' + esc(body.join("\n")).replace(/\\n/g, "<br>") + "</div>\n";
                    continue;
                }
                html += "<pre><code" + (lang ? ' class="language-' + esc(lang) + '"' : "") + ">" + esc(body.join("\n")) + "</code></pre>\n";
                continue;
            }

            var h = line.match(/^(#{1,6})\s+(.+?)\s*#*$/);
            if (h) {
                var level = h[1].length;
                var text = h[2];
                var customId = text.match(/\{#([a-zA-Z0-9\-_]+)\}\s*$/);
                var id;
                if (customId) {
                    text = text.slice(0, customId.index).trim();
                    id = customId[1];
                    slugCounts[id] = (slugCounts[id] || 0) + 1;
                } else {
                    id = slugify(text);
                }
                html += '<h' + level + ' id="' + esc(id) + '">' + renderInline(text) + "</h" + level + ">\n";
                i++;
                continue;
            }

            if (/^\s*([-*_])\s*(\1\s*){2,}$/.test(line)) { html += "<hr>\n"; i++; continue; }

            if (/^\s*>/.test(line)) {
                var qLines = [];
                while (i < lines.length && /^\s*>/.test(lines[i])) {
                    qLines.push(lines[i].replace(/^\s*>\s?/, ""));
                    i++;
                }
                var alertMatch = qLines[0] && qLines[0].match(/^\[!(NOTE|TIP|IMPORTANT|WARNING|CAUTION)\]\s*$/i);
                if (alertMatch) {
                    var kind = alertMatch[1].toUpperCase();
                    var cls = kind === "TIP" ? "tip" : kind === "WARNING" || kind === "CAUTION" ? "warning" : kind === "IMPORTANT" ? "important" : "";
                    html += '<div class="callout' + (cls ? " " + cls : "") + '">' + parseBlocks(qLines.slice(1)) + "</div>\n";
                } else {
                    html += "<blockquote>" + parseBlocks(qLines) + "</blockquote>\n";
                }
                continue;
            }

            if (/^\s*\|/.test(line) && lines[i + 1] && /^\s*\|?\s*:?-{2,}:?\s*(\|\s*:?-{2,}:?\s*)+\|?\s*$/.test(lines[i + 1])) {
                var headerCells = splitRow(line);
                var aligns = splitRow(lines[i + 1]).map(function (c) {
                    var l = /^:/.test(c), r = /:$/.test(c);
                    return l && r ? "center" : r ? "right" : l ? "left" : "";
                });
                i += 2;
                var rows = [];
                while (i < lines.length && /\|/.test(lines[i]) && !/^\s*$/.test(lines[i])) { rows.push(splitRow(lines[i])); i++; }
                html += "<table><thead><tr>" + headerCells.map(function (c, ix) {
                    return "<th" + (aligns[ix] ? ' style="text-align:' + aligns[ix] + '"' : "") + ">" + renderInline(c) + "</th>";
                }).join("") + "</tr></thead><tbody>" + rows.map(function (r) {
                    return "<tr>" + r.map(function (c, ix) {
                        return "<td" + (aligns[ix] ? ' style="text-align:' + aligns[ix] + '"' : "") + ">" + renderInline(c) + "</td>";
                    }).join("") + "</tr>";
                }).join("") + "</tbody></table>\n";
                continue;
            }

            var listM = line.match(/^(\s*)(?:[-*+]|\d+\.)\s+/);
            if (listM) {
                var r = parseList(lines, i, listM[1].length);
                html += r.html;
                i = r.next;
                continue;
            }

            var paraLines = [];
            while (i < lines.length && !isBlockStart(lines[i])) {
                paraLines.push(lines[i].trim());
                i++;
            }
            if (paraLines.length) {
                html += "<p>" + renderInline(paraLines.join(" ")) + "</p>\n";
                continue;
            }
            i++;
        }
        return html;
    }

    return {
        render: function (markdown) {
            slugCounts = Object.create(null);
            var lines = String(markdown || "").replace(/\r\n/g, "\n").split("\n");
            return parseBlocks(lines);
        }
    };
})();
