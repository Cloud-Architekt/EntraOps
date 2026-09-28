(function () {
    "use strict";

    document.addEventListener("docs:rendered", function (event) {
        if (event.detail.page !== "service-em-landing-zone-visualization" || !window.mermaid) return;
        window.mermaid.initialize({
            startOnLoad: false,
            securityLevel: "strict",
            theme: document.documentElement.getAttribute("data-theme") === "dark" ? "dark" : "default"
        });
        window.mermaid.run({ querySelector: ".mermaid" });
    });
})();