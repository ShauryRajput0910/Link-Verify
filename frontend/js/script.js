async function verifyLink() {
    const input = document.getElementById("urlInput");
    const result = document.getElementById("quickResult");

    if (!input || !result) {
        console.error("Input or result element not found.");
        return;
    }

    const url = input.value.trim();

    if (url === "") {
        result.style.display = "block";
        result.style.color = "#ffb800";
        result.style.borderColor = "rgba(255,184,0,0.4)";
        result.style.background = "rgba(255,184,0,0.08)";
        result.innerHTML = "⚠ <strong>INPUT REQUIRED:</strong> Please enter or paste a URL to verify.";
        return;
    }

    // Show cyber analyzing message
    result.style.display = "block";
    result.style.color = "#00f0ff";
    result.style.borderColor = "rgba(0,240,255,0.4)";
    result.style.background = "rgba(0,240,255,0.08)";
    result.innerHTML = "⚡ <strong>CYBER RADAR ACTIVE:</strong> Deconstructing URL heuristics & querying PIB threat registry...";

    try {
        console.log("Sending URL to backend:", url);

        const apiUrl = window.location.origin.includes("localhost") || window.location.origin.includes("127.0.0.1")
            ? "/api/scan"
            : "/api/scan";

        const response = await fetch(apiUrl, {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({ url: url })
        });

        const data = await response.json();
        console.log("Backend response:", data);

        if (!response.ok) {
            throw new Error(data.message || "Scan failed");
        }

        // Save backend result
        localStorage.setItem("scanResult", JSON.stringify(data));

        const isBad = ["FAKE", "DANGEROUS", "MALICIOUS"].includes(data.verdict);
        const isSusp = ["SUSPICIOUS", "UNVERIFIED"].includes(data.verdict);

        let verdictColor = "#00ff9d";
        if (isBad) {
            verdictColor = "#ff3366";
        } else if (isSusp) {
            verdictColor = "#ffb800";
        }

        result.style.color = verdictColor;
        result.style.borderColor = isBad ? "rgba(255,51,102,0.4)" : (isSusp ? "rgba(255,184,0,0.4)" : "rgba(0,255,157,0.4)");
        result.style.background = isBad ? "rgba(255,51,102,0.08)" : (isSusp ? "rgba(255,184,0,0.08)" : "rgba(0,255,157,0.08)");

        let dymHTML = "";
        if (data.didYouMean) {
            dymHTML = `<div style="margin-top:6px; color:#00f0ff; font-size:13px;">💡 <strong>Did you mean:</strong> <span style="text-decoration:underline; font-weight:700;">${data.didYouMean}</span>?</div>`;
        }

        let fixHTML = "";
        if (data.autoFixed && data.fixMessages && data.fixMessages.length > 0) {
            fixHTML = `<div style="margin-top:4px; color:#94a3b8; font-size:11px;">⚡ Auto-fixed: ${data.fixMessages.join(" ")}</div>`;
        }

        result.innerHTML = `✓ <strong>ANALYSIS COMPLETE:</strong> Verdict: <span style="font-weight:800;letter-spacing:1px;color:${verdictColor}">${data.verdict}</span>.${dymHTML}${fixHTML}<div style="margin-top:6px;font-size:11px;color:#94a3b8;">Opening Security Analysis Console...</div>`;

        // Open analysis page after brief delay
        setTimeout(function () {
            window.location.href = "analysis.html";
        }, data.didYouMean ? 1400 : 850);

    } catch (error) {
        console.error("Backend Error:", error);

        result.style.color = "#ff3366";
        result.style.borderColor = "rgba(255,51,102,0.4)";
        result.style.background = "rgba(255,51,102,0.08)";
        result.innerHTML = "✕ <strong>BACKEND OFFLINE:</strong> Could not connect to http://localhost:5000/api/scan.";
    }
}

/* =========================================
   DOM LOAD EVENTS
========================================= */
window.addEventListener("DOMContentLoaded", function () {
    const input = document.getElementById("urlInput");
    if (input) {
        input.addEventListener("keydown", function (e) {
            if (e.key === "Enter") {
                verifyLink();
            }
        });
    }

    const analysisURL = document.getElementById("analysisURL");
    if (analysisURL) {
        const savedResult = localStorage.getItem("scanResult");
        if (savedResult) {
            try {
                const data = JSON.parse(savedResult);
                analysisURL.textContent = data.url || "Unknown URL";
            } catch (error) {
                console.error("Error reading scan result:", error);
            }
        }
    }
});
