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

        result.style.color = "#00ff9d";
        result.style.borderColor = "rgba(0,255,157,0.4)";
        result.style.background = "rgba(0,255,157,0.08)";
        result.innerHTML = `✓ <strong>ANALYSIS VERIFIED:</strong> Verdict: <span style="font-weight:800;letter-spacing:1px;color:${data.verdict === 'FAKE' ? '#ff3366' : '#00ff9d'}">${data.verdict}</span>. Launching 3D Security Console...`;

        // Open analysis page after brief cyber delay
        setTimeout(function () {
            window.location.href = "analysis.html";
        }, 850);

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
