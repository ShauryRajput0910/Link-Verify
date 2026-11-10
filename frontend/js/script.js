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
        result.style.color = "#ffb84d";
        result.style.borderColor = "rgba(255,184,77,0.3)";

        result.innerHTML =
            "⚠ Please enter a URL before verification.";

        return;
    }


    // Show analyzing message

    result.style.display = "block";
    result.style.color = "#37ff9b";
    result.style.borderColor = "rgba(55,255,155,0.25)";

    result.innerHTML =
        "◌ Analyzing URL...";


    try {

        console.log("Sending URL to backend:", url);


        const response = await fetch(
            "http://localhost:5000/api/scan",
            {
                method: "POST",

                headers: {
                    "Content-Type": "application/json"
                },

                body: JSON.stringify({
                    url: url
                })
            }
        );


        const data = await response.json();

        console.log("Backend response:", data);


        if (!response.ok) {

            throw new Error(
                data.message || "Scan failed"
            );

        }


        // Save backend result

        localStorage.setItem(
            "scanResult",
            JSON.stringify(data)
        );


        result.style.color = "#37ff9b";
        result.style.borderColor =
            "rgba(55,255,155,0.25)";

        result.innerHTML =
            "✓ Analysis completed. Opening security analysis...";


        // Open analysis page

        setTimeout(function () {

            window.location.href = "analysis.html";

        }, 700);


    } catch (error) {

        console.error(
            "Backend Error:",
            error
        );


        result.style.color = "#ff6b6b";

        result.style.borderColor =
            "rgba(255,107,107,0.3)";

        result.innerHTML =
            "✕ Backend connection failed. Make sure the server is running.";

    }

}


/* =========================================
   LOAD RESULT ON ANALYSIS PAGE
========================================= */

window.addEventListener(
    "DOMContentLoaded",
    function () {

        const analysisURL =
            document.getElementById("analysisURL");


        if (analysisURL) {

            const savedResult =
                localStorage.getItem("scanResult");


            if (savedResult) {

                try {

                    const data =
                        JSON.parse(savedResult);


                    analysisURL.textContent =
                        data.url || "Unknown URL";

                } catch (error) {

                    console.error(
                        "Error reading scan result:",
                        error
                    );

                }

            }

        }

    }
);