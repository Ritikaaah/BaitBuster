// Backend API address
const API_URL = "http://127.0.0.1:8000/analyze";


// Get HTML elements
const websiteName = document.getElementById("website-name");
const websiteUrl = document.getElementById("website-url");

const scanButton = document.getElementById("scan-button");

const resultSection = document.getElementById("result-section");
const riskBadge = document.getElementById("risk-badge");
const riskScore = document.getElementById("risk-score");
const riskDescription = document.getElementById("risk-description");

const scoreFill = document.getElementById("score-fill");
const findingsList = document.getElementById("findings-list");

const errorMessage = document.getElementById("error-message");


// Store the currently active website URL
let currentUrl = "";

// GET THE CURRENT CHROME TAB
function loadCurrentWebsite() {

    chrome.tabs.query(
        { active: true, currentWindow: true },
        function (tabs) {

            const tab = tabs[0];

            if (!tab || !tab.url) {
                websiteName.textContent = "Website unavailable";
                websiteUrl.textContent = "Open a regular website";
                scanButton.disabled = true;
                return;
            }

            currentUrl = tab.url;

            try {
                const parsedUrl = new URL(currentUrl);

                if (!["http:", "https:"].includes(parsedUrl.protocol)) {
                    throw new Error("Unsupported website");
                }

                websiteName.textContent = parsedUrl.hostname;
                websiteUrl.textContent = currentUrl;

            } catch (error) {

                websiteName.textContent = "Unsupported page";
                websiteUrl.textContent =
                    "Open a website using HTTP or HTTPS";

                scanButton.disabled = true;
            }
        }
    );
}

// DISPLAY AN ERROR MESSAGE
function showError(message) {

    errorMessage.textContent = message;

    errorMessage.classList.remove("hidden");

    resultSection.classList.add("hidden");
}

// ANALYZE THE WEBSITE
async function analyzeWebsite() {

    if (!currentUrl) {
        showError("No valid website URL is available.");
        return;
    }

    // Hide previous results and errors
    resultSection.classList.add("hidden");
    errorMessage.classList.add("hidden");

    // Show loading state
    scanButton.disabled = true;
    scanButton.querySelector("span:first-child").textContent =
        "Analysing website...";

    try {

        // Send URL to our FastAPI backend
        const response = await fetch(API_URL, {

            method: "POST",

            headers: {
                "Content-Type": "application/json"
            },

            body: JSON.stringify({
                url: currentUrl
            })
        });


        // Convert JSON response into a JavaScript object
        const data = await response.json();


        // Handle unsuccessful responses
        if (!response.ok) {

            throw new Error(
                data.detail || "Unable to analyse this website."
            );
        }


        // Display the analysis
        displayResults(data);

    } catch (error) {

        showError(
            error.message.includes("Failed to fetch")
                ? "Cannot connect to BaitBuster. Make sure the backend server is running."
                : error.message
        );

    } finally {

        // Restore the scan button
        scanButton.disabled = false;

        scanButton.querySelector("span:first-child").textContent =
            "Analyse this website";
    }
}

//DISPLAY THE RESULTS
function displayResults(data) {

    const risk = data.risk;

    const score = risk.score;
    const category = risk.category.toLowerCase();


    // Display risk score
    riskScore.textContent = String(score).padStart(2, "0");

    // Display risk category
    riskBadge.textContent = category.toUpperCase();

    riskBadge.className = "risk-badge " + category;


    // Display an appropriate explanation
    if (category === "high") {

        riskDescription.textContent =
            "Multiple concerning indicators detected.";

    } else if (category === "medium") {

        riskDescription.textContent =
            "Some indicators deserve closer attention.";

    } else {

        riskDescription.textContent =
            "Few suspicious indicators detected.";
    }


    // Update score bar
    scoreFill.style.width = score + "%";

    scoreFill.className = "score-fill " + category;


    // Display suspicious findings
    displayFindings(data.findings);


    // Show the result section
    resultSection.classList.remove("hidden");
}

// DISPLAY SUSPICIOUS FINDINGS
function displayFindings(findings) {

    // Clear previous findings
    findingsList.replaceChildren();


    // Handle URLs with no suspicious findings
    if (findings.length === 0) {

        const message = document.createElement("p");

        message.className = "finding-message";

        message.textContent =
            "No suspicious indicators were detected by our current checks.";

        findingsList.appendChild(message);

        return;
    }


    // Display every finding
    findings.forEach(function (finding) {

        const item = document.createElement("div");

        item.className = "finding-item";


        const name = document.createElement("p");

        name.className = "finding-name";

        name.textContent = finding.rule;


        const description = document.createElement("p");

        description.className = "finding-message";

        description.textContent = finding.message;


        const severity = document.createElement("span");

        severity.className = "finding-severity";

        severity.textContent =
            "SEVERITY: " + finding.severity.toUpperCase();


        item.appendChild(name);

        item.appendChild(description);

        item.appendChild(severity);


        findingsList.appendChild(item);
    });
}

// Button event to trigger website analysis
scanButton.addEventListener("click", analyzeWebsite);

// Initialize the popup:
loadCurrentWebsite();