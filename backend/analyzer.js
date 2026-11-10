const { URL } = require("url");
const { cleanAndNormalizeURL, findDidYouMeanSuggestion } = require("./normalizer");

// ==========================================
// LINKVERIFY - URL ANALYSIS ENGINE
// ==========================================

// Domains reported as fake by official sources.
// Confirm each entry against its official source.
const knownFakeDomains = new Set([
    "viksitbharatrozgaryojana.org",
    "pmviksitbharatrozgaryojana.com"
]);

// Exact official domains manually verified for this project.
const knownOfficialDomains = new Set([
    "pmvbry.epfindia.gov.in",
    "pmvbry.labour.gov.in"
]);

// Official warning references.
const officialWarnings = {
    "viksitbharatrozgaryojana.org": {
        source: "Press Information Bureau (PIB), Government of India",
        reference:
            "https://www.pib.gov.in/Pressreleaseshare.aspx?PRID=2163332&lang=2&reg=48"
    }
};

// Match an exact domain or a subdomain.
function matchesDomain(hostname, domain) {
    return hostname === domain || hostname.endsWith("." + domain);
}

// Convert risk score into a display category.
function getRiskCategory(score) {
    if (score >= 80) return "Safe";
    if (score >= 60) return "Low Risk";
    if (score >= 40) return "Medium Risk";
    if (score >= 20) return "High Risk";
    return "Dangerous";
}

function analyzeURL(input) {
    const reasons = [];

    try {
        if (typeof input !== "string" || !input.trim()) {
            return {
                score: 0,
                verdict: "Invalid URL",
                reasons: ["Please enter a valid URL."]
            };
        }

        // 1. Smart Clean & Auto-Fix missing .com, typos, spaces, slashes
        const normalized = cleanAndNormalizeURL(input);
        const didYouMeanObj = normalized.didYouMean
            ? {
                suggestedURL: typeof normalized.didYouMean === "string" ? normalized.didYouMean : normalized.didYouMean.suggestedURL,
                suggestedDomain: (typeof normalized.didYouMean === "string" ? normalized.didYouMean : normalized.didYouMean.suggestedURL).replace(/^https?:\/\//, "")
              }
            : findDidYouMeanSuggestion(normalized.hostname, input);

        const parsedURL = new URL(normalized.cleanedURL);

        if (
            parsedURL.protocol !== "http:" &&
            parsedURL.protocol !== "https:"
        ) {
            return {
                score: 0,
                verdict: "Invalid URL",
                reasons: ["Only HTTP and HTTPS URLs are supported."]
            };
        }

        const hostname = parsedURL.hostname
            .toLowerCase()
            .replace(/\.$/, "");

        // Reject embedded credentials.
        if (parsedURL.username || parsedURL.password) {
            return {
                score: 0,
                verdict: "Suspicious",
                reasons: [
                    "The URL contains embedded username or password information."
                ]
            };
        }

        // Record any auto-fixes
        if (normalized.autoFixed && normalized.fixMessages.length > 0) {
            reasons.push("⚡ Auto-corrected: " + normalized.fixMessages.join(" "));
        }

        // Record "Did You Mean"
        if (didYouMeanObj) {
            reasons.push(`💡 Did you mean: ${didYouMeanObj.suggestedURL}?`);
        }

        // ==========================================
        // 1. KNOWN FAKE DOMAIN CHECK
        // ==========================================

        for (const domain of knownFakeDomains) {
            if (matchesDomain(hostname, domain)) {
                const warning = officialWarnings[domain];

                return {
                    score: 0,
                    verdict: "FAKE",
                    domain: hostname,
                    normalizedURL: normalized.cleanedURL,
                    originalInput: input,
                    autoFixed: normalized.autoFixed,
                    didYouMean: didYouMeanObj ? didYouMeanObj.suggestedURL : null,
                    didYouMeanDomain: didYouMeanObj ? didYouMeanObj.suggestedDomain : null,
                    reasons: [
                        "This domain matches LinkVerify's known-fake list.",
                        warning
                            ? "An official PIB warning is associated with this domain."
                            : "This domain is listed for manual review.",
                        ...reasons
                    ],
                    officialSource: warning ? warning.source : null,
                    sourceURL: warning ? warning.reference : null
                };
            }
        }

        // ==========================================
        // 2. VERIFIED OFFICIAL DOMAIN CHECK
        // ==========================================

        for (const domain of knownOfficialDomains) {
            if (matchesDomain(hostname, domain)) {
                return {
                    score: 100,
                    verdict: "VERIFIED OFFICIAL",
                    domain: hostname,
                    normalizedURL: normalized.cleanedURL,
                    originalInput: input,
                    autoFixed: normalized.autoFixed,
                    didYouMean: didYouMeanObj ? didYouMeanObj.suggestedURL : null,
                    didYouMeanDomain: didYouMeanObj ? didYouMeanObj.suggestedDomain : null,
                    reasons: [
                        "The domain matches LinkVerify's manually approved official-domain list.",
                        "This is a local allowlist match, not a live government database check.",
                        ...reasons
                    ]
                };
            }
        }

        // ==========================================
        // 3. UNKNOWN WEBSITE RISK SCORING
        // ==========================================

        let score = 100;

        if (parsedURL.protocol !== "https:") {
            score -= 20;
            reasons.push("HTTPS is not enabled.");
        }

        // Typosquatting penalty if user typed an impostor domain (e.g. amazn.com)
        if (didYouMeanObj && hostname !== didYouMeanObj.suggestedDomain) {
            score -= 30;
            reasons.push(
                `⚠ Potential Typosquatting / Impersonation Risk: This domain mimics ${didYouMeanObj.suggestedDomain}. Verify you are visiting the authentic portal.`
            );
        }

        const suspiciousWords = [
            "login",
            "verify",
            "password",
            "claim",
            "winner",
            "free",
            "reward",
            "prize"
        ];

        const searchableURL =
            (hostname + parsedURL.pathname).toLowerCase();

        const matchedWords = suspiciousWords.filter(word =>
            searchableURL.includes(word)
        );

        if (matchedWords.length > 0) {
            score -= Math.min(matchedWords.length * 5, 20);
            reasons.push(
                "Potentially suspicious keywords: " +
                matchedWords.join(", ")
            );
        }

        if (hostname.split(".").length > 4) {
            score -= 10;
            reasons.push("The hostname contains many subdomains.");
        }

        const isIPv4 =
            /^\d{1,3}(?:\.\d{1,3}){3}$/.test(hostname);

        if (isIPv4) {
            score -= 25;
            reasons.push("The URL uses an IP address instead of a domain.");
        }

        if (input.length > 100) {
            score -= 10;
            reasons.push("The URL is unusually long.");
        }

        if (input.includes("@")) {
            score -= 20;
            reasons.push("The URL contains an @ symbol.");
        }

        score = Math.max(0, Math.min(score, 100));

        let verdict = "UNVERIFIED";
        if (score <= 40) {
            verdict = "SUSPICIOUS";
        }

        return {
            score: score,
            verdict: verdict,
            riskCategory: getRiskCategory(score),
            domain: hostname,
            normalizedURL: normalized.cleanedURL,
            originalInput: input,
            autoFixed: normalized.autoFixed,
            fixMessages: normalized.fixMessages,
            didYouMean: didYouMeanObj ? didYouMeanObj.suggestedURL : null,
            didYouMeanDomain: didYouMeanObj ? didYouMeanObj.suggestedDomain : null,
            reasons: [
                ...reasons,
                "The website has not been independently verified.",
                "A high score does not prove that a website is safe."
            ]
        };

    } catch (error) {
        return {
            score: 0,
            verdict: "Invalid URL",
            reasons: ["Please enter a valid URL."]
        };
    }
}

module.exports = analyzeURL;
