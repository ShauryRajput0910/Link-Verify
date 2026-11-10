const { URL } = require("url");
const { cleanAndNormalizeURL, findDidYouMeanSuggestion } = require("./normalizer");
const { predict } = require("./ml_model");
const { checkURLThreat } = require("./threat_api");

// ==========================================
// LINKVERIFY - UNIFIED MULTI-LAYER URL ANALYZER
// Layers: 1. Lexical & Typo Radar
//         2. Trained Supervised ML Model
//         3. Threat Intelligence API & Live DNS
// ==========================================

// Domains reported as fake by official sources.
const knownFakeDomains = new Set([
    "viksitbharatrozgaryojana.org",
    "pmviksitbharatrozgaryojana.com"
]);

// Exact official domains manually verified for this project.
const knownOfficialDomains = new Set([
    "pmvbry.epfindia.gov.in",
    "pmvbry.labour.gov.in",
    "epfindia.gov.in",
    "labour.gov.in",
    "india.gov.in",
    "pib.gov.in"
]);

// Official warning references.
const officialWarnings = {
    "viksitbharatrozgaryojana.org": {
        source: "Press Information Bureau (PIB), Government of India",
        reference:
            "https://www.pib.gov.in/Pressreleaseshare.aspx?PRID=2163332&lang=2&reg=48"
    },
    "pmviksitbharatrozgaryojana.com": {
        source: "Cyber Crime Coordination Centre (I4C), MHA",
        reference: "https://cybercrime.gov.in"
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

/**
 * Multi-layer async URL analysis
 * Combines Lexical Normalizer, ML Neural Classifier, and Threat Intelligence APIs
 */
async function analyzeURL(input) {
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
        // 2. RUN ML CLASSIFIER & THREAT INTELLIGENCE
        // ==========================================
        const mlAnalysis = predict(normalized.cleanedURL);
        const threatIntel = await checkURLThreat(normalized.cleanedURL);

        // ==========================================
        // 3. KNOWN FAKE DOMAIN / THREAT API HIT
        // ==========================================
        let matchedFake = null;
        for (const domain of knownFakeDomains) {
            if (matchesDomain(hostname, domain)) {
                matchedFake = domain;
                break;
            }
        }

        if (matchedFake || threatIntel.isMalicious) {
            const warning = matchedFake ? officialWarnings[matchedFake] : null;
            const officialSource = threatIntel.agency || (warning ? warning.source : "Government Cybersecurity Registry");
            const sourceURL = threatIntel.bulletin || (warning ? warning.reference : null);

            return {
                score: 0,
                verdict: "FAKE",
                domain: hostname,
                normalizedURL: normalized.cleanedURL,
                originalInput: input,
                autoFixed: normalized.autoFixed,
                fixMessages: normalized.fixMessages,
                didYouMean: didYouMeanObj ? didYouMeanObj.suggestedURL : null,
                didYouMeanDomain: didYouMeanObj ? didYouMeanObj.suggestedDomain : null,
                reasons: [
                    "🚨 Alert: Flagged by Threat Intelligence & Official Cybersecurity Registry.",
                    threatIntel.details || "This domain is officially confirmed as a fake website.",
                    ...reasons
                ],
                officialSource: officialSource,
                sourceURL: sourceURL,
                mlAnalysis: mlAnalysis,
                threatIntelligence: threatIntel
            };
        }

        // ==========================================
        // 4. VERIFIED OFFICIAL DOMAIN CHECK
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
                    fixMessages: normalized.fixMessages,
                    didYouMean: didYouMeanObj ? didYouMeanObj.suggestedURL : null,
                    didYouMeanDomain: didYouMeanObj ? didYouMeanObj.suggestedDomain : null,
                    reasons: [
                        "✓ Verified authentic official government/institutional domain.",
                        "Direct match with verified whitelist and authoritative registry.",
                        ...reasons
                    ],
                    officialSource: "Government of India Official Domain Whitelist",
                    sourceURL: "https://www.india.gov.in",
                    mlAnalysis: mlAnalysis,
                    threatIntelligence: threatIntel
                };
            }
        }

        // ==========================================
        // 5. COMPOSITE HEURISTIC & ML SCORING
        // ==========================================
        let heuristicScore = 100;
        let isCriticalPhishing = false;

        // Protocol Check: Only grant full HTTPS safety points if original input explicitly used https
        if (parsedURL.protocol !== "https:") {
            heuristicScore -= 20;
            reasons.push("HTTPS is not enabled (missing TLS cryptographic encryption).");
        } else if (!normalized.originalHadHttps) {
            heuristicScore -= 20;
            reasons.push("HTTPS was missing in the original input (auto-filled for scanning purposes only).");
        }

        // Defanged / Quarantine notation
        if (normalized.isDefanged) {
            heuristicScore -= 35;
            reasons.push(
                "🚨 Quarantined / Defanged Syntax: Link contains '[.]' or 'hxxps' notation commonly used to distribute or report malware/phishing."
            );
        }

        // Deceptive protocol hostname (e.g. hxxps.com, https-login.com)
        if (/^(hxxps?|https?-|http-|ssl-|secure-login-|web-login-)/i.test(hostname)) {
            heuristicScore -= 40;
            reasons.push(
                `🚨 Deceptive Hostname: Domain '${hostname}' mimics a security/protocol prefix to mislead users into believing it is a secure connection.`
            );
        }

        // Protected Brands List for Phishing & Fragment Deception Detection
        const PROTECTED_BRANDS = [
            { brand: "whatsapp", officialDomain: "whatsapp.com" },
            { brand: "google", officialDomain: "google.com" },
            { brand: "facebook", officialDomain: "facebook.com" },
            { brand: "instagram", officialDomain: "instagram.com" },
            { brand: "apple", officialDomain: "apple.com" },
            { brand: "microsoft", officialDomain: "microsoft.com" },
            { brand: "netflix", officialDomain: "netflix.com" },
            { brand: "paypal", officialDomain: "paypal.com" },
            { brand: "amazon", officialDomain: "amazon.com" },
            { brand: "sbi", officialDomain: "onlinesbi.sbi" },
            { brand: "hdfc", officialDomain: "hdfcbank.com" },
            { brand: "icici", officialDomain: "icicibank.com" },
            { brand: "paytm", officialDomain: "paytm.com" },
            { brand: "phonepe", officialDomain: "phonepe.com" },
            { brand: "telegram", officialDomain: "telegram.org" }
        ];

        // Critical URL Fragment (#) Deception / Anchor Spoofing
        if (parsedURL.hash) {
            const rawHash = parsedURL.hash.toLowerCase();
            for (const pb of PROTECTED_BRANDS) {
                if (rawHash.includes(pb.brand)) {
                    if (!matchesDomain(hostname, pb.officialDomain)) {
                        heuristicScore -= 80;
                        isCriticalPhishing = true;
                        reasons.push(
                            `🚨 URL Fragment Deception Attack: Link embeds '${pb.brand}' in the anchor hash ('${parsedURL.hash}'), but destination host is '${hostname}'. The browser will NOT load ${pb.officialDomain}!`
                        );
                        break;
                    }
                }
            }
        }

        // Brand Lure in Path or Search Query
        const fullPathAndSearch = (parsedURL.pathname + parsedURL.search).toLowerCase();
        for (const pb of PROTECTED_BRANDS) {
            if (fullPathAndSearch.includes(pb.brand)) {
                if (!matchesDomain(hostname, pb.officialDomain)) {
                    heuristicScore -= 45;
                    reasons.push(
                        `⚠ Deceptive Path / Brand Lure: The URL path includes '${pb.brand}', but destination domain '${hostname}' is NOT affiliated with ${pb.officialDomain}.`
                    );
                    break;
                }
            }
        }

        // Typosquatting penalty if user typed an impostor domain (e.g. amazn.com)
        if (didYouMeanObj && hostname !== didYouMeanObj.suggestedDomain) {
            heuristicScore -= 30;
            reasons.push(
                `⚠ Potential Typosquatting / Impersonation Risk: This domain mimics authentic brand '${didYouMeanObj.suggestedDomain}'.`
            );
        }

        const suspiciousWords = [
            "login", "verify", "password", "claim", "winner",
            "free", "reward", "prize", "wallet", "bonus"
        ];

        const searchableURL = (hostname + parsedURL.pathname + parsedURL.hash).toLowerCase();
        const matchedWords = suspiciousWords.filter(word =>
            searchableURL.includes(word)
        );

        if (matchedWords.length > 0) {
            heuristicScore -= Math.min(matchedWords.length * 5, 20);
            reasons.push(
                "Potentially suspicious keywords detected: " + matchedWords.join(", ")
            );
        }

        if (hostname.split(".").length > 4) {
            heuristicScore -= 10;
            reasons.push("The hostname contains deep subdomain nesting.");
        }

        const isIPv4 = /^\d{1,3}(?:\.\d{1,3}){3}$/.test(hostname);
        if (isIPv4) {
            heuristicScore -= 25;
            reasons.push("The URL uses a raw IP address instead of a domain name.");
        }

        if (input.length > 100) {
            heuristicScore -= 10;
            reasons.push("The URL is unusually long.");
        }

        if (input.includes("@")) {
            heuristicScore -= 20;
            reasons.push("The URL contains an '@' symbol (often used for credential trickery).");
        }

        heuristicScore = Math.max(0, Math.min(heuristicScore, 100));

        // Incorporate ML Model inference (60% ML weight, 40% Heuristics)
        const mlSafetyScore = mlAnalysis.available ? mlAnalysis.safetyProbability : 50;
        let compositeSafetyScore = Math.round(heuristicScore * 0.40 + mlSafetyScore * 0.60);

        // Cap score if ML detects strong phishing pattern or critical anchor deception
        if (isCriticalPhishing) {
            compositeSafetyScore = Math.min(compositeSafetyScore, 5);
        } else if (mlAnalysis.available && mlAnalysis.phishingProbability >= 70) {
            compositeSafetyScore = Math.min(compositeSafetyScore, 15);
            reasons.push(`🤖 ML Neural Classifier: High Phishing Probability (${mlAnalysis.phishingProbability}%).`);
        }

        // Deduct points if domain is unresolvable
        if (threatIntel.status === "UNRESOLVED_DOMAIN") {
            compositeSafetyScore = Math.max(0, compositeSafetyScore - 25);
            reasons.push("⚠ Host Integrity: Domain does not resolve in public DNS (disposable or down host).");
        }

        compositeSafetyScore = Math.max(0, Math.min(compositeSafetyScore, 100));

        let verdict = "UNVERIFIED";
        if (isCriticalPhishing || compositeSafetyScore <= 20) {
            verdict = "DANGEROUS";
        } else if (compositeSafetyScore <= 45 || (mlAnalysis.available && mlAnalysis.verdict === "PHISHING")) {
            verdict = "SUSPICIOUS";
        } else if (compositeSafetyScore >= 75 && (!mlAnalysis.available || mlAnalysis.verdict === "SAFE")) {
            verdict = "LOW RISK";
        }

        return {
            score: compositeSafetyScore,
            verdict: verdict,
            riskCategory: getRiskCategory(compositeSafetyScore),
            domain: hostname,
            normalizedURL: normalized.cleanedURL,
            originalInput: input,
            autoFixed: normalized.autoFixed,
            fixMessages: normalized.fixMessages,
            didYouMean: didYouMeanObj ? didYouMeanObj.suggestedURL : null,
            didYouMeanDomain: didYouMeanObj ? didYouMeanObj.suggestedDomain : null,
            reasons: [
                ...reasons,
                "Continuous AI inspection: Combined Heuristic + ML Classifier + Threat Feeds."
            ],
            officialSource: null,
            sourceURL: null,
            mlAnalysis: mlAnalysis,
            threatIntelligence: threatIntel
        };

    } catch (error) {
        return {
            score: 0,
            verdict: "Invalid URL",
            reasons: ["Please enter a valid URL: " + error.message]
        };
    }
}

module.exports = analyzeURL;
