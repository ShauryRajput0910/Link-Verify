/**
 * ============================================================================
 * LINKVERIFY - Smart URL Normalizer, Auto-Fixer & Did-You-Mean Typo Detector
 * ============================================================================
 */

// Curated dictionary of top legitimate platforms, banks, and verified govt portals
const POPULAR_DOMAINS = [
    // Tech & Social
    "google.com",
    "google.co.in",
    "youtube.com",
    "facebook.com",
    "instagram.com",
    "whatsapp.com",
    "twitter.com",
    "x.com",
    "linkedin.com",
    "microsoft.com",
    "apple.com",
    "netflix.com",
    "github.com",
    "wikipedia.org",
    "openai.com",
    "chatgpt.com",
    "reddit.com",
    "spotify.com",
    "yahoo.com",
    "telegram.org",
    "gmail.com",

    // E-commerce & Shopping
    "amazon.com",
    "amazon.in",
    "flipkart.com",
    "myntra.com",
    "meesho.com",
    "ebay.com",

    // Finance & Payments
    "onlinesbi.sbi",
    "hdfcbank.com",
    "icicibank.com",
    "axisbank.com",
    "paypal.com",
    "paytm.com",
    "phonepe.com",

    // Travel & Services
    "irctc.co.in",
    "makemytrip.com",

    // Official Govt Portals
    "pmvbry.labour.gov.in",
    "pmvbry.epfindia.gov.in",
    "epfindia.gov.in",
    "pib.gov.in",
    "uidai.gov.in",
    "incometax.gov.in",
    "india.gov.in",
    "cowin.gov.in",
    "digilocker.gov.in",
    "passportindia.gov.in",
    "parivahan.gov.in"
];

// Common short prefixes/nicknames and typo stems mapped to official domains
const QUICK_SHORTCUTS = {
    "google": "google.com",
    "gogle": "google.com",
    "googl": "google.com",
    "gooogle": "google.com",
    "yt": "youtube.com",
    "youtub": "youtube.com",
    "yutube": "youtube.com",
    "ytube": "youtube.com",
    "youtube": "youtube.com",
    "fb": "facebook.com",
    "facebok": "facebook.com",
    "facebbok": "facebook.com",
    "facebook": "facebook.com",
    "insta": "instagram.com",
    "instgram": "instagram.com",
    "instagram": "instagram.com",
    "whatsapp": "whatsapp.com",
    "watsapp": "whatsapp.com",
    "whatsap": "whatsapp.com",
    "amzn": "amazon.in",
    "amazn": "amazon.in",
    "amazon": "amazon.in",
    "flipkart": "flipkart.com",
    "flipkrt": "flipkart.com",
    "flpkart": "flipkart.com",
    "netflx": "netflix.com",
    "netflix": "netflix.com",
    "githb": "github.com",
    "github": "github.com",
    "microsft": "microsoft.com",
    "microsoft": "microsoft.com",
    "wikipdia": "wikipedia.org",
    "wikipedia": "wikipedia.org",
    "paypa1": "paypal.com",
    "paypl": "paypal.com",
    "paypal": "paypal.com",
    "sbi": "onlinesbi.sbi",
    "onlinesbi": "onlinesbi.sbi",
    "pmvbry": "pmvbry.labour.gov.in",
    "irctc": "irctc.co.in"
};

/**
 * Standard Levenshtein distance algorithm
 */
function getLevenshteinDistance(a, b) {
    if (a === b) return 0;
    if (!a.length) return b.length;
    if (!b.length) return a.length;

    const matrix = [];
    for (let i = 0; i <= b.length; i++) {
        matrix[i] = [i];
    }
    for (let j = 0; j <= a.length; j++) {
        matrix[0][j] = j;
    }

    for (let i = 1; i <= b.length; i++) {
        for (let j = 1; j <= a.length; j++) {
            if (b.charAt(i - 1) === a.charAt(j - 1)) {
                matrix[i][j] = matrix[i - 1][j - 1];
            } else {
                matrix[i][j] = Math.min(
                    matrix[i - 1][j - 1] + 1,
                    matrix[i][j - 1] + 1,
                    matrix[i - 1][j] + 1
                );
            }
        }
    }
    return matrix[b.length][a.length];
}

/**
 * Clean up extra noise and auto-fix malformed inputs
 */
function cleanAndNormalizeURL(rawInput) {
    if (typeof rawInput !== "string") {
        return {
            cleanedURL: "",
            hostname: "",
            autoFixed: false,
            fixMessages: [],
            didYouMean: null,
            isDefanged: false,
            originalHadHttps: false,
            hadExplicitProtocol: false,
            hasFragment: false,
            rawFragment: ""
        };
    }

    let input = rawInput.trim();
    const fixMessages = [];
    let autoFixed = false;
    let didYouMean = null;

    // Track original protocol presence before any fixes
    const originalHadHttps = /^https:\/\//i.test(input);
    const originalHadHttp = /^http:\/\//i.test(input);
    const hadExplicitProtocol = originalHadHttps || originalHadHttp;

    // 0. Detect Defanged / Obfuscated cyber threat notation
    const hasDefangedDots = /\[\.\]|\(\.\)|\{\.\}|\[dot\]/i.test(input);
    const hasDefangedColons = /\[:\]|\(:\)|\[colon\]/i.test(input);
    const hasHxxpProto = /^hxxps?[:\/]+/i.test(input);
    const isDefanged = hasDefangedDots || hasDefangedColons || hasHxxpProto;

    if (hasDefangedDots) {
        input = input.replace(/\[\.\]|\(\.\)|\{\.\}|\[dot\]/gi, ".");
        autoFixed = true;
        fixMessages.push("Refanged defanged dots '[.]' to '.'.");
    }

    if (hasDefangedColons) {
        input = input.replace(/\[:\]|\(:\)|\[colon\]/gi, ":");
        autoFixed = true;
        fixMessages.push("Refanged defanged colons '[:]'.");
    }

    if (hasHxxpProto) {
        if (/^hxxps[:\/]+/i.test(input)) {
            input = input.replace(/^hxxps[:\/]+/i, "https://");
        } else {
            input = input.replace(/^hxxp[:\/]+/i, "http://");
        }
        autoFixed = true;
        fixMessages.push("Refanged 'hxxp' malware/quarantine protocol.");
    }

    // 1. Strip surrounding quotes, brackets, angle brackets, backticks
    const cleanedQuotes = input.replace(/^[<"`'\[\(]+|[>"'`\]\)]+$/g, "");
    if (cleanedQuotes !== input) {
        input = cleanedQuotes;
        autoFixed = true;
        fixMessages.push("Removed surrounding brackets/quotes.");
    }

    // 2. Fix protocol typos (htp://, htps://, http//, https//, https:///)
    if (/^ht{1,2}ps?[:\/]+/i.test(input) && !/^https?:\/\//i.test(input)) {
        input = input.replace(/^ht{1,2}ps?[:\/]+/i, "https://");
        autoFixed = true;
        fixMessages.push("Corrected protocol to https://");
    }

    let protocol = "https://";
    let body = input;

    if (/^https?:\/\//i.test(input)) {
        const match = input.match(/^https?:\/\//i)[0];
        protocol = match.toLowerCase();
        body = input.substring(match.length);
    } else {
        autoFixed = true;
        fixMessages.push("Added default https:// protocol (unverified).");
    }

    // Strip leading slashes from body (e.g. from https:///example.com)
    body = body.replace(/^\/+/, "");

    // Separate domain from path/query/hash
    let slashIdx = body.indexOf("/");
    let hashIdxBeforeSlash = body.indexOf("#");

    // If '#' appears before any '/', split at '#'
    let splitIdx = slashIdx;
    if (hashIdxBeforeSlash !== -1 && (slashIdx === -1 || hashIdxBeforeSlash < slashIdx)) {
        splitIdx = hashIdxBeforeSlash;
    }

    let domainPart = splitIdx === -1 ? body : body.substring(0, splitIdx);
    let pathPart = splitIdx === -1 ? "" : body.substring(splitIdx);

    // 3. Remove spaces inside domain
    if (/\s+/.test(domainPart)) {
        domainPart = domainPart.replace(/\s+/g, "");
        autoFixed = true;
        fixMessages.push("Removed internal spaces in domain name.");
    }

    // 4. Fix typo commas: www,google,com -> www.google.com
    if (domainPart.includes(",")) {
        domainPart = domainPart.replace(/,/g, ".");
        autoFixed = true;
        fixMessages.push("Replaced typo commas with dots.");
    }

    // 5. Fix multiple consecutive dots: google..com -> google.com
    if (/\.{2,}/.test(domainPart)) {
        domainPart = domainPart.replace(/\.{2,}/g, ".");
        autoFixed = true;
        fixMessages.push("Cleaned multiple consecutive dots.");
    }

    // 6. Remove trailing dots/slashes/colons from domain
    domainPart = domainPart.replace(/[.:\/]+$/, "");

    // 7. Fix missing dot before common TLD: googlecom -> google.com
    const missingDotMatch = domainPart.match(/^([a-zA-Z0-9-]+)(com|org|net|gov|edu|co|io|ai)$/i);
    if (missingDotMatch && !domainPart.includes(".")) {
        domainPart = `${missingDotMatch[1]}.${missingDotMatch[2]}`;
        autoFixed = true;
        fixMessages.push(`Added missing dot before .${missingDotMatch[2]} extension.`);
    }

    // 8. Fix common TLD typos
    if (/\.(con|cm|cmo|coom|comm)$/i.test(domainPart)) {
        domainPart = domainPart.replace(/\.(con|cm|cmo|coom|comm)$/i, ".com");
        autoFixed = true;
        fixMessages.push("Corrected typo domain extension to .com");
    } else if (/\.(og|orgg)$/i.test(domainPart)) {
        domainPart = domainPart.replace(/\.(og|orgg)$/i, ".org");
        autoFixed = true;
        fixMessages.push("Corrected typo domain extension to .org");
    } else if (/\.(inn)$/i.test(domainPart)) {
        domainPart = domainPart.replace(/\.(inn)$/i, ".in");
        autoFixed = true;
        fixMessages.push("Corrected typo domain extension to .in");
    }

    // 9. If no dot in domain at all (e.g. 'google', 'youtub', 'amazn')
    if (!domainPart.includes(".")) {
        const lower = domainPart.toLowerCase();
        if (QUICK_SHORTCUTS[lower]) {
            const canonical = QUICK_SHORTCUTS[lower];
            if (lower !== canonical.split(".")[0]) {
                didYouMean = `https://${canonical}`;
            }
            domainPart = canonical;
            autoFixed = true;
            fixMessages.push(`Completed domain as ${domainPart}`);
        } else {
            domainPart = domainPart + ".com";
            autoFixed = true;
            fixMessages.push("Added missing .com domain extension.");
        }
    }

    // Clean path (trim duplicate slashes at beginning if it starts with slash)
    if (pathPart && pathPart.startsWith("/")) {
        pathPart = "/" + pathPart.replace(/^\/+/, "");
    }

    const cleanedURL = `${protocol}${domainPart}${pathPart}`;
    const hasFragment = cleanedURL.includes("#");
    const rawFragment = hasFragment ? cleanedURL.substring(cleanedURL.indexOf("#")) : "";

    return {
        cleanedURL,
        hostname: domainPart.toLowerCase(),
        autoFixed,
        fixMessages,
        didYouMean,
        isDefanged,
        originalHadHttps,
        hadExplicitProtocol,
        hasFragment,
        rawFragment
    };
}

/**
 * Intelligent "Did You Mean" Suggestion Finder
 * Detects if the user typed a typo of a popular or official domain
 */
function findDidYouMeanSuggestion(hostname, originalRaw) {
    if (!hostname) return null;

    const cleanHost = hostname.toLowerCase().replace(/^www\./, "");
    const hostBase = cleanHost.split(".")[0];
    const hostTLD = cleanHost.split(".").slice(1).join(".");

    // Check if original raw input was a typo of a shortcut
    if (originalRaw) {
        const rawClean = originalRaw.toLowerCase().replace(/^https?:\/\//, "").replace(/^www\./, "").replace(/[\/].*$/, "");
        const rawBase = rawClean.split(".")[0].replace(/[^a-z0-9]/g, "");
        if (QUICK_SHORTCUTS[rawBase]) {
            const target = QUICK_SHORTCUTS[rawBase];
            if (rawClean !== target && rawBase !== target.split(".")[0]) {
                return {
                    suggestedURL: `https://${target}`,
                    suggestedDomain: target,
                    reason: `Typo detected for official service ${target}.`
                };
            }
        }
    }

    // Check direct shortcut lookup
    if (QUICK_SHORTCUTS[hostBase]) {
        const target = QUICK_SHORTCUTS[hostBase];
        if (cleanHost !== target && hostBase !== target.split(".")[0]) {
            return {
                suggestedURL: `https://${target}`,
                suggestedDomain: target,
                reason: `Typo detected for official service ${target}.`
            };
        }
    }

    // Exact match against popular domains -> already accurate, no typo suggestion needed
    if (POPULAR_DOMAINS.includes(cleanHost)) {
        return null;
    }

    let bestMatch = null;
    let minDistance = Infinity;

    for (const legitDomain of POPULAR_DOMAINS) {
        const legitBase = legitDomain.split(".")[0];
        const legitTLD = legitDomain.split(".").slice(1).join(".");

        // Check full domain distance
        const fullDist = getLevenshteinDistance(cleanHost, legitDomain);

        // Check base name distance (e.g. 'gogle' vs 'google')
        const baseDist = getLevenshteinDistance(hostBase, legitBase);

        // Substring / Missing character match (e.g. 'amazn' inside 'amazon')
        const isCloseBase = (baseDist <= 2 && Math.abs(hostBase.length - legitBase.length) <= 2) ||
                           (legitBase.includes(hostBase) && hostBase.length >= 4) ||
                           (hostBase.includes(legitBase) && Math.abs(hostBase.length - legitBase.length) <= 2);

        if (isCloseBase && (fullDist <= 3 || baseDist <= 2)) {
            const totalScore = baseDist * 2 + (hostTLD === legitTLD ? 0 : 1);
            if (totalScore < minDistance) {
                minDistance = totalScore;
                bestMatch = legitDomain;
            }
        }
    }

    if (bestMatch && bestMatch !== cleanHost) {
        return {
            suggestedURL: `https://${bestMatch}`,
            suggestedDomain: bestMatch,
            reason: `Did you mean ${bestMatch}? Attackers often exploit typosquatting to mimic legitimate portals.`
        };
    }

    return null;
}

module.exports = {
    cleanAndNormalizeURL,
    findDidYouMeanSuggestion,
    POPULAR_DOMAINS,
    QUICK_SHORTCUTS
};
