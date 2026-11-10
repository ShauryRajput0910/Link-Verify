/**
 * ============================================================================
 * LINKVERIFY - MACHINE LEARNING MODEL TRAINING PIPELINE
 * Supervised Logistic Regression Classifier with Feature Normalization & L2
 * ============================================================================
 */

const fs = require("fs");
const path = require("path");

// ==========================================
// 1. FEATURE EXTRACTION PIPELINE
// ==========================================

const SUSPICIOUS_KEYWORDS = [
    "login", "verify", "verification", "secure", "account", "banking",
    "update", "wallet", "claim", "prize", "winner", "reward", "free",
    "gift", "bonus", "confirm", "security", "support", "signin",
    "password", "yojana", "rozgar", "kyc", "alert", "fund", "pay"
];

function calculateEntropy(str) {
    if (!str || str.length === 0) return 0;
    const freq = {};
    for (let i = 0; i < str.length; i++) {
        const ch = str[i];
        freq[ch] = (freq[ch] || 0) + 1;
    }
    let entropy = 0;
    const len = str.length;
    for (const ch in freq) {
        const p = freq[ch] / len;
        entropy -= p * Math.log2(p);
    }
    return entropy;
}

function extractFeatures(urlStr) {
    let parsed;
    try {
        let full = urlStr.trim();
        if (!/^https?:\/\//i.test(full)) {
            full = "http://" + full;
        }
        parsed = new URL(full);
    } catch (e) {
        // Fallback dummy URL
        parsed = {
            hostname: urlStr.replace(/^https?:\/\//i, "").split("/")[0] || "",
            pathname: "",
            search: "",
            protocol: "http:"
        };
    }

    const raw = urlStr.toLowerCase();
    const hostname = (parsed.hostname || "").toLowerCase();
    const path = (parsed.pathname || "").toLowerCase();
    const search = (parsed.search || "").toLowerCase();

    // 1. url_length
    const urlLength = raw.length;

    // 2. domain_length
    const domainLength = hostname.length;

    // 3. num_subdomains
    const parts = hostname.split(".");
    const numSubdomains = Math.max(0, parts.length - 2);

    // 4. num_dots
    const numDots = (raw.match(/\./g) || []).length;

    // 5. num_hyphens
    const numHyphens = (raw.match(/-/g) || []).length;

    // 6. has_ip (IPv4 detection)
    const hasIP = /^(?:\d{1,3}\.){3}\d{1,3}$/.test(hostname) ? 1 : 0;

    // 7. has_at
    const hasAt = raw.includes("@") ? 1 : 0;

    // 8. digit_ratio
    const digitCount = (raw.match(/\d/g) || []).length;
    const digitRatio = urlLength > 0 ? digitCount / urlLength : 0;

    // 9. entropy of full url
    const entropy = calculateEntropy(raw);

    // 10. suspicious_keywords count
    let keywordHits = 0;
    for (const kw of SUSPICIOUS_KEYWORDS) {
        if (raw.includes(kw)) keywordHits++;
    }

    // 11. has_punycode or suspicious tld
    const hasPunycode = hostname.includes("xn--") ? 1 : 0;

    // 12. path_depth
    const pathDepth = (path.match(/\//g) || []).length;

    // 13. query_length
    const queryLength = search.length;

    // 14. has_special_chars (?, =, %, &, _)
    const specialChars = (raw.match(/[?=%&_~]/g) || []).length;

    // 15. is_https
    const isHttps = parsed.protocol === "https:" ? 1 : 0;

    // 16. is_official_tld (.gov, .gov.in, .nic.in, .edu)
    const isOfficialTld = /\.(gov|nic|edu)(\.[a-z]{2})?$/.test(hostname) ? 1 : 0;

    return [
        urlLength,
        domainLength,
        numSubdomains,
        numDots,
        numHyphens,
        hasIP,
        hasAt,
        digitRatio,
        entropy,
        keywordHits,
        hasPunycode,
        pathDepth,
        queryLength,
        specialChars,
        isHttps,
        isOfficialTld
    ];
}

const FEATURE_NAMES = [
    "url_length",
    "domain_length",
    "num_subdomains",
    "num_dots",
    "num_hyphens",
    "has_ip",
    "has_at",
    "digit_ratio",
    "entropy",
    "keyword_hits",
    "has_punycode",
    "path_depth",
    "query_length",
    "special_chars",
    "is_https",
    "is_official_tld"
];

// ==========================================
// 2. TRAINING DATASET (CURATED BENCHMARK)
// 1 = Phishing / Scam / Malicious
// 0 = Legitimate / Safe / Official
// ==========================================

const DATASET = [
    // --- Legitimate Sites (label = 0) ---
    { url: "https://www.google.com", label: 0 },
    { url: "https://google.com/search?q=machine+learning", label: 0 },
    { url: "https://github.com/torvalds/linux", label: 0 },
    { url: "https://github.com", label: 0 },
    { url: "https://www.wikipedia.org", label: 0 },
    { url: "https://en.wikipedia.org/wiki/Phishing", label: 0 },
    { url: "https://www.amazon.com", label: 0 },
    { url: "https://www.amazon.in/dp/B08N5WRWNW", label: 0 },
    { url: "https://www.microsoft.com/en-us", label: 0 },
    { url: "https://azure.microsoft.com", label: 0 },
    { url: "https://www.apple.com/iphone", label: 0 },
    { url: "https://developer.apple.com/documentation", label: 0 },
    { url: "https://www.youtube.com/watch?v=dQw4w9WgXcQ", label: 0 },
    { url: "https://youtube.com", label: 0 },
    { url: "https://www.netflix.com/browse", label: 0 },
    { url: "https://pmvbry.labour.gov.in", label: 0 },
    { url: "https://pmvbry.epfindia.gov.in", label: 0 },
    { url: "https://www.india.gov.in", label: 0 },
    { url: "https://epfindia.gov.in/site_en/index.php", label: 0 },
    { url: "https://pib.gov.in/PressReleasePage.aspx?PRID=1980000", label: 0 },
    { url: "https://incometax.gov.in/iec/foportal/", label: 0 },
    { url: "https://uidai.gov.in", label: 0 },
    { url: "https://www.onlinesbi.sbi", label: 0 },
    { url: "https://www.hdfcbank.com", label: 0 },
    { url: "https://www.icicibank.com", label: 0 },
    { url: "https://railway.app", label: 0 },
    { url: "https://docs.railway.app/deploy/overview", label: 0 },
    { url: "https://www.reddit.com/r/technology", label: 0 },
    { url: "https://stackoverflow.com/questions/tagged/node.js", label: 0 },
    { url: "https://nodejs.org/en/docs", label: 0 },
    { url: "https://developer.mozilla.org/en-US/docs/Web/API", label: 0 },
    { url: "https://twitter.com/home", label: 0 },
    { url: "https://x.com", label: 0 },
    { url: "https://www.linkedin.com/feed", label: 0 },
    { url: "https://medium.com/@engineering/scalability", label: 0 },
    { url: "https://www.nytimes.com/section/world", label: 0 },
    { url: "https://bbc.com/news", label: 0 },
    { url: "https://cnn.com", label: 0 },
    { url: "https://www.iitb.ac.in", label: 0 },
    { url: "https://www.mit.edu", label: 0 },
    { url: "https://stanford.edu", label: 0 },
    { url: "https://cloudflare.com", label: 0 },
    { url: "https://digitalocean.com/products/droplets", label: 0 },
    { url: "https://aws.amazon.com/console", label: 0 },
    { url: "https://paypal.com", label: 0 },
    { url: "https://stripe.com/docs/api", label: 0 },
    { url: "https://gitlab.com", label: 0 },
    { url: "https://bitbucket.org", label: 0 },
    { url: "https://slack.com", label: 0 },
    { url: "https://zoom.us", label: 0 },

    // --- Phishing / Scam / Malicious Sites (label = 1) ---
    { url: "http://viksitbharatrozgaryojana.org", label: 1 },
    { url: "http://pmviksitbharatrozgaryojana.com", label: 1 },
    { url: "http://192.168.1.105/bank-login/verification.php", label: 1 },
    { url: "http://185.220.101.4/secure/paypal-update/", label: 1 },
    { url: "http://142.250.190.46/signin/google-drive-confirm.html", label: 1 },
    { url: "http://amazn-account-security-alert-verify.com", label: 1 },
    { url: "http://paypal-verification-account-update-center.org/login", label: 1 },
    { url: "http://appleid.apple.com.verify-device-support.tk", label: 1 },
    { url: "http://secure-login-hdfc-bank-kyc-update.net/auth", label: 1 },
    { url: "http://sbi-online-kyc-claim-bonus-reward.xyz/login.php", label: 1 },
    { url: "http://netflix-billing-update-failure-claim.club/re-login", label: 1 },
    { url: "http://free-iphone15-pro-giveaway-winner-claim.top", label: 1 },
    { url: "http://wallet-metamask-seed-phrase-verify.io.in/connect", label: 1 },
    { url: "http://rozgar-yojana-sarkari-form-apply-online-free.online", label: 1 },
    { url: "http://user:pass@phishing-bank-portal.com/login", label: 1 },
    { url: "http://bank-verification.com@malicious-redirect.com/index", label: 1 },
    { url: "http://xn--gogle-qra.com/search-login", label: 1 },
    { url: "http://google.com.account-protection.security-review.info/login", label: 1 },
    { url: "http://facebook.com-login-action-verification-now.co", label: 1 },
    { url: "http://instagram-free-followers-claim-prize.buzz", label: 1 },
    { url: "http://whatsapp-gold-edition-download-free.biz", label: 1 },
    { url: "http://pm-kisan-yojana-claim-payment-verify-aadhaar.top", label: 1 },
    { url: "http://epfo-claim-settlement-urgent-kyc-update.space", label: 1 },
    { url: "http://103.245.22.18/sbi/otp-verification.aspx", label: 1 },
    { url: "http://chase-bank-fraud-detection-security-alert.us", label: 1 },
    { url: "http://wellsfargo-online-banking-signon-verification.cc", label: 1 },
    { url: "http://binance-wallet-security-withdrawal-frozen.vip", label: 1 },
    { url: "http://crypto-airdrop-5000-usdt-winner-claim.site", label: 1 },
    { url: "http://steam-community-free-skins-trade-offer.link", label: 1 },
    { url: "http://microsoft-outlook-office365-password-reset.pw", label: 1 },
    { url: "http://dropbox-shared-document-urgent-review.ga", label: 1 },
    { url: "http://fedex-parcel-delivery-tracking-confirm-fee.gq", label: 1 },
    { url: "http://dhl-express-package-held-customs-payment.cf", label: 1 },
    { url: "http://indiaofficial-rozgar-portal-application-fee.click", label: 1 },
    { url: "http://ayushman-bharat-card-download-pay-now.website", label: 1 },
    { url: "http://pradhanmantri-awas-yojana-subsidy-claim.online", label: 1 },
    { url: "http://fake-telecom-5g-upgrade-free-recharge.live", label: 1 },
    { url: "http://paytm-kyc-suspended-pan-update-link.today", label: 1 },
    { url: "http://airtel-sim-deactivation-warning-verify.services", label: 1 },
    { url: "http://income-tax-refund-approved-enter-account.cam", label: 1 },
    { url: "http://fastag-blacklist-clear-payment-urgent.work", label: 1 },
    { url: "http://covid-booster-certificate-download-fee.ml", label: 1 },
    { url: "http://electric-bill-unpaid-power-cut-tonight-call.bid", label: 1 },
    { url: "http://lottery-department-government-winner-75lakh.xyz", label: 1 },
    { url: "http://job-offer-part-time-telegram-daily-5000.rocks", label: 1 },
    { url: "http://youtube-monetization-violation-copyright-appeal.info", label: 1 },
    { url: "http://meta-business-manager-suspension-appeal.center", label: 1 },
    { url: "http://twitter-blue-badge-free-verification.vip", label: 1 },
    { url: "http://amazon-prime-renewal-failed-update-card.shop", label: 1 },
    { url: "http://flipkart-big-billion-days-1-rupee-deal.store", label: 1 }
];

// ==========================================
// 3. SIGMOID & LOSS FUNCTIONS
// ==========================================

function sigmoid(z) {
    if (z > 30) return 1;
    if (z < -30) return 0;
    return 1 / (1 + Math.exp(-z));
}

// Compute binary cross-entropy loss with L2 penalty
function computeLoss(X, y, weights, bias, lambda) {
    const m = y.length;
    let totalLoss = 0;
    for (let i = 0; i < m; i++) {
        let z = bias;
        for (let j = 0; j < weights.length; j++) {
            z += weights[j] * X[i][j];
        }
        const p = Math.max(1e-15, Math.min(1 - 1e-15, sigmoid(z)));
        totalLoss += - (y[i] * Math.log(p) + (1 - y[i]) * Math.log(1 - p));
    }
    // L2 regularization
    let l2 = 0;
    for (let j = 0; j < weights.length; j++) {
        l2 += weights[j] * weights[j];
    }
    return (totalLoss / m) + (lambda / (2 * m)) * l2;
}

// ==========================================
// 4. TRAINING WITH GRADIENT DESCENT
// ==========================================

function trainModel() {
    console.log("⚡ [ML Pipeline] Starting ML training on " + DATASET.length + " labeled samples...");

    // Extract raw feature vectors
    const X_raw = DATASET.map(d => extractFeatures(d.url));
    const y = DATASET.map(d => d.label);

    const numSamples = X_raw.length;
    const numFeatures = FEATURE_NAMES.length;

    // Standardize features: calculate mean and std dev
    const means = new Array(numFeatures).fill(0);
    const stdDevs = new Array(numFeatures).fill(0);

    for (let j = 0; j < numFeatures; j++) {
        let sum = 0;
        for (let i = 0; i < numSamples; i++) {
            sum += X_raw[i][j];
        }
        means[j] = sum / numSamples;

        let varSum = 0;
        for (let i = 0; i < numSamples; i++) {
            varSum += Math.pow(X_raw[i][j] - means[j], 2);
        }
        stdDevs[j] = Math.sqrt(varSum / numSamples) || 1; // avoid divide by zero
    }

    // Normalized feature matrix
    const X = X_raw.map(row =>
        row.map((val, j) => (val - means[j]) / stdDevs[j])
    );

    // Initialize weights and bias
    let weights = new Array(numFeatures).fill(0).map(() => (Math.random() - 0.5) * 0.1);
    let bias = 0;

    // Hyperparameters
    const learningRate = 0.08;
    const epochs = 2000;
    const lambda = 0.01; // L2 regularizer

    for (let epoch = 1; epoch <= epochs; epoch++) {
        const dW = new Array(numFeatures).fill(0);
        let dB = 0;

        for (let i = 0; i < numSamples; i++) {
            let z = bias;
            for (let j = 0; j < numFeatures; j++) {
                z += weights[j] * X[i][j];
            }
            const error = sigmoid(z) - y[i];

            for (let j = 0; j < numFeatures; j++) {
                dW[j] += error * X[i][j];
            }
            dB += error;
        }

        // Apply gradients with L2 regularization
        for (let j = 0; j < numFeatures; j++) {
            weights[j] -= learningRate * ((dW[j] / numSamples) + (lambda / numSamples) * weights[j]);
        }
        bias -= learningRate * (dB / numSamples);

        if (epoch % 500 === 0 || epoch === epochs) {
            const loss = computeLoss(X, y, weights, bias, lambda);
            console.log(`Epoch ${epoch}/${epochs} - Loss: ${loss.toFixed(5)}`);
        }
    }

    // Evaluate metrics
    let correct = 0;
    let truePos = 0;
    let falsePos = 0;
    let trueNeg = 0;
    let falseNeg = 0;

    for (let i = 0; i < numSamples; i++) {
        let z = bias;
        for (let j = 0; j < numFeatures; j++) {
            z += weights[j] * X[i][j];
        }
        const prob = sigmoid(z);
        const pred = prob >= 0.5 ? 1 : 0;
        if (pred === y[i]) correct++;

        if (pred === 1 && y[i] === 1) truePos++;
        if (pred === 1 && y[i] === 0) falsePos++;
        if (pred === 0 && y[i] === 0) trueNeg++;
        if (pred === 0 && y[i] === 1) falseNeg++;
    }

    const accuracy = (correct / numSamples) * 100;
    const precision = truePos + falsePos > 0 ? (truePos / (truePos + falsePos)) * 100 : 100;
    const recall = truePos + falseNeg > 0 ? (truePos / (truePos + falseNeg)) * 100 : 100;
    const f1 = (2 * precision * recall) / (precision + recall) || 0;

    console.log("==========================================");
    console.log(`✓ Training Complete!`);
    console.log(`  Accuracy:  ${accuracy.toFixed(2)}%`);
    console.log(`  Precision: ${precision.toFixed(2)}%`);
    console.log(`  Recall:    ${recall.toFixed(2)}%`);
    console.log(`  F1-Score:  ${f1.toFixed(2)}%`);
    console.log("==========================================");

    // Prepare model payload
    const modelArtifact = {
        modelType: "Supervised Logistic Regression Classifier",
        framework: "LinkVerify ML Engine (L2 Regularized)",
        trainedAt: new Date().toISOString(),
        datasetSize: numSamples,
        metrics: {
            accuracy: Number(accuracy.toFixed(2)),
            precision: Number(precision.toFixed(2)),
            recall: Number(recall.toFixed(2)),
            f1Score: Number(f1.toFixed(2))
        },
        featureNames: FEATURE_NAMES,
        means: means,
        stdDevs: stdDevs,
        weights: weights,
        bias: bias,
        suspiciousKeywords: SUSPICIOUS_KEYWORDS
    };

    const modelsDir = path.join(__dirname, "models");
    if (!fs.existsSync(modelsDir)) {
        fs.mkdirSync(modelsDir, { recursive: true });
    }

    const outPath = path.join(modelsDir, "phishing_weights.json");
    fs.writeFileSync(outPath, JSON.stringify(modelArtifact, null, 2), "utf8");
    console.log("✓ Trained model weights successfully written to: " + outPath);

    return modelArtifact;
}

if (require.main === module) {
    trainModel();
}

module.exports = {
    trainModel,
    extractFeatures,
    calculateEntropy,
    FEATURE_NAMES,
    SUSPICIOUS_KEYWORDS
};
