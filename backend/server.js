
const express = require("express");
const cors = require("cors");
const path = require("path");
require("dotenv").config();

const db = require("./db");
const analyzeURL = require("./analyzer");

const app = express();
const PORT = process.env.PORT || 5000;

// ==========================================
// MIDDLEWARE
// ==========================================

app.use(cors());
app.use(express.json());

// Serve static frontend files
app.use(express.static(path.join(__dirname, "../frontend")));

// ==========================================
// HEALTH ROUTE
// ==========================================

app.get("/api/health", (req, res) => {
    res.send("FraudSense / LinkVerify Backend is Running!");
});

// ==========================================
// SCAN URL API
// ==========================================

app.post("/api/scan", async (req, res) => {
    const { url } = req.body;

    if (typeof url !== "string" || !url.trim()) {
        return res.status(400).json({
            success: false,
            message: "Please provide a valid URL."
        });
    }

    const cleanURL = url.trim();

    // ==========================================
    // USE THE MULTI-LAYER ANALYZER (AI ML + THREAT API)
    // ==========================================

    let analysis;
    try {
        analysis = await analyzeURL(cleanURL);
    } catch (err) {
        console.error("Analyzer error:", err);
        return res.status(500).json({
            success: false,
            message: "Analysis engine failure: " + err.message
        });
    }

    // analyzer.js returns a score where a higher
    // score means lower risk for ordinary URLs.
    // Known fake and official domains have explicit
    // verdicts that must override score-based labels.

    let verdict = analysis.verdict;
    let riskScore;

    if (verdict === "FAKE" || verdict === "Known Fake") {
        verdict = "FAKE";
        riskScore = 100;
    } else if (verdict === "VERIFIED OFFICIAL" ||
        verdict === "Verified Official") {
        verdict = "VERIFIED OFFICIAL";
        riskScore = 0;
    } else if (verdict === "Invalid URL") {
        verdict = "INVALID URL";
        riskScore = 0;
    } else if (verdict === "Suspicious" || verdict === "SUSPICIOUS") {
        verdict = "SUSPICIOUS";
        riskScore = 85;
    } else {
        // Unknown sites remain unverified.
        verdict = analysis.verdict || "UNVERIFIED";

        // Convert safety score to risk score for storage.
        const safetyScore = Number(analysis.score ?? 50);
        riskScore = Math.max(0, Math.min(100, 100 - safetyScore));
    }

    const reasons = Array.isArray(analysis.reasons)
        ? analysis.reasons
        : [];

    // ==========================================
    // SAVE RESULT TO DATABASE
    // ==========================================

    db.saveScan(
        {
            url: cleanURL,
            risk_score: riskScore,
            verdict: verdict
        },
        (err, savedRecord) => {
            // ======================================
            // SEND RESULT TO FRONTEND
            // ======================================

            return res.json({
                success: true,
                id: savedRecord ? savedRecord.id : null,
                url: analysis.normalizedURL || cleanURL,
                originalURL: cleanURL,
                didYouMean: analysis.didYouMean || null,
                didYouMeanDomain: analysis.didYouMeanDomain || null,
                autoFixed: analysis.autoFixed || false,
                fixMessages: analysis.fixMessages || [],
                riskScore,
                safetyScore: analysis.score,
                verdict,
                riskCategory: analysis.riskCategory,
                reasons: analysis.reasons || reasons,
                officialSource: analysis.officialSource || null,
                sourceURL: analysis.sourceURL || null,
                mlAnalysis: analysis.mlAnalysis || null,
                threatIntelligence: analysis.threatIntelligence || null,
                message: analysis.didYouMean
                    ? `Did you mean: ${analysis.didYouMean}?`
                    : "URL analysis completed successfully."
            });
        }
    );
});

// ==========================================
// GET SCAN HISTORY
// ==========================================

app.get("/api/scans", (req, res) => {
    db.getScans((err, scans) => {
        if (err) {
            console.error("Database fetch error:", err.message);
            return res.status(500).json({
                success: false,
                message: "Database error",
                error: err.message
            });
        }

        res.json({
            success: true,
            scans: scans || []
        });
    });
});

// ==========================================
// START SERVER
// ==========================================

app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});

