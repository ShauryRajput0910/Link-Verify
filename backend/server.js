
const express = require("express");
const cors = require("cors");
const mysql = require("mysql2");
const path = require("path");
require("dotenv").config();

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
// MYSQL CONNECTION
// ==========================================

const db = mysql.createConnection({
    host: process.env.DB_HOST || "localhost",
    user: process.env.DB_USER || "root",
    password: process.env.DB_PASSWORD || "",
    database: process.env.DB_NAME || "linkverify"
});

db.connect((err) => {
    if (err) {
        console.error("MySQL connection failed:", err.message);
        return;
    }

    console.log("MySQL connected successfully!");
});

// ==========================================
// HEALTH ROUTE
// ==========================================

app.get("/api/health", (req, res) => {
    res.send("FraudSense / LinkVerify Backend is Running!");
});

// ==========================================
// SCAN URL API
// ==========================================

app.post("/api/scan", (req, res) => {
    const { url } = req.body;

    if (typeof url !== "string" || !url.trim()) {
        return res.status(400).json({
            success: false,
            message: "Please provide a valid URL."
        });
    }

    const cleanURL = url.trim();

    // ==========================================
    // USE THE EXISTING ANALYZER
    // ==========================================

    const analysis = analyzeURL(cleanURL);

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
        riskScore = 100;
    } else if (verdict === "Invalid URL") {
        verdict = "INVALID URL";
        riskScore = 0;
    } else if (verdict === "Suspicious") {
        verdict = "SUSPICIOUS";
        riskScore = 0;
    } else {
        // Unknown sites remain unverified.
        verdict = "UNVERIFIED";

        // Convert safety score to risk score for storage.
        const safetyScore = Number(analysis.score ?? 50);
        riskScore = Math.max(0, Math.min(100, 100 - safetyScore));
    }

    const reasons = Array.isArray(analysis.reasons)
        ? analysis.reasons
        : [];

    // ==========================================
    // SAVE RESULT TO MYSQL
    // ==========================================

    const sql = `
        INSERT INTO url_scans
        (url, risk_score, verdict)
        VALUES (?, ?, ?)
    `;

    db.query(
        sql,
        [cleanURL, riskScore, verdict],
        (err, result) => {
            if (err) {
                console.warn("Database notice (running without DB persistence):", err.message);
            }

            // ======================================
            // SEND RESULT TO FRONTEND
            // ======================================

            return res.json({
                success: true,
                id: result ? result.insertId : null,
                url: cleanURL,
                riskScore,
                safetyScore: analysis.score,
                verdict,
                reasons,
                officialSource: analysis.officialSource || null,
                sourceURL: analysis.sourceURL || null,
                message: "URL analysis completed successfully."
            });
        }
    );
});

// ==========================================
// GET SCAN HISTORY
// ==========================================

app.get("/api/scans", (req, res) => {
    const sql = `
        SELECT *
        FROM url_scans
        ORDER BY scan_time DESC
    `;

    db.query(sql, (err, results) => {
        if (err) {
            console.warn("Database notice:", err.message);

            return res.json({
                success: true,
                scans: []
            });
        }

        res.json({
            success: true,
            scans: results
        });
    });
});

// ==========================================
// START SERVER
// ==========================================

app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});

