const fs = require("fs");
const path = require("path");
const mysql = require("mysql2");
require("dotenv").config({ path: path.join(__dirname, ".env") });

// ==========================================
// CONFIGURATION & PATHS
// ==========================================

const DATA_DIR = path.join(__dirname, "data");
const SCANS_FILE = path.join(DATA_DIR, "scans.json");

// Ensure data directory and fallback JSON file exist
if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR, { recursive: true });
}

if (!fs.existsSync(SCANS_FILE)) {
    fs.writeFileSync(SCANS_FILE, JSON.stringify([], null, 2), "utf8");
}

// Read fallback scans
function readLocalScans() {
    try {
        if (!fs.existsSync(SCANS_FILE)) return [];
        const raw = fs.readFileSync(SCANS_FILE, "utf8");
        return JSON.parse(raw) || [];
    } catch (err) {
        console.error("Error reading local scans file:", err.message);
        return [];
    }
}

// Write fallback scans
function writeLocalScans(scans) {
    try {
        fs.writeFileSync(SCANS_FILE, JSON.stringify(scans, null, 2), "utf8");
    } catch (err) {
        console.error("Error writing local scans file:", err.message);
    }
}

// ==========================================
// MYSQL CONNECTION SETUP
// ==========================================

// Supports Railway environment variables (MYSQLHOST, MYSQLUSER, etc.) and standard DB_* variables
const mysqlConfig = {
    host: process.env.MYSQLHOST || process.env.DB_HOST || "localhost",
    user: process.env.MYSQLUSER || process.env.DB_USER || "root",
    password: process.env.MYSQLPASSWORD || process.env.DB_PASSWORD || "",
    database: process.env.MYSQLDATABASE || process.env.DB_NAME || "linkverify",
    port: Number(process.env.MYSQLPORT || process.env.DB_PORT || 3306),
    connectTimeout: 5000
};

let mysqlClient = null;
let isConnected = false;

try {
    mysqlClient = mysql.createConnection(mysqlConfig);

    mysqlClient.connect((err) => {
        if (err) {
            console.warn("MySQL notice: Local/Cloud MySQL not reached (" + err.code + "). Using local persistent storage engine.");
            isConnected = false;
            return;
        }

        isConnected = true;
        console.log("✓ MySQL connected successfully!");

        // Auto-create url_scans table if it doesn't exist
        const createTableSQL = `
            CREATE TABLE IF NOT EXISTS url_scans (
                id INT AUTO_INCREMENT PRIMARY KEY,
                url VARCHAR(500) NOT NULL,
                risk_score INT NOT NULL,
                verdict VARCHAR(50) NOT NULL,
                scan_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `;

        mysqlClient.query(createTableSQL, (tableErr) => {
            if (tableErr) {
                console.warn("MySQL notice: Could not verify/create table url_scans:", tableErr.message);
            } else {
                console.log("✓ MySQL url_scans table is ready!");
            }
        });
    });

    mysqlClient.on("error", (err) => {
        console.warn("MySQL runtime notice:", err.message);
        isConnected = false;
    });

} catch (e) {
    console.warn("MySQL setup notice:", e.message);
    isConnected = false;
}

// ==========================================
// UNIFIED DATABASE API
// ==========================================

/**
 * Save a scan to database (MySQL with fallback to local persistent scans.json)
 */
function saveScan(scanData, callback) {
    const { url, risk_score, verdict } = scanData;
    const now = new Date();

    const newRecord = {
        id: Date.now(),
        url: url,
        risk_score: Number(risk_score) || 0,
        verdict: verdict || "UNVERIFIED",
        scan_time: now.toISOString()
    };

    // 1. Always save to local persistent JSON file
    const localScans = readLocalScans();
    localScans.unshift(newRecord);
    // Keep last 500 scans
    if (localScans.length > 500) {
        localScans.length = 500;
    }
    writeLocalScans(localScans);

    // 2. If MySQL is connected, also insert into MySQL
    if (isConnected && mysqlClient) {
        const sql = `
            INSERT INTO url_scans (url, risk_score, verdict)
            VALUES (?, ?, ?)
        `;

        mysqlClient.query(sql, [url, newRecord.risk_score, newRecord.verdict], (err, result) => {
            if (err) {
                console.warn("MySQL insert notice:", err.message);
                if (typeof callback === "function") {
                    callback(null, newRecord);
                }
                return;
            }

            if (result && result.insertId) {
                newRecord.id = result.insertId;
            }

            if (typeof callback === "function") {
                callback(null, newRecord);
            }
        });
    } else {
        if (typeof callback === "function") {
            callback(null, newRecord);
        }
    }
}

/**
 * Get all scans (MySQL with fallback to local persistent scans.json)
 */
function getScans(callback) {
    if (isConnected && mysqlClient) {
        const sql = `
            SELECT *
            FROM url_scans
            ORDER BY scan_time DESC
            LIMIT 200
        `;

        mysqlClient.query(sql, (err, rows) => {
            if (err) {
                console.warn("MySQL query notice, falling back to local storage:", err.message);
                const local = readLocalScans();
                if (typeof callback === "function") {
                    callback(null, local);
                }
                return;
            }

            if (rows && rows.length > 0) {
                if (typeof callback === "function") {
                    callback(null, rows);
                }
            } else {
                // If MySQL is empty, return local scans if any exist
                const local = readLocalScans();
                if (typeof callback === "function") {
                    callback(null, local.length > 0 ? local : rows);
                }
            }
        });
    } else {
        const local = readLocalScans();
        if (typeof callback === "function") {
            callback(null, local);
        }
    }
}

function isMySQLReady() {
    return isConnected;
}

module.exports = {
    saveScan,
    getScans,
    isMySQLReady,
    mysqlClient
};
