const express = require("express");
const { Pool } = require("pg");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const dns = require("dns").promises;
const tls = require("tls");
const net = require("net");

const app = express();

app.use(express.json({ limit: "20kb" }));
app.use(express.static(__dirname));

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET;
const ADMIN_EMAIL = String(process.env.ADMIN_EMAIL || "").trim().toLowerCase();

if (!JWT_SECRET) {
    console.error("JWT_SECRET is missing.");
    process.exit(1);
}

const pool = new Pool({
    connectionString: process.env.DATABASE_URL
});

let phishingURLs = new Set();
let phishingDomains = new Set();
let databaseReady = false;
let threatFeedReady = false;

const REPORT_CATEGORIES = [
    "deposit_before_withdrawal",
    "withdrawal_fee",
    "payment_to_unlock_earnings",
    "recruitment_required",
    "unrealistic_returns",
    "other"
];

/* DATABASE */
async function initializeDatabase() {
    await pool.query(`
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            name VARCHAR(100) NOT NULL,
            email VARCHAR(255) UNIQUE NOT NULL,
            password VARCHAR(255) NOT NULL,
            plan VARCHAR(30) DEFAULT 'Free',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    `);

    await pool.query(`
        CREATE TABLE IF NOT EXISTS scans (
            id SERIAL PRIMARY KEY,
            user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
            url TEXT NOT NULL,
            malicious BOOLEAN DEFAULT FALSE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    `);

    await pool.query(`
        CREATE TABLE IF NOT EXISTS scam_reports (
            id SERIAL PRIMARY KEY,
            user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
            domain VARCHAR(253) NOT NULL,
            category VARCHAR(50) NOT NULL,
            details VARCHAR(500),
            status VARCHAR(30) DEFAULT 'unverified',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    `);

    await pool.query(`
        CREATE INDEX IF NOT EXISTS idx_scam_reports_domain_created
        ON scam_reports(domain, created_at DESC)
    `);

    await pool.query(`
        ALTER TABLE users
        ADD COLUMN IF NOT EXISTS role VARCHAR(20) DEFAULT 'user'
    `);

    await pool.query(`
        UPDATE users SET role = 'user' WHERE role IS NULL
    `);

    if (ADMIN_EMAIL) {
        await pool.query(
            `UPDATE users SET role = 'admin' WHERE LOWER(email) = $1`,
            [ADMIN_EMAIL]
        );
    }

    databaseReady = true;
    console.log("Database ready.");
}

/* AUTHENTICATION */
function authenticate(req, res, next) {
    const header = req.headers.authorization;

    if (!header || !header.startsWith("Bearer ")) {
        return res.status(401).json({ error: "Please log in first." });
    }

    try {
        req.user = jwt.verify(header.split(" ")[1], JWT_SECRET);
        next();
    } catch {
        return res.status(401).json({
            error: "Session expired. Please log in again."
        });
    }
}

/* ADMIN AUTHENTICATION */
async function adminOnly(req, res, next) {
    try {
        if (!ADMIN_EMAIL) {
            return res.status(503).json({
                error: "Administrator email is not configured."
            });
        }

        const result = await pool.query(
            `SELECT id, email, role FROM users WHERE id = $1`,
            [req.user.id]
        );

        if (!result.rows.length) {
            return res.status(403).json({
                error: "Administrator access denied."
            });
        }

        const user = result.rows[0];

        if (
            user.role !== "admin" ||
            user.email.toLowerCase() !== ADMIN_EMAIL
        ) {
            return res.status(403).json({
                error: "You do not have administrator permission."
            });
        }

        req.admin = user;
        next();
    } catch (error) {
        console.error("Admin authentication error:", error.message);
        res.status(500).json({
            error: "Could not verify administrator access."
        });
    }
}

/* REGISTER */
app.post("/api/register", async (req, res) => {
    try {
        const { name, email, password } = req.body;

        if (!name || !email || !password) {
            return res.status(400).json({
                error: "All fields are required."
            });
        }

        if (
            typeof password !== "string" ||
            password.length < 8 ||
            password.length > 72
        ) {
            return res.status(400).json({
                error: "Password must be between 8 and 72 characters."
            });
        }

        const cleanEmail = String(email).trim().toLowerCase();
        const cleanName = String(name).trim();

        if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(cleanEmail)) {
            return res.status(400).json({
                error: "Enter a valid email address."
            });
        }

        if (!cleanName || cleanName.length > 100) {
            return res.status(400).json({ error: "Enter a valid name." });
        }

        const hashedPassword = await bcrypt.hash(password, 12);
        const role =
            ADMIN_EMAIL && cleanEmail === ADMIN_EMAIL ? "admin" : "user";

        await pool.query(
            `INSERT INTO users (name, email, password, role)
             VALUES ($1, $2, $3, $4)`,
            [cleanName, cleanEmail, hashedPassword, role]
        );

        res.json({
            success: true,
            message: "Registration successful. Please log in."
        });
    } catch (error) {
        if (error.code === "23505") {
            return res.status(409).json({
                error: "Email already registered."
            });
        }

        console.error("Registration error:", error.message);
        res.status(500).json({ error: "Registration failed." });
    }
});

/* LOGIN */
app.post("/api/login", async (req, res) => {
    try {
        const { email, password } = req.body;

        const result = await pool.query(
            `SELECT * FROM users WHERE email = $1`,
            [String(email || "").trim().toLowerCase()]
        );

        if (!result.rows.length) {
            return res.status(401).json({
                error: "Invalid email or password."
            });
        }

        const user = result.rows[0];
        const valid = await bcrypt.compare(password || "", user.password);

        if (!valid) {
            return res.status(401).json({
                error: "Invalid email or password."
            });
        }

        const token = jwt.sign(
            { id: user.id },
            JWT_SECRET,
            { expiresIn: "7d" }
        );

        res.json({
            success: true,
            token,
            user: {
                id: user.id,
                name: user.name,
                email: user.email,
                plan: user.plan,
                role: user.role
            }
        });
    } catch (error) {
        console.error("Login error:", error.message);
        res.status(500).json({ error: "Login failed." });
    }
});
/* USER PROFILE */
app.get("/api/profile", authenticate, async (req, res) => {
    try {
        const result = await pool.query(
            `SELECT id, name, email, plan, role, created_at
             FROM users WHERE id = $1`,
            [req.user.id]
        );

        if (!result.rows.length) {
            return res.status(404).json({ error: "Account not found." });
        }

        res.json(result.rows[0]);
    } catch {
        res.status(500).json({ error: "Could not load profile." });
    }
});

/* OPENPHISH THREAT FEED */
async function updateThreatFeed() {
    try {
        const response = await fetch(
            "https://openphish.com/feed.txt",
            { signal: AbortSignal.timeout(15000) }
        );

        if (!response.ok) {
            throw new Error("Threat feed unavailable.");
        }

        const feedText = await response.text();
        const urls = feedText
            .split(/\r?\n/)
            .map(x => x.trim())
            .filter(x => x.startsWith("http"));

        const newURLs = new Set();
        const newDomains = new Set();

        for (const item of urls) {
            try {
                const parsed = new URL(item);
                newURLs.add(parsed.href);
                newDomains.add(parsed.hostname.toLowerCase());
            } catch {}
        }

        phishingURLs = newURLs;
        phishingDomains = newDomains;
        threatFeedReady = true;

        console.log("Threat feed loaded:", urls.length);
    } catch (error) {
        console.error("Threat feed error:", error.message);
    }
}

updateThreatFeed();
setInterval(updateThreatFeed, 12 * 60 * 60 * 1000);

/* URL VALIDATION */
function validateURL(value) {
    let parsed;

    try {
        parsed = new URL(value);
    } catch {
        throw new Error("Enter a valid website address.");
    }

    if (!["http:", "https:"].includes(parsed.protocol)) {
        throw new Error("Only HTTP and HTTPS websites are supported.");
    }

    if (!parsed.hostname || parsed.username || parsed.password) {
        throw new Error("Invalid website address.");
    }

    const hostname = parsed.hostname.toLowerCase();

    if (
        hostname === "localhost" ||
        hostname.endsWith(".localhost") ||
        hostname.endsWith(".local")
    ) {
        throw new Error("Private network addresses cannot be analysed.");
    }

    if (net.isIP(hostname)) {
        throw new Error("Please enter a public domain name.");
    }

    return parsed;
}

/* NORMALIZE DOMAIN */
function normalizeDomain(domain) {
    return domain.toLowerCase().replace(/^www\./, "");
}

/* COMMUNITY REPORT SUMMARY */
async function getCommunityReportSummary(domain) {
    try {
        const normalized = normalizeDomain(domain);

        const result = await pool.query(
            `SELECT
                COUNT(*)::INTEGER AS total_reports,
                COUNT(*) FILTER (WHERE status = 'verified')::INTEGER AS verified_reports,
                COUNT(*) FILTER (WHERE status = 'unverified')::INTEGER AS unverified_reports,
                COUNT(DISTINCT user_id)::INTEGER AS distinct_reporters
             FROM scam_reports
             WHERE domain = $1
             AND status IN ('unverified', 'verified')
             AND created_at >= NOW() - INTERVAL '180 days'`,
            [normalized]
        );

        const categories = await pool.query(
            `SELECT category, COUNT(*)::INTEGER AS count
             FROM scam_reports
             WHERE domain = $1
             AND status IN ('unverified', 'verified')
             AND created_at >= NOW() - INTERVAL '180 days'
             GROUP BY category ORDER BY count DESC`,
            [normalized]
        );

        const row = result.rows[0];
        let status = "NO_REPORTS";
        let message = "No community reports have been submitted.";

        if (row.total_reports > 0) {
            status = "UNVERIFIED_REPORTS";
            message = "Users have submitted reports about this website. Reports may be unverified.";
        }

        if (row.verified_reports > 0) {
            status = "VERIFIED_COMMUNITY_REPORTS";
            message = "Some community reports have been reviewed and verified by SafeClick administrators.";
        }

        if (row.distinct_reporters >= 3) {
            status = "MULTIPLE_COMMUNITY_REPORTS";
            message = "Multiple users have independently reported concerns about this website.";
        }

        return {
            available: true,
            totalReports: row.total_reports,
            verifiedReports: row.verified_reports,
            unverifiedReports: row.unverified_reports,
            distinctReporters: row.distinct_reporters,
            status,
            message,
            categories: categories.rows
        };
    } catch (error) {
        console.error("Community report error:", error.message);
        return {
            available: false,
            totalReports: 0,
            verifiedReports: 0,
            unverifiedReports: 0,
            distinctReporters: 0,
            status: "UNAVAILABLE",
            message: "Community report information is unavailable.",
            categories: []
        };
    }
}

/* SUBMIT FINANCIAL SCAM REPORT */
app.post("/api/scam-reports", authenticate, async (req, res) => {
    try {
        let { url, category, details } = req.body;

        if (!url || typeof url !== "string") {
            return res.status(400).json({
                error: "Enter the website address."
            });
        }

        url = url.trim();
        if (!/^https?:\/\//i.test(url)) url = "https://" + url;

        const parsed = validateURL(url);
        const domain = normalizeDomain(parsed.hostname);

        if (!REPORT_CATEGORIES.includes(category)) {
            return res.status(400).json({
                error: "Select a valid report category."
            });
        }

        if (details !== undefined && typeof details !== "string") {
            return res.status(400).json({
                error: "Report details must be text."
            });
        }

        details = String(details || "").trim();
        if (details.length > 500) {
            return res.status(400).json({
                error: "Details cannot exceed 500 characters."
            });
        }

        const dailyLimit = await pool.query(
            `SELECT COUNT(*)::INTEGER AS total
             FROM scam_reports
             WHERE user_id = $1
             AND created_at >= NOW() - INTERVAL '24 hours'`,
            [req.user.id]
        );

        if (dailyLimit.rows[0].total >= 5) {
            return res.status(429).json({
                error: "You have reached the daily report limit."
            });
        }

        const duplicate = await pool.query(
            `SELECT id FROM scam_reports
             WHERE user_id = $1 AND domain = $2
             AND created_at >= NOW() - INTERVAL '30 days'
             LIMIT 1`,
            [req.user.id, domain]
        );

        if (duplicate.rows.length) {
            return res.status(409).json({
                error: "You have already reported this website within the last 30 days."
            });
        }

        await pool.query(
            `INSERT INTO scam_reports (user_id, domain, category, details)
             VALUES ($1, $2, $3, $4)`,
            [req.user.id, domain, category, details || null]
        );

        res.status(201).json({
            success: true,
            message: "Your report has been submitted. It will appear as an unverified community report."
        });
    } catch (error) {
        console.error("Report submission error:", error.message);
        res.status(400).json({
            error: error.message || "Could not submit report."
        });
    }
});
/* DOMAIN AGE */
async function checkDomainAge(domain) {
    const endpoints = [
        "https://rdap.org/domain/" + encodeURIComponent(domain)
    ];

    // Verisign provides an authoritative RDAP endpoint for .com and .net.
    const tld = domain.split(".").pop();
    if (tld === "com" || tld === "net") {
        endpoints.push(
            "https://rdap.verisign.com/" + tld + "/v1/domain/" + encodeURIComponent(domain)
        );
    }

    for (const endpoint of endpoints) {
        try {
            const response = await fetch(endpoint, {
                signal: AbortSignal.timeout(7000),
                headers: { Accept: "application/rdap+json, application/json" }
            });
            if (!response.ok) continue;

            const data = await response.json();
            const event = (data.events || []).find(
                item => item.eventAction === "registration"
            );
            if (!event) continue;

            const registrationDate = new Date(event.eventDate);
            if (Number.isNaN(registrationDate.getTime())) continue;

            const ageDays = Math.floor(
                (Date.now() - registrationDate.getTime()) / 86400000
            );
            if (ageDays < 0) continue;

            return {
                available: true,
                registered: registrationDate.toISOString(),
                ageDays,
                ageYears: Math.floor(ageDays / 365)
            };
        } catch {
            // Try the next RDAP provider before reporting unavailable.
        }
    }

    return {
        available: false,
        message: "Domain registration information could not be retrieved from available RDAP services."
    };
}

/* DNS ANALYSIS WITH BACKUP DNS-OVER-HTTPS PROVIDERS AND DIAGNOSTIC LOGGING */
async function checkDNS(domain) {
    const failures = [];

    try {
        const records = await dns.lookup(domain, {
            all: true,
            verbatim: true
        });

        if (records.length) {
            return {
                available: true,
                addresses: [...new Set(records.map(record => record.address))],
                method: "system DNS"
            };
        }
        failures.push("system DNS returned no records");
    } catch (error) {
        failures.push(`system DNS: ${error.code || error.name || "lookup failed"}`);
    }

    const providers = [
        "https://cloudflare-dns.com/dns-query",
        "https://dns.google/resolve"
    ];
    const addresses = new Set();

    for (const provider of providers) {
        const providerName = provider.includes("cloudflare") ? "Cloudflare" : "Google";
        try {
            for (const type of ["A", "AAAA"]) {
                const endpoint = provider + "?name=" +
                    encodeURIComponent(domain) + "&type=" + type;
                const response = await fetch(endpoint, {
                    signal: AbortSignal.timeout(8000),
                    headers: provider.includes("cloudflare")
                        ? { Accept: "application/dns-json" }
                        : { Accept: "application/json" }
                });

                if (!response.ok) {
                    failures.push(`${providerName} ${type}: HTTP ${response.status}`);
                    continue;
                }

                const data = await response.json();
                for (const answer of data.Answer || []) {
                    if ((answer.type === 1 || answer.type === 28) && answer.data) {
                        addresses.add(answer.data);
                    }
                }
            }

            if (addresses.size) {
                return {
                    available: true,
                    addresses: [...addresses],
                    method: `${providerName} DNS-over-HTTPS`
                };
            }
        } catch (error) {
            failures.push(`${providerName}: ${error.code || error.name || "request failed"}`);
        }
    }

    console.warn(`[SafeClick DNS] Lookup failed for ${domain}: ${failures.join("; ")}`);
    return {
        available: false,
        message: "DNS records could not be retrieved from the system or backup DNS providers."
    };
}

/* SSL CERTIFICATE */
async function checkSSL(domain) {
    return new Promise(resolve => {
        let finished = false;
        let socket;

        function finish(result) {
            if (finished) return;
            finished = true;
            clearTimeout(timer);

            if (socket && !socket.destroyed) socket.destroy();
            resolve(result);
        }

        const timer = setTimeout(() => {
            finish({
                available: false,
                valid: false,
                message: "SSL check timed out."
            });
        }, 7000);

        try {
            socket = tls.connect({
                host: domain,
                port: 443,
                servername: domain,
                rejectUnauthorized: false,
                timeout: 6000
            });

            socket.on("secureConnect", function () {
                const certificate = socket.getPeerCertificate();

                const valid =
                    socket.authorized === true &&
                    !!certificate &&
                    Object.keys(certificate).length > 0;

                finish({
                    available: true,
                    valid,
                    issuer: certificate.issuer?.O || "Unknown",
                    expires: certificate.valid_to || null,
                    message: valid
                        ? "Valid SSL certificate."
                        : "SSL certificate could not be verified."
                });
            });

            socket.on("error", () => {
                finish({
                    available: false,
                    valid: false,
                    message: "SSL certificate unavailable."
                });
            });

            socket.on("timeout", () => {
                finish({
                    available: false,
                    valid: false,
                    message: "SSL check timed out."
                });
            });
        } catch {
            finish({
                available: false,
                valid: false,
                message: "SSL certificate unavailable."
            });
        }
    });
}

/* VIRUSTOTAL REPUTATION */
async function checkVirusTotal(url) {
    const apiKey = process.env.VIRUSTOTAL_API_KEY;

    if (!apiKey) {
        return {
            available: false,
            scanned: false,
            message: "VirusTotal API key not configured."
        };
    }

    try {
        const id = Buffer.from(url, "utf8")
            .toString("base64")
            .replace(/=/g, "")
            .replace(/\+/g, "-")
            .replace(/\//g, "_");

        const response = await fetch(
            `https://www.virustotal.com/api/v3/urls/${id}`,
            {
                headers: { "x-apikey": apiKey },
                signal: AbortSignal.timeout(12000)
            }
        );

        if (response.status === 404) {
            return {
                available: false,
                scanned: false,
                message: "No existing VirusTotal report."
            };
        }

        if (!response.ok) {
            return {
                available: false,
                scanned: false,
                message: "VirusTotal check unavailable."
            };
        }

        const data = await response.json();
        const stats = data.data?.attributes?.last_analysis_stats || {};

        return {
            available: true,
            scanned: true,
            malicious: stats.malicious || 0,
            suspicious: stats.suspicious || 0,
            harmless: stats.harmless || 0,
            undetected: stats.undetected || 0
        };
    } catch {
        return {
            available: false,
            scanned: false,
            message: "VirusTotal could not be reached."
        };
    }
}

/* THREAT DETECTION */
function checkThreats(url, domain) {
    const exactMatch = phishingURLs.has(url);

    const domainMatch = [...phishingDomains].some(
        item => domain === item || domain.endsWith("." + item)
    );

    return {
        available: threatFeedReady,
        malicious: exactMatch || domainMatch,
        exactMatch,
        domainMatch,
        message: threatFeedReady
            ? "Threat feed checked."
            : "Threat feed unavailable."
    };
}

/* ANALYSIS COVERAGE */
function calculateCoverage(checks) {
    const total = Object.keys(checks).length;

    const completed = Object.values(checks).filter(
        value => value === true
    ).length;

    const percentage = Math.round((completed / total) * 100);

    return {
        completed,
        total,
        percentage,
        status: percentage >= 80 ? "SUFFICIENT" : "LIMITED"
    };
}
/* IMPROVED WEBSITE RISK ANALYSIS */
async function analyzeWebsite(value) {
    const parsed = validateURL(value);
    const domain = parsed.hostname.toLowerCase();
    const hostname = domain.replace(/^www\./, "");
    const threats = checkThreats(parsed.href, domain);

    const [
        domainAge,
        dnsInfo,
        ssl,
        reputation,
        communityReports
    ] = await Promise.all([
        checkDomainAge(domain),
        checkDNS(domain),
        parsed.protocol === "https:"
            ? checkSSL(domain)
            : Promise.resolve({
                available: true,
                valid: false,
                message: "Website does not use HTTPS."
            }),
        checkVirusTotal(parsed.href),
        getCommunityReportSummary(hostname)
    ]);

    let riskScore = 0;
    const warnings = [];
    const riskFactors = [];

    function addRisk(points, title, explanation) {
        riskScore += points;
        riskFactors.push({
            points,
            title,
            explanation
        });
        warnings.push(explanation);
    }

    /* KNOWN PHISHING THREATS */
    if (threats.malicious) {
        addRisk(
            90,
            "Known phishing threat",
            "This website matches an entry in the phishing threat feed."
        );
    }

    /* DOMAIN AGE */
    if (domainAge.available) {
        if (domainAge.ageDays < 30) {
            addRisk(
                20,
                "Very recently registered domain",
                "The domain was registered less than 30 days ago."
            );
        } else if (domainAge.ageDays < 90) {
            addRisk(
                10,
                "Recently registered domain",
                "The domain was registered less than 90 days ago."
            );
        } else if (domainAge.ageDays < 180) {
            addRisk(
                4,
                "Relatively new domain",
                "The domain is less than six months old."
            );
        }
    } else {
        warnings.push("Domain registration age could not be verified.");
    }

    /* HTTPS AND SSL */
    if (parsed.protocol === "http:") {
        addRisk(
            15,
            "Unencrypted connection",
            "This website uses HTTP instead of encrypted HTTPS."
        );
    } else if (ssl.available && !ssl.valid) {
        addRisk(
            20,
            "SSL certificate warning",
            "The website's SSL certificate could not be verified."
        );
    } else if (!ssl.available) {
        warnings.push("SSL security information is unavailable.");
    }

    /* SUSPICIOUS DOMAIN FORMATTING */
    if (hostname.includes("xn--")) {
        addRisk(
            25,
            "Internationalized domain warning",
            "The domain contains encoded international characters that deserve closer inspection."
        );
    }

    const labels = hostname.split(".");

    if (labels.length > 5) {
        addRisk(
            8,
            "Unusually deep subdomain structure",
            "The website uses many subdomain levels."
        );
    }

    /* SUSPICIOUS WORDING */
    const lureWords = [
        "login",
        "verify",
        "wallet",
        "password",
        "signin",
        "claim",
        "bonus",
        "withdraw",
        "secure-update"
    ];

    const hostnameHasLure = lureWords.some(
        word => hostname.includes(word)
    );

    const pathHasLure = lureWords.some(
        word => parsed.pathname.toLowerCase().includes(word)
    );

    if (hostnameHasLure) {
        addRisk(
            8,
            "Sensitive-action wording in domain",
            "The domain contains wording commonly used in account or payment lures. This alone does not prove fraud."
        );
    }

    if (pathHasLure) {
        addRisk(
            4,
            "Sensitive-action wording in URL path",
            "The URL path contains account or payment-related wording. This alone does not prove fraud."
        );
    }

    /* LONG URL */
    if (parsed.href.length > 180) {
        addRisk(
            5,
            "Unusually long web address",
            "The web address is unusually long and should be inspected carefully."
        );
    }

    /* URL SHORTENERS */
    const shorteners = [
        "bit.ly",
        "tinyurl.com",
        "t.co",
        "is.gd",
        "cutt.ly",
        "rb.gy",
        "shorturl.at"
    ];

    if (shorteners.includes(hostname)) {
        addRisk(
            5,
            "Shortened web address",
            "The shortened address hides its final destination."
        );
    }

    /* VIRUSTOTAL */
    if (reputation.available) {
        if (reputation.malicious > 0) {
            addRisk(
                50,
                "VirusTotal malicious detections",
                `VirusTotal reports ${reputation.malicious} malicious detection(s).`
            );
        }

        if (reputation.suspicious > 0) {
            addRisk(
                15,
                "VirusTotal suspicious detections",
                `VirusTotal reports ${reputation.suspicious} suspicious detection(s).`
            );
        }
    } else {
        warnings.push(
            reputation.message || "VirusTotal reputation is unavailable."
        );
    }

    /* COMMUNITY REPORTS */
    if (communityReports.verifiedReports > 0) {
        addRisk(
            15,
            "Verified community reports",
            "SafeClick administrators have verified one or more community reports about this domain."
        );
    } else if (communityReports.distinctReporters >= 3) {
        addRisk(
            8,
            "Multiple independent community reports",
            "Multiple users have reported concerns about this domain. These reports still require review."
        );
    } else if (communityReports.totalReports > 0) {
        warnings.push(
            "Unverified community reports exist. They are not proof that this website is fraudulent."
        );
    }

    /* DNS */
    if (!dnsInfo.available) {
        warnings.push("DNS information could not be verified.");
    }

    /* THREAT FEED */
    if (!threats.available) {
        warnings.push("The phishing threat feed is currently unavailable.");
    }

    /* COVERAGE */
    const coverage = calculateCoverage({
        phishingFeed: threats.available,
        domainAge: domainAge.available,
        dns: dnsInfo.available,
        ssl: ssl.available,
        virusTotal: reputation.available
    });

    riskScore = Math.min(100, riskScore);

    let riskLevel;

    if (riskScore >= 60) {
        riskLevel = "HIGH";
    } else if (riskScore >= 25) {
        riskLevel = "MEDIUM";
    } else if (coverage.percentage < 80) {
        riskLevel = "INCONCLUSIVE";
    } else {
        riskLevel = "LOW";
    }

    if (!riskFactors.length && riskLevel === "LOW") {
        warnings.push(
            "No major warning indicators were found by the checks that completed."
        );
    }

    return {
        website: parsed.href,
        domain,
        analysisDate: new Date().toISOString(),

        risk: {
            score: riskScore,
            level: riskLevel,
            confidence: coverage.status,
            factors: riskFactors
        },

        analysisCoverage: coverage,
        phishing: threats,
        domainAge,
        dns: dnsInfo,
        ssl,
        reputation,
        communityReports,
        warnings,

        disclaimer:
            "The risk score is an indicator based on available checks, not a probability of fraud. Some warning signs can occur on legitimate websites. A low score does not guarantee safety, and an inconclusive result means there was not enough information to make a reliable assessment."
    };
}

/* ADVANCED ANALYSIS ENDPOINT */
app.post("/api/analyze-website", authenticate, async (req, res) => {
    try {
        const { url } = req.body;

        if (!url || typeof url !== "string") {
            return res.status(400).json({
                error: "Enter a website address."
            });
        }

        const result = await analyzeWebsite(url);

        const malicious =
            result.phishing.malicious ||
            (
                result.reputation.available &&
                result.reputation.malicious > 0
            );

        await pool.query(
            `INSERT INTO scans (user_id, url, malicious)
             VALUES ($1, $2, $3)`,
            [req.user.id, result.website, malicious]
        );

        res.json({
            success: true,
            analysis: result
        });
    } catch (error) {
        console.error("Analysis error:", error.message);
        res.status(400).json({
            error: error.message || "Website analysis failed."
        });
    }
});

/* MAIN WEBSITE SCANNER */
app.post("/api/check-url", authenticate, async (req, res) => {
    try {
        let value = String(req.body.url || "").trim();

        if (!value) {
            return res.status(400).json({
                success: false,
                error: "Enter a website address."
            });
        }

        if (!/^https?:\/\//i.test(value)) {
            value = "https://" + value;
        }

        const analysis = await analyzeWebsite(value);

        const malicious =
            analysis.phishing.malicious ||
            (
                analysis.reputation.available &&
                analysis.reputation.malicious > 0
            );

        await pool.query(
            `INSERT INTO scans (user_id, url, malicious)
             VALUES ($1, $2, $3)`,
            [req.user.id, analysis.website, malicious]
        );

        let message;

        if (analysis.risk.level === "HIGH") {
            message = "High risk indicators detected. Avoid this website.";
        } else if (analysis.risk.level === "MEDIUM") {
            message = "Warning: This website has suspicious indicators.";
        } else if (analysis.risk.level === "INCONCLUSIVE") {
            message = "There is not enough information to establish whether this website is safe.";
        } else {
            message = "No major threats detected by the available checks. Stay cautious.";
        }

        res.json({
            success: true,
            malicious,
            message,
            analysis
        });
    } catch (error) {
        console.error("Website scanning error:", error.message);
        res.status(400).json({
            success: false,
            error: error.message || "Website analysis failed."
        });
    }
});
/* SCAN HISTORY */
app.get("/api/scan-history", authenticate, async (req, res) => {
    try {
        const result = await pool.query(
            `SELECT id, url, malicious, created_at
             FROM scans
             WHERE user_id = $1
             ORDER BY created_at DESC
             LIMIT 100`,
            [req.user.id]
        );

        res.json({ scans: result.rows });
    } catch (error) {
        console.error("Scan history error:", error.message);
        res.status(500).json({
            error: "Could not load scan history."
        });
    }
});

/* ADMIN OVERVIEW */
app.get("/api/admin/overview", authenticate, adminOnly, async (req, res) => {
    try {
        const [users, scans, reports, pending] = await Promise.all([
            pool.query("SELECT COUNT(*)::INTEGER AS total FROM users"),
            pool.query("SELECT COUNT(*)::INTEGER AS total FROM scans"),
            pool.query("SELECT COUNT(*)::INTEGER AS total FROM scam_reports"),
            pool.query(
                "SELECT COUNT(*)::INTEGER AS total FROM scam_reports WHERE status = 'unverified'"
            )
        ]);

        res.json({
            success: true,
            overview: {
                totalUsers: users.rows[0].total,
                totalScans: scans.rows[0].total,
                totalReports: reports.rows[0].total,
                pendingReports: pending.rows[0].total
            }
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({
            error: "Could not load admin overview."
        });
    }
});

/* ADMIN USERS */
app.get("/api/admin/users", authenticate, adminOnly, async (req, res) => {
    try {
        const result = await pool.query(
            `SELECT id, name, email, plan, role, created_at
             FROM users
             ORDER BY created_at DESC
             LIMIT 200`
        );

        res.json({ success: true, users: result.rows });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: "Could not load users." });
    }
});

/* ADMIN SCANS */
app.get("/api/admin/scans", authenticate, adminOnly, async (req, res) => {
    try {
        const result = await pool.query(
            `SELECT scans.id, scans.url, scans.malicious, scans.created_at,
                    users.name AS user_name,
                    users.email AS user_email
             FROM scans
             LEFT JOIN users ON scans.user_id = users.id
             ORDER BY scans.created_at DESC
             LIMIT 200`
        );

        res.json({ success: true, scans: result.rows });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: "Could not load scans." });
    }
});

/* ADMIN COMMUNITY REPORTS */
app.get("/api/admin/reports", authenticate, adminOnly, async (req, res) => {
    try {
        const result = await pool.query(
            `SELECT scam_reports.id, scam_reports.domain,
                    scam_reports.category, scam_reports.details,
                    scam_reports.status, scam_reports.created_at,
                    users.name AS reporter_name,
                    users.email AS reporter_email
             FROM scam_reports
             LEFT JOIN users ON scam_reports.user_id = users.id
             ORDER BY scam_reports.created_at DESC
             LIMIT 200`
        );

        res.json({ success: true, reports: result.rows });
    } catch (error) {
        console.error(error);
        res.status(500).json({
            error: "Could not load community reports."
        });
    }
});

/* ADMIN REPORT MODERATION */
app.patch(
    "/api/admin/reports/:id/status",
    authenticate,
    adminOnly,
    async (req, res) => {
        try {
            const reportId = Number(req.params.id);
            const { status } = req.body;

            if (!Number.isInteger(reportId) || reportId < 1) {
                return res.status(400).json({
                    error: "Invalid report ID."
                });
            }

            if (!["unverified", "verified", "rejected"].includes(status)) {
                return res.status(400).json({
                    error: "Invalid report status."
                });
            }

            const result = await pool.query(
                `UPDATE scam_reports
                 SET status = $1
                 WHERE id = $2
                 RETURNING id, domain, category, status`,
                [status, reportId]
            );

            if (!result.rows.length) {
                return res.status(404).json({
                    error: "Report not found."
                });
            }

            res.json({
                success: true,
                message: "Report status updated.",
                report: result.rows[0]
            });
        } catch (error) {
            console.error(error);
            res.status(500).json({
                error: "Could not update report status."
            });
        }
    }
);

/* HEALTH CHECK */
app.get("/api/health", (req, res) => {
    res.json({
        status: "SafeClick is running",
        databaseReady,
        threatsLoaded: phishingURLs.size,
        threatFeedReady,
        advancedAnalysis: true,
        adminDashboard: true,
        adminConfigured: Boolean(ADMIN_EMAIL),
        virusTotalConfigured: Boolean(process.env.VIRUSTOTAL_API_KEY)
    });
});

/* START SERVER */
async function startServer() {
    try {
        await initializeDatabase();

        app.listen(PORT, "0.0.0.0", () => {
            console.log("SafeClick running on port " + PORT);
        });
    } catch (error) {
        console.error("Startup error:", error);
        process.exit(1);
    }
}

startServer();
