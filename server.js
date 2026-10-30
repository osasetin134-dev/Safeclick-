const express = require("express");
const { Pool } = require("pg");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json({ limit: "10kb" }));
app.use(express.static(__dirname));

const pool = new Pool({
  connectionString: process.env.DATABASE_URL
});

const JWT_SECRET = process.env.JWT_SECRET;

let databaseReady = false;
let phishingURLs = new Set();
let phishingDomains = new Set();
let lastUpdated = 0;

const FEED_URL =
  "https://raw.githubusercontent.com/openphish/public_feed/main/feed.txt";

// DATABASE SETUP

async function initializeDatabase() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      name VARCHAR(100) NOT NULL,
      email VARCHAR(255) UNIQUE NOT NULL,
      password VARCHAR(255) NOT NULL,
      plan VARCHAR(30) DEFAULT 'free',
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS scans (
      id SERIAL PRIMARY KEY,
      user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      url TEXT NOT NULL,
      malicious BOOLEAN NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `);

  databaseReady = true;
  console.log("SafeClick database connected successfully.");
}

// AUTHENTICATION

function authenticate(req, res, next) {
  const header = req.headers.authorization;

  if (!header || !header.startsWith("Bearer ")) {
    return res.status(401).json({
      error: "Please log in first."
    });
  }

  try {
    const token = header.split(" ")[1];

    req.user = jwt.verify(token, JWT_SECRET);

    next();
  } catch {
    return res.status(401).json({
      error: "Invalid or expired login session."
    });
  }
}

// REGISTER

app.post("/api/register", async (req, res) => {
  try {
    if (!databaseReady) {
      return res.status(503).json({
        error: "Database is unavailable."
      });
    }

    const { name, email, password } = req.body;

    if (!name || !email || !password) {
      return res.status(400).json({
        error: "All fields are required."
      });
    }

    if (
      typeof name !== "string" ||
      typeof email !== "string" ||
      typeof password !== "string"
    ) {
      return res.status(400).json({
        error: "Invalid registration details."
      });
    }

    if (name.trim().length > 100 ||
        email.trim().length > 255) {
      return res.status(400).json({
        error: "Name or email is too long."
      });
    }

    if (password.length < 8 || password.length > 72) {
      return res.status(400).json({
        error: "Password must contain 8 to 72 characters."
      });
    }

    const cleanEmail = email.trim().toLowerCase();

    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(cleanEmail)) {
      return res.status(400).json({
        error: "Please enter a valid email address."
      });
    }

    const hashedPassword = await bcrypt.hash(password, 12);

    const result = await pool.query(
      `INSERT INTO users (name, email, password)
       VALUES ($1, $2, $3)
       RETURNING id, name, email, plan`,
      [name.trim(), cleanEmail, hashedPassword]
    );

    res.status(201).json({
      message: "Account created successfully.",
      user: result.rows[0]
    });

  } catch (error) {
    if (error.code === "23505") {
      return res.status(409).json({
        error: "An account with this email already exists."
      });
    }

    console.error("Registration error:", error.message);

    res.status(500).json({
      error: "Unable to create account."
    });
  }
});

// LOGIN

app.post("/api/login", async (req, res) => {
  try {
    if (!databaseReady) {
      return res.status(503).json({
        error: "Database is unavailable."
      });
    }

    const { email, password } = req.body;

    if (typeof email !== "string" ||
        typeof password !== "string") {
      return res.status(400).json({
        error: "Email and password are required."
      });
    }

    const result = await pool.query(
      "SELECT * FROM users WHERE email = $1",
      [email.trim().toLowerCase()]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({
        error: "Invalid email or password."
      });
    }

    const user = result.rows[0];

    const validPassword = await bcrypt.compare(
      password,
      user.password
    );

    if (!validPassword) {
      return res.status(401).json({
        error: "Invalid email or password."
      });
    }

    if (!JWT_SECRET) {
      throw new Error("JWT_SECRET is not configured.");
    }

    const token = jwt.sign(
      {
        id: user.id,
        email: user.email
      },
      JWT_SECRET,
      { expiresIn: "1h" }
    );

    res.json({
      message: "Login successful.",
      token,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        plan: user.plan
      }
    });

  } catch (error) {
    console.error("Login error:", error.message);

    res.status(500).json({
      error: "Unable to log in."
    });
  }
});

// USER PROFILE

app.get("/api/profile", authenticate, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, name, email, plan, created_at
       FROM users WHERE id = $1`,
      [req.user.id]
    );

    if (!result.rows.length) {
      return res.status(404).json({
        error: "User not found."
      });
    }

    res.json({
      user: result.rows[0]
    });

  } catch (error) {
    console.error("Profile error:", error.message);

    res.status(500).json({
      error: "Unable to load profile."
    });
  }
});

// UPDATE PHISHING DATABASE

async function updateFeed() {
  const twelveHours = 12 * 60 * 60 * 1000;

  if (
    Date.now() - lastUpdated < twelveHours &&
    phishingURLs.size > 0
  ) {
    return;
  }

  console.log("Updating phishing security database...");

  const response = await fetch(FEED_URL, {
    signal: AbortSignal.timeout(20000)
  });

  if (!response.ok) {
    throw new Error("Unable to download phishing database.");
  }

  const text = await response.text();

  const urls = new Set();
  const domains = new Set();

  for (const line of text.split(/\r?\n/)) {
    try {
      const parsed = new URL(line.trim());

      if (!["http:", "https:"].includes(parsed.protocol)) {
        continue;
      }

      urls.add(parsed.href);
      domains.add(parsed.hostname.toLowerCase());

    } catch {}
  }

  if (urls.size === 0) {
    throw new Error("Phishing database is empty.");
  }

  phishingURLs = urls;
  phishingDomains = domains;
  lastUpdated = Date.now();

  console.log(
    `Security database updated: ${urls.size} URLs loaded.`
  );
}

// SCAN URL AND SAVE HISTORY

app.post("/api/check-url", authenticate, async (req, res) => {
  try {
    if (!databaseReady) {
      return res.status(503).json({
        error: "Database is unavailable."
      });
    }

    const { url } = req.body;

    if (!url || typeof url !== "string") {
      return res.status(400).json({
        error: "Please provide a valid URL."
      });
    }

    let parsed;

    try {
      parsed = new URL(url);
    } catch {
      return res.status(400).json({
        error: "Invalid URL."
      });
    }

    if (!["http:", "https:"].includes(parsed.protocol)) {
      return res.status(400).json({
        error: "Only HTTP and HTTPS links are supported."
      });
    }

    await updateFeed();

    const hostname = parsed.hostname.toLowerCase();

    const malicious =
      phishingURLs.has(parsed.href) ||
      [...phishingDomains].some(domain =>
        hostname === domain || hostname.endsWith("." + domain)
      );

    await pool.query(
      `INSERT INTO scans (user_id, url, malicious)
       VALUES ($1, $2, $3)`,
      [req.user.id, parsed.href, malicious]
    );

    res.json({
      malicious,
      message: malicious
        ? "Danger! This URL appears in the phishing database."
        : "No known threat detected. This does not guarantee safety."
    });

  } catch (error) {
    console.error("Scanning error:", error.message);

    res.status(503).json({
      error: "Security scanning is temporarily unavailable."
    });
  }
});

// USER SCAN HISTORY

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

    res.json({
      history: result.rows
    });

  } catch (error) {
    console.error("History error:", error.message);

    res.status(500).json({
      error: "Unable to load scan history."
    });
  }
});

// HEALTH CHECK

app.get("/api/health", (req, res) => {
  res.json({
    status: "online",
    databaseReady,
    databaseLoaded: phishingURLs.size > 0,
    threatsLoaded: phishingURLs.size,
    lastUpdated: lastUpdated || null
  });
});

// START SERVER

app.listen(PORT, async () => {
  console.log(`SafeClick running on port ${PORT}`);

  try {
    if (!process.env.DATABASE_URL) {
      throw new Error("DATABASE_URL is missing.");
    }

    if (!JWT_SECRET) {
      throw new Error("JWT_SECRET is missing.");
    }

    await initializeDatabase();

  } catch (error) {
    databaseReady = false;
    console.error(
      "Database initialization failed:",
      error.message
    );
  }
});
