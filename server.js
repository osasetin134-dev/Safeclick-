const express = require("express");

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json({ limit: "10kb" }));
app.use(express.static(__dirname));

const FEED_URL =
  "https://raw.githubusercontent.com/openphish/public_feed/main/feed.txt";

let phishingURLs = new Set();
let phishingDomains = new Set();
let lastUpdated = 0;

async function updateFeed() {
  const twelveHours = 12 * 60 * 60 * 1000;

  if (Date.now() - lastUpdated < twelveHours &&
      phishingURLs.size > 0) {
    return;
  }

  console.log("Updating phishing security database...");

  const response = await fetch(FEED_URL, {
    signal: AbortSignal.timeout(20000)
  });

  if (!response.ok) {
    throw new Error("Unable to download OpenPhish feed.");
  }

  const text = await response.text();

  const urls = new Set();
  const domains = new Set();

  for (const line of text.split(/\r?\n/)) {
    try {
      const parsed = new URL(line.trim());

      if (!["http:", "https:"].includes(parsed.protocol)) continue;

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

  console.log(`Security database updated: ${urls.size} URLs loaded.`);
}

app.get("/api/health", (req, res) => {
  res.json({
    status: "online",
    databaseLoaded: phishingURLs.size > 0,
    threatsLoaded: phishingURLs.size,
    lastUpdated: lastUpdated || null
  });
});

app.post("/api/check-url", async (req, res) => {
  try {
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
      phishingDomains.has(hostname);

    console.log(`Checked: ${hostname} | Threat: ${malicious}`);

    res.json({
      configured: true,
      malicious,
      message: malicious
        ? "Danger! This domain appears in the phishing database."
        : "No known threat detected. This does not guarantee safety.",
      databaseLoaded: true
    });

  } catch (error) {
    console.error("Scanning error:", error.message);

    res.status(503).json({
      configured: false,
      error: "Security scanning is temporarily unavailable."
    });
  }
});

app.listen(PORT, () => {
  console.log(`SafeClick running on port ${PORT}`);
});
