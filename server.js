const express = require("express");

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json({ limit: "10kb" }));
app.use(express.static(__dirname));

const FEED_URL =
  "https://raw.githubusercontent.com/openphish/public_feed/main/feed.txt";

let phishingURLs = new Set();
let lastUpdated = 0;

async function updateFeed() {
  const twelveHours = 12 * 60 * 60 * 1000;

  if (Date.now() - lastUpdated < twelveHours &&
      phishingURLs.size > 0) {
    return;
  }

  const response = await fetch(FEED_URL, {
    signal: AbortSignal.timeout(15000)
  });

  if (!response.ok) {
    throw new Error("Unable to download security feed.");
  }

  const text = await response.text();

  phishingURLs = new Set(
    text.split(/\r?\n/)
      .map(url => url.trim())
      .filter(url => url.startsWith("http://") ||
                     url.startsWith("https://"))
      .map(url => {
        try {
          return new URL(url).href;
        } catch {
          return null;
        }
      })
      .filter(Boolean)
  );

  lastUpdated = Date.now();
}

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

    const malicious = phishingURLs.has(parsed.href);

    res.json({
      configured: true,
      malicious,
      message: malicious
        ? "Warning! This URL appears in the phishing threat database."
        : "This URL was not found in the phishing database. This does not guarantee safety."
    });

  } catch (error) {
    res.status(503).json({
      error: "Security scanning is temporarily unavailable."
    });
  }
});

app.listen(PORT, () => {
  console.log(`SafeClick running on port ${PORT}`);
});
