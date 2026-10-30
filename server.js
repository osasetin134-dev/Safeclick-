const express = require("express");
const app = express();
const PORT = process.env.PORT || 3000;
app.use(express.json({ limit: "10kb" }));
app.use(express.static(__dirname));
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
    const apiKey = process.env.GOOGLE_SAFE_BROWSING_API_KEY;
    if (!apiKey) {
      return res.json({
        configured: false,
        malicious: false,
        message: "Security scanning is not configured."
      });
    }
    const response = await fetch(
      `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${apiKey}`,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json"
        },
        body: JSON.stringify({
          client: {
            clientId: "safeclick",
            clientVersion: "1.0"
          },
          threatInfo: {
            threatTypes: [
              "MALWARE",
              "SOCIAL_ENGINEERING",
              "UNWANTED_SOFTWARE",
              "POTENTIALLY_HARMFUL_APPLICATION"
            ],
            platformTypes: ["ANY_PLATFORM"],
            threatEntryTypes: ["URL"],
            threatEntries: [{ url: parsed.href }]
          }
        })
      }
    );
    if (!response.ok) {
      throw new Error("Security provider unavailable.");
    }
    const data = await response.json();
    const matches = Array.isArray(data.matches) &&
      data.matches.length > 0;
    res.json({
      configured: true,
      malicious: matches,
      message: matches
        ? "Known threat detected."
        : "No known threat detected. This does not guarantee safety."
    });
  } catch (error) {
    res.status(503).json({
      error: "Security check temporarily unavailable."
    });
  }
});
app.listen(PORT, () => {
  console.log(`SafeClick running on port ${PORT}`);
});
