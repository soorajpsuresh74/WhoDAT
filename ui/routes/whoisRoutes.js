const express = require("express");
const axios = require("axios");
const path = require("path");

const router = express.Router();
const FASTAPI_URL = `${process.env.backend_protocol}://${process.env.backend_host}:${process.env.backend_port}`;

// Route to serve the website analysis HTML page
router.get("/whois-analysis", (req, res) => {
    res.sendFile(path.join(__dirname, "..", "Template", "whois_analysis.html"));
});

// Route to handle website analysis requests
router.post("/whois-lookup", async (req, res) => {
    try {
        const { domain } = req.body;

        if (!domain) {
            return res.status(400).json({ error: "domain is required" });
        }

        // Forward request to FastAPI backend
        const response = await axios.post(`${FASTAPI_URL}/analyze-whois`, { domain });
        console.log(response.data)
        res.json(response.data);
    } catch (error) {
        console.error("❌ Error analyzing domain:", error.message);

        const status = error.response ? error.response.status : 500;
        res.status(status).json({ error: "Error analyzing domain", details: error.message });
    }
});

module.exports = router;
