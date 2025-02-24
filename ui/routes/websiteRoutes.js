const express = require("express");
const axios = require("axios");
const path = require("path");

const router = express.Router();
const FASTAPI_URL = `${process.env.backend_protocol}://${process.env.backend_host}:${process.env.backend_port}`;

// Route to serve the website analysis HTML page
router.get("/website-analysis", (req, res) => {
    res.sendFile(path.join(__dirname, "..", "Template", "website_analysis.html"));
});

// Route to handle website analysis requests
router.post("/analyze-website", async (req, res) => {
    try {
        const { website } = req.body;

        if (!website) {
            return res.status(400).json({ error: "Website URL is required" });
        }

        // Forward request to FastAPI backend
        const response = await axios.post(`${FASTAPI_URL}/analyze-website`, { website });

        res.json(response.data);
    } catch (error) {
        console.error("❌ Error analyzing website:", error.message);

        const status = error.response ? error.response.status : 500;
        res.status(status).json({ error: "Error analyzing website", details: error.message });
    }
});

module.exports = router;
