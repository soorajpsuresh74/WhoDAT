const express = require("express");
const axios = require("axios");
const path = require("path");

const router = express.Router();
const FASTAPI_URL = `${process.env.backend_protocol}://${process.env.backend_host}:${process.env.backend_port}`;

router.get("/ip-analysis", (req, res) => {
  res.sendFile(path.join(__dirname, "..", "Template", "ip_analysis.html"));
});

router.post("/analyze-ip", async (req, res) => {
  try {
    const { ip } = req.body;
    if (!ip) {
      return res.status(400).json({ error: "IP address is required" });
    }
    const response = await axios.post(`${FASTAPI_URL}/analyze-ip`, { ip });
    res.json(response.data);
  } catch (error) {
    console.error("❌ Error analyzing IP:", error.message);

    const status = error.response ? error.response.status : 500;
    res
      .status(status)
      .json({ error: "Error analyzing IP", details: error.message });
  }
});

module.exports = router;