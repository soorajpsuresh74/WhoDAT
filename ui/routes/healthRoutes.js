const express = require("express");
const axios = require("axios");

const router = express.Router();
const FASTAPI_URL = `${process.env.backend_protocol}://${process.env.backend_host}:${process.env.backend_port}`;

router.get("/api/health", async (req, res) => {
  try {
    const response = await axios.get(`${FASTAPI_URL}/health`);
    res.json(response.data);
  } catch (error) {
    console.error("❌ Health check failed:", error.message);
    res.status(500).json({ status: "down", error: error.message });
  }
});

module.exports = router;
