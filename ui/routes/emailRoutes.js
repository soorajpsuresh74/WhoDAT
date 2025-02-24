const express = require("express");
const multer = require("multer");
const path = require("path");
const fs = require("fs");
const axios = require("axios");
const FormData = require("form-data");

const router = express.Router();
const UPLOADS_DIR = path.join(__dirname, "..", "uploads");
const FASTAPI_URL = `${process.env.backend_protocol}://${process.env.backend_host}:${process.env.backend_port}`;

const upload = multer({ dest: UPLOADS_DIR });

router.get("/email-analysis", (req, res) => {
  res.sendFile(path.join(__dirname, "..", "Template", "email-analysis.html"));
});

router.post("/upload-email", upload.single("emailFile"), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: "No file uploaded" });
    }

    const formData = new FormData();
    formData.append("file", fs.createReadStream(req.file.path));

    const response = await axios.post(`${FASTAPI_URL}/upload-email`, formData, {
      headers: formData.getHeaders(),
    });

    fs.unlinkSync(req.file.path);
    res.json(response.data);
  } catch (error) {
    console.error("❌ Error uploading file:", error.message);
    res.status(500).json({ error: "Error uploading file" });
  }
});

router.post("/analyze-email", async (req, res) => {
  try {
    const { filename } = req.body;

    if (!filename) {
      return res.status(400).json({ error: "Filename is required" });
    }

    const response = await axios.post(`${FASTAPI_URL}/analyze-email`, { filename });
    res.json(response.data);
  } catch (error) {
    console.error("❌ Error analyzing email:", error.message);
    res.status(500).json({ error: "Error analyzing email", details: error.message });
  }
});

module.exports = router;
