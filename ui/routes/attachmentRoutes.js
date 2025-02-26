const express = require("express");
const path = require("path");
const fs = require("fs");
const axios = require("axios");
const FormData = require("form-data");
const fileUpload = require("express-fileupload");

const router = express.Router();
const UPLOADS_DIR = path.join(__dirname, "..", "uploads");
const FASTAPI_URL = `${process.env.backend_protocol}://${process.env.backend_host}:${process.env.backend_port}`;

// Ensure the uploads directory exists
if (!fs.existsSync(UPLOADS_DIR)) {
  fs.mkdirSync(UPLOADS_DIR, { recursive: true });
}

// Serve the HTML upload page
router.get("/attachment-analysis", (req, res) => {
  res.sendFile(path.join(__dirname, "..", "Template", "attachment-analysis.html"));
});

// ✅ Upload Attachment Route
router.post("/upload-attachment", fileUpload({ createParentPath: true }), async (req, res) => {
  try {
    if (!req.files || Object.keys(req.files).length === 0) {
      return res.status(400).json({ error: "No file uploaded" });
    }

    const file = req.files.files;
    const filePath = path.join(UPLOADS_DIR, file.name);

    await file.mv(filePath);

    console.log("✅ File saved locally:", filePath);

    const formData = new FormData();
    formData.append("file", fs.createReadStream(filePath));

    try {
      const response = await axios.post(`${FASTAPI_URL}/upload-attachment`, formData, {
        headers: formData.getHeaders(),
      });

      fs.unlinkSync(filePath);

      console.log("✅ File uploaded successfully:", file.name);
      res.json({ filename: file.name, message: "File uploaded successfully", fastapiResponse: response.data });

    } catch (apiError) {
      console.error("❌ Error sending file to FastAPI:", apiError.message);
      res.status(500).json({ error: "FastAPI upload failed", details: apiError.message });
    }

  } catch (error) {
    console.error("❌ Error uploading file:", error.message);
    res.status(500).json({ error: "Error uploading file", details: error.message });
  }
});

// ✅ Analyze uploaded file
router.post("/analyze-attachment", async (req, res) => {
  try {
    const { filename } = req.body;

    if (!filename) {
      return res.status(400).json({ error: "Filename is required" });
    }

    const response = await axios.post(`${FASTAPI_URL}/analyze-attachment`, { filename });

    console.log("✅ Analysis response:", response.data);
    res.json(response.data);
  } catch (error) {
    console.error("❌ Error analyzing file:", error.message);
    res.status(500).json({ error: "Error analyzing file", details: error.message });
  }
});

module.exports = router;
