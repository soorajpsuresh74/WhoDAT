require("dotenv").config();
const express = require("express");
const path = require("path");
const axios = require("axios");
const multer = require("multer");
const fs = require("fs");
const FormData = require("form-data");

const app = express();

// Load environment variables
const PROTOCOL = process.env.protocol || "http";
const HOST = process.env.host || "localhost";
const PORT = process.env.port || 3000;

const BACKEND_PROTOCOL = process.env.backend_protocol || "http";
const BACKEND_HOST = process.env.backend_host || "localhost";
const BACKEND_PORT = process.env.backend_port || 8000;

const FASTAPI_URL = `${BACKEND_PROTOCOL}://${BACKEND_HOST}:${BACKEND_PORT}`;

if (!PROTOCOL || !HOST || !PORT) {
  console.error("❌ Missing required environment variables for frontend!");
  process.exit(1);
}

if (!BACKEND_PROTOCOL || !BACKEND_HOST || !BACKEND_PORT) {
  console.error("❌ Missing required environment variables for backend!");
  process.exit(1);
}

console.log("✅ Env variables successfully loaded");

// Ensure uploads directory exists
const UPLOADS_DIR = path.join(__dirname, "uploads");
if (!fs.existsSync(UPLOADS_DIR)) {
  fs.mkdirSync(UPLOADS_DIR);
}

app.use(express.static(path.join(__dirname, "Template")));
app.use(express.json());

const upload = multer({ dest: UPLOADS_DIR });

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "Template", "index.html"));
});

app.get("/email-analysis", (req, res) => {
  res.sendFile(path.join(__dirname, "Template", "email-analysis.html"));
});

app.post("/upload-email", upload.single("emailFile"), async (req, res) => {
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

app.post("/analyze-email", async (req, res) => {
  try {
    const { filename } = req.body;

    if (!filename) {
      return res.status(400).json({ error: "Filename is required" });
    }

    const response = await axios.post(`${FASTAPI_URL}/analyze-email`, { filename });
    console.log(response.data)

    res.json(response.data);
  } catch (error) {
    console.error("❌ Error analyzing email:", error.message);
    
    const status = error.response ? error.response.status : 500;
    res.status(status).json({ error: "Error analyzing email", details: error.message });
  }
});

app.get("/attachment-analysis", (req, res) => {
  res.sendFile(path.join(__dirname, "Template", "attachmet-analysis.html"));
});

app.post("/upload-attachment", upload.single("attachmentFile"), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: "No attachment uploaded" });
    }

    const formData = new FormData();
    formData.append("attachment", fs.createReadStream(req.file.path));

    const response = await axios.post(`${FASTAPI_URL}/upload-attachment`, formData, {
      headers: formData.getHeaders(),
    });

    fs.unlinkSync(req.file.path); // Remove the uploaded file after processing

    res.json(response.data);
  } catch (error) {
    console.error("❌ Error uploading attachment:", error.message);
    res.status(500).json({ error: "Error uploading attachment" });
  }
});

// Route to analyze the uploaded attachment
app.post("/analyze-attachment", async (req, res) => {
  try {
    const { filename } = req.body;

    if (!filename) {
      return res.status(400).json({ error: "Filename is required" });
    }

    const response = await axios.post(`${FASTAPI_URL}/analyze-attachment`, { filename });
    res.json(response.data);
  } catch (error) {
    console.error("❌ Error analyzing attachment:", error.message);
    
    const status = error.response ? error.response.status : 500;
    res.status(status).json({ error: "Error analyzing attachment", details: error.message });
  }
});

app.get("/api/health", async (req, res) => {
  try {
    const response = await axios.get(`${FASTAPI_URL}/health`);
    res.json(response.data);
  } catch (error) {
    console.error("❌ Health check failed:", error.message);
    res.status(500).json({ status: "down", error: error.message });
  }
});

app.use((req, res) => {
  res.status(404).sendFile(path.join(__dirname, "Template", "404.html"));
});

app.listen(PORT, () => {
  console.log(`🚀 Server running at ${PROTOCOL}://${HOST}:${PORT}`);
});
