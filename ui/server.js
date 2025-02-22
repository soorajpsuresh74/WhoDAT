require("dotenv").config();
const express = require("express");
const path = require("path");
const axios = require("axios");

const app = express();

const PROTOCOL = process.env.protocol || "http";
const HOST = process.env.host || "localhost";
const PORT = process.env.port || 3000;

const BACKEND_PROTOCOL = process.env.backend_protocol || "http";
const BACKEND_HOST = process.env.backend_host || "localhost";
const BACKEND_PORT = process.env.backend_port || 8000;

if (!PROTOCOL || !HOST || !PORT) {
  console.error("Missing required environment variables for frontend!");
  process.exit(1);
}

if (!BACKEND_PROTOCOL || !BACKEND_HOST || !BACKEND_PORT) {
  console.error("Missing required environment variables for backend!");
  process.exit(1);
}

console.log("Env variables successfully loaded");

const FASTAPI_URL = `${BACKEND_PROTOCOL}://${BACKEND_HOST}:${BACKEND_PORT}`;

app.use(express.static(path.join(__dirname, "Template")));

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "Template", "index.html"));
});

app.get("/about", (req, res) => {
  res.sendFile(path.join(__dirname, "Template", "about.html"));
});

app.get("/category", (req, res) => {
  res.sendFile(path.join(__dirname, "Template", "category.html"));
});

app.get("/status", (req, res) => {
  res.sendFile(path.join(__dirname, "Template", "status.html"));
});

app.get("/api/health", async (req, res) => {
  try {
    const response = await axios.get(`${FASTAPI_URL}/health`);
    res.json(response.data);
  } catch (error) {
    res.status(500).json({ status: "down", error: error.message });
  }
});


app.use((req, res) => {
  res.status(404).sendFile(path.join(__dirname, "Template", "404.html"));
});


app.listen(PORT, () => {
  console.log("Info: Server started successfully!");
  console.log(`Server running at ${PROTOCOL}://${HOST}:${PORT}`);
});
