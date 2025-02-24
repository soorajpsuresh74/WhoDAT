require("dotenv").config();
const express = require("express");
const path = require("path");
const fs = require("fs");

const emailRoutes = require("./routes/emailRoutes");
const attachmentRoutes = require("./routes/attachmentRoutes");
const healthRoutes = require("./routes/healthRoutes");
const ipRoutes = require("./routes/ipRoutes");
const urlRoutes = require("./routes/urlRoutes");
const websiteRoutes = require("./routes/websiteRoutes");
const dmarcRoutes = require("./routes/dmarcRoutes");

const app = express();

const PROTOCOL = process.env.protocol || "http";
const HOST = process.env.host || "localhost";
const PORT = process.env.port || 3000;

console.log("✅ Env variables successfully loaded");

const UPLOADS_DIR = path.join(__dirname, "uploads");
if (!fs.existsSync(UPLOADS_DIR)) {
  fs.mkdirSync(UPLOADS_DIR);
}

app.use(express.static(path.join(__dirname, "Template")));
app.use(express.json());

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "Template", "index.html"));
});

app.use(emailRoutes);
app.use(attachmentRoutes);
app.use(healthRoutes);
app.use(ipRoutes);
app.use(urlRoutes);
app.use(websiteRoutes);
app.use(dmarcRoutes);

app.use((req, res) => {
  res.status(404).sendFile(path.join(__dirname, "Template", "404.html"));
});

app.listen(PORT, () => {
  console.log(`🚀 Server running at ${PROTOCOL}://${HOST}:${PORT}`);
});
