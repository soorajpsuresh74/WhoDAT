require('dotenv').config();
const express = require('express');
const path = require('path');

const app = express();
const PROTOCOL = process.env.protocol || false;
const HOST = process.env.host || false;
const PORT = process.env.port || false;

if (!process.env.protocol || !process.env.host || !process.env.port) {
    console.error("Missing required environment variables!");
    process.exit(1);
} else {
    console.log("Env variables successfully loaded");
}

app.use(express.static(path.join(__dirname, 'Template')));

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'Template', 'index.html'))
});

app.get('/about', (req, res) => {
    res.sendFile(path.join(__dirname, 'Template', 'about.html'))
});

app.get('/category', (req, res) => {
    res.sendFile(path.join(__dirname, 'Template', 'category.html'))
});

app.use((req, res) => {
    res.status(404).sendFile(path.join(__dirname, 'Template', '404.html'));
});

app.listen(PORT, () => {
    console.log("Info: Server started successfully!");
    console.log(`Server running at ${PROTOCOL}://${HOST}:${PORT}`);
    
});
